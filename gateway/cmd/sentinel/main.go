// Sentinel gateway entry point: load config, build the pipeline, serve.
//
//	sentinel                               start the gateway
//	sentinel watch [--all] [--color] <file> live window: one line per decision
//	sentinel totp <secret>                 print the current 2FA code for a secret
//	sentinel explain <text>                what the WAF rules and the ML model say about an input
package main

import (
	"errors"

	"path/filepath"

	"crypto/tls"

	"golang.org/x/crypto/acme/autocert"

	"math"
	"sentinel/gateway/internal/metrics"

	"sentinel/gateway/internal/crs"

	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/certs"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/dashboard"
	"sentinel/gateway/internal/kv"
	"sentinel/gateway/internal/middleware"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/waf"
	"sentinel/gateway/internal/watch"
)

// Version is shown on the dashboard. Release builds set it with
// -ldflags "-X main.Version=0.4.0".
var Version = "0.19.0"

func main() {
	if len(os.Args) > 1 {
		if cmd, ok := edition.Commands[os.Args[1]]; ok {
			os.Exit(cmd(os.Args[2:], os.Stdout))
		}
		switch os.Args[1] {
		case "watch":
			os.Exit(watchCmd(os.Args[2:], os.Stdout))
		case "totp":
			os.Exit(totpCmd(os.Args[2:], os.Stdout))
		case "explain":
			os.Exit(explainCmd(os.Args[2:], os.Stdout))
		case "init":
			os.Exit(initCmd(os.Args[2:], os.Stdout))
		case "check-config":
			os.Exit(checkConfigCmd(os.Args[2:], os.Stdout))
		case "bench":
			os.Exit(benchCmd(os.Args[2:], os.Stdout))
		case "healthcheck":
			os.Exit(healthcheckCmd(os.Stdout))
		case "version", "--version", "-v":
			fmt.Println("sentinel", Version)
			os.Exit(0)
		case "help", "--help", "-h":
			fmt.Print(usage)
			os.Exit(0)
		}
	}

	file, fromFile, err := loadConfigFile(os.Args[1:])
	if err != nil {
		slog.Error("config file", "error", err)
		os.Exit(1)
	}
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogFile)
	fatal := func(what string, err error) {
		log.Error(what, "error", err.Error())
		os.Exit(1)
	}
	if file != "" {
		log.Info("config file loaded", "file", file, "settings", len(fromFile))
	}
	if cfg.Mode == "monitor" {
		log.Warn("MONITOR MODE: every check runs and logs, but nothing is blocked. " +
			"Watch the dashboard, then set mode: protect (or MODE=protect) to start blocking.")
	}

	engine, err := buildEngine(cfg, log)
	if err != nil {
		fatal("rules", err)
	}

	// Security events from the checks go to the access log and the
	// dashboard; an edition may also record them (edition.Prepare).
	var rec middleware.Recorder

	// The data folder keeps the secret, accounts, exclusions and
	// certificates across restarts when there is no database.
	dataOK := usableDir(cfg.DataDir)
	if !dataOK {
		log.Warn("data folder not writable: accounts, exclusions and the secret are kept in memory and lost on restart",
			"dir", cfg.DataDir, "fix", "make it writable, or set DATA_DIR")
	}

	// Users: PostgreSQL if configured, else a file in the data folder.
	ctx := context.Background()
	var store auth.Store
	switch {
	case cfg.DatabaseURL != "":
		pg, err := auth.OpenPG(ctx, cfg.DatabaseURL, 60*time.Second)
		if err != nil {
			fatal("database", err)
		}
		defer pg.Close()
		store = pg
	case dataOK:
		fs, err := auth.OpenFileStore(filepath.Join(cfg.DataDir, "users.json"))
		if err != nil {
			fatal("users file", err)
		}
		store = fs
		log.Info("dashboard: admin accounts are kept in the data folder", "file", filepath.Join(cfg.DataDir, "users.json"))
	default:
		store = auth.NewMemoryStore()
	}
	secret := cfg.Secret
	if secret == "" {
		if dataOK {
			if secret, err = loadOrCreateSecret(filepath.Join(cfg.DataDir, "secret")); err != nil {
				fatal("secret", err)
			}
		} else {
			secret = randomSecret()
		}
	}
	cfg.Secret = secret
	if dataOK && cfg.HistoryDays > 0 {
		cfg.HistoryDir = filepath.Join(cfg.DataDir, "history")
	}
	if cfg.ExclusionsFile == "" && dataOK {
		cfg.ExclusionsFile = filepath.Join(cfg.DataDir, "exclusions.yaml")
	}
	if cfg.TLSAutoCache == "" {
		cfg.TLSAutoCache = filepath.Join(cfg.DataDir, "certs")
	}
	keys, err := auth.DeriveKeys(secret)
	if err != nil {
		fatal("secret", err)
	}
	authSvc, err := auth.NewService(store, keys)
	if err != nil {
		fatal("auth", err)
	}
	// Shared counters for rate limiting and bans: Redis if configured. If
	// Redis can't be reached at startup, fall back to memory and say so.
	if cfg.RedisURL != "" {
		var rds *kv.Redis
		for i := 0; i < 15; i++ {
			if rds, err = kv.NewRedis(ctx, cfg.RedisURL); err == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			log.Error("redis unreachable, using memory for rate limits", "error", err.Error())
		} else {
			defer rds.Close()
			cfg.KV = rds
		}
	}

	if edition.Prepare != nil {
		r, closer, err := edition.Prepare(ctx, cfg, authSvc, log)
		if err != nil {
			fatal("startup", err)
		}
		if closer != nil {
			defer closer()
		}
		if r != nil {
			rec = r
		}
	}

	handler, err := NewHandler(cfg, engine, authSvc, rec, log)
	if err != nil {
		fatal("startup", err)
	}

	if cfg.DashboardAddr != "" {
		admin := &http.Server{Addr: cfg.DashboardAddr, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 0, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminPortKey{}, true)))
			})}
		go func() {
			log.Info("dashboard", "url", setupURL(cfg.DashboardAddr)+dashboard.PagePath)
			if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("dashboard server", "error", err.Error())
			}
		}()
	} else if cfg.Dashboard {
		log.Info("dashboard", "url", setupURL(cfg.ListenAddr)+dashboard.PagePath)
	}
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second, // stops slowloris-style attacks
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Optional HTTPS listener, which is also where mTLS clients connect.
	var tlsSrv *http.Server
	var autoTLS *tls.Config
	cfg.TLSAutoDomains = config.AutoDomains(cfg.TLSAutoDomains, cfg.Sites)
	if len(cfg.TLSAutoDomains) > 0 {
		// Automatic HTTPS: certificates from Let's Encrypt, renewed before
		// they expire. The plain HTTP listener answers the ACME challenges
		// and sends everything else to HTTPS.
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLSAutoDomains...),
			Cache:      autocert.DirCache(cfg.TLSAutoCache),
			Email:      cfg.TLSAutoEmail,
		}
		srv.Handler = m.HTTPHandler(nil)
		if cfg.TLSListenAddr == "" {
			cfg.TLSListenAddr = ":443"
		}
		if cfg.TLSCertFile == "" {
			autoTLS = m.TLSConfig()
			autoTLS.MinVersion = tls.VersionTLS12
		}
		log.Info("automatic HTTPS (Let's Encrypt)", "domains", cfg.TLSAutoDomains, "cache", cfg.TLSAutoCache,
			"note", "ports 80 and 443 must be reachable from the internet")
	}
	if cfg.TLSListenAddr != "" {
		tlsCfg := autoTLS
		if tlsCfg == nil {
			var err error
			if tlsCfg, err = certs.ServerConfig(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
				fatal("tls", err)
			}
		}
		if edition.TLS != nil {
			if err := edition.TLS(cfg, tlsCfg); err != nil {
				fatal("tls", err)
			}
		}
		tlsSrv = &http.Server{
			Addr: cfg.TLSListenAddr, Handler: handler, TLSConfig: tlsCfg,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20,
			ErrorLog: slogTLSErrors(log),
		}
		go func() {
			log.Info("https listener started", "listen", cfg.TLSListenAddr)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				fatal("https server", err)
			}
		}()
	}

	go func() {
		attrs := []any{"version", Version, "mode", cfg.Mode, "listen", cfg.ListenAddr, "upstreams", cfg.Upstreams,
			"rules", engine.RuleCount() + crsRules(engine), "database", cfg.DatabaseURL != "", "store", storeName(cfg.KV)}
		log.Info("sentinel started", append(attrs, startedAttrs(cfg)...)...)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal("server", err)
		}
	}()

	if cfg.MetricsAddr != "" {
		reg := metrics.Default
		reg.Gauge("sentinel_info", "Version and mode (always 1).", fmt.Sprintf(`version=%q,mode=%q`, Version, cfg.Mode), func() float64 { return 1 })
		reg.Gauge("sentinel_rules_loaded", "Rules loaded (Sentinel's own plus CRS).", "", func() float64 { return float64(engine.RuleCount() + crsRules(engine)) })
		reg.Gauge("sentinel_bans_active", "IPs banned right now.", "", func() float64 {
			if currentBans == nil {
				return math.NaN()
			}
			return float64(len(currentBans.List()))
		})
		reg.Gauge("sentinel_exclusions", "Exclusions in force.", "", func() float64 { return float64(len(middleware.Exclusions.List())) })
		mux := http.NewServeMux()
		mux.Handle("/metrics", reg.Handler())
		msrv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
		go func() {
			log.Info("metrics for Prometheus", "url", "http://"+cfg.MetricsAddr+"/metrics")
			if err := msrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server", "error", err.Error())
			}
		}()
	}

	// Reload rules, CRS and exclusions on SIGHUP, when one of their
	// files changes, or from the dashboard.
	rl := &reloader{engine: engine, log: log, file: file, fileVars: fromFile}
	reloadFunc = rl.reload
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			rl.reload("SIGHUP")
		}
	}()
	watched := []string{file, cfg.RulesFile, cfg.ExclusionsFile}
	if edition.WatchFiles != nil {
		watched = append(watched, edition.WatchFiles(cfg)...)
	}
	go rl.watch(watched...)

	// Graceful shutdown: finish in-flight requests on Ctrl+C / docker stop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	for _, save := range saveProfiles {
		save()
	}
	if currentHistory != nil {
		currentHistory.Close()
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	if tlsSrv != nil {
		tlsSrv.Shutdown(sctx)
	}
	log.Info("sentinel stopped")
}

type adminPortKey struct{}

// onAdminPort: the request came in on the dashboard's own port.
func onAdminPort(r *http.Request) bool {
	v, _ := r.Context().Value(adminPortKey{}).(bool)
	return v
}

// adminAddr is where the dashboard (and the first-run page) is served.
func adminAddr(cfg *config.Config) string {
	if cfg.DashboardAddr != "" {
		return cfg.DashboardAddr
	}
	return cfg.ListenAddr
}

// setupURL turns a listen address into a URL a person can open.
func setupURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://localhost:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// usableDir creates dir if needed and checks it can be written.
func usableDir(dir string) bool {
	if dir == "" || os.MkdirAll(dir, 0o700) != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// loadOrCreateSecret reads the secret file, or makes a new random secret
// and saves it (owner-only), so logins and 2FA survive restarts.
func loadOrCreateSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= 32 {
			return s, nil
		}
		return "", fmt.Errorf("%s holds less than 32 characters", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	s := randomSecret()
	return s, os.WriteFile(path, []byte(s+"\n"), 0o600)
}

func crsRules(e *waf.Engine) int {
	if s := e.CRS(); s != nil {
		return s.Stats.Rules
	}
	return 0
}

// builtinCRS is where the Docker image keeps the Core Rule Set.
const builtinCRS = "/etc/sentinel/crs/rules"

// crsPath turns the CRS setting into a folder. Unset means "use the built-in
// copy if there is one" (so the Docker image has CRS on by default), "on"
// requires the built-in copy, "off" disables CRS.
func crsPath(v string) string {
	switch strings.ToLower(v) {
	case "off", "false", "none":
		return ""
	case "":
		if _, err := os.Stat(builtinCRS); err == nil {
			return builtinCRS
		}
		return ""
	case "on", "true", "builtin":
		return builtinCRS
	}
	return v
}

// watchCmd runs the live decisions window until Ctrl+C.
func watchCmd(args []string, out io.Writer) int {
	var opt watch.Options
	file := os.Getenv("LOG_FILE")
	for _, a := range args {
		switch a {
		case "--all":
			opt.All = true
		case "--color":
			opt.Color = true
		case "--from-start":
			opt.FromStart = true
		default:
			file = a
		}
	}
	if file == "" {
		fmt.Fprintln(out, "usage: sentinel watch [--all] [--color] [--from-start] <log-file>")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	watch.Follow(ctx, file, out, opt)
	return 0
}

// totpCmd prints the current 6-digit code for a secret, like an
// authenticator app does. Handy for testing and scripted demos.
func totpCmd(args []string, out io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(out, "usage: sentinel totp <base32-secret>")
		return 2
	}
	code, err := auth.TOTPCode(args[0], time.Now())
	if err != nil {
		fmt.Fprintln(out, "usage: sentinel totp <base32-secret>")
		return 2
	}
	fmt.Fprintln(out, code)
	return 0
}

func mlDescribe(cfg *config.Config) string {
	if cfg.MLMode == "off" || cfg.MLMode == "" {
		return "off"
	}
	return fmt.Sprintf("%s, threshold %.2f", cfg.MLMode, cfg.MLThreshold)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func startedAttrs(cfg *config.Config) []any {
	if edition.StartedAttrs == nil {
		return nil
	}
	return edition.StartedAttrs(cfg)
}

func storeName(s kv.Store) string {
	if s == nil {
		return "memory"
	}
	return s.Name()
}

// slogTLSErrors sends the HTTPS server's errors (mostly clients with a bad
// or untrusted certificate failing the handshake) to the JSON log.
func slogTLSErrors(log *slog.Logger) *stdlog.Logger {
	return slog.NewLogLogger(log.Handler(), slog.LevelWarn)
}

// explainCmd shows what the WAF rules and the ML classifier make of one
// input, with the ML's reasons. Handy for tuning and for demos.
func explainCmd(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, "usage: sentinel explain <text>")
		return 2
	}
	text := strings.Join(args, " ")
	rules, err := waf.LoadRules(os.Getenv("RULES_FILE"))
	if err != nil {
		fmt.Fprintln(out, "rules:", err)
		return 2
	}
	engine := waf.NewEngine(rules, 5)
	if dir := crsPath(os.Getenv("CRS_DIR")); dir != "" {
		if set, err := crs.Load(dir, 1); err == nil {
			engine.UseCRS(set)
		}
	}
	r, _ := http.NewRequest("GET", "/?q="+url.QueryEscape(text), nil)
	r.Header.Set("User-Agent", "sentinel-explain")
	r.Header.Set("Accept", "*/*")
	d := engine.Inspect(r, nil)
	fmt.Fprintf(out, "Input:      %s\n", text)
	if d.Attack {
		fmt.Fprintf(out, "WAF rules:  ATTACK (score %d, %s: %s)\n", d.Score, d.Matches[0].RuleID, d.Matches[0].Name)
	} else if len(d.Matches) > 0 {
		fmt.Fprintf(out, "WAF rules:  no attack (score %d, below the threshold)\n", d.Score)
	} else {
		fmt.Fprintln(out, "WAF rules:  no rule matches")
	}
	m, err := ml.Default()
	if err != nil {
		fmt.Fprintln(out, "ML:", err)
		return 2
	}
	e := m.Explain(text, 5)
	verdict := "normal"
	if e.Probability >= 0.9 {
		verdict = "ATTACK"
	}
	fmt.Fprintf(out, "ML model:   %s (%.1f%% likely an attack)\n", verdict, e.Probability*100)
	if len(e.Reasons) > 0 {
		fmt.Fprintln(out, "Pieces pushing towards \"attack\":")
		for _, rs := range e.Reasons {
			fmt.Fprintf(out, "  %-24q +%.2f\n", rs.Token, rs.Weight)
		}
	}
	return 0
}

func randomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// newLogger writes JSON lines to stdout and, optionally, a file. JSON logs
// are easy to load into the dashboard and the evaluation scripts later.
func newLogger(file string) *slog.Logger {
	var out io.Writer = os.Stdout
	if consoleFormat() == "pretty" {
		out = &consoleWriter{out: os.Stdout, color: os.Getenv("NO_COLOR") == ""}
	}
	if file != "" {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			out = io.MultiWriter(out, f)
		} else {
			slog.Warn("cannot open log file, logging to stdout only", "file", file, "error", err)
		}
	}
	return slog.New(slog.NewJSONHandler(out, nil))
}
