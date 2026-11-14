// Sentinel gateway entry point: load config, build the pipeline, serve.
//
//	sentinel                               start the gateway
//	sentinel watch [--all] [--color] <file> live window: one line per decision
//	sentinel totp <secret>                 print the current 2FA code for a secret
//	sentinel explain <text>                what the WAF rules and the ML model say about an input
package main

import (
	"sentinel/gateway/internal/ml/profile"

	"errors"

	"path/filepath"

	"crypto/sha256"
	"sentinel/gateway/internal/bot"

	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"

	"sentinel/gateway/internal/alert"

	"math"
	"sentinel/gateway/internal/metrics"

	"slices"

	"sentinel/gateway/internal/exclude"

	"sentinel/gateway/internal/crs"

	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"sentinel/gateway/internal/blocklist"
	"sentinel/gateway/internal/certs"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/dashboard"
	"sentinel/gateway/internal/events"
	"sentinel/gateway/internal/geo"
	"sentinel/gateway/internal/kv"
	"sentinel/gateway/internal/middleware"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/promptguard"
	"sentinel/gateway/internal/proxy"
	"sentinel/gateway/internal/ratelimit"
	"sentinel/gateway/internal/schema"
	"sentinel/gateway/internal/waf"
	"sentinel/gateway/internal/watch"
)

// Version is shown on the dashboard. Release builds set it with
// -ldflags "-X main.Version=0.4.0".
var Version = "0.11.0"

func main() {
	if len(os.Args) > 1 {
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

	// Security events from the checks go to the access log and the dashboard;
	// rec stays nil in the free edition.
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
		log.Info("logins: accounts are kept in the data folder", "file", filepath.Join(cfg.DataDir, "users.json"))
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
		log.Info("sentinel started",
			"version", Version,
			"mode", cfg.Mode,
			"listen", cfg.ListenAddr,
			"upstreams", cfg.Upstreams,
			"rules", engine.RuleCount()+crsRules(engine),
			"database", cfg.DatabaseURL != "",
			"store", storeName(cfg.KV),
		)
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
		msrv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
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
	go rl.watch(file, cfg.RulesFile, cfg.ExclusionsFile)

	// Graceful shutdown: finish in-flight requests on Ctrl+C / docker stop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	if saveProfile != nil {
		saveProfile()
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	if tlsSrv != nil {
		tlsSrv.Shutdown(sctx)
	}
	log.Info("sentinel stopped")
}

// NewHandler wires the pipeline. Order matters: outermost runs first.
//
//	RequestContext -> AccessLog -> Signals -> [health] ->
//	1 IPBlock -> Geo -> Honeypot -> Bots -> 3 Authenticate (Sentinel's own
//	pages) -> 2 RateLimit -> LoginGuard -> StripIdentityHeaders -> 6 Schema ->
//	PromptGuard -> 7 WAF -> 8 ML -> AppProfile ->
//	(Sentinel login API and dashboard | reverse proxy -> app)
//
// Rate limiting runs after Authenticate so logged-in users are counted by
// name. rec may be nil (audit logging off).
func NewHandler(cfg *config.Config, engine *waf.Engine, authSvc *auth.Service, rec middleware.Recorder, log *slog.Logger) (http.Handler, error) {
	routes, err := proxy.ParseRoutes(cfg.Upstreams)
	if err != nil {
		return nil, err
	}
	spec, err := schema.Load(cfg.APISpecFile, cfg.APISpecPrefix)
	if err != nil {
		return nil, err
	}

	trust := middleware.ProxyTrust{All: cfg.TrustProxyHeaders}
	if trust.Nets, err = geo.ParsePrefixes(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}
	store := cfg.KV
	if store == nil {
		store = kv.NewMemory()
	}

	geoDB, err := geo.Load(cfg.GeoIPFile)
	if err != nil {
		return nil, fmt.Errorf("GEOIP_FILE: %w", err)
	}
	filter := &geo.Filter{
		DenyCountries:  geo.ParseCountries(cfg.GeoDenyCountries),
		AllowCountries: geo.ParseCountries(cfg.GeoAllowCountries),
	}
	if filter.DenyIPs, err = geo.ParsePrefixes(cfg.IPDeny); err != nil {
		return nil, fmt.Errorf("IP_DENY: %w", err)
	}
	if filter.AllowIPs, err = geo.ParsePrefixes(cfg.IPAllow); err != nil {
		return nil, fmt.Errorf("IP_ALLOW: %w", err)
	}

	var limiter *ratelimit.Limiter
	if !strings.EqualFold(cfg.RateLimits, "off") {
		spec := cfg.RateLimits
		if spec == "" {
			spec = ratelimit.DefaultRules
		}
		rules, err := ratelimit.Parse(spec)
		if err != nil {
			return nil, err
		}
		limiter = ratelimit.New(rules, store)
	}

	loginFails := &middleware.LoginFailures{Store: store, Window: 15 * time.Minute}

	respMode := cfg.ResponseCheck
	if cfg.Mode == "monitor" && respMode == "block" {
		respMode = "detect"
	}
	upstream := middleware.ResponseGuard(respMode, cfg.ResponseMaxBytes, log)(proxy.NewRouter(routes, log))
	authAPI := auth.NewHandlers(authSvc, rec, log)
	bans := blocklist.New()
	currentBans = bans
	hub := events.NewHub(5000)
	if cfg.AlertWebhookURL != "" {
		host, _ := os.Hostname()
		currentAlerter = &alert.Alerter{URL: cfg.AlertWebhookURL, ChatID: cfg.AlertTelegramChat, Burst: cfg.AlertBurst, Log: log, Name: host}
		go currentAlerter.Watch(context.Background(), hub)
		log.Info("alerts on", "to", redactURL(cfg.AlertWebhookURL), "burst", cfg.AlertBurst)
	}

	excl, err := exclude.Load(cfg.ExclusionsFile)
	if err != nil {
		return nil, fmt.Errorf("exclusions: %w", err)
	}
	if p := cfg.ProfileData; p != nil {
		var list []exclude.Exclusion
		for _, pe := range p.Exclusions {
			for _, rule := range pe.Rules {
				list = append(list, exclude.Exclusion{Rule: rule, Path: pe.Path, Field: pe.Field, Note: pe.Note, By: "profile: " + cfg.Profile})
			}
		}
		if err := excl.AddPreset(list); err != nil {
			return nil, fmt.Errorf("profile %s: %w", cfg.Profile, err)
		}
		log.Info("profile applied", "profile", cfg.Profile, "about", p.Description)
	}
	middleware.Exclusions = excl
	if n := len(excl.List()); n > 0 {
		log.Info("exclusions loaded", "file", cfg.ExclusionsFile, "count", n)
	}

	var dash http.Handler
	if cfg.Dashboard {
		info := dashboard.Info{Version: Version, Mode: cfg.Mode, WAFMode: cfg.WAFMode, ML: mlDescribe(cfg), Rules: engine.RuleCount() + crsRules(engine), Store: store.Name(),
			Started: time.Now().Format(time.RFC3339), PromptPath: cfg.PromptGuardPaths}
		if limiter != nil {
			info.RateLimits = limiter.Describe()
		}
		info.Geo = fmt.Sprintf("%d ranges; deny %s; allow %s", geoDB.Size(), orNone(cfg.GeoDenyCountries), orNone(cfg.GeoAllowCountries))
		dash = &dashboard.Dashboard{Hub: hub, Bans: bans, Rec: rec, Log: log, Info: info, Excl: excl, Reload: func(why string) error {
			if reloadFunc == nil {
				return fmt.Errorf("reload is only available in the running gateway")
			}
			return reloadFunc(why)
		}}
	}

	// First run: no accounts yet, so print a one-time link to create the admin.
	setupState, setupToken, err := authSvc.NewSetup(context.Background())
	if err != nil {
		return nil, err
	}
	setup := &dashboard.Setup{Svc: authSvc, State: setupState, Log: log, Rec: rec, OnCreated: func(user, ip string) {
		currentAlerter.Send("admin:"+user, alert.Message{Title: "Admin account created",
			Text: fmt.Sprintf("The first-run setup created the admin account %q (from %s). If that wasn't you, stop Sentinel now.", user, ip)})
	}}
	if setupToken != "" {
		log.Warn("FIRST RUN: no accounts yet. Create the admin account (the link works once):",
			"url", setupURL(adminAddr(cfg))+dashboard.SetupPath+"#"+setupToken)
	}

	traps := cfg.HoneypotPaths
	if len(traps) == 0 {
		traps = middleware.DefaultHoneypots
		if p := cfg.ProfileData; p != nil {
			// Pages that are real in this kind of app must not be traps.
			traps = slices.DeleteFunc(slices.Clone(traps), func(t string) bool { return slices.Contains(p.RemoveTraps, t) })
		}
	}
	banFor := cfg.HoneypotBan
	if banFor <= 0 {
		banFor = time.Hour
	}

	// The end of the chain: Sentinel's own login API, or the protected apps.
	var model *ml.Model
	if cfg.MLMode == "detect" || cfg.MLMode == "block" {
		if model, err = ml.Default(); err != nil {
			return nil, err
		}
	}

	// In monitor mode every check that can refuse a request runs in shadow:
	// it logs what it would refuse, and the request goes on anyway.
	// The WAF, ML and prompt guard have their own log-only mode, which keeps
	// their logs accurate ("detected", not "blocked").
	wafMode, mlMode, pgMode := cfg.WAFMode, cfg.MLMode, cfg.PromptGuardMode
	if cfg.Mode == "monitor" {
		wafMode, pgMode = "detect", "detect"
		if mlMode == "block" {
			mlMode = "detect"
		}
	}
	guard := func(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
		if cfg.Mode == "monitor" {
			return middleware.Shadow(mw)
		}
		return mw
	}

	var pipeline http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminPath := strings.HasPrefix(r.URL.Path, dashboard.SetupPath) || strings.HasPrefix(r.URL.Path, dashboard.APIPrefix) ||
			strings.HasPrefix(r.URL.Path, dashboard.PagePath)
		if cfg.DashboardAddr != "" {
			if onAdminPort(r) {
				// The admin port serves only Sentinel's own pages.
				if !adminPath && !strings.HasPrefix(r.URL.Path, auth.Prefix) {
					http.Redirect(w, r, dashboard.PagePath, http.StatusFound)
					return
				}
			} else if adminPath {
				// Not on the public port: the dashboard has its own.
				http.NotFound(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, auth.Prefix) {
			authAPI.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, dashboard.SetupPath) {
			setup.ServeHTTP(w, r)
			return
		}
		if dash != nil && (strings.HasPrefix(r.URL.Path, dashboard.APIPrefix) || strings.HasPrefix(r.URL.Path, dashboard.PagePath)) {
			dash.ServeHTTP(w, r)
			return
		}
		upstream.ServeHTTP(w, r)
	})
	if cfg.AppProfile != "off" {
		mode := cfg.AppProfile
		if cfg.Mode == "monitor" && mode == "block" {
			mode = "detect"
		}
		file := filepath.Join(cfg.DataDir, "app-profile.json")
		prof, err := profile.Load(file)
		if err != nil {
			return nil, err
		}
		n, pages, fields := prof.Stats()
		log.Info("app profile", "mode", mode, "learned_from", n, "pages", pages, "fields", fields, "file", file)
		if mode == "learn" {
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := prof.Save(file); err != nil {
						log.Warn("app profile not saved", "error", err.Error())
					}
				}
			}()
			saveProfile = func() { prof.Save(file) }
		}
		pipeline = middleware.AppProfile(prof, mode, cfg.AppProfileMinSeen, cfg.MaxBodyBytes, log)(pipeline)
	}
	if model != nil {
		pipeline = guard(middleware.ML(model, mlMode, cfg.MLThreshold, cfg.MLSkipPaths, cfg.MaxBodyBytes, rec, log))(pipeline) // 8
	}
	pipeline = guard(middleware.WAF(engine, wafMode, cfg.MaxBodyBytes, rec, log))(pipeline) // 7
	if len(cfg.PromptGuardPaths) > 0 {
		pg := &promptguard.Guard{Threshold: cfg.PromptThreshold}
		pipeline = guard(middleware.PromptGuard(pg, cfg.PromptGuardPaths, cfg.PromptCanary, pgMode, cfg.MaxBodyBytes, rec, log))(pipeline)
	}
	pipeline = guard(middleware.Schema(spec, cfg.MaxBodyBytes, rec, log))(pipeline) // 6
	pipeline = middleware.StripIdentityHeaders(pipeline)
	waf.MaxFieldBytes = cfg.MaxFieldBytes
	pipeline = guard(middleware.LoginGuard(loginFails, cfg.LoginFailLimit, rec, log))(pipeline)
	if limiter != nil {
		pipeline = guard(middleware.RateLimitBan(limiter, bans, cfg.HoneypotBan, rec, log))(pipeline) // 2
	}
	pipeline = middleware.Authenticate(authSvc)(pipeline) // 3
	if cfg.Mode != "monitor" {
		pipeline = middleware.BodyLimit(cfg.MaxBodyBytes, rec, log)(pipeline)
	}
	botKey := sha256.Sum256([]byte("sentinel-bot-challenge|" + cfg.Secret))
	if cfg.Secret == "" {
		rand.Read(botKey[:]) // passes end when Sentinel restarts
	}
	pipeline = guard(middleware.Bots(middleware.BotOptions{
		BlockScanners: cfg.BotBlockScanners,
		Challenge:     cfg.BotChallenge,
		Paths:         cfg.BotPaths,
		Challenger:    &bot.Challenger{Key: botKey[:], Difficulty: cfg.BotDifficulty, PassFor: 24 * time.Hour},
	}, log))(pipeline)
	pipeline = guard(middleware.Honeypot(traps, bans, banFor, rec, log))(pipeline)
	pipeline = guard(middleware.Geo(geoDB, filter, rec, log))(pipeline)
	pipeline = guard(middleware.IPBlock(bans, log))(pipeline) // 1

	// Sentinel's health endpoint skips the pipeline.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__sentinel/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": cfg.Mode, "waf_mode": cfg.WAFMode, "version": Version})
			return
		}
		pipeline.ServeHTTP(w, r)
	})

	var inner http.Handler = middleware.CountLoginFailures(loginFails)(root)
	if cfg.SecurityHeaders {
		inner = middleware.SecurityHeaders(inner)
	}
	return middleware.RequestContext(trust)(middleware.AccessLog(log, hub)(inner)), nil
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
