package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel/gateway/internal/alert"
	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/blocklist"
	"sentinel/gateway/internal/bot"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/dashboard"
	"sentinel/gateway/internal/events"
	"sentinel/gateway/internal/exclude"
	"sentinel/gateway/internal/geo"
	"sentinel/gateway/internal/kv"
	"sentinel/gateway/internal/middleware"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/ml/profile"
	"sentinel/gateway/internal/promptguard"
	"sentinel/gateway/internal/proxy"
	"sentinel/gateway/internal/ratelimit"
	"sentinel/gateway/internal/reqctx"
	"sentinel/gateway/internal/schema"
	"sentinel/gateway/internal/waf"
)

// shared is what every site uses: one ban list, one login, one dashboard,
// one history. Each site gets its own pipeline of checks (sitePipeline).
type shared struct {
	cfg        *config.Config
	engine     *waf.Engine
	authSvc    *auth.Service
	rec        middleware.Recorder
	log        *slog.Logger
	store      kv.Store
	geoDB      *geo.DB
	filter     *geo.Filter
	bans       *blocklist.List
	hub        *events.Hub
	loginFails *middleware.LoginFailures
	spec       *schema.Validator
	model      *ml.Model
	traps      []string
	banFor     time.Duration
	botKey     []byte
	admin      http.Handler // Sentinel's own pages: login API, first-run setup, dashboard
	adminPort  http.Handler // the dashboard port's own chain (no IP bans: see adminChain)
}

// site is one built site: its settings and its pipeline.
type site struct {
	name   string
	hosts  []string
	conf   config.Site // as configured (before dashboard changes)
	mu     sync.Mutex  // rebuilds
	mode   string
	waf    string
	ml     string
	limits []string
	router *proxy.Router
	prof   *profile.Profile // app profile, kept across rebuilds
	h      atomic.Value     // http.Handler: the current pipeline
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.h.Load().(http.Handler).ServeHTTP(w, r)
}

// NewHandler wires everything. Order matters: outermost runs first.
//
//	RequestContext -> AccessLog -> [health] -> site by Host ->
//	1 IPBlock -> Geo -> Honeypot -> Bots -> BodyLimit -> 3 Authenticate
//	(Sentinel's own pages) -> 2 RateLimit -> LoginGuard -> StripIdentityHeaders
//	-> 6 Schema -> PromptGuard -> 7 WAF -> 8 ML -> AppProfile ->
//	(Sentinel's login API and dashboard | reverse proxy -> app)
//
// rec may be nil (no security event store).
func NewHandler(cfg *config.Config, engine *waf.Engine, authSvc *auth.Service, rec middleware.Recorder, log *slog.Logger) (http.Handler, error) {
	sh, err := newShared(cfg, engine, authSvc, rec, log)
	if err != nil {
		return nil, err
	}
	sites, err := sh.buildSites()
	if err != nil {
		return nil, err
	}
	hostRouter := newHostRouter(sites)
	hostRouter.admin = sh.adminPort
	if d, ok := sh.admin.(*adminPages); ok && d.dash != nil {
		d.dash.Sites = func() []dashboard.SiteStatus { return siteStatus(sites, cfg.Mode) }
		d.dash.SetMode = func(name, mode string) error { return sh.setSiteMode(sites, name, mode) }
	}

	trust := middleware.ProxyTrust{All: cfg.TrustProxyHeaders}
	if trust.Nets, err = geo.ParsePrefixes(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}
	// Sentinel's health endpoint skips the pipeline.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__sentinel/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": cfg.Mode, "waf_mode": cfg.WAFMode, "version": Version})
			return
		}
		hostRouter.ServeHTTP(w, r)
	})
	var inner http.Handler = middleware.CountLoginFailures(sh.loginFails)(root)
	if cfg.SecurityHeaders {
		inner = middleware.SecurityHeaders(inner)
	}
	return middleware.RequestContext(trust)(middleware.AccessLog(log, sh.hub)(inner)), nil
}

func newShared(cfg *config.Config, engine *waf.Engine, authSvc *auth.Service, rec middleware.Recorder, log *slog.Logger) (*shared, error) {
	sh := &shared{cfg: cfg, engine: engine, authSvc: authSvc, rec: rec, log: log, store: cfg.KV}
	if sh.store == nil {
		sh.store = kv.NewMemory()
	}
	var err error
	if sh.spec, err = schema.Load(cfg.APISpecFile, cfg.APISpecPrefix); err != nil {
		return nil, err
	}
	if sh.geoDB, err = geo.Load(cfg.GeoIPFile); err != nil {
		return nil, fmt.Errorf("GEOIP_FILE: %w", err)
	}
	sh.filter = &geo.Filter{
		DenyCountries:  geo.ParseCountries(cfg.GeoDenyCountries),
		AllowCountries: geo.ParseCountries(cfg.GeoAllowCountries),
	}
	if sh.filter.DenyIPs, err = geo.ParsePrefixes(cfg.IPDeny); err != nil {
		return nil, fmt.Errorf("IP_DENY: %w", err)
	}
	if sh.filter.AllowIPs, err = geo.ParsePrefixes(cfg.IPAllow); err != nil {
		return nil, fmt.Errorf("IP_ALLOW: %w", err)
	}
	sh.loginFails = &middleware.LoginFailures{Store: sh.store, Window: 15 * time.Minute}
	sh.bans = blocklist.New()
	currentBans = sh.bans
	sh.hub = events.NewHub(5000)
	if cfg.HistoryDir != "" {
		hist, err := events.OpenHistory(cfg.HistoryDir, cfg.HistoryDays, log)
		if err != nil {
			log.Warn("history: not kept on disk", "dir", cfg.HistoryDir, "error", err.Error())
		} else {
			sh.hub.Persist(hist) // before alerts subscribe: old events must not alert again
			currentHistory = hist
			log.Info("history: kept on disk", "dir", cfg.HistoryDir, "days", cfg.HistoryDays, "loaded", len(sh.hub.Recent(0)))
		}
	}
	if cfg.AlertWebhookURL != "" {
		host, _ := os.Hostname()
		currentAlerter = &alert.Alerter{URL: cfg.AlertWebhookURL, ChatID: cfg.AlertTelegramChat, Burst: cfg.AlertBurst, Log: log, Name: host}
		go currentAlerter.Watch(context.Background(), sh.hub)
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

	sh.traps = cfg.HoneypotPaths
	if len(sh.traps) == 0 {
		sh.traps = middleware.DefaultHoneypots
		if p := cfg.ProfileData; p != nil {
			// Pages that are real in this kind of app must not be traps.
			sh.traps = slices.DeleteFunc(slices.Clone(sh.traps), func(t string) bool { return slices.Contains(p.RemoveTraps, t) })
		}
	}
	sh.banFor = cfg.HoneypotBan
	if sh.banFor <= 0 {
		sh.banFor = time.Hour
	}
	if needsModel(cfg) {
		if sh.model, err = ml.Default(); err != nil {
			return nil, err
		}
	}
	key := sha256.Sum256([]byte("sentinel-bot-challenge|" + cfg.Secret))
	if cfg.Secret == "" {
		rand.Read(key[:]) // passes end when Sentinel restarts
	}
	sh.botKey = key[:]
	waf.MaxFieldBytes = cfg.MaxFieldBytes
	if sh.admin, err = sh.adminPages(excl); err != nil {
		return nil, err
	}
	if sh.adminPort, err = sh.adminChain(); err != nil {
		return nil, err
	}
	return sh, nil
}

// needsModel: the ML model is loaded if any site uses it.
func needsModel(cfg *config.Config) bool {
	uses := func(m string) bool { return m == "detect" || m == "block" }
	if uses(cfg.MLMode) {
		return true
	}
	for _, s := range cfg.Sites {
		if uses(s.MLMode) {
			return true
		}
	}
	return false
}

// buildSites makes one pipeline per configured site. Without SITES there is
// one site for every host, with the global settings.
func (sh *shared) buildSites() ([]*site, error) {
	cfg := sh.cfg
	list := cfg.Sites
	if len(list) == 0 {
		list = []config.Site{{Hosts: []string{"*"}, Spec: cfg.Upstreams, HealthCheck: cfg.HealthCheck}}
	}
	overrides := loadModeOverrides(sh.modesFile())
	var out []*site
	for _, sc := range list {
		s := &site{name: sc.Name, hosts: sc.Hosts, conf: sc}
		if m, ok := overrides[sc.Name]; ok {
			sc.Mode = m
			sh.log.Info("site mode set on the dashboard", "site", siteLabel(sc.Name), "mode", m, "file", sh.modesFile())
		}
		err := sh.sitePipeline(sc, s)
		if err != nil {
			if sc.Name != "" {
				return nil, fmt.Errorf("site %q: %w", sc.Name, err)
			}
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// sitePipeline builds (or rebuilds) one site's checks with its own modes
// and limits, and switches the site to them. A rebuild keeps the site's
// servers, their health and its app profile.
func (sh *shared) sitePipeline(sc config.Site, s *site) error {
	cfg, log := sh.cfg, sh.log
	mode, wafM, mlM := pick(sc.Mode, cfg.Mode), pick(sc.WAFMode, cfg.WAFMode), pick(sc.MLMode, cfg.MLMode)

	if s.router == nil {
		routes, err := proxy.ParseRoutes(sc.Spec)
		if err != nil {
			return err
		}
		s.router = proxy.NewRouter(routes, proxy.Options{HealthPath: pick(sc.HealthCheck, cfg.HealthCheck)}, log)
	}
	var limits []string

	var limiter *ratelimit.Limiter
	limitSpec := pick(sc.RateLimitSpec(), cfg.RateLimits)
	if !strings.EqualFold(limitSpec, "off") {
		if limitSpec == "" {
			limitSpec = ratelimit.DefaultRules
		}
		rules, err := ratelimit.Parse(limitSpec)
		if err != nil {
			return err
		}
		limiter = ratelimit.New(rules, sh.store).ForSite(sc.Name)
		limits = limiter.Describe()
	}

	monitor := mode == "monitor"
	respMode := cfg.ResponseCheck
	if monitor && respMode == "block" {
		respMode = "detect"
	}
	upstream := middleware.ResponseGuard(respMode, cfg.ResponseMaxBytes, log)(s.router)

	// In monitor mode every check that can refuse a request runs in shadow:
	// it logs what it would refuse, and the request goes on anyway. The WAF,
	// ML and prompt guard have their own log-only mode, which keeps their
	// logs accurate ("detected", not "blocked").
	wafMode, mlMode, pgMode := wafM, mlM, cfg.PromptGuardMode
	if monitor {
		wafMode, pgMode = "detect", "detect"
		if mlMode == "block" {
			mlMode = "detect"
		}
	}
	guard := func(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
		if monitor {
			return middleware.Shadow(mw)
		}
		return mw
	}

	admin := sh.admin
	var p http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAdminPath(r.URL.Path) {
			admin.ServeHTTP(w, r)
			return
		}
		upstream.ServeHTTP(w, r)
	})
	if cfg.AppProfile != "off" {
		pmode := cfg.AppProfile
		if monitor && pmode == "block" {
			pmode = "detect"
		}
		if s.prof == nil {
			name := "app-profile.json"
			if sc.Name != "" {
				name = "app-profile-" + sc.Name + ".json"
			}
			file := filepath.Join(cfg.DataDir, name)
			prof, err := profile.Load(file)
			if err != nil {
				return err
			}
			n, pages, fields := prof.Stats()
			log.Info("app profile", "site", sc.Name, "mode", pmode, "learned_from", n, "pages", pages, "fields", fields, "file", file)
			if cfg.AppProfile == "learn" {
				go func() {
					for range time.Tick(30 * time.Second) {
						if err := prof.Save(file); err != nil {
							log.Warn("app profile not saved", "error", err.Error())
						}
					}
				}()
				saveProfiles = append(saveProfiles, func() { prof.Save(file) })
			}
			s.prof = prof
		}
		p = middleware.AppProfile(s.prof, pmode, cfg.AppProfileMinSeen, cfg.MaxBodyBytes, log)(p)
	}
	if mlMode == "detect" || mlMode == "block" {
		p = guard(middleware.ML(sh.model, mlMode, cfg.MLThreshold, cfg.MLSkipPaths, cfg.MaxBodyBytes, sh.rec, log))(p) // 8
	}
	var opinion middleware.SecondOpinion
	if cfg.SecondOpinion && sh.model != nil {
		model := sh.model
		opinion = func(text string) float64 { p, _ := model.ScoreText(text); return p }
	}
	p = guard(middleware.WAFWithSecondOpinion(sh.engine, wafMode, cfg.MaxBodyBytes, opinion, sh.rec, log))(p) // 7
	if len(cfg.PromptGuardPaths) > 0 {
		pg := &promptguard.Guard{Threshold: cfg.PromptThreshold}
		p = guard(middleware.PromptGuard(pg, cfg.PromptGuardPaths, cfg.PromptCanary, pgMode, cfg.MaxBodyBytes, sh.rec, log))(p)
	}
	p = guard(middleware.Schema(sh.spec, cfg.MaxBodyBytes, sh.rec, log))(p) // 6
	p = middleware.StripIdentityHeaders(p)
	p = guard(middleware.LoginGuard(sh.loginFails, cfg.LoginFailLimit, sh.rec, log))(p)
	if limiter != nil {
		p = guard(middleware.RateLimitBan(limiter, sh.bans, cfg.HoneypotBan, sh.rec, log))(p) // 2
	}
	p = middleware.Authenticate(sh.authSvc)(p) // 3
	if !monitor {
		p = middleware.BodyLimit(cfg.MaxBodyBytes, sh.rec, log)(p)
	}
	p = guard(middleware.Bots(middleware.BotOptions{
		BlockScanners: cfg.BotBlockScanners,
		Challenge:     cfg.BotChallenge,
		Paths:         cfg.BotPaths,
		Challenger:    &bot.Challenger{Key: sh.botKey, Difficulty: cfg.BotDifficulty, PassFor: 24 * time.Hour},
	}, log))(p)
	p = guard(middleware.Honeypot(sh.traps, sh.bans, sh.banFor, sh.rec, log))(p)
	p = guard(middleware.Geo(sh.geoDB, sh.filter, sh.rec, log))(p)
	p = guard(middleware.IPBlock(sh.bans, log))(p) // 1
	name := sc.Name
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqctx.From(r.Context()).Site = name
		p.ServeHTTP(w, r)
	})
	s.mode, s.waf, s.ml, s.limits = mode, wafM, mlM, limits
	s.h.Store(h)
	if len(sh.cfg.Sites) > 0 {
		log.Info("site", "name", sc.Name, "hosts", sc.Hosts, "upstreams", sc.Spec, "mode", mode, "waf_mode", wafM, "ml_mode", mlM)
	}
	return nil
}

// modesFile keeps modes set on the dashboard ("" = no data folder).
func (sh *shared) modesFile() string {
	if sh.cfg.DataDir == "" || !usableDir(sh.cfg.DataDir) {
		return ""
	}
	return filepath.Join(sh.cfg.DataDir, "site-modes.json")
}

func loadModeOverrides(file string) map[string]string {
	out := map[string]string{}
	if file == "" {
		return out
	}
	if b, err := os.ReadFile(file); err == nil {
		json.Unmarshal(b, &out)
	}
	for k, v := range out {
		if v != "monitor" && v != "protect" {
			delete(out, k)
		}
	}
	return out
}

// setSiteMode switches a site between monitor and protect from the
// dashboard, saves the choice (it wins over the config file) and rebuilds
// the site's pipeline. Choosing the configured mode again removes the saved
// choice.
func (sh *shared) setSiteMode(sites []*site, name, mode string) error {
	if mode != "monitor" && mode != "protect" {
		return fmt.Errorf("mode must be monitor or protect")
	}
	var s *site
	for _, x := range sites {
		if x.name == name {
			s = x
		}
	}
	if s == nil {
		return fmt.Errorf("no site %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.conf
	configured := pick(sc.Mode, sh.cfg.Mode)
	sc.Mode = mode
	if err := sh.sitePipeline(sc, s); err != nil {
		return err
	}
	if file := sh.modesFile(); file != "" {
		overrides := loadModeOverrides(file)
		if mode == configured {
			delete(overrides, name)
		} else {
			overrides[name] = mode
		}
		b, _ := json.MarshalIndent(overrides, "", "  ")
		if err := os.WriteFile(file, b, 0o600); err != nil {
			sh.log.Warn("site mode not saved: it lasts until Sentinel restarts", "file", file, "error", err.Error())
		}
	}
	sh.log.Warn("site mode changed on the dashboard", "site", siteLabel(name), "mode", mode)
	currentAlerter.Send("mode:"+name, alert.Message{Title: "Site mode changed",
		Text: fmt.Sprintf("Site %q is now in %s mode (changed on the dashboard).", siteLabel(name), mode)})
	return nil
}

func siteLabel(name string) string {
	if name == "" {
		return "all hosts"
	}
	return name
}

func pick(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func isAdminPath(p string) bool {
	return strings.HasPrefix(p, "/__sentinel/")
}

// adminPages serves Sentinel's own pages, the same for every site.
type adminPages struct {
	cfg     *config.Config
	authAPI http.Handler
	setup   http.Handler
	dash    *dashboard.Dashboard
}

func (sh *shared) adminPages(excl *exclude.Set) (http.Handler, error) {
	cfg, log := sh.cfg, sh.log
	a := &adminPages{cfg: cfg, authAPI: auth.NewHandlers(sh.authSvc, sh.rec, log)}
	if cfg.Dashboard {
		info := dashboard.Info{Version: Version, Mode: cfg.Mode, WAFMode: cfg.WAFMode, ML: mlDescribe(cfg),
			Rules: sh.engine.RuleCount() + crsRules(sh.engine), Store: sh.store.Name(),
			Started: time.Now().Format(time.RFC3339), PromptPath: cfg.PromptGuardPaths}
		info.Geo = fmt.Sprintf("%d ranges; deny %s; allow %s", sh.geoDB.Size(), orNone(cfg.GeoDenyCountries), orNone(cfg.GeoAllowCountries))
		a.dash = &dashboard.Dashboard{Hub: sh.hub, Bans: sh.bans, Rec: sh.rec, Log: log, Info: info, Excl: excl, Reload: func(why string) error {
			if reloadFunc == nil {
				return fmt.Errorf("reload is only available in the running gateway")
			}
			return reloadFunc(why)
		}}
	}
	// First run: no accounts yet, so print a one-time link to create the admin.
	setupState, setupToken, err := sh.authSvc.NewSetup(context.Background())
	if err != nil {
		return nil, err
	}
	a.setup = &dashboard.Setup{Svc: sh.authSvc, State: setupState, Log: log, Rec: sh.rec, OnCreated: func(user, ip string) {
		currentAlerter.Send("admin:"+user, alert.Message{Title: "Admin account created",
			Text: fmt.Sprintf("The first-run setup created the admin account %q (from %s). If that wasn't you, stop Sentinel now.", user, ip)})
	}}
	if setupToken != "" {
		log.Warn("FIRST RUN: no accounts yet. Create the admin account (the link works once):",
			"url", setupURL(adminAddr(cfg))+dashboard.SetupPath+"#"+setupToken)
	}
	return a, nil
}

// adminChain is what requests on the dashboard's own port go through. IP
// bans, honeypots and country lists are left out on purpose: that port is
// for administrators (keep it private), and an admin who shares an address
// with an attacker (an office or mobile network) must still be able to open
// the dashboard to lift the ban. Logins stay rate limited and guarded
// against password spraying.
func (sh *shared) adminChain() (http.Handler, error) {
	cfg, log := sh.cfg, sh.log
	rules, err := ratelimit.Parse(ratelimit.DefaultRules)
	if err != nil {
		return nil, err
	}
	var h http.Handler = sh.admin
	h = middleware.LoginGuard(sh.loginFails, cfg.LoginFailLimit, sh.rec, log)(h)
	h = middleware.RateLimitBan(ratelimit.New(rules, sh.store).ForSite("__admin"), nil, 0, sh.rec, log)(h)
	h = middleware.Authenticate(sh.authSvc)(h)
	return middleware.BodyLimit(cfg.MaxBodyBytes, sh.rec, log)(h), nil
}

func (a *adminPages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	dashPath := strings.HasPrefix(path, dashboard.SetupPath) || strings.HasPrefix(path, dashboard.APIPrefix) ||
		strings.HasPrefix(path, dashboard.PagePath)
	if a.cfg.DashboardAddr != "" && !onAdminPort(r) && dashPath {
		http.NotFound(w, r) // not on the public port: the dashboard has its own
		return
	}
	switch {
	case strings.HasPrefix(path, auth.Prefix):
		a.authAPI.ServeHTTP(w, r)
	case strings.HasPrefix(path, dashboard.SetupPath):
		a.setup.ServeHTTP(w, r)
	case a.dash != nil && (strings.HasPrefix(path, dashboard.APIPrefix) || strings.HasPrefix(path, dashboard.PagePath)):
		a.dash.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// hostRouter picks the site by the request's Host: an exact name first,
// then the longest "*.example.com" match, then the "*" site.
type hostRouter struct {
	exact    map[string]*site
	wildcard []struct {
		suffix string
		s      *site
	}
	fallback *site
	first    *site
	admin    http.Handler // the dashboard port
}

func newHostRouter(sites []*site) *hostRouter {
	hr := &hostRouter{exact: map[string]*site{}, first: sites[0]}
	for _, s := range sites {
		for _, h := range s.hosts {
			switch {
			case h == "*":
				hr.fallback = s
			case strings.HasPrefix(h, "*."):
				hr.wildcard = append(hr.wildcard, struct {
					suffix string
					s      *site
				}{h[1:], s})
			default:
				hr.exact[h] = s
			}
		}
	}
	slices.SortFunc(hr.wildcard, func(a, b struct {
		suffix string
		s      *site
	}) int {
		return len(b.suffix) - len(a.suffix)
	})
	return hr
}

func (hr *hostRouter) find(host string) *site {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if s, ok := hr.exact[host]; ok {
		return s
	}
	for _, w := range hr.wildcard {
		if strings.HasSuffix(host, w.suffix) {
			return w.s
		}
	}
	return hr.fallback
}

func (hr *hostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if onAdminPort(r) {
		if !isAdminPath(r.URL.Path) {
			http.Redirect(w, r, dashboard.PagePath, http.StatusFound) // the admin port serves only Sentinel's own pages
			return
		}
		hr.admin.ServeHTTP(w, r)
		return
	}
	s := hr.find(r.Host)
	if s == nil {
		if isAdminPath(r.URL.Path) {
			s = hr.first // Sentinel's own pages work on any host
		} else {
			info := reqctx.From(r.Context())
			info.SetOutcome(reqctx.Outcome{Kind: "denied", Reason: "no site is configured for host " + r.Host, Rule: "sites"})
			http.Error(w, "no site is configured for this host name", http.StatusMisdirectedRequest)
			return
		}
	}
	s.ServeHTTP(w, r)
}

func siteStatus(sites []*site, defaultMode string) []dashboard.SiteStatus {
	out := make([]dashboard.SiteStatus, 0, len(sites))
	for _, s := range sites {
		s.mu.Lock()
		st := dashboard.SiteStatus{Name: s.name, Hosts: s.hosts, Mode: s.mode, ConfigMode: pick(s.conf.Mode, defaultMode), WAFMode: s.waf, MLMode: s.ml, RateLimits: s.limits}
		s.mu.Unlock()
		for _, u := range s.router.Status() {
			st.Servers = append(st.Servers, dashboard.ServerStatus{Prefix: u.Prefix, URL: u.URL, Up: u.Up})
		}
		out = append(out, st)
	}
	return out
}
