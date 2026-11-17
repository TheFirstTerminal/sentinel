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
	"sentinel/gateway/internal/export"
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
	hosts      *hostRouter             // picks the site by host name
	siteSet    atomic.Pointer[[]*site] // the running sites
	siteMu     sync.Mutex              // adding and removing sites
	added      []config.Site           // sites added on the dashboard
	logins     middleware.LoginCounter // what LoginGuard asks (loginFails unless an edition replaces it)
	ext        any                     // the edition's own state (see edition.go)
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
	name    string
	hosts   []string
	conf    config.Site // as configured (before dashboard changes)
	mu      sync.Mutex  // rebuilds
	mode    string
	waf     string
	ml      string
	limits  []string
	edited  dashboard.SiteSettings // changes made on the dashboard
	added   bool                   // added on the dashboard
	router  *proxy.Router
	servers string            // what router was built from (serversKey)
	prof    *profile.Profile  // app profile, kept across rebuilds
	spec    *schema.Validator // the site's own API spec, if it has one
	h       atomic.Value      // http.Handler: the current pipeline
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
	sh.siteSet.Store(&sites)
	hostRouter := newHostRouter(sites)
	hostRouter.admin = sh.adminPort
	sh.hosts = hostRouter
	if d, ok := sh.admin.(*adminPages); ok && d.dash != nil {
		d.dash.Sites = func() []dashboard.SiteStatus { return siteStatus(sh.siteList(), cfg.Mode) }
		d.dash.SetMode = func(name, mode string) error { return sh.setSiteMode(sh.siteList(), name, mode) }
		d.dash.SetSite = func(name string, in dashboard.SiteSettings) error { return sh.setSite(sh.siteList(), name, in) }
		d.dash.AddSite = sh.addSite
		d.dash.RemoveSite = sh.removeSite
		d.dash.Alerts = sh.alertSettings
		d.dash.SetAlerts = sh.setAlerts
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
	inner := edition.Outer(sh, root)
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
	sh.logins = sh.loginFails
	if edition.Shared != nil {
		if err := edition.Shared(sh); err != nil {
			return nil, err
		}
	}
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
	{
		host, _ := os.Hostname()
		currentAlerter = &alert.Alerter{URL: cfg.AlertWebhookURL, ChatID: cfg.AlertTelegramChat, Burst: cfg.AlertBurst, Log: log, Name: host}
		if saved, ok := loadAlertSettings(sh.settingsFile("alerts.json")); ok {
			currentAlerter.Set(saved.WebhookURL, saved.TelegramChat, saved.Burst)
			log.Info("alert settings from the dashboard", "file", sh.settingsFile("alerts.json"))
		}
		go currentAlerter.Watch(context.Background(), sh.hub)
		if edition.AlertsReady != nil {
			edition.AlertsReady(sh)
		}
		if u, _, burst := currentAlerter.Settings(); u != "" {
			log.Info("alerts on", "to", redactURL(u), "burst", burst)
		}
	}

	if cfg.ExportSyslog != "" {
		sl, err := export.ParseSyslog(cfg.ExportSyslog)
		if err != nil {
			return nil, fmt.Errorf("export.syslog: %w", err)
		}
		sl.All, sl.Log = cfg.ExportAll, log
		go sl.Watch(context.Background(), sh.hub)
		log.Info("events exported to syslog", "to", cfg.ExportSyslog)
	}
	if cfg.ExportOTLP != "" {
		o, err := export.ParseOTLP(cfg.ExportOTLP, cfg.ExportOTLPHeaders)
		if err != nil {
			return nil, fmt.Errorf("export.otlp: %w", err)
		}
		o.All, o.Log = cfg.ExportAll, log
		go o.Watch(context.Background(), sh.hub)
		log.Info("events exported to OpenTelemetry", "to", o.Endpoint)
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
	sh.added = sh.loadAdded()
	if len(sh.added) > 0 {
		if _, err := sh.effectiveSites(nil); err != nil {
			sh.log.Warn("sites added on the dashboard ignored: they don't fit the config file any more", "error", err.Error(), "file", sh.settingsFile("sites-added.json"))
			sh.added = nil
		}
	}
	nConfigured := len(list)
	list = append(list, sh.added...)
	edits := sh.loadSiteSettings()
	effective, err := sh.effectiveSites(edits)
	if err != nil {
		sh.log.Warn("site settings from the dashboard ignored: they don't fit the config file any more", "error", err.Error(), "file", sh.settingsFile("site-settings.json"))
		edits, effective = nil, nil
	}
	var out []*site
	for i, sc := range list {
		s := &site{name: sc.Name, hosts: sc.Hosts, conf: sc, added: i >= nConfigured}
		if ed, ok := edits[sc.Name]; ok {
			s.edited = ed
			sc = withEdits(sc, ed)
			if e, ok := effective[sc.Name]; ok {
				sc = e
				s.hosts = sc.Hosts
			}
			sh.log.Info("site settings changed on the dashboard", "site", siteLabel(sc.Name), "file", sh.settingsFile("site-settings.json"))
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
		s.servers = serversKey(sc, cfg)
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
	pgPaths, canary := cfg.PromptGuardPaths, cfg.PromptCanary
	if len(sc.PromptGuardPaths) > 0 {
		pgPaths, canary = sc.PromptGuardPaths, pick(sc.PromptCanary, cfg.PromptCanary)
	}
	if len(pgPaths) > 0 {
		pg := &promptguard.Guard{Threshold: cfg.PromptThreshold}
		p = guard(middleware.PromptGuard(pg, pgPaths, canary, pgMode, cfg.MaxBodyBytes, sh.rec, log))(p)
	}
	spec := sh.spec
	if sc.APISpecFile != "" {
		if s.spec == nil {
			var err error
			if s.spec, err = schema.Load(sc.APISpecFile, sc.APISpecPrefix); err != nil {
				return fmt.Errorf("api_spec_file: %w", err)
			}
		}
		spec = s.spec
	}
	p = guard(middleware.Schema(spec, cfg.MaxBodyBytes, sh.rec, log))(p) // 6
	p = edition.Access(sh, sc, p, guard)
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
		a.dash = &dashboard.Dashboard{Hub: sh.hub, Bans: sh.bans, Rec: sh.rec, Log: log, Info: info, Excl: excl, Auth: sh.authSvc, Reload: func(why string) error {
			if reloadFunc == nil {
				return fmt.Errorf("reload is only available in the running gateway")
			}
			return reloadFunc(why)
		}}
		if edition.Dashboard != nil {
			edition.Dashboard(sh, a.dash)
		}
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
	h = middleware.LoginGuard(sh.logins, cfg.LoginFailLimit, sh.rec, log)(h)
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
// then the longest "*.example.com" match, then the "*" site. Its index is
// rebuilt when a site's host names change on the dashboard.
type hostRouter struct {
	idx   atomic.Pointer[hostIndex]
	admin http.Handler // the dashboard port
}

type hostIndex struct {
	exact    map[string]*site
	wildcard []hostSuffix
	fallback *site
	first    *site
}

type hostSuffix struct {
	suffix string
	s      *site
}

func newHostRouter(sites []*site) *hostRouter {
	hr := &hostRouter{}
	hr.rebuild(sites)
	return hr
}

// rebuild indexes the sites' current host names.
func (hr *hostRouter) rebuild(sites []*site) {
	ix := &hostIndex{exact: map[string]*site{}, first: sites[0]}
	for _, s := range sites {
		for _, h := range s.hostNames() {
			switch {
			case h == "*":
				ix.fallback = s
			case strings.HasPrefix(h, "*."):
				ix.wildcard = append(ix.wildcard, hostSuffix{h[1:], s})
			default:
				ix.exact[h] = s
			}
		}
	}
	slices.SortFunc(ix.wildcard, func(a, b hostSuffix) int { return len(b.suffix) - len(a.suffix) })
	hr.idx.Store(ix)
}

func (hr *hostRouter) find(host string) *site {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	ix := hr.idx.Load()
	if s, ok := ix.exact[host]; ok {
		return s
	}
	for _, w := range ix.wildcard {
		if strings.HasSuffix(host, w.suffix) {
			return w.s
		}
	}
	return ix.fallback
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
			s = hr.idx.Load().first // Sentinel's own pages work on any host
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
		st := dashboard.SiteStatus{Name: s.name, Hosts: s.hosts, Editable: s.name != "", Added: s.added,
			Config: dashboard.SiteSettings{Hosts: s.conf.Hosts, Upstreams: s.conf.Upstreams, HealthCheck: s.conf.HealthCheck}, Mode: s.mode, ConfigMode: pick(s.conf.Mode, defaultMode), Edited: s.edited, ConfigLimits: s.conf.RateLimits, WAFMode: s.waf, MLMode: s.ml, RateLimits: s.limits}
		s.mu.Unlock()
		for _, u := range s.router.Status() {
			st.Servers = append(st.Servers, dashboard.ServerStatus{Prefix: u.Prefix, URL: u.URL, Up: u.Up})
		}
		out = append(out, st)
	}
	return out
}
