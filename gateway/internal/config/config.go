// Package config loads gateway settings from a YAML file and environment
// variables (the environment wins).
//
// Every setting has a safe default so the gateway runs with zero config,
// and Docker Compose can override any of them.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinel/gateway/internal/kv"
)

type Config struct {
	// Mode is "monitor" (every check runs and logs, nothing is refused) or
	// "protect" (refuse what the checks catch). New installs start in
	// monitor so a false alarm can never break the app on day one.
	Mode string

	CRSDir      string   // folder with OWASP Core Rule Set .conf files (empty = off)
	CRSParanoia int      // CRS paranoia level 1-4
	CRSExclude  []string // CRS rule IDs or ranges to switch off

	ExclusionsFile string // YAML list of per-path/field rule exclusions

	MetricsAddr string // where Prometheus metrics are served, e.g. ":9090" ("" = off)

	// DashboardAddr gives the dashboard its own port, e.g. ":9000"; then it
	// is not reachable on the public one. "" = on the main port.
	DashboardAddr string

	// AppProfile learns the app's normal requests: "off", "learn",
	// "detect" or "block".
	AppProfile        string
	AppProfileMinSeen int

	// DataDir keeps what must survive a restart when there is no database:
	// the secret key, accounts, exclusions and HTTPS certificates.
	DataDir string

	ResponseCheck    string // "off", "detect" or "block": leaks in the app's responses
	ResponseMaxBytes int    // responses up to this size are checked

	BotBlockScanners bool     // refuse known attack tools by User-Agent
	BotChallenge     string   // "off", "suspicious" or "all"
	BotPaths         []string // where challenges apply
	BotStrictPaths   []string // where every client needs a pass (BOT_STRICT_PATHS)
	BotDifficulty    int      // proof-of-work bits

	// Automatic HTTPS (Let's Encrypt): the domains Sentinel gets
	// certificates for, a contact e-mail, and where certificates are kept.
	TLSAutoDomains []string
	TLSAutoEmail   string
	TLSAutoCache   string

	AlertWebhookURL   string // Slack, Discord, Telegram or any webhook ("" = no alerts)
	AlertTelegramChat string
	AlertBurst        int    // stopped requests from one IP in a minute that make an alert
	ExportSyslog      string // udp://host:514, tcp://... or tls://... ("" = off)
	ExportOTLP        string // OpenTelemetry collector, e.g. http://collector:4318 ("" = off)
	ExportOTLPHeaders string // Name=value,... sent with every OTLP request
	ExportAll         bool   // also export plain allowed requests
	KubeIngressClass  string // act as the Kubernetes Ingress controller for this class ("" = off)

	Profile     string   // e.g. "wordpress"
	ProfileData *Profile // its traps to remove and exclusions (nil = none)

	ListenAddr    string   // where the gateway listens, e.g. ":8080"
	UpstreamURL   *url.URL // the protected app we forward clean requests to
	WAFMode       string   // "block" = stop attacks, "detect" = only log them
	SecondOpinion bool     // WAF_SECOND_OPINION: the ML model may let a borderline CRS-only detection through
	WAFThreshold  int      // anomaly score at which a request is treated as an attack
	RulesFile     string   // optional JSON file that replaces the built-in rules
	MaxBodyBytes  int64    // how much of a request body the WAF inspects
	LogFile       string   // optional file for security events (JSON lines)

	// TrustProxyHeaders: only enable when another proxy sits in front of
	// Sentinel. Otherwise attackers can fake X-Forwarded-For to dodge IP bans.
	TrustProxyHeaders bool

	AuditLogFile  string        // tamper-evident audit log (Sentinel Pro; empty = off)
	HoneypotPaths []string      // trap paths; nil = built-in list
	HoneypotBan   time.Duration // how long a honeypot hit bans the IP

	// Phase 2
	Upstreams     string // "/api/=http://api:8000,/=http://web-1:3000|http://web-2:3000"
	HealthCheck   string // path checked on every server, e.g. "/healthz" ("" = none)
	Sites         []Site // per-domain settings (SITES); empty = one site for every host
	HistoryDays   int    // days of dashboard history kept on disk (HISTORY_DAYS, 0 = off)
	HistoryDir    string // set at startup: <data dir>/history when the data folder is usable
	DatabaseURL   string // PostgreSQL; empty = in-memory users (lost on restart)
	Secret        string // SENTINEL_SECRET, master key for tokens and encryption
	SeedUsersFile string // JSON users created on first start (Sentinel Pro)
	PolicyFile    string // RBAC/ABAC policy JSON (Sentinel Pro)
	APISpecFile   string // OpenAPI spec; empty = schema validation off
	APISpecPrefix string // which paths the spec covers (required with a spec)

	// Phase 3
	TrustedProxies    string // CIDRs whose X-Forwarded-For is believed
	RedisURL          string // shared counters; empty = memory
	RateLimits        string // "/prefix=limit/window,..." or "off"
	GeoIPFile         string // cidr,country CSV
	GeoDenyCountries  string // "KP,RU"
	GeoAllowCountries string // if set, only these (and LAN)
	IPDeny            string // CIDRs always refused
	IPAllow           string // if set, only these may connect
	RiskEnabled       bool   // risk scoring (Sentinel Pro)
	RiskStepUp        int
	RiskBlock         int
	RiskHighCountries string
	RiskQuietHours    string // "00-05"
	Timezone          string // for quiet hours
	TLSListenAddr     string // e.g. ":8443"; empty = no HTTPS listener
	TLSCertFile       string
	TLSKeyFile        string
	ClientCAFile      string // CA that signs client certificates (mTLS, Sentinel Pro)
	MTLSRoutes        string // "/prefix=cn1|cn2,..." routes that need a client certificate
	TLSAutogenDir     string // generate lab certificates here if missing

	// Phase 4
	Dashboard        bool     // serve /__sentinel/dashboard (DASHBOARD=off to disable)
	PromptGuardPaths []string // AI chat endpoints to protect from prompt injection
	PromptGuardMode  string   // block or detect
	PromptThreshold  int
	PromptCanary     string // secret marker in the AI's hidden prompt

	MaxFieldBytes   int   // largest single value the WAF inspects (WAF_MAX_FIELD_BYTES, 0 = off)
	MaxInspectMS    int   // Core Rule Set time per request before it is refused (WAF_MAX_INSPECT_MS, 0 = off)
	LoginFailLimit  int64 // failed logins per account before it is paused (LOGIN_FAIL_LIMIT, 0 = off)
	SecurityHeaders bool  // add nosniff, Referrer-Policy, X-Frame-Options, HSTS (SECURITY_HEADERS=off to disable)

	// Phase 5
	MLMode      string  // off, detect or block
	MLThreshold float64 // probability that counts as an attack
	MLSkipPaths []string

	// KV is the shared counter store, set by main (Redis or memory), not
	// read from the environment. nil = a fresh in-memory store.
	KV kv.Store
}

func Load() (*Config, error) {
	upstream, err := url.Parse(env("UPSTREAM_URL", "http://localhost:3000"))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("UPSTREAM_URL must be a full URL like http://app:3000")
	}

	profile, err := applyProfile(os.Getenv("PROFILE"))
	if err != nil {
		return nil, err
	}
	burst, err := strconv.Atoi(env("ALERT_BURST", "20"))
	if err != nil || burst < 1 {
		return nil, fmt.Errorf("ALERT_BURST must be a positive number")
	}
	if u := os.Getenv("ALERT_WEBHOOK_URL"); u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, fmt.Errorf("ALERT_WEBHOOK_URL must be an http(s) URL")
	}
	botMode := strings.ToLower(env("BOT_CHALLENGE", "off"))
	if botMode != "off" && botMode != "suspicious" && botMode != "all" {
		return nil, fmt.Errorf("BOT_CHALLENGE must be off, suspicious or all")
	}
	botBits, err := strconv.Atoi(env("BOT_DIFFICULTY", "15"))
	if err != nil || botBits < 4 || botBits > 24 {
		return nil, fmt.Errorf("BOT_DIFFICULTY must be 4-24 (each step doubles the work)")
	}
	respCheck := strings.ToLower(env("RESPONSE_CHECK", "block"))
	if respCheck != "off" && respCheck != "detect" && respCheck != "block" {
		return nil, fmt.Errorf("RESPONSE_CHECK must be off, detect or block")
	}
	respMax, err := strconv.Atoi(env("RESPONSE_MAX_BYTES", "1048576"))
	if err != nil || respMax < 1024 {
		return nil, fmt.Errorf("RESPONSE_MAX_BYTES must be at least 1024")
	}
	appProf := strings.ToLower(env("APP_PROFILE", "off"))
	if appProf != "off" && appProf != "learn" && appProf != "detect" && appProf != "block" {
		return nil, fmt.Errorf("APP_PROFILE must be off, learn, detect or block")
	}
	appMin, err := strconv.Atoi(env("APP_PROFILE_MIN_SEEN", "20"))
	if err != nil || appMin < 1 {
		return nil, fmt.Errorf("APP_PROFILE_MIN_SEEN must be a positive number")
	}
	gmode := strings.ToLower(env("MODE", "monitor"))
	if gmode != "monitor" && gmode != "protect" {
		return nil, fmt.Errorf("MODE must be 'monitor' (log only) or 'protect' (block)")
	}
	paranoia, err := strconv.Atoi(env("CRS_PARANOIA", "1"))
	if err != nil || paranoia < 1 || paranoia > 4 {
		return nil, fmt.Errorf("CRS_PARANOIA must be 1, 2, 3 or 4")
	}

	threshold, err := strconv.Atoi(env("WAF_THRESHOLD", "5"))
	if err != nil || threshold < 1 {
		return nil, fmt.Errorf("WAF_THRESHOLD must be a positive integer")
	}

	maxBody, err := strconv.ParseInt(env("MAX_BODY_BYTES", "1048576"), 10, 64)
	if err != nil || maxBody < 0 {
		return nil, fmt.Errorf("MAX_BODY_BYTES must be a non-negative integer")
	}

	mode := strings.ToLower(env("WAF_MODE", "block"))
	if mode != "block" && mode != "detect" {
		return nil, fmt.Errorf("WAF_MODE must be 'block' or 'detect'")
	}

	banMinutes, err := strconv.Atoi(env("HONEYPOT_BAN_MINUTES", "60"))
	if err != nil || banMinutes < 1 {
		return nil, fmt.Errorf("HONEYPOT_BAN_MINUTES must be a positive integer")
	}

	var traps []string
	if v := os.Getenv("HONEYPOT_PATHS"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				traps = append(traps, p)
			}
		}
	}

	// Zero-trust settings belong to Sentinel Pro. Refuse to start rather than
	// ignore them: someone who set POLICY_FILE expects their routes protected.
	for _, v := range ProVariables {
		if val := os.Getenv(v); !Pro && val != "" && !(v == "RISK" && strings.EqualFold(val, "off")) {
			return nil, fmt.Errorf("%s is a Sentinel Pro setting (logins and single sign-on for your apps, access policies, mTLS, risk step-up and the tamper-evident audit log); remove it to run the free edition", v)
		}
	}
	stepUp, err := strconv.Atoi(env("RISK_STEP_UP", "40"))
	if err != nil || stepUp < 1 || stepUp > 100 {
		return nil, fmt.Errorf("RISK_STEP_UP must be 1-100")
	}
	block, err := strconv.Atoi(env("RISK_BLOCK", "80"))
	if err != nil || block < stepUp || block > 101 {
		return nil, fmt.Errorf("RISK_BLOCK must be between RISK_STEP_UP and 101 (101 = never block)")
	}

	sites, err := ParseSites(os.Getenv("SITES"))
	if err != nil {
		return nil, err
	}
	historyDays, err := strconv.Atoi(env("HISTORY_DAYS", "30"))
	if err != nil || historyDays < 0 || historyDays > 3650 {
		return nil, fmt.Errorf("HISTORY_DAYS must be 0-3650 (0 = keep no history on disk)")
	}
	health := os.Getenv("HEALTH_CHECK")
	if health != "" && !strings.HasPrefix(health, "/") {
		return nil, fmt.Errorf("HEALTH_CHECK must be a path like /healthz")
	}

	pgMode := strings.ToLower(env("PROMPT_GUARD_MODE", "block"))
	if pgMode != "block" && pgMode != "detect" {
		return nil, fmt.Errorf("PROMPT_GUARD_MODE must be 'block' or 'detect'")
	}
	pgThreshold, err := strconv.Atoi(env("PROMPT_GUARD_THRESHOLD", "5"))
	if err != nil || pgThreshold < 1 {
		return nil, fmt.Errorf("PROMPT_GUARD_THRESHOLD must be a positive integer")
	}
	var pgPaths []string
	for _, p := range strings.Split(os.Getenv("PROMPT_GUARD_PATHS"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			pgPaths = append(pgPaths, p)
		}
	}

	loginLimit, err := strconv.ParseInt(env("LOGIN_FAIL_LIMIT", "10"), 10, 64)
	if err != nil || loginLimit < 0 {
		return nil, fmt.Errorf("LOGIN_FAIL_LIMIT must be 0 (off) or a positive number")
	}
	maxField, err := strconv.Atoi(env("WAF_MAX_FIELD_BYTES", "65536"))
	if err != nil || maxField < 0 {
		return nil, fmt.Errorf("WAF_MAX_FIELD_BYTES must be 0 (off) or a positive number")
	}
	maxInspect, err := strconv.Atoi(env("WAF_MAX_INSPECT_MS", "5000"))
	if err != nil || maxInspect < 0 {
		return nil, fmt.Errorf("WAF_MAX_INSPECT_MS must be 0 (off) or a positive number")
	}
	mlMode := strings.ToLower(env("ML_MODE", "detect"))
	if mlMode != "off" && mlMode != "detect" && mlMode != "block" {
		return nil, fmt.Errorf("ML_MODE must be off, detect or block")
	}
	mlThreshold, err := strconv.ParseFloat(env("ML_THRESHOLD", "0.9"), 64)
	if err != nil || mlThreshold <= 0 || mlThreshold >= 1 {
		return nil, fmt.Errorf("ML_THRESHOLD must be between 0 and 1, e.g. 0.9")
	}
	var mlSkip []string
	for _, p := range strings.Split(os.Getenv("ML_SKIP_PATHS"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			mlSkip = append(mlSkip, p)
		}
	}

	return &Config{
		Mode:              gmode,
		ExclusionsFile:    os.Getenv("EXCLUSIONS_FILE"),
		MetricsAddr:       os.Getenv("METRICS_ADDR"),
		AppProfile:        appProf,
		AppProfileMinSeen: appMin,
		DashboardAddr:     os.Getenv("DASHBOARD_ADDR"),
		DataDir:           dataDir(),
		ResponseCheck:     respCheck,
		ResponseMaxBytes:  respMax,
		TLSAutoDomains:    splitList(os.Getenv("TLS_AUTO_DOMAINS")),
		TLSAutoEmail:      os.Getenv("TLS_AUTO_EMAIL"),
		TLSAutoCache:      os.Getenv("TLS_AUTO_CACHE"),
		BotBlockScanners:  !strings.EqualFold(os.Getenv("BOT_BLOCK_SCANNERS"), "off") && !strings.EqualFold(os.Getenv("BOT_BLOCK_SCANNERS"), "false"),
		BotChallenge:      botMode,
		BotPaths:          splitList(env("BOT_CHALLENGE_PATHS", "/")),
		BotStrictPaths:    splitList(os.Getenv("BOT_STRICT_PATHS")),
		BotDifficulty:     botBits,
		AlertWebhookURL:   os.Getenv("ALERT_WEBHOOK_URL"),
		AlertTelegramChat: os.Getenv("ALERT_TELEGRAM_CHAT_ID"),
		AlertBurst:        burst,
		ExportSyslog:      os.Getenv("EXPORT_SYSLOG"),
		ExportOTLP:        os.Getenv("EXPORT_OTLP"),
		ExportOTLPHeaders: os.Getenv("EXPORT_OTLP_HEADERS"),
		ExportAll:         os.Getenv("EXPORT_ALL") == "true",
		KubeIngressClass:  os.Getenv("KUBERNETES_INGRESS_CLASS"),
		Profile:           strings.ToLower(os.Getenv("PROFILE")),
		ProfileData:       profile,
		CRSDir:            os.Getenv("CRS_DIR"),
		CRSParanoia:       paranoia,
		// 920220 (double URL encoding) flags any literal "%" such as "50%
		// off"; Sentinel's own rules already decode repeated encoding.
		CRSExclude:        splitList(env("CRS_EXCLUDE", "920220")),
		LoginFailLimit:    loginLimit,
		MaxFieldBytes:     maxField,
		MaxInspectMS:      maxInspect,
		SecurityHeaders:   !strings.EqualFold(os.Getenv("SECURITY_HEADERS"), "off"),
		MLMode:            mlMode,
		MLThreshold:       mlThreshold,
		MLSkipPaths:       mlSkip,
		Dashboard:         !strings.EqualFold(os.Getenv("DASHBOARD"), "off"),
		PromptGuardPaths:  pgPaths,
		PromptGuardMode:   pgMode,
		PromptThreshold:   pgThreshold,
		PromptCanary:      os.Getenv("PROMPT_CANARY"),
		TrustedProxies:    os.Getenv("TRUSTED_PROXIES"),
		RedisURL:          os.Getenv("REDIS_URL"),
		RateLimits:        os.Getenv("RATE_LIMITS"),
		Sites:             sites,
		HealthCheck:       health,
		HistoryDays:       historyDays,
		SecondOpinion:     !strings.EqualFold(os.Getenv("WAF_SECOND_OPINION"), "off") && !strings.EqualFold(os.Getenv("WAF_SECOND_OPINION"), "false"),
		GeoIPFile:         os.Getenv("GEOIP_FILE"),
		GeoDenyCountries:  os.Getenv("GEO_DENY_COUNTRIES"),
		GeoAllowCountries: os.Getenv("GEO_ALLOW_COUNTRIES"),
		IPDeny:            os.Getenv("IP_DENY"),
		IPAllow:           os.Getenv("IP_ALLOW"),
		RiskEnabled:       Pro && !strings.EqualFold(os.Getenv("RISK"), "off"),
		RiskStepUp:        stepUp,
		RiskBlock:         block,
		RiskHighCountries: os.Getenv("RISK_HIGH_COUNTRIES"),
		RiskQuietHours:    env("RISK_QUIET_HOURS", "00-05"),
		Timezone:          env("TZ", "UTC"),
		TLSListenAddr:     os.Getenv("TLS_LISTEN_ADDR"),
		TLSCertFile:       os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("TLS_KEY_FILE"),
		ClientCAFile:      os.Getenv("CLIENT_CA_FILE"),
		MTLSRoutes:        os.Getenv("MTLS_ROUTES"),
		TLSAutogenDir:     os.Getenv("TLS_AUTOGEN_DIR"),
		Upstreams:         env("UPSTREAMS", "/="+upstream.String()),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		Secret:            os.Getenv("SENTINEL_SECRET"),
		SeedUsersFile:     os.Getenv("SEED_USERS_FILE"),
		PolicyFile:        os.Getenv("POLICY_FILE"),
		AuditLogFile:      os.Getenv("AUDIT_LOG_FILE"),
		APISpecFile:       os.Getenv("API_SPEC_FILE"),
		APISpecPrefix:     os.Getenv("API_SPEC_PREFIX"),
		HoneypotPaths:     traps,
		HoneypotBan:       time.Duration(banMinutes) * time.Minute,
		ListenAddr:        env("LISTEN_ADDR", ":8080"),
		UpstreamURL:       upstream,
		WAFMode:           mode,
		WAFThreshold:      threshold,
		RulesFile:         os.Getenv("RULES_FILE"),
		MaxBodyBytes:      maxBody,
		LogFile:           os.Getenv("LOG_FILE"),
		TrustProxyHeaders: strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true"),
	}, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// dataDir: DATA_DIR, else /var/lib/sentinel when it exists (the Docker
// image), else ./sentinel-data.
func dataDir() string {
	if d := os.Getenv("DATA_DIR"); d != "" {
		return d
	}
	if fi, err := os.Stat("/var/lib/sentinel"); err == nil && fi.IsDir() {
		return "/var/lib/sentinel"
	}
	return "sentinel-data"
}
