package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// A config file is an easier way to write the same settings as the
// environment variables. Each key maps to one variable: nested keys are
// joined with "_" (waf.threshold -> WAF_THRESHOLD), and a few have short
// names (upstream -> UPSTREAM_URL). An environment variable always wins over
// the file, so Docker and Kubernetes can override single settings.

// aliases maps short file keys to their variable.
var aliases = map[string]string{
	"LISTEN":                  "LISTEN_ADDR",
	"METRICS_LISTEN":          "METRICS_ADDR",
	"DASHBOARD_LISTEN":        "DASHBOARD_ADDR",
	"ALERTS_WEBHOOK_URL":      "ALERT_WEBHOOK_URL",
	"ALERTS_TELEGRAM_CHAT_ID": "ALERT_TELEGRAM_CHAT_ID",
	"ALERTS_BURST":            "ALERT_BURST",
	"LOG_FORMAT":              "LOG_FORMAT",
	"UPSTREAM":                "UPSTREAM_URL",
	"ROUTES":                  "UPSTREAMS",
	"SECRET":                  "SENTINEL_SECRET",
	"TIMEZONE":                "TZ",
	"WAF_CRS":                 "CRS_DIR",
	"WAF_CRS_PARANOIA":        "CRS_PARANOIA",
	"WAF_CRS_EXCLUDE":         "CRS_EXCLUDE",
	"WAF_RULES_FILE":          "RULES_FILE",
	"GEO_FILE":                "GEOIP_FILE",
	"RISK_ENABLED":            "RISK",
	"TLS_LISTEN":              "TLS_LISTEN_ADDR",
	"TLS_CLIENT_CA_FILE":      "CLIENT_CA_FILE",
	"TLS_MTLS_ROUTES":         "MTLS_ROUTES",
	"PROMPT_GUARD_CANARY":     "PROMPT_CANARY",
	"API_SPEC_FILE":           "API_SPEC_FILE",
	"HONEYPOT_BAN":            "HONEYPOT_BAN_MINUTES",
	"DASHBOARD_ENABLED":       "DASHBOARD",
	"WAF_MAX_FIELD":           "WAF_MAX_FIELD_BYTES",
	"PROMPT_GUARD_ENDPOINT":   "PROMPT_GUARD_PATHS",
}

// Pro is true in Sentinel Pro builds. The free edition accepts Pro settings
// only to refuse them with a clear message (see Load).
var Pro bool

// ProVariables are Sentinel Pro settings.
var ProVariables = []string{"POLICY_FILE", "SEED_USERS_FILE", "AUDIT_LOG_FILE", "CLIENT_CA_FILE", "MTLS_ROUTES", "TLS_AUTOGEN_DIR",
	"RISK", "RISK_STEP_UP", "RISK_BLOCK", "RISK_HIGH_COUNTRIES", "RISK_QUIET_HOURS",
	"SSO_ISSUER", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET", "SSO_URL", "SSO_ROLE_CLAIM", "SSO_ROLES", "SSO_DEPARTMENT_CLAIM", "SSO_SCOPES", "SSO_SESSION_HOURS", "SSO_ALLOWED_DOMAINS",
	"LICENSE_KEY", "LICENSE_FILE"}

// Variables is every setting Sentinel reads. A file key that maps to none
// of them is a mistake (usually a typo) and stops the start.
var Variables = []string{
	"MODE", "PROFILE", "APP_PROFILE", "APP_PROFILE_MIN_SEEN", "DASHBOARD_ADDR", "DATA_DIR", "RESPONSE_CHECK", "RESPONSE_MAX_BYTES", "BOT_BLOCK_SCANNERS", "BOT_CHALLENGE", "BOT_CHALLENGE_PATHS", "BOT_DIFFICULTY", "LISTEN_ADDR", "METRICS_ADDR", "ALERT_WEBHOOK_URL", "ALERT_TELEGRAM_CHAT_ID", "ALERT_BURST", "UPSTREAM_URL", "UPSTREAMS", "SITES", "HEALTH_CHECK", "HISTORY_DAYS", "SENTINEL_SECRET", "TZ",
	"WAF_MODE", "WAF_THRESHOLD", "WAF_SECOND_OPINION", "RULES_FILE", "CRS_DIR", "CRS_PARANOIA", "CRS_EXCLUDE", "EXCLUSIONS_FILE", "MAX_BODY_BYTES", "WAF_MAX_FIELD_BYTES",
	"LOG_FILE", "LOG_FORMAT", "AUDIT_LOG_FILE", "TRUST_PROXY_HEADERS", "TRUSTED_PROXIES",
	"HONEYPOT_PATHS", "HONEYPOT_BAN_MINUTES",
	"DATABASE_URL", "SEED_USERS_FILE", "POLICY_FILE", "API_SPEC_FILE", "API_SPEC_PREFIX",
	"REDIS_URL", "RATE_LIMITS", "LOGIN_FAIL_LIMIT",
	"GEOIP_FILE", "GEO_DENY_COUNTRIES", "GEO_ALLOW_COUNTRIES", "IP_DENY", "IP_ALLOW",
	"RISK", "RISK_STEP_UP", "RISK_BLOCK", "RISK_HIGH_COUNTRIES", "RISK_QUIET_HOURS",
	"TLS_LISTEN_ADDR", "TLS_AUTO_DOMAINS", "TLS_AUTO_EMAIL", "TLS_AUTO_CACHE", "TLS_CERT_FILE", "TLS_KEY_FILE", "CLIENT_CA_FILE", "MTLS_ROUTES", "TLS_AUTOGEN_DIR",
	"DASHBOARD", "SECURITY_HEADERS",
	"PROMPT_GUARD_PATHS", "PROMPT_GUARD_MODE", "PROMPT_GUARD_THRESHOLD", "PROMPT_CANARY",
	"ML_MODE", "ML_THRESHOLD", "ML_SKIP_PATHS",
	"EXPORT_SYSLOG", "EXPORT_OTLP", "EXPORT_OTLP_HEADERS", "EXPORT_ALL",
	"SSO_ISSUER", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET", "SSO_URL", "SSO_ROLE_CLAIM", "SSO_ROLES", "SSO_DEPARTMENT_CLAIM", "SSO_SCOPES", "SSO_SESSION_HOURS", "SSO_ALLOWED_DOMAINS",
	"LICENSE_KEY", "LICENSE_FILE",
}

// ApplyFile reads a YAML config file and sets every variable it defines that
// the environment does not already set. It returns the variables it set.
func ApplyFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vars, err := ParseFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var set []string
	for name, value := range vars {
		if _, inEnv := os.LookupEnv(name); inEnv {
			continue // the environment wins
		}
		os.Setenv(name, value)
		set = append(set, name)
	}
	sort.Strings(set)
	return set, nil
}

// ParseFile turns config file contents into variable=value pairs.
func ParseFile(data []byte) (map[string]string, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, v := range Variables {
		known[v] = true
	}
	out := map[string]string{}
	var walk func(prefix string, m map[string]any) error
	walk = func(prefix string, m map[string]any) error {
		for k, v := range m {
			name := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(k, "-", "_"), ".", "_"))
			if prefix != "" {
				name = prefix + "_" + name
			}
			if a, ok := aliases[name]; ok {
				name = a
			}
			if sub, ok := v.(map[string]any); ok && !known[name] {
				if err := walk(name, sub); err != nil {
					return err
				}
				continue
			}
			if !known[name] {
				msg := fmt.Sprintf("unknown setting %q", fileKey(prefix, k))
				if s := closest(name); s != "" {
					msg += fmt.Sprintf(" (did you mean the one the variable %s sets?)", s)
				}
				return fmt.Errorf("%s; docs/configuration.md lists every setting", msg)
			}
			s, err := scalar(name, v)
			if err != nil {
				return err
			}
			out[name] = s
		}
		return nil
	}
	if err := walk("", root); err != nil {
		return nil, err
	}
	return out, nil
}

// scalar writes a file value the way its variable expects it: lists are
// comma separated, maps become "key=value,...", booleans become true/off.
func scalar(name string, v any) (string, error) {
	if name == "SITES" { // a list of sites: kept as JSON
		if str, ok := v.(string); ok {
			return str, nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("sites: %v", err)
		}
		return string(b), nil
	}
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case bool:
		if x {
			return "true", nil
		}
		return "off", nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			s, err := scalar(name, item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Longest prefix first, the order route matching uses anyway.
		sort.Slice(keys, func(i, j int) bool {
			return len(keys[i]) > len(keys[j]) || len(keys[i]) == len(keys[j]) && keys[i] < keys[j]
		})
		parts := make([]string, 0, len(x))
		for _, k := range keys {
			s, err := scalar(name, x[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, k+"="+s)
		}
		return strings.Join(parts, ","), nil
	}
	return "", fmt.Errorf("%s: unsupported value %v", name, v)
}

func fileKey(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return strings.ToLower(prefix) + "." + k
}

// closest finds the known variable nearest to a mistyped name.
func closest(name string) string {
	best, bestD := "", 3 // at most 2 edits away
	for _, v := range Variables {
		if d := editDistance(name, v); d < bestD {
			best, bestD = v, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
