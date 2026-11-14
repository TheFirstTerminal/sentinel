package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFile(t *testing.T) {
	got, err := ParseFile([]byte(`
mode: protect
upstream: http://app:3000
routes:
  /api/: http://api:8000
  /: http://web:3000
waf: {threshold: 7, crs: /crs}
ml: {mode: block, threshold: 0.95, skip_paths: [/socket.io/, /health]}
dashboard: false
rate_limits: {/: 600/1m}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"MODE": "protect", "UPSTREAM_URL": "http://app:3000",
		"UPSTREAMS":     "/api/=http://api:8000,/=http://web:3000",
		"WAF_THRESHOLD": "7", "CRS_DIR": "/crs", "ML_MODE": "block", "ML_THRESHOLD": "0.95",
		"ML_SKIP_PATHS": "/socket.io/,/health", "DASHBOARD": "off", "RATE_LIMITS": "/=600/1m",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestTyposAreRejected(t *testing.T) {
	_, err := ParseFile([]byte("waf:\n  treshold: 5\n"))
	if err == nil || !strings.Contains(err.Error(), "waf.treshold") || !strings.Contains(err.Error(), "WAF_THRESHOLD") {
		t.Fatalf("want an error naming waf.treshold, got %v", err)
	}
}

// The shipped example must always be valid and start in monitor mode.
func TestExampleIsValid(t *testing.T) {
	got, err := ParseFile(Example)
	if err != nil {
		t.Fatal(err)
	}
	if got["MODE"] != "monitor" {
		t.Errorf("example mode = %q", got["MODE"])
	}
}

func TestEnvironmentWinsOverFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(p, []byte("mode: protect\nwaf: {threshold: 9}\n"), 0o644)
	t.Setenv("MODE", "monitor")
	t.Setenv("WAF_THRESHOLD", "") // set but empty still counts as set
	os.Unsetenv("WAF_THRESHOLD")
	if _, err := ApplyFile(p); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("WAF_THRESHOLD")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "monitor" || c.WAFThreshold != 9 {
		t.Errorf("mode=%s threshold=%d", c.Mode, c.WAFThreshold)
	}
}

func TestDefaultIsMonitor(t *testing.T) {
	os.Unsetenv("MODE")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "monitor" {
		t.Errorf("default mode = %s", c.Mode)
	}
}

// Every file key in docs/configuration.md must be one the parser accepts,
// and every variable must be documented.
func TestDocumentedKeysParse(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/configuration.md")
	if err != nil {
		t.Skip("docs not found")
	}
	documented := map[string]bool{}
	for _, line := range strings.Split(string(doc), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 6 || !strings.Contains(cells[1], "`") { // settings tables have 4 columns
			continue
		}
		for _, v := range strings.Split(cells[2], "/") {
			documented[strings.Trim(strings.TrimSpace(v), "`")] = true
		}
		for _, key := range strings.Split(cells[1], "/") {
			key = strings.Trim(strings.TrimSpace(key), "`")
			// Build "a:\n  b: x" from "a.b".
			parts := strings.Split(key, ".")
			var y strings.Builder
			for i, p := range parts {
				y.WriteString(strings.Repeat("  ", i) + p + ":")
				if i < len(parts)-1 {
					y.WriteString("\n")
				}
			}
			y.WriteString(" x\n")
			if _, err := ParseFile([]byte(y.String())); err != nil {
				t.Errorf("documented key %q: %v", key, err)
			}
		}
	}
	pro := map[string]bool{}
	for _, v := range ProVariables {
		pro[v] = true
	}
	for _, v := range Variables {
		if !documented[v] && !pro[v] { // Pro settings are refused, not documented
			t.Errorf("variable %s is not in docs/configuration.md", v)
		}
	}
}

// Every Pro setting stops the free edition with a clear message.
func TestProSettingsAreRefused(t *testing.T) {
	for _, v := range ProVariables {
		t.Run(v, func(t *testing.T) {
			t.Setenv(v, "x")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "Sentinel Pro") {
				t.Errorf("%s=x: want a Sentinel Pro error, got %v", v, err)
			}
		})
	}
	t.Setenv("RISK", "off") // switching a Pro feature off is fine
	if _, err := Load(); err != nil {
		t.Errorf("RISK=off: %v", err)
	}
}

func TestProfileAndExclusionsFileFromEnvironment(t *testing.T) {
	t.Setenv("PROFILE", "wordpress")
	t.Setenv("EXCLUSIONS_FILE", "/tmp/x.yaml")
	t.Setenv("RATE_LIMITS", "") // set (empty) wins over the profile...
	os.Unsetenv("RATE_LIMITS")  // ...so unset it to get the profile's
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ExclusionsFile != "/tmp/x.yaml" || c.Profile != "wordpress" || c.ProfileData == nil {
		t.Fatalf("got %q %q %v", c.ExclusionsFile, c.Profile, c.ProfileData)
	}
	if !strings.Contains(c.RateLimits, "/wp-login.php=10/1m") {
		t.Errorf("profile rate limits not applied: %q", c.RateLimits)
	}
	os.Unsetenv("RATE_LIMITS")
	t.Setenv("PROFILE", "wordpres")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "wordpress") {
		t.Errorf("unknown profile: %v", err)
	}
}

// Every setting added in v0.9 must reach the Config through Load().
func TestNewSettingsAreRead(t *testing.T) {
	for k, v := range map[string]string{
		"METRICS_ADDR": ":9090", "ALERT_WEBHOOK_URL": "https://hooks.slack.com/x", "ALERT_TELEGRAM_CHAT_ID": "42", "ALERT_BURST": "7",
		"TLS_AUTO_DOMAINS": "a.example,b.example", "TLS_AUTO_EMAIL": "ops@example.com", "TLS_AUTO_CACHE": "/certs",
		"BOT_BLOCK_SCANNERS": "off", "BOT_CHALLENGE": "all", "BOT_CHALLENGE_PATHS": "/login,/signup", "BOT_DIFFICULTY": "12",
		"EXCLUSIONS_FILE": "/e.yaml", "PROFILE": "ai",
	} {
		t.Setenv(k, v)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%v|%v|%v|%v|%v|%v|%v|%v|%v|%v|%v|%v|%v", c.MetricsAddr, c.AlertWebhookURL, c.AlertTelegramChat, c.AlertBurst,
		c.TLSAutoDomains, c.TLSAutoEmail, c.TLSAutoCache, c.BotBlockScanners, c.BotChallenge, c.BotPaths, c.BotDifficulty, c.ExclusionsFile, c.Profile)
	want := ":9090|https://hooks.slack.com/x|42|7|[a.example b.example]|ops@example.com|/certs|false|all|[/login /signup]|12|/e.yaml|ai"
	if got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}
	t.Setenv("BOT_BLOCK_SCANNERS", "")
	if c, _ := Load(); !c.BotBlockScanners {
		t.Error("scanner blocking must be on by default")
	}
}
