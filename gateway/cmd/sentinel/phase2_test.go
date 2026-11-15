package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/waf"
)

// lab: Sentinel in front of a fake app that records what it received.
type lab struct {
	t       *testing.T
	gw      *httptest.Server
	mu      sync.Mutex
	hits    int
	lastHdr http.Header
	logBuf  *strings.Builder
}

func newLab(t *testing.T) *lab { return newLabWith(t, nil) }

// newLabWith lets a test change the configuration first.
func newLabWith(t *testing.T, change func(*config.Config)) *lab {
	t.Helper()
	l := &lab{t: t, logBuf: &strings.Builder{}}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.hits++
		l.lastHdr = r.Header.Clone()
		l.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(app.Close)
	u, _ := url.Parse(app.URL)
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, Upstreams: "/=" + u.String(), APISpecPrefix: "/staff/api/",
		APISpecFile: labSpec}
	if change != nil {
		change(cfg)
	}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{w: l.logBuf}, nil))
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, log)
	if err != nil {
		t.Fatal(err)
	}
	l.gw = httptest.NewServer(h)
	t.Cleanup(l.gw.Close)
	return l
}

type lockedWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

func (l *lab) do(method, path, token, body string, hdr ...string) (int, map[string]any) {
	l.t.Helper()
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, l.gw.URL+path, rb)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (l *lab) appHits() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits
}

func (l *lab) login(user, pass string) string {
	l.t.Helper()
	code, out := l.do("POST", "/__sentinel/auth/login", "", `{"username":"`+user+`","password":"`+pass+`"}`)
	if code != 200 {
		l.t.Fatalf("login %s: %d %v", user, code, out)
	}
	if out["mfa_required"] == true {
		c, _ := auth.TOTPCode(testTOTP, time.Now())
		code, out = l.do("POST", "/__sentinel/auth/verify-2fa", "", `{"mfa_token":"`+out["mfa_token"].(string)+`","code":"`+c+`"}`)
		if code != 200 {
			l.t.Fatalf("2fa %s: %d %v", user, code, out)
		}
	}
	return out["token"].(string)
}

func TestLoginErrors(t *testing.T) {
	l := newLab(t)
	if code, out := l.do("POST", "/__sentinel/auth/login", "", `{"username":"alice","password":"wrong"}`); code != 401 || out["error"] != "invalid username or password" {
		t.Errorf("wrong password: %d %v", code, out)
	}
	if code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"alice","password":"x","role":"admin"}`); code != 400 {
		t.Errorf("unknown JSON fields on login must be rejected, got %d", code)
	}
	_, out := l.do("POST", "/__sentinel/auth/login", "", `{"username":"admin","password":"Admin#2026"}`)
	if out["mfa_required"] != true || out["token"] != nil {
		t.Fatalf("admin password alone must not give a token: %v", out)
	}
	if code, _ := l.do("POST", "/__sentinel/auth/verify-2fa", "", `{"mfa_token":"`+out["mfa_token"].(string)+`","code":"000000"}`); code != 401 {
		t.Errorf("wrong 2FA code: %d", code)
	}
	// Logins are for Sentinel's administrators only: a non-admin account
	// (left in a shared database, say) gets the same answer as a wrong
	// password, even with its right password.
	if code, out := l.do("POST", "/__sentinel/auth/login", "", `{"username":"alice","password":"Alice#2026"}`); !config.Pro && (code != 401 || out["token"] != nil) {
		t.Errorf("non-admin login must be refused: %d %v", code, out)
	}
}

func TestIdentityHeadersAndTokenHandling(t *testing.T) {
	l := newLab(t)
	admin := l.login("admin", "Admin#2026")

	// A client claiming an identity via headers gets nowhere: they're stripped.
	l.do("GET", "/staff/api/health", "", "", "X-Sentinel-Role", "admin", "X-Sentinel-User", "admin", "X-Sentinel-Client", "payroll")
	for _, h := range []string{"X-Sentinel-User", "X-Sentinel-Role", "X-Sentinel-Client"} {
		if v := l.lastHdr.Get(h); v != "" {
			t.Errorf("%s must be stripped, the app got %q", h, v)
		}
	}

	// The app's own Authorization header passes through untouched, and a
	// Sentinel admin token sent to the app gives it no identity headers.
	l.do("GET", "/rest/basket/1", "shop-own-token", "")
	if l.lastHdr.Get("Authorization") != "Bearer shop-own-token" {
		t.Errorf("the app's token must be forwarded untouched, got %q", l.lastHdr.Get("Authorization"))
	}
	l.do("GET", "/rest/basket/1", admin, "")
	if l.lastHdr.Get("X-Sentinel-User") != "" {
		t.Error("no identity headers for the apps in the free edition")
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	l := newLab(t)
	admin := l.login("admin", "Admin#2026")
	if code, out := l.do("GET", "/__sentinel/auth/me", admin, ""); code != 200 || out["user"] != "admin" {
		t.Fatalf("me: %d %v", code, out)
	}
	l.do("POST", "/__sentinel/auth/logout", admin, "")
	if code, _ := l.do("GET", "/__sentinel/auth/me", admin, ""); code != 401 {
		t.Fatalf("token must be dead after logout: %d", code)
	}
}

func TestDecisionsAreLoggedForWatch(t *testing.T) {
	l := newLab(t)
	l.login("admin", "Admin#2026")
	l.do("PUT", "/staff/api/employees/alice", "", `{"salary":9999999}`)
	l.do("GET", "/rest/products/search?q="+url.QueryEscape("' OR 1=1--"), "", "")

	logs := l.logBuf.String()
	for _, want := range []string{
		`"outcome":"mfa_ok"`,
		`"outcome":"invalid","reason":"field 'salary' is not allowed"`,
		`"outcome":"blocked"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log missing %s", want)
		}
	}
}

// doForm posts a form body from the given client IP.
func (l *lab) doForm(path, body, ip string) (int, string) {
	l.t.Helper()
	req, _ := http.NewRequest("POST", l.gw.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
