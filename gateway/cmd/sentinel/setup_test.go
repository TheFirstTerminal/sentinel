package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/waf"
)

// The whole first-run path a new user follows: the link from the log, the
// admin account, 2FA enrolment, then the dashboard.
func TestFirstRunSetupToDashboard(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer app.Close()
	u, _ := url.Parse(app.URL)
	keys, _ := auth.DeriveKeys(strings.Repeat("s", 40))
	svc, _ := auth.NewService(auth.NewMemoryStore(), keys) // no users
	logs := &lockedWriter{w: &strings.Builder{}}
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, Upstreams: "/=" + app.URL, WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, Dashboard: true, ListenAddr: ":8080"}
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), svc, nil, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	defer gw.Close()
	l := &lab{t: t, gw: gw, logBuf: logs.w}

	m := regexp.MustCompile(`"url":"http://localhost:8080/__sentinel/setup#([A-Za-z0-9_-]+)"`).FindStringSubmatch(logs.w.String())
	if m == nil {
		t.Fatalf("no setup link in the log:\n%s", logs.w.String())
	}
	tok := m[1]

	if code, _ := l.do("GET", "/__sentinel/setup", "", ""); code != 200 {
		t.Fatalf("setup page: %d", code)
	}
	if code, out := l.do("POST", "/__sentinel/setup/api", "", `{"token":"guess","username":"root","password":"long-enough-pass"}`); code != 403 {
		t.Fatalf("wrong token accepted: %d %v", code, out)
	}
	if code, out := l.do("POST", "/__sentinel/setup/api", "", `{"token":"`+tok+`","username":"root","password":"long-enough-pass"}`); code != 200 {
		t.Fatalf("setup: %d %v", code, out)
	}
	if code, _ := l.do("POST", "/__sentinel/setup/api", "", `{"token":"`+tok+`","username":"evil","password":"long-enough-pass"}`); code != 403 {
		t.Fatal("the link worked twice")
	}

	// Log in (no 2FA yet): the dashboard API refuses, enrolment works.
	_, out := l.do("POST", "/__sentinel/auth/login", "", `{"username":"root","password":"long-enough-pass"}`)
	first, _ := out["token"].(string)
	if code, _ := l.do("GET", "/__sentinel/api/stats", first, ""); code != 403 {
		t.Fatalf("dashboard open without 2FA: %d", code)
	}
	code, out := l.do("POST", "/__sentinel/auth/2fa/setup", first, "")
	secret, _ := out["secret"].(string)
	if qr, _ := out["qr"].(string); code != 200 || !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("2FA setup: %d, qr %.40q", code, out["qr"])
	}
	c, _ := auth.TOTPCode(secret, time.Now())
	if code, out := l.do("POST", "/__sentinel/auth/2fa/enable", first, `{"code":"`+c+`"}`); code != 200 {
		t.Fatalf("enable 2FA: %d %v", code, out)
	}

	// Log in again with a code: the dashboard opens.
	_, out = l.do("POST", "/__sentinel/auth/login", "", `{"username":"root","password":"long-enough-pass"}`)
	mfa, _ := out["mfa_token"].(string)
	c2, _ := auth.TOTPCode(secret, time.Now().Add(30*time.Second)) // the next code (the last one was used)
	code, out = l.do("POST", "/__sentinel/auth/verify-2fa", "", `{"mfa_token":"`+mfa+`","code":"`+c2+`"}`)
	if code != 200 {
		t.Fatalf("verify: %d %v", code, out)
	}
	full, _ := out["token"].(string)
	if code, _ := l.do("GET", "/__sentinel/api/stats", full, ""); code != 200 {
		t.Fatalf("dashboard with admin + 2FA: %d", code)
	}
	// The setup endpoint now says it's done.
	resp, _ := http.Get(gw.URL + "/__sentinel/setup/api")
	var st map[string]bool
	json.NewDecoder(resp.Body).Decode(&st)
	if st["active"] {
		t.Error("setup still active")
	}
}

// With its own port, the dashboard is not reachable on the public one.
func TestDashboardOnItsOwnPort(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("app page")) }))
	defer app.Close()
	u, _ := url.Parse(app.URL)
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, Upstreams: "/=" + app.URL, WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, Dashboard: true, ListenAddr: ":8080", DashboardAddr: ":9000"}
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(h)
	defer public.Close()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminPortKey{}, true)))
	}))
	defer admin.Close()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	code := func(base, path string) int {
		res, err := noFollow.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := code(public.URL, "/__sentinel/dashboard"); c != 404 {
		t.Errorf("dashboard on the public port: %d", c)
	}
	if c := code(public.URL, "/__sentinel/api/stats"); c != 404 {
		t.Errorf("dashboard API on the public port: %d", c)
	}
	if c := code(public.URL, "/products"); c != 200 {
		t.Errorf("app on the public port: %d", c)
	}
	if c := code(admin.URL, "/__sentinel/dashboard"); c != 200 {
		t.Errorf("dashboard on its port: %d", c)
	}
	if c := code(admin.URL, "/"); c != 302 {
		t.Errorf("admin port root should go to the dashboard: %d", c)
	}
	if c := code(admin.URL, "/products"); c != 302 {
		t.Errorf("the app must not be served on the admin port: %d", c)
	}
}
