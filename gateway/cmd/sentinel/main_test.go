package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/waf"
)

// End-to-end: a fake "protected app" behind a real gateway.
func setup(t *testing.T, mode string) (gateway *httptest.Server, hits *int) {
	t.Helper()
	count := 0
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Powered-By", "Express")
		w.Write([]byte("app ok: " + string(body)))
	}))
	t.Cleanup(app.Close)

	u, _ := url.Parse(app.URL)
	rules, err := waf.LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{UpstreamURL: u, WAFMode: mode, WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: 10 * time.Minute, Upstreams: "/=" + u.String(), APISpecPrefix: "/staff/api/",
		APISpecFile: labSpec}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, log)
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return gw, &count
}

// The tests run Sentinel with the lab's example configuration. labUsers
// holds the admin (with 2FA) and some non-admin accounts, which must not be
// able to log in.
const (
	labSpec  = "../../testdata/staff-api.openapi.json"
	labUsers = "../../testdata/demo-users.json"
	testTOTP = "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TF" // admin's secret in labUsers
)

func testAuth(t *testing.T) *auth.Service {
	t.Helper()
	keys, _ := auth.DeriveKeys(strings.Repeat("t", 40))
	svc, err := auth.NewService(auth.NewMemoryStore(), keys)
	if err != nil {
		t.Fatal(err)
	}
	users, err := auth.LoadSeedFile(labUsers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Seed(context.Background(), users); err != nil {
		t.Fatal(err)
	}
	return svc
}

func get(t *testing.T, u string) int {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestHoneypotBansAttacker(t *testing.T) {
	gw, hits := setup(t, "block")

	if code := get(t, gw.URL+"/"); code != 200 {
		t.Fatalf("normal page before trap: %d", code)
	}
	// The attacker sees an ordinary 404, nothing reveals the trap.
	if code := get(t, gw.URL+"/admin-backup"); code != 404 {
		t.Fatalf("honeypot should look like 404, got %d", code)
	}
	// Now everything from that IP is refused, even normal pages.
	if code := get(t, gw.URL+"/"); code != 403 {
		t.Fatalf("banned IP should get 403, got %d", code)
	}
	if *hits != 1 {
		t.Errorf("only the first normal request should reach the app, hits=%d", *hits)
	}
	// Health stays reachable so the demo script can check the lab.
	if code := get(t, gw.URL+"/__sentinel/health"); code != 200 {
		t.Errorf("health should bypass bans, got %d", code)
	}

}

func TestHoneypotMatchesSubpathsAndCase(t *testing.T) {
	for _, p := range []string{"/WP-ADMIN/install.php", "/.env", "/.git/config", "//backup.zip"} {
		t.Run(p, func(t *testing.T) {
			gw, _ := setup(t, "block")
			get(t, gw.URL+p)
			if code := get(t, gw.URL+"/"); code != 403 {
				t.Errorf("%s should trigger the honeypot, next request got %d", p, code)
			}
		})
	}
}

func TestCleanRequestReachesApp(t *testing.T) {
	gw, hits := setup(t, "block")
	resp, err := http.Post(gw.URL+"/api/Feedbacks", "application/json",
		strings.NewReader(`{"comment":"nice shop"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || *hits != 1 {
		t.Fatalf("status %d hits %d", resp.StatusCode, *hits)
	}
	if !strings.Contains(string(body), "nice shop") {
		t.Errorf("body was not forwarded intact: %s", body)
	}
	if resp.Header.Get("X-Powered-By") != "" {
		t.Error("X-Powered-By should be stripped")
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Error("missing X-Request-ID")
	}
}

func TestAttackBlockedBeforeApp(t *testing.T) {
	gw, hits := setup(t, "block")
	resp, err := http.Get(gw.URL + "/rest/products/search?q=" + url.QueryEscape("' OR 1=1--"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if *hits != 0 {
		t.Error("attack reached the app")
	}
	if strings.Contains(string(body), "SQLI") {
		t.Error("block page must not reveal which rule fired")
	}
}

func TestDetectModeLetsAttackThrough(t *testing.T) {
	gw, hits := setup(t, "detect")
	resp, err := http.Get(gw.URL + "/search?q=" + url.QueryEscape("<script>alert(1)</script>"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || *hits != 1 {
		t.Fatalf("detect mode should forward: status %d hits %d", resp.StatusCode, *hits)
	}
}

func TestHealthEndpoint(t *testing.T) {
	gw, hits := setup(t, "block")
	resp, err := http.Get(gw.URL + "/__sentinel/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || *hits != 0 {
		t.Fatalf("health: status %d, app hits %d", resp.StatusCode, *hits)
	}
}
