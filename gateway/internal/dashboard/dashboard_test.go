package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/blocklist"
	"sentinel/gateway/internal/events"
	"sentinel/gateway/internal/reqctx"
)

// call sends one API request as the given identity (nil = not logged in).
func call(d *Dashboard, id *reqctx.Identity, method, path, body string) (int, string) {
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rb)
	info := &reqctx.Info{ID: "test"}
	if id != nil {
		info.SetUser(id)
	}
	r = r.WithContext(reqctx.With(r.Context(), info))
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

var admin = &reqctx.Identity{Username: "admin", Role: "admin", MFA: true}

func newDash(t *testing.T) *Dashboard {
	t.Helper()
	hub := events.NewHub(100)
	hist, err := events.OpenHistory(t.TempDir(), 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hist.Close)
	hub.Persist(hist)
	return &Dashboard{Hub: hub, Bans: blocklist.New(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Info: Info{Version: "test"}}
}

func TestDashboardNeedsAnAdminWith2FA(t *testing.T) {
	d := newDash(t)
	for _, p := range []string{"stats", "events", "history", "bans", "info", "sites"} {
		if code, _ := call(d, nil, "GET", APIPrefix+p, ""); code != 401 {
			t.Errorf("%s without a login: %d, want 401", p, code)
		}
		if code, _ := call(d, &reqctx.Identity{Username: "admin", Role: "admin"}, "GET", APIPrefix+p, ""); code != 403 {
			t.Errorf("%s as an admin without 2FA: %d, want 403", p, code)
		}
		if code, _ := call(d, &reqctx.Identity{Username: "bob", Role: "employee", MFA: true}, "GET", APIPrefix+p, ""); code != 403 {
			t.Errorf("%s as a non-admin: %d, want 403", p, code)
		}
	}
	if code, body := call(d, nil, "GET", PagePath, ""); code != 200 || !strings.Contains(body, "<html") {
		t.Errorf("the page itself is public (a login form): %d", code)
	}
}

func TestDashboardBans(t *testing.T) {
	d := newDash(t)
	if code, _ := call(d, admin, "POST", APIPrefix+"bans", `{"ip":"203.0.113.9","minutes":5}`); code != 200 {
		t.Fatalf("ban: %d", code)
	}
	if !d.Bans.Banned("203.0.113.9") {
		t.Error("the IP should be banned")
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"bans", `{"ip":"not-an-ip"}`); code != 400 {
		t.Errorf("a bad IP must be refused: %d", code)
	}
	if code, _ := call(d, admin, "DELETE", APIPrefix+"bans/203.0.113.9", ""); code != 200 || d.Bans.Banned("203.0.113.9") {
		t.Errorf("unban: %d", code)
	}
	if code, _ := call(d, admin, "DELETE", APIPrefix+"bans/203.0.113.9", ""); code != 404 {
		t.Errorf("unban what isn't banned: %d", code)
	}
}

func TestDashboardStatsAndHistory(t *testing.T) {
	d := newDash(t)
	now := time.Now()
	d.Hub.Publish(events.Event{Time: now, Outcome: "blocked", Site: "shop", Path: "/a", Rule: "SQLI-001", ClientIP: "198.51.100.1"})
	d.Hub.Publish(events.Event{Time: now, Outcome: "blocked", Site: "api", Path: "/b", Rule: "XSS-001"})
	d.Hub.Publish(events.Event{Time: now, Outcome: "allowed", Site: "shop", Path: "/c"})

	var st events.Stats
	_, body := call(d, admin, "GET", APIPrefix+"stats?site=shop", "")
	json.Unmarshal([]byte(body), &st)
	if st.Total != 2 || st.Stopped != 1 {
		t.Errorf("stats for one site: %+v", st)
	}

	var list []events.Event
	_, body = call(d, admin, "GET", APIPrefix+"history?stopped=1&site=shop", "")
	json.Unmarshal([]byte(body), &list)
	if len(list) != 1 || list[0].Rule != "SQLI-001" {
		t.Errorf("history: %s", body)
	}
	_, body = call(d, admin, "GET", APIPrefix+"history?q=198.51.100", "")
	json.Unmarshal([]byte(body), &list)
	if len(list) != 1 {
		t.Errorf("history text search: %s", body)
	}
	if code, _ := call(d, admin, "GET", APIPrefix+"history?from=yesterday", ""); code != 400 {
		t.Errorf("a bad time must be refused: %d", code)
	}
}

func TestDashboardSites(t *testing.T) {
	d := newDash(t)
	if code, body := call(d, admin, "GET", APIPrefix+"sites", ""); code != 200 || strings.TrimSpace(body) != "[]" {
		t.Errorf("no sites known yet: %d %s", code, body)
	}
	var gotSite, gotMode string
	d.Sites = func() []SiteStatus { return []SiteStatus{{Name: "shop", Mode: "monitor"}} }
	d.SetMode = func(site, mode string) error {
		if mode != "monitor" && mode != "protect" {
			return errors.New("mode must be monitor or protect")
		}
		gotSite, gotMode = site, mode
		return nil
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"sites/shop/mode", `{"mode":"protect"}`); code != 200 || gotSite != "shop" || gotMode != "protect" {
		t.Errorf("switch mode: %d %q %q", code, gotSite, gotMode)
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"sites/_/mode", `{"mode":"monitor"}`); code != 200 || gotSite != "" {
		t.Errorf("\"_\" is the only, unnamed site: %d %q", code, gotSite)
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"sites/shop/mode", `{"mode":"off"}`); code != 400 {
		t.Errorf("a bad mode must be refused: %d", code)
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"sites/shop/mode", `not json`); code != 400 {
		t.Errorf("bad JSON must be refused: %d", code)
	}
}

func TestDashboardPageHeaders(t *testing.T) {
	d := newDash(t)
	r := httptest.NewRequest("GET", PagePath, nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	h := w.Result().Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("the page must not be framed: %v", h)
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control: %q", h.Get("Cache-Control"))
	}
}
