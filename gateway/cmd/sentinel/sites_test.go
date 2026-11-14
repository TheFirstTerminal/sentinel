package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/waf"
)

// sitesLab runs Sentinel with SITES in front of named fake apps. Each app
// answers with its own name, so a test can see where a request went.
func sitesLab(t *testing.T, sitesJSON string, apps ...string) (gw *httptest.Server, logs *strings.Builder) {
	t.Helper()
	for _, name := range apps {
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, name) }))
		t.Cleanup(app.Close)
		sitesJSON = strings.ReplaceAll(sitesJSON, "{"+name+"}", app.URL)
	}
	sites, err := config.ParseSites(sitesJSON)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, Mode: "protect", WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, Upstreams: "/=" + u.String(), Sites: sites, Dashboard: true}
	logs = &strings.Builder{}
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, slog.New(slog.NewJSONHandler(&lockedWriter{w: logs}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gw = httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return gw, logs
}

func hostGet(t *testing.T, gw *httptest.Server, host, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", gw.URL+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const attack = "/?q=1'+UNION+SELECT+password+FROM+users--"

func TestSitesRouteByHost(t *testing.T) {
	gw, logs := sitesLab(t, `[
		{"name":"shop","hosts":["shop.test","www.shop.test"],"upstreams":["{shop}"]},
		{"name":"api","hosts":["api.test"],"routes":{"/v2/":"{v2}","/":"{api}"}},
		{"name":"sub","hosts":["*.example.test"],"upstreams":["{sub}"]},
		{"name":"deep","hosts":["*.a.example.test"],"upstreams":["{deep}"]}
	]`, "shop", "api", "v2", "sub", "deep")
	for _, c := range []struct{ host, path, want string }{
		{"shop.test", "/", "shop"},
		{"WWW.Shop.Test:8080", "/", "shop"}, // case and port don't matter
		{"api.test", "/users", "api"},
		{"api.test", "/v2/users", "v2"},
		{"blog.example.test", "/", "sub"},
		{"x.a.example.test", "/", "deep"}, // the longest wildcard wins
	} {
		if code, body := hostGet(t, gw, c.host, c.path); code != 200 || body != c.want {
			t.Errorf("%s%s: %d %q, want %q", c.host, c.path, code, body, c.want)
		}
	}
	// No site for this host: refused, never sent to some app.
	if code, body := hostGet(t, gw, "unknown.test", "/"); code != http.StatusMisdirectedRequest || strings.Contains(body, "shop") {
		t.Errorf("unknown host: %d %q", code, body)
	}
	if !strings.Contains(logs.String(), `"site":"api"`) {
		t.Error("log lines should name the site")
	}
	// Sentinel's own pages answer on any host.
	if code, _ := hostGet(t, gw, "unknown.test", "/__sentinel/dashboard"); code != 200 {
		t.Errorf("dashboard on an unknown host: %d", code)
	}
}

func TestSiteCatchAll(t *testing.T) {
	gw, _ := sitesLab(t, `[
		{"name":"shop","hosts":["shop.test"],"upstreams":["{shop}"]},
		{"name":"rest","hosts":["*"],"upstreams":["{rest}"]}
	]`, "shop", "rest")
	if _, body := hostGet(t, gw, "anything.test", "/"); body != "rest" {
		t.Errorf("catch-all site: %q", body)
	}
}

func TestSitesHaveTheirOwnMode(t *testing.T) {
	gw, logs := sitesLab(t, `[
		{"name":"live","hosts":["live.test"],"upstreams":["{live}"]},
		{"name":"new","hosts":["new.test"],"upstreams":["{new}"],"mode":"monitor"}
	]`, "live", "new")
	if code, _ := hostGet(t, gw, "live.test", attack); code != 403 {
		t.Errorf("protect site: attack got %d, want 403", code)
	}
	if code, body := hostGet(t, gw, "new.test", attack); code != 200 || body != "new" {
		t.Errorf("monitor site: attack got %d %q, want it forwarded", code, body)
	}
	if !strings.Contains(logs.String(), `"outcome":"detected"`) {
		t.Error("the monitor site should log the attack as detected")
	}
}

func TestSitesHaveTheirOwnRateLimits(t *testing.T) {
	gw, _ := sitesLab(t, `[
		{"name":"a","hosts":["a.test"],"upstreams":["{a}"],"rate_limits":{"/":"3/1m"}},
		{"name":"b","hosts":["b.test"],"upstreams":["{b}"],"rate_limits":{"/":"3/1m"}}
	]`, "a", "b")
	for i := 0; i < 3; i++ {
		hostGet(t, gw, "a.test", "/")
	}
	if code, _ := hostGet(t, gw, "a.test", "/"); code != 429 {
		t.Errorf("4th request to a: %d, want 429", code)
	}
	if code, _ := hostGet(t, gw, "b.test", "/"); code != 200 {
		t.Errorf("site b must have its own counter: %d", code)
	}
}

func TestSitesLoadBalance(t *testing.T) {
	gw, _ := sitesLab(t, `[{"name":"shop","hosts":["*"],"upstreams":["{one}","{two}"]}]`, "one", "two")
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		_, body := hostGet(t, gw, "shop.test", "/")
		seen[body]++
	}
	if seen["one"] != 3 || seen["two"] != 3 {
		t.Errorf("traffic not shared: %v", seen)
	}
}

func TestSitesConfig(t *testing.T) {
	vars, err := config.ParseFile([]byte(`
sites:
  - name: shop
    hosts: [shop.example.com]
    upstreams: [http://shop-1:3000, http://shop-2:3000]
    rate_limits: { /login: 10/1m }
    mode: monitor
`))
	if err != nil {
		t.Fatal(err)
	}
	sites, err := config.ParseSites(vars["SITES"])
	if err != nil || len(sites) != 1 || sites[0].Spec != "/=http://shop-1:3000|http://shop-2:3000" || sites[0].RateLimitSpec() != "/login=10/1m" {
		t.Fatalf("from YAML: %+v %v", sites, err)
	}
	for bad, why := range map[string]string{
		`[{"hosts":["a.test"],"upstreams":["http://a"]}]`:                                                                     "needs a name",
		`[{"name":"Shop!","hosts":["a.test"],"upstreams":["http://a"]}]`:                                                      "lowercase",
		`[{"name":"a","upstreams":["http://a"]}]`:                                                                             "needs hosts",
		`[{"name":"a","hosts":["a.test"]}]`:                                                                                   "needs upstreams",
		`[{"name":"a","hosts":["a.test"],"upstreams":["ftp://a"]}]`:                                                           "expected http",
		`[{"name":"a","hosts":["a.test"],"upstreams":["http://a"],"mode":"block"}]`:                                           "mode",
		`[{"name":"a","hosts":["a.test"],"upstreams":["http://a"]},{"name":"b","hosts":["a.test"],"upstreams":["http://b"]}]`: "already used",
		`[{"name":"a","hosts":["a.*.test"],"upstreams":["http://a"]}]`:                                                        "host",
		`[{"name":"a","hosts":["a.test"],"upstreams":["http://a"],"colour":"red"}]`:                                           "unknown field",
	} {
		if _, err := config.ParseSites(bad); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: want an error about %q, got %v", bad, why, err)
		}
	}
}
