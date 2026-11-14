package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func backend(t *testing.T, name string) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	healthy := &atomic.Bool{}
	healthy.Store(true)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, name)
	}))
	t.Cleanup(s.Close)
	return s, healthy
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Body.String()
}

func mustRoutes(t *testing.T, spec string) []Route {
	t.Helper()
	r, err := ParseRoutes(spec)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseRoutes(t *testing.T) {
	r := mustRoutes(t, "/api/=http://a:1|http://b:2, /=http://c:3")
	if len(r) != 2 || len(r[0].Upstreams) != 2 || r[1].Upstreams[0].Host != "c:3" {
		t.Fatalf("parsed %+v", r)
	}
	for _, bad := range []string{"", "api=http://a", "/=a:1", "/=http://a|", "/=http://a,/=http://b"} {
		if _, err := ParseRoutes(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestLongestPrefixWins(t *testing.T) {
	api, _ := backend(t, "api")
	web, _ := backend(t, "web")
	rt := NewRouter(mustRoutes(t, "/="+web.URL+",/api/="+api.URL), Options{}, quiet)
	defer rt.Close()
	if _, body := get(t, rt, "/api/x"); body != "api" {
		t.Errorf("/api/x went to %q", body)
	}
	if _, body := get(t, rt, "/shop"); body != "web" {
		t.Errorf("/shop went to %q", body)
	}
}

func TestRoundRobin(t *testing.T) {
	a, _ := backend(t, "a")
	b, _ := backend(t, "b")
	rt := NewRouter(mustRoutes(t, "/="+a.URL+"|"+b.URL), Options{}, quiet)
	defer rt.Close()
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		_, body := get(t, rt, "/")
		seen[body]++
	}
	if seen["a"] != 5 || seen["b"] != 5 {
		t.Errorf("requests not shared evenly: %v", seen)
	}
}

func TestDeadServerIsSkipped(t *testing.T) {
	a, _ := backend(t, "a")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close() // nothing listens here any more
	rt := NewRouter(mustRoutes(t, "/="+a.URL+"|"+dead), Options{DownFor: time.Minute}, quiet)
	defer rt.Close()
	fails := 0
	for i := 0; i < 10; i++ {
		if code, _ := get(t, rt, "/"); code != 200 {
			fails++
		}
	}
	if fails > 1 {
		t.Errorf("%d of 10 requests failed; after the first failure the dead server must be skipped", fails)
	}
	up := 0
	for _, s := range rt.Status() {
		if s.Up {
			up++
		}
	}
	if up != 1 {
		t.Errorf("status should show 1 server up: %+v", rt.Status())
	}
}

func TestHealthCheckTakesServerOutAndBack(t *testing.T) {
	a, _ := backend(t, "a")
	b, bHealthy := backend(t, "b")
	bHealthy.Store(false)
	rt := NewRouter(mustRoutes(t, "/="+a.URL+"|"+b.URL), Options{HealthPath: "/healthz", HealthInterval: 20 * time.Millisecond}, quiet)
	defer rt.Close()
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 6; i++ {
		if _, body := get(t, rt, "/"); body != "a" {
			t.Fatalf("unhealthy server got traffic")
		}
	}
	bHealthy.Store(true)
	time.Sleep(100 * time.Millisecond)
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		_, body := get(t, rt, "/")
		seen[body] = true
	}
	if !seen["b"] {
		t.Error("server did not come back after its health check passed")
	}
}

func TestSingleServerIsAlwaysTried(t *testing.T) {
	a, _ := backend(t, "a")
	u, _ := url.Parse(a.URL)
	rt := NewRouter([]Route{{Prefix: "/", Upstreams: []*url.URL{u}}}, Options{}, quiet)
	defer rt.Close()
	rt.routes[0].servers[0].downUntil.Store(time.Now().Add(time.Hour).UnixNano())
	if code, _ := get(t, rt, "/"); code != 200 {
		t.Errorf("a single server marked down must still be tried, got %d", code)
	}
}

func TestHeaders(t *testing.T) {
	var got http.Header
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("X-Powered-By", "PHP/5.4")
		w.Header().Set("Server", "Apache/2.2")
	}))
	defer app.Close()
	rt := NewRouter(mustRoutes(t, "/="+app.URL), Options{}, quiet)
	defer rt.Close()
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got.Get("X-Protected-By") != "Sentinel" || got.Get("X-Forwarded-For") == "" {
		t.Errorf("app headers: %v", got)
	}
	if rec.Header().Get("X-Powered-By") != "" || rec.Header().Get("Server") != "" {
		t.Errorf("technology headers must be hidden: %v", rec.Header())
	}
}
