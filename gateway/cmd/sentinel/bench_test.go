package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/waf"
)

// BenchmarkPipeline: CPU cost of one ordinary request through every check
// (no network). CRS_TEST_DIR adds the Core Rule Set.
func BenchmarkPipeline(b *testing.B) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(app)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	rules, _ := waf.LoadRules("")
	e := waf.NewEngine(rules, 5)
	if d := os.Getenv("CRS_TEST_DIR"); d != "" {
		s, _ := crs.Load(d, 1)
		e.UseCRS(s)
	}
	cfg := &config.Config{Mode: "protect", UpstreamURL: u, Upstreams: "/=" + srv.URL, WAFMode: "block", WAFThreshold: 5,
		MaxBodyBytes: 1 << 20, HoneypotBan: time.Hour, RateLimits: "/=100000000/1m",
		MLMode: "block", MLThreshold: 0.9, LoginFailLimit: 10, SecurityHeaders: true}
	authSvc, _ := benchAuth()
	h, err := NewHandler(cfg, e, authSvc, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var r *http.Request
		if i%2 == 0 {
			r = httptest.NewRequest("GET", "/products/search?q=apple+juice&page=2&sort=price", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
			r.Header.Set("Accept", "text/html,application/xhtml+xml")
			r.Header.Set("Cookie", "language=en; theme=dark")
		} else {
			r = httptest.NewRequest("POST", "/api/basket/items", strings.NewReader(`{"productId":12,"quantity":2,"note":"Please deliver after 5pm, thanks!"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("User-Agent", "Mozilla/5.0")
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
}
