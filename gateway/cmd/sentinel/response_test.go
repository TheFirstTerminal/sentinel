package main

import (
	"compress/gzip"
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

func TestResponseLeaks(t *testing.T) {
	sqlErr := "<b>Warning</b>: You have an error in your SQL syntax near '1''"
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sqlerr":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(500)
			io.WriteString(w, sqlErr)
		case "/card":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"card":"4111 1111 1111 1111","phone":"+964 770 123 4567"}`)
		case "/gz":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			io.WriteString(zw, "Traceback (most recent call last):\n  File \"app.py\"")
			zw.Close()
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: "+sqlErr+"\n\n")
			w.(http.Flusher).Flush()
		case "/flush":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "part 1\n")
			w.(http.Flusher).Flush()
			io.WriteString(w, sqlErr)
		case "/big":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, strings.Repeat("x", 2<<20)+sqlErr)
		case "/files/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<title>Index of /files/</title>")
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer app.Close()
	u, _ := url.Parse(app.URL)
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, Upstreams: "/=" + app.URL, WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, ResponseCheck: "block", ResponseMaxBytes: 1 << 20, ExclusionsFile: ""}
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	defer gw.Close()
	get := func(path string) (int, string, http.Header) {
		req, _ := http.NewRequest("GET", gw.URL+path, nil)
		req.Header.Set("Accept-Encoding", "gzip, br") // the transport then won't decode for us
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var rd io.Reader = res.Body
		if res.Header.Get("Content-Encoding") == "gzip" {
			rd, _ = gzip.NewReader(res.Body)
		}
		b, _ := io.ReadAll(rd)
		return res.StatusCode, string(b), res.Header
	}
	if code, body, _ := get("/sqlerr"); code != 500 || strings.Contains(body, "SQL syntax") || !strings.Contains(body, "withheld by Sentinel") {
		t.Errorf("SQL error leaked: %d %q", code, body)
	}
	if code, body, _ := get("/card"); code != 200 || strings.Contains(body, "4111 1111") || !strings.Contains(body, "************1111") || !strings.Contains(body, "+964 770 123 4567") {
		t.Errorf("card: %d %q", code, body)
	}
	if code, body, _ := get("/gz"); code != 500 || strings.Contains(body, "Traceback") {
		t.Errorf("gzip stack trace leaked: %d %q", code, body)
	}
	if _, body, _ := get("/stream"); !strings.Contains(body, "data: ") {
		t.Errorf("SSE stream broken: %q", body)
	}
	if code, body, _ := get("/flush"); code != 200 || !strings.HasPrefix(body, "part 1") {
		t.Errorf("flushed response broken: %d %q", code, body[:min(len(body), 40)])
	}
	if code, body, _ := get("/big"); code != 200 || len(body) < 2<<20 {
		t.Errorf("big response cut: %d %d", code, len(body))
	}
	if code, body, _ := get("/ok"); code != 200 || body != `{"ok":true}` {
		t.Errorf("normal response changed: %d %q", code, body)
	}
}
