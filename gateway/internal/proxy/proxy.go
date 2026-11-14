// Package proxy forwards clean requests to the protected application.
//
// A reverse proxy receives the client's request, makes the same request to
// the real server, and sends the answer back. The client never talks to the
// app directly, which is what lets Sentinel inspect and block traffic.
package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Route sends every path starting with Prefix to Upstream.
type Route struct {
	Prefix   string
	Upstream *url.URL
}

// NewRouter picks the upstream by the longest matching prefix, so
// "/staff/" goes to the Staff API and everything else ("/") to Juice Shop.
func NewRouter(routes []Route, log *slog.Logger) http.Handler {
	sorted := append([]Route(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Prefix) > len(sorted[j].Prefix) })
	handlers := make([]http.Handler, len(sorted))
	for i, rt := range sorted {
		handlers[i] = New(rt.Upstream, log)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i, rt := range sorted {
			if strings.HasPrefix(r.URL.Path, rt.Prefix) {
				handlers[i].ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
}

// ParseRoutes reads "PREFIX=URL,PREFIX=URL" (the UPSTREAMS setting).
func ParseRoutes(spec string) ([]Route, error) {
	var routes []Route
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, raw, ok := strings.Cut(part, "=")
		u, err := url.Parse(strings.TrimSpace(raw))
		if !ok || !strings.HasPrefix(prefix, "/") || err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("bad upstream %q, expected /prefix=http://host:port", part)
		}
		routes = append(routes, Route{Prefix: strings.TrimSpace(prefix), Upstream: u})
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	return routes, nil
}

func New(upstream *url.URL, log *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host // keep the original Host header
			pr.SetXForwarded()       // tell the app the real client IP
			pr.Out.Header.Set("X-Protected-By", "Sentinel")
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
		},
		ModifyResponse: func(resp *http.Response) error {
			// Hide what technology the app runs on; attackers use it to pick exploits.
			resp.Header.Del("X-Powered-By")
			resp.Header.Del("Server")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream_error", "path", r.URL.Path, "error", err.Error())
			http.Error(w, "protected application is unavailable", http.StatusBadGateway)
		},
	}
}
