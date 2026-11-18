// Package proxy forwards clean requests to the protected application.
//
// A reverse proxy receives the client's request, makes the same request to
// the real server, and sends the answer back. The client never talks to the
// app directly, which is what lets Sentinel inspect and block traffic.
//
// A route can have several servers. Requests are spread over them in turn
// (round robin), and a server that is down is skipped: it is taken out when
// a connection to it fails or its health check fails, and put back when its
// health check passes again.
package proxy

import (
	"sentinel/gateway/internal/reqctx"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Route sends every path starting with Prefix to one of its Upstreams.
type Route struct {
	Prefix    string
	Upstreams []*url.URL
}

// Options tune how servers are checked.
type Options struct {
	HealthPath     string        // e.g. "/healthz"; "" = no active checks
	HealthInterval time.Duration // default 10s
	DownFor        time.Duration // how long a failed server is skipped without a health check; default 10s
}

// Router picks the route by the longest matching prefix, then a server.
type Router struct {
	routes []*pool
	log    *slog.Logger
	stop   context.CancelFunc
}

// NewRouter builds the router and, with a health path, starts the checks.
// Call Close to stop them.
func NewRouter(routes []Route, opt Options, log *slog.Logger) *Router {
	if opt.HealthInterval <= 0 {
		opt.HealthInterval = 10 * time.Second
	}
	if opt.DownFor <= 0 {
		opt.DownFor = 10 * time.Second
	}
	sorted := append([]Route(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].Prefix) > len(sorted[j].Prefix) })
	ctx, cancel := context.WithCancel(context.Background())
	rt := &Router{log: log, stop: cancel}
	for _, r := range sorted {
		p := &pool{prefix: r.Prefix, downFor: opt.DownFor, log: log}
		for _, u := range r.Upstreams {
			s := &server{url: u}
			s.proxy = newReverseProxy(u, p, s, log)
			p.servers = append(p.servers, s)
		}
		if opt.HealthPath != "" {
			for _, s := range p.servers {
				go p.check(ctx, s, opt.HealthPath, opt.HealthInterval)
			}
		}
		rt.routes = append(rt.routes, p)
	}
	return rt
}

// Close stops the health checks.
func (rt *Router) Close() { rt.stop() }

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, p := range rt.routes {
		if strings.HasPrefix(r.URL.Path, p.prefix) {
			s := p.pick()
			if s == nil {
				rt.log.Error("upstream_error", "path", r.URL.Path, "error", "every server for "+p.prefix+" is down")
				http.Error(w, "protected application is unavailable", http.StatusBadGateway)
				return
			}
			s.proxy.ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// Status is one server's state, for the dashboard.
type Status struct {
	Prefix string `json:"prefix"`
	URL    string `json:"url"`
	Up     bool   `json:"up"`
}

// Status lists every server and whether it is in use.
func (rt *Router) Status() []Status {
	var out []Status
	for _, p := range rt.routes {
		for _, s := range p.servers {
			out = append(out, Status{Prefix: p.prefix, URL: s.url.String(), Up: s.available(time.Now())})
		}
	}
	return out
}

type server struct {
	url       *url.URL
	proxy     http.Handler
	unhealthy atomic.Bool  // health check failing
	downUntil atomic.Int64 // unix nanos: skipped after a failed connection
}

func (s *server) available(now time.Time) bool {
	return !s.unhealthy.Load() && now.UnixNano() >= s.downUntil.Load()
}

type pool struct {
	prefix  string
	servers []*server
	next    atomic.Uint64
	downFor time.Duration
	log     *slog.Logger
}

// pick returns the next available server, or nil when all are down. With
// one server that is down, it is still tried: refusing without trying would
// keep a single-server app offline until the next health check.
func (p *pool) pick() *server {
	now := time.Now()
	n := len(p.servers)
	start := p.next.Add(1)
	for i := 0; i < n; i++ {
		s := p.servers[(start+uint64(i))%uint64(n)]
		if s.available(now) {
			return s
		}
	}
	if n == 1 {
		return p.servers[0]
	}
	return nil
}

// failed takes a server out for a while after a failed connection.
func (p *pool) failed(s *server, err error) {
	if len(p.servers) > 1 {
		s.downUntil.Store(time.Now().Add(p.downFor).UnixNano())
		p.log.Warn("upstream_down", "server", s.url.String(), "for", p.downFor.String(), "error", err.Error())
	}
}

func (p *pool) check(ctx context.Context, s *server, path string, every time.Duration) {
	client := &http.Client{Timeout: 3 * time.Second}
	target := s.url.ResolveReference(&url.URL{Path: path}).String()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := client.Do(req)
		ok := err == nil && resp.StatusCode < 500
		if resp != nil {
			resp.Body.Close()
		}
		if was := !s.unhealthy.Load(); was != ok {
			s.unhealthy.Store(!ok)
			if ok {
				p.log.Info("upstream_up", "server", s.url.String())
			} else {
				why := "status 5xx"
				if err != nil {
					why = err.Error()
				}
				p.log.Warn("upstream_unhealthy", "server", s.url.String(), "check", target, "error", why)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ParseRoutes reads "PREFIX=URL|URL,PREFIX=URL" (the UPSTREAMS setting).
// Several URLs separated by "|" share the route's traffic.
func ParseRoutes(spec string) ([]Route, error) {
	var routes []Route
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, raw, ok := strings.Cut(part, "=")
		prefix = strings.TrimSpace(prefix)
		if !ok || !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("bad upstream %q, expected /prefix=http://host:port", part)
		}
		if seen[prefix] {
			return nil, fmt.Errorf("upstream prefix %q is listed twice", prefix)
		}
		seen[prefix] = true
		rt := Route{Prefix: prefix}
		for _, one := range strings.Split(raw, "|") {
			u, err := url.Parse(strings.TrimSpace(one))
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, fmt.Errorf("bad upstream %q in %q, expected http://host:port", one, part)
			}
			rt.Upstreams = append(rt.Upstreams, u)
		}
		routes = append(routes, rt)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	return routes, nil
}

func newReverseProxy(upstream *url.URL, p *pool, s *server, log *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host // keep the original Host header
			pr.SetXForwarded()       // tell the app the real client IP
			// Behind a trusted load balancer the connection's address is
			// the balancer: pass on the client IP Sentinel worked out.
			if ip := reqctx.From(pr.In.Context()).ClientIP; ip != "" {
				pr.Out.Header.Set("X-Forwarded-For", ip)
			}
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
			var op *net.OpError
			if errors.As(err, &op) && op.Op == "dial" {
				p.failed(s, err) // couldn't connect: skip this server for a while
			}
			log.Error("upstream_error", "path", r.URL.Path, "server", upstream.Host, "error", err.Error())
			http.Error(w, "protected application is unavailable", http.StatusBadGateway)
		},
	}
}
