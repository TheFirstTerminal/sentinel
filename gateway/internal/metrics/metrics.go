// Package metrics exposes Sentinel's numbers in the Prometheus text format
// (no client library: the format is simple and stable).
//
// Label values are bounded: outcomes are a fixed set and rule IDs come from
// the loaded rules, so a client can't create new time series by sending
// odd requests.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Buckets for request durations, in seconds (Sentinel plus the app).
var Buckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Registry holds the counters.
type Registry struct {
	mu       sync.Mutex
	outcomes map[string]*atomic.Uint64 // by outcome
	rules    map[string]*atomic.Uint64 // stopped requests by rule
	buckets  []atomic.Uint64           // cumulative histogram counts
	count    atomic.Uint64
	sumMicro atomic.Uint64
	gauges   []gauge
	started  time.Time
}

type gauge struct {
	name, help string
	labels     string
	fn         func() float64
}

// Default is the registry the gateway uses.
var Default = New()

func New() *Registry {
	return &Registry{outcomes: map[string]*atomic.Uint64{}, rules: map[string]*atomic.Uint64{},
		buckets: make([]atomic.Uint64, len(Buckets)), started: time.Now()}
}

func (r *Registry) counter(m map[string]*atomic.Uint64, key string) *atomic.Uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := m[key]
	if !ok {
		if len(m) >= 2000 { // a hard cap, whatever happens
			key = "other"
			if c, ok = m[key]; ok {
				return c
			}
		}
		c = &atomic.Uint64{}
		m[key] = c
	}
	return c
}

// Observe records one finished request.
func (r *Registry) Observe(outcome, rule string, stopped bool, d time.Duration) {
	r.counter(r.outcomes, outcome).Add(1)
	if stopped && rule != "" {
		r.counter(r.rules, rule).Add(1)
	}
	s := d.Seconds()
	for i, b := range Buckets {
		if s <= b {
			r.buckets[i].Add(1)
		}
	}
	r.count.Add(1)
	r.sumMicro.Add(uint64(d.Microseconds()))
}

// Gauge adds a value read when metrics are scraped. labels is like
// `mode="protect"` (or "").
func (r *Registry) Gauge(name, help, labels string, fn func() float64) {
	r.mu.Lock()
	r.gauges = append(r.gauges, gauge{name, help, labels, fn})
	r.mu.Unlock()
}

func esc(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// Write writes everything in the Prometheus text format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	outs := snapshot(r.outcomes)
	rules := snapshot(r.rules)
	gauges := append([]gauge(nil), r.gauges...)
	r.mu.Unlock()

	fmt.Fprintln(w, "# HELP sentinel_requests_total Requests by what Sentinel decided.")
	fmt.Fprintln(w, "# TYPE sentinel_requests_total counter")
	for _, k := range sortedKeys(outs) {
		fmt.Fprintf(w, "sentinel_requests_total{outcome=\"%s\"} %d\n", esc(k), outs[k])
	}
	fmt.Fprintln(w, "# HELP sentinel_rule_stops_total Requests stopped (or that would be) by each rule.")
	fmt.Fprintln(w, "# TYPE sentinel_rule_stops_total counter")
	for _, k := range sortedKeys(rules) {
		fmt.Fprintf(w, "sentinel_rule_stops_total{rule=\"%s\"} %d\n", esc(k), rules[k])
	}
	fmt.Fprintln(w, "# HELP sentinel_request_duration_seconds Time from request to response, including the app.")
	fmt.Fprintln(w, "# TYPE sentinel_request_duration_seconds histogram")
	for i, b := range Buckets {
		fmt.Fprintf(w, "sentinel_request_duration_seconds_bucket{le=\"%g\"} %d\n", b, r.buckets[i].Load())
	}
	n := r.count.Load()
	fmt.Fprintf(w, "sentinel_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", n)
	fmt.Fprintf(w, "sentinel_request_duration_seconds_sum %g\n", float64(r.sumMicro.Load())/1e6)
	fmt.Fprintf(w, "sentinel_request_duration_seconds_count %d\n", n)

	seen := map[string]bool{}
	for _, g := range gauges {
		if !seen[g.name] {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
			seen[g.name] = true
		}
		v := g.fn()
		if math.IsNaN(v) {
			continue
		}
		if g.labels != "" {
			fmt.Fprintf(w, "%s{%s} %g\n", g.name, g.labels, v)
		} else {
			fmt.Fprintf(w, "%s %g\n", g.name, v)
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(w, "# HELP sentinel_uptime_seconds Seconds since Sentinel started.\n# TYPE sentinel_uptime_seconds gauge\nsentinel_uptime_seconds %g\n", time.Since(r.started).Seconds())
	fmt.Fprintf(w, "# HELP sentinel_goroutines Running goroutines.\n# TYPE sentinel_goroutines gauge\nsentinel_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP sentinel_memory_bytes Memory in use (heap).\n# TYPE sentinel_memory_bytes gauge\nsentinel_memory_bytes %d\n", ms.HeapAlloc)
}

// Handler serves the metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Write(w)
	})
}

func snapshot(m map[string]*atomic.Uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v.Load()
	}
	return out
}

func sortedKeys(m map[string]uint64) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
