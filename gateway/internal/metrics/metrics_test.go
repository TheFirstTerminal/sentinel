package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Observe("allowed", "", false, 3*time.Millisecond)
	r.Observe("blocked", "SQLI-001", true, 20*time.Millisecond)
	r.Observe("blocked", "SQLI-001", true, 2*time.Second)
	r.Gauge("sentinel_bans_active", "Banned IPs.", "", func() float64 { return 2 })
	r.Gauge("sentinel_info", "Version and mode.", `version="0.9.0",mode="protect"`, func() float64 { return 1 })
	var b strings.Builder
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		`sentinel_requests_total{outcome="blocked"} 2`,
		`sentinel_requests_total{outcome="allowed"} 1`,
		`sentinel_rule_stops_total{rule="SQLI-001"} 2`,
		`sentinel_request_duration_seconds_bucket{le="0.005"} 1`,
		`sentinel_request_duration_seconds_bucket{le="0.025"} 2`,
		`sentinel_request_duration_seconds_bucket{le="+Inf"} 3`,
		`sentinel_request_duration_seconds_count 3`,
		"sentinel_bans_active 2",
		`sentinel_info{version="0.9.0",mode="protect"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// A flood of distinct keys can't grow memory without bound.
func TestCardinalityCap(t *testing.T) {
	r := New()
	for i := 0; i < 5000; i++ {
		r.Observe("blocked", "R-"+strings.Repeat("x", i%50)+string(rune('a'+i%26))+string(rune(i)), true, time.Millisecond)
	}
	if n := len(r.rules); n > 2001 {
		t.Errorf("%d rule series", n)
	}
}
