// Package events keeps the most recent decisions in memory for the
// dashboard: a ring buffer for history and statistics, and live
// subscribers for the feed.
package events

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one request and Sentinel's decision (same fields as the access log).
type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	ClientIP  string    `json:"client_ip"`
	Country   string    `json:"country,omitempty"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Field     string    `json:"field,omitempty"`   // the field that triggered it
	Related   []string  `json:"related,omitempty"` // other rules on that field
	User      string    `json:"user,omitempty"`
	Role      string    `json:"role,omitempty"`
	Site      string    `json:"site,omitempty"`
	Duration  float64   `json:"duration_ms"`
}

// Stopped reports whether Sentinel refused the request.
func (e Event) Stopped() bool {
	switch e.Outcome {
	case "allowed", "login", "mfa_required", "mfa_ok", "detected":
		return false
	}
	return true
}

type Hub struct {
	mu   sync.Mutex
	ring []Event
	next int
	full bool
	subs map[chan Event]struct{}
	now  func() time.Time
	disk *History // nil = memory only
}

// Persist keeps every event except plain allowed requests on disk too, and
// refills the hub from what is already there.
func (h *Hub) Persist(hist *History) {
	for _, e := range hist.Last(len(h.ring)) {
		h.Publish(e)
	}
	h.mu.Lock()
	h.disk = hist
	h.mu.Unlock()
}

func NewHub(size int) *Hub {
	if size < 1 {
		size = 5000
	}
	return &Hub{ring: make([]Event, size), subs: map[chan Event]struct{}{}, now: time.Now}
}

// Publish stores the event and sends it to live subscribers. A subscriber
// that can't keep up misses events instead of slowing Sentinel down.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disk != nil && e.Outcome != "allowed" {
		h.disk.Append(e)
	}
	h.ring[h.next] = e
	h.next = (h.next + 1) % len(h.ring)
	if h.next == 0 {
		h.full = true
	}
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a channel of new events and a function to stop.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Recent returns up to n events, newest last.
func (h *Hub) Recent(n int) []Event {
	all := h.snapshot()
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

func (h *Hub) snapshot() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Event
	if h.full {
		out = append(out, h.ring[h.next:]...)
	}
	out = append(out, h.ring[:h.next]...)
	return out
}

// Count is a name and how often it occurred.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Stats summarises the last window of events.
type Stats struct {
	Window     string         `json:"window"`
	Total      int            `json:"total"`
	Stopped    int            `json:"stopped"`
	ByOutcome  map[string]int `json:"by_outcome"`
	TopIPs     []Count        `json:"top_ips"`   // most stopped requests
	TopRules   []Count        `json:"top_rules"` // rules that stopped the most
	TopCountry []Count        `json:"top_countries"`
	PerMinute  []Minute       `json:"per_minute"` // oldest first
}

type Minute struct {
	Time    time.Time `json:"time"`
	Allowed int       `json:"allowed"`
	Stopped int       `json:"stopped"`
}

// History is the hub's disk history, or nil.
func (h *Hub) History() *History {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.disk
}

// Stats summarises the last window of events, for one site or ("") all.
func (h *Hub) Stats(window time.Duration, site ...string) Stats {
	now := h.now()
	from := now.Add(-window)
	s := Stats{Window: window.String(), ByOutcome: map[string]int{}}
	ips, rules, countries := map[string]int{}, map[string]int{}, map[string]int{}
	minutes := int(window / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	start := now.Truncate(time.Minute).Add(-time.Duration(minutes-1) * time.Minute)
	s.PerMinute = make([]Minute, minutes)
	for i := range s.PerMinute {
		s.PerMinute[i].Time = start.Add(time.Duration(i) * time.Minute)
	}
	for _, e := range h.snapshot() {
		if e.Time.Before(from) || len(site) > 0 && site[0] != "" && e.Site != site[0] {
			continue
		}
		s.Total++
		s.ByOutcome[e.Outcome]++
		stopped := e.Stopped()
		if stopped {
			s.Stopped++
			ips[e.ClientIP]++
			if e.Rule != "" {
				rules[e.Rule]++
			} else {
				rules[e.Outcome]++
			}
		}
		if e.Country != "" {
			countries[e.Country]++
		}
		if i := int(e.Time.Sub(start) / time.Minute); i >= 0 && i < minutes {
			if stopped {
				s.PerMinute[i].Stopped++
			} else {
				s.PerMinute[i].Allowed++
			}
		}
	}
	s.TopIPs, s.TopRules, s.TopCountry = top(ips, 8), top(rules, 8), top(countries, 8)
	return s
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Hidden: Sentinel's own dashboard traffic, which would drown out the
// requests that matter. It is still written to the access log.
func Hidden(path, outcome string) bool {
	return outcome == "allowed" && (strings.HasPrefix(path, "/__sentinel/api/") ||
		strings.HasPrefix(path, "/__sentinel/dashboard") || path == "/__sentinel/health")
}
