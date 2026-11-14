// Package ratelimit (check 2) limits how many requests one client may make
// per time window, so brute-force logins, scraping and floods are cut off
// before they cost anything.
//
// Rules are path prefixes with a limit, e.g.
//
//	/__sentinel/auth/=10/1m,/staff/=120/1m,/=600/1m
//
// The longest matching prefix wins. A logged-in user is counted by username
// (so changing IP doesn't help); everyone else by IP address. Counters live
// in the kv store: memory for one gateway, Redis when several share the load.
package ratelimit

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentinel/gateway/internal/kv"
)

type Rule struct {
	Prefix string
	Limit  int64
	Window time.Duration
}

func (r Rule) String() string { return fmt.Sprintf("%s=%d/%s", r.Prefix, r.Limit, short(r.Window)) }

// DefaultRules: strict on login, generous elsewhere.
const DefaultRules = "/__sentinel/auth/=10/1m,/=600/1m"

// Parse reads "prefix=limit/window,..." (window: 10s, 1m, 1h).
func Parse(s string) ([]Rule, error) {
	var rules []Rule
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, spec, ok := strings.Cut(part, "=")
		lim, win, ok2 := strings.Cut(spec, "/")
		if !ok || !ok2 || !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("RATE_LIMITS: %q should look like /path/=100/1m", part)
		}
		n, err := strconv.ParseInt(lim, 10, 64)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("RATE_LIMITS: %q: limit must be a positive number", part)
		}
		if win == "" || (win[0] < '0' || win[0] > '9') {
			win = "1" + win // "100/m" = "100/1m"
		}
		d, err := time.ParseDuration(win)
		if err != nil || d < time.Second {
			return nil, fmt.Errorf("RATE_LIMITS: %q: window must be like 10s, 1m or 1h", part)
		}
		rules = append(rules, Rule{Prefix: prefix, Limit: n, Window: d})
	}
	// Longest prefix first, so the most specific rule wins.
	sort.SliceStable(rules, func(i, j int) bool { return len(rules[i].Prefix) > len(rules[j].Prefix) })
	return rules, nil
}

type Limiter struct {
	rules []Rule
	store kv.Store
	ns    string // keeps each site's counters apart
}

func New(rules []Rule, store kv.Store) *Limiter { return &Limiter{rules: rules, store: store} }

// ForSite is a limiter whose counters are separate from other sites'.
func (l *Limiter) ForSite(site string) *Limiter {
	if site == "" {
		return l
	}
	return &Limiter{rules: l.rules, store: l.store, ns: site + "|"}
}

// Result of one check.
type Result struct {
	Rule       *Rule // nil = no rule applies
	Count      int64 // requests in this window, including this one
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
}

// Check counts the request. subject is "user:alice" or "ip:1.2.3.4".
// If the store fails, the request is allowed (fail open) and err is set,
// so an outage of Redis doesn't take the protected apps offline.
func (l *Limiter) Check(ctx context.Context, path, subject string) (Result, error) {
	return l.CheckWeighted(ctx, path, subject, 1)
}

// CheckWeighted counts the request as weight requests: a large body costs
// Sentinel more to inspect, so it uses up more of the client's limit.
func (l *Limiter) CheckWeighted(ctx context.Context, path, subject string, weight int64) (Result, error) {
	rule := l.match(path)
	if rule == nil {
		return Result{Allowed: true}, nil
	}
	key := "rl:" + l.ns + rule.Prefix + ":" + subject
	n, err := l.store.IncrBy(ctx, key, max(weight, 1), rule.Window)
	if err != nil {
		return Result{Rule: rule, Allowed: true}, err
	}
	res := Result{Rule: rule, Count: n, Allowed: n <= rule.Limit}
	if res.Count > rule.Limit && res.Count-weight < rule.Limit+1 {
		res.Count = rule.Limit + 1 // first refusal of the window (for the audit log)
	}
	if res.Allowed {
		res.Remaining = rule.Limit - n
	} else {
		res.RetryAfter = rule.Window
	}
	return res, nil
}

// Describe lists the rules, most specific first.
func (l *Limiter) Describe() []string {
	out := make([]string, len(l.rules))
	for i, r := range l.rules {
		out[i] = r.String()
	}
	return out
}

func (l *Limiter) match(path string) *Rule {
	for i := range l.rules {
		if strings.HasPrefix(path, l.rules[i].Prefix) {
			return &l.rules[i]
		}
	}
	return nil
}

func short(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
