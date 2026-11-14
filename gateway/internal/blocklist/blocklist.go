// Package blocklist keeps temporarily banned IP addresses.
//
// Phase 1 keeps the list in memory (restarting the gateway clears it).
// Phase 3 moves it to Redis so bans survive restarts and can be managed
// from the dashboard.
package blocklist

import (
	"sort"
	"sync"
	"time"
)

type List struct {
	mu    sync.Mutex
	until map[string]time.Time
	now   func() time.Time
}

func New() *List {
	return &List{until: map[string]time.Time{}, now: time.Now}
}

// Ban blocks ip for d. A longer existing ban is kept.
func (l *List) Ban(ip string, d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	end := l.now().Add(d)
	if cur, ok := l.until[ip]; !ok || end.After(cur) {
		l.until[ip] = end
	}
}

// Banned reports whether ip is currently banned, and forgets expired bans.
func (l *List) Banned(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	end, ok := l.until[ip]
	if !ok {
		return false
	}
	if l.now().After(end) {
		delete(l.until, ip)
		return false
	}
	return true
}

// Ban is one active ban.
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

// List returns the active bans, soonest to end first.
func (l *List) List() []Ban {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var out []Ban
	for ip, end := range l.until {
		if now.After(end) {
			delete(l.until, ip)
			continue
		}
		out = append(out, Ban{ip, end})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// Unban lifts a ban. It reports whether there was one.
func (l *List) Unban(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.until[ip]
	delete(l.until, ip)
	return ok
}
