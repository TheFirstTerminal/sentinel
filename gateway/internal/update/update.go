// Package update asks GitHub once a day whether a newer Sentinel has been
// released, so the dashboard can say so (UPDATE_CHECK, on by default). It
// sends nothing but the request itself: no ID, no settings, no traffic.
package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// URL is the latest public release. Free and Pro share version numbers.
var URL = "https://api.github.com/repos/TheFirstTerminal/sentinel/releases/latest"

// Checker remembers the newest version seen.
type Checker struct {
	current string
	latest  atomic.Value // string
}

// Start checks now and every 24 hours until ctx ends.
func Start(ctx context.Context, current string) *Checker {
	c := &Checker{current: current}
	c.latest.Store("")
	go func() {
		for {
			c.check(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()
	return c
}

func (c *Checker) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Sentinel update check")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var r struct {
		Tag string `json:"tag_name"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r) != nil {
		return
	}
	v := strings.TrimPrefix(r.Tag, "v")
	if Newer(v, c.current) {
		c.latest.Store(v)
	}
}

// Available is the newer version, or "" when this one is current (or the
// check is off or hasn't succeeded).
func (c *Checker) Available() string {
	if c == nil {
		return ""
	}
	return c.latest.Load().(string)
}

// Newer reports whether version a (like "0.19.0") is later than b. A
// development build ("dev") is never told to update.
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) []int {
	f := strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 3)
	if len(f) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, s := range f {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}
