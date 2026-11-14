package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

const labGeo = "../../testdata/geoip.csv"

// Like the lab: requests "from" other countries arrive with an
// X-Forwarded-For header through a trusted proxy (here: localhost).
func phase3(c *config.Config) {
	c.TrustedProxies = "127.0.0.0/8"
	c.GeoIPFile = labGeo
	c.GeoDenyCountries = "KP"
}

func from(ip string) []string { return []string{"X-Forwarded-For", ip} }

func TestRateLimitLogin(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) { phase3(c); c.RateLimits = "/__sentinel/auth/=5/1m,/=1000/1m" })
	codes := []int{}
	for i := 0; i < 7; i++ {
		code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"alice","password":"guess`+string(rune('a'+i))+`"}`)
		codes = append(codes, code)
	}
	for i, c := range codes {
		want := 401
		if i >= 5 {
			want = 429
		}
		if c != want {
			t.Fatalf("attempt %d: %d, want %d (all: %v)", i+1, c, want, codes)
		}
	}
	// Another IP is not affected.
	if code, _ := l.do("POST", "/__sentinel/auth/login", "", `{"username":"admin","password":"Admin#2026"}`, from("203.0.113.9")...); code != 200 {
		t.Errorf("other IP: %d", code)
	}
	if !strings.Contains(l.logBuf.String(), `"outcome":"rate_limited"`) {
		t.Error("rate_limited not logged")
	}
}

func TestRateLimitHeaders(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) { c.RateLimits = "/=2/1m" })
	req, _ := http.NewRequest("GET", l.gw.URL+"/", nil)
	for i := 0; i < 3; i++ {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if i == 2 && (resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "60" || resp.Header.Get("X-RateLimit-Limit") != "2") {
			t.Errorf("3rd: %d %v", resp.StatusCode, resp.Header)
		}
	}
}

func TestGeoBlock(t *testing.T) {
	l := newLabWith(t, phase3)
	before := l.appHits()
	if code, _ := l.do("GET", "/", "", "", from("192.0.2.200")...); code != 403 {
		t.Errorf("KP: %d", code)
	}
	if l.appHits() != before {
		t.Error("blocked country reached the app")
	}
	if code, _ := l.do("GET", "/", "", "", from("198.51.100.7")...); code != 200 {
		t.Errorf("DE: %d", code)
	}
	// Spoofing doesn't work without a trusted proxy in front.
	l2 := newLabWith(t, func(c *config.Config) { phase3(c); c.TrustedProxies = "" })
	if code, _ := l2.do("GET", "/", "", "", from("192.0.2.200")...); code != 200 {
		t.Errorf("untrusted X-Forwarded-For was believed: %d", code)
	}
}

func TestFloodingIPIsBanned(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) { phase3(c); c.RateLimits = "/=10/1m" })
	flood := from("203.0.113.50")
	for i := 0; i < 3*10; i++ {
		l.do("GET", "/", "", "", flood...)
	}
	// Banned now: even after the window, every request is refused (403, not 429).
	if code, _ := l.do("GET", "/", "", "", flood...); code != 403 {
		t.Fatalf("flooding IP: %d, want 403 (banned)", code)
	}
	if code, _ := l.do("GET", "/", "", "", from("203.0.113.51")...); code != 200 {
		t.Errorf("another IP: %d", code)
	}
	if !strings.Contains(l.logBuf.String(), "flood_ban") {
		t.Error("flood ban not logged")
	}
}
