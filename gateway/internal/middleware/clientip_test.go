package middleware

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	lb := ProxyTrust{Nets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	cases := []struct {
		name  string
		peer  string
		xff   string
		trust ProxyTrust
		want  string
	}{
		{"no header", "1.2.3.4:5", "", lb, "1.2.3.4"},
		{"untrusted peer ignores header", "1.2.3.4:5", "9.9.9.9", lb, "1.2.3.4"},
		{"trusted proxy", "10.0.0.2:5", "9.9.9.9", lb, "9.9.9.9"},
		{"client-sent fake on the left is skipped", "10.0.0.2:5", "6.6.6.6, 9.9.9.9", lb, "9.9.9.9"},
		{"chain of trusted proxies", "10.0.0.2:5", "9.9.9.9, 10.0.0.7", lb, "9.9.9.9"},
		{"garbage in header", "10.0.0.2:5", "not-an-ip", lb, "10.0.0.2"},
		{"trust all (legacy)", "1.2.3.4:5", "6.6.6.6, 9.9.9.9", ProxyTrust{All: true}, "6.6.6.6"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, c.trust); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
