package main

import (
	"fmt"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

// In monitor mode attacks reach the app, but every one is logged as
// "monitored" with what would have happened.
func TestMonitorModeLogsButNeverBlocks(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) {
		redteam(c)
		c.Mode = "monitor"
		c.RateLimits = "/=2/1m"
	})
	attacks := []struct{ method, path, body string }{
		{"GET", "/search?q=1'+UNION+SELECT+password+FROM+users--", ""},
		{"GET", "/.env", ""}, // honeypot
		{"PUT", "/staff/api/employees/alice", `{"salary":9999999}`}, // not in the API schema
		{"POST", "/api/x", `{"q":"<script>alert(1)</script>"}`},
		{"GET", "/ok", ""}, // 2nd request from 10.9.9.1
		{"GET", "/ok", ""}, // 3rd: over the limit of 2
	}
	for i, a := range attacks {
		ip := fmt.Sprintf("10.9.9.%d", i+1)
		if a.path == "/ok" {
			ip = "10.9.9.1" // the IP that already sent requests
		}
		code, _ := l.do(a.method, a.path, "", a.body, from(ip)...)
		if code != 200 {
			t.Errorf("%s %s: got %d, monitor mode must forward everything", a.method, a.path, code)
		}
	}
	if l.hits != len(attacks) {
		t.Errorf("app saw %d requests, want %d", l.hits, len(attacks))
	}
	logs := l.logBuf.String()
	for _, want := range []string{`"outcome":"monitored"`, `"outcome":"detected"`, "would be honeypot", "would be invalid", "would be rate_limited", "SQLI"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs do not mention %q:\n%s", want, logs)
		}
	}
}

// The same requests are refused in protect mode (the default for tests).
func TestProtectModeStillBlocks(t *testing.T) {
	l := newLabWith(t, redteam)
	code, _ := l.do("GET", "/search?q=1'+UNION+SELECT+password+FROM+users--", "", "", from("10.9.9.8")...)
	if code != 403 {
		t.Errorf("got %d, want 403", code)
	}
}
