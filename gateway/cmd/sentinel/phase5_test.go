package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

// A payload the WAF rules don't describe; the ML classifier recognises it.
const zeroDay = "1' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -"

func TestMLCatchesWhatRulesMiss(t *testing.T) {
	off := newLabWith(t, func(c *config.Config) { c.MLMode = "off" })
	if code, _ := off.do("GET", "/rest/products/search?q="+url.QueryEscape(zeroDay), "", ""); code != 200 {
		t.Fatalf("WAF alone should miss this payload (got %d), pick another for the demo", code)
	}

	l := newLabWith(t, func(c *config.Config) { c.MLMode, c.MLThreshold = "block", 0.9 })
	before := l.appHits()
	if code, _ := l.do("GET", "/rest/products/search?q="+url.QueryEscape(zeroDay), "", ""); code != 403 {
		t.Errorf("ML block: %d", code)
	}
	if l.appHits() != before {
		t.Error("blocked request reached the app")
	}
	logs := l.logBuf.String()
	if !strings.Contains(logs, `"outcome":"ml_blocked"`) || !strings.Contains(logs, "because:") {
		t.Error("ML decision or explanation not logged")
	}
	// Normal use is not affected.
	for _, q := range []string{"apple juice", "O'Brien", "rock 'n' roll"} {
		if code, _ := l.do("GET", "/rest/products/search?q="+url.QueryEscape(q), "", ""); code != 200 {
			t.Errorf("normal search %q: %d", q, code)
		}
	}
	if code, _ := l.do("POST", "/api/Feedbacks", "", `{"comment":"Great shop, fast delivery (5 stars)","rating":5,"captcha":"12"}`); code != 200 {
		t.Errorf("normal JSON body: %d", code)
	}

	d := newLabWith(t, func(c *config.Config) { c.MLMode, c.MLThreshold = "detect", 0.9 })
	if code, _ := d.do("GET", "/rest/products/search?q="+url.QueryEscape(zeroDay), "", ""); code != 200 {
		t.Errorf("detect mode blocked: %d", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) { c.SecurityHeaders = true })
	resp, err := http.Get(l.gw.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "strict-origin-when-cross-origin"} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on plain HTTP")
	}
}
