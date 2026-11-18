package middleware

import (
	"testing"

	"sentinel/gateway/internal/waf"
)

func TestBenignCookies(t *testing.T) {
	e := waf.NewEngine(nil, 5)
	crsCookie := waf.Match{RuleID: "CRS-932270", Target: "cookies", Field: "_abck", Excerpt: "~0~YAAQ~-1~", Severity: 5}
	sqlCookie := waf.Match{RuleID: "CRS-942100", Target: "cookies", Field: "id", Excerpt: "1' or '1'='1", Severity: 5}
	own := waf.Match{RuleID: "SQLI-001", Target: "cookies", Field: "id", Excerpt: "1' or '1'='1", Severity: 5}
	opinion := func(s string) float64 {
		if s == "~0~YAAQ~-1~" {
			return 0.01
		}
		return 0.99
	}
	dec := func(ms ...waf.Match) waf.Decision {
		d := waf.Decision{Matches: ms}
		for _, m := range ms {
			d.Score += m.Severity
		}
		d.Attack = d.Score >= 5
		return d
	}
	if !benignCookies(e, dec(crsCookie), opinion) {
		t.Error("a tracking cookie the model doubts must not block")
	}
	if benignCookies(e, dec(sqlCookie), opinion) {
		t.Error("SQL injection in a cookie must still block")
	}
	if benignCookies(e, dec(crsCookie, own), opinion) {
		t.Error("a Sentinel rule match must still block")
	}
	if benignCookies(e, dec(crsCookie), nil) {
		t.Error("without ML nothing changes")
	}
}
