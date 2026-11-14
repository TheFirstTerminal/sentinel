package middleware

import (
	"testing"

	"sentinel/gateway/internal/waf"
)

func TestSecondOpinion(t *testing.T) {
	benign := func(string) float64 { return 0.01 }
	unsure := func(string) float64 { return 0.3 }
	crsOnly := waf.Decision{Score: 5, Attack: true, Matches: []waf.Match{{RuleID: "CRS-932235", Excerpt: "Node.js & Express"}}}
	if !BenignBySecondOpinion(crsOnly, 5, benign) {
		t.Error("a borderline CRS-only match on text the model calls harmless should be let through")
	}
	if BenignBySecondOpinion(crsOnly, 5, unsure) {
		t.Error("the model must be confident (below 5%), not just unsure")
	}
	if BenignBySecondOpinion(crsOnly, 5, nil) {
		t.Error("without a model (second opinion off) nothing changes")
	}
	strong := crsOnly
	strong.Score = 10
	if BenignBySecondOpinion(strong, 5, benign) {
		t.Error("a score above the threshold (several rules agree) must still block")
	}
	ownRule := waf.Decision{Score: 5, Attack: true, Matches: []waf.Match{{RuleID: "SQLI-001", Excerpt: "' union select"}}}
	if BenignBySecondOpinion(ownRule, 5, benign) {
		t.Error("Sentinel's own rules are never overruled")
	}
	mixed := waf.Decision{Score: 5, Attack: true, Matches: []waf.Match{{RuleID: "CRS-942100", Excerpt: "x"}, {RuleID: "XSS-001", Excerpt: "<script"}}}
	if BenignBySecondOpinion(mixed, 5, benign) {
		t.Error("a Sentinel rule among the matches: block")
	}
	long := waf.Decision{Score: 5, Attack: true, Matches: []waf.Match{{RuleID: "CRS-932235", Excerpt: string(make([]byte, 3000))}}}
	if BenignBySecondOpinion(long, 5, benign) {
		t.Error("a value too long to judge must still block")
	}
	if BenignBySecondOpinion(waf.Decision{Score: 2}, 5, benign) {
		t.Error("not an attack: nothing to overrule")
	}
}
