package waf

import (
	"slices"

	"sentinel/gateway/internal/prefilter"

	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Targets are the parts of a request a rule can look at.
const (
	TargetPath    = "path"
	TargetQuery   = "query"
	TargetBody    = "body"
	TargetCookies = "cookies"
	TargetHeaders = "headers"
)

// Rule is one detection signature. Each match adds Severity to the request's
// anomaly score; the request is treated as an attack when the score reaches
// the threshold. This "anomaly scoring" idea comes from the OWASP Core Rule
// Set: one weak signal alone doesn't block, several together do.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity int      `json:"severity"`
	Targets  []string `json:"targets"`
	Pattern  string   `json:"pattern"`
	// Reference links a virtual patch to its advisory.
	Reference string `json:"reference,omitempty"`

	re      *regexp.Regexp
	pre     *prefilter.Prefilter // skips the regex when it cannot match
	targets map[string]bool
}

//go:embed default_rules.json
var defaultRulesJSON []byte

// LoadRules reads rules from path, or the built-in set when path is empty.
func LoadRules(path string) ([]*Rule, error) {
	data := defaultRulesJSON
	if path != "" {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("reading rules file: %w", err)
		}
	}
	rules, err := ParseRules(data)
	if err != nil {
		return nil, err
	}
	// Virtual patches for well-known exploited CVEs are always added: they
	// protect an app that hasn't been updated yet.
	vp, err := ParseRules(virtualPatchesJSON)
	if err != nil {
		return nil, fmt.Errorf("virtual patches: %w", err)
	}
	for _, r := range vp {
		if !slices.ContainsFunc(rules, func(x *Rule) bool { return x.ID == r.ID }) {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

//go:embed virtual_patches.json
var virtualPatchesJSON []byte

// ParseRules validates and compiles rules from JSON.
func ParseRules(data []byte) ([]*Rule, error) {
	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing rules: %w", err)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Pattern == "" {
			return nil, fmt.Errorf("every rule needs an id and a pattern")
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true

		// (?i) = case-insensitive. Go's regexp engine (RE2) runs in linear
		// time, so an attacker can't freeze the WAF with a crafted input
		// (no "ReDoS"), which is a real risk with other regex engines.
		re, err := regexp.Compile("(?i)" + r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad pattern: %w", r.ID, err)
		}
		r.re = re
		r.pre = prefilter.New("(?i)" + r.Pattern)
		r.targets = map[string]bool{}
		for _, t := range r.Targets {
			r.targets[t] = true
		}
		if r.Severity <= 0 {
			r.Severity = 1
		}
	}
	return rules, nil
}
