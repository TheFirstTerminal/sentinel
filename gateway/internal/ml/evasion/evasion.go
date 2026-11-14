// Package evasion rewrites attack payloads the way attackers do to slip
// past filters, to test how well the WAF and the ML classifier hold up
// against inputs they were not written or trained for.
package evasion

import (
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

// Mutation is one evasion technique.
type Mutation struct {
	Name  string
	Apply func(r *rand.Rand, s string) string
}

var kw = regexp.MustCompile(`(?i)\b(union|select|from|where|and|or|order|sleep|script|alert|onerror|onload|cat|passwd|etc)\b`)

var Mutations = []Mutation{
	{"random case", func(r *rand.Rand, s string) string {
		b := []rune(s)
		for i, c := range b {
			if r.Intn(2) == 0 {
				b[i] = []rune(strings.ToUpper(string(c)))[0]
			} else {
				b[i] = []rune(strings.ToLower(string(c)))[0]
			}
		}
		return string(b)
	}},
	{"MySQL version comments", func(r *rand.Rand, s string) string {
		return kw.ReplaceAllStringFunc(s, func(k string) string { return "/*!50000" + k + "*/" })
	}},
	{"URL encoding", func(r *rand.Rand, s string) string { return url.QueryEscape(s) }},
	{"double URL encoding", func(r *rand.Rand, s string) string { return url.QueryEscape(url.QueryEscape(s)) }},
	{"HTML entities", func(r *rand.Rand, s string) string {
		return strings.NewReplacer("<", "&lt;", ">", "&gt;", "'", "&#39;", "\"", "&quot;").Replace(s)
	}},
	{"tabs and newlines for spaces", func(r *rand.Rand, s string) string {
		return strings.Map(func(c rune) rune {
			if c == ' ' {
				return []rune("\t\n\r\v\f")[r.Intn(5)]
			}
			return c
		}, s)
	}},
	{"no spaces (parentheses, IFS)", func(r *rand.Rand, s string) string {
		s = regexp.MustCompile(`(?i)\s+(select)\s+`).ReplaceAllString(s, "($1(")
		s = strings.ReplaceAll(s, "cat ", "cat${IFS}")
		return strings.ReplaceAll(s, " ", "/**/")
	}},
	{"operator swaps", func(r *rand.Rand, s string) string {
		return strings.NewReplacer(" or ", " || ", " OR ", " || ", " and ", " && ", " AND ", " && ", "1=1", "2>1", "=", " like ").Replace(s)
	}},
	{"shell quote splitting", func(r *rand.Rand, s string) string {
		return strings.NewReplacer("cat", "c''at", "passwd", "pa''sswd", "whoami", "who\"\"ami", "/etc", "/e''tc", "id", "i''d").Replace(s)
	}},
	{"XSS tag tricks", func(r *rand.Rand, s string) string {
		return strings.NewReplacer("<script>", "<script/x>", " onerror", "/onerror", " onload", "/onload", "alert(1)", "top[`al`+`ert`](1)", "alert", "self['ale'+'rt']").Replace(s)
	}},
}

// Apply runs 1-3 random mutations.
func Apply(r *rand.Rand, s string) (string, []string) {
	n := 1 + r.Intn(3)
	var used []string
	for i := 0; i < n; i++ {
		m := Mutations[r.Intn(len(Mutations))]
		s = m.Apply(r, s)
		used = append(used, m.Name)
	}
	return s, used
}
