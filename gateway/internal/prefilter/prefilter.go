package prefilter

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Package prefilter skips regexes that cannot match.
//
// A Prefilter is a set of lowercase strings such that every match of a
// regex contains at least one of them. Checking for those strings is far
// cheaper than running Go's regex engine, which has no DFA and is slow on
// CRS's large alternations; most values contain none of them, so the regex
// never runs. This is the idea behind RE2's FilteredRE2 and Hyperscan.
//
// It must never reject a value the regex would match. The rules below only
// ever widen the set (case is ignored, any branch that cannot be described
// makes the whole regex unfiltered), and TestPrefilterIsSound checks it.
type Prefilter struct {
	lits []string // one of these must appear (lowercase); nil = no condition
	// One of these bytes must appear (lowercase; 0x80 stands for any
	// non-ASCII byte). Used when no useful strings are known, e.g. for
	// patterns built to resist evasion like c["^]*a["^]*t.
	chars    [256]bool
	hasChars bool
}

const maxLits = 256

func New(pattern string) *Prefilter {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	// (No Simplify: it expands nested repeats like (a{100}){100} into huge trees.)
	p := &Prefilter{}
	if lits, ok := required(re); ok && len(lits) > 0 && minLen(lits) >= 2 {
		p.lits = lits // (one-letter strings appear in nearly every value)
	}
	if set, ok := requiredChars(re); ok && selective(set) {
		for _, r := range set {
			if r >= 0x80 {
				p.chars[0x80] = true
			} else {
				p.chars[unicode.ToLower(r)] = true
			}
		}
		p.hasChars = true
	}
	if p.lits == nil && !p.hasChars {
		return nil
	}
	return p
}

// MayMatch reports whether v contains one of the strings. lower is v in
// lower case.
func (p *Prefilter) MayMatch(lower string) bool {
	if p.hasChars {
		found := false
		for i := 0; i < len(lower); i++ {
			c := lower[i]
			if c >= 0x80 {
				c = 0x80
			}
			if p.chars[c] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if p.lits == nil {
		return true
	}
	for _, l := range p.lits {
		if strings.Contains(lower, l) {
			return true
		}
	}
	return false
}

// requiredChars returns characters one of which every match contains.
func requiredChars(re *syntax.Regexp) ([]rune, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		// Any one character of the literal will do; pick the rarest.
		best := []rune(nil)
		for _, r := range re.Rune {
			c := []rune{r}
			if re.Flags&syntax.FoldCase != 0 {
				c = append(c, unicode.SimpleFold(r))
			}
			if best == nil || cost(c) < cost(best) {
				best = c
			}
		}
		return best, best != nil
	case syntax.OpCapture, syntax.OpPlus:
		return requiredChars(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredChars(re.Sub[0])
		}
		return nil, false
	case syntax.OpCharClass:
		var out []rune
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= 0x80 {
				out = append(out, 0x80) // stands for every non-ASCII character
				if lo >= 0x80 {
					continue
				}
				hi = 0x7f
			}
			for r := lo; r <= hi; r++ {
				out = append(out, r)
			}
		}
		return out, len(out) > 0
	case syntax.OpAlternate:
		var out []rune
		for _, sub := range re.Sub {
			s, ok := requiredChars(sub)
			if !ok {
				return nil, false
			}
			out = append(out, s...)
		}
		return out, true
	case syntax.OpConcat:
		var best []rune
		for _, sub := range re.Sub {
			if s, ok := requiredChars(sub); ok && (best == nil || cost(s) < cost(best)) {
				best = s
			}
		}
		return best, best != nil
	}
	return nil, false
}

// cost estimates how often a character set is present in ordinary input:
// letters, digits and spaces are everywhere, punctuation is rare.
func cost(set []rune) int {
	c := 0
	seen := map[rune]bool{}
	for _, r := range set {
		r = unicode.ToLower(r)
		if seen[r] {
			continue
		}
		seen[r] = true
		switch {
		case r >= 0x80:
			c += 20
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ':
			c += 10
		default:
			c++
		}
	}
	return c
}

// selective: the set must leave out letters, digits and space, or it
// would pass nearly every value and only cost time.
func selective(set []rune) bool {
	for _, r := range set {
		if r >= 0x80 || unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' {
			return false
		}
	}
	return len(set) > 0
}

// required returns strings one of which every match contains; ok=false
// means no such set is known.
func required(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}, true
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpCharClass:
		// A small class like [Ee] or [\-_] is a set of one-character strings.
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] > 3 {
				return nil, false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				out = append(out, strings.ToLower(string(r)))
			}
		}
		if len(out) == 0 || len(out) > 8 {
			return nil, false
		}
		return dedupe(out), true
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			l, ok := required(sub)
			if !ok {
				return nil, false
			}
			out = append(out, l...)
			if len(out) > maxLits {
				return nil, false
			}
		}
		return dedupe(out), true
	case syntax.OpConcat:
		// Join neighbouring single-string parts ("ev" + "al" = "eval") and
		// pick the part whose shortest string is longest.
		var best []string
		var cur []string // a run of parts that are each a single string
		consider := func(l []string) {
			if l != nil && better(l, best) {
				best = l
			}
		}
		flush := func() {
			if len(cur) > 0 {
				consider([]string{strings.Join(cur, "")})
				cur = nil
			}
		}
		for _, sub := range re.Sub {
			l, ok := required(sub)
			if ok && len(l) == 1 && exact(sub) {
				cur = append(cur, l[0])
				continue
			}
			flush()
			if ok {
				consider(l)
			}
		}
		flush()
		if best == nil {
			return nil, false
		}
		return best, true
	}
	return nil, false
}

// exact reports whether re matches exactly its required string (so it can
// be joined with its neighbours).
func exact(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		return true
	case syntax.OpCapture:
		return exact(re.Sub[0])
	case syntax.OpCharClass:
		return len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] ||
			// [Aa]: one letter in both cases
			len(re.Rune) == 4 && strings.EqualFold(string(re.Rune[0]), string(re.Rune[2])) && re.Rune[0] == re.Rune[1] && re.Rune[2] == re.Rune[3]
	}
	return false
}

func better(a, b []string) bool {
	if b == nil {
		return true
	}
	ma, mb := minLen(a), minLen(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func minLen(l []string) int {
	m := 1 << 30
	for _, s := range l {
		if n := utf8.RuneCountInString(s); n < m {
			m = n
		}
	}
	return m
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	out := l[:0]
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Lower lowercases v, quickly when it is already lowercase ASCII.
func Lower(v string) string {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return strings.ToLower(v)
		}
	}
	return v
}
