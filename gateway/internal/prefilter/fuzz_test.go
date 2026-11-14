package prefilter

import (
	"regexp"
	"testing"
	"time"
)

// FuzzPrefilterSound: for any pattern and value, if the regex matches then
// the prefilter must let the value through. A failure here would mean a
// skipped attack.
func FuzzPrefilterSound(f *testing.F) {
	for _, s := range [][2]string{
		{`(?i)union\s+select`, "1 UNION  SELECT 2"}, {`eval\(|new\s+Function`, "x=new Function(1)"},
		{`(?:;|\|\||&&)\s*(?:cat|ls)\b`, "a && ls -la"}, {`c["^]*a["^]*t\s`, `c"a^t /etc`}, {`(?i)[<>]\s*[a-z]+`, "< SCRIPT"},
		{`[Ee][Vv][Aa][Ll]`, "eVaL"}, {`(?i)k`, "K"}, {`\x{212a}`, "k"}, {`(?i)ſ`, "S"}, {`a{2,}b`, "aab"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		st := time.Now()
		p := New(pattern)
		if d := time.Since(st); d > 2*time.Second {
			t.Fatalf("New(%q) took %v", pattern, d)
		}
		if p == nil || !re.MatchString(value) {
			return
		}
		if !p.MayMatch(Lower(value)) {
			t.Fatalf("pattern %q matches %q but the prefilter rejected it (lits %q)", pattern, value, p.lits)
		}
	})
}
