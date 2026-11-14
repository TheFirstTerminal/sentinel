package prefilter

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

func TestPrefilterLiterals(t *testing.T) {
	for pattern, want := range map[string]string{
		`(?i)union\s+select`:      "select",
		`eval\(|new\s+Function`:   "eval(,function",
		`(?:etc/passwd|win\.ini)`: "etc/passwd,win.ini",
		`a.*`:                     "", // too short to help
		`(?:foo)?bar`:             "bar",
		`x*`:                      "",
		`[Ee][Vv][Aa][Ll]`:        "eval",
	} {
		p := New(pattern)
		got := ""
		if p != nil {
			got = strings.Join(p.lits, ",")
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", pattern, got, want)
		}
	}
}

// The prefilter must never reject a value its regex matches. Random strings
// built from the patterns' own pieces make matches likely.
func TestPrefilterIsSound(t *testing.T) {
	patterns := []string{
		`(?i)union\s+select`, `eval\(|new\s+Function`, `(?i)(?:<script|javascript:)`,
		`(?i)\b(?:s(?:elect|leep)|benchmark)\s*\(`, `[Ee][Vv][Aa][Ll]\s*\(`, `(?:\.\./|\.\.\\)+etc`,
	}
	pieces := []string{";", "||", "&&", "\"", "^", "c", "a", "t", "cat", "ls", "<", ">", "${jndi:", "or", "OR", "\t", "union", "UNION", " ", "  ", "select", "SeLeCt", "eval", "EVAL", "(", "new", "Function",
		"<script", "JavaScript:", "sleep", "benchmark", "../", "..\\", "etc", "x", "1", "'"}
	rnd := rand.New(rand.NewSource(1))
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		p := New(pat)
		if p == nil {
			continue
		}
		for i := 0; i < 20000; i++ {
			var b strings.Builder
			for j := rnd.Intn(6); j >= 0; j-- {
				b.WriteString(pieces[rnd.Intn(len(pieces))])
			}
			v := b.String()
			if re.MatchString(v) && !p.MayMatch(Lower(v)) {
				t.Fatalf("%s matches %q but the prefilter rejected it", pat, v)
			}
		}
	}
}
