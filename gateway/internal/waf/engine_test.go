package waf

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(rules, 5)
}

// Attacks that MUST be blocked. Several use encoding tricks to prove the
// normalizer works.
func TestBlocksAttacks(t *testing.T) {
	e := newTestEngine(t)
	cases := []struct{ name, target, payload string }{
		{"sqli tautology", "/rest/products/search?q=", "' OR 1=1--"},
		{"sqli union", "/rest/products/search?q=", "x')) UNION SELECT id,email,password FROM Users--"},
		{"sqli union with comments", "/search?q=", "1 UNION/**/SELECT null"},
		{"sqli url encoded", "/search?q=", "%27%20OR%20%271%27%3D%271"},
		{"sqli double encoded", "/search?q=", "%2527%2520OR%25201%253D1--"},
		{"sqli stacked drop", "/item?id=", "1; DROP TABLE users"},
		{"sqli time blind", "/item?id=", "1 AND SLEEP(5)"},
		{"sqli metadata", "/item?id=", "1 union select table_name from information_schema.tables"},
		{"xss script", "/search?q=", "<script>alert(1)</script>"},
		{"xss html entities", "/search?q=", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"xss img onerror", "/search?q=", `<img src=x onerror=alert(1)>`},
		{"xss iframe javascript", "/search?q=", `<iframe src="javascript:alert('xss')">`},
		{"path traversal", "/file?name=", "../../../../etc/passwd"},
		{"path traversal encoded", "/file?name=", "..%2F..%2F..%2Fetc%2Fpasswd"},
		{"command injection", "/ping?host=", "127.0.0.1; cat /etc/passwd"},
		{"command substitution", "/ping?host=", "$(whoami)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := c.payload
			if !strings.Contains(payload, "%") {
				payload = urlEncode(payload)
			}
			r := httptest.NewRequest("GET", c.target+payload, nil)
			d := e.Inspect(r, nil)
			if !d.Attack {
				t.Errorf("expected block, got score %d matches %+v", d.Score, d.Matches)
			}
		})
	}
}

func TestBlocksAttackInJSONBody(t *testing.T) {
	e := newTestEngine(t)
	body := `{"email":"admin@juice-sh.op' OR 1=1--","password":"x"}`
	r := httptest.NewRequest("POST", "/rest/user/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	d := e.Inspect(r, []byte(body))
	if !d.Attack {
		t.Fatalf("expected block, got %+v", d)
	}
	if d.Matches[0].Field != "email" {
		t.Errorf("expected match on field email, got %q", d.Matches[0].Field)
	}
}

// Juice Shop's "forgotten backup" file: %2500 decodes to a null byte that
// cuts the filename short so a .md-only check is bypassed.
func TestBlocksNullBytePath(t *testing.T) {
	e := newTestEngine(t)
	r := httptest.NewRequest("GET", "/ftp/package.json.bak%2500.md", nil)
	if d := e.Inspect(r, nil); !d.Attack {
		t.Fatalf("expected null byte path to be blocked, got %+v", d)
	}
}

// The classic Juice Shop admin login bypass: the email ends the SQL string
// and comments out the password check.
func TestBlocksLoginBypass(t *testing.T) {
	e := newTestEngine(t)
	body := `{"email":"admin@juice-sh.op'--","password":"x"}`
	r := httptest.NewRequest("POST", "/rest/user/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if d := e.Inspect(r, []byte(body)); !d.Attack {
		t.Fatalf("expected login bypass to be blocked, got %+v", d)
	}
}

func TestBlocksScannerUserAgent(t *testing.T) {
	e := newTestEngine(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "sqlmap/1.8#stable (https://sqlmap.org)")
	if d := e.Inspect(r, nil); !d.Attack {
		t.Fatalf("expected sqlmap user agent to be blocked, got %+v", d)
	}
}

// Normal traffic that must NOT be blocked. False positives are as important
// as detections: a WAF that blocks real users gets switched off.
func TestAllowsNormalTraffic(t *testing.T) {
	e := newTestEngine(t)
	queries := []string{
		"/rest/products/search?q=apple juice",
		"/rest/products/search?q=O'Brien",
		"/search?q=union station",
		"/search?q=select a size",
		"/search?q=rock and roll",
		"/search?q=drop me a line",
		"/api/Products/1",
		"/assets/i18n/en.json",
		"/search?q=1+1=2",
		"/search?q=email me at a@b.com",
	}

	for _, q := range queries {
		r := httptest.NewRequest("GET", strings.ReplaceAll(q, " ", "+"), nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0")
		if d := e.Inspect(r, nil); d.Attack {
			t.Errorf("false positive on %q: %+v", q, d.Matches)
		}
	}

	bodies := []string{
		`{"email":"user@example.com","password":"S3cure#Pass!"}`,
		`{"comment":"Great product, 5 stars! Colour #ff0000 was perfect","rating":5}`,
		`{"address":"12 O'Connell St","notes":"Leave at door -- thanks"}`,
	}
	for _, b := range bodies {
		r := httptest.NewRequest("POST", "/api/Feedbacks", strings.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if d := e.Inspect(r, []byte(b)); d.Attack {
			t.Errorf("false positive on body %s: %+v", b, d.Matches)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"%2527":                  "'",
		"UNION/**/SELECT":        "union select",
		"&lt;ScRiPt&gt;":         "<script>",
		"a\x00b":                 "a␀b",
		"  lots   of\t\nspace  ": "lots of\nspace", // newlines kept: they separate shell commands
		"/*!50000UNION*/ SELECT": "union select",
		"＇ ｕｎｉｏｎ":                "' union",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBadRulesRejected(t *testing.T) {
	if _, err := ParseRules([]byte(`[{"id":"X","pattern":"(unclosed"}]`)); err == nil {
		t.Error("expected invalid regex to be rejected")
	}
	if _, err := ParseRules([]byte(`[{"id":"X","pattern":"a"},{"id":"X","pattern":"b"}]`)); err == nil {
		t.Error("expected duplicate ids to be rejected")
	}
}

func urlEncode(s string) string {
	r := strings.NewReplacer(" ", "%20", "'", "%27", "\"", "%22", "<", "%3C", ">", "%3E",
		"#", "%23", ";", "%3B", "=", "%3D", "&", "%26", "(", "%28", ")", "%29", "$", "%24")
	return r.Replace(s)
}
