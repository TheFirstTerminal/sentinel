package waf

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel/gateway/internal/crs"
)

func TestPlainGraphQL(t *testing.T) {
	plain := []string{
		"query ProductCard($handle: String!) {\n  product(handle: $handle) {\n    title\n    id\n  }\n}",
		"{ me { id name } }",
		"mutation Add($in: CartInput!) { add(input: $in) { ...Cart } }\nfragment Cart on Cart { id }",
		"query { a # a comment\n b }",
		`query { p(handle: "en-us", from: "2024-10-01T00:00:00", by: "a@b.c") { id } }`,
	}
	for _, q := range plain {
		if !PlainGraphQL(q) {
			t.Errorf("plain GraphQL not recognised: %q", q)
		}
	}
	notPlain := []string{
		`query { user(name: "x' OR 1=1--") { id } }`,
		"query { a(x: $(id)) }",
		"query { a } ; cat /etc/passwd",
		"query { a | id }",
		"query { a }}",
		"queryx { a }",
		"' or 1=1--",
		"query { a(x: `id`) }",
		"{ a(x: ${IFS}) }",
		"query { a /* b */ }",
		`query { f(path: "../../etc") { id } }`,
		`query { f(u: "/etc/passwd") { id } }`,
		`query { f(u: "a;id") { id } }`,
		`query { f(u: "unterminated) { id } }`,
		"",
	}
	for _, q := range notPlain {
		if PlainGraphQL(q) {
			t.Errorf("treated as plain GraphQL: %q", q)
		}
	}
}

// More known false alarms, each next to the attack it must not hide.
func TestMoreFalseAlarms(t *testing.T) {
	e := NewEngine(mustDefaultRules(t), 5)
	post := func(ct, body string) Decision {
		r := httptest.NewRequest("POST", "/graphql", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		return e.Inspect(r, []byte(body))
	}
	if d := post("application/json", `[{"query":"query Offers($where: OffersInput) { offers(where: $where) { id } }"}]`); d.Attack {
		t.Fatalf("$where GraphQL variable blocked: %+v", d)
	}
	if d := post("application/json", `{"filter":{"$where":"sleep(5000)"}}`); !d.Attack {
		t.Fatalf("NoSQL $where operator missed: %+v", d)
	}
	mp := "------WebKitFormBoundaryX\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n2\r\n------WebKitFormBoundaryX--\r\n"
	if d := post("multipart/form-data; boundary=----WebKitFormBoundaryX", mp); d.Attack {
		t.Fatalf("multipart boundary read as SQL: %+v", d)
	}
	evil := strings.Replace(mp, "\r\n2\r\n", "\r\nx' OR 1=1--\r\n", 1)
	if d := post("multipart/form-data; boundary=----WebKitFormBoundaryX", evil); !d.Attack {
		t.Fatalf("SQL injection in a multipart field missed: %+v", d)
	}
	if d := post("application/json, application/json", `{"q":"' UNION SELECT password FROM users--"}`); !d.Attack {
		t.Fatalf("doubled Content-Type hides the JSON body: %+v", d)
	}
	if SingleContentType("application/json, application/json") != "application/json" || SingleContentType("text/plain, application/json") != "text/plain, application/json" {
		t.Fatal("SingleContentType")
	}
	if !crsFalseAlarm(921130, "ARGS:json.nextHopProtocol", "http/1.1", false) || crsFalseAlarm(921130, "ARGS:x", "GET / HTTP/1.1", false) {
		t.Fatal("921130 exception")
	}
}

func TestTextRuns(t *testing.T) {
	got := TextRuns("\x1f\x8b\x08ab\x00union select password\xff\xfeok", 6)
	if got != "union select password\n" {
		t.Fatalf("got %q", got)
	}
}

// Known CRS false alarms are dropped and their score taken back; the same
// rules still count everywhere else.
func TestCRSFalseAlarms(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "REQUEST-942-T.conf"), []byte(`
SecAction "id:900,phase:1,pass,nolog,setvar:'tx.critical_anomaly_score=5'"
SecRule ARGS "@rx ---|' or" "id:942100,phase:2,block,msg:'SQLi',tag:'attack-sqli',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule ARGS "@rx \bexec\b" "id:932370,phase:2,block,msg:'RCE',tag:'attack-rce',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`), 0o644)
	set, err := crs.Load(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(nil, 5)
	e.UseCRS(set)

	if d := e.Inspect(httptest.NewRequest("GET", "/setuid?us_privacy=1---", nil), nil); d.Attack || d.Score != 0 {
		t.Fatalf("CCPA string blocked: %+v", d)
	}
	if d := e.Inspect(httptest.NewRequest("GET", "/?q=1---x", nil), nil); !d.Attack {
		t.Fatalf("other value with --- no longer checked: %+v", d)
	}

	gql := `{"query":"query Run { exec { id } }"}`
	r := httptest.NewRequest("POST", "/graphql", strings.NewReader(gql))
	r.Header.Set("Content-Type", "application/json")
	if d := e.Inspect(r, []byte(gql)); d.Attack {
		t.Fatalf("plain GraphQL blocked: %+v", d)
	}
	bad := `{"query":"query Run { exec { id } }","other":"exec"}`
	r = httptest.NewRequest("POST", "/graphql", strings.NewReader(bad))
	r.Header.Set("Content-Type", "application/json")
	if d := e.Inspect(r, []byte(bad)); !d.Attack {
		t.Fatalf("match outside the GraphQL document dropped: %+v", d)
	}
	inj := `{"query":"query { u(n: \"x' or 1\") { exec } }"}`
	r = httptest.NewRequest("POST", "/graphql", strings.NewReader(inj))
	r.Header.Set("Content-Type", "application/json")
	if d := e.Inspect(r, []byte(inj)); !d.Attack {
		t.Fatalf("GraphQL with a string literal not checked: %+v", d)
	}
}

func TestLargeBinaryBodyInspectsText(t *testing.T) {
	old := MaxFieldBytes
	MaxFieldBytes = 1000
	defer func() { MaxFieldBytes = old }()
	e := NewEngine(mustDefaultRules(t), 5)
	noise := strings.Repeat("\x1f\x8b\xff\x00", 1000)
	r := httptest.NewRequest("POST", "/collect", strings.NewReader(noise))
	if d := e.Inspect(r, []byte(noise)); d.Attack {
		t.Fatalf("binary beacon refused: %+v", d)
	}
	evil := noise + "' UNION SELECT password FROM users--" + noise
	r = httptest.NewRequest("POST", "/collect", strings.NewReader(evil))
	if d := e.Inspect(r, []byte(evil)); !d.Attack {
		t.Fatalf("SQL hidden in a binary body missed: %+v", d)
	}
	mangled := strings.Repeat("�\x1fab", 500) // binary already decoded as UTF-8
	r = httptest.NewRequest("POST", "/collect", strings.NewReader(mangled))
	if d := e.Inspect(r, []byte(mangled)); d.Attack {
		t.Fatalf("mangled binary beacon refused: %+v", d)
	}
	text := strings.Repeat("a", 2000)
	r = httptest.NewRequest("POST", "/collect", strings.NewReader(text))
	if d := e.Inspect(r, []byte(text)); !d.Attack || d.Matches[0].RuleID != "BODY-003" {
		t.Fatalf("large text body no longer refused: %+v", d)
	}
}

func mustDefaultRules(t *testing.T) []*Rule {
	t.Helper()
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	return rules
}
