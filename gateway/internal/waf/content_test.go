package waf

import (
	"net/http/httptest"

	"testing"
)

// A body sent as text/plain (or with no type) that is really a form has
// its fields checked one by one, like a body that says what it is.
func TestFieldsByContent(t *testing.T) {
	has := func(in []Input, field, value string) bool {
		for _, i := range in {
			if i.Field == field && i.Value == value && !i.Name {
				return true
			}
		}
		return false
	}
	in := bodyInputs("", []byte("id=1&q=nc+-lvvp+4445+-e+/bin/sh"))
	if !has(in, "q", "nc -lvvp 4445 -e /bin/sh") {
		t.Fatalf("form in an untyped body not split into fields: %+v", in)
	}
	in = bodyInputs("text/plain", []byte("p=nc -lvvp 4445 -e /bin/sh &"))
	if !has(in, "p", "nc -lvvp 4445 -e /bin/sh &") {
		t.Fatalf("value with & not checked whole: %+v", in)
	}
	in = bodyInputs("text/plain", []byte("p=a;echo $((87+12))"))
	if !has(in, "p", "a;echo $((87+12))") {
		t.Fatalf("value with ; and + not checked as sent: %+v", in)
	}
	for _, b := range []string{"hello world", "x = 1", "{not json", `{"csp-report":{"a":"b"}}`, "\x1f\x8b\x08"} {
		if in := bodyInputs("text/plain", []byte(b)); len(in) != 1 || in[0].Field != "(raw)" {
			t.Errorf("%q: want only the raw body, got %+v", b, in)
		}
	}
}

func TestTraversalInHeaders(t *testing.T) {
	e := NewEngine(mustDefaultRules(t), 5)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-File", "..\x01/..\x01/..\x01/etc/passwd")
	if d := e.Inspect(r, nil); !d.Attack {
		t.Fatalf("traversal in a custom header missed: %+v", d)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Referer", "https://shop.example/etc/hosting-plans")
	if d := e.Inspect(r, nil); d.Attack {
		t.Fatalf("ordinary Referer blocked: %+v", d)
	}
}
