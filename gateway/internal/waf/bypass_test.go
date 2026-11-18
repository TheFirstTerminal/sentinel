package waf

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Payloads GoTestWAF got past Sentinel 0.15.0, and normal inputs that look
// a little like them. Each payload must be blocked; each normal input must
// pass.
func TestBypassesFound2026(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rules, 5)
	check := func(q string) Decision {
		r := httptest.NewRequest("GET", "/search?q="+url.QueryEscape(q), nil)
		return e.Inspect(r, nil)
	}
	b64 := func(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) }
	attacks := []string{
		"confirm.call(null,1)",
		"javascript:alert(1)",
		"JaVaScRiPt :void(0)",
		"alert?.(document?.cookie)",
		"db.injection.insert({success:1});",
		"(&(uid=admin)(!(&(1=0)(userPassword=q))))",
		"*)(uid=*))(|(uid=*",
		"\nV100 CAPABILITY\nV101 FETCH 4791",
		"|getent hosts somehost.burpcollaborator.net.&",
		"ax--exec=`id`--remote=origin",
		"aaaa'+#{16*8787}+'bbb",
		`\\::1\c$\users\default\ntuser.dat`,
		"\xc0\xae\xc0\xae\xc0\xafetc\xc0\xafpasswd",
		"<?xml version=\"1.0\" encoding=\"UTF-7\"?><foo/>",
		b64("<script>alert(1)</script>"),
		b64("1' UNION SELECT password FROM users--"),
		b64("../../../../etc/passwd"),
	}
	for _, a := range attacks {
		if d := check(a); !d.Attack {
			t.Errorf("not blocked: %q (score %d, %v)", a, d.Score, d.Matches)
		}
	}
	normal := []string{
		"Please confirm (by Friday) that the order is right",
		"alert me when the price drops",
		"db.example.com is our database host",
		"(and then) we left",
		"Mail from: the office. Rcpt is in the drawer",
		"host a party at #{place}",
		"use --verbose for more output",
		"C:\\Users\\me\\Documents",
		"SGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l", // base64 of plain text without code
		"eyJ1c2VyIjoiYW5uIiwiaWQiOjQyfQ",   // base64 JSON: {"user":"ann","id":42}
		"dGhpc19pc19hX3Rva2VuXzEyMzQ1Njc4OTA",
		"5f2c9e7a1b3d4c6e8f0a1b2c3d4e5f6a", // hex ID
		"JavaScript: Basics of JavaScript Language",
	}
	for _, n := range normal {
		if d := check(n); d.Attack {
			t.Errorf("false alarm: %q (score %d, %v)", n, d.Score, d.Matches)
		}
	}
}
