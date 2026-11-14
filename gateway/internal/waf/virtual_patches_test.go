package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sentinel/gateway/internal/ml/dataset"
)

// Each virtual patch must catch its exploit, as published, and nothing in
// the normal-traffic data.
func TestVirtualPatches(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rules, 5)
	type exploit struct {
		id     string
		method string
		target string
		hdr    [2]string
		body   string
		ctype  string
	}
	cases := []exploit{
		{"VP-2014-6271", "GET", "/cgi-bin/status", [2]string{"User-Agent", "() { :; }; /bin/bash -c 'cat /etc/passwd'"}, "", ""},
		{"VP-2017-5638", "POST", "/struts2-showcase/upload.action", [2]string{"Content-Type", "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"}, "", ""},
		{"VP-2022-22965", "POST", "/app", [2]string{}, "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di", "application/x-www-form-urlencoded"},
		{"VP-2022-22963", "POST", "/functionRouter", [2]string{"spring.cloud.function.routing-expression", "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/pwned\")"}, "x", "text/plain"},
		{"VP-2022-26134", "GET", "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%29%29%7D/", [2]string{}, "", ""},
		{"VP-2023-22527", "POST", "/template/aui/text-inline.vm", [2]string{}, "label=\\u0027%2b#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d", "application/x-www-form-urlencoded"},
		{"VP-2021-41773", "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", [2]string{}, "", ""},
		{"VP-2024-4577", "POST", "/test.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", [2]string{}, "<?php echo 1; ?>", "text/plain"},
		{"VP-2023-46805", "GET", "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection", [2]string{}, "", ""},
		{"VP-2018-7600", "POST", "/user/register?element_parents=account/mail/%23value&ajax_form=1", [2]string{}, "form_id=user_register_form&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id", "application/x-www-form-urlencoded"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
		if c.hdr[0] != "" {
			r.Header.Set(c.hdr[0], c.hdr[1])
		}
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		d := e.Inspect(r, []byte(c.body))
		found := false
		for _, m := range d.Matches {
			found = found || m.RuleID == c.id
		}
		if !found {
			t.Errorf("%s did not fire (matches: %v)", c.id, d.Matches)
		}
	}

	// No virtual patch fires on normal input.
	vp := map[string]bool{}
	for _, r := range rules {
		if strings.HasPrefix(r.ID, "VP-") {
			vp[r.ID] = true
		}
	}
	for _, ex := range dataset.Generate(5000, 4) {
		if ex.Attack {
			continue
		}
		r := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(ex.Text), nil)
		r.Header.Set("User-Agent", ex.Text)
		for _, m := range e.Inspect(r, nil).Matches {
			if vp[m.RuleID] {
				t.Errorf("%s fired on normal input %q", m.RuleID, ex.Text)
			}
		}
	}
}

// Content-Type is inspected now (Struts exploits live there); ordinary
// values must never match.
func TestContentTypesAreNotAttacks(t *testing.T) {
	rules, _ := LoadRules("")
	e := NewEngine(rules, 5)
	for _, ct := range []string{
		"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
		"multipart/form-data; boundary=--------------------------123456789012345678901234",
		"application/json; charset=utf-8", "application/x-www-form-urlencoded", "text/plain;charset=UTF-8",
		"application/vnd.api+json", "application/merge-patch+json", "application/grpc-web+proto", "text/xml; charset=\"utf-8\"",
		"application/x-ndjson", "image/png", "application/octet-stream", "multipart/mixed; boundary=\"simple boundary\"",
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader("{}"))
		r.Header.Set("Content-Type", ct)
		if d := e.Inspect(r, nil); len(d.Matches) > 0 {
			t.Errorf("%q: %v", ct, d.Matches)
		}
	}
}
