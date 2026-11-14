package crs

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// FuzzTransforms: no transformation may panic or hang on any input.
func FuzzTransforms(f *testing.F) {
	for _, s := range []string{"%u0627%2", "\\x4", "\\u00", "/*", "a/../../b", "%%%", "\\", "YWJj=", "\xff%uFF07"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, tr := range transforms {
			tr(s)
		}
		parseArgs(s)
		utf8Escapes := bytesAsRunes(s)
		_ = runesAsBytes(utf8Escapes)
	})
}

// FuzzParseRule: the rule parser must reject bad input with an error, never
// a panic (rule files may be edited by hand).
func FuzzParseRule(f *testing.F) {
	for _, s := range []string{
		`SecRule ARGS "@rx a" "id:1,phase:2,t:lowercase,setvar:'tx.a=+1'"`,
		`SecRule &TX:x "@eq 0" "id:2,chain"`, `SecRule ARGS:/a(/ "@pm" ""`, `SecMarker "END"`, `SecAction "id:3,ctl:ruleRemoveTargetById=1;ARGS:a"`,
		`SecRule REQUEST_HEADERS "!@validateByteRange 1-x" "id:4"`, `SecRule "unclosed`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parseStatement(s, t.TempDir())
		statements(s)
		splitActions(s)
	})
}

// FuzzEvaluate sends any raw HTTP request through a rule set that uses
// every feature (chains, captures, macros, ctl, transforms, operators).
func FuzzEvaluate(f *testing.F) {
	dir := f.TempDir()
	os.WriteFile(filepath.Join(dir, "REQUEST-920-T.conf"), []byte(miniCRS+`
SecRule REQUEST_BODY|XML:/*|XML://@*|FILES|MULTIPART_PART_HEADERS|REQUEST_COOKIES "@rx (?i)<script" "id:2001,phase:2,t:none,t:jsDecode,t:cssDecode,t:htmlEntityDecode,t:base64Decode,t:cmdLine,t:normalizePathWin,msg:'x',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule ARGS "@detectSQLi" "id:2002,phase:2,msg:'sqli',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule ARGS "@detectXSS" "id:2003,phase:2,multiMatch,t:urlDecodeUni,t:utf8toUnicode,msg:'xss',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" "id:2004,phase:1,msg:'cl',tag:'paranoia-level/1'"
SecRule &REQUEST_HEADERS:Host "@eq 0" "id:2005,phase:1,msg:'host',tag:'paranoia-level/1'"
`), 0o644)
	set, err := Load(dir, 4)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"GET /?q=1%27%20UNION%20SELECT HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"a\":[1,{\"b\":2}]}",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 70\r\n\r\n--x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\n\r\n<?php\r\n--x--",
		"POST / HTTP/1.1\r\nHost: a\r\nContent-Type: text/xml\r\nContent-Length: 20\r\n\r\n<a b=\"<script\">x</a>",
		"GET /?token=ab--cd12&x=%uff07 HTTP/1.1\r\nHost: a\r\nCookie: a=b; c\r\nX-Evil: 1\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		set.Evaluate(req, body)
	})
}
