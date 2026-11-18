package waf

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
	"unicode/utf8"
)

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"%2527", "&#x3c;", "/*!50000UNION*/", "ＳＥＬＥＣＴ", "\\u003c", "%%%u", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := Normalize(s)
		if len(n) > 8*len(s)+64 {
			t.Fatalf("Normalize grew %d bytes into %d", len(s), len(n))
		}
	})
}

// FuzzInspect: any request, any body, through every built-in rule.
func FuzzInspect(f *testing.F) {
	rules, err := LoadRules("")
	if err != nil {
		f.Fatal(err)
	}
	e := NewEngine(rules, 5)
	f.Add([]byte("POST /a?b=c HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"a\":[1]}"))
	f.Add([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1;b=2"))
	f.Add([]byte("GET /%2e%2e/etc/passwd?x=%u0027 HTTP/1.1\r\nHost: x\r\nCookie: s=1' or 1=1\r\nUser-Agent: ${jndi:ldap://x}\r\n\r\n"))
	f.Add([]byte("POST /up HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: 98\r\n\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\n\r\n<?php ?>\r\n--b--\r\n"))
	f.Add([]byte("GET /PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg?q=JzEgT1IgMT0xLS0 HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		e.Inspect(req, body)
	})
}

// FuzzBase64Text: any value; a decoded result is always valid text.
func FuzzBase64Text(f *testing.F) {
	f.Add("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg")
	f.Add("eyJ1c2VyIjoiYW5uIn0=")
	f.Fuzz(func(t *testing.T, v string) {
		if text, ok := Base64Text(v); ok && !utf8.ValidString(text) {
			t.Fatalf("decoded %q to invalid UTF-8", v)
		}
	})
}
