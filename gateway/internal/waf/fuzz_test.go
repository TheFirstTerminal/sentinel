package waf

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
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
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		e.Inspect(req, body)
	})
}
