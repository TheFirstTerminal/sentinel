package crs

import (
	"net/http/httptest"
	"testing"
)

// A payload in a custom header is checked by the ARGS rules; browser
// headers with quotes (Sec-CH-UA) are not.
func TestCustomHeadersAsArgs(t *testing.T) {
	s := mini(t, 1)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Search", "1' union select password from users")
	if res := s.Evaluate(r, nil); !fired(res, 1001) {
		t.Fatalf("payload in a custom header missed: %+v", res.Matches)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Sec-Ch-Ua", `"Chromium";v="126", "union select"`)
	r.Header.Set("X-Request-Id", "union select") // no injection characters
	if res := s.Evaluate(r, nil); fired(res, 1001) {
		t.Fatalf("standard or plain header checked as an argument: %+v", res.Matches)
	}
}

func fired(res Result, id int) bool {
	for _, m := range res.Matches {
		if m.ID == id {
			return true
		}
	}
	return false
}
