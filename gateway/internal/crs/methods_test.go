package crs

import (
	"net/http/httptest"
	"testing"
)

// REST methods pass rule 911100; unusual ones are still refused.
func TestAllowedMethods(t *testing.T) {
	s, err := Load(crsDir(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	fired := func(m string) bool {
		for _, x := range s.Evaluate(httptest.NewRequest(m, "/api/items/7", nil), nil).Matches {
			if x.ID == 911100 {
				return true
			}
		}
		return false
	}
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} {
		if fired(m) {
			t.Errorf("%s refused", m)
		}
	}
	for _, m := range []string{"TRACE", "CONNECT", "FOOBAR"} {
		if !fired(m) {
			t.Errorf("%s allowed", m)
		}
	}
}
