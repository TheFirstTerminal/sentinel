package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.19.0", "0.18.1", true}, {"0.18.1", "0.18.1", false}, {"0.18.0", "0.18.1", false}, {"1.0.0", "0.99.9", true},
		{"0.18.10", "0.18.9", true}, {"0.19.0", "dev", false}, {"junk", "0.1.0", false}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestCheck(t *testing.T) {
	tag := `{"tag_name":"v0.19.0"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tag)) }))
	defer srv.Close()
	defer func(old string) { URL = old }(URL)
	URL = srv.URL
	c := &Checker{current: "0.18.1"}
	c.latest.Store("")
	c.check(context.Background())
	if c.Available() != "0.19.0" {
		t.Fatalf("got %q", c.Available())
	}
	c = &Checker{current: "0.19.0"}
	c.latest.Store("")
	c.check(context.Background())
	if c.Available() != "" {
		t.Fatalf("current version told to update: %q", c.Available())
	}
	tag = `{"tag_name":"v9.0.0-<b>x</b>"}`
	c = &Checker{current: "0.19.0"}
	c.latest.Store("")
	c.check(context.Background())
	if c.Available() != "9.0.0" {
		t.Fatalf("tag not reduced to its number: %q", c.Available())
	}
	var nilC *Checker
	if nilC.Available() != "" {
		t.Fatal("nil checker")
	}
}
