package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestInertValue(t *testing.T) {
	for _, v := range []string{"name", "product_list_order", "127.0.0.1:8888", "10.0.0.1", "1---", "1YNN",
		"query Q($id: ID!) { node(id: $id) { id name } }"} {
		if !inertValue(v) {
			t.Errorf("%q should not need the model", v)
		}
	}
	for _, v := range []string{"whoami", "id", "PHPINFO", "1--", "1' or 1=1", "name;id", "127.0.0.1;id",
		"127.0.0.1:80/admin", `query { u(n: "x' or 1") { id } }`, "<script>"} {
		if inertValue(v) {
			t.Errorf("%q must still be scored", v)
		}
	}
}

func TestMLInputsPathSegments(t *testing.T) {
	seen := func(target string) []string {
		var out []string
		r := httptest.NewRequest("GET", target, nil)
		for _, in := range MLInputs(r, nil) {
			if in.Field == "path segment" {
				out = append(out, in.Value)
			}
		}
		return out
	}
	if got := seen("/api/users/1'%20OR%20x=x--/orders"); len(got) != 1 || got[0] != "1' OR x=x--" {
		t.Fatalf("payload in a path segment not scored: %q", got)
	}
	if got := seen("/products/blue-shirt-42/reviews"); len(got) != 0 {
		t.Fatalf("ordinary slugs scored: %q", got)
	}
}

func TestMLCookieInputs(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "sid=abc123; q=1%27%20OR%20x%3Dx--; __sentinel_pass=x'y; theme=dark mode")
	got := map[string]string{}
	for _, in := range MLCookieInputs(r) {
		got[in.Field] = in.Value
	}
	if got["q"] != "1' OR x=x--" || got["theme"] != "dark mode" {
		t.Fatalf("cookie values with injection characters not scored: %v", got)
	}
	if _, ok := got["sid"]; ok {
		t.Fatalf("plain cookie scored: %v", got)
	}
	if _, ok := got["__sentinel_pass"]; ok {
		t.Fatalf("Sentinel's own cookie scored: %v", got)
	}
}
