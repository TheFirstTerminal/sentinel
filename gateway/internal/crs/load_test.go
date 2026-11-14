package crs

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// CRS_TEST_DIR points at a CRS checkout's rules/ folder.
func crsDir(t *testing.T) string {
	d := os.Getenv("CRS_TEST_DIR")
	if d == "" {
		t.Skip("set CRS_TEST_DIR to a CRS rules/ folder")
	}
	return d
}

func TestLoadAndDetect(t *testing.T) {
	s, err := Load(crsDir(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", s.Stats)
	r := httptest.NewRequest("GET", "/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	res := s.Evaluate(r, nil)
	if res.Score < 5 {
		t.Errorf("SQLi scored %d: %+v", res.Score, res.Matches)
	}
	for _, m := range res.Matches {
		t.Logf("%d %s %s=%s", m.ID, m.Msg, m.Var, m.Value)
	}
	ok := httptest.NewRequest("GET", "/products?search=apple+juice&page=2", nil)
	ok.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	ok.Header.Set("Accept", "text/html")
	if res := s.Evaluate(ok, nil); res.Score != 0 {
		var ids []string
		for _, m := range res.Matches {
			ids = append(ids, m.Msg)
		}
		t.Errorf("normal request scored %d: %s", res.Score, strings.Join(ids, "; "))
	}
}

// CRS byte patterns (PCRE semantics) must match UTF-8 input.
func TestBytePatterns(t *testing.T) {
	op, err := parseOperator(`@rx (?:\xe2(?:\x91[\xa0-\xbf]))+`, "")
	if err != nil {
		t.Fatal(err)
	}
	if ok, m := op.match("x①②y", ""); !ok || m[0] != "①②" {
		t.Errorf("got %v %q", ok, m)
	}
	if ok, _ := op.match("plain", ""); ok {
		t.Error("matched plain text")
	}
}
