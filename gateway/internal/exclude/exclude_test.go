package exclude

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExcluded(t *testing.T) {
	s, _ := Load("")
	if _, err := s.Add(Exclusion{Rule: "CRS-942100", Path: "/api/reviews", Field: "comment"}); err != nil {
		t.Fatal(err)
	}
	s.Add(Exclusion{Rule: "CRS-941*", Field: "html_body"})
	s.Add(Exclusion{Rule: "ML", Path: "/upload", Method: "post"})
	cases := []struct {
		rule, method, path, field string
		want                      bool
	}{
		{"CRS-942100", "POST", "/api/reviews/5", "ARGS:json.comment", true},
		{"CRS-942100", "POST", "/api/reviews", "comment", true},
		{"CRS-942100", "POST", "/api/reviews", "title", false},   // other field
		{"CRS-942100", "POST", "/api/orders", "comment", false},  // other path
		{"CRS-942200", "POST", "/api/reviews", "comment", false}, // other rule
		{"crs-941160", "GET", "/anything", "HTML_BODY", true},    // prefix, any path, case
		{"ML", "POST", "/upload/x", "file", true},
		{"ML", "GET", "/upload/x", "file", false}, // method
	}
	for _, c := range cases {
		if got := s.Excluded(c.rule, c.method, c.path, c.field); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
	var nilSet *Set
	if nilSet.Excluded("X", "GET", "/", "a") {
		t.Error("nil set excluded something")
	}
}

func TestNeverEverywhere(t *testing.T) {
	s, _ := Load("")
	for _, e := range []Exclusion{{Rule: "CRS-942100"}, {Rule: "*", Path: "/x"}, {Rule: "", Path: "/x"}, {Rule: "A", Path: "x"}} {
		if _, err := s.Add(e); err == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

func TestSaveAndReload(t *testing.T) {
	f := filepath.Join(t.TempDir(), "exclusions.yaml")
	s, err := Load(f) // missing file: empty
	if err != nil {
		t.Fatal(err)
	}
	e, _ := s.Add(Exclusion{Rule: "SQLI-001", Path: "/search", Note: "product names like 'Select Series'", By: "root"})
	s2, err := Load(f)
	if err != nil || len(s2.List()) != 1 || s2.List()[0].Note != e.Note {
		t.Fatalf("not saved: %v %+v", err, s2.List())
	}
	data, _ := os.ReadFile(f)
	if !strings.HasPrefix(string(data), "# Sentinel exclusions") {
		t.Errorf("no header:\n%s", data)
	}
	if ok, _ := s.Remove(e.ID); !ok {
		t.Fatal("remove failed")
	}
	s2.Reload()
	if len(s2.List()) != 0 {
		t.Error("removal not saved")
	}
	os.WriteFile(f, []byte("- rule: X\n"), 0o644) // no path or field
	if s2.Reload() == nil {
		t.Error("invalid file accepted")
	}
}
