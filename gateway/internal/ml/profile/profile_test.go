package profile

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLearnThenCheck(t *testing.T) {
	p := New()
	for i := 0; i < 200; i++ {
		p.Learn(httptest.NewRequest("GET", fmt.Sprintf("/shop?id=%d&qty=%d", 1000+i*7, i%40), nil), nil)
	}
	if a := p.Check(httptest.NewRequest("GET", "/shop?id=99&qty=3", nil), nil, 20); len(a) != 0 {
		t.Fatalf("normal request flagged: %+v", a)
	}
	if a := p.Check(httptest.NewRequest("GET", "/shop?id=1%27or%201=1&qty=2", nil), nil, 20); len(a) == 0 {
		t.Fatal("tampered id not flagged")
	}
	if a := p.Check(httptest.NewRequest("GET", "/shop?id=1&debug=1", nil), nil, 20); len(a) == 0 {
		t.Fatal("unknown parameter not flagged")
	}
	file := filepath.Join(t.TempDir(), "p.json")
	if err := p.Save(file); err != nil {
		t.Fatal(err)
	}
	q, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if a := q.Check(httptest.NewRequest("GET", "/shop?id=x'--&qty=2", nil), nil, 20); len(a) == 0 {
		t.Fatal("loaded profile lost what it learned")
	}
}
