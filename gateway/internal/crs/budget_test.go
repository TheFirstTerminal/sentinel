package crs

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A body of many fields stops at the budget instead of running every rule.
func TestBudget(t *testing.T) {
	s, err := Load(crsDir(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 8000; i++ {
		fmt.Fprintf(&b, `"field_%d":"some ordinary text value number %d",`, i, i)
	}
	b.WriteString(`"end":1}`)
	body := []byte(b.String())
	r := httptest.NewRequest("POST", "/api", strings.NewReader(b.String()))
	r.Header.Set("Content-Type", "application/json")

	defer func(old time.Duration) { Budget = old }(Budget)
	Budget = 0
	t0 := time.Now()
	full := s.Evaluate(r, body)
	took := time.Since(t0)
	if full.Incomplete {
		t.Fatal("no budget, yet incomplete")
	}
	Budget = took / 10
	t0 = time.Now()
	cut := s.Evaluate(r, body)
	if !cut.Incomplete {
		t.Fatalf("budget %v not enforced (full run %v)", Budget, took)
	}
	if d := time.Since(t0); d > Budget+took/4 {
		t.Errorf("stopped after %v, budget %v", d, Budget)
	}
	t.Logf("full %v, cut at %v", took, Budget)
}

// Large bodies take turns: with every slot taken, one waits until the
// budget and comes back incomplete; small bodies never wait.
func TestLargeBodiesTakeTurns(t *testing.T) {
	s, err := Load(crsDir(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(largeSlots); i++ {
		largeSlots <- struct{}{}
	}
	defer func() {
		for len(largeSlots) > 0 {
			<-largeSlots
		}
	}()
	defer func(old time.Duration) { Budget = old }(Budget)
	Budget = 50 * time.Millisecond

	big := `{"a":"` + strings.Repeat("x", LargeBody) + `"}`
	r := httptest.NewRequest("POST", "/api", strings.NewReader(big))
	r.Header.Set("Content-Type", "application/json")
	t0 := time.Now()
	if res := s.Evaluate(r, []byte(big)); !res.Incomplete {
		t.Fatal("a large body ran with no slot free")
	}
	if d := time.Since(t0); d < Budget || d > 10*Budget {
		t.Errorf("waited %v, budget %v", d, Budget)
	}

	small := `{"q":"red shoes"}`
	r = httptest.NewRequest("POST", "/api", strings.NewReader(small))
	r.Header.Set("Content-Type", "application/json")
	if res := s.Evaluate(r, []byte(small)); res.Incomplete {
		t.Fatal("a small body waited for a large-body slot")
	}
}
