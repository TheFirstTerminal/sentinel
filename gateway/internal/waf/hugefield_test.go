package waf

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// One huge field must be refused quickly, not run through every rule.
func TestHugeFieldIsRefusedCheaply(t *testing.T) {
	rs, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rs, 5)
	body := `{"note":"` + strings.Repeat("hello world ", 75000) + `"}`
	r, _ := http.NewRequest("POST", "/x", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	start := time.Now()
	d := e.Inspect(r, []byte(body))
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("took %v", took)
	}
	if !d.Attack || d.Matches[0].RuleID != "BODY-003" {
		t.Errorf("want BODY-003, got %+v", d)
	}
}
