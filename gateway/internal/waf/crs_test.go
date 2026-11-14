package waf

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"sentinel/gateway/internal/crs"
)

// CRS matches are added to the decision with their rule ID and score.
func TestEngineWithCRS(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "REQUEST-930-T.conf"), []byte(`
SecAction "id:900,phase:1,pass,nolog,setvar:'tx.critical_anomaly_score=5'"
SecRule ARGS "@rx /etc/shadow" "id:930999,phase:2,block,msg:'Shadow file',tag:'attack-lfi',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`), 0o644)
	set, err := crs.Load(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(nil, 5) // no native rules: only CRS can catch it
	e.UseCRS(set)
	d := e.Inspect(httptest.NewRequest("GET", "/?f=/etc/shadow", nil), nil)
	if !d.Attack || d.Matches[0].RuleID != "CRS-930999" || d.Matches[0].Category != "lfi" {
		t.Fatalf("got %+v", d)
	}
	if d := e.Inspect(httptest.NewRequest("GET", "/?f=report.pdf", nil), nil); d.Attack {
		t.Fatalf("clean request blocked: %+v", d)
	}
}
