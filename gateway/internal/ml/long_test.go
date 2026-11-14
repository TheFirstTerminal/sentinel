package ml

import (
	"math/rand"
	"strings"
	"testing"

	"sentinel/gateway/internal/ml/dataset"
)

// Long normal texts are scored in windows; joining normal inputs into long
// texts must not create false alarms.
func TestLongNormalText(t *testing.T) {
	m, _ := Default()
	var normal []string
	for _, e := range dataset.Generate(3000, 77) {
		if !e.Attack {
			normal = append(normal, e.Text)
		}
	}
	r := rand.New(rand.NewSource(1))
	fp := 0
	const n = 1000
	for i := 0; i < n; i++ {
		parts := make([]string, 4+r.Intn(12))
		for j := range parts {
			parts[j] = normal[r.Intn(len(normal))]
		}
		text := strings.Join(parts, " ")
		if p, part := m.ScoreText(text); p >= 0.9 {
			fp++
			if fp <= 5 {
				t.Logf("flagged %.2f: %q", p, part)
			}
		}
	}
	if rate := float64(fp) / n; rate > 0.01 {
		t.Errorf("%d of %d long normal texts flagged (%.1f%%)", fp, n, rate*100)
	}
}
