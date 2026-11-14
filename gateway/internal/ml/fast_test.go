package ml

import (
	"math"
	"testing"

	"sentinel/gateway/internal/ml/dataset"
)

// The fast scorer must give the same score as Featurize + Score.
func TestScoreFastMatchesFeaturize(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{"", "a", "عصير تفاح", "1' OR 1=1--", "<script>alert(1)</script>", "x\x00y", "\xff\xfe broken utf8",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
	for _, e := range dataset.Generate(2000, 9) {
		inputs = append(inputs, e.Text)
	}
	for _, s := range inputs {
		want := m.Score(Featurize(s))
		if got := m.scoreFast(s); math.Abs(got-want) > 1e-9 {
			t.Fatalf("%q: fast %v, Featurize %v", s, got, want)
		}
	}
}

func BenchmarkScoreText(b *testing.B) {
	m, _ := Default()
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.ScoreText(ua)
	}
}
