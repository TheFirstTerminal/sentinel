package ml

import (
	"math"
	"testing"
)

// FuzzScoreFast: the fast scorer must agree with Featurize+Score on any
// input, including broken UTF-8.
func FuzzScoreFast(f *testing.F) {
	for _, s := range []string{"", "1' OR 1=1--", "عصير", "\xff\xfe", "<svg onload=alert(1)>", "a\x00b", "ﾟ"} {
		f.Add(s)
	}
	m, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		want := m.Score(Featurize(s))
		if got := m.scoreFast(s); math.Abs(got-want) > 1e-9 {
			t.Fatalf("%q: fast %v, Featurize %v", s, got, want)
		}
		m.ScoreText(s)
	})
}
