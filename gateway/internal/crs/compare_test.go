package crs_test

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/ml/dataset"
	"sentinel/gateway/internal/waf"
)

// TestCompareWithCRS measures what CRS adds on Sentinel's evaluation data:
// attacks caught and normal input wrongly blocked, at paranoia 1 and 2.
func TestCompareWithCRS(t *testing.T) {
	dir := os.Getenv("CRS_TEST_DIR")
	if dir == "" {
		t.Skip()
	}
	rules, _ := waf.LoadRules("")
	data := dataset.Generate(5000, 2)
	for _, pl := range []int{0, 1, 2} {
		e := waf.NewEngine(rules, 5)
		if pl > 0 {
			s, err := crs.Load(dir, pl)
			if err != nil {
				t.Fatal(err)
			}
			s.Exclude([]string{"920220"}) // Sentinel's default

			e.UseCRS(s)
		}
		var tp, fn, fp, tn int
		fpByFam := map[string]int{}
		for _, ex := range data {
			r, _ := http.NewRequest("GET", "/search?q="+url.QueryEscape(ex.Text), nil)
			r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
			r.Header.Set("Accept", "text/html")
			r.Host = "shop.example.com"
			hit := e.Inspect(r, nil).Attack
			switch {
			case ex.Attack && hit:
				tp++
			case ex.Attack:
				fn++
			case hit:
				fp++
				fpByFam[ex.Family]++
			default:
				tn++
			}
		}
		t.Logf("PL%d: attacks caught %.1f%%, normal blocked %.2f%% %v", pl, 100*float64(tp)/float64(tp+fn), 100*float64(fp)/float64(fp+tn), fpByFam)
	}
}

// BenchmarkCRS measures one realistic request through all CRS rules.
func BenchmarkCRS(b *testing.B) {
	dir := os.Getenv("CRS_TEST_DIR")
	if dir == "" {
		b.Skip()
	}
	s, _ := crs.Load(dir, 1)
	r, _ := http.NewRequest("GET", "/products/search?q=apple+juice&page=2&sort=price", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9,ar;q=0.8")
	r.Header.Set("Cookie", "session=abc123def456; theme=dark")
	r.Host = "shop.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Evaluate(r, nil)
	}
}
