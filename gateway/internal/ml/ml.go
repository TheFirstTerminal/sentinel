// Package ml is check 8: a machine-learning classifier that scores each
// input field as attack or normal, and explains its decision.
//
// The WAF's rules only catch what someone wrote a rule for. The classifier
// learned what attacks look like in general, from thousands of examples, so
// it can flag variations no rule describes. It is a logistic regression over
// "hashed character n-grams": every 3-5 character slice and every word and
// symbol of the (normalised) input becomes a feature, and the model has
// learned one weight per feature. That keeps it small (it runs in
// microseconds, no GPU, no external service) and explainable: the score is
// a sum, so Sentinel can say exactly which pieces of the input pushed it
// towards "attack".
package ml

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"unicode"

	"sentinel/gateway/internal/waf"
)

// Dim is the number of hash buckets (feature slots).
const Dim = 1 << 15

type Model struct {
	Version string    `json:"version"`
	Trained string    `json:"trained"`
	Bias    float64   `json:"bias"`
	Weights []float64 `json:"weights"`
}

//go:embed model.json
var embedded []byte

// Default loads the model that ships with Sentinel.
func Default() (*Model, error) { return Parse(embedded) }

// Parse reads a model saved as JSON.
func Parse(data []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("ml model: %w", err)
	}
	if len(m.Weights) != Dim {
		return nil, fmt.Errorf("ml model: %d weights, want %d", len(m.Weights), Dim)
	}
	return &m, nil
}

// Vector is a sparse feature vector; Tokens remembers which pieces of the
// input landed in each slot, for explanations.
type Vector struct {
	Idx    []int
	Val    []float64
	Tokens map[int][]string
}

// Featurize turns one input value into features.
func Featurize(s string) Vector {
	t := waf.Normalize(s)
	counts := map[int]float64{}
	tokens := map[int][]string{}
	add := func(kind, tok string) {
		h := fnv.New32a()
		h.Write([]byte(kind))
		h.Write([]byte(tok))
		i := int(h.Sum32() % Dim)
		counts[i]++
		if len(tokens[i]) < 3 && !contains(tokens[i], kind+tok) {
			tokens[i] = append(tokens[i], kind+tok)
		}
	}
	// Character n-grams (with start/end markers).
	r := []rune("\x02" + t + "\x03")
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(r); i++ {
			add("c", string(r[i:i+n]))
		}
	}
	// Words and symbols, and pairs of them.
	toks := words(t)
	for i, w := range toks {
		add("w", w)
		if i > 0 {
			add("b", toks[i-1]+" "+w)
		}
	}
	// A few shape features.
	add("len", lengthBucket(len(t)))

	v := Vector{Tokens: tokens}
	var norm float64
	for i, c := range counts {
		x := 1 + math.Log(c)
		v.Idx = append(v.Idx, i)
		v.Val = append(v.Val, x)
		norm += x * x
	}
	norm = math.Sqrt(norm)
	for i := range v.Val {
		v.Val[i] /= norm
	}
	return v
}

// words splits into words and single symbols: "' or 1=1--" ->
// ["'", "or", "1", "=", "1", "-", "-"].
func words(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_':
			cur.WriteRune(r)
		case unicode.IsSpace(r):
			flush()
		default:
			flush()
			out = append(out, string(r))
		}
	}
	flush()
	return out
}

func lengthBucket(n int) string {
	switch {
	case n < 8:
		return "xs"
	case n < 24:
		return "s"
	case n < 64:
		return "m"
	case n < 256:
		return "l"
	}
	return "xl"
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Score is the probability (0-1) that the vector is an attack.
func (m *Model) Score(v Vector) float64 {
	z := m.Bias
	for k, i := range v.Idx {
		z += m.Weights[i] * v.Val[k]
	}
	return sigmoid(z)
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

// Long inputs are scored in overlapping windows as well as whole: the
// feature vector is normalised, so an attack buried in a long, harmless
// text would otherwise be diluted below the threshold.
const (
	window   = 128
	stride   = 64
	maxInput = 32 << 10 // characters scored per field (bounds CPU)
)

// ScoreText returns the highest score over the whole text and its windows,
// and the part of the text that scored it.
func (m *Model) ScoreText(s string) (float64, string) {
	r := []rune(s)
	if len(r) > maxInput {
		r = r[:maxInput]
		s = string(r)
	}
	if len(r) <= window+stride/2 {
		return m.scoreFast(s), s
	}
	best, part := 0.0, ""
	if len(r) <= 4096 {
		best, part = m.scoreFast(s), s
	}
	// Two window sizes: 128 characters for longer attacks, 48 for short
	// ones (an 18-character LDAP filter is still diluted in 128).
	for _, ws := range [][2]int{{window, stride}, {48, 24}} {
		for i := 0; i < len(r); i += ws[1] {
			end := min(i+ws[0], len(r))
			w := string(r[i:end])
			if p := m.scoreFast(w); p > best {
				best, part = p, w
			}
			if end == len(r) {
				break
			}
		}
	}
	return best, part
}

// Reason is one piece of the input and how much it pushed the score.
type Reason struct {
	Token  string  `json:"token"`
	Weight float64 `json:"weight"` // positive = towards attack
}

// Explanation of one prediction.
type Explanation struct {
	Probability float64  `json:"probability"`
	Reasons     []Reason `json:"reasons"` // strongest first
}

// Explain scores s and lists the input pieces that mattered most. Each
// feature's contribution (weight x value) is credited to the word of the
// input it came from, so the reasons read "extractvalue", "sleep",
// "ontoggle" rather than character slices.
func (m *Model) Explain(s string, top int) Explanation {
	v := Featurize(s)
	e := Explanation{Probability: m.Score(v)}
	norm := waf.Normalize(s)
	byWord := map[string]float64{}
	for k, i := range v.Idx {
		c := m.Weights[i] * v.Val[k]
		if c <= 0 {
			continue
		}
		tok := readable(v.Tokens[i])
		if tok == "" {
			continue
		}
		byWord[wordAround(norm, tok)] += c
	}
	type kv struct {
		w string
		c float64
	}
	var all []kv
	for w, c := range byWord {
		all = append(all, kv{w, c})
	}
	// Words first, then symbols; strongest first within each.
	sort.Slice(all, func(a, b int) bool {
		la, lb := letters(all[a].w) >= 2, letters(all[b].w) >= 2
		if la != lb {
			return la
		}
		return all[a].c > all[b].c
	})
	for _, x := range all {
		e.Reasons = append(e.Reasons, Reason{x.w, math.Round(x.c*100) / 100})
		if len(e.Reasons) == top {
			break
		}
	}
	return e
}

// wordAround expands a piece of text to the whole word it sits in
// ("leep(" in "pg_sleep(10)" -> "pg_sleep"). Pieces without letters stay.
func wordAround(text, piece string) string {
	if letters(piece) == 0 {
		return piece
	}
	if strings.Contains(piece, " ") && !strings.Contains(text, piece) {
		for _, f := range strings.Fields(piece) { // a word pair: credit its word
			if letters(f) > 0 {
				piece = f
				break
			}
		}
	}
	i := strings.Index(text, piece)
	if i < 0 {
		return piece
	}
	isW := func(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	// Start inside the piece at its first letter, then grow both ways.
	j := i
	for j < i+len(piece) && !isW(text[j]) {
		j++
	}
	k := j
	for k < len(text) && isW(text[k]) {
		k++
	}
	for j > 0 && isW(text[j-1]) {
		j--
	}
	if j >= k {
		return piece
	}
	return text[j:k]
}

// readable picks the clearest token of a slot: words and word pairs before
// character slices, nothing that is only digits or spaces.
func readable(toks []string) string {
	best := ""
	for _, kt := range toks {
		kind, t := kt[:1], kt[1:]
		if kind == "l" { // length bucket
			continue
		}
		t = strings.Trim(strings.NewReplacer("\x02", "", "\x03", "").Replace(t), " ")
		if strings.Trim(t, "0123456789 ") == "" {
			continue
		}
		if kind == "w" || kind == "b" {
			return t
		}
		if best == "" {
			best = t
		}
	}
	return best
}

// Summary like "union select (+1.9), ' (+0.8)".
func (e Explanation) Summary() string {
	parts := make([]string, len(e.Reasons))
	for i, r := range e.Reasons {
		parts[i] = fmt.Sprintf("%q +%.2f", r.Token, r.Weight)
	}
	return strings.Join(parts, ", ")
}

func letters(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}
