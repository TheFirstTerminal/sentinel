package ml

import (
	"math"
	"slices"
	"sync"
	"unicode"
	"unicode/utf8"

	"sentinel/gateway/internal/waf"
)

// scoreFast computes exactly m.Score(Featurize(s)) without building the
// explanation data or allocating per feature. Scoring runs on every input
// of every request; Featurize is only needed to explain a flagged one.
func (m *Model) scoreFast(s string) float64 {
	sc := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sc)
	idx := sc.idx[:0]

	t := waf.Normalize(s)
	// Character n-grams over "\x02" + t + "\x03" (rune boundaries).
	sc.buf = append(append(append(sc.buf[:0], 2), t...), 3)
	b := sc.buf
	offs := sc.offs[:0]
	for i := 0; i < len(b); {
		offs = append(offs, i)
		_, size := utf8.DecodeRune(b[i:])
		i += size
	}
	offs = append(offs, len(b))
	runes := len(offs) - 1
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= runes; i++ {
			idx = append(idx, hashIdx("c", b[offs[i]:offs[i+n]], nil))
		}
	}
	// Words and symbols, and pairs of them (same split as words()).
	spans := sc.spans[:0]
	start := -1
	for i, r := range t {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_':
			if start < 0 {
				start = i
			}
		default:
			if start >= 0 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
			if !unicode.IsSpace(r) {
				spans = append(spans, [2]int{i, i + utf8.RuneLen(r)})
			}
		}
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(t)})
	}
	tb := sc.tb[:0]
	tb = append(tb, t...)
	for k, sp := range spans {
		idx = append(idx, hashIdx("w", tb[sp[0]:sp[1]], nil))
		if k > 0 {
			p := spans[k-1]
			idx = append(idx, hashIdx("b", tb[p[0]:p[1]], tb[sp[0]:sp[1]]))
		}
	}
	idx = append(idx, hashIdx("len", []byte(lengthBucket(len(t))), nil))

	// Count repeats, then the same log-scaling and normalisation as Featurize.
	slices.Sort(idx)
	var norm, dot float64
	for i := 0; i < len(idx); {
		j := i
		for j < len(idx) && idx[j] == idx[i] {
			j++
		}
		x := 1 + math.Log(float64(j-i))
		norm += x * x
		dot += m.Weights[idx[i]] * x
		i = j
	}
	sc.idx, sc.buf, sc.offs, sc.spans, sc.tb = idx, b, offs, spans, tb
	if norm == 0 {
		return sigmoid(m.Bias)
	}
	return sigmoid(m.Bias + dot/math.Sqrt(norm))
}

// hashIdx is FNV-1a over kind, a, (" " and b if b != nil), mod Dim: the
// same as Featurize's add(kind, tok).
func hashIdx(kind string, a, b []byte) int {
	h := uint32(2166136261)
	for i := 0; i < len(kind); i++ {
		h ^= uint32(kind[i])
		h *= 16777619
	}
	for _, c := range a {
		h ^= uint32(c)
		h *= 16777619
	}
	if b != nil {
		h ^= ' '
		h *= 16777619
		for _, c := range b {
			h ^= uint32(c)
			h *= 16777619
		}
	}
	return int(h % Dim)
}

type scratch struct {
	idx   []int
	buf   []byte
	tb    []byte
	offs  []int
	spans [][2]int
}

var scratchPool = sync.Pool{New: func() any { return &scratch{} }}
