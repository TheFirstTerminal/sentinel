package crs

// matcher finds whether any of many phrases occurs in a text, in one pass
// (Aho-Corasick). CRS's @pm and @pmFromFile lists have up to hundreds of
// phrases; checking them one by one cost a search per phrase per value.
// Matching is on lowercase bytes, as @pm is case-insensitive.
type matcher struct {
	next  []map[byte]int32 // goto function (sparse)
	fail  []int32
	out   []int32 // index of a phrase ending here (via fail links), or -1
	words []string
}

func newMatcher(words []string) *matcher {
	m := &matcher{next: []map[byte]int32{{}}, fail: []int32{0}, out: []int32{-1}, words: words}
	for wi, w := range words {
		if w == "" {
			continue
		}
		s := int32(0)
		for i := 0; i < len(w); i++ {
			c := lower(w[i])
			n, ok := m.next[s][c]
			if !ok {
				n = int32(len(m.next))
				m.next = append(m.next, map[byte]int32{})
				m.fail = append(m.fail, 0)
				m.out = append(m.out, -1)
				m.next[s][c] = n
			}
			s = n
		}
		if m.out[s] < 0 {
			m.out[s] = int32(wi)
		}
	}
	// Breadth-first: failure links and inherited outputs.
	queue := []int32{}
	for _, n := range m.next[0] {
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c, n := range m.next[s] {
			queue = append(queue, n)
			f := m.fail[s]
			for {
				if t, ok := m.next[f][c]; ok && t != n {
					m.fail[n] = t
					break
				}
				if f == 0 {
					m.fail[n] = 0
					break
				}
				f = m.fail[f]
			}
			if m.out[n] < 0 {
				m.out[n] = m.out[m.fail[n]]
			}
		}
	}
	return m
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// find returns the first phrase found in s, or "".
func (m *matcher) find(s string) (string, bool) {
	st := int32(0)
	for i := 0; i < len(s); i++ {
		c := lower(s[i])
		for {
			if n, ok := m.next[st][c]; ok {
				st = n
				break
			}
			if st == 0 {
				break
			}
			st = m.fail[st]
		}
		if o := m.out[st]; o >= 0 {
			return m.words[o], true
		}
	}
	return "", false
}
