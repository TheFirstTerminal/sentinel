package crs

import (
	"math/rand"
	"strings"
	"testing"
)

// The one-pass matcher must agree with checking each phrase.
func TestMatcherAgreesWithContains(t *testing.T) {
	words := []string{"etc/passwd", "passwd", "win.ini", "he", "she", "his", "hers", "/proc/self/environ", "boot.ini", "a", "ab", "bab", "babb"}
	m := newMatcher(words)
	rnd := rand.New(rand.NewSource(1))
	alphabet := "abhersiPASSWDetc/.inproclfv"
	for i := 0; i < 50000; i++ {
		b := make([]byte, rnd.Intn(20))
		for j := range b {
			b[j] = alphabet[rnd.Intn(len(alphabet))]
		}
		s := string(b)
		want := false
		for _, w := range words {
			want = want || strings.Contains(strings.ToLower(s), w)
		}
		if _, got := m.find(s); got != want {
			t.Fatalf("%q: matcher %v, contains %v", s, got, want)
		}
	}
}

func FuzzMatcher(f *testing.F) {
	f.Add("etc/passwd,win.ini", "GET /../../ETC/PASSWD")
	f.Fuzz(func(t *testing.T, list, s string) {
		words := strings.Split(strings.ToLower(list), ",")
		m := newMatcher(words)
		want := false
		for _, w := range words {
			want = want || (w != "" && strings.Contains(string(lowerBytes(s)), w))
		}
		if _, got := m.find(s); got != want {
			t.Fatalf("%q in %q: matcher %v, contains %v", list, s, got, want)
		}
	})
}

func lowerBytes(s string) []byte {
	b := []byte(s)
	for i := range b {
		b[i] = lower(b[i])
	}
	return b
}
