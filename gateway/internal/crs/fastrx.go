package crs

import (
	"regexp"
	"regexp/syntax"
	"sync"
	"unicode"
	"unicode/utf8"
)

// starts is a faster way to answer re.MatchString for regexes that can
// only begin a match on a few characters, such as the Unix command rules
// (932230 and its siblings), which need a shell character like ; | & or
// "busybox" in front of the command name. Go's matcher tries every
// position of the value at once, and with thousands of alternatives that
// costs about 20 µs per byte; here the regex runs anchored, only where a
// match could start. The answer is exactly the same.
type starts struct {
	first0  [256]bool // bytes a match at position 0 can start with
	first   [256]bool // bytes a match anywhere else can start with
	pattern string
	orig    *regexp.Regexp

	// Compiled on first use, so that startup doesn't pay for regexes
	// that never see a candidate.
	once   sync.Once
	at0    *regexp.Regexp // anchored, for position 0
	inside *regexp.Regexp // one character, then the regex anchored after it
}

// maxStartBytes: with more possible ASCII first bytes there is little to
// skip.
const maxStartBytes = 40

// newStarts returns nil when the regex isn't suited: it can match an empty
// string or start on too many characters.
//
// For a position i past 0 the regex runs on v[j:], j being the start of
// the character before i, behind one "any character": ^, \b and (?m)^
// then see the same neighbour as in v, and ^ can no longer hold.
func newStarts(pattern string, orig *regexp.Regexp) *starts {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	var s starts
	if nullable, ok := firstBytes(re, &s.first0); !ok || nullable {
		return nil
	}
	in := re
	if hasOp(re, syntax.OpBeginText) {
		in = noBeginText(re)
	}
	if nullable, ok := firstBytes(in, &s.first); !ok || nullable {
		return nil
	}
	n := 0
	for _, b := range s.first[:utf8.RuneSelf] {
		if b {
			n++
		}
	}
	if n > maxStartBytes {
		return nil
	}
	s.pattern, s.orig = pattern, orig
	return &s
}

func (s *starts) compile() {
	at0, err1 := regexp.Compile(`\A(?:` + s.pattern + `)`)
	inside, err2 := regexp.Compile(`\A(?s:.)(?:` + s.pattern + `)`)
	if err1 == nil && err2 == nil {
		s.at0, s.inside = at0, inside
	}
}

// MatchString reports whether the original regex matches v.
func (s *starts) MatchString(v string) bool {
	s.once.Do(s.compile)
	if s.inside == nil || s.candidates(v) > maxCandidates {
		// Each anchored run may read to the end of v (a class such as
		// [a-z]+ keeps it alive), so many candidates in a long value could
		// cost far more than the plain regex, which reads v once.
		return s.orig.MatchString(v)
	}
	if len(v) > 0 && s.first0[v[0]] && s.at0.MatchString(v) {
		return true
	}
	for i := 1; i < len(v); i++ {
		if !s.first[v[i]] || !utf8.RuneStart(v[i]) {
			continue
		}
		_, size := utf8.DecodeLastRuneInString(v[:i])
		if s.inside.MatchString(v[i-size:]) {
			return true
		}
	}
	return false
}

// maxCandidates is how many start positions are worth trying one by one.
const maxCandidates = 32

// candidates counts the positions past 0 a match could start at, up to
// maxCandidates+1.
func (s *starts) candidates(v string) int {
	n := 0
	for i := 1; i < len(v); i++ {
		if s.first[v[i]] {
			if n++; n > maxCandidates {
				break
			}
		}
	}
	return n
}

// firstBytes adds to set every byte a match of re can start with and
// reports whether re can match without consuming anything. ok is false
// when re can start with any character.
func firstBytes(re *syntax.Regexp, set *[256]bool) (nullable, ok bool) {
	switch re.Op {
	case syntax.OpNoMatch:
		return false, true
	case syntax.OpEmptyMatch, syntax.OpBeginText, syntax.OpEndText, syntax.OpEndLine,
		syntax.OpBeginLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true, true // zero width: the next item decides
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return false, false
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return true, true
		}
		addRune(set, re.Rune[0], re.Flags&syntax.FoldCase != 0)
		return false, true
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
				set[r] = true
			}
			if hi >= utf8.RuneSelf {
				for b := 0xc2; b <= 0xf4; b++ { // UTF-8 lead bytes
					set[b] = true
				}
			}
		}
		return false, true
	case syntax.OpCapture:
		return firstBytes(re.Sub[0], set)
	case syntax.OpStar, syntax.OpQuest:
		_, ok := firstBytes(re.Sub[0], set)
		return true, ok
	case syntax.OpPlus:
		return firstBytes(re.Sub[0], set)
	case syntax.OpRepeat:
		n, ok := firstBytes(re.Sub[0], set)
		return n || re.Min == 0, ok
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			n, ok := firstBytes(sub, set)
			if !ok {
				return false, false
			}
			if !n {
				return false, true
			}
		}
		return true, true
	case syntax.OpAlternate:
		any := false
		for _, sub := range re.Sub {
			n, ok := firstBytes(sub, set)
			if !ok {
				return false, false
			}
			any = any || n
		}
		return any, true
	}
	return false, false
}

func addRune(set *[256]bool, r rune, fold bool) {
	rs := []rune{r}
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			rs = append(rs, f)
		}
	}
	for _, x := range rs {
		if x < utf8.RuneSelf {
			set[x] = true
			continue
		}
		var b [utf8.UTFMax]byte
		utf8.EncodeRune(b[:], x)
		set[b[0]] = true
	}
}

func hasOp(re *syntax.Regexp, op syntax.Op) bool {
	if re.Op == op {
		return true
	}
	for _, s := range re.Sub {
		if hasOp(s, op) {
			return true
		}
	}
	return false
}

// noBeginText copies re with every ^ (start of text) made impossible: past
// position 0 it can't hold. Only used to work out the first bytes.
func noBeginText(re *syntax.Regexp) *syntax.Regexp {
	if re.Op == syntax.OpBeginText {
		return &syntax.Regexp{Op: syntax.OpNoMatch}
	}
	c := *re
	c.Sub = make([]*syntax.Regexp, len(re.Sub))
	for i, s := range re.Sub {
		c.Sub[i] = noBeginText(s)
	}
	return &c
}
