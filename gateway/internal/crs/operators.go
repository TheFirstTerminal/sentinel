package crs

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/corazawaf/libinjection-go"

	"sentinel/gateway/internal/prefilter"
)

type operator struct {
	name   string
	negate bool
	param  string // may contain %{...} macros
	re     *regexp.Regexp
	bytes  bool     // match byte by byte, like PCRE (see highByte)
	words  []string // @pm / @pmFromFile, lowercased
	ac     *matcher // the same words, for one-pass matching
	ranges [256]bool
	nets   []*net.IPNet
	pre    *prefilter.Prefilter // nil = always run the regex
}

// parseOperator reads "@name param", "!@name param" or a bare regex.
func parseOperator(s, dir string) (*operator, error) {
	op := &operator{name: "rx"}
	if strings.HasPrefix(s, "!@") {
		op.negate, s = true, s[1:]
	}
	if strings.HasPrefix(s, "@") {
		name, param, _ := strings.Cut(s[1:], " ")
		op.name, op.param = strings.ToLower(name), param
	} else {
		op.param = s
	}
	switch op.name {
	case "rx":
		re, err := regexp.Compile(op.param)
		op.bytes = highByte.MatchString(op.param)
		if !op.bytes {
			op.pre = prefilter.New(op.param)
		}
		if err != nil {
			return nil, fmt.Errorf("regex not supported by RE2")
		}
		op.re = re
	case "pm":
		op.words = strings.Fields(strings.ToLower(op.param))
	case "pmfromfile", "pmf":
		for _, f := range strings.Fields(op.param) {
			data, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				return nil, fmt.Errorf("operator @pmFromFile: %v", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					op.words = append(op.words, strings.ToLower(line))
				}
			}
		}
	case "validatebyterange":
		for _, part := range strings.Split(op.param, ",") {
			lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
			a, err1 := strconv.Atoi(lo)
			b := a
			var err2 error
			if isRange {
				b, err2 = strconv.Atoi(hi)
			}
			if err1 != nil || err2 != nil || a < 0 || b > 255 || a > b {
				return nil, fmt.Errorf("operator @validateByteRange: bad range %q", part)
			}
			for c := a; c <= b; c++ {
				op.ranges[c] = true
			}
		}
	case "ipmatch":
		for _, part := range strings.FieldsFunc(op.param, func(r rune) bool { return r == ',' || r == ' ' }) {
			if !strings.Contains(part, "/") {
				if strings.Contains(part, ":") {
					part += "/128"
				} else {
					part += "/32"
				}
			}
			_, n, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("operator @ipMatch: bad address %q", part)
			}
			op.nets = append(op.nets, n)
		}
	case "within", "streq", "contains", "beginswith", "endswith", "eq", "ge", "gt", "lt", "le",
		"validateurlencoding", "validateutf8encoding", "detectsqli", "detectxss", "unconditionalmatch", "nomatch":
	default:
		return nil, fmt.Errorf("operator @%s", op.name)
	}
	if len(op.words) > 0 {
		op.ac = newMatcher(op.words)
	}
	return op, nil
}

// match runs the operator. param is op.param with macros expanded.
// It returns whether it matched and, for @rx, the capture groups.
func (op *operator) match(v, param string) (bool, []string) {
	return op.matchOpt(v, param, true)
}

// matchOpt is match; groups=false skips extracting captures (much faster).
func (op *operator) matchOpt(v, param string, groups bool) (bool, []string) {
	if op.pre != nil && !op.pre.MayMatch(prefilter.Lower(v)) {
		return op.negate, nil // the regex cannot match this value
	}
	return op.matchChecked(v, param, groups)
}

// matchChecked is matchOpt after the prefilter has passed.
func (op *operator) matchChecked(v, param string, groups bool) (bool, []string) {
	if op.name == "rx" && !groups && !op.negate {
		if op.bytes {
			v = bytesAsRunes(v)
		}
		return op.re.MatchString(v), nil
	}
	ok, groups2 := op.eval(v, param)
	if op.negate {
		return !ok, nil
	}
	return ok, groups2
}

func (op *operator) eval(v, param string) (bool, []string) {
	switch op.name {
	case "rx":
		// Almost every value doesn't match: answer that with the fast
		// matcher and only extract captures for real matches.
		if op.bytes {
			v2 := bytesAsRunes(v)
			if !op.re.MatchString(v2) {
				return false, nil
			}
			m := op.re.FindStringSubmatch(v2)
			for i := range m {
				m[i] = runesAsBytes(m[i])
			}
			return m != nil, m
		}
		if !op.re.MatchString(v) {
			return false, nil
		}
		m := op.re.FindStringSubmatch(v)
		return m != nil, m
	case "pm", "pmfromfile", "pmf":
		if op.ac != nil {
			if w, ok := op.ac.find(v); ok {
				return true, []string{w}
			}
			return false, nil
		}
		lv := strings.ToLower(v)
		for _, w := range op.words {
			if strings.Contains(lv, w) {
				return true, []string{w}
			}
		}
		return false, nil
	case "within":
		return v != "" && strings.Contains(param, v), nil
	case "streq":
		return v == param, nil
	case "contains":
		return strings.Contains(v, param), nil
	case "beginswith":
		return strings.HasPrefix(v, param), nil
	case "endswith":
		return strings.HasSuffix(v, param), nil
	case "eq", "ge", "gt", "lt", "le":
		a, b := atoi(v), atoi(param)
		switch op.name {
		case "eq":
			return a == b, nil
		case "ge":
			return a >= b, nil
		case "gt":
			return a > b, nil
		case "lt":
			return a < b, nil
		}
		return a <= b, nil
	case "validatebyterange":
		for i := 0; i < len(v); i++ {
			if !op.ranges[v[i]] {
				return true, nil
			}
		}
		return false, nil
	case "validateurlencoding":
		for i := 0; i < len(v); i++ {
			if v[i] == '%' && (i+2 >= len(v) || !isHex(v[i+1:i+3])) {
				return true, nil
			}
		}
		return false, nil
	case "validateutf8encoding":
		return !utf8.ValidString(v), nil
	case "detectsqli":
		ok, fp := libinjection.IsSQLi(v)
		return ok, []string{fp}
	case "detectxss":
		return libinjection.IsXSS(v), nil
	case "unconditionalmatch":
		return true, nil
	case "ipmatch":
		ip := net.ParseIP(strings.TrimSpace(v))
		for _, n := range op.nets {
			if ip != nil && n.Contains(ip) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil // nomatch
}

// atoi reads a leading integer the way ModSecurity does (junk = 0).
func atoi(s string) int {
	s = strings.TrimSpace(s)
	end := 0
	if end < len(s) && (s[end] == '-' || s[end] == '+') {
		end++
	}
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// highByte finds \x80-\xff escapes. PCRE matches bytes, so CRS writes some
// patterns byte by byte (e.g. \xe2(?:\x91[\xa0-\xbf]...) for circled
// digits). Go's regexp matches characters and would read \xe2 as "â".
var highByte = regexp.MustCompile(`\\x[89a-fA-F][0-9a-fA-F]`)

// bytesAsRunes turns each byte into the character with the same number, so
// a byte pattern compiled by Go matches exactly as it would in PCRE.
func bytesAsRunes(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			goto convert
		}
	}
	return s
convert:
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

// runesAsBytes undoes bytesAsRunes (for captured text).
func runesAsBytes(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = append(b, byte(r))
	}
	return string(b)
}
