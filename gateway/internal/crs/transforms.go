package crs

import (
	"crypto/md5" //nolint:gosec // ModSecurity's t:md5, not for security
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"html"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

type transform func(string) string

// transforms are the ModSecurity t: functions that CRS request rules use.
var transforms = map[string]transform{
	"lowercase":          strings.ToLower,
	"urldecode":          func(s string) string { return urlDecode(s, false) },
	"urldecodeuni":       func(s string) string { return urlDecode(s, true) },
	"htmlentitydecode":   html.UnescapeString,
	"jsdecode":           jsDecode,
	"cssdecode":          cssDecode,
	"utf8tounicode":      utf8ToUnicode,
	"removenulls":        func(s string) string { return strings.ReplaceAll(s, "\x00", "") },
	"removewhitespace":   removeWhitespace,
	"compresswhitespace": compressWhitespace,
	"replacecomments":    replaceComments,
	"removecommentschar": removeCommentsChar,
	"cmdline":            cmdLine,
	"escapeseqdecode":    escapeSeqDecode,
	"normalizepath":      func(s string) string { return normalizePath(s, false) },
	"normalisepath":      func(s string) string { return normalizePath(s, false) },
	"normalizepathwin":   func(s string) string { return normalizePath(s, true) },
	"normalisepathwin":   func(s string) string { return normalizePath(s, true) },
	"base64decode":       base64Decode,
	"base64decodeext":    base64Decode,
	"length":             func(s string) string { return strconv.Itoa(len(s)) },
	"trim":               strings.TrimSpace,
	"trimleft":           func(s string) string { return strings.TrimLeft(s, " \t\n\r\f\v") },
	"trimright":          func(s string) string { return strings.TrimRight(s, " \t\n\r\f\v") },
	"sha1":               func(s string) string { h := sha1.Sum([]byte(s)); return string(h[:]) },
	"md5":                func(s string) string { h := md5.Sum([]byte(s)); return string(h[:]) },
	"hexencode":          func(s string) string { return fmt.Sprintf("%x", s) },
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if _, ok := unhex(s[i]); !ok {
			return false
		}
	}
	return true
}

// urlDecode decodes %XX and '+'; invalid sequences stay as they are.
// With uni it also decodes %uXXXX: fullwidth ASCII becomes ASCII, and any
// other character above U+00FF becomes that character in UTF-8.
//
// ModSecurity without a unicode map keeps only the low byte, which turns
// Arabic, Cyrillic and other text into ASCII noise: U+0627 (Arabic alef)
// becomes 0x27, an apostrophe, and ordinary Arabic searches look like SQL
// injection. Keeping the real character avoids that; the evasion the
// low-byte rule targets only affects old IIS servers.
func urlDecode(s string, uni bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && uni && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex(s[i+2:i+6]):
			v, _ := strconv.ParseUint(s[i+2:i+6], 16, 16)
			switch {
			case v >= 0xFF01 && v <= 0xFF5E: // fullwidth ASCII
				b.WriteByte(byte(v - 0xFF00 + 0x20))
			case v > 0xFF:
				b.WriteRune(rune(v))
			default:
				b.WriteByte(byte(v))
			}
			i += 5
		case c == '%' && i+2 < len(s) && isHex(s[i+1:i+3]):
			h, _ := unhex(s[i+1])
			l, _ := unhex(s[i+2])
			b.WriteByte(h<<4 | l)
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// jsDecode decodes JavaScript escapes: \xHH, \uHHHH, \OOO and \c.
func jsDecode(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n := s[i+1]
		switch {
		case (n == 'u' || n == 'U') && i+5 < len(s) && isHex(s[i+2:i+6]):
			v, _ := strconv.ParseUint(s[i+2:i+6], 16, 16)
			if v >= 0xFF01 && v <= 0xFF5E {
				v = v - 0xFF00 + 0x20
			}
			b.WriteByte(byte(v))
			i += 5
		case (n == 'x' || n == 'X') && i+3 < len(s) && isHex(s[i+2:i+4]):
			h, _ := unhex(s[i+2])
			l, _ := unhex(s[i+3])
			b.WriteByte(h<<4 | l)
			i += 3
		case n >= '0' && n <= '7':
			j, v := i+1, 0
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				v = v*8 + int(s[j]-'0')
				j++
			}
			b.WriteByte(byte(v))
			i = j - 1
		default:
			b.WriteByte(escapeChar(n))
			i++
		}
	}
	return b.String()
}

func escapeChar(n byte) byte {
	switch n {
	case 'a':
		return 7
	case 'b':
		return 8
	case 'f':
		return 12
	case 'n':
		return 10
	case 'r':
		return 13
	case 't':
		return 9
	case 'v':
		return 11
	}
	return n
}

// cssDecode decodes CSS escapes: \ followed by 1-6 hex digits, or \c.
func cssDecode(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			break
		}
		j := i + 1
		for j < len(s) && j < i+7 && isHex(s[j:j+1]) {
			j++
		}
		if j > i+1 {
			v, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			if v >= 0xFF01 && v <= 0xFF5E {
				v = v - 0xFF00 + 0x20
			}
			b.WriteByte(byte(v))
			if j < len(s) && s[j] == ' ' {
				j++ // a space ends the escape
			}
			i = j - 1
			continue
		}
		if s[i+1] == '\n' {
			i++
			continue
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

// utf8ToUnicode writes non-ASCII characters as %uXXXX.
func utf8ToUnicode(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			goto convert
		}
	}
	return s
convert:
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		if r == utf8.RuneError {
			b.WriteString("%uFFFD")
			continue
		}
		fmt.Fprintf(&b, "%%u%04x", r)
	}
	return b.String()
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' || c == 0xA0
}

func removeWhitespace(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if !isSpace(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func compressWhitespace(s string) string {
	var b strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		if isSpace(s[i]) {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteByte(s[i])
	}
	return b.String()
}

// replaceComments replaces each /* ... */ (closed or not) with one space.
func replaceComments(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteByte(' ')
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			return b.String()
		}
		s = s[i+2+j+2:]
	}
}

func removeCommentsChar(s string) string {
	for _, c := range []string{"/*", "*/", "<!--", "-->", "--", "#"} {
		s = strings.ReplaceAll(s, c, "")
	}
	return s
}

// cmdLine normalises shell input the way ModSecurity does: drops \ " ' ^,
// turns , and ; into spaces, squeezes spaces, removes spaces before / and
// (, and lowercases.
func cmdLine(s string) string {
	var b strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\'', '\\', '^':
			continue
		case ' ', '\t', '\n', '\r', ',', ';':
			space = true
			continue
		case '/', '(':
			space = false
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func escapeSeqDecode(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n := s[i+1]
		switch {
		case (n == 'x' || n == 'X') && i+3 < len(s) && isHex(s[i+2:i+4]):
			h, _ := unhex(s[i+2])
			l, _ := unhex(s[i+3])
			b.WriteByte(h<<4 | l)
			i += 3
		case n >= '0' && n <= '7':
			j, v := i+1, 0
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				v = v*8 + int(s[j]-'0')
				j++
			}
			b.WriteByte(byte(v))
			i = j - 1
		case strings.IndexByte(`abfnrtv\?'"`, n) >= 0:
			b.WriteByte(escapeChar(n))
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func normalizePath(s string, win bool) string {
	if win {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	if s == "" {
		return s
	}
	trailing := strings.HasSuffix(s, "/")
	abs := strings.HasPrefix(s, "/")
	c := path.Clean(s)
	if !abs {
		c = strings.TrimPrefix(c, "./")
		if c == "." {
			c = ""
		}
	}
	if trailing && !strings.HasSuffix(c, "/") {
		c += "/"
	}
	return c
}

func base64Decode(s string) string {
	t := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if out, err := enc.DecodeString(t); err == nil {
			return string(out)
		}
	}
	// Decode the valid prefix, like ModSecurity.
	valid := 0
	for valid < len(t) && strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", t[valid]) >= 0 {
		valid++
	}
	valid -= valid % 4
	out, _ := base64.RawStdEncoding.DecodeString(t[:valid])
	return string(out)
}
