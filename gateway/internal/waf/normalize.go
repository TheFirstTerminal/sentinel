package waf

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

var (
	sqlComment   = regexp.MustCompile(`/\*.*?\*/`)
	mysqlVersion = regexp.MustCompile(`/\*!\d*(.*?)\*/`) // /*!50000UNION*/ runs as UNION in MySQL
	spaces       = regexp.MustCompile(`[ \t\r\f\v]+`)
	newlines     = regexp.MustCompile(`\s*\n\s*`)
)

// Normalize turns an input into one canonical form before rules run.
//
// Attackers hide payloads with encoding: %27 for ', %2527 (double encoding),
// &lt;script&gt;, UNION/**/SELECT, mixed case, extra spaces. If the WAF
// checked raw input, each trick would need its own rule. Decoding first
// means one rule catches all variations.
func Normalize(s string) string {
	// Fullwidth letters (＇ｕｎｉｏｎ) are folded to ASCII: some apps and
	// databases normalise Unicode and would read them as ' union.
	s = foldWidth(s)
	// Undo URL encoding repeatedly to defeat double/triple encoding.
	for i := 0; i < 8; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	s = overlong.Replace(s)
	s = html.UnescapeString(s)
	s = foldWidth(s)
	// A null byte (%00) is used to cut a filename short ("secret.bak%00.md"
	// passes a ".md only" check but opens secret.bak). Mark it visibly so
	// rule NULL-001 can catch it instead of silently dropping it.
	s = strings.ReplaceAll(s, "\x00", "␀")
	s = mysqlVersion.ReplaceAllString(s, " $1 ")
	s = sqlComment.ReplaceAllString(s, " ") // UNION/**/SELECT -> UNION SELECT
	s = strings.ToLower(s)
	s = spaces.ReplaceAllString(s, " ")
	s = newlines.ReplaceAllString(s, "\n") // kept: a newline separates shell commands
	return strings.TrimSpace(s)
}

// overlong turns "overlong" UTF-8 forms of . / and \ (%C0%AE, %C0%AF,
// %E0%80%AE...) back into the characters: old or lenient decoders read
// %C0%AE%C0%AE%C0%AF as ../, so path traversal hides in them.
var overlong = strings.NewReplacer(
	"\xc0\xae", ".", "\xc0\xaf", "/", "\xc1\x9c", `\`,
	"\xe0\x80\xae", ".", "\xe0\x80\xaf", "/", "\xe0\x81\x9c", `\`,
)

// foldWidth maps fullwidth ASCII (U+FF01-U+FF5E) and the ideographic space
// to their ASCII forms.
func foldWidth(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r >= 0xFF01 && r <= 0xFF5E || r == 0x3000 }) {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFF01 + '!'
		case r == 0x3000:
			return ' '
		}
		return r
	}, s)
}
