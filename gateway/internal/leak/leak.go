// Package leak checks what an app sends back. A database error or a stack
// trace in a response is how attackers learn that an injection works, and a
// private key or card number in one is a breach.
package leak

import (
	"regexp"
	"strings"
)

// Finding is one problem in a response.
type Finding struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Excerpt string `json:"excerpt"`
	Mask    bool   `json:"-"` // fix by masking (cards), not by withholding the response
}

type rule struct {
	id, name string
	re       *regexp.Regexp
}

var rules = []rule{
	{"LEAK-SQL", "database error message", regexp.MustCompile(`(?i)you have an error in your sql syntax|warning: mysqli?_|unclosed quotation mark after the character string|quoted string not properly terminated|pg_query\(\): query failed|ERROR:\s+syntax error at or near|sqlite3?\.OperationalError|SQLITE_ERROR|\bORA-\d{5}\b|microsoft ole db provider for (?:sql server|odbc)|java\.sql\.SQLException|org\.hibernate\.exception|SequelizeDatabaseError|PDOException`)},
	{"LEAK-TRACE", "stack trace", regexp.MustCompile(`Traceback \(most recent call last\):|(?m)^\s+at (?:java|javax|org\.springframework|sun)\.[\w.$]+\([\w.]+\.java:\d+\)|(?:Fatal error|Parse error|Warning)</b>:.+ on line <b>\d+</b>|PHP (?:Fatal|Parse) error:|Server Error in '/' Application|goroutine \d+ \[running\]:|(?m)^\s+at [\w.<>$]+ \(/[^)]+\.(?:js|ts):\d+:\d+\)`)},
	{"LEAK-KEY", "private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"LEAK-CLOUD", "cloud access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_\-]{35}\b|\bsk_live_[0-9a-zA-Z]{24,}\b|\bgh[pousr]_[0-9A-Za-z]{36}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"LEAK-LISTING", "directory listing", regexp.MustCompile(`<title>Index of /[^<]*</title>|<h1>Directory listing for /`)},
}

// Card layouts only: plain digits, groups of four, or Amex 4-6-5. Phone
// numbers ("+44 20 7618 0622") have other groupings.
var cardRe = regexp.MustCompile(`\b(?:\d{13,19}|\d{4}(?: \d{4}){2,3}(?: \d{1,3})?|\d{4}(?:-\d{4}){2,3}(?:-\d{1,3})?|\d{4} \d{6} \d{4,5}|\d{4}-\d{6}-\d{4,5})\b`)

// cardAt: the match at loc is a card number (and not part of a phone
// number written with a leading +).
func cardAt(s string, loc []int) (string, bool) {
	if loc[0] > 0 && (s[loc[0]-1] == '+' || (loc[0] > 1 && s[loc[0]-1] == ' ' && s[loc[0]-2] == '+')) {
		return "", false
	}
	d := onlyDigits(s[loc[0]:loc[1]])
	return d, isCard(d)
}

// Check looks for leaks in a response body.
func Check(body string) []Finding {
	var out []Finding
	for _, r := range rules {
		if loc := r.re.FindStringIndex(body); loc != nil {
			out = append(out, Finding{ID: r.id, Name: r.name, Excerpt: excerpt(body, loc)})
		}
	}
	for _, loc := range cardRe.FindAllStringIndex(body, 50) {
		if digits, ok := cardAt(body, loc); ok {
			out = append(out, Finding{ID: "LEAK-CARD", Name: "payment card number", Excerpt: maskCard(digits), Mask: true})
			break
		}
	}
	return out
}

// MaskCards replaces every valid card number with its last four digits.
func MaskCards(body string) string {
	var b strings.Builder
	last := 0
	for _, loc := range cardRe.FindAllStringIndex(body, -1) {
		if d, ok := cardAt(body, loc); ok {
			b.WriteString(body[last:loc[0]])
			b.WriteString(maskCard(d))
			last = loc[1]
		}
	}
	b.WriteString(body[last:])
	return b.String()
}

func maskCard(d string) string { return strings.Repeat("*", len(d)-4) + d[len(d)-4:] }

func onlyDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// isCard: 13-19 digits, a known issuer prefix, and a valid Luhn checksum.
// The prefix check keeps order numbers and timestamps from matching.
func isCard(d string) bool {
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	switch {
	case d[0] == '4': // Visa
	case d[:2] >= "51" && d[:2] <= "55", len(d) == 16 && d[:4] >= "2221" && d[:4] <= "2720": // Mastercard
	case d[:2] == "34" || d[:2] == "37": // Amex
	case d[:4] == "6011" || d[:2] == "65": // Discover
	case d[:4] >= "3528" && d[:4] <= "3589": // JCB
	default:
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func excerpt(s string, loc []int) string {
	a, b := max(0, loc[0]-20), min(len(s), loc[1]+40)
	return strings.Join(strings.Fields(s[a:b]), " ")
}
