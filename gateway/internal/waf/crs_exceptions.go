package waf

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Core Rule Set matches that are known false alarms on real browser
// traffic. Each one was measured on the held-out half of the open-appsec
// comparison and checked against every attack in it: none of the attacks
// relied on them.

// usPrivacy is the IAB CCPA consent string ("1---", "1YNN") that ad and
// analytics tags send everywhere. libinjection reads "---" as a SQL comment.
var usPrivacy = regexp.MustCompile(`(?i)^1[-yn]{3}$`)

// crsFalseAlarm reports whether a CRS match is one of the known false
// alarms. gql is true when every "query" input is a plain GraphQL document.
func crsFalseAlarm(id int, variable, value string, gql bool) bool {
	switch id {
	case 921140:
		// Header injection needs a raw CR or LF, which Go's HTTP server
		// refuses before Sentinel sees the request. In the Cookie header the
		// rule only finds %0A from URL-encoded JSON (cart and consent
		// cookies); each cookie is still checked on its own.
		return strings.EqualFold(variable, "REQUEST_HEADERS:Cookie")
	case 920340, 920640:
		// A body without a Content-Type: browsers send these for beacons
		// (navigator.sendBeacon with a Blob, gzip analytics). The body is
		// still inspected raw by Sentinel's rules.
		return true
	case 942100:
		return usPrivacy.MatchString(value)
	case 921130:
		return protocolVersion.MatchString(value)
	case 930120:
		// "json.profile_id": CRS writes JSON paths with dots, so a key
		// such as profile or passwd reads as a dotfile. A real path has
		// a slash.
		return strings.HasPrefix(variable, "ARGS_NAMES:json.") && !strings.ContainsAny(value, `/\`)
	case 941170, 941210:
		return harmlessScheme(value)
	case 941180:
		// A bare property name ("window.location.href" as an OpenTelemetry
		// attribute key): without a quote, bracket or call it runs nothing.
		return propertyName.MatchString(value)
	case 932270:
		return !shellTildeIn(value)
	case 932130, 933135:
		return onlyPlaceholders(value)
	case 942550:
		return plainJSON(value)
	}
	if gql && gqlVar.MatchString(variable) {
		return true
	}
	return false
}

// gqlVar is how CRS names a GraphQL document: query=, {"query":} or a
// batch [{"query":}].
var gqlVar = regexp.MustCompile(`^ARGS(?:_GET|_POST)?:(?:json\.(?:\d+\.)?)?query$`)

// isGraphQLField reports whether a Sentinel input name holds a GraphQL
// document: query=, {"query":} or a batch [{"query":}].
func isGraphQLField(field string) bool {
	return field == "query" || field == "[].query"
}

// protocolVersion is a bare protocol name such as "http/1.1": browsers
// report it in Resource Timing data (nextHopProtocol). Request smuggling
// needs a method, a path and line breaks around it.
var protocolVersion = regexp.MustCompile(`(?i)^(?:http/[0-9.]+|h2c?|h3)$`)

const plainLiteral = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:@"

// PlainGraphQL reports whether v is a GraphQL document with nothing an
// injection needs. Field names such as "id", "exec" or "system" made the
// command and SQL rules fire on ordinary API calls; string arguments may
// hold only letters, digits and _-.,:@, and without ', ;, |, &, <, >, ` or
// a path there is no room for a payload. Values usually arrive separately
// in "variables", which are checked as normal fields.
func PlainGraphQL(v string) bool {
	s := strings.TrimSpace(v)
	if len(s) > 64<<10 {
		return false
	}
	ok := s != "" && s[0] == '{'
	for _, kw := range []string{"query", "mutation", "subscription", "fragment"} {
		if strings.HasPrefix(s, kw) && len(s) > len(kw) && strings.ContainsRune(" \t\r\n{(", rune(s[len(kw)])) {
			ok = true
		}
	}
	if !ok {
		return false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth < 0 {
				return false
			}
		case c == '$':
			// Variables only: $name, never $( or ${.
			if i+1 >= len(s) || !(s[i+1] == '_' || s[i+1] >= 'a' && s[i+1] <= 'z' || s[i+1] >= 'A' && s[i+1] <= 'Z') {
				return false
			}
		case c == '"':
			// A string argument ("en-us", "2024-10-01"): only characters
			// that can't end it early, separate commands or name a path.
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				return false
			}
			lit := s[i+1 : i+1+end]
			if strings.Contains(lit, "..") || strings.Trim(lit, plainLiteral) != "" {
				return false
			}
			i += end + 1
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(" \t\r\n_(),:!@.[]=#-", c) >= 0:
		default:
			return false // quotes, ; | & < > ` \ % * / and anything else
		}
	}
	return depth == 0
}

// shellTilde is a tilde the shell would expand: at the start of a word.
// Bot-manager and session cookies use it as a separator ("hash~0~data"),
// always between letters or digits.
var shellTilde = regexp.MustCompile(`(?:^|[^A-Za-z0-9])~`)

// shellTildeIn reports whether v has a tilde the shell would expand to a
// home directory. Akamai's _abck cookie also writes fields such as
// "==~-1~||-1||~-1": a tilde before a number is its separator, while an
// attack needs ~/path or ~user.
func shellTildeIn(v string) bool {
	for _, loc := range shellTilde.FindAllStringIndex(v, -1) {
		rest := v[loc[1]:]
		rest = strings.TrimPrefix(rest, "-")
		if rest == "" || rest[0] < '0' || rest[0] > '9' {
			return true
		}
	}
	return false
}

// placeholder is a template slot that ad and analytics tags leave unfilled,
// such as ${user_id}, ${user.gdpr} or ${uipid()}. Shell evasion uses
// ${IFS}, ${PATH:0:1} or $(...), which this doesn't match; in a shell a
// dot or () inside ${} is a syntax error.
// Upper case only with an underscore (${USER_ID}, ${AUCTION_PRICE}): shell
// evasion uses single-word variables such as ${IFS}, ${PATH} or ${HOME}.
var placeholder = regexp.MustCompile(`\$\{(?:[a-z][a-z0-9_]{2,}(?:\.[a-z][a-z0-9_]*)*(?:\(\))?|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\}`)

// onlyPlaceholders reports whether every "${" in v opens a template slot
// and v has no other shell substitution.
func onlyPlaceholders(v string) bool {
	if !strings.Contains(v, "${") {
		return false
	}
	rest := placeholder.ReplaceAllString(v, "")
	return !strings.Contains(rest, "${") && !strings.Contains(rest, "$(") && !strings.Contains(rest, "`")
}

// sqlWord is a keyword a JSON-based SQL injection needs.
var sqlWord = regexp.MustCompile(`(?i)\b(?:select|union|insert|update|delete|drop|from|where|having|sleep|benchmark|waitfor|or|and|like|json_\w+)\b|--|/\*`)

// plainJSON reports whether v is a JSON document with no SQL in it: rule
// 942550 looks for JSON syntax that SQL engines accept, and fires on
// every JSON value nested in a string.
func plainJSON(v string) bool {
	t := strings.TrimSpace(v)
	if strings.HasPrefix(t, "%7B") || strings.HasPrefix(t, "%7b") || strings.HasPrefix(t, "%5B") || strings.HasPrefix(t, "%5b") {
		// URL-encoded, as analytics cookies (Mixpanel) store it.
		d, err := url.PathUnescape(t)
		if err != nil {
			return false
		}
		t = d
	}
	if t == "" || (t[0] != '{' && t[0] != '[') || !json.Valid([]byte(t)) {
		return false
	}
	return !sqlWord.MatchString(t)
}

// inertScheme is a javascript: or data: URI that runs nothing: an empty
// link target, an SDK version string ("javascript:2.8.18") or an image.
var inertScheme = regexp.MustCompile(`(?i)javascript:\s*(?:void\s*\(\s*0\s*\)\s*;?\s*|;\s*|[0-9]+(?:\.[0-9]+)+)?(?:$|["',}\]])|data:image/(?:png|jpe?g|gif|webp|avif);base64,`)

// harmlessScheme reports whether every javascript: and data: in v is inert.
func harmlessScheme(v string) bool {
	return inertSchemesOnly(v) && !strings.Contains(v, "<")
}

// inertSchemesOnly is harmlessScheme without the check for tags, for
// Sentinel's own javascript: rule (XSS-003): session replay recordings hold
// whole pages with <iframe src="javascript:void(0)">, and tags are the
// other XSS rules' job.
func inertSchemesOnly(v string) bool {
	if !anyScheme.MatchString(v) {
		return false
	}
	rest := strings.ToLower(inertScheme.ReplaceAllString(v, " "))
	return !strings.Contains(rest, "javascript:") && !strings.Contains(rest, "data:") &&
		!strings.Contains(rest, "vbscript:")
}

var propertyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

var anyScheme = regexp.MustCompile(`(?i)javascript:|data:`)
