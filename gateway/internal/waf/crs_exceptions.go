package waf

import (
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
