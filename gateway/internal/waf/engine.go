// Package waf is Sentinel's Web Application Firewall engine.
//
// Flow for every request:
//  1. Extract inputs: path, each query value, each body field, cookies, headers.
//  2. Normalize each input (decode tricks away).
//  3. Run every rule that applies to that input's target.
//  4. Add up severities into an anomaly score and decide.
package waf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/prefilter"
)

// Input is one piece of the request that gets inspected.
type Input struct {
	Target string // path, query, body, cookies, headers
	Field  string // e.g. query parameter name or header name
	Value  string
	Name   bool // Value is the parameter's name, not its value
}

// Match records which rule fired, and where.
type Match struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Target   string `json:"target"`
	Field    string `json:"field,omitempty"`
	Excerpt  string `json:"excerpt"`
}

// Decision is the WAF's verdict on one request.
type Decision struct {
	Score   int     `json:"score"`
	Attack  bool    `json:"attack"`
	Matches []Match `json:"matches,omitempty"`
}

type Engine struct {
	mu        sync.RWMutex // Swap replaces the rules while requests are checked
	rules     []*Rule
	threshold int
	crs       *crs.Set // optional OWASP Core Rule Set, run beside the rules
}

// Swap takes the rules and Core Rule Set of n (a reload) atomically:
// requests being checked finish with the old rules, new ones use the new.
func (e *Engine) Swap(n *Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules, e.crs = n.rules, n.crs
}

// UseCRS adds the OWASP Core Rule Set. Its anomaly score is added to the
// score of Sentinel's own rules; both use 5 for a critical match, so the
// same threshold works for both.
func (e *Engine) UseCRS(s *crs.Set) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.crs = s
}

// CRS returns the loaded Core Rule Set, or nil.
func (e *Engine) CRS() *crs.Set {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.crs
}

// Threshold is the anomaly score at which a request is an attack.
func (e *Engine) Threshold() int { return e.threshold }

func NewEngine(rules []*Rule, threshold int) *Engine {
	return &Engine{rules: rules, threshold: threshold}
}

// RuleCount is how many rules are loaded.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Headers that are never inspected: their format is fixed by the protocol
// or checked elsewhere (tokens by authentication, cookies separately), and
// matching attack rules on them only produces false alarms. Every other
// header, including custom ones (X-Api-Version...), is inspected: attacks
// such as Log4Shell arrive in any header the app logs.
var skippedHeaders = map[string]bool{
	"Authorization": true, "Cookie": true, "Content-Length": true,
	"Accept": true, "Accept-Encoding": true, "Accept-Language": true, "Connection": true,
	"Host": true, "If-None-Match": true, "If-Modified-Since": true, "Cache-Control": true,
	"Pragma": true, "Upgrade-Insecure-Requests": true, "X-Request-Id": true,
	"X-Forwarded-For": true, "X-Forwarded-Proto": true, "X-Real-Ip": true, "Te": true,
	"Range": true, "Origin": true, "Priority": true,
}

// Inspect evaluates a request. body is the (possibly truncated) body bytes,
// read by the caller so the proxy can still forward the full body.
func (e *Engine) Inspect(r *http.Request, body []byte) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	enc, body := decodeBody(r, body)
	inputs := ExtractInputs(r, body)
	limit := MaxInputs
	if mt, _, _ := mime.ParseMediaType(SingleContentType(r.Header.Get("Content-Type"))); mt == "application/json" || strings.HasSuffix(mt, "+json") {
		limit = MaxJSONInputs
	}
	if len(inputs) > limit {
		// Thousands of fields cost CPU in every check and are a known way to
		// exhaust a WAF (and to pollute parameters): no real form sends that
		// many. JSON gets more room: analytics batches carry thousands.
		return Decision{Score: 5, Attack: e.threshold <= 5, Matches: []Match{{RuleID: "BODY-002",
			Name: fmt.Sprintf("more than %d parameters or fields", limit), Category: "protocol", Severity: 5,
			Target: TargetBody, Excerpt: fmt.Sprintf("%d inputs", len(inputs))}}}
	}

	inputs = splitLargeJSON(inputs)
	bodyFields := 0
	for _, in := range inputs {
		if in.Target == TargetBody && in.Field != "(raw)" {
			bodyFields++
		}
	}
	var d Decision
	fired := map[string]bool{} // count each rule once per request
	for _, in := range inputs {
		if in.Value == tooDeep && !fired["BODY-001"] {
			fired["BODY-001"] = true
			d.Score += 5
			d.Matches = append(d.Matches, Match{RuleID: "BODY-001", Name: fmt.Sprintf("JSON nested deeper than %d levels", MaxJSONDepth),
				Category: "protocol", Severity: 5, Target: TargetBody, Field: in.Field, Excerpt: "(nesting)"})
			continue
		}
		if MaxFieldBytes > 0 && len(in.Value) > MaxFieldBytes && in.Field == "(raw)" && in.Target == TargetBody && looksBinary(in.Value) {
			// A large binary body (gzip or protobuf analytics, session
			// replay uploads): the rules can only match its readable text,
			// so inspect that. Refused below only if the text alone is too big.
			in.Value = TextRuns(in.Value, 6)
		}
		if MaxFieldBytes > 0 && len(in.Value) > MaxFieldBytes && in.Field == "(raw)" && in.Target == TargetBody && bodyFields > 1 {
			// A large JSON or form body that parsed into fields: each field
			// is checked on its own (and refused if one alone is too big),
			// so the whole body adds nothing but cost.
			continue
		}
		if MaxFieldBytes > 0 && len(in.Value) > MaxFieldBytes {
			// Running every rule over one huge value costs about a second of
			// CPU, so a few such requests could stall the gateway. Real form
			// and API fields are far smaller; refuse instead of inspecting.
			if !fired["BODY-003"] {
				fired["BODY-003"] = true
				d.Score += 5
				d.Matches = append(d.Matches, Match{RuleID: "BODY-003", Name: fmt.Sprintf("single value larger than %d bytes", MaxFieldBytes),
					Category: "protocol", Severity: 5, Target: in.Target, Field: in.Field, Excerpt: fmt.Sprintf("%d bytes", len(in.Value))})
			}
			continue
		}
		norm := Normalize(in.Value)
		if norm == "" {
			continue
		}
		lower := prefilter.Lower(norm)
		// A body that isn't text (compressed or protobuf analytics, file
		// uploads) has zero bytes in it by nature: that's not an injection.
		binary := in.Field == "(raw)" && !utf8.ValidString(in.Value)
		// "$where" is a common GraphQL variable name, not a MongoDB operator.
		gqlDoc := isGraphQLField(in.Field) && !in.Name && PlainGraphQL(in.Value)
		for _, rule := range e.rules {
			if fired[rule.ID] || !rule.targets[in.Target] {
				continue
			}
			// Zero bytes in text decoded from base64 (Criteo's cto_bundle)
			// are the decoder's doing, not the client's.
			decoded := strings.HasSuffix(in.Field, " (base64)")
			if (binary || decoded) && rule.ID == "NULL-001" || gqlDoc && rule.ID == "NOSQL-001" || rule.ID == "XSS-003" && inertSchemesOnly(querySplit(in)) {
				continue
			}
			if rule.pre != nil && !rule.pre.MayMatch(lower) {
				continue
			}
			loc := rule.re.FindStringIndex(norm)
			if loc == nil {
				continue
			}
			fired[rule.ID] = true
			d.Score += rule.Severity
			d.Matches = append(d.Matches, Match{
				RuleID:   rule.ID,
				Name:     rule.Name,
				Category: rule.Category,
				Severity: rule.Severity,
				Target:   in.Target,
				Field:    in.Field,
				Excerpt:  excerpt(norm, loc[0], loc[1]),
			})
		}
	}
	if e.crs != nil && !fired["BODY-003"] {
		res := e.crs.Evaluate(r, body)
		d.Score += res.Score
		if res.Incomplete {
			// Fail closed: the rules that didn't run might have matched.
			d.Score += 5
			d.Matches = append(d.Matches, Match{RuleID: "BODY-004", Name: fmt.Sprintf("inspection took longer than %v", crs.Budget),
				Category: "protocol", Severity: 5, Target: TargetBody, Excerpt: fmt.Sprintf("%d inputs", len(inputs))})
		}
		gql := plainGraphQLQueries(inputs)
		ct := r.Header.Get("Content-Type")
		// The same type sent twice: CRS calls it malformed, the body is
		// still parsed and inspected as that type.
		dupCT := strings.Contains(ct, ",") && SingleContentType(ct) != ct
		for _, m := range res.Matches {
			if m.Paranoia > e.crs.Paranoia {
				continue // detection-only rule above the blocking level
			}
			if crsFalseAlarm(m.ID, m.Var, m.Full, gql) || enc && m.ID == 920450 && strings.HasSuffix(m.Var, "_content-encoding") || dupCT && (m.ID == 920420 || m.ID == 920470 || m.ID == 921421) {
				d.Score -= crsSeverity(m.Severity)
				continue
			}
			d.Matches = append(d.Matches, Match{
				RuleID: fmt.Sprintf("CRS-%d", m.ID), Name: m.Msg, Category: orDefault(m.Category, "protocol"),
				Severity: crsSeverity(m.Severity), Target: crsTarget(m.Var), Field: m.Var, Excerpt: m.Value,
			})
		}
	}
	d.Attack = d.Score >= e.threshold
	return d
}

// querySplit is the value with "&" ending each parameter when it is a whole
// query string ("oid=javascript:;&ot=a"), so a scheme is judged by its own
// parameter only.
func querySplit(in Input) string {
	if in.Field == "(raw)" && in.Target == TargetQuery {
		// Split first, then decode: an encoded %26 stays part of its value.
		v := strings.ReplaceAll(in.Value, "&", `"`)
		if d, err := url.QueryUnescape(v); err == nil {
			return d
		}
		return v
	}
	return in.Value
}

// plainGraphQLQueries is true when the request has "query" inputs and
// every one of them is a plain GraphQL document.
func plainGraphQLQueries(inputs []Input) bool {
	seen := false
	for _, in := range inputs {
		if in.Name || !isGraphQLField(in.Field) || in.Target == TargetHeaders || in.Target == TargetCookies {
			continue
		}
		if !PlainGraphQL(in.Value) {
			return false
		}
		seen = true
	}
	return seen
}

// SingleContentType turns a repeated Content-Type ("application/json,
// application/json", from clients that set the header twice) into one.
// Anything else is returned unchanged.
func SingleContentType(ct string) string {
	parts := strings.Split(ct, ",")
	for _, p := range parts[1:] {
		if strings.TrimSpace(p) != strings.TrimSpace(parts[0]) {
			return ct
		}
	}
	return strings.TrimSpace(parts[0])
}

// looksBinary: not UTF-8, or binary that a client already decoded as
// UTF-8 (one in a hundred characters or more is U+FFFD, the replacement
// for bytes that weren't text).
func looksBinary(v string) bool {
	if !utf8.ValidString(v) || strings.HasPrefix(v, "\x1f\x8b") {
		return true
	}
	return strings.Count(v, "�")*100 >= utf8.RuneCountInString(v)
}

// TextRuns keeps the runs of at least min printable ASCII characters in a
// binary value, one per line: the part of it an injection could live in.
func TextRuns(v string, min int) string {
	var b strings.Builder
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= min {
			b.WriteString(v[start:end])
			b.WriteByte('\n')
		}
		start = -1
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c >= 0x20 && c < 0x7f || c == '\t' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(v))
	return b.String()
}

// Without drops the matches drop says to (exclusions) and scores again.
func (e *Engine) Without(d Decision, drop func(Match) bool) Decision {
	out := Decision{}
	for _, m := range d.Matches {
		if drop(m) {
			continue
		}
		out.Matches = append(out.Matches, m)
		out.Score += m.Severity
	}
	out.Attack = out.Score >= e.threshold
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func crsSeverity(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "ERROR":
		return 4
	case "WARNING":
		return 3
	case "NOTICE":
		return 2
	}
	return 0
}

func crsTarget(v string) string {
	switch {
	case strings.HasPrefix(v, "ARGS_GET"), strings.HasPrefix(v, "QUERY_STRING"):
		return TargetQuery
	case strings.HasPrefix(v, "REQUEST_COOKIES"):
		return TargetCookies
	case strings.HasPrefix(v, "REQUEST_HEADERS"):
		return TargetHeaders
	case strings.HasPrefix(v, "REQUEST_FILENAME"), strings.HasPrefix(v, "REQUEST_URI"), strings.HasPrefix(v, "REQUEST_BASENAME"):
		return TargetPath
	}
	return TargetBody
}

// ExtractInputs splits a request into separately inspected values.
//
// Inspecting each field on its own (instead of the raw body) avoids false
// positives: a JSON body is full of quotes and '#' colours that look like
// SQL when read as one string, but are harmless inside their own value.
func ExtractInputs(r *http.Request, body []byte) []Input {
	var inputs []Input

	path := r.URL.EscapedPath()
	inputs = append(inputs, Input{Target: TargetPath, Value: path})
	for _, seg := range strings.Split(path, "/") {
		if dec, err := url.PathUnescape(seg); err == nil {
			if text, ok := Base64Text(dec); ok {
				inputs = append(inputs, Input{Target: TargetPath, Field: "path (base64)", Value: text})
			}
		}
	}

	for key, values := range r.URL.Query() {
		inputs = append(inputs, Input{Target: TargetQuery, Field: key, Value: key, Name: true})
		for _, v := range values {
			inputs = append(inputs, Input{Target: TargetQuery, Field: key, Value: v})
		}
	}
	// Also inspect the raw query: some payloads break the key=value format.
	if r.URL.RawQuery != "" {
		inputs = append(inputs, Input{Target: TargetQuery, Field: "(raw)", Value: r.URL.RawQuery})
	}

	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, "__sentinel_") {
			continue // Sentinel's own signed cookies (bot check)
		}
		inputs = append(inputs, Input{Target: TargetCookies, Field: c.Name, Value: c.Value})
	}

	names := make([]string, 0, len(r.Header))
	for h := range r.Header {
		if !skippedHeaders[h] && !strings.HasPrefix(h, "Sec-") {
			names = append(names, h)
		}
	}
	sort.Strings(names)
	for _, h := range names {
		for _, v := range r.Header.Values(h) {
			inputs = append(inputs, Input{Target: TargetHeaders, Field: h, Value: v})
		}
	}

	if len(body) > 0 {
		inputs = append(inputs, bodyInputs(r.Header.Get("Content-Type"), body)...)
	}
	// A value that is base64 for readable text is checked decoded too:
	// apps that decode a parameter would otherwise get an attack no rule saw.
	for _, in := range inputs {
		if in.Name || in.Field == "(raw)" {
			continue
		}
		if text, ok := Base64Text(in.Value); ok {
			inputs = append(inputs, Input{Target: in.Target, Field: in.Field + " (base64)", Value: text})
		}
	}
	return inputs
}

// Base64Text decodes a value that is base64 (standard or URL alphabet,
// with or without padding) of readable text with some punctuation. Tokens,
// IDs and binary data don't qualify, so they aren't checked twice.
func Base64Text(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 12 || len(v) > 64<<10 {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' || c == '=') {
			return "", false
		}
	}
	raw := strings.TrimRight(v, "=")
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err = enc.DecodeString(raw); err == nil {
			break
		}
	}
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	printable, punct := 0, 0
	for _, r := range string(b) {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r >= 0x20 && r != 0x7f:
			printable++
		}
		if strings.ContainsRune(`<>'"();=/\{}$|&*:%`, r) {
			punct++
		}
	}
	n := utf8.RuneCount(b)
	if n == 0 || printable*100 < n*97 || punct == 0 {
		return "", false
	}
	return string(b), true
}

func bodyInputs(contentType string, body []byte) []Input {
	mediaType, params, _ := mime.ParseMediaType(SingleContentType(contentType))

	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			var out []Input
			if depth(v) > MaxJSONDepth {
				// Deeply nested JSON crashes or stalls many parsers.
				return []Input{{Target: TargetBody, Field: "(structure)", Value: tooDeep}}
			}
			walkJSON("", v, &out)
			return out
		}
	case mediaType == "multipart/form-data" && params["boundary"] != "":
		// Each field is checked on its own (and file names), plus the raw
		// body as before: a field may hold an encoded attack.
		// The "--boundary" lines are left out: after a field's closing
		// quote they read as a SQL comment.
		raw := strings.ReplaceAll(string(body), "--"+params["boundary"], "\n")
		out := []Input{{Target: TargetBody, Field: "(raw)", Value: raw}}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for i := 0; i < MaxInputs; i++ {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			name := part.FormName()
			if fn := part.FileName(); fn != "" {
				out = append(out, Input{Target: TargetBody, Field: name + " (file name)", Value: fn})
			}
			value, _ := io.ReadAll(io.LimitReader(part, int64(MaxFieldBytes)+1))
			if part.FileName() == "" || utf8.Valid(value) {
				out = append(out, Input{Target: TargetBody, Field: name, Value: string(value)})
			}
		}
		return out
	case mediaType == "application/x-www-form-urlencoded":
		if form, err := url.ParseQuery(string(body)); err == nil {
			var out []Input
			for key, values := range form {
				out = append(out, Input{Target: TargetBody, Field: key, Value: key, Name: true})
				for _, v := range values {
					out = append(out, Input{Target: TargetBody, Field: key, Value: v})
				}
			}
			return out
		}
	}
	// Unknown type or unparseable body (often a sign of tampering): inspect raw.
	out := []Input{{Target: TargetBody, Field: "(raw)", Value: string(body)}}
	// Some servers parse a body by its content, not its declared type
	// (PHP's php://input, Express with type "*/*"). If it reads as a form,
	// check its fields too, so the ML model sees what a payload hidden
	// there would be: an attacker's way around the field checks.
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") && mediaType != "application/x-www-form-urlencoded" {
		out = append(out, fieldsByContent(body)...)
	}
	return out
}

// fieldsByContent splits a body of another declared type into form fields,
// when it starts like a form.
func fieldsByContent(body []byte) []Input {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || !utf8.Valid(b) {
		return nil
	}
	// JSON sent as text/plain is left raw: those are analytics beacons and
	// CSP reports, whose fields the model mistakes for code.
	first := formName.FindSubmatch(b)
	if first == nil {
		return nil
	}
	// Not url.ParseQuery: it refuses ";" and turns "+" into a space, and
	// command payloads are full of both. Each value is checked as sent
	// and, if different, decoded; and everything after the first "name="
	// as one value, since a payload may contain "&" itself.
	var out []Input
	add := func(k, v string) {
		out = append(out, Input{Target: TargetBody, Field: k, Value: v})
		if dec, err := url.QueryUnescape(v); err == nil && dec != v {
			out = append(out, Input{Target: TargetBody, Field: k, Value: dec})
		}
	}
	s := string(b)
	add(string(first[1]), s[len(first[0]):])
	if strings.Contains(s, "&") {
		for _, piece := range strings.Split(s, "&") {
			if k, v, ok := strings.Cut(piece, "="); ok && formKey.MatchString(k) {
				add(k, v)
			}
		}
	}
	return out
}

// formName is how a form body starts: a short field name and "=".
var (
	formName = regexp.MustCompile(`^([A-Za-z0-9_.\[\]-]{1,64})=`)
	formKey  = regexp.MustCompile(`^[A-Za-z0-9_.\[\]%-]{1,64}$`)
)

// MaxInputs is the most parameters, fields and headers inspected per request.
const MaxInputs = 1000

// MaxJSONInputs is the same limit for a JSON body. Analytics and
// session-replay batches often carry a few thousand fields (1,000 refused
// about 1 in 200 real requests); the size limits still bound the work.
const MaxJSONInputs = 10000

// MaxFieldBytes is the largest single value (field, header, raw body) that
// is inspected; larger ones are refused (rule BODY-003). 0 turns the check
// off. Set from WAF_MAX_FIELD_BYTES.
var MaxFieldBytes = 64 << 10

// MaxJSONDepth is the deepest JSON nesting accepted; real APIs rarely pass 10.
const MaxJSONDepth = 64

// tooDeep is a marker value that rule BODY-001 matches.
const tooDeep = "\x00sentinel:json-too-deep"

func depth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		m := 0
		for _, x := range t {
			m = max(m, depth(x))
		}
		return m + 1
	case []any:
		m := 0
		for _, x := range t {
			m = max(m, depth(x))
		}
		return m + 1
	}
	return 0
}

// walkJSON collects every string key and value from nested JSON.
func walkJSON(path string, v any, out *[]Input) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic order for logs and tests
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			*out = append(*out, Input{Target: TargetBody, Field: p, Value: k, Name: true})
			walkJSON(p, t[k], out)
		}
	case []any:
		for _, item := range t {
			walkJSON(path+"[]", item, out)
		}
	case string:
		*out = append(*out, Input{Target: TargetBody, Field: path, Value: t})
	}
}

// excerpt returns the matched text with a little context, capped for logs.
func excerpt(s string, start, end int) string {
	from, to := max(0, start-20), min(len(s), end+20)
	out := s[from:to]
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}
