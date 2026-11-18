package crs

import (
	"net"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sentinel/gateway/internal/prefilter"
	"sort"
	"strconv"
	"strings"
)

type varSpec struct {
	name    string // ARGS, REQUEST_HEADERS...
	key     string // lowercased exact key, or ""
	keyRe   *regexp.Regexp
	exclude bool // !ARGS:foo
	count   bool // &ARGS
}

// collections hold several named values; selecting a key picks one.
var collections = map[string]bool{
	"ARGS": true, "ARGS_GET": true, "ARGS_POST": true,
	"ARGS_NAMES": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true,
	"REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true,
	"REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true,
	"FILES": true, "FILES_NAMES": true, "MULTIPART_PART_HEADERS": true,
	"XML": true, "TX": true, "MATCHED_VARS": true, "MATCHED_VARS_NAMES": true,
}

// singles hold one value.
var singles = map[string]bool{
	"REQUEST_URI": true, "REQUEST_URI_RAW": true, "REQUEST_FILENAME": true, "REQUEST_BASENAME": true,
	"REQUEST_LINE": true, "REQUEST_METHOD": true, "REQUEST_PROTOCOL": true, "QUERY_STRING": true,
	"REQUEST_BODY": true, "REQUEST_BODY_LENGTH": true, "ARGS_COMBINED_SIZE": true, "FILES_COMBINED_SIZE": true,
	"REQBODY_PROCESSOR": true, "REQBODY_ERROR": true, "MATCHED_VAR": true, "MATCHED_VAR_NAME": true,
	"REMOTE_ADDR": true, "UNIQUE_ID": true, "MULTIPART_STRICT_ERROR": true, "MULTIPART_UNMATCHED_BOUNDARY": true,
}

func parseVars(s string) ([]varSpec, error) {
	var out []varSpec
	for _, part := range strings.Split(s, "|") {
		var v varSpec
		if strings.HasPrefix(part, "!") {
			v.exclude, part = true, part[1:]
		}
		if strings.HasPrefix(part, "&") {
			v.count, part = true, part[1:]
		}
		name, key, hasKey := strings.Cut(part, ":")
		v.name = strings.ToUpper(name)
		if !collections[v.name] && !singles[v.name] {
			return nil, fmt.Errorf("variable %s", v.name)
		}
		if hasKey {
			key = strings.Trim(key, "'")
			if v.name == "XML" {
				v.key = key // an XPath: "/*" (text) or "//@*" (attributes)
			} else if len(key) >= 2 && key[0] == '/' && key[len(key)-1] == '/' {
				re, err := regexp.Compile("(?i)" + key[1:len(key)-1])
				if err != nil {
					return nil, fmt.Errorf("variable key regex not supported")
				}
				v.keyRe = re
			} else {
				v.key = strings.ToLower(key)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

type kv struct{ key, value string }

// Tx is one request being checked: its variables and the TX collection.
type Tx struct {
	cols   map[string][]kv
	single map[string]string
	tx     map[string]string

	matched  []kv // MATCHED_VARS of the current rule (key = full name)
	current  *Rule
	body     []byte
	argsSize int

	removedRanges  [][2]int
	removedTags    []string
	targetRemovals []targetRemoval

	matchedVar kv
	ruleID     int
	matches    []Match
	tcache     map[[2]string]string
	vcache     map[string][]kv // values of fixed variable lists
	txSorted   []kv            // TX in key order; nil when TX changed

	// Per-request caches: the same values are looked at by hundreds of rules.
	names    map[string][]string // "ARGS:q"-style names of each request collection
	singleKV map[string][]kv     // single variables, wrapped once
	lower    map[string]string   // lowercased values, for the prefilters
}

// lowerOf is prefilter.Lower, remembered for the request.
func (tx *Tx) lowerOf(v string) string {
	if l, ok := tx.lower[v]; ok {
		return l
	}
	l := prefilter.Lower(v)
	if l == v {
		return v // nothing to lower: not worth remembering
	}
	if tx.lower == nil {
		tx.lower = map[string]string{}
	}
	tx.lower[v] = l
	return l
}

// itemNames returns "COL:key" for each item of a request collection.
func (tx *Tx) itemNames(col string, items []kv) []string {
	if col == "TX" || col == "MATCHED_VARS" || col == "MATCHED_VARS_NAMES" {
		out := make([]string, len(items))
		for i, it := range items {
			out[i] = col + ":" + it.key
		}
		return out
	}
	if n, ok := tx.names[col]; ok && len(n) == len(items) {
		return n
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = col + ":" + it.key
	}
	if tx.names == nil {
		tx.names = map[string][]string{}
	}
	tx.names[col] = out
	return out
}

// newTx builds the variables of a request. body is its (complete) body.
func newTx(r *http.Request, body []byte) *Tx {
	tx := &Tx{cols: map[string][]kv{}, single: map[string]string{}, tx: map[string]string{}, body: body}
	add := tx.add
	arg := tx.addArg
	for _, p := range parseArgs(r.URL.RawQuery) {
		arg("GET", p.key, p.value)
	}

	for _, c := range r.Cookies() {
		add("REQUEST_COOKIES", c.Name, c.Value)
		add("REQUEST_COOKIES_NAMES", c.Name, c.Name)
	}
	if len(r.Cookies()) == 0 && r.Header.Get("Cookie") != "" {
		// Go drops cookies it can't parse; ModSecurity keeps them.
		for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
			add("REQUEST_COOKIES", k, v)
			add("REQUEST_COOKIES_NAMES", k, k)
		}
	}

	hdr := func(k, v string) {
		add("REQUEST_HEADERS", k, v)
		add("REQUEST_HEADERS_NAMES", k, k)
	}
	if r.Host != "" {
		hdr("Host", r.Host)
	}
	for _, k := range sortedKeys(r.Header) {
		for _, v := range r.Header[k] {
			hdr(k, v)
		}
	}
	if len(r.TransferEncoding) > 0 {
		hdr("Transfer-Encoding", strings.Join(r.TransferEncoding, ","))
	}
	if r.ContentLength > 0 && r.Header.Get("Content-Length") == "" {
		hdr("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}

	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	file, _, _ := strings.Cut(uri, "?")
	if strings.Contains(file, "://") { // absolute form: drop the scheme and host
		if u, err := url.Parse(file); err == nil {
			file = u.EscapedPath()
		}
	}
	tx.single["REQUEST_URI"] = uri
	tx.single["REQUEST_URI_RAW"] = uri
	// As in ModSecurity, the path variables are URL-decoded (once).
	if dec, err := url.PathUnescape(file); err == nil {
		file = dec
	}
	tx.single["REQUEST_FILENAME"] = file
	tx.single["REQUEST_BASENAME"] = path.Base("/" + file)
	if strings.HasSuffix(file, "/") {
		tx.single["REQUEST_BASENAME"] = ""
	}
	tx.single["QUERY_STRING"] = r.URL.RawQuery
	tx.single["REQUEST_METHOD"] = r.Method
	tx.single["REQUEST_PROTOCOL"] = r.Proto
	tx.single["REQUEST_LINE"] = r.Method + " " + uri + " " + r.Proto
	tx.single["REQUEST_BODY_LENGTH"] = strconv.Itoa(len(body))
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		tx.single["REMOTE_ADDR"] = host // also right for IPv6 ("[::1]:80")
	} else {
		tx.single["REMOTE_ADDR"] = r.RemoteAddr
	}
	tx.single["REQBODY_ERROR"] = "0"
	tx.single["ARGS_COMBINED_SIZE"] = "0"

	if len(body) > 0 {
		ct := r.Header.Get("Content-Type")
		mt, params, _ := mime.ParseMediaType(ct)
		switch {
		case mt == "application/x-www-form-urlencoded":
			tx.single["REQBODY_PROCESSOR"] = "URLENCODED"
			tx.single["REQUEST_BODY"] = string(body)
			for _, p := range parseArgs(string(body)) {
				arg("POST", p.key, p.value)
			}
		case mt == "application/json" || strings.HasSuffix(mt, "+json"):
			tx.single["REQBODY_PROCESSOR"] = "JSON"
			var v any
			if err := json.Unmarshal(body, &v); err != nil {
				tx.single["REQBODY_ERROR"] = "1"
			} else {
				walkJSON("json", v, func(k, val string) { arg("POST", k, val) })
			}
		case mt == "multipart/form-data":
			tx.single["REQBODY_PROCESSOR"] = "MULTIPART"
			filesSize := 0
			mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					tx.single["REQBODY_ERROR"] = "1"
					tx.single["MULTIPART_STRICT_ERROR"] = "1"
					break
				}
				for _, k := range sortedKeys(p.Header) {
					for _, hv := range p.Header[k] {
						add("MULTIPART_PART_HEADERS", p.FormName(), k+": "+hv)
					}
				}
				data, _ := io.ReadAll(io.LimitReader(p, int64(len(body))))
				if p.FileName() != "" {
					add("FILES", p.FormName(), p.FileName())
					add("FILES_NAMES", p.FormName(), p.FormName())
					filesSize += len(data)
				} else {
					arg("POST", p.FormName(), string(data))
				}
			}
			tx.single["FILES_COMBINED_SIZE"] = strconv.Itoa(filesSize)
		case strings.HasSuffix(mt, "/xml") || strings.HasSuffix(mt, "+xml"):
			tx.single["REQBODY_PROCESSOR"] = "XML"
			d := xml.NewDecoder(bytes.NewReader(body))
			d.Strict = false
			for {
				t, err := d.Token()
				if err != nil {
					if err != io.EOF {
						tx.single["REQBODY_ERROR"] = "1"
					}
					break
				}
				switch e := t.(type) {
				case xml.CharData:
					if s := strings.TrimSpace(string(e)); s != "" {
						add("XML", "/*", s)
					}
				case xml.StartElement:
					for _, a := range e.Attr {
						add("XML", "//@*", a.Value)
					}
				}
			}
		}
	}
	if _, parsed := tx.single["REQBODY_PROCESSOR"]; !parsed && len(body) > 0 {
		// No processor understands this body (text/plain, octet-stream...):
		// keep it visible so an attack can't hide in an odd content type.
		tx.single["REQUEST_BODY"] = string(body)
	}
	return tx
}

func (tx *Tx) add(col, k, v string) { tx.cols[col] = append(tx.cols[col], kv{k, v}) }

func (tx *Tx) addArg(src, k, v string) {
	tx.vcache = nil
	tx.add("ARGS", k, v)
	tx.add("ARGS_NAMES", k, k)
	tx.add("ARGS_"+src, k, v)
	tx.add("ARGS_"+src+"_NAMES", k, k)
	tx.argsSize += len(k) + len(v)
	tx.single["ARGS_COMBINED_SIZE"] = strconv.Itoa(tx.argsSize)
}

// parseArgs splits a query string or form body the way ModSecurity does:
// only "&" separates arguments (Go's parser also rejects ";", which would
// let an attacker hide a payload from the checks), and bad %-escapes are
// kept as they are instead of dropping the argument.
func parseArgs(s string) []kv {
	var out []kv
	if s == "" {
		return nil
	}
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out = append(out, kv{urlDecode(k, false), urlDecode(v, false)})
	}
	return out
}

func walkJSON(prefix string, v any, f func(k, v string)) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			walkJSON(prefix+"."+k, x[k], f)
		}
	case []any:
		for i, item := range x {
			walkJSON(prefix+"."+strconv.Itoa(i), item, f)
		}
	case string:
		f(prefix, x)
	case nil:
		f(prefix, "")
	case bool:
		f(prefix, strconv.FormatBool(x))
	case float64:
		f(prefix, strconv.FormatFloat(x, 'f', -1, 64))
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// values returns the (name, value) pairs a rule's variables select.
func (tx *Tx) values(specs []varSpec) []kv {
	var out []kv
	type exclKey struct{ col, key string }
	var excluded map[exclKey]bool // most rules exclude nothing: no map then
	var exclRe []varSpec
	for _, s := range specs {
		if s.exclude {
			if s.keyRe != nil {
				exclRe = append(exclRe, s)
			} else {
				if excluded == nil {
					excluded = map[exclKey]bool{}
				}
				excluded[exclKey{s.name, s.key}] = true
			}
		}
	}
	isExcluded := func(col, key string) bool {
		if excluded == nil && exclRe == nil {
			return false
		}
		if excluded[exclKey{col, strings.ToLower(key)}] {
			return true
		}
		for _, s := range exclRe {
			if s.name == col && s.keyRe.MatchString(key) {
				return true
			}
		}
		return false
	}
	for _, s := range specs {
		if s.exclude {
			continue
		}
		if excluded[exclKey{s.name, ""}] {
			continue // the whole variable was removed (e.g. by ctl)
		}
		if s.name == "TX" && s.key != "" && s.keyRe == nil {
			// One TX variable by name: look it up instead of sorting all of
			// TX, which changes after almost every rule (anomaly scores).
			key := strings.ToLower(s.key)
			v, ok := tx.tx[key]
			if s.count {
				n := 0
				if ok {
					n = 1
				}
				out = append(out, kv{"&TX", strconv.Itoa(n)})
			} else if ok && !isExcluded("TX", key) {
				out = append(out, kv{"TX:" + key, v})
			}
			continue
		}
		items := tx.collection(s.name)
		if s.key != "" || s.keyRe != nil {
			var sel []kv
			for _, it := range items {
				if (s.name == "XML" && it.key == s.key) || (s.keyRe != nil && s.keyRe.MatchString(it.key)) || (s.keyRe == nil && strings.EqualFold(it.key, s.key)) {
					sel = append(sel, it)
				}
			}
			items = sel
		}
		if s.count {
			out = append(out, kv{"&" + s.name, strconv.Itoa(len(items))})
			continue
		}
		if !collections[s.name] {
			for _, it := range items {
				out = append(out, kv{s.name, it.value})
			}
			continue
		}
		names := tx.itemNames(s.name, items)
		for i, it := range items {
			if isExcluded(s.name, it.key) {
				continue
			}
			out = append(out, kv{names[i], it.value})
		}
	}
	return out
}

func (tx *Tx) collection(name string) []kv {
	switch name {
	case "TX":
		if tx.txSorted == nil {
			tx.txSorted = make([]kv, 0, len(tx.tx))
			for _, k := range sortedKeys(tx.tx) {
				tx.txSorted = append(tx.txSorted, kv{k, tx.tx[k]})
			}
		}
		return tx.txSorted
	case "MATCHED_VARS":
		return tx.matched
	case "MATCHED_VARS_NAMES":
		out := make([]kv, len(tx.matched))
		for i, m := range tx.matched {
			out[i] = kv{m.key, m.key}
		}
		return out
	case "MATCHED_VAR":
		if tx.matchedVar.key == "" {
			return nil
		}
		return []kv{{"", tx.matchedVar.value}}
	case "MATCHED_VAR_NAME":
		if tx.matchedVar.key == "" {
			return nil
		}
		return []kv{{"", tx.matchedVar.key}}
	}
	if collections[name] {
		return tx.cols[name]
	}
	if v, ok := tx.single[name]; ok {
		if w, ok := tx.singleKV[name]; ok && w[0].value == v {
			return w
		}
		w := []kv{{"", v}}
		if tx.singleKV == nil {
			tx.singleKV = map[string][]kv{}
		}
		tx.singleKV[name] = w
		return w
	}
	return nil
}
