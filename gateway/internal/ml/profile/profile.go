// Package profile learns what normal traffic to one app looks like, field
// by field, and flags requests that don't fit: anomaly detection, the
// classic approach for web traffic (Kruegel and Vigna, "Anomaly Detection
// of Web-based Attacks", 2003).
//
// It needs no attack examples. From normal traffic it learns, for each page
// (path) and each of its parameters: the usual length, the characters used,
// whether the value is always a number, and, for fields with a few fixed
// values, those values. It also learns which pages and parameters exist.
// A request is anomalous when something falls outside what was learned.
//
// This catches what attack-syntax rules and the attack classifier can't:
// parameter tampering, such as a quantity of "9e3k" or a 500-character
// "name". It only knows one app: learn it from that app's own traffic.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

// Field is what was learned about one parameter of one page.
type Field struct {
	N       int             `json:"n"`
	MinLen  int             `json:"min_len"`
	MaxLen  int             `json:"max_len"`
	Classes string          `json:"classes"` // character classes seen (see class)
	Numeric bool            `json:"numeric"` // every value was a number
	Values  map[string]bool `json:"values,omitempty"`
	many    bool            // too many distinct values to be a fixed list
}

// Page is what was learned about one path.
type Page struct {
	N      int               `json:"n"`
	Fields map[string]*Field `json:"fields"`
}

// Profile is a learned app.
type Profile struct {
	mu       sync.RWMutex
	Pages    map[string]*Page `json:"pages"`
	Requests int              `json:"requests"`
}

// Anomaly is one thing in a request that doesn't fit the profile.
type Anomaly struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
	Value  string `json:"value"`
}

const maxEnum = 12 // a field with this many distinct values or fewer is a fixed list (if seen often)

func New() *Profile { return &Profile{Pages: map[string]*Page{}} }

// class maps a byte to its character class: letters and digits are
// grouped (any letter is like any other), punctuation is kept exactly,
// and non-ASCII bytes (accents, other alphabets) are one class.
func class(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return 'a'
	case c >= '0' && c <= '9':
		return '0'
	case c >= 0x80:
		return 'u'
	case c < 0x20 || c == 0x7f:
		return 'c' // control characters
	}
	return c
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && !(i == 0 && s[i] == '-') && s[i] != '.' {
			return false
		}
	}
	return true
}

type input struct{ Field, Value string }

// inputs are the query and form parameters (names and decoded values).
func inputs(r *http.Request, body []byte) []input {
	out := params(r.URL.RawQuery)
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if len(body) > 0 && (ct == "" || strings.HasPrefix(ct, "application/x-www-form-urlencoded")) {
		out = append(out, params(string(body))...)
	}
	return out
}

func params(s string) []input {
	var out []input
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out = append(out, input{unescape(k), unescape(v)})
	}
	return out
}

// unescape decodes %XX and '+', keeping anything malformed as it is.
func unescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// Learn adds one normal request.
func (p *Profile) Learn(r *http.Request, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Requests++
	pg := p.Pages[r.URL.Path]
	if pg == nil {
		pg = &Page{Fields: map[string]*Field{}}
		p.Pages[r.URL.Path] = pg
	}
	pg.N++
	for _, in := range inputs(r, body) {
		f := pg.Fields[in.Field]
		if f == nil {
			f = &Field{MinLen: len(in.Value), MaxLen: len(in.Value), Numeric: true, Values: map[string]bool{}}
			pg.Fields[in.Field] = f
		}
		f.N++
		f.MinLen = min(f.MinLen, len(in.Value))
		f.MaxLen = max(f.MaxLen, len(in.Value))
		f.Numeric = f.Numeric && isNumber(in.Value)
		for i := 0; i < len(in.Value); i++ {
			if c := class(in.Value[i]); !strings.ContainsRune(f.Classes, rune(c)) {
				f.Classes += string(rune(c))
			}
		}
		if f.Values == nil {
			f.many = true // (a profile loaded from a file: nil means "many")
		}
		if !f.many {
			f.Values[in.Value] = true
			if len(f.Values) > maxEnum {
				f.many, f.Values = true, nil
			}
		}
	}
}

// Check returns what doesn't fit (nil = nothing). minSeen is how often a
// page or field must have been seen before Sentinel trusts what it learned
// about it (too few examples = no opinion).
func (p *Profile) Check(r *http.Request, body []byte, minSeen int) []Anomaly {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pg := p.Pages[r.URL.Path]
	if pg == nil {
		if p.Requests >= minSeen*10 {
			return []Anomaly{{Field: "(path)", Reason: "a page this app never served", Value: r.URL.Path}}
		}
		return nil
	}
	if pg.N < minSeen {
		return nil
	}
	var out []Anomaly
	for _, in := range inputs(r, body) {
		f := pg.Fields[in.Field]
		if f == nil {
			out = append(out, Anomaly{in.Field, "a parameter this page never had", in.Value})
			continue
		}
		if f.N < minSeen {
			continue
		}
		v := in.Value
		switch {
		case f.Values != nil && len(f.Values) <= maxEnum && f.N >= minSeen*5 && !f.Values[v]:
			out = append(out, Anomaly{in.Field, fmt.Sprintf("not one of its %d usual values", len(f.Values)), v})
		case f.Numeric && !isNumber(v):
			out = append(out, Anomaly{in.Field, "always a number, but this isn't", v})
		case len(v) > f.MaxLen+f.MaxLen/4+2:
			out = append(out, Anomaly{in.Field, fmt.Sprintf("%d characters, longest usual is %d", len(v), f.MaxLen), v})
		default:
			for i := 0; i < len(v); i++ {
				if c := class(v[i]); !strings.ContainsRune(f.Classes, rune(c)) {
					what := fmt.Sprintf("%q", string(v[i]))
					if c == 'u' {
						what = "non-ASCII text"
					}
					out = append(out, Anomaly{in.Field, "contains " + what + ", which this field never had", v})
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// Save writes the profile as JSON (atomically).
func (p *Profile) Save(path string) error {
	p.mu.RLock()
	data, err := json.Marshal(p)
	p.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a saved profile (a missing file gives an empty one).
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	} else if err != nil {
		return nil, err
	}
	p := New()
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Pages == nil {
		p.Pages = map[string]*Page{}
	}
	return p, nil
}

// Stats: how much has been learned.
func (p *Profile) Stats() (requests, pages, fields int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pg := range p.Pages {
		fields += len(pg.Fields)
	}
	return p.Requests, len(p.Pages), fields
}
