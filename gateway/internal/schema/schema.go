// Package schema is check 6: API schema validation.
//
// A WAF looks for known-BAD input (a blocklist). Schema validation is the
// opposite, a "positive security model": the API's OpenAPI specification
// describes what GOOD requests look like, and anything else is rejected:
//   - endpoints or methods that aren't in the spec
//   - path/query values of the wrong type or format
//   - JSON fields the API doesn't expect ("role": "admin" sent to a profile
//     update = mass assignment, OWASP API Top 10)
//   - wrong types, too-long strings, bad emails, values out of range
//
// This supports the subset of OpenAPI 3 that real APIs use most: path and
// query parameters, JSON request bodies, $ref to components, and the
// keywords type, properties, required, additionalProperties, minProperties,
// minLength, maxLength, pattern, format (email), enum, minimum, maximum, items.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Schema is a JSON Schema object (OpenAPI flavour).
type Schema struct {
	Ref                  string             `json:"$ref"`
	Type                 string             `json:"type"`
	Properties           map[string]*Schema `json:"properties"`
	Required             []string           `json:"required"`
	AdditionalProperties *bool              `json:"additionalProperties"`
	MinProperties        *int               `json:"minProperties"`
	MinLength            *int               `json:"minLength"`
	MaxLength            *int               `json:"maxLength"`
	Pattern              string             `json:"pattern"`
	Format               string             `json:"format"`
	Enum                 []any              `json:"enum"`
	Minimum              *float64           `json:"minimum"`
	Maximum              *float64           `json:"maximum"`
	Items                *Schema            `json:"items"`

	re *regexp.Regexp
}

type Parameter struct {
	Name     string  `json:"name"`
	In       string  `json:"in"` // path or query
	Required bool    `json:"required"`
	Schema   *Schema `json:"schema"`
}

type Operation struct {
	Parameters  []Parameter `json:"parameters"`
	RequestBody *struct {
		Required bool `json:"required"`
		Content  map[string]struct {
			Schema *Schema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type spec struct {
	Components struct {
		Schemas map[string]*Schema `json:"schemas"`
	} `json:"components"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

type route struct {
	template string
	segments []string
	ops      map[string]*Operation // GET, PUT...
	params   []Parameter           // shared by all methods of the path
}

// Validator checks requests whose path starts with Prefix.
type Validator struct {
	Prefix string
	routes []*route
	named  map[string]*Schema
}

// Load reads an OpenAPI spec from path. With no path, schema validation is
// off and Load returns a nil Validator (which applies to nothing).
func Load(path, prefix string) (*Validator, error) {
	if path == "" {
		return nil, nil
	}
	if prefix == "" {
		return nil, fmt.Errorf("API_SPEC_PREFIX is required with API_SPEC_FILE (e.g. /api/)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading API spec: %w", err)
	}
	return Parse(data, prefix)
}

func Parse(data []byte, prefix string) (*Validator, error) {
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] != '{' {
		// YAML, the format most specs are written in.
		j, err := yamlToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("parsing API spec: %w", err)
		}
		data = j
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing API spec: %w", err)
	}
	v := &Validator{Prefix: prefix, named: s.Components.Schemas}
	for _, sc := range v.named {
		if err := v.compile(sc); err != nil {
			return nil, err
		}
	}
	for tmpl, item := range s.Paths {
		r := &route{template: tmpl, segments: split(tmpl), ops: map[string]*Operation{}}
		for key, raw := range item {
			if key == "parameters" {
				if err := json.Unmarshal(raw, &r.params); err != nil {
					return nil, fmt.Errorf("%s parameters: %w", tmpl, err)
				}
				continue
			}
			var op Operation
			if err := json.Unmarshal(raw, &op); err != nil {
				return nil, fmt.Errorf("%s %s: %w", key, tmpl, err)
			}
			r.ops[strings.ToUpper(key)] = &op
		}
		for _, p := range r.allParams() {
			if err := v.compile(p.Schema); err != nil {
				return nil, err
			}
		}
		for _, op := range r.ops {
			if op.RequestBody != nil {
				for _, c := range op.RequestBody.Content {
					if err := v.compile(c.Schema); err != nil {
						return nil, err
					}
				}
			}
		}
		v.routes = append(v.routes, r)
	}
	// Literal segments beat {params}: /admin/employees before /{x}/employees.
	sort.Slice(v.routes, func(i, j int) bool { return literals(v.routes[i]) > literals(v.routes[j]) })
	return v, nil
}

// Applies reports whether this validator is responsible for the path.
func (v *Validator) Applies(path string) bool {
	return v != nil && v.Prefix != "" && (path == strings.TrimSuffix(v.Prefix, "/") || strings.HasPrefix(path, v.Prefix))
}

// Error explains why a request doesn't match the spec.
type Error struct {
	Status  int    // 400, 404, 405 or 415
	Message string // safe to show the client
}

func (e *Error) Error() string { return e.Message }

// Validate checks one request. body is the (already read) request body.
func (v *Validator) Validate(r *http.Request, body []byte) *Error {
	segs := split(r.URL.Path)
	var rt *route
	var pathVals map[string]string
	for _, c := range v.routes {
		if vals, ok := matchPath(c.segments, segs); ok {
			rt, pathVals = c, vals
			break
		}
	}
	if rt == nil {
		return &Error{http.StatusNotFound, "endpoint is not in the API specification"}
	}
	op, ok := rt.ops[r.Method]
	if !ok {
		return &Error{http.StatusMethodNotAllowed, fmt.Sprintf("method %s is not allowed on %s", r.Method, rt.template)}
	}

	params := append(append([]Parameter{}, rt.params...), op.Parameters...)
	query := r.URL.Query()
	known := map[string]bool{}
	for _, p := range params {
		switch p.In {
		case "path":
			if msg := v.checkScalar(p.Schema, pathVals[p.Name]); msg != "" {
				return &Error{http.StatusBadRequest, fmt.Sprintf("path parameter '%s' %s", p.Name, msg)}
			}
		case "query":
			known[p.Name] = true
			vals, present := query[p.Name]
			if !present {
				if p.Required {
					return &Error{http.StatusBadRequest, fmt.Sprintf("query parameter '%s' is required", p.Name)}
				}
				continue
			}
			if len(vals) > 1 {
				return &Error{http.StatusBadRequest, fmt.Sprintf("query parameter '%s' was given more than once", p.Name)}
			}
			if msg := v.checkScalar(p.Schema, vals[0]); msg != "" {
				return &Error{http.StatusBadRequest, fmt.Sprintf("query parameter '%s' %s", p.Name, msg)}
			}
		}
	}
	for name := range query {
		if !known[name] {
			return &Error{http.StatusBadRequest, fmt.Sprintf("unexpected query parameter '%s'", name)}
		}
	}

	if op.RequestBody == nil {
		if len(bytes.TrimSpace(body)) > 0 {
			return &Error{http.StatusBadRequest, "this endpoint does not accept a request body"}
		}
		return nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if op.RequestBody.Required {
			return &Error{http.StatusBadRequest, "a JSON request body is required"}
		}
		return nil
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	content, ok := op.RequestBody.Content[mt]
	if !ok {
		return &Error{http.StatusUnsupportedMediaType, "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return &Error{http.StatusBadRequest, "request body is not valid JSON"}
	}
	if msg := v.check(content.Schema, doc, "body"); msg != "" {
		return &Error{http.StatusBadRequest, msg}
	}
	return nil
}

// check validates a JSON value; returns "" when valid.
func (v *Validator) check(s *Schema, val any, where string) string {
	s = v.resolve(s)
	if s == nil {
		return ""
	}
	if len(s.Enum) > 0 && !inEnum(s.Enum, val) {
		return fmt.Sprintf("%s must be one of %v", where, s.Enum)
	}
	switch s.Type {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			return where + " must be a JSON object"
		}
		if s.MinProperties != nil && len(obj) < *s.MinProperties {
			return fmt.Sprintf("%s must have at least %d field(s)", where, *s.MinProperties)
		}
		for _, req := range s.Required {
			if _, ok := obj[req]; !ok {
				return fmt.Sprintf("field '%s' is required", req)
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ps, ok := s.Properties[k]
			if !ok {
				if s.AdditionalProperties != nil && !*s.AdditionalProperties {
					return fmt.Sprintf("field '%s' is not allowed", k)
				}
				continue
			}
			if msg := v.check(ps, obj[k], "field '"+k+"'"); msg != "" {
				return msg
			}
		}
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return where + " must be an array"
		}
		for i, item := range arr {
			if msg := v.check(s.Items, item, fmt.Sprintf("%s[%d]", where, i)); msg != "" {
				return msg
			}
		}
	case "string":
		str, ok := val.(string)
		if !ok {
			return where + " must be a string"
		}
		if msg := v.checkString(s, str); msg != "" {
			return where + " " + msg
		}
	case "integer", "number":
		n, ok := val.(json.Number)
		if !ok {
			return where + " must be a number"
		}
		f, err := n.Float64()
		if err != nil || (s.Type == "integer" && f != math.Trunc(f)) {
			return where + " must be a whole number"
		}
		if msg := checkRange(s, f); msg != "" {
			return where + " " + msg
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return where + " must be true or false"
		}
	}
	return ""
}

// checkScalar validates a path/query value (always text in the URL).
func (v *Validator) checkScalar(s *Schema, raw string) string {
	s = v.resolve(s)
	if s == nil {
		return ""
	}
	if len(s.Enum) > 0 && !inEnum(s.Enum, raw) {
		return fmt.Sprintf("must be one of %v", s.Enum)
	}
	switch s.Type {
	case "integer", "number":
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || (s.Type == "integer" && f != math.Trunc(f)) {
			return "must be a whole number"
		}
		return checkRange(s, f)
	case "boolean":
		if raw != "true" && raw != "false" {
			return "must be true or false"
		}
		return ""
	default:
		return v.checkString(s, raw)
	}
}

func (v *Validator) checkString(s *Schema, str string) string {
	n := len([]rune(str))
	if s.MinLength != nil && n < *s.MinLength {
		return fmt.Sprintf("must be at least %d characters", *s.MinLength)
	}
	if s.MaxLength != nil && n > *s.MaxLength {
		return fmt.Sprintf("must be at most %d characters", *s.MaxLength)
	}
	if s.re != nil && !s.re.MatchString(str) {
		return "has an invalid format"
	}
	if s.Format == "email" {
		if a, err := mail.ParseAddress(str); err != nil || a.Address != str {
			return "must be a valid email address"
		}
	}
	return ""
}

func checkRange(s *Schema, f float64) string {
	if s.Minimum != nil && f < *s.Minimum {
		return fmt.Sprintf("must be at least %v", *s.Minimum)
	}
	if s.Maximum != nil && f > *s.Maximum {
		return fmt.Sprintf("must be at most %v", *s.Maximum)
	}
	return ""
}

func inEnum(enum []any, val any) bool {
	for _, e := range enum {
		if fmt.Sprint(e) == fmt.Sprint(val) {
			return true
		}
	}
	return false
}

func (v *Validator) resolve(s *Schema) *Schema {
	for depth := 0; s != nil && s.Ref != "" && depth < 10; depth++ {
		s = v.named[strings.TrimPrefix(s.Ref, "#/components/schemas/")]
	}
	return s
}

// compile pre-compiles regex patterns and checks $refs exist.
func (v *Validator) compile(s *Schema) error {
	if s == nil {
		return nil
	}
	if s.Ref != "" {
		if v.resolve(s) == nil {
			return fmt.Errorf("unknown schema reference %s", s.Ref)
		}
		return nil
	}
	if s.Pattern != "" && s.re == nil {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("bad pattern %q: %w", s.Pattern, err)
		}
		s.re = re
	}
	for _, p := range s.Properties {
		if err := v.compile(p); err != nil {
			return err
		}
	}
	return v.compile(s.Items)
}

func (r *route) allParams() []Parameter {
	all := append([]Parameter{}, r.params...)
	for _, op := range r.ops {
		all = append(all, op.Parameters...)
	}
	return all
}

func matchPath(tmpl, path []string) (map[string]string, bool) {
	if len(tmpl) != len(path) {
		return nil, false
	}
	vals := map[string]string{}
	for i, seg := range tmpl {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			vals[seg[1:len(seg)-1]] = path[i]
		} else if seg != path[i] {
			return nil, false
		}
	}
	return vals, true
}

func literals(r *route) int {
	n := 0
	for _, s := range r.segments {
		if !strings.HasPrefix(s, "{") {
			n++
		}
	}
	return n
}

func split(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// yamlToJSON converts a YAML document to JSON. Map keys become strings, as
// in JSON: status codes such as 200 are written without quotes in YAML.
func yamlToJSON(data []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(stringKeys(v))
}

func stringKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = stringKeys(e)
		}
		return x
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = stringKeys(e)
		}
		return m
	case []any:
		for i, e := range x {
			x[i] = stringKeys(e)
		}
		return x
	}
	return v
}
