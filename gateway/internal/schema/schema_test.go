package schema

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The lab's Staff API spec is a realistic example, so the tests use it.
const staffSpec = "../../testdata/staff-api.openapi.json"

func validator(t *testing.T) *Validator {
	t.Helper()
	v, err := Load(staffSpec, "/staff/api/")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestStaffSpec(t *testing.T) {
	v := validator(t)
	cases := []struct {
		name   string
		method string
		target string
		body   string
		ctype  string
		status int // 0 = valid
		msg    string
	}{
		{"health", "GET", "/staff/api/health", "", "", 0, ""},
		{"profile", "GET", "/staff/api/employees/alice", "", "", 0, ""},
		{"salary", "GET", "/staff/api/employees/bob/salary", "", "", 0, ""},
		{"update phone", "PUT", "/staff/api/employees/alice", `{"phone":"+964 770 123 4567"}`, "application/json", 0, ""},
		{"update email", "PUT", "/staff/api/employees/alice", `{"email":"alice@corp.example"}`, "application/json", 0, ""},
		{"admin list filtered", "GET", "/staff/api/admin/employees?department=hr&limit=5", "", "", 0, ""},

		{"mass assignment: role", "PUT", "/staff/api/employees/alice", `{"phone":"+9647701234567","role":"admin"}`, "application/json", 400, "field 'role' is not allowed"},
		{"mass assignment: salary", "PUT", "/staff/api/employees/alice", `{"salary":999999}`, "application/json", 400, "field 'salary' is not allowed"},
		{"bad email", "PUT", "/staff/api/employees/alice", `{"email":"not-an-email"}`, "application/json", 400, "valid email"},
		{"wrong type", "PUT", "/staff/api/employees/alice", `{"phone":7701234567}`, "application/json", 400, "must be a string"},
		{"empty object", "PUT", "/staff/api/employees/alice", `{}`, "application/json", 400, "at least 1"},
		{"no body", "PUT", "/staff/api/employees/alice", "", "application/json", 400, "required"},
		{"not json", "PUT", "/staff/api/employees/alice", `phone=1`, "application/json", 400, "not valid JSON"},
		{"two json docs", "PUT", "/staff/api/employees/alice", `{"phone":"+9647701234567"}{"role":"admin"}`, "application/json", 400, "not valid JSON"},
		{"form instead of json", "PUT", "/staff/api/employees/alice", `phone=1`, "application/x-www-form-urlencoded", 415, "application/json"},
		{"bad username", "GET", "/staff/api/employees/Robert');DROP", "", "", 400, "path parameter 'username'"},
		{"unknown endpoint", "GET", "/staff/api/debug", "", "", 404, "not in the API specification"},
		{"wrong method", "DELETE", "/staff/api/employees/alice", "", "", 405, "not allowed"},
		{"unknown query param", "GET", "/staff/api/employees/alice?debug=1", "", "", 400, "unexpected query parameter"},
		{"bad enum", "GET", "/staff/api/admin/employees?department=finance", "", "", 400, "must be one of"},
		{"limit too big", "GET", "/staff/api/admin/employees?limit=1000", "", "", 400, "at most 100"},
		{"limit not a number", "GET", "/staff/api/admin/employees?limit=abc", "", "", 400, "whole number"},
		{"duplicate query param", "GET", "/staff/api/admin/employees?limit=1&limit=2", "", "", 400, "more than once"},
		{"body on GET", "GET", "/staff/api/employees/alice", `{"x":1}`, "application/json", 400, "does not accept a request body"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
			if c.ctype != "" {
				r.Header.Set("Content-Type", c.ctype)
			}
			err := v.Validate(r, []byte(c.body))
			if c.status == 0 {
				if err != nil {
					t.Fatalf("expected valid, got %d %q", err.Status, err.Message)
				}
				return
			}
			if err == nil || err.Status != c.status || !strings.Contains(err.Message, c.msg) {
				t.Fatalf("expected %d containing %q, got %+v", c.status, c.msg, err)
			}
		})
	}
}

func TestApplies(t *testing.T) {
	v := validator(t)
	if !v.Applies("/staff/api/health") || v.Applies("/rest/products/search") || v.Applies("/staffroom") {
		t.Fatal("Applies prefix check is wrong")
	}
}

func TestNoSpecMeansOff(t *testing.T) {
	v, err := Load("", "")
	if err != nil || v != nil || v.Applies("/anything") {
		t.Fatalf("no spec file: validation must be off, got %v %v", v, err)
	}
	if _, err := Load(staffSpec, ""); err == nil {
		t.Fatal("a spec without a prefix must be rejected")
	}
}

func TestBadSpecRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"paths":{"/a":{"get":{"parameters":[{"name":"x","in":"query","schema":{"$ref":"#/components/schemas/Nope"}}]}}}}`), "/"); err == nil {
		t.Fatal("unknown $ref must be rejected")
	}
	if _, err := Parse([]byte(`{"paths":{"/a":{"get":{"parameters":[{"name":"x","in":"query","schema":{"type":"string","pattern":"("}}]}}}}`), "/"); err == nil {
		t.Fatal("bad regex must be rejected")
	}
}

func TestParseYAML(t *testing.T) {
	v, err := Parse([]byte(`openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /api/users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [name]
              properties:
                name: {type: string, maxLength: 5}
      responses:
        200: {description: ok}
`), "/api/")
	if err != nil {
		t.Fatal(err)
	}
	if v == nil || len(v.routes) != 1 {
		t.Fatalf("routes not read from YAML: %+v", v)
	}
}
