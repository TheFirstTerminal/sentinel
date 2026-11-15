package crs

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCRSRegressionSuite replays CRS's own regression tests (the go-ftw
// YAML files) through this engine and reports how many behave as CRS
// expects. It needs a CRS checkout: CRS_TEST_DIR=<crs>/rules.
type ftwFile struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		TestID int `yaml:"test_id"`
		Stages []struct {
			Input struct {
				Method       *string           `yaml:"method"`
				URI          *string           `yaml:"uri"`
				Version      *string           `yaml:"version"`
				Headers      map[string]string `yaml:"headers"`
				Data         string            `yaml:"data"`
				Encoded      string            `yaml:"encoded_request"`
				Autocomplete *bool             `yaml:"autocomplete_headers"`
			} `yaml:"input"`
			Output ftwOutput `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

type ftwOutput struct {
	Log struct {
		Expect   []int `yaml:"expect_ids"`
		NoExpect []int `yaml:"no_expect_ids"`
	} `yaml:"log"`
}

type override struct {
	RuleID  int       `yaml:"rule_id"`
	TestIDs []int     `yaml:"test_ids"`
	Output  ftwOutput `yaml:"output"`
}

func TestCRSRegressionSuite(t *testing.T) {
	dir := crsDir(t)
	set, err := Load(dir, 4) // the suite expects every paranoia level on
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "..", "tests", "regression")
	overrides := map[string]ftwOutput{}
	if data, err := os.ReadFile(filepath.Join(base, "coraza-overrides.yaml")); err == nil {
		var o struct {
			Overrides []override `yaml:"test_overrides"`
		}
		yaml.Unmarshal(data, &o)
		for _, ov := range o.Overrides {
			for _, id := range ov.TestIDs {
				overrides[fmt.Sprintf("%d-%d", ov.RuleID, id)] = ov.Output
			}
		}
	}
	files, _ := filepath.Glob(filepath.Join(base, "tests", "REQUEST-*", "*.yaml"))
	var pass, fail, goRejects, noCheck int
	failsByFile := map[string]int{}
	var failures []string
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var tf ftwFile
		if err := yaml.Unmarshal(data, &tf); err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, tc := range tf.Tests {
			for _, st := range tc.Stages {
				out := st.Output
				if ov, ok := overrides[fmt.Sprintf("%d-%d", tf.RuleID, tc.TestID)]; ok {
					out = ov
				}
				if len(out.Log.Expect) == 0 && len(out.Log.NoExpect) == 0 {
					noCheck++
					continue
				}
				raw := rawRequest(st.Input.Method, st.Input.URI, st.Input.Version, st.Input.Headers, st.Input.Data, st.Input.Encoded, st.Input.Autocomplete)
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
				if err != nil || req.ProtoMajor != 1 {
					goRejects++ // Go's HTTP server refuses this request before any check
					continue
				}
				body, _ := io.ReadAll(req.Body)
				res := set.Evaluate(req, body)
				fired := map[int]bool{}
				for _, m := range res.Matches {
					fired[m.ID] = true
				}
				ok := true
				for _, id := range out.Log.Expect {
					if !fired[id] {
						ok = false
					}
				}
				for _, id := range out.Log.NoExpect {
					if fired[id] {
						ok = false
					}
				}
				if ok {
					pass++
				} else {
					fail++
					failsByFile[filepath.Base(filepath.Dir(f))]++
					var got []int
					for id := range fired {
						got = append(got, id)
					}
					sort.Ints(got)
					failures = append(failures, fmt.Sprintf("%d-%d expect %v no %v got %v", tf.RuleID, tc.TestID, out.Log.Expect, out.Log.NoExpect, got))
				}
			}
		}
	}
	total := pass + fail
	t.Logf("CRS regression suite: %d/%d passed (%.1f%%); %d refused by Go's HTTP parser; %d have no log expectation",
		pass, total, 100*float64(pass)/float64(total), goRejects, noCheck)
	for k, v := range failsByFile {
		t.Logf("  failures in %s: %d", k, v)
	}
	if os.Getenv("CRS_SHOW_FAILURES") != "" {
		for _, f := range failures {
			t.Log(f)
		}
	}
	if min := 0.98; float64(pass)/float64(total) < min {
		t.Errorf("pass rate below %.0f%%", min*100)
	}
}

func rawRequest(method, uri, version *string, headers map[string]string, data, encoded string, auto *bool) []byte {
	if encoded != "" {
		b, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(encoded, "\n", ""))
		return b
	}
	m, u, v := "GET", "/", "HTTP/1.1"
	if method != nil {
		m = *method
	}
	if uri != nil {
		u = *uri
	}
	if version != nil {
		v = *version
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", m, u, v)
	has := func(k string) bool {
		for h := range headers {
			if strings.EqualFold(h, k) {
				return true
			}
		}
		return false
	}
	keys := sortedKeys(headers)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, headers[k])
	}
	if auto == nil || *auto {
		if data != "" && !has("Content-Length") && !has("Transfer-Encoding") {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(data))
		}
		if data != "" && !has("Content-Type") {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		}
		if !has("Connection") {
			b.WriteString("Connection: close\r\n")
		}
		if !has("Host") {
			b.WriteString("Host: localhost\r\n")
		}
	}
	b.WriteString("\r\n")
	b.WriteString(data)
	return b.Bytes()
}
