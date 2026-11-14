// Package csic reads the CSIC 2010 HTTP dataset (Spanish National Research
// Council): 36,000 normal training requests, 36,000 normal test requests
// and 25,065 attacks (SQL injection, XSS, buffer overflow, CRLF, SSI, file
// disclosure, parameter tampering...) against a web shop.
//
// The files are plain HTTP requests separated by blank lines. Get them from
// https://www.tic.itefi.csic.es/dataset/ (or a mirror) and point -csic at
// the folder with normalTrafficTraining.txt, normalTrafficTest.txt and
// anomalousTrafficTest.txt.
package csic

import (
	"bytes"
	"fmt"

	"io"
	"net/http"
	"net/url"
	"os"
	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/ml/profile"
	"sentinel/gateway/internal/waf"
	"strconv"
	"strings"
)

// Request is one request from the dataset.
type Request struct {
	Req    *http.Request
	Body   []byte
	Attack bool
}

// Load reads one dataset file. attack says what its requests are.
func Load(path string, attack bool) ([]Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	var out []Request
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); {
		// Skip to a request line.
		for i < len(lines) && !isRequestLine(lines[i]) {
			i++
		}
		if i >= len(lines) {
			break
		}
		start := lines[i]
		i++
		hdr := http.Header{}
		clen := 0
		for i < len(lines) && lines[i] != "" {
			k, v, ok := strings.Cut(lines[i], ":")
			if ok {
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				hdr.Add(k, v)
				if strings.EqualFold(k, "Content-Length") {
					clen, _ = strconv.Atoi(v)
				}
			}
			i++
		}
		i++ // the blank line
		var body []byte
		if clen > 0 && i < len(lines) {
			body = []byte(lines[i])
			i++
		}
		parts := strings.Fields(start)
		u, err := url.Parse(parts[1])
		if err != nil {
			// Some attacks are not valid URLs; Go's server would refuse them,
			// so keep the raw text as the path to inspect.
			u = &url.URL{Path: strings.TrimPrefix(parts[1], "http://localhost:8080")}
		}
		r, err := http.NewRequest(parts[0], "http://localhost"+u.RequestURI(), io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			r, _ = http.NewRequest(parts[0], "http://localhost/", io.NopCloser(bytes.NewReader(body)))
			r.URL.Path = u.Path
		}
		r.Header = hdr
		r.Host = hdr.Get("Host")
		r.ContentLength = int64(len(body))
		if len(body) > 0 && r.Header.Get("Content-Type") == "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		out = append(out, Request{Req: r, Body: body, Attack: attack})
	}
	return out, nil
}

func isRequestLine(l string) bool {
	return (strings.HasPrefix(l, "GET ") || strings.HasPrefix(l, "POST ") || strings.HasPrefix(l, "PUT ")) && strings.HasSuffix(l, "HTTP/1.1")
}

// Fresh returns a copy of the request whose body can be read again.
func (q Request) Fresh() *http.Request {
	r := q.Req.Clone(q.Req.Context())
	r.Body = io.NopCloser(bytes.NewReader(q.Body))
	return r
}

// Evaluate returns a Markdown table: rules, ML, both (and CRS if given).
func Evaluate(normal, attacks []Request, m *ml.Model, crsDir string) string {
	return EvaluateWithProfile(normal, attacks, m, crsDir, nil)
}

// EvaluateWithProfile also tests an app profile learned from normal traffic
// (nil = skip it).
func EvaluateWithProfile(normal, attacks []Request, m *ml.Model, crsDir string, prof *profile.Profile) string {
	rules, err := waf.LoadRules("")
	if err != nil {
		panic(err)
	}
	plain := waf.NewEngine(rules, 5)
	var withCRS *waf.Engine
	if crsDir != "" {
		set, err := crs.Load(crsDir, 1)
		if err != nil {
			panic(err)
		}
		set.Exclude([]string{"920220"})
		withCRS = waf.NewEngine(rules, 5)
		withCRS.UseCRS(set)
	}
	type counts struct{ hit, n int }
	layers := []string{"Sentinel rules", "ML", "Sentinel rules + ML"}
	if withCRS != nil {
		layers = append(layers, "Sentinel rules + OWASP CRS", "Sentinel rules + OWASP CRS + ML")
	}
	if prof != nil {
		layers = append(layers, "App profile (anomaly detection)", "Sentinel rules + ML + app profile")
		if withCRS != nil {
			layers = append(layers, "All: rules + CRS + ML + app profile")
		}
	}
	det := map[string]*counts{}
	fp := map[string]*counts{}
	for _, l := range layers {
		det[l], fp[l] = &counts{}, &counts{}
	}
	run := func(q Request, into map[string]*counts) {
		r := q.Fresh()
		rule := plain.Inspect(r, q.Body).Attack
		mlHit := MLHit(m, q)
		res := map[string]bool{"Sentinel rules": rule, "ML": mlHit, "Sentinel rules + ML": rule || mlHit}
		c := false
		if withCRS != nil {
			c = withCRS.Inspect(q.Fresh(), q.Body).Attack
			res["Sentinel rules + OWASP CRS"] = c
			res["Sentinel rules + OWASP CRS + ML"] = c || mlHit
		}
		if prof != nil {
			a := len(prof.Check(q.Fresh(), q.Body, ProfileMinSeen)) > 0
			res["App profile (anomaly detection)"] = a
			res["Sentinel rules + ML + app profile"] = rule || mlHit || a
			res["All: rules + CRS + ML + app profile"] = c || rule || mlHit || a
		}
		for _, l := range layers {
			into[l].n++
			if res[l] {
				into[l].hit++
			}
		}
	}
	for _, q := range attacks {
		run(q, det)
	}
	for _, q := range normal {
		run(q, fp)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "| Layers | Attacks caught (of %d) | Normal requests wrongly flagged (of %d) |\n|---|---|---|\n", len(attacks), len(normal))
	for _, l := range layers {
		fmt.Fprintf(&b, "| %s | %.1f%% | %.2f%% |\n", l, 100*float64(det[l].hit)/float64(det[l].n), 100*float64(fp[l].hit)/float64(fp[l].n))
	}
	return b.String()
}

// MLHit scores a request the way the gateway's ML check does: every
// query, form, cookie and header value (not the path), highest score wins.
func MLHit(m *ml.Model, q Request) bool {
	for _, in := range Values(q) {
		if p, _ := m.ScoreText(in.Value); p >= 0.9 {
			return true
		}
	}
	return false
}

// ProfileMinSeen: how often a page or field must have been seen before the
// profile has an opinion about it.
const ProfileMinSeen = 20

// LearnProfile learns an app profile from normal requests.
func LearnProfile(normal []Request) *profile.Profile {
	p := profile.New()
	for _, q := range normal {
		p.Learn(q.Fresh(), q.Body)
	}
	return p
}

// Values returns the values the gateway's ML check would score in a
// request, by field.
func Values(q Request) []waf.Input {
	var out []waf.Input
	for _, in := range waf.ExtractInputs(q.Fresh(), q.Body) {
		if in.Target == waf.TargetPath || in.Field == "(raw)" || in.Name || len(in.Value) < 3 || strings.EqualFold(in.Field, "Content-Type") {
			continue
		}
		out = append(out, in)
	}
	return out
}
