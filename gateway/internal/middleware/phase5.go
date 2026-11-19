package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/exclude"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/reqctx"
	"sentinel/gateway/internal/waf"
)

// ML (check 8) runs after the WAF rules let a request through and asks the
// classifier about each query and body field. In "detect" mode it only
// logs; in "block" mode it stops requests at or above the threshold.
func ML(m *ml.Model, mode string, threshold float64, skip []string, maxBody int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hasPrefix(r.URL.Path, skip) || strings.HasPrefix(r.URL.Path, "/__sentinel/") {
				next.ServeHTTP(w, r)
				return
			}
			body, err := peekBody(r, maxBody)
			if err != nil {
				bodyFail(w, r, err, maxBody, rec, log)
				return
			}
			var worst waf.Input
			best := 0.0
			for _, in := range MLInputs(r, body) {
				if Exclusions.ExcludedOn(reqctx.From(r.Context()).Site, "ML", r.Method, r.URL.Path, in.Field) {
					continue
				}
				if p, part := m.ScoreText(in.Value); p > best {
					best, worst = p, in
					worst.Value = part
				}
			}
			if best < threshold {
				next.ServeHTTP(w, r)
				return
			}
			info := reqctx.From(r.Context())
			ex := m.Explain(worst.Value, 3)
			kind := "ml_blocked"
			if mode == "detect" {
				kind = "detected"
			}
			field := worst.Field
			if field == "" {
				field = string(worst.Target)
			}
			info.SetOutcome(reqctx.Outcome{Kind: kind, Rule: "ML", Field: exclude.NormalizeField(field),
				Reason: fmt.Sprintf("ML: %.0f%% likely an attack", best*100),
				Detail: fmt.Sprintf("field: %s  value: %s  because: %s", field, cut(worst.Value, 60), ex.Summary())})
			record(rec, log, audit.Event{Type: "ml_" + map[bool]string{true: "detected", false: "blocked"}[mode == "detect"],
				ClientIP: info.ClientIP, RequestID: info.ID, Method: r.Method, Path: r.URL.Path,
				Detail: map[string]any{"field": field, "probability": best, "reasons": ex.Reasons}})
			if mode == "block" {
				writeBlocked(w, info.ID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Values too plain to carry an injection, which the model still flagged on
// real traffic: a bare word ("name" as a sort field: SQL vocabulary), an
// IP address with a port, the IAB privacy string "1---", and a GraphQL
// document without string literals. Bare shell commands stay scored: an
// app that runs a parameter as a command is exploited by "whoami" alone.
var (
	bareWord      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,40}$`)
	ipPort        = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$`)
	privacyString = regexp.MustCompile(`(?i)^1[-yn]{3}$`)
	shellCommands = map[string]bool{"id": true, "whoami": true, "uname": true, "ls": true, "pwd": true, "dir": true,
		"ifconfig": true, "ipconfig": true, "hostname": true, "phpinfo": true, "env": true, "set": true, "ver": true,
		"systeminfo": true, "netstat": true, "ps": true, "sh": true, "bash": true, "cmd": true, "powershell": true,
		"reboot": true, "shutdown": true, "halt": true, "passwd": true, "nc": true, "wget": true, "curl": true}
)

func inertValue(v string) bool {
	switch {
	case bareWord.MatchString(v):
		return !shellCommands[strings.ToLower(v)]
	case ipPort.MatchString(v), privacyString.MatchString(v):
		return true
	}
	return waf.PlainGraphQL(v)
}

// MLInputs are the values of a request the ML model scores: what users type
// (query and body fields, most headers), not names, the path or cookies.
// Shared with the trainer so it learns from exactly what the gateway asks.
func MLInputs(r *http.Request, body []byte) []waf.Input {
	var out []waf.Input
	for _, in := range waf.ExtractInputs(r, body) {
		// Names are left to the rules: the model scores what users type,
		// and a field called "pwd" is not a shell command. Cookies are left
		// to the rules too: browsers and analytics scripts fill them with
		// encoded JSON the model mistakes for injections.
		if in.Target == waf.TargetPath || in.Target == waf.TargetCookies || in.Field == "(raw)" || in.Name || len(in.Value) < 3 {
			continue
		}
		if inertValue(in.Value) {
			continue
		}
		if in.Target == waf.TargetHeaders && strings.EqualFold(in.Field, "Content-Type") {
			continue // checked by rules (Struts exploits); random boundaries confuse the model
		}
		if in.Target == waf.TargetHeaders && (strings.EqualFold(in.Field, "Referer") || strings.EqualFold(in.Field, "Origin")) {
			// A URL the browser sets: "http://localhost/..." looks like
			// SSRF to the model. Score only its query, where an injected
			// payload would be.
			u, err := url.Parse(in.Value)
			if err != nil {
				continue
			}
			q, err := url.QueryUnescape(u.RawQuery)
			if err != nil {
				q = u.RawQuery
			}
			if len(q) < 3 {
				continue
			}
			in.Value = q
		}
		out = append(out, in)
	}
	return out
}
