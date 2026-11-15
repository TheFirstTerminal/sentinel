package middleware

import (
	"net/url"

	"sentinel/gateway/internal/exclude"

	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/audit"
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
			for _, in := range waf.ExtractInputs(r, body) {
				// Names are left to the rules: the model scores what users
				// type, and a field called "pwd" is not a shell command.
				if in.Target == waf.TargetPath || in.Field == "(raw)" || in.Name || len(in.Value) < 3 {
					continue
				}
				if Exclusions.ExcludedOn(reqctx.From(r.Context()).Site, "ML", r.Method, r.URL.Path, in.Field) {
					continue
				}
				if in.Target == waf.TargetHeaders && strings.EqualFold(in.Field, "Content-Type") {
					continue // checked by rules (Struts exploits); random boundaries confuse the model
				}
				if in.Target == waf.TargetHeaders && (strings.EqualFold(in.Field, "Referer") || strings.EqualFold(in.Field, "Origin")) {
					// A URL the browser sets: "http://localhost/..." looks like
					// SSRF to the model. Score only its query, where an
					// injected payload would be.
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
