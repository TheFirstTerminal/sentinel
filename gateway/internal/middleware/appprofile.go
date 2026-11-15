package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/ml/profile"
	"sentinel/gateway/internal/reqctx"
)

// AppProfile learns what the app's normal requests look like and flags the
// ones that don't fit (see package profile).
//
// mode "learn": requests that passed every other check and that the app
// answered successfully teach the profile. "detect": anomalies are logged.
// "block": they are refused. Anomaly checks are switched on per page once
// it has been seen minSeen times.
func AppProfile(p *profile.Profile, mode string, minSeen int, maxBody int64, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if mode == "" || mode == "off" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/__sentinel/") {
				next.ServeHTTP(w, r)
				return
			}
			var body []byte
			if r.Body != nil && r.ContentLength != 0 {
				b, err := peekBody(r, maxBody)
				if err != nil {
					next.ServeHTTP(w, r)
					return
				}
				body = b
			}
			info := reqctx.From(r.Context())
			if mode == "learn" {
				sw := &statusRecorder{ResponseWriter: w, status: 200}
				next.ServeHTTP(sw, r)
				if out, ok := info.Outcome(); (!ok || out.Kind == "allowed") && sw.status < 400 {
					c := r.Clone(r.Context())
					c.Body = io.NopCloser(bytes.NewReader(body))
					p.Learn(c, body)
				}
				return
			}
			if found := p.Check(r, body, minSeen); len(found) > 0 {
				a := found[0]
				kind := "detected"
				if mode == "block" {
					kind = "blocked"
				}
				info.SetOutcome(reqctx.Outcome{Kind: kind, Rule: "APP-PROFILE", Field: a.Field,
					Reason: "unusual for this app: " + a.Field + " " + a.Reason, Detail: "value: " + cut(a.Value, 80)})
				if mode == "block" && !Exclusions.ExcludedOn(reqctx.From(r.Context()).Site, "APP-PROFILE", r.Method, r.URL.Path, a.Field) {
					writeBlocked(w, info.ID)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
