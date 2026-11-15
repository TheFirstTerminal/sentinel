package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/reqctx"
	"sentinel/gateway/internal/schema"
)

// Authenticator verifies Sentinel access tokens (auth.Service does).
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*auth.Claims, error)
}

// Identity headers Sentinel sets for the protected app. Anything a client
// sends with these names is removed first, so nobody can claim to be admin
// by adding "X-Sentinel-Role: admin" to their request.
var identityHeaders = []string{"X-Sentinel-User", "X-Sentinel-Role", "X-Sentinel-Department", "X-Sentinel-MFA", "X-Sentinel-Client"}

// AuthenticateApps: also read tokens on requests for the protected apps,
// not only on Sentinel's own pages (set by editions that log users in to
// the apps).
var AuthenticateApps bool

// Authenticate (check 3) reads "Authorization: Bearer <token>" on Sentinel's
// own pages (/__sentinel/...: the dashboard and its login). A valid token
// attaches the admin to the request; an invalid one is only remembered.
// Requests for the protected apps are left alone, so the apps' own tokens
// pass through untouched.
func Authenticate(a Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !AuthenticateApps && !strings.HasPrefix(r.URL.Path, "/__sentinel/") {
				next.ServeHTTP(w, r)
				return
			}
			if tok := auth.BearerToken(r); tok != "" {
				info := reqctx.From(r.Context())
				c, err := a.Authenticate(r.Context(), tok)
				if err != nil {
					info.SetTokenInvalid(err.Error())
				} else {
					info.SetUser(&reqctx.Identity{
						Username: c.Sub, Role: c.Role, Dept: c.Dept, MFA: c.MFA, TokenID: c.Jti, Expires: c.Exp,
					})
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StripIdentityHeaders removes X-Sentinel-* identity headers that a client
// sent, so nobody can claim to be someone by adding "X-Sentinel-Role: admin".
// Apps behind Sentinel can rely on these headers never coming from outside.
func StripIdentityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range identityHeaders {
			r.Header.Del(h)
		}
		next.ServeHTTP(w, r)
	})
}

// Schema (check 6) validates requests against the API specification.
func Schema(v *schema.Validator, maxBody int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !v.Applies(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			body, err := peekBody(r, maxBody)
			if err != nil {
				bodyFail(w, r, err, maxBody, rec, log)
				return
			}
			if verr := v.Validate(r, body); verr != nil {
				deny(w, r, rec, log, verr.Status, "invalid", verr.Message, "api-schema",
					"request does not match the API specification: "+verr.Message)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// deny records the outcome + audit entry and writes the error response.
func deny(w http.ResponseWriter, r *http.Request, rec Recorder, log *slog.Logger, status int, kind, reason, rule, clientMsg string) {
	info := reqctx.From(r.Context())
	info.SetOutcome(reqctx.Outcome{Kind: kind, Reason: reason, Rule: rule})
	detail := map[string]any{"status": status, "reason": reason, "rule": rule}
	if u := info.User(); u != nil {
		detail["user"], detail["role"] = u.Username, u.Role
	}
	typ := "access_denied"
	if kind == "invalid" {
		typ = "schema_rejected"
	}
	record(rec, log, audit.Event{
		Type: typ, ClientIP: info.ClientIP, RequestID: info.ID,
		Method: r.Method, Path: r.URL.Path, Detail: detail,
	})
	writeError(w, status, clientMsg, info.ID)
}
