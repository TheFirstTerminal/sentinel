package auth

import (
	"encoding/base64"

	"github.com/skip2/go-qrcode"

	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/reqctx"
)

// Recorder is the audit log (may be nil).
type Recorder interface{ Record(audit.Event) error }

// Handlers serves Sentinel's own login API under /__sentinel/auth/:
//
//	POST /__sentinel/auth/login        {"username","password"}
//	POST /__sentinel/auth/verify-2fa   {"mfa_token","code"}
//	POST /__sentinel/auth/logout       (Bearer token)
//	GET  /__sentinel/auth/me           (Bearer token)
//	POST /__sentinel/auth/2fa/setup    (Bearer token)  -> secret + otpauth URI
//	POST /__sentinel/auth/2fa/enable   (Bearer token)  {"code"}
type Handlers struct {
	svc *Service
	rec Recorder
	log *slog.Logger
}

const Prefix = "/__sentinel/auth/"

func NewHandlers(svc *Service, rec Recorder, log *slog.Logger) *Handlers {
	return &Handlers{svc: svc, rec: rec, log: log}
}

func (h *Handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + strings.TrimPrefix(r.URL.Path, Prefix) {
	case "POST login":
		h.login(w, r)
	case "POST verify-2fa":
		h.verify2FA(w, r)
	case "POST logout":
		h.withUser(w, r, h.logout)
	case "GET me":
		h.withUser(w, r, h.me)
	case "POST 2fa/setup":
		h.withUser(w, r, h.setup2FA)
	case "POST 2fa/enable":
		h.withUser(w, r, h.enable2FA)
	default:
		writeJSON(w, r, http.StatusNotFound, map[string]any{"error": "unknown auth endpoint"})
	}
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !readJSON(w, r, &in) {
		return
	}
	info := reqctx.From(r.Context())
	if len(in.Username) > 64 {
		// No real account has such a name; don't let it reach the stores.
		info.SetOutcome(reqctx.Outcome{Kind: "invalid", Reason: "username longer than 64 characters"})
		writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "username too long"})
		return
	}
	res, err := h.svc.Login(r.Context(), in.Username, in.Password)
	if errors.Is(err, ErrBadCredentials) {
		info.Login = in.Username
		info.SetOutcome(reqctx.Outcome{Kind: "login_failed", Reason: "wrong username or password", Detail: "user: " + in.Username})
		h.audit(r, "login_failed", map[string]any{"username": in.Username})
		writeJSON(w, r, http.StatusUnauthorized, map[string]any{"error": ErrBadCredentials.Error()})
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if res.MFARequired {
		info.SetOutcome(reqctx.Outcome{Kind: "mfa_required", Reason: "password OK, waiting for 2FA code", Detail: "user: " + res.User})
		h.audit(r, "login_password_ok", map[string]any{"username": res.User, "mfa_required": true})
	} else {
		info.Login = res.User
		info.SetOutcome(reqctx.Outcome{Kind: "login", Reason: "logged in (no 2FA)", Detail: "user: " + res.User + "  role: " + res.Role})
		h.audit(r, "login_success", map[string]any{"username": res.User, "mfa": false})
	}
	writeJSON(w, r, http.StatusOK, res)
}

func (h *Handlers) verify2FA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	info := reqctx.From(r.Context())
	res, err := h.svc.VerifyMFA(r.Context(), in.MFAToken, in.Code)
	if err != nil {
		status, msg := http.StatusUnauthorized, err.Error()
		switch {
		case errors.Is(err, ErrBadCode), errors.Is(err, ErrCodeReused), errors.Is(err, ErrTooManyAttempts):
		case errors.Is(err, ErrTokenExpired):
			msg = "the login took too long, log in again"
		case isTokenErr(err):
			msg = "invalid login session, log in again"
		default:
			h.fail(w, r, err)
			return
		}
		info.SetOutcome(reqctx.Outcome{Kind: "mfa_failed", Reason: msg})
		h.audit(r, "mfa_failed", map[string]any{"reason": msg})
		writeJSON(w, r, status, map[string]any{"error": msg})
		return
	}
	info.Login = res.User
	info.SetOutcome(reqctx.Outcome{Kind: "mfa_ok", Reason: "2FA code correct", Detail: "user: " + res.User + "  role: " + res.Role})
	h.audit(r, "login_success", map[string]any{"username": res.User, "mfa": true})
	writeJSON(w, r, http.StatusOK, res)
}

func (h *Handlers) logout(w http.ResponseWriter, r *http.Request, c *Claims) {
	if err := h.svc.Logout(r.Context(), c); err != nil {
		h.fail(w, r, err)
		return
	}
	reqctx.From(r.Context()).SetOutcome(reqctx.Outcome{Kind: "allowed", Reason: "logged out, token revoked", Detail: "user: " + c.Sub})
	h.audit(r, "logout", map[string]any{"username": c.Sub})
	writeJSON(w, r, http.StatusOK, map[string]any{"status": "logged out"})
}

func (h *Handlers) me(w http.ResponseWriter, r *http.Request, c *Claims) {
	writeJSON(w, r, http.StatusOK, map[string]any{
		"user": c.Sub, "role": c.Role, "department": c.Dept, "mfa": c.MFA, "expires_at": c.Exp,
	})
}

func (h *Handlers) setup2FA(w http.ResponseWriter, r *http.Request, c *Claims) {
	secret, uri, err := h.svc.Begin2FA(r.Context(), c.Sub)
	if errors.Is(err, Err2FAAlreadyOn) {
		writeJSON(w, r, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	qr := ""
	if png, err := qrcode.Encode(uri, qrcode.Medium, 220); err == nil {
		qr = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"secret":       secret,
		"otpauth_uri":  uri,
		"qr":           qr, // the same URI as a QR code to scan
		"instructions": "Add this secret to an authenticator app, then POST the 6-digit code to /__sentinel/auth/2fa/enable",
	})
}

func (h *Handlers) enable2FA(w http.ResponseWriter, r *http.Request, c *Claims) {
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	err := h.svc.Enable2FA(r.Context(), c.Sub, in.Code)
	switch {
	case errors.Is(err, ErrBadCode), errors.Is(err, ErrCodeReused), errors.Is(err, ErrNo2FASetup), errors.Is(err, Err2FAAlreadyOn):
		writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": err.Error()})
	case err != nil:
		h.fail(w, r, err)
	default:
		h.audit(r, "2fa_enabled", map[string]any{"username": c.Sub})
		writeJSON(w, r, http.StatusOK, map[string]any{"status": "2FA enabled, your next login will ask for a code"})
	}
}

// withUser requires a valid access token for the endpoint.
func (h *Handlers) withUser(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request, *Claims)) {
	tok := BearerToken(r)
	if tok == "" {
		writeJSON(w, r, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return
	}
	c, err := h.svc.Authenticate(r.Context(), tok)
	if err != nil {
		writeJSON(w, r, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	next(w, r, c)
}

func (h *Handlers) audit(r *http.Request, typ string, detail map[string]any) {
	if h.rec == nil {
		return
	}
	info := reqctx.From(r.Context())
	if err := h.rec.Record(audit.Event{
		Type: typ, ClientIP: info.ClientIP, RequestID: info.ID,
		Method: r.Method, Path: r.URL.Path, Detail: detail,
	}); err != nil {
		h.log.Error("audit_write_failed", "error", err.Error())
	}
}

func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("auth_error", "request_id", reqctx.From(r.Context()).ID, "error", err.Error())
	writeJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "internal error"})
}

// BearerToken extracts the token from "Authorization: Bearer <token>".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	for _, from := range TokenSources {
		if t := from(r); t != "" {
			return t
		}
	}
	return ""
}

// TokenSources are other places a token may come from when there is no
// Authorization header (e.g. a session cookie, in editions that log people
// in through a browser). Empty by default.
var TokenSources []func(*http.Request) string

func isTokenErr(err error) bool {
	for _, e := range []error{ErrTokenMalformed, ErrTokenAlg, ErrTokenSignature, ErrTokenExpired, ErrTokenPurpose, ErrTokenRevoked} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, r, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // never cache tokens
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sentinel"`)
	}
	w.WriteHeader(status)
	if m, ok := v.(map[string]any); ok {
		m["request_id"] = reqctx.From(r.Context()).ID
	}
	json.NewEncoder(w).Encode(v)
}
