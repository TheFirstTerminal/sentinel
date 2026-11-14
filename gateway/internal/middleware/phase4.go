package middleware

import (
	"sentinel/gateway/internal/exclude"

	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/promptguard"
	"sentinel/gateway/internal/reqctx"
)

// PromptGuard protects AI chat endpoints (paths under prefixes) from
// prompt injection, and withholds any reply that contains the canary.
func PromptGuard(g *promptguard.Guard, prefixes []string, canary, mode string, maxBody int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasPrefix(r.URL.Path, prefixes) {
				next.ServeHTTP(w, r)
				return
			}
			info := reqctx.From(r.Context())
			body, err := peekBody(r, maxBody)
			if err != nil {
				bodyFail(w, r, err, maxBody, rec, log)
				return
			}
			fields := promptguard.Fields(body)
			for k, vs := range r.URL.Query() {
				for _, v := range vs {
					fields = append(fields, promptguard.Field{Name: k, Text: v})
				}
			}
			// Also check all the text together: an injection split across
			// fields ("ignore all previous" + "instructions") reaches the
			// model as one prompt.
			if len(fields) > 1 {
				parts := make([]string, len(fields))
				for i, f := range fields {
					parts[i] = f.Text
				}
				fields = append(fields, promptguard.Field{Name: "(all fields)", Text: strings.Join(parts, " ")})
			}
			res := g.InspectExcept(fields, func(rule, field string) bool {
				return Exclusions.Excluded(rule, r.Method, r.URL.Path, field)
			})
			if g.Attack(res) {
				m := res.Matches[0]
				kind := "prompt_injection"
				if mode == "detect" {
					kind = "detected"
				}
				info.SetOutcome(reqctx.Outcome{Kind: kind, Rule: m.RuleID, Reason: m.Name, Field: exclude.NormalizeField(m.Field),
					Detail: fmt.Sprintf("field: %s  matched: %s%s", m.Field, m.Excerpt, via(m.Via))})
				record(rec, log, audit.Event{Type: "prompt_injection_" + map[bool]string{true: "detected", false: "blocked"}[mode == "detect"],
					ClientIP: info.ClientIP, RequestID: info.ID, Method: r.Method, Path: r.URL.Path,
					Detail: map[string]any{"score": res.Score, "matches": res.Matches}})
				if mode != "detect" {
					writeError(w, http.StatusForbidden, "Request blocked by Sentinel: it looks like an attempt to manipulate the AI assistant", info.ID)
					return
				}
			}
			if canary == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Hold the reply until it is complete, then check it for the canary.
			buf := &bufferedWriter{header: http.Header{}, status: http.StatusOK}
			next.ServeHTTP(buf, r)
			if leaked(buf.body.Bytes(), canary) {
				info.SetOutcome(reqctx.Outcome{Kind: "leak_blocked", Rule: "PI-CANARY",
					Reason: "the AI's reply contained its hidden prompt (canary found)"})
				record(rec, log, audit.Event{Type: "ai_leak_blocked", ClientIP: info.ClientIP, RequestID: info.ID,
					Method: r.Method, Path: r.URL.Path, Detail: map[string]any{"reply_bytes": buf.body.Len()}})
				writeError(w, http.StatusBadGateway, "The assistant's reply was withheld by Sentinel because it contained protected data", info.ID)
				return
			}
			for k, v := range buf.header {
				w.Header()[k] = v
			}
			w.WriteHeader(buf.status)
			w.Write(buf.body.Bytes())
		})
	}
}

func via(v string) string {
	if v == "" {
		return ""
	}
	return "  (found via " + v + ")"
}

func hasPrefix(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

type bufferedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header         { return b.header }
func (b *bufferedWriter) WriteHeader(code int)        { b.status = code }
func (b *bufferedWriter) Write(p []byte) (int, error) { return b.body.Write(p) }

// SecurityHeaders adds protective response headers the app didn't set
// itself (ASVS 14.4): no MIME sniffing, a careful Referrer-Policy, no
// framing by other sites, and HSTS on HTTPS. Headers the app sets win.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&headerWriter{ResponseWriter: w, tls: r.TLS != nil}, r)
	})
}

type headerWriter struct {
	http.ResponseWriter
	tls  bool
	done bool
}

func (h *headerWriter) add() {
	if h.done {
		return
	}
	h.done = true
	hd := h.ResponseWriter.Header()
	set := func(k, v string) {
		if hd.Get(k) == "" {
			hd.Set(k, v)
		}
	}
	set("X-Content-Type-Options", "nosniff")
	set("Referrer-Policy", "strict-origin-when-cross-origin")
	set("X-Frame-Options", "SAMEORIGIN")
	if h.tls {
		set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func (h *headerWriter) WriteHeader(code int) { h.add(); h.ResponseWriter.WriteHeader(code) }
func (h *headerWriter) Write(b []byte) (int, error) {
	h.add()
	return h.ResponseWriter.Write(b)
}
func (h *headerWriter) Flush() {
	h.add()
	if f, ok := h.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (h *headerWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// leaked reports whether a reply contains the canary, also when the model
// was told to disguise it: reversed, base64, hex, or with characters in
// between (S-N-T-L, "S N T L").
func leaked(reply []byte, canary string) bool {
	low := strings.ToLower(string(reply))
	c := strings.ToLower(canary)
	rev := []rune(c)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	variants := []string{c, string(rev), strings.ToLower(hex.EncodeToString([]byte(canary)))}
	// base64 of the canary inside longer text depends on its position mod 3:
	// encode it at all three offsets and keep the blocks that are stable.
	for k := 0; k < 3; k++ {
		e := base64.StdEncoding.EncodeToString(append(make([]byte, k), canary...))
		if len(e) > 12 {
			mid := strings.ToLower(e[4 : len(e)-4])
			variants = append(variants, mid, strings.NewReplacer("+", "-", "/", "_").Replace(mid))
		}
	}
	for _, v := range variants {
		if strings.Contains(low, v) {
			return true
		}
	}
	alnum := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return strings.Contains(alnum(low), alnum(c))
}
