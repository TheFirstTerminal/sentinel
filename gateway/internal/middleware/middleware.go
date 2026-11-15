// Package middleware holds the checks that wrap the reverse proxy.
//
// A middleware is a function that takes the next handler and returns a new
// handler that does something before (or after) calling it. Chaining them
// builds the pipeline from the architecture diagram:
//
//	RequestContext -> AccessLog -> IPBlock -> Honeypot -> Authenticate ->
//	Authorize -> Schema -> WAF -> (Sentinel login API | reverse proxy -> app)
//
// Later phases slot in rate limiting and ML the same way.
package middleware

import (
	"sentinel/gateway/internal/metrics"

	"sentinel/gateway/internal/exclude"

	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/events"
	"sentinel/gateway/internal/reqctx"
	"sentinel/gateway/internal/waf"
)

func RequestIDFrom(ctx context.Context) string { return reqctx.From(ctx).ID }
func ClientIPFrom(ctx context.Context) string  { return reqctx.From(ctx).ClientIP }

// RequestContext gives each request an ID (so a blocked request shown to the
// user can be found in the logs) and resolves the real client IP.
func RequestContext(trust ProxyTrust) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := &reqctx.Info{ID: newID(), ClientIP: clientIP(r, trust)}
			w.Header().Set("X-Request-ID", info.ID)
			next.ServeHTTP(w, r.WithContext(reqctx.With(r.Context(), info)))
		})
	}
}

// AccessLog writes ONE line per request at the end, including Sentinel's
// decision (outcome) and the user. The live watch window reads these lines.
// hub (may be nil) also receives every decision, for the dashboard.
func AccessLog(log *slog.Logger, hub *events.Hub) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			info := reqctx.From(r.Context())
			out, ok := info.Outcome()
			if !ok {
				out = reqctx.Outcome{Kind: "allowed"}
			}
			attrs := []any{
				"request_id", info.ID,
				"client_ip", info.ClientIP,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", float64(time.Since(start).Microseconds()) / 1000,
				"outcome", out.Kind,
			}
			if out.Reason != "" {
				attrs = append(attrs, "reason", out.Reason)
			}
			if out.Rule != "" {
				attrs = append(attrs, "rule", out.Rule)
			}
			if out.Detail != "" {
				attrs = append(attrs, "detail", out.Detail)
			}
			if out.Field != "" {
				attrs = append(attrs, "field", out.Field)
			}
			if u := info.User(); u != nil {
				attrs = append(attrs, "user", u.Username, "role", u.Role, "mfa", u.MFA)
			}
			if info.Country != "" {
				attrs = append(attrs, "country", info.Country)
			}
			if info.Site != "" {
				attrs = append(attrs, "site", info.Site)
			}
			log.Info("request", attrs...)
			stopped := events.Event{Outcome: out.Kind}.Stopped() || out.Kind == "monitored" || out.Kind == "detected"
			metrics.Default.Observe(out.Kind, out.Rule, stopped, time.Since(start))
			if hub != nil && !events.Hidden(r.URL.Path, out.Kind) {
				ev := events.Event{
					Time: start, RequestID: info.ID, ClientIP: info.ClientIP, Country: info.Country,
					Method: r.Method, Path: r.URL.Path, Status: rec.status, Outcome: out.Kind,
					Reason: out.Reason, Rule: out.Rule, Detail: out.Detail, Site: info.Site,
					Field: out.Field, Related: out.Related,
					Duration: float64(time.Since(start).Microseconds()) / 1000,
				}
				if u := info.User(); u != nil {
					ev.User, ev.Role = u.Username, u.Role
				} else if info.Login != "" {
					ev.User = info.Login
				}
				hub.Publish(ev)
			}
		})
	}
}

// Exclusions switch rules off for some paths and fields (see package
// exclude). Shared by the WAF, ML and prompt-guard checks; nil = none.
var Exclusions *exclude.Set

// WAF inspects each request and blocks attacks (or only logs them in
// "detect" mode, useful for tuning rules without breaking the app).
func WAF(engine *waf.Engine, mode string, maxBody int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return WAFWithSecondOpinion(engine, mode, maxBody, nil, rec, log)
}

// SecondOpinion scores a value: the probability that it is an attack.
type SecondOpinion func(text string) float64

// secondOpinionBenign: below this probability the ML model is confident a
// value is harmless.
const secondOpinionBenign = 0.05

// BenignBySecondOpinion is true when only the Core Rule Set fired, the
// score is no higher than the threshold, and the ML model is confident that
// every value CRS matched is harmless. Such a request is logged as detected
// instead of blocked. On generated data this removed every CRS false alarm
// (16 of 3000 normal inputs) without letting one of 6000 attacks through.
func BenignBySecondOpinion(d waf.Decision, threshold int, opinion SecondOpinion) bool {
	if opinion == nil || !d.Attack || d.Score > threshold || len(d.Matches) == 0 {
		return false
	}
	for _, m := range d.Matches {
		if !strings.HasPrefix(m.RuleID, "CRS-") || m.Excerpt == "" || len(m.Excerpt) > 2000 {
			return false // a Sentinel rule fired, or the value is too long to judge
		}
		if opinion(m.Excerpt) >= secondOpinionBenign {
			return false
		}
	}
	return true
}

// WAFWithSecondOpinion is WAF with the ML model as a second opinion on
// borderline Core Rule Set detections (opinion nil = off).
func WAFWithSecondOpinion(engine *waf.Engine, mode string, maxBody int64, opinion SecondOpinion, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := peekBody(r, maxBody)
			if err != nil {
				bodyFail(w, r, err, maxBody, rec, log)
				return
			}
			info := reqctx.From(r.Context())

			decision := engine.Inspect(r, body)
			if !Exclusions.Empty() {
				decision = engine.Without(decision, func(m waf.Match) bool {
					return Exclusions.ExcludedOn(info.Site, m.RuleID, r.Method, r.URL.Path, fieldName(m))
				})
			}
			secondOpinion := BenignBySecondOpinion(decision, engine.Threshold(), opinion)
			if len(decision.Matches) > 0 {
				action := "allowed"
				if decision.Attack {
					action = "blocked"
					if mode == "detect" || secondOpinion {
						action = "detected"
					}
				}
				log.Warn("waf_event",
					"request_id", info.ID,
					"client_ip", info.ClientIP,
					"method", r.Method,
					"path", r.URL.Path,
					"action", action,
					"score", decision.Score,
					"matches", decision.Matches,
				)
				// Attacks (blocked or detected) also go to the tamper-evident audit log.
				if decision.Attack {
					m := decision.Matches[0]
					// Other rules that fired on the same field: an "Allow"
					// for this field must cover them too.
					var related []string
					for _, o := range decision.Matches[1:] {
						if fieldName(o) == fieldName(m) {
							related = append(related, o.RuleID)
						}
					}
					info.SetOutcome(reqctx.Outcome{
						Kind:    action,
						Rule:    m.RuleID,
						Reason:  m.Name + secondOpinionNote(secondOpinion),
						Detail:  fmt.Sprintf("field: %s  matched: %s", fieldName(m), m.Excerpt),
						Field:   exclude.NormalizeField(fieldName(m)),
						Related: related,
					})
					record(rec, log, audit.Event{
						Type:      "waf_" + action,
						ClientIP:  info.ClientIP,
						RequestID: info.ID,
						Method:    r.Method,
						Path:      r.URL.Path,
						Detail:    map[string]any{"score": decision.Score, "matches": decision.Matches},
					})
				}
			}

			if decision.Attack && mode == "block" && !secondOpinion {
				writeBlocked(w, info.ID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func secondOpinionNote(on bool) string {
	if on {
		return " (let through: the ML model is confident this is harmless; waf.second_opinion)"
	}
	return ""
}

func fieldName(m waf.Match) string {
	if m.Field != "" {
		return m.Field
	}
	return m.Target
}

// peekBody reads up to max bytes for inspection, then puts the body back so
// the proxy can still forward it in full.
func peekBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody || max == 0 {
		return nil, nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, err
	}
	// Put back what was read, even when refusing: in monitor mode the
	// request still goes to the app and needs its whole body.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	if int64(len(head)) > max {
		return nil, errBodyTooLarge
	}
	return head, nil
}

var errBodyTooLarge = errors.New("request body too large")

// BodyLimit refuses bodies larger than max before any check reads them.
// Inspecting only the first part of a large body would let an attack hide
// after a megabyte of padding, so a body Sentinel can't inspect whole is
// not forwarded at all.
func BodyLimit(max int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if max > 0 && r.ContentLength > max {
				bodyFail(w, r, errBodyTooLarge, max, rec, log)
				return
			}
			if max > 0 && r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bodyFail(w http.ResponseWriter, r *http.Request, err error, max int64, rec Recorder, log *slog.Logger) {
	var mbe *http.MaxBytesError
	if errors.Is(err, errBodyTooLarge) || errors.As(err, &mbe) {
		deny(w, r, rec, log, http.StatusRequestEntityTooLarge, "invalid",
			fmt.Sprintf("body larger than %d bytes cannot be inspected", max), "body-limit", "request body too large")
		return
	}
	deny(w, r, rec, log, http.StatusBadRequest, "invalid", "could not read request body", "body", "could not read request body")
}

// writeBlocked tells the client it was blocked, but NOT which rule fired:
// that would teach the attacker how to tweak the payload. Details stay in
// the logs, findable by the request ID.
func writeBlocked(w http.ResponseWriter, requestID string) {
	writeError(w, http.StatusForbidden, "Request blocked by Sentinel security gateway", requestID)
}

func writeError(w http.ResponseWriter, status int, msg, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sentinel"`)
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "request_id": requestID})
}

// ProxyTrust says whose X-Forwarded-For header to believe.
//
// All: believe it from anyone (old TRUST_PROXY_HEADERS=true; only safe when
// Sentinel can't be reached except through the proxy).
// Nets: believe it only when the connection comes from these addresses (the
// load balancer), and take the right-most address that isn't a proxy, so a
// client can't fake its IP by sending its own X-Forwarded-For.
type ProxyTrust struct {
	All  bool
	Nets []netip.Prefix
}

func (t ProxyTrust) trusts(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, n := range t.Nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request, trust ProxyTrust) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return peer
	}
	var hops []string
	for _, v := range xff {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	if len(hops) == 0 {
		return peer
	}
	if trust.All {
		return hops[0]
	}
	if !trust.trusts(peer) {
		return peer
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if _, err := netip.ParseAddr(hops[i]); err != nil {
			return peer // garbage in the header: don't guess
		}
		if !trust.trusts(hops[i]) {
			return hops[i]
		}
	}
	return hops[0]
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the real writer (the
// dashboard's live stream needs it to lift the write deadline).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush keeps streaming responses working through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
