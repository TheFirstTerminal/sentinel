package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sentinel/gateway/internal/blocklist"
	"strconv"
	"strings"
	"time"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/geo"
	"sentinel/gateway/internal/kv"
	"sentinel/gateway/internal/ratelimit"
	"sentinel/gateway/internal/reqctx"
)

// Geo (part of check 1) looks up the client's country and applies the IP
// and country allow/deny lists. It always runs, so the logs and the
// dashboard know the country even when no list is configured.
func Geo(db *geo.DB, f *geo.Filter, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.From(r.Context())
			info.Country = db.Country(info.ClientIP)
			if why := f.Check(info.ClientIP, info.Country); why != "" {
				deny(w, r, rec, log, http.StatusForbidden, "geo_blocked", why, "geo-filter",
					"access from your location is not allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit (check 2). Logged-in users are counted by username, everyone
// else by IP. Over the limit: 429 Too Many Requests with Retry-After.
func RateLimit(l *ratelimit.Limiter, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return RateLimitBan(l, nil, 0, rec, log)
}

// FloodFactor: a client that sends this many times its limit within one
// window is flooding, not just busy, and its IP is banned (RateLimitBan).
const FloodFactor = 3

// RateLimitBan is RateLimit that also bans flooding IPs for banFor.
func RateLimitBan(l *ratelimit.Limiter, bans *blocklist.List, banFor time.Duration, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := reqctx.From(r.Context())
			subject := "ip:" + info.ClientIP
			if u := info.User(); u != nil {
				subject = "user:" + u.Username
			}
			// Every started 64 KB of body counts as one more request.
			weight := int64(1)
			if r.ContentLength > 0 {
				weight += r.ContentLength / (64 << 10)
			} else if r.ContentLength < 0 {
				weight += 16 // unknown length (chunked): assume up to 1 MB
			}
			res, err := l.CheckWeighted(r.Context(), r.URL.Path, subject, weight)
			if err != nil {
				log.Warn("rate_limit_store_error", "error", err.Error(), "request_id", info.ID)
			}
			if res.Rule == nil {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(res.Rule.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(res.Remaining, 10))
			if !res.Allowed {
				secs := int(res.RetryAfter / time.Second)
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				reason := fmt.Sprintf("more than %d requests per %s (%s)", res.Rule.Limit, res.Rule.Window, subject)
				info.SetOutcome(reqctx.Outcome{Kind: "rate_limited", Reason: reason, Rule: res.Rule.String()})
				// Audit only the first refused request of a window, not a flood of them.
				if res.Count == res.Rule.Limit+1 {
					record(rec, log, audit.Event{
						Type: "rate_limited", ClientIP: info.ClientIP, RequestID: info.ID,
						Method: r.Method, Path: r.URL.Path,
						Detail: map[string]any{"subject": subject, "rule": res.Rule.String()},
					})
				}
				if bans != nil && banFor > 0 && res.Count >= FloodFactor*res.Rule.Limit {
					bans.Ban(info.ClientIP, banFor)
					info.SetOutcome(reqctx.Outcome{Kind: "banned", Rule: res.Rule.String(),
						Reason: fmt.Sprintf("flooding: %d requests, limit %d per %s; IP %s banned for %.0f min",
							res.Count, res.Rule.Limit, res.Rule.Window, info.ClientIP, banFor.Minutes())})
					log.Warn("flood_ban", "ip", info.ClientIP, "rule", res.Rule.String(), "request_id", info.ID)
					record(rec, log, audit.Event{Type: "flood_ban", ClientIP: info.ClientIP, RequestID: info.ID,
						Method: r.Method, Path: r.URL.Path, Detail: map[string]any{"rule": res.Rule.String()}})
				}
				writeError(w, http.StatusTooManyRequests,
					fmt.Sprintf("too many requests, try again in %d seconds", secs), info.ID)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LoginCounter tells LoginGuard how many logins failed for an account
// recently, and how long until they stop counting.
type LoginCounter interface {
	Count(ctx context.Context, user string) int64
	Period() time.Duration
}

// LoginFailures counts failed logins per account, whatever IP they come
// from, for LoginGuard. Long names are hashed: the name comes from the
// client, and a megabyte-long one must not become a megabyte-long key.
type LoginFailures struct {
	Store  kv.Store
	Window time.Duration // how long a failure counts (15 minutes)
}

func (l *LoginFailures) key(user string) string {
	user = strings.ToLower(user)
	if len(user) > 64 {
		h := sha256.Sum256([]byte(user))
		user = "#" + hex.EncodeToString(h[:16])
	}
	return "loginfail:" + user
}

// Failed counts one failed password or 2FA code for an account.
func (l *LoginFailures) Failed(ctx context.Context, user string) {
	if user != "" {
		l.Store.Incr(ctx, l.key(user), l.Window)
	}
}

// Period is how long a failure counts.
func (l *LoginFailures) Period() time.Duration { return l.Window }

// Count is the number of recent failures for an account.
func (l *LoginFailures) Count(ctx context.Context, user string) int64 {
	n, _ := l.Store.Get(ctx, l.key(user))
	return n
}

// CountLoginFailures records failed logins after each request.
func CountLoginFailures(l *LoginFailures) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			info := reqctx.From(r.Context())
			if out, decided := info.Outcome(); decided && (out.Kind == "login_failed" || out.Kind == "mfa_failed") {
				user := info.Login
				if u := info.User(); u != nil {
					user = u.Username
				}
				// Background context: the client may already have gone.
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				l.Failed(ctx, user)
			}
		})
	}
}

// LoginGuard limits failed logins per ACCOUNT, whatever IP they come from:
// after limit failures in the window (15 minutes), further password
// attempts for that account are refused with 429 until the window ends.
// Per-IP rate limits can't stop an attacker who spreads guesses over many
// addresses (password spraying); this can. Unknown usernames are counted
// the same way, so the answer reveals nothing about which accounts exist.
func LoginGuard(e LoginCounter, limit int64, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit <= 0 || r.Method != http.MethodPost || r.URL.Path != "/__sentinel/auth/login" {
				next.ServeHTTP(w, r)
				return
			}
			body, err := peekBody(r, 64<<10)
			if err != nil {
				bodyFail(w, r, err, 64<<10, rec, log)
				return
			}
			var in struct {
				Username string `json:"username"`
			}
			json.Unmarshal(body, &in)
			if in.Username != "" && e.Count(r.Context(), in.Username) >= limit {
				info := reqctx.From(r.Context())
				info.Login = in.Username
				w.Header().Set("Retry-After", strconv.Itoa(int(e.Period()/time.Second)))
				deny(w, r, rec, log, http.StatusTooManyRequests, "rate_limited",
					fmt.Sprintf("%d failed logins for this account recently", limit), "login-guard",
					"too many failed logins for this account, try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
