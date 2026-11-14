package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/blocklist"
	"sentinel/gateway/internal/reqctx"
)

// Recorder receives security events for the tamper-evident audit log.
// It may be nil (audit logging disabled).
type Recorder interface {
	Record(audit.Event) error
}

// DefaultHoneypots are fake paths no real user ever visits, but that
// attackers and scanners try first because they often hold secrets.
var DefaultHoneypots = []string{
	"/admin-backup",
	"/backup",
	"/backup.zip",
	"/db.sql",
	"/.env",
	"/.git",
	"/config.php.bak",
	"/wp-admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/server-status",
	"/api/internal/debug",
}

// IPBlock rejects every request from a banned IP before anything else runs.
func IPBlock(bans *blocklist.List, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIPFrom(r.Context())
			if bans.Banned(ip) {
				reqctx.From(r.Context()).SetOutcome(reqctx.Outcome{
					Kind: "banned", Reason: "IP is banned (touched a honeypot earlier)", Detail: "ip: " + ip,
				})
				log.Warn("banned_ip_request",
					"request_id", RequestIDFrom(r.Context()),
					"client_ip", ip,
					"path", r.URL.Path,
				)
				writeBlocked(w, RequestIDFrom(r.Context()))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Honeypot bans any client that touches a trap path.
//
// The attacker gets an ordinary "404 page not found", so nothing tells them
// they were caught. Every request after that is refused by IPBlock until the
// ban expires.
func Honeypot(traps []string, bans *blocklist.List, banFor time.Duration, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	cleaned := make([]string, 0, len(traps))
	for _, t := range traps {
		if t = normalizeTrapPath(t); t != "/" {
			cleaned = append(cleaned, t)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trap, hit := matchTrap(cleaned, r.URL.Path)
			if !hit {
				next.ServeHTTP(w, r)
				return
			}
			ip := ClientIPFrom(r.Context())
			bans.Ban(ip, banFor)
			reqctx.From(r.Context()).SetOutcome(reqctx.Outcome{
				Kind:   "honeypot",
				Rule:   trap,
				Reason: fmt.Sprintf("trap touched, IP %s banned for %.0f min", ip, banFor.Minutes()),
			})

			log.Warn("honeypot_hit",
				"request_id", RequestIDFrom(r.Context()),
				"client_ip", ip,
				"path", r.URL.Path,
				"trap", trap,
				"ban_minutes", banFor.Minutes(),
			)
			record(rec, log, audit.Event{
				Type:      "honeypot_hit",
				ClientIP:  ip,
				RequestID: RequestIDFrom(r.Context()),
				Method:    r.Method,
				Path:      r.URL.Path,
				Detail:    map[string]any{"trap": trap, "ban_minutes": banFor.Minutes()},
			})
			http.NotFound(w, r)
		})
	}
}

// matchTrap matches the trap itself, anything under it (/wp-admin and
// /wp-admin/install.php) and copies of it (/.env.bak, /admin-backup.zip),
// case-insensitively. Path parameters (/admin-backup;x=1) and encoded
// letters (/%61dmin-backup) don't hide it.
func matchTrap(traps []string, p string) (string, bool) {
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	p = normalizeTrapPath(p)
	// Drop ;parameters from every segment: some servers ignore them.
	if strings.Contains(p, ";") {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			if j := strings.IndexByte(s, ';'); j >= 0 {
				segs[i] = s[:j]
			}
		}
		p = path.Clean(strings.Join(segs, "/"))
	}
	for _, t := range traps {
		if p == t || strings.HasPrefix(p, t+"/") || strings.HasPrefix(p, t+".") || strings.HasPrefix(p, t+"~") {
			return t, true
		}
	}
	return "", false
}

func normalizeTrapPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p) // removes //, /./, ../ and trailing slashes
}

func record(rec Recorder, log *slog.Logger, ev audit.Event) {
	if rec == nil {
		return
	}
	if err := rec.Record(ev); err != nil {
		log.Error("audit_write_failed", "error", err.Error())
	}
}
