package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"sentinel/gateway/internal/bot"
	"sentinel/gateway/internal/reqctx"
)

// BotOptions configures Bots.
type BotOptions struct {
	BlockScanners bool
	Challenger    *bot.Challenger // nil = no challenge
	Challenge     string          // "off", "suspicious" or "all"
	Paths         []string        // where challenges apply (prefixes)
}

// Bots blocks known attack tools and challenges clients that look
// automated (see package bot).
func Bots(o BotOptions, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/__sentinel/") {
				next.ServeHTTP(w, r)
				return
			}
			info := reqctx.From(r.Context())
			if o.BlockScanners {
				if tool := bot.Scanner(r.UserAgent()); tool != "" {
					info.SetOutcome(reqctx.Outcome{Kind: "blocked", Rule: "BOT-SCANNER",
						Reason: "attack tool in the User-Agent: " + tool, Field: "user-agent", Detail: "user-agent: " + cut(r.UserAgent(), 80)})
					writeBlocked(w, info.ID)
					return
				}
			}
			if o.Challenger == nil || o.Challenge == "off" || o.Challenge == "" || !hasPrefix(r.URL.Path, o.Paths) {
				next.ServeHTTP(w, r)
				return
			}
			ip := info.ClientIP
			if o.Challenger.HasPass(r, ip) {
				next.ServeHTTP(w, r)
				return
			}
			if o.Challenger.Solved(r, ip) {
				http.SetCookie(w, o.Challenger.Pass(r, ip))
				http.SetCookie(w, &http.Cookie{Name: bot.WorkCookie, Value: "", Path: "/", MaxAge: -1})
				next.ServeHTTP(w, r)
				return
			}
			why := bot.Suspicious(r)
			if o.Challenge == "all" && why == "" {
				why = "every visitor is checked on this path"
			}
			// Only browsers loading a page can run the check; everything
			// else goes on to the other checks.
			if why == "" || !bot.WantsHTML(r) {
				next.ServeHTTP(w, r)
				return
			}
			info.SetOutcome(reqctx.Outcome{Kind: "challenged", Rule: "BOT-CHALLENGE", Reason: "browser check: " + why})
			h := w.Header()
			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(o.Challenger.Page(r, ip)))
		})
	}
}
