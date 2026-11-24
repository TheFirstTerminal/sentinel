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
	// StrictPaths need a pass from every client: a browser loading a page
	// gets the check, anything else without a pass is refused. For login
	// and signup forms, which real users always reach through a browser.
	StrictPaths []string
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
			strict := o.Challenger != nil && hasPrefix(r.URL.Path, o.StrictPaths)
			challenging := o.Challenger != nil && o.Challenge != "off" && o.Challenge != "" && hasPrefix(r.URL.Path, o.Paths)
			if !strict && !challenging {
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
			why := ""
			if challenging {
				why = bot.Suspicious(r)
				if o.Challenge == "all" && why == "" {
					why = "every visitor is checked on this path"
				}
			}
			if strict && why == "" {
				why = "a browser check is required on this path"
			}
			if strict && !bot.WantsHTML(r) {
				// Can't run the check and has no pass: a script, or a form
				// posted without loading its page first.
				info.SetOutcome(reqctx.Outcome{Kind: "blocked", Rule: "BOT-STRICT", Reason: "no browser check pass on a strict path"})
				writeError(w, http.StatusForbidden, "Open this page in a browser first: it needs a browser check", info.ID)
				return
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
