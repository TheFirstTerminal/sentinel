package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/dashboard"
	"sentinel/gateway/internal/middleware"
)

// edition holds the points where an edition of Sentinel adds its own
// checks. Sentinel Free leaves them at these defaults; Sentinel Pro, a
// separate build, sets them from its own files, so every other file is
// the same in both.
var edition = struct {
	// Commands are extra subcommands (sentinel <name> ...).
	Commands map[string]func(args []string, out io.Writer) int
	// Prepare runs once at startup, after logins and the shared store are
	// ready. It may return a recorder for security events and a function
	// to call on shutdown.
	Prepare func(ctx context.Context, cfg *config.Config, authSvc *auth.Service, log *slog.Logger) (middleware.Recorder, func(), error)
	// TLS adjusts the HTTPS listener's settings.
	TLS func(cfg *config.Config, t *tls.Config) error
	// Shared runs while the shared parts are built (after the bans, before
	// the sites). It may replace sh.logins and sh.rec and keep its own
	// state in sh.ext.
	Shared func(sh *shared) error
	// AlertsReady runs once alerts can be sent.
	AlertsReady func(sh *shared)
	// Outer wraps every request, outside the sites (it sees the final
	// outcome of each request).
	Outer func(sh *shared, h http.Handler) http.Handler
	// Access adds a site's access checks; they run after rate limiting and
	// before the API schema check.
	Access func(sh *shared, sc config.Site, p http.Handler, guard func(func(http.Handler) http.Handler) func(http.Handler) http.Handler) http.Handler
	// Dashboard adds to the dashboard (info rows, features, API routes).
	Dashboard func(sh *shared, d *dashboard.Dashboard)
	// Reload loads the edition's own reloadable files; apply switches over.
	Reload func(cfg *config.Config) (apply func(), err error)
	// WatchFiles are more files whose change triggers a reload.
	WatchFiles func(cfg *config.Config) []string
	// StartedAttrs are more fields for the "sentinel started" log line.
	StartedAttrs func(cfg *config.Config) []any
	// Bench adjusts the configuration `sentinel bench` measures.
	Bench func(cfg *config.Config)
}{
	Outer: func(sh *shared, h http.Handler) http.Handler {
		return middleware.CountLoginFailures(sh.loginFails)(h)
	},
	Access: func(sh *shared, sc config.Site, p http.Handler, guard func(func(http.Handler) http.Handler) func(http.Handler) http.Handler) http.Handler {
		p = middleware.StripIdentityHeaders(p)
		return guard(middleware.LoginGuard(sh.logins, sh.cfg.LoginFailLimit, sh.rec, sh.log))(p)
	},
}
