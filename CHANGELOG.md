# Changelog

## 0.12.0 · 2026-11-14
- **Several sites** (`sites`): one Sentinel for several websites and APIs, chosen by host name (exact, `*.example.com` or `*`), each with its own servers, routes, mode, WAF mode, ML mode, rate limits and health check. Unknown hosts get 421.
- **Several servers per app**, sharing traffic in turn. A server that refuses connections is skipped for 10 seconds; with `health_check`, failing servers get no traffic until they pass again.
- **History on disk** (`history_days`, default 30): every stopped or flagged request, kept across restarts and searchable on the dashboard.
- **Dashboard**: a sites panel with server health, a one-click switch between monitor and protect per site (saved, survives restarts), a site picker, a history search, no second password entry when turning on 2FA, a phone layout, and the setup page in the same design.
- **Fewer false alarms**: when only the Core Rule Set fires at the threshold and the ML model is sure the value is harmless, the request is logged instead of blocked (`waf.second_opinion`). On the benchmark, false alarms went from 0.5% to 0, with no attack let through.
- **Faster Core Rule Set**: about 17% less time and half the allocations per request.
- Fix: IP bans no longer apply on the dashboard's own port, so an admin who shares an address with an attacker can still get in to lift the ban.

## 0.11.0 · 2026-11-14
First public release: **Sentinel Free**, under the PolyForm Shield License 1.0.0.

- Attack detection in three layers: Sentinel's own rules (with evasion decoding), the OWASP Core Rule Set in a built-in engine, and an explainable ML model.
- App profile (`APP_PROFILE=learn|detect|block`): learns each page's normal parameters and flags requests that don't fit.
- Monitor mode, false-alarm exclusions with an Allow button, profiles for WordPress, Laravel, Django, Next.js and AI apps, hot reload.
- Rate limits, flood bans (3× the limit within one window bans the IP), a per-account guard against password spraying, honeypots, geo and IP lists, bot checks.
- Prompt-injection guard and canary check for AI endpoints; response leak checks; virtual patches for exploited CVEs; OpenAPI schema validation.
- Live dashboard with an admin login (2FA codes are accepted for 5 minutes after they are shown, once each), automatic HTTPS, Prometheus metrics, alerts.
- Built with Go 1.26.11 and current dependencies (pgx 5.9.2, golang.org/x/*): fixes 43 known vulnerabilities in the Go 1.24 standard library and an SQL-injection bug in the PostgreSQL driver. `govulncheck` reports none.
- Zero-trust access for your apps (logins, access policies, mTLS, risk-based step-up, tamper-evident audit log) moves to Sentinel Pro; their settings now stop the free edition with a clear message.
