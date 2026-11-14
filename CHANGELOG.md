# Changelog

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
