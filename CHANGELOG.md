# Changelog

## 0.15.0 · 2026-11-17
- **Kubernetes Ingress controller**: with `kubernetes_ingress_class` (Helm: `ingressController.enabled`), Sentinel reads Ingresses and protects and routes their hosts itself.
- **Dashboard**: add and remove sites without a restart.
- **Dashboard accounts with roles**: admin, operator (bans, false alarms, reloads) and viewer (looks only). Admins add, reset and remove accounts; each sets up 2FA at first login.
- **Docs**: common setups (Nginx, Cloudflare, Kubernetes, directly on the internet), and how to check Sentinel works.

## 0.14.0 · 2026-11-15
- **OWASP Core Rule Set 4.25.2 (LTS)** (was 4.8.0), with XML attribute values inspected too. The built-in engine passes 99.3% of its regression suite; path variables are now URL-decoded as in ModSecurity.
- **Dashboard**: change a site's host names, servers and health check without a restart.
- **Packages**: `.deb` and `.rpm` for amd64 and arm64 (with a systemd service), a Homebrew formula, and a macOS Intel binary.
- **Docs site**: https://tsxmamii.github.io/sentinel/
- Editions build on extension points instead of changing shared files.

## 0.13.0 · 2026-11-15
- **Exclusions per site**: an exclusion can name one site; **Allow…** fills it in.
- **API spec and prompt guard per site** (`api_spec_file`, `api_spec_prefix`, `prompt_guard_paths`, `prompt_canary` in a site).
- **Automatic HTTPS for every site**: `tls.auto_domains: [sites]` gets certificates for every site's host names.
- **Log export**: security events to syslog (`export.syslog`, UDP, TCP or TLS) and to OpenTelemetry collectors (`export.otlp`).
- **One-line install on Linux**: `deploy/install.sh` installs the latest release as a systemd service, checking its checksum and signature.
- **Dashboard editing**: change a site's mode, WAF mode, ML mode and rate limits, and where alerts go, without a restart. Kept in the data folder.

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
