# Configuration

Sentinel reads its settings from a YAML file, from environment variables, or
both. **An environment variable always wins over the file**, so Docker and
Kubernetes can override a single setting without editing the file.

```bash
sentinel init                 # writes a commented sentinel.yaml to start from
sentinel check-config         # checks it without starting (typos are named)
sentinel                      # runs with ./sentinel.yaml if it exists
sentinel --config /path/to/sentinel.yaml
```

The file is found with `--config`, then `SENTINEL_CONFIG`, then
`./sentinel.yaml`, then `/etc/sentinel/sentinel.yaml`. An unknown key stops
the start with a suggestion (`waf.treshold` → did you mean `WAF_THRESHOLD`?),
so a typo can never silently turn a protection off.

In the file, nested keys map to one variable: `waf: {threshold: 7}` is
`WAF_THRESHOLD=7`. Lists become comma-separated values, maps become
`key=value` pairs, and `false` becomes `off`.

## The basics

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `mode` | `MODE` | `monitor` | `monitor`: every check runs and is logged, nothing is blocked. `protect`: refuse what the checks catch. Start in monitor, read the log for a few days, then switch. |
| `profile` | `PROFILE` | none | A starting point for your kind of app: `wordpress`, `laravel`, `django`, `nextjs` or `ai` (see below) |
| `upstream` | `UPSTREAM_URL` | `http://localhost:3000` | The app Sentinel protects |
| `routes` | `UPSTREAMS` | `/` → `upstream` | Several apps by path prefix (longest wins): `{/api/: http://api:8000, /: http://web:3000}`. Several servers for one app share its traffic in turn: `{/: [http://web-1:3000, http://web-2:3000]}` (as a variable: `/=http://web-1:3000\|http://web-2:3000`) |
| `health_check` | `HEALTH_CHECK` | none | A path Sentinel requests on every server every 10 seconds, e.g. `/healthz`. A server that fails it (no answer or a 5xx) gets no traffic until it passes again. A server that refuses a connection is skipped for 10 seconds even without this |
| `sites` | `SITES` | none (one site for every host name) | Several websites or APIs by host name, each with its own servers and settings (as a variable: JSON): see [Several sites](#several-sites) |
| `listen` | `LISTEN_ADDR` | `:8080` | Where Sentinel listens |
| `data_dir` | `DATA_DIR` | `/var/lib/sentinel` in the Docker image, else `./sentinel-data` | Keeps what must survive a restart when there is no database: the secret key, accounts, exclusions and HTTPS certificates. Keep it on a volume. If it isn't writable, Sentinel says so and keeps them in memory |
| `log_format` | `LOG_FORMAT` | automatic | `pretty` (one readable line per decision) in a terminal, `json` otherwise |
| `log_file` | `LOG_FILE` | none | Also write JSON logs here (`sentinel watch` reads it) |
| `history_days` | `HISTORY_DAYS` | `30` | Days of dashboard history kept on disk, in `history/` in the data folder: every request Sentinel stopped or flagged (plain allowed requests are not kept). It survives restarts, older days are deleted, and the dashboard can search it. `0` keeps history in memory only |
| `dashboard` | `DASHBOARD` | on | The dashboard, at `/__sentinel/dashboard` (accounts with 2FA; see *Dashboard accounts* below) |
| `dashboard_listen` | `DASHBOARD_ADDR` | none (on the main port) | Give the dashboard its own port, e.g. `:9000`: then it opens at `http://<host>:9000` and is not reachable on the public port at all. Recommended: keep that port private (firewall or VPN). IP bans don't apply on it, so an admin who shares an address with an attacker (an office or mobile network) can still get in to lift the ban; logins there stay rate limited |
| `security_headers` | `SECURITY_HEADERS` | on | Adds nosniff, Referrer-Policy, X-Frame-Options and (over HTTPS) HSTS when the app doesn't |
| `timezone` | `TZ` | `UTC` | Time zone for log times shown to people |

### Dashboard accounts

The first-run link creates the first **admin**. Admins add more accounts in
the dashboard's **Accounts** card, each with a role:

| Role | Can |
|---|---|
| `admin` | everything, including sites, alerts and accounts |
| `operator` | ban and unban, allow false alarms, reload rules; see everything |
| `viewer` | see everything, change nothing |

A new account gets a one-time password, shown once to the admin who made
it, and sets up 2FA at its first login. **Reset** gives a new one-time
password and starts 2FA again (a lost phone). A changed role or a removed
account takes effect at once. One admin always stays, and nobody can
remove or demote their own account.

## Several sites

One Sentinel can protect several websites and APIs, chosen by the host
name of each request. Each site has its own servers and can have its own
mode, WAF mode, ML mode, rate limits and health check; anything a site
leaves out uses the global setting.

```yaml
mode: protect
sites:
  - name: shop
    hosts: [shop.example.com, www.shop.example.com]
    upstreams: [http://shop-1:3000, http://shop-2:3000]   # shared in turn
    health_check: /healthz
    rate_limits: { /login: 10/1m, /: 600/1m }
  - name: api
    hosts: [api.example.com]
    routes: { /v2/: http://api-v2:8000, /: http://api:8000 }
    mode: monitor            # new API: watch it for a while first
  - name: others
    hosts: ["*.example.com"] # any other subdomain
    upstreams: [http://static:80]
```

| Site key | Meaning |
|---|---|
| `name` | Lowercase letters, digits and `-`. Shown in the logs and on the dashboard |
| `hosts` | Exact names (`shop.example.com`), wildcards (`*.example.com`, longest wins) or `*` for any host no other site has |
| `upstreams` | The servers for `/`; several share the traffic |
| `routes` | By path prefix within the site, like the global `routes` |
| `health_check`, `mode`, `waf_mode`, `ml_mode`, `rate_limits` | As the global settings, for this site only. Rate limits are counted per site |
| `api_spec_file`, `api_spec_prefix` | This site's OpenAPI spec and the path it covers, instead of the global `api_spec`. Both or neither |
| `prompt_guard_paths`, `prompt_canary` | This site's AI chat endpoints (and canary), instead of the global `prompt_guard` |

A request whose host name matches no site gets `421 Misdirected Request`
and is logged; add a site with `hosts: ["*"]` to catch the rest instead.
Sentinel's own pages (the dashboard and its login) work on every host. As
an environment variable, `SITES` is the same list as JSON:
`SITES='[{"name":"shop","hosts":["shop.example.com"],"upstreams":["http://shop:3000"]}]'`.

**Changing a site on the dashboard.** Each site's **Edit** button changes its
mode, WAF mode, ML mode, rate limits, host names, servers and health check
while Sentinel runs. Changes are checked like the config file is (a host name
used by two sites, a server that isn't a URL) and refused with the reason.
They are kept in `site-settings.json` in the data folder and win over the
config file; **Back to the config file** removes them.

**Add site** creates a new site (name, host names, servers, an optional
health check). It starts in monitor mode and is kept in `sites-added.json`
in the data folder. Sites added there can be removed there; sites from the
config file are removed in the file.

### Profiles

A profile fills in settings that suit a kind of app. Anything you set
yourself still wins, and you can see exactly what a profile does in
[`gateway/internal/config/profiles.go`](../gateway/internal/config/profiles.go).

| Profile | What it does |
|---|---|
| `wordpress` | Removes the `/wp-admin` and `/wp-login.php` honeypot traps (they are real pages there, so admins would be banned), rate-limits `wp-login.php` and `xmlrpc.php`, and lets HTML and code through in the post, theme and plugin editors |
| `laravel` | Encrypted `laravel_session` / `XSRF-TOKEN` cookies and the `_token` field are not mistaken for attacks; rate-limits `/login` and `/password/` |
| `django` | The same for `csrftoken`, `csrfmiddlewaretoken` and `sessionid`; rate-limits the admin and account logins |
| `nextjs` | The ML model skips `/_next/` build assets; NextAuth cookies are not mistaken for attacks; rate-limits `/api/auth/` |
| `ai` | Turns the prompt-injection guard on for `/api/chat`, `/api/generate` (Ollama) and the OpenAI- and Anthropic-style `/v1/...` endpoints |

## Attack detection

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `waf.mode` | `WAF_MODE` | `block` | Inside protect mode: `block`, or `detect` to only log WAF findings |
| `waf.threshold` | `WAF_THRESHOLD` | `5` | Anomaly score that counts as an attack (a critical match scores 5) |
| `waf.second_opinion` | `WAF_SECOND_OPINION` | on | When only the OWASP Core Rule Set flags a request, its score is no higher than the threshold, and the ML model is at least 95% sure every value it flagged is harmless, the request is logged as `detected` instead of blocked. This removes typical CRS false alarms ("Node.js & Express", "phone case (large)") while Sentinel's own rules and clear CRS hits still block. Needs `ml.mode` detect or block. `off` blocks every CRS detection |
| `waf.rules_file` | `RULES_FILE` | built-in | Replace Sentinel's own rules with a JSON file |
| `waf.crs` | `CRS_DIR` | on if built in (the Docker image), else off | The OWASP Core Rule Set: `on`, `off`, or the path of a CRS `rules/` folder |
| `waf.crs_paranoia` | `CRS_PARANOIA` | `1` | `1` (few false alarms) to `4` (strict; expect to tune) |
| `waf.crs_exclude` | `CRS_EXCLUDE` | `920220` | CRS rule IDs or ranges to switch off, e.g. `[920220, 942100-942199]` |
| `exclusions_file` | `EXCLUSIONS_FILE` | `exclusions.yaml` in the data folder | YAML list of exclusions: a rule switched off for one path and/or field. The dashboard's "Allow…" button adds to it; see below |
| `waf.max_field_bytes` | `WAF_MAX_FIELD_BYTES` | `65536` | A single field, header or raw body larger than this is refused (rule BODY-003); `0` = off |
| `waf.max_inspect_ms` | `WAF_MAX_INSPECT_MS` | `5000` | A request that keeps the Core Rule Set busy longer than this is refused (rule BODY-004), so a few crafted requests can't stall the gateway; `0` = off |
| `max_body_bytes` | `MAX_BODY_BYTES` | `1048576` | Larger bodies are refused with 413: they can't be inspected whole |
| `app_profile` | `APP_PROFILE` | `off` | **Learn your app.** `learn`: Sentinel learns, from requests that passed every check, what each page's parameters normally look like (length, characters, numbers, fixed values). `detect` / `block`: flag or refuse requests that don't fit, which catches parameter tampering that has no attack syntax. Saved in the data folder. On the CSIC 2010 dataset it caught 96.6% of attacks with 0.01% false alarms ([ml-report](ml-report.md)) |
| `app_profile_min_seen` | `APP_PROFILE_MIN_SEEN` | `20` | A page or field must have been seen this often before the profile judges it |
| `ml.mode` | `ML_MODE` | `detect` | The ML classifier: `off`, `detect` (log only) or `block` |
| `ml.threshold` | `ML_THRESHOLD` | `0.9` | Probability that counts as an attack |
| `ml.skip_paths` | `ML_SKIP_PATHS` | none | Path prefixes the model ignores (e.g. `[/socket.io/]`) |
| `prompt_guard.paths` | `PROMPT_GUARD_PATHS` | none | AI chat endpoints to protect from prompt injection |
| `prompt_guard.mode` | `PROMPT_GUARD_MODE` | `block` | `block` or `detect` |
| `prompt_guard.threshold` | `PROMPT_GUARD_THRESHOLD` | `5` | Score that counts as an injection |
| `prompt_guard.canary` | `PROMPT_CANARY` | none | A secret word in your AI's hidden prompt; a reply containing it (even encoded) is withheld |
| `honeypot.paths` | `HONEYPOT_PATHS` | built-in list | Trap paths (`/.env`, `/wp-admin`...); a hit bans the IP |
| `honeypot.ban_minutes` | `HONEYPOT_BAN_MINUTES` | `60` | How long a trap hit, or flooding, bans the IP |

**Why 920220 is excluded by default.** CRS rule 920220 looks for double URL
encoding and also fires on any literal `%` in a query, such as a search for
"50% off". Sentinel's own normalizer already decodes repeated encoding, so
the rule adds false alarms and almost no detection (measured in
[benchmarks.md](benchmarks.md)). Set `CRS_EXCLUDE` to something else, or to
an empty list, to change this.

### Exclusions (fixing false alarms)

When a rule blocks something legitimate, switch that rule off **only where
it misfires**, not everywhere. Click "Allow…" on the request in the
dashboard, or write the file by hand:

```yaml
- rule: CRS-942100          # or SQLI-001, ML, PI-001, or a prefix like CRS-942*
  path: /api/reviews        # requests whose path starts with this
  field: comment            # only this field (query, form, JSON, header or cookie name)
  note: reviews can mention SQL words
```

Each entry needs a path or a field (or both), so a rule can never be
switched off everywhere by accident. `method:` narrows it further, and
`site:` (a name from `sites`) limits it to one site; without it the entry
counts on every site. "Allow…" fills in the site of the request. The file is
re-read on `SIGHUP`.

## What the app sends back

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `response_check` | `RESPONSE_CHECK` | `block` (`detect` in monitor mode) | Check the app's responses for leaks: database errors, stack traces, private and cloud keys, directory listings (withheld in `block`, logged in `detect`), and payment card numbers (always masked to the last four digits). `off` turns it off |
| `response_max_bytes` | `RESPONSE_MAX_BYTES` | `1048576` | Text responses up to this size are checked. Larger, binary and streaming responses (SSE, anything that flushes) pass through unchecked, so streaming never breaks |

A database error in a response is often the first sign that an injection
works, so withholding it takes away the attacker's feedback. To allow a leak
type for some paths (a file server that lists folders on purpose), add an
exclusion with the finding's ID, e.g. `rule: LEAK-LISTING`, `path: /files/`,
`field: response`.

## Bots

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `bot.block_scanners` | `BOT_BLOCK_SCANNERS` | on | Refuse requests whose User-Agent names an attack tool (sqlmap, nikto, nuclei, wpscan...) |
| `bot.challenge` | `BOT_CHALLENGE` | `off` | A JavaScript check for browsers: `suspicious` (clients that look automated: no User-Agent, headless or automation tools, a "browser" without Accept-Language) or `all` (every visitor on the paths below) |
| `bot.challenge_paths` | `BOT_CHALLENGE_PATHS` | `/` | Where the check applies, e.g. `[/login, /signup]` |
| `bot.difficulty` | `BOT_DIFFICULTY` | `15` | Proof-of-work size; a browser needs about 0.1–0.5 s at 15, and each step up doubles it |

The check is a short proof of work: a browser solves it once and gets a
signed cookie for 24 hours, bound to its IP and User-Agent. Requests that
don't ask for an HTML page (APIs, images) are never shown a check, so APIs
keep working. Be realistic about what it stops: scripts and simple bots,
not a determined attacker driving a real browser (modern headless browsers
look like normal ones). With `all`, search engines can't index the checked
paths, so use it for pages like `/login`, not your whole site.

## Traffic limits and network

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `rate_limits` | `RATE_LIMITS` | `{/__sentinel/auth/: 10/1m, /: 600/1m}` | Requests per window by path prefix; logged-in users are counted by name. `off` turns it off. A client that sends 3× its limit within one window is flooding and its IP is banned (`honeypot.ban_minutes`) |
| `login_fail_limit` | `LOGIN_FAIL_LIMIT` | `10` | Failed logins per account (from any IP) before a 15-minute pause; `0` = off |
| `redis_url` | `REDIS_URL` | none (memory) | Share counters and bans between Sentinel instances |
| `trusted_proxies` | `TRUSTED_PROXIES` | none | Your load balancer's CIDRs; only their `X-Forwarded-For` is believed |
| `trust_proxy_headers` | `TRUST_PROXY_HEADERS` | `false` | Believe `X-Forwarded-For` from anyone (only when nothing can reach Sentinel except your proxy) |
| `geo.file` | `GEOIP_FILE` | none | `cidr,country` CSV (convert any IP-to-country database) |
| `geo.deny_countries` | `GEO_DENY_COUNTRIES` | none | e.g. `[KP]` |
| `geo.allow_countries` | `GEO_ALLOW_COUNTRIES` | none | If set, only these countries (and private addresses) |
| `ip.deny` / `ip.allow` | `IP_DENY` / `IP_ALLOW` | none | CIDRs always refused / the only ones allowed |

## Monitoring and alerts

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `metrics_listen` | `METRICS_ADDR` | off | Serve Prometheus metrics at `http://<this>/metrics`, e.g. `:9090`. A separate port, so they are never public on the main one |
| `alerts.webhook_url` | `ALERT_WEBHOOK_URL` | off | Where alerts go: a Slack or Discord webhook, a Telegram `https://api.telegram.org/bot<token>/sendMessage` URL, or any URL (JSON is posted) |
| `alerts.telegram_chat_id` | `ALERT_TELEGRAM_CHAT_ID` | none | The chat to send to, for Telegram |
| `alerts.burst` | `ALERT_BURST` | `20` | Stopped requests from one IP within a minute that make an "attack burst" alert |
| `export.syslog` | `EXPORT_SYSLOG` | off | Send security events to a syslog server (RFC 5424, facility *log audit*): `udp://host:514`, `tcp://host:601` or `tls://host:6514` |
| `export.otlp` | `EXPORT_OTLP` | off | Send security events to an OpenTelemetry collector as log records (OTLP over HTTP, JSON), e.g. `http://otel-collector:4318` |
| `export.otlp_headers` | `EXPORT_OTLP_HEADERS` | none | Headers sent to the collector, e.g. `api-key=...` (several: `A=1,B=2`) |
| `export.all` | `EXPORT_ALL` | `false` | Also export plain allowed requests, not only blocked, flagged and login events |
| `kubernetes_ingress_class` | `KUBERNETES_INGRESS_CLASS` | off | Be the Kubernetes Ingress controller for this ingress class (e.g. `sentinel`): sites come from Ingresses. See [common setups](setups.md#sentinel-as-the-ingress-controller) |

Alerts are sent for: a honeypot hit, an attack burst from one IP, password
guessing on an account, a new admin account and a failed reload. Each subject alerts at most once per 10 minutes, with at most 20
alerts a minute in total, so an attack can't flood your phone.

The **Alerts** card on the dashboard sets the webhook, Telegram chat and
burst size while Sentinel runs (kept in `alerts.json` in the data folder,
winning over the config file), and can turn alerts off.

Exported events carry the outcome, client IP, method, path, status, rule,
reason, site, country, user and request ID, so a SIEM (Splunk, Elastic,
Graylog, Wazuh, Grafana Loki through a collector) can search and alert on
them. Delivery never slows requests down: if the other side is down,
events are dropped and the count is logged every minute.

Metrics: `sentinel_requests_total{outcome}`, `sentinel_rule_stops_total{rule}`,
`sentinel_request_duration_seconds` (histogram), `sentinel_bans_active`,
`sentinel_rules_loaded`, `sentinel_exclusions`, `sentinel_info{version,mode}`,
plus uptime, memory and goroutines. A ready Grafana dashboard is in
[`deploy/grafana/sentinel.json`](../deploy/grafana/sentinel.json).

## The dashboard's login, API schema and HTTPS

| File key | Variable | Default | Meaning |
|---|---|---|---|
| `secret` | `SENTINEL_SECRET` | made once and kept in the data folder | Master key for the dashboard's login tokens and encrypted 2FA secrets, at least 32 characters (`openssl rand -hex 32`) |
| `database_url` | `DATABASE_URL` | none (accounts in the data folder) | PostgreSQL for the admin accounts and revoked tokens |
| `api_spec.file` / `api_spec.prefix` | `API_SPEC_FILE` / `API_SPEC_PREFIX` | off | OpenAPI 3 spec; requests that don't match it are refused |
| `tls.auto_domains` | `TLS_AUTO_DOMAINS` | none | **Automatic HTTPS**: certificates from Let's Encrypt for these domains, renewed automatically, e.g. `[shop.example.com]`. The entry `sites` stands for every exact host name of every site (`[sites]` covers them all). Ports 80 and 443 must be reachable from the internet; plain HTTP is redirected to HTTPS |
| `tls.auto_email` | `TLS_AUTO_EMAIL` | none | Contact address for Let's Encrypt (expiry warnings) |
| `tls.auto_cache` | `TLS_AUTO_CACHE` | `certs` in the data folder | Folder where certificates are kept (keep it on a volume, or Let's Encrypt's rate limits apply on every restart) |
| `tls.listen` | `TLS_LISTEN_ADDR` | none (`:443` with automatic HTTPS) | e.g. `:8443` to also serve HTTPS |
| `tls.cert_file` / `tls.key_file` | `TLS_CERT_FILE` / `TLS_KEY_FILE` | none | Server certificate and key |

Logins for your own apps, access policies (RBAC/ABAC), mTLS for services,
risk-based step-up and the tamper-evident audit log are part of Sentinel
Pro. If one of their settings (`POLICY_FILE`, `MTLS_ROUTES`,
`AUDIT_LOG_FILE`, ...) is set, the free edition refuses to start and says
so, instead of quietly running without the protection you expected.
