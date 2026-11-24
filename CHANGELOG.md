# Changelog

## 0.17.9 · 2026-11-24
- **Strict bot check for login and signup**: new `bot.strict_paths` (`BOT_STRICT_PATHS`). On those paths every client needs a browser check pass: a browser loading the page gets the check as before, and anything else without a pass, such as a script, `curl` or a form posted without loading its page, is refused (rule BOT-STRICT). The regular `bot.challenge` still checks page loads only, so API clients and webhooks on other paths are unaffected. It works with `bot.challenge` off.

## 0.17.8 · 2026-11-24
- **REST APIs work in protect mode**: `PUT`, `PATCH` and `DELETE` were refused by Core Rule Set rule 911100 (its default list allows only GET, HEAD, POST and OPTIONS), so updates and deletes to an API behind Sentinel failed, and so did the dashboard's own "remove" buttons. They are allowed now; `TRACE`, `CONNECT` and made-up methods are still refused.
- **OpenAPI specs in YAML**: `api_spec.file` accepted only JSON, and a YAML spec stopped startup with "invalid character". Both work now.
- **More stack traces withheld**: the response check now recognises Java, Kotlin and Scala traces from any package (it only knew `java.*`, Spring and `sun.*` frames, and missed Java 9+ `java.base/` frames), `Exception in thread "main"` lines, and .NET traces (`at Shop.Cart.Add() in Cart.cs:line 42`).
- **The demo lab starts reliably**:
  - `Start Sentinel.bat` and `lab/start.sh` find Git and Docker Desktop installed for one user only (in `AppData\Local\Programs`), not only in Program Files, and open Docker Desktop on macOS too;
  - a lab built from source now reports its real version instead of `dev`, so `lab/start.sh` no longer rebuilds Sentinel (and downloads the Core Rule Set again) on every start, which failed on slow or locked-down networks.
- A mistyped setting now suggests the right one in the file's own words: `unknown setting "waf.treshold" (did you mean "waf.threshold", the variable WAF_THRESHOLD?)`.
- Docs: the README's numbers are current (CRS regression suite 99.2%, about 1 normal request in 50 wrongly blocked), and the bot check's docs say it applies to page loads.

## 0.17.7 · 2026-11-23
- **Fewer false alarms**: on the open-appsec comparison Sentinel wrongly blocks 1.9% of normal requests (1,580; 0.17.6: 1,636) and blocks exactly the same attacks (99.97%, checked one by one). Found only on the half of the sites not counted:
  - the ML model skips shop price filters such as `$150 and over` (the currency sign keeps `1 and 1` scored) and empty functions that analytics tags send as ids (`function kd(){}`);
  - XSS-003 judges a whole query string parameter by parameter, so `oid=javascript:;&ot=a` passes and `javascript:alert(...)` is still caught;
  - NULL-001 no longer fires on zero bytes that come from decoding a base64 cookie (Criteo's `cto_bundle`); a real `%00` still does.

## 0.17.6 · 2026-11-23
- **More attacks caught**: on the open-appsec comparison Sentinel blocks 11,051 of 11,054 attacks (99.97%; 0.17.5: 11,046) and wrongly blocks the same 2.0% of normal requests. New and widened rules, each checked against about 69,000 normal requests:
  - SQLI-012: always-true conditions without quotes (`AND 1=1`, `OR x=y#`);
  - SQLI-001 also finds `union select` split by `#` comments;
  - SQLI-006 also finds DB2 system tables (`sysibm`, `syscat`);
  - CMDI-006: VBScript web shells (`On Error Resume Next`).
- The `WAF_MAX_INSPECT_MS` docs now say the limit counts elapsed time, so a heavily loaded server reaches it sooner.

## 0.17.5 · 2026-11-22
- **Fewer false alarms**: on the open-appsec comparison Sentinel wrongly blocks 2.0% of normal requests (1,637; 0.17.4: 1,816) and blocks exactly the same attacks (99.9%, checked one by one). As before, the fixes were found only on the half of the sites not counted.
  - Core Rule Set exceptions now look at the whole matched value. They used to see only its first 120 characters, so a long JSON cookie (Mixpanel) never read as JSON, and a few values were judged on their start alone;
  - Akamai bot-manager cookies (`_abck`) use `~-1` as a separator: a tilde before a number no longer reads as a shell home directory (`~/path` and `~user` still do);
  - unfilled upper-case ad-tag placeholders such as `${USER_ID}` and `${AUCTION_PRICE}` no longer read as shell variables (`${IFS}`, `${PATH}` still do);
  - Sentinel's `javascript:` rule (XSS-003) ignores inert `javascript:void(0)` and `javascript:;`, also in session-replay recordings of whole pages;
  - a value that is only a property name, such as `window.location.href` as a trace attribute key, no longer trips CRS 941180 (`alert(document.cookie)` still does).

## 0.17.4 · 2026-11-22
- **Fewer false alarms**: on the open-appsec comparison Sentinel wrongly blocks 1,816 normal requests (0.17.3: 1,874) and blocks exactly the same attacks (99.9%, checked one by one). As before, the fixes were found only on the half of the sites not counted.
  - the directory traversal rule (LFI-001) no longer reads `...` before a JSON-escaped quote (`...\"`) as a Windows `..\`, which analytics payloads such as Shopify's send constantly; `..\..\windows` is still caught;
  - JSON values holding Chrome's brand list (`"Not)A;Brand"`) no longer read as SQL to Core Rule Set rule 942550; JSON with SQL keywords, `--` or `/*` still does.

## 0.17.3 · 2026-11-21
- **A time limit per request**: a request that keeps the Core Rule Set busy for more than 5 seconds is refused (rule BODY-004) instead of being checked to the end, so a few large, crafted requests can no longer stall the gateway (a 440 KB JSON body of many fields used to cost about 3 seconds of CPU each). Requests over the limit are blocked, not let through, because the rules that didn't run might have matched. Set it with `WAF_MAX_INSPECT_MS` (`0` = off). On the open-appsec comparison: 99.9% of attacks blocked, 2.2% of normal requests wrongly blocked (1,874; 0.17.2: 1,881); one large trace upload on a busy gateway hit the limit.

## 0.17.2 · 2026-11-21
- **Fewer false alarms**: the Core Rule Set no longer fires on URL-encoded JSON cookies without SQL in them (Mixpanel's `mp_*_mixpanel`), or on ad-tag placeholders with dotted names or calls such as `${user.gdpr}` and `${uipid()}`. Shell expansions (`${IFS}`, `${jndi:...}`, `$(...)`) are still caught. On the open-appsec comparison: 99.9% of attacks blocked, 2.2% of normal requests wrongly blocked (5 fewer than 0.17.1).

## 0.17.1 · 2026-11-20
- **Faster Core Rule Set**: about a quarter less CPU on real browser traffic, with exactly the same verdicts. 214 of CRS's regular expressions can only start a match on a few characters (the Unix command rules need `;`, `|`, `&`, `$(` or "busybox" in front of the command name), so Sentinel now runs them only from those positions instead of from every byte of every value. Checked against the plain regexes on 25,000 real request values plus random ones, and against CRS's own regression suite (unchanged at 4,775/4,812). A value with many possible start positions goes to the plain regex, so a crafted value can't make it much slower than before.
- **Compressed request bodies are inspected**: a body sent with `Content-Encoding: gzip` or `deflate`, or gzip without saying so (some analytics beacons), is expanded (up to 1 MB) and checked like any other body. Before, rules saw only the compressed bytes, and CRS blocked the header itself.
- **Fewer false alarms**: on the open-appsec comparison Sentinel wrongly blocks 2.2% of normal requests (0.17.0: 2.5%) and blocks the same 99.9% of attacks. As before, the fixes were found only on the half of the sites not counted.
  - a form, multipart or `text/plain` JSON body over 64 KB is checked field by field instead of refused as one oversized value;
  - Core Rule Set rules no longer fire on Akamai-style cookies (`hash~0~data`), unfilled ad-tag placeholders such as `${user_id}`, JSON documents without SQL nested in a string, JSON keys such as `profile_id`, or inert `javascript:void(0)`, `javascript:;`, SDK version strings and `data:image` URIs.

## 0.17.0 · 2026-11-19
- **Fewer false alarms**: on the open-appsec comparison (normal traffic counted only on sites never used for tuning) Sentinel wrongly blocks 2.5% of normal requests, down from 4.4%, and blocks 99.9% of attacks (0.16.4: 95.4%; see the benchmarks page for how independent that number is). Fixed false alarms:
  - Core Rule Set rules no longer fire on URL-encoded newlines in the Cookie header, the IAB privacy string `1---`, plain GraphQL documents, bodies sent without a Content-Type (beacons), protocol names such as `http/1.1`, or a Content-Type header sent twice;
  - the ML model skips values too plain to carry an attack: bare words, IP addresses, `1---` and GraphQL documents;
  - large binary bodies (compressed analytics, session replay) are checked by their readable text instead of refused;
  - JSON bodies may hold 10,000 fields (forms stay at 1,000);
  - multipart boundary lines no longer read as SQL comments.
- **Fewer ways around the checks**, found by moving caught attacks to other parts of the request:
  - the ML model checks URL path segments that contain a quote, `;`, `|`, `<`, `(`, `$`, a backtick or a space;
  - a body of another type that reads as a form is checked field by field;
  - cookie values with injection characters are checked by the model at a stricter threshold (0.98);
  - custom headers holding injection characters are checked by the Core Rule Set's argument rules;
  - LFI-003 and LFI-004 check headers; LFI-004 also catches separators written as `%u2215` or as broken percent-escapes.

## 0.16.4 · 2026-11-19
- **More attacks blocked, same false alarms**: on the open-appsec comparison (normal traffic counted only on sites the ML model never saw) Sentinel now blocks 95.4% of attacks (0.16.3: 93.4%) and still wrongly blocks 4.4% of normal requests. New rule LFI-004 catches path traversal that hides its slashes (overlong UTF-8, control bytes, `0x5c`) on the way to `/etc/passwd`, `/etc/issue`, `windows/system32/...`; the ML model had caught some of these before it was retrained on real traffic.
- **Dashboard, first run**:
  - turning on 2FA logs you in straight away, instead of logging you out and making you wait for the next code;
  - in monitor mode the dashboard counts what would have been stopped ("flagged") and shows it in the rule and IP tables; before, a new install looked as if it caught nothing;
  - fix: requests let through in monitor mode by a rate limit, ban or honeypot (outcome `monitored`) were counted as stopped;
  - an expired session (e.g. after a restart without a data volume) logs out instead of retrying the live stream every 3 seconds;
  - the dashboard's own setup and 2FA requests are hidden from the live views like its other housekeeping;
  - the configuration panel no longer says rate limits are "off" when they are set per site.
- The note about one unsupported Core Rule Set rule at startup is information, not a warning.
- The documentation site has a front page: https://sentinel.tft.markets.
- Dependencies updated: libinjection-go 0.3.6 (detection on the open-appsec attack set unchanged), pgx 5.13.0, golang.org/x/net 0.63.0.

## 0.16.3 · 2026-11-19
- **Comparison (open-appsec dataset, normal traffic counted only on sites the model never saw)**: Sentinel blocks 93.4% of attacks and wrongly blocks 4.4% of normal requests (0.16.1: 95.0% / 7.5%); ModSecurity + CRS 90.3% / 26.7%, BunkerWeb 90.3% / 28.8%. See `docs/benchmarks.md`.
- **ML model trained on real browser traffic**: values from recorded browsing sessions on half the sites of the open-appsec dataset (Apache-2.0) are now part of the normal training data. On the other half, sites the model never saw, it wrongly flags 0.7% of normal requests instead of 3.0%. Public attack payloads it never saw: 94.8% caught (was 96.1%). Report: `docs/ml-report.md`; trainer flag `-traffic`.
- **Security hardening**:
  - alert webhooks can no longer reach link-local addresses (the cloud metadata service at 169.254.169.254) and don't follow redirects, so a stolen admin session can't use them to fetch cloud credentials;
  - control characters in exported syslog events are escaped: a `%0a` in a URL can't forge a second event in a log system that splits lines;
  - the metrics server has full read, write and idle timeouts.
- XSS-003 (`javascript:` URLs) no longer checks cookies: Adobe Analytics' `s_sq` cookie records clicked `javascript:void(0)` links.
- Fuzzing covers multipart bodies and base64-decoded values.
- The ML middleware's choice of what to score is one function (`middleware.MLInputs`), shared with the trainer.

## 0.16.2 · 2026-11-18
- **Sentinel moved to the TheFirstTerminal organization**: the repository is `github.com/TheFirstTerminal/sentinel` (old links redirect), the docs are at https://sentinel.tft.markets, the image is `ghcr.io/thefirstterminal/sentinel`, Homebrew is `brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel`, and the contact address is support@tft.markets. Images up to 0.16.1 stay at `ghcr.io/tsxmamii/sentinel`.

## 0.16.1 · 2026-11-18
- **Fewer false alarms on real traffic**. On the open-appsec dataset Sentinel now blocks 95.0% of attacks (was 85.3%) and wrongly blocks 7.7% of normal requests (was 14.6%); ModSecurity + CRS: 90.3% / 24.7%, BunkerWeb: 90.3% / 27.4%:
  - the ML model no longer scores cookies (analytics cookies hold encoded JSON it mistook for injections); the rules still check them;
  - a Core Rule Set match in a cookie blocks only if the ML model agrees (Akamai, Mixpanel and consent cookies tripped CRS command and SQL rules);
  - the ML model was retrained with normal GraphQL queries and analytics telemetry (timing strings, CSS selectors), which it flagged before;
  - the shell-command rule (CMDI-001) no longer fires on consent and tracking cookies or ad parameters (`|id:…`, `;cat=…`); a command must be followed by a space, the end or a shell character;
  - the null-byte rule skips bodies that are not text (compressed or protobuf analytics, uploads);
  - `text/plain` request bodies (`navigator.sendBeacon`, analytics) and CSP reports are allowed content types.
- **Security fixes**:
  - a 2FA login token now works only once (it was revoked but the revocation was not checked);
  - wrong 2FA codes sent in parallel all count against the limit of 5;
  - two admins demoting each other at once can no longer leave no admin;
  - with `TRUST_PROXY_HEADERS=true`, an `X-Forwarded-For` that is not an IP is ignored;
  - dashboard changes made with a login cookie (Pro single sign-on) must come from the dashboard's own page.
- The protected app gets the client IP Sentinel worked out in `X-Forwarded-For` (behind a load balancer it got the balancer's); IPv6 client addresses reach CRS correctly.

## 0.16.0 · 2026-11-18
- **Better detection** (GoTestWAF: attacks blocked 51% → 85%, normal requests allowed 96% → 95%; ModSecurity + CRS on the same test: 49% / 91%):
  - values that are base64 for readable text are checked decoded, multipart form fields one by one, overlong UTF-8 (`%C0%AE`) is undone;
  - new rules: NoSQL commands, LDAP filters, IMAP/SMTP commands, out-of-band callback hosts, git/ssh option injection, `#{}` templates, Windows admin shares, UTF-7 XML, JavaScript call probes (`confirm.call(…)`, `alert?.(…)`);
  - the `javascript:` rule no longer fires on prose ("JavaScript: Basics").
- **ML model retrained** with public payloads (PayloadsAllTheThings, MIT) and technical prose as normal input: 96.7% of 1,153 held-out public payloads caught, no normal input wrongly blocked.
- **Compared with other self-hosted WAFs** on the open-appsec dataset (docs/benchmarks.md): Sentinel 85.4% balanced accuracy, ModSecurity + CRS 82.8%, BunkerWeb 81.5%; Sentinel wrongly blocks 14.6% of normal requests, the others 25-27%.
- **Dashboard**: the edition in the header; Free links to what Pro adds.

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
