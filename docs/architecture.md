# How Sentinel works

This is the deep dive. For installing and configuring Sentinel, start with
the [README](https://github.com/TheFirstTerminal/sentinel/blob/main/README.md).

## How a request flows

```
client ─► RequestContext ─► AccessLog ─► IPBlock ─► Geo ─► Honeypot ─► Bots ─► BodyLimit ─►
          (ID, real IP)     (1 line,     (1 banned  (IP/    (404 +      (scanners,
                             decision)    IP → 403)  country) ban)       challenge)

      ─► RateLimit ─► LoginGuard ─► Schema ─► PromptGuard ─► WAF ─► ML ─► AppProfile ─► app
         (2 per IP,   (failed       (6 API    (AI routes:     (7 rules  (8 model,  (learned
          429; 3× =    logins per    spec)     injection +     + CRS)    explained) fields)
          ban)         account)                canary)
```

Sentinel's own pages (`/__sentinel/...`: the dashboard, its login and the
first-run setup) sit at the end of the same chain, so they are protected by
every check too.

| Path | What it does |
|---|---|
| `gateway/cmd/sentinel/` | Builds the pipeline; monitor mode; `init`, `check-config`, `bench`, `watch`, `explain` and `totp` commands |
| `gateway/internal/auth/` | The dashboard's admin login: JWT, TOTP 2FA, bcrypt, encrypted secrets, first-run setup |
| `gateway/internal/schema/` | OpenAPI request validator |
| `gateway/internal/middleware/` | Request context, access log, IP ban, honeypot, bots, rate limits, login guard, schema, WAF, ML and app-profile steps |
| `gateway/internal/ratelimit/` | Rate limit rules and counting |
| `gateway/internal/geo/` | IP → country, IP and country allow/deny lists |
| `gateway/internal/certs/` | The HTTPS listener's certificate |
| `gateway/internal/kv/`, `redisx/` | Shared counters (memory or Redis) and a tiny Redis client |
| `gateway/internal/promptguard/` | Prompt-injection detection for AI endpoints |
| `gateway/internal/dashboard/` | The dashboard page and its API |
| `gateway/internal/events/` | Recent decisions in memory: history, statistics, live feed |
| `gateway/internal/ml/` | ML classifier (check 8): features, model, explanations; `dataset/` and `evasion/` for training and testing; `profile/` for the app profile |
| `gateway/cmd/mltrain/` | Trains the model and writes [`docs/ml-report.md`](ml-report.md) |
| `gateway/cmd/evaluate/`, `lab/eval/` | Evaluation from outside: replay, overhead, sqlmap ([`docs/evaluation.md`](evaluation.md)) |
| `gateway/internal/watch/` | The live decisions window |
| `gateway/internal/waf/` | Rules, normalization, scoring |
| `gateway/internal/crs/` | OWASP Core Rule Set engine (SecLang interpreter) |
| `gateway/internal/prefilter/` | Skips regexes that cannot match (literal and character prefilters) |
| `gateway/internal/config/` | Settings from YAML and environment variables |
| `gateway/internal/proxy/` | Routes by path prefix and forwards clean requests |
| `deploy/` | Running Sentinel for real: Docker Compose, systemd, Helm |
| `lab/` | The quick demo: Sentinel in front of Juice Shop |
| `lab/start.sh`, `Start Sentinel.bat` | One-step start: Docker, build, wait, demo menu |

## Key ideas

**Reverse proxy.** The client only ever talks to Sentinel. Sentinel makes the
request to the real app on the client's behalf, so it can inspect and block
everything; the app is never exposed directly.

**Middleware chain.** Each check is a function wrapping the next one. Cheap
checks run first (a banned IP is refused before any regex runs).

**Normalization.** Attackers hide payloads (`%27`, `%2527`, `&lt;script&gt;`,
`UNION/**/SELECT`, null bytes). Sentinel decodes all of that first, so one
rule catches every variation.

**Per-field inspection** and **anomaly scoring** (OWASP Core Rule Set idea):
each JSON/form field is checked on its own, and weak signals only block when
they add up.

**Honeypots.** Fake paths like `/admin-backup` that no real user visits.
A hit returns an ordinary 404 and bans the IP.

**The dashboard's login.** The dashboard is for Sentinel's administrators
only; other accounts can't log in.

**JWT.** After login Sentinel issues a token `header.claims.signature`
signed with HMAC-SHA256. The client can read it but not change it (changing
the role or user inside it breaks the signature). Sentinel only accepts
`HS256` (the `"alg":"none"` trick is refused), tokens live 15 minutes, and
logout revokes them immediately (revocation list in PostgreSQL).

**2FA (TOTP, RFC 6238).** Phone and server share a secret and both compute
`HMAC-SHA1(secret, time/30s)` → 6 digits, so codes match with no connection
between them. A password-only login gets a 5-minute "MFA token" that is good
for nothing except exchanging it, together with a code, for a real token.
Codes can't be reused (replay protection), 5 wrong codes end the attempt, and
the secrets are stored **encrypted** (AES-256-GCM) in the database.

**Passwords** are stored as bcrypt hashes (slow on purpose). An unknown
username takes as long as a wrong password, so attackers can't discover
usernames by timing.

**One master secret, separate keys.** `SENTINEL_SECRET` is expanded with
HKDF into a token-signing key and an encryption key.

**Positive security model.** The WAF blocks known-bad input; schema
validation only lets through what the API's OpenAPI spec says is good.
Unknown fields (`"role":"admin"` in a profile update = **mass assignment**),
wrong types, bad formats, unknown endpoints and unexpected query parameters
are rejected before the app sees them.

**No forged identities.** Anything a client sends as `X-Sentinel-User`,
`X-Sentinel-Role` and similar headers is deleted before the request reaches
the app, so an app behind Sentinel never sees a client-made identity header.

**Rate limiting.** Each path prefix has a limit per time window
(`/__sentinel/auth/=10/1m`), counted per IP. Over the limit: `429 Too Many Requests` with
`Retry-After`, before any password is checked, so guessing passwords stops
being practical. A client that sends 3 times its limit within one window is
flooding and its IP is banned. The **login guard** also counts failed
dashboard logins per account, from any IP, which stops password spraying
that per-IP limits can't see.

**Real client IP.** Behind a load balancer every request seems to come from
the load balancer. `TRUSTED_PROXIES` names it; only then is
`X-Forwarded-For` read, from the right, skipping trusted hops, so a client
can't fake its address by sending its own header.

**Geo-filtering.** An offline `cidr,country` file tells Sentinel where an
address is. Countries or address ranges can be blocked, or only some
allowed. Private addresses always count as `LAN`.

**Prompt injection.** Apps that pass user text to an AI model can be
talked into ignoring their instructions ("ignore all previous
instructions...") or revealing their hidden prompt. On `PROMPT_GUARD_PATHS`
Sentinel normalises every text field (invisible characters, look-alike
letters, l33t-speak, spaced-out letters, base64) and scores it against
injection patterns. Patterns never catch everything, so there is a second
layer: the app puts a secret **canary** in its hidden prompt, and any reply
containing it is withheld (`502`). The lab's HR assistant is a simulated
chatbot with exactly this weakness.

**Machine learning (check 8).** Rules only catch what someone wrote a rule
for. After the WAF lets a request through, a classifier scores each query
and body field. It is a logistic regression over hashed character 3-5-grams,
words and word pairs of the normalised input: small (about 250 KB, embedded
in the binary), fast (microseconds, no GPU or external service) and
explainable, because the score is a sum: Sentinel credits each feature's
share to the word it came from and logs, for example, `"pg_sleep" +4.89`.
`sentinel explain "<text>"` shows the WAF's and the model's verdicts side
by side. The model is trained on generated data (23 attack families and
many kinds of normal input, including look-alikes such as "Please select a
size" or "O'Brien") and tested on fresh data and on evasion rewrites it never
saw (encodings, comments, case, operator swaps, shell quote splitting...):
see [`docs/ml-report.md`](ml-report.md). Because the data is
synthetic, start real deployments with `ML_MODE=detect`.

**Security headers.** Responses get `X-Content-Type-Options: nosniff`, a
`Referrer-Policy`, `X-Frame-Options` and (over HTTPS) HSTS, unless the app
already sets them.

**Evaluation.** `bash lab/evaluate.sh` attacks the lab from outside: a
replay of thousands of attacks, evasion variants and normal input, the time
Sentinel adds, and sqlmap with and without its tamper scripts. The first run
found a real bypass, which was fixed; see
[`docs/evaluation.md`](evaluation.md).

**Standards and supply chain.** [`docs/asvs.md`](asvs.md) maps
Sentinel to OWASP ASVS 4.0.3 requirement by requirement, including the gaps.
Releases are built by GitHub Actions with an SBOM, a vulnerability scan
(govulncheck, Grype) and keyless signatures (cosign) once the repository is
public: [`docs/supply-chain.md`](supply-chain.md).

**Dashboard.** `/__sentinel/dashboard`, for admins who passed 2FA: requests
and stops per minute, why requests were stopped, top attacking IPs and
countries, bans (ban or unban with a click), a live feed and a console of every
decision. The page uses no external files; the token stays in
the browser tab and is sent in a header, never in a URL.

**Redis.** Rate limit counters and bans live in Redis, so several
Sentinel instances share them and they survive restarts. If Redis is
missing at startup Sentinel uses memory; if it fails later, requests are let
through (fail open) rather than taking the apps offline. The Redis client is
about 220 lines in `internal/redisx` (no third-party dependency).


**OWASP Core Rule Set.** Beside its own rules, Sentinel runs CRS, the rule
set ModSecurity and Coraza use, with its own engine
(`gateway/internal/crs`): a SecLang interpreter for the parts the request
rules use (chains, the TX collection, setvar and macros, skipAfter, ctl
exceptions, paranoia levels, about 20 operators including libinjection, and
the transformations). CRS's anomaly score is added to Sentinel's, so one
threshold covers both. CI replays CRS's own regression suite on every push:
[`benchmarks.md`](benchmarks.md).

**Monitor mode.** Every check that can refuse a request runs inside a
"shadow": its answer goes to a writer that discards it, and if the check
refused, the request is forwarded anyway and logged as "would be blocked".
New installs start this way, so a false alarm can't break an app on its
first day.
