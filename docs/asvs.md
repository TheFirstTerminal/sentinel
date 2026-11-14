# Sentinel and OWASP ASVS 4.0.3

The [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
(ASVS) lists what a secure application must do. Sentinel is a gateway, not
the application itself, so for each requirement this table says what
Sentinel does about it, and what is still the protected app's job.

Requirement numbers and wording are from ASVS **4.0.3** (summarised).

**Status:**
- **Met:** Sentinel does this for every app behind it.
- **Helps:** Sentinel adds a layer of defence, but the requirement is about how the app itself is built, so the app still has to meet it.
- **App:** only the app can do this. Sentinel can't.
- **Partly:** Sentinel does part of it. The note says what's missing.
- **Pro:** met by Sentinel Pro's zero-trust features (logins for your apps, access policies, mTLS, risk-based step-up, tamper-evident audit log); the free edition leaves it to the app.

## V2 Authentication

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 2.1.1 | Passwords at least 12 characters | Partly | Sentinel's own accounts are its dashboard administrators, created through the first-run setup. There is no self-service password change yet, so there is no length check at change time. |
| 2.2.1 | Anti-automation against brute force and credential stuffing | Met | Rate limit on the login API (`/__sentinel/auth/=10/1m`, counted per IP), flood bans, and a per-account limit on failed logins from any IP (password spraying). Five wrong 2FA codes end the login attempt. |
| 2.4.1 | Passwords stored resistant to offline attacks | Met | bcrypt hashes. |
| 2.4.4 | bcrypt work factor as high as practical (min. 10) | Met | Cost 12. |
| 2.8.1 | Time-based OTPs have a defined lifetime | Met | TOTP per RFC 6238: 30-second steps, ±1 step tolerance. The MFA token that waits for the code lasts 5 minutes. |
| 2.8.3 | Approved algorithms for OTPs | Met | HMAC-SHA1 as RFC 6238 specifies. Secrets come from a CSPRNG. |
| 2.8.4 | A TOTP code can be used only once | Met | The last accepted time step is stored per user, and replays are rejected. |
| 2.8.5 | A reused TOTP code is logged and rejected | Met | Rejected with "already used", logged as `mfa_failed`. |
| 2.10.1 | Service-to-service auth doesn't rely on unchanging passwords or API keys | Pro | mTLS for services (`MTLS_ROUTES`). |
| 2.10.4 | Secrets not in source code | Partly | All secrets come from environment variables, and the 2FA secrets in the database are encrypted with AES-256-GCM. The lab's `docker-compose.yml` contains lab-only values, marked as such. |

## V3 Session management

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 3.3.1 | Logout and expiry invalidate the session token | Met | Tokens expire after 15 minutes. Logout puts the token's ID on a revocation list in PostgreSQL. |
| 3.3.2 | Periodic re-authentication | Met | 15-minute tokens. There are no refresh tokens, so users log in again. |
| 3.5.2 | Session tokens rather than static API secrets | Met | Short-lived signed JWTs for people, certificates for services. |
| 3.5.3 | Stateless tokens protected against tampering, null cipher, key substitution | Met | HMAC-SHA256 signatures. Only `HS256` is accepted (`alg: none` and algorithm switching are refused). The signing key is derived with HKDF and kept separate from the encryption key. |

## V4 Access control

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 4.1.1 | Access control enforced on a trusted server-side layer | Pro | Access policies checked in the gateway on every request. The free edition protects Sentinel's own dashboard this way; your app's access control is the app's job. |
| 4.1.2 | Access control data can't be manipulated by users | Met | Client-sent `X-Sentinel-*` headers are removed before the app sees them, so no client can forge an identity header. |
| 4.1.3 | Least privilege | Met | Rules give each role only the paths and methods it needs. |
| 4.1.5 | Access controls fail securely | Partly | Sentinel's own checks fail securely (an invalid token is never treated as a login, schema checks don't depend on Redis); only rate limiting fails open if Redis is down, which favours availability. Default-deny access policies for your app are in Pro. |
| 4.2.1 | Protection against IDOR (BOLA) | Pro | Owner rules such as `/employees/{username}/salary` only for that user, HR or admins. |
| 4.2.2 | Strong anti-CSRF | App | Sentinel uses bearer tokens in a header, which aren't sent automatically. CSRF protection for the app's own cookie sessions is the app's job. |
| 4.3.1 | Admin interfaces use MFA | Met | `require_mfa` on admin routes, and the dashboard needs admin + 2FA. |
| 4.3.3 | Step-up or adaptive authentication | Pro | Risk-based step-up: medium risk needs a session that passed 2FA, and high risk is blocked. |

## V5 Validation, sanitization and encoding

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 5.1.1 | HTTP parameter pollution | Helps | The WAF inspects every value of repeated parameters, and the schema validator rejects unexpected parameters. |
| 5.1.2 | Mass assignment | Met | Schema validation rejects fields the API spec doesn't allow (`additionalProperties: false`). |
| 5.1.3 | Positive (allow-list) input validation | Met | OpenAPI schema validation on the APIs it covers (types, formats, lengths, patterns). |
| 5.1.4 | Structured data strongly typed and validated against a schema | Met | Same. |
| 5.3.3 | Output escaping against XSS | Helps | The WAF and the ML model block XSS payloads on the way in. Escaping output is the app's job. |
| 5.3.4 | Parameterised database queries | Helps | SQL injection is blocked by the WAF and the ML model, and was tested with sqlmap (`docs/evaluation.md`). Sentinel's own database access is parameterised. |
| 5.3.7 | LDAP injection | Helps | ML model (LDAP family in training). |
| 5.3.8 | OS command injection | Helps | WAF rule CMDI-001 and the ML model. |
| 5.3.9 | Local/remote file inclusion | Helps | WAF rules LFI-001/002 and NULL-001, and the ML model. |
| 5.3.10 | XPath/XML injection | Helps | ML model (XXE family). |

## V7 Logging and error handling

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 7.1.1 | No credentials or payment details in logs | Met | Passwords, tokens and 2FA codes are never logged. Login failures log only the username. |
| 7.1.3 | Security events logged (auth success and failure, access control failures) | Met | One access-log line per request, with Sentinel's decision: attacks, refusals, bans, dashboard logins and dashboard actions. |
| 7.1.4 | Enough detail to investigate | Met | Time, request ID, client IP and country, rule, field, reason and matched text. |
| 7.2.1 | All authentication decisions logged | Met | `login`, `login_failed`, `mfa_required`, `mfa_ok`, `mfa_failed`. |
| 7.2.2 | All access control decisions can be logged | Met | Every request's outcome is logged. |
| 7.3.1 | Encoding prevents log injection | Met | Structured JSON logs (`log/slog`). |
| 7.3.3 | Security logs protected from modification | Pro | Hash-chained audit log with an anchor outside the file, so editing, deleting, reordering or cutting off the end is detected. |
| 7.4.1 | Generic error messages | Met | Blocked requests get a generic message and a request ID. The rule that fired is only in the log. |

## V9 Communication

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 9.1.1 | TLS for all client connections | Partly | HTTPS listener (`TLS_LISTEN_ADDR`). The plain HTTP port is still open for the lab, so in production either turn it off or put a TLS proxy in front. |
| 9.1.3 | Only recent TLS versions | Met | TLS 1.2 minimum. |
| 9.2.1 | Only trusted certificates, specific CAs for internal ones | Pro | mTLS trusts only the configured client CA. |
| 9.2.2 | Encrypt all server connections | Partly | Connections to the apps, PostgreSQL and Redis are plain inside the Docker network. |

## V11 Business logic

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 11.1.2 | Steps processed in realistic human time | Helps | Rate limits per user or IP. |
| 11.1.4 | Anti-automation against excessive calls and mass exfiltration | Met | Rate limits per path prefix, counted per user when logged in, with `429` and `Retry-After`. |
| 11.1.7 | Monitor unusual activity | Met | Attack-burst and password-guessing alerts, the live console and the dashboard. |
| 11.1.8 | Alerting on automated attacks | Partly | The dashboard and live window show attacks as they happen. There are no push alerts (email, chat) yet. |

## V13 API and web services

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 13.1.3 | API URLs don't expose secrets | Met | Tokens are only accepted in the `Authorization` header, and the dashboard never puts them in URLs. |
| 13.1.4 | Authorization at URI and resource level | Pro | Access policies on path patterns with `{username}` owner checks. |
| 13.1.5 | Unexpected content types rejected | Partly | The schema validator checks bodies on the APIs it covers. Other routes pass through. |
| 13.2.1 | Enabled HTTP methods valid for the user and action | Partly | Unknown endpoints and methods are rejected by the schema validator (with an OpenAPI spec). Per-user method rules are in Pro. |
| 13.2.2 | JSON schema validation before accepting input | Met | OpenAPI validation. |
| 13.2.5 | Content-Type checked | Partly | See 13.1.5. |

## V14 Configuration

| ASVS | Requirement (summary) | Status | How Sentinel meets it |
|---|---|---|---|
| 14.1.1 | Secure, repeatable automated build and deployment | Met | GitHub Actions CI on every push, and a release workflow on version tags. |
| 14.1.5 | Integrity of security-relevant configuration can be verified | Partly | Configuration is in git. The dashboard shows the running configuration. |
| 14.2.1 | Components up to date, dependency checker in the build | Met | `govulncheck` in CI and the release, and Grype scans the image SBOM (the release fails on critical findings). |
| 14.2.4 | Components from trusted repositories | Met | Go modules from the official repositories, vendored and checksummed (`go.sum`). Base images are official (`golang`, distroless). |
| 14.2.5 | Software Bill of Materials | Met | The release publishes an SPDX SBOM for every image (`docs/supply-chain.md`). |
| 14.2.6 | Third-party libraries sandboxed or encapsulated | Partly | Only two direct Go dependencies (pgx, x/crypto). The runtime image is distroless, non-root, with no shell. |
| 14.4.4 | `X-Content-Type-Options: nosniff` | Met | Added to every response the app didn't set it on (`SECURITY_HEADERS`). |
| 14.4.5 | `Strict-Transport-Security` | Met | On HTTPS responses. |
| 14.4.6 | Suitable `Referrer-Policy` | Met | `strict-origin-when-cross-origin` unless the app sets one. |
| 14.4.7 | No framing by third-party sites | Met | `X-Frame-Options: SAMEORIGIN` unless the app sets one. The dashboard uses `DENY` and CSP `frame-ancestors 'none'`. |
| 14.4.3 | Content Security Policy | Partly | The dashboard has a strict CSP. CSP for the protected app depends on the app's own scripts, so it's the app's job. |
| 14.5.1 | Only the HTTP methods the app uses | Met | The schema validator rejects methods the API spec does not list. |
| 14.5.4 | Headers added by trusted proxies are authenticated | Met | `X-Forwarded-For` is only believed from `TRUSTED_PROXIES`, and identity headers are always overwritten. |

## Known gaps (roadmap)

- No self-service password change or password policy (2.1.x). No breached-password check (2.1.7).
- TLS between Sentinel and the apps, PostgreSQL and Redis (9.2.2).
- Push alerts for attacks (11.1.8).
