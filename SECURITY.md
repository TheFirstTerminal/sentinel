# Security policy

Sentinel is a security tool, so a weakness in it can put the apps behind it
at risk. Thank you for reporting one privately.

## Reporting a vulnerability

**Please don't open a public issue.** Use GitHub's private reporting
instead: on the [Security tab](https://github.com/TheFirstTerminal/sentinel/security),
choose **Report a vulnerability**. Only the maintainer can see the report.

Useful to include:

- the Sentinel version (`sentinel version`) and how it runs (Docker, binary, Helm)
- the setting that matters (e.g. `mode`, `waf_mode`, `ml_mode`, rate limits)
- the request that gets through, or the steps to reproduce
- what happens, and what you expected

A bypass counts: a request that carries an attack Sentinel should stop
(SQL injection, XSS, a known CVE payload...) but lets through in `protect`
mode. Please include the payload.

## What happens next

- You get an answer within **3 days**.
- Confirmed issues are fixed in a new release as soon as possible; the fix
  is credited to you in the changelog unless you'd rather stay anonymous.
- Please give us a reasonable time to release the fix (normally up to 90
  days) before you publish details.

## Supported versions

Only the latest release gets security fixes. Upgrade before reporting if you
can: the problem may already be fixed.

## Not in scope

- Attacks on the deliberately vulnerable apps in `lab/` (Juice Shop is
  meant to be vulnerable; it listens on `127.0.0.1` only).
- Requests that are let through in `monitor` mode: that mode logs and never
  blocks, by design.
- Denial of service by sheer traffic volume (network-level DDoS is out of
  Sentinel's scope).
