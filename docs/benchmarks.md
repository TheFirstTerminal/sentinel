# Sentinel benchmarks

Made with `sentinel bench` (version 0.9.0) on 2026-11-11: 2 CPU cores, go1.24.7, linux/amd64. Run it yourself to get numbers for your hardware.

## 1. Detection

3000 generated attacks from 24 families, the same attacks rewritten with evasion techniques (encodings, comments, case, whitespace and quote tricks), and 3000 normal inputs (searches, names, reviews, Arabic text, passwords, JSON...). Each is sent as a search parameter with ordinary browser headers. Data: `internal/ml/dataset` (seed 2, which the ML model was not trained on).

| Layers | Attacks caught | Evasion variants caught | Normal input wrongly flagged |
|---|---|---|---|
| Sentinel rules | 67.9% | 65.9% | 0.0% |
| Sentinel rules + ML | 99.7% | 99.6% | 0.0% |
| Sentinel rules + OWASP CRS | 94.9% | 86.9% | 0.5% |
| Sentinel rules + OWASP CRS + ML | 99.8% | 99.8% | 0.5% |

The data is generated, so treat these as a comparison between layers, not a promise for real traffic. That is why new installs start in monitor mode.

## 1b. CSIC 2010

The HTTP dataset CSIC 2010 (Spanish National Research Council): 36,000 normal
and 25,065 anomalous requests to an e-shop. Most of its "attacks" are
parameter tampering with no attack syntax at all (a letter in a phone number,
an over-long surname), which signature rules and a syntax-based model are not
built to see. The **app profile** (`APP_PROFILE`) learns each page's
parameters from the dataset's normal *training* file only, then judges the
*test* files:

| Layers | Attacks caught (of 25065) | Normal requests wrongly flagged (of 36000) |
|---|---|---|
| Sentinel rules | 18.1% | 0.00% |
| ML | 14.9% | 0.00% |
| Sentinel rules + ML | 19.6% | 0.00% |
| Sentinel rules + OWASP CRS | 29.7% | 0.01% |
| Sentinel rules + OWASP CRS + ML | 30.8% | 0.01% |
| App profile (anomaly detection) | 96.6% | 0.01% |
| Sentinel rules + ML + app profile | 96.6% | 0.01% |
| All: rules + CRS + ML + app profile | 98.2% | 0.02% |

The ML model was not retrained on CSIC: mixing it in made the model worse on
real attack syntax. Reproduce with
`go run ./cmd/csiceval -csic <folder with the three CSIC files> -crs <coreruleset/rules>`.

## 2. Speed

A real HTTP server (the "app", answering with a small JSON document) and Sentinel in front of it, both on this machine. Clients send a mix of ordinary requests: a search with browser headers and cookies, a JSON POST, and a static file. Every check that applies runs (rate-limit counting, WAF, ML, response leak checks); logs go nowhere.

### Latency: one client, one request at a time

What a single user feels.

| Setup | Median | p95 | p99 | Added by Sentinel (median) |
|---|---|---|---|---|
| App directly | 0.03 ms | 0.09 ms | 0.14 ms | |
| Through Sentinel: rules + ML | 0.28 ms | 0.58 ms | 0.78 ms | 0.24 ms |
| Through Sentinel: rules + OWASP CRS + ML | 1.47 ms | 2.39 ms | 3.57 ms | 1.43 ms |

### Throughput: 32 clients at once

The most requests per second this machine handles. The load generator shares the CPU with Sentinel and the app, so a dedicated server does better; compare the rows.

| Setup | Requests/s | Median | p99 |
|---|---|---|---|
| App directly | 40945 | 0.66 ms | 4.74 ms |
| Through Sentinel: rules + ML | 6452 | 4.29 ms | 15.15 ms |
| Through Sentinel: rules + OWASP CRS + ML | 1468 | 20.68 ms | 48.85 ms |

## 3. OWASP Core Rule Set compatibility

Sentinel runs CRS with its own engine (`gateway/internal/crs`), so CRS's own
regression suite is the fairest test of it. CI clones CRS v4.8.0 and replays
every request test (about 3,800) through the engine on every push.

| | Result |
|---|---|
| CRS request rules loaded | 405 of 405 (none skipped) |
| Regression tests passed | **3,765 of 3,794 (99.2%)** |
| Requests Go's HTTP server rejects before any check (e.g. HTTP/3.0 on a TCP socket) | 6 |

Of the 29 that differ, 7 are expected: 5 need argument-length limits that
`crs-setup.conf` leaves off by default, and 2 test the blocking-evaluation
rule 949110, whose job Sentinel does itself. The other 22 are edge cases
(mostly in PHP and Java detection at higher paranoia levels); run the suite
with `CRS_SHOW_FAILURES=1` to list them.

Three places where Sentinel deliberately differs from ModSecurity:

- **`%uXXXX` decoding keeps the character.** ModSecurity keeps only the low
  byte, which turns Arabic "ا" (U+0627) into an apostrophe and makes ordinary
  Arabic text look like SQL injection. Sentinel decodes it to the real
  character (fullwidth ASCII still becomes ASCII).
- **Arguments containing `;` are inspected.** Go's own parser drops them; a
  WAF built on it would let a payload hide behind a semicolon.
- **Rule 920220 is off by default** (`CRS_EXCLUDE`): it flags any literal `%`
  ("50% off"), and Sentinel's normalizer already handles repeated encoding.
  Excluding it took false alarms on the data above from 2.5% to 0.5% and cost
  0.2 points of detection.

## 4. How the speed was achieved

- **Literal prefilters.** Go's regex engine has no DFA, so a CRS rule with
  hundreds of alternatives is slow even when it doesn't match. From each
  pattern's syntax tree Sentinel works out strings, or punctuation, of which
  every match must contain one, and skips the regex when a value has none
  (the idea behind RE2's FilteredRE2). It never skips a regex that would
  match: the CRS suite passes identically with and without it, and a test
  checks it on random inputs.
- **Shared work.** Transformation chains and variable lists that many CRS
  rules have in common are computed once per request.
- **Allocation-free ML scoring.** Features are hashed in place; the
  explanation data is only built for flagged requests. A test checks the
  fast path gives exactly the same score.
- **Matching before capturing.** Captures are only extracted after a match.
- **One pass for phrase lists.** CRS's `@pm` lists (hundreds of file names,
  commands and keywords) are matched with Aho-Corasick, in one pass over the
  value instead of one search per phrase.

CRS still costs about 1.2 ms per request on this machine, mostly in
rules that can legitimately match plain words (Unix command names), which no
prefilter may skip. Turn it off with `CRS_DIR=off` when every millisecond
matters; Sentinel's own rules plus ML catch nearly as much on this data.

## Reproduce

```bash
cd gateway
go run ./cmd/sentinel bench --crs /path/to/coreruleset/rules --out ../docs/benchmarks.md
CRS_TEST_DIR=/path/to/coreruleset/rules go test -v -run TestCRSRegressionSuite ./internal/crs/
```
