# Sentinel benchmarks

Made with `sentinel bench` (version 0.12.0) on 2026-11-14, in Docker on a Windows laptop limited to 2 CPU cores (go1.26.11, linux/amd64). With ML on, the gateway's second opinion on borderline Core Rule Set detections (`waf.second_opinion`) is applied, as in production. Run it yourself to get numbers for your hardware.

## 1. Detection

3000 generated attacks from 24 families, the same attacks rewritten with evasion techniques (encodings, comments, case, whitespace and quote tricks), and 3000 normal inputs (searches, names, reviews, Arabic text, passwords, JSON...). Each is sent as a search parameter with ordinary browser headers. Data: `internal/ml/dataset` (seed 2, which the ML model was not trained on).

| Layers | Attacks caught | Evasion variants caught | Normal input wrongly flagged |
|---|---|---|---|
| Sentinel rules | 67.9% | 65.9% | 0.0% |
| Sentinel rules + ML | 99.7% | 99.6% | 0.0% |
| Sentinel rules + OWASP CRS | 94.9% | 86.9% | 0.5% |
| Sentinel rules + OWASP CRS + ML | 99.8% | 99.8% | 0.0% |

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

## 1c. Against other self-hosted WAFs (open-appsec dataset)

The open-source [WAF comparison project](https://github.com/openappsec/waf-comparison-project)
sends real-world normal traffic (recorded while browsing real sites) and public
attack payloads to each WAF and records what is blocked. Run in fast mode (a
fixed ~15% sample), each WAF in Docker in front of the same app, default
settings, blocking mode, November 2026.

Since 0.16.3 Sentinel's ML model learns normal input from the recorded
sessions of **half** of the dataset's sites. So the table counts normal
traffic only on the **other half** (318 sites, 85,207 requests) that the model
never saw, for every WAF. Attacks: all 11,054.

| WAF | Attacks blocked | Normal requests wrongly blocked | Balanced accuracy |
|---|---|---|---|
| **Sentinel 0.17.6** | **99.97%** | **2.0%** | **99.0%** |
| Sentinel 0.17.5 | 99.9% | 2.0% | 99.0% |
| Sentinel 0.17.1 | 99.9% | 2.2% | 98.8% |
| Sentinel 0.17.0 | 99.9% | 2.5% | 98.7% |
| Sentinel 0.16.4 | 95.4% | 4.4% | 95.5% |
| Sentinel 0.16.3 | 93.4% | 4.4% | 94.5% |
| Sentinel 0.16.1 | 95.0% | 7.5% | 93.7% |
| Sentinel 0.16.0 | 85.3% | 14.6% (all sites) | 85.4% |
| ModSecurity + OWASP CRS (PL1) | 90.3% | 26.7% | 81.8% |
| BunkerWeb | 90.3% | 28.8% | 80.8% |

Sentinel blocks more attacks than both and wrongly blocks about 1 normal
request in 45, against more than 1 in 4 for the others. From 0.16.0 on, every
false alarm was traced to the rule or model input behind it (tracking cookies,
analytics beacons, GraphQL, binary bodies) and fixed. Those rule fixes were
found on this dataset, so treat the gap as an upper bound; they are general
(no rule names a site). 0.16.3 traded 1.6 points of attacks for 40% fewer
false alarms; 0.16.4 won them back with a rule for traversal payloads that
disguise their slashes (LFI-004), which wrongly blocks none of the normal
requests. 0.17.0 cut false alarms by 43% by tracing the rest on the half of
the sites not counted here, then checked the result on this half. Its attack
number is less independent: LFI-004 was widened using this dataset's missed
traversal payloads (broken and `%u`-encoded separators), and that accounts
for most of the jump to 99.9%. Expect a lower number on attacks you write
yourself. 0.17.1 and 0.17.5 took false alarms from 2.5% to 2.0% the same way (tuned on
the uncounted half only) and blocks the same attacks. The normal traffic here includes many unusual requests, so all
numbers are worse than on a typical site; start in monitor mode and check the
dashboard before blocking.

### GoTestWAF

[GoTestWAF](https://github.com/wallarm/gotestwaf), same setup:

| WAF | Attacks blocked | Normal requests allowed |
|---|---|---|
| Sentinel 0.15.0 | 51.3% | 95.7% |
| **Sentinel 0.16.0** | **84.9%** | 95.0% |
| ModSecurity + OWASP CRS (PL1) | 48.6% | 90.8% |

## 2. Speed

A real HTTP server (the "app", answering with a small JSON document) and Sentinel in front of it, both on this machine. Clients send a mix of ordinary requests: a search with browser headers and cookies, a JSON POST, and a static file. Every check that applies runs (rate-limit counting, WAF, ML, response leak checks); logs go nowhere.

### Latency: one client, one request at a time

What a single user feels.

| Setup | Median | p95 | p99 | Added by Sentinel (median) |
|---|---|---|---|---|
| App directly | 0.18 ms | 0.28 ms | 0.41 ms | |
| Through Sentinel: rules + ML | 0.62 ms | 1.03 ms | 1.34 ms | 0.43 ms |
| Through Sentinel: rules + OWASP CRS + ML | 1.79 ms | 2.46 ms | 3.05 ms | 1.60 ms |

### Throughput: 32 clients at once

The most requests per second this machine handles. The load generator shares the CPU with Sentinel and the app, so a dedicated server does better; compare the rows.

| Setup | Requests/s | Median | p99 |
|---|---|---|---|
| App directly | 33250 | 0.84 ms | 3.52 ms |
| Through Sentinel: rules + ML | 5594 | 5.17 ms | 15.29 ms |
| Through Sentinel: rules + OWASP CRS + ML | 1496 | 20.21 ms | 46.86 ms |
