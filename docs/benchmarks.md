# Sentinel benchmarks

Made with `sentinel bench` (version 0.11.0) on 2026-11-14, in Docker on a Windows laptop limited to 2 CPU cores (go1.24.13, linux/amd64). Run it yourself to get numbers for your hardware.

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
| App directly | 0.21 ms | 0.37 ms | 0.53 ms | |
| Through Sentinel: rules + ML | 0.98 ms | 1.63 ms | 1.99 ms | 0.78 ms |
| Through Sentinel: rules + OWASP CRS + ML | 2.69 ms | 4.70 ms | 7.00 ms | 2.48 ms |

### Throughput: 32 clients at once

The most requests per second this machine handles. The load generator shares the CPU with Sentinel and the app, so a dedicated server does better; compare the rows.

| Setup | Requests/s | Median | p99 |
|---|---|---|---|
| App directly | 12852 | 0.42 ms | 74.70 ms |
| Through Sentinel: rules + ML | 3169 | 2.27 ms | 81.37 ms |
| Through Sentinel: rules + OWASP CRS + ML | 861 | 11.73 ms | 105.10 ms |
