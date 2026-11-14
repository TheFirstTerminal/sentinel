# Evaluation

How well does Sentinel protect an app against real attacks, and what does it
cost? `bash lab/evaluate.sh` measures it from the outside, the way an
attacker would see it:

1. **Attack replay.** Thousands of attacks from 24 families are sent straight to the
   app and through Sentinel, each one also rewritten with evasion
   techniques, plus the same amount of normal input. The attacks are
   generated with a different seed than the ML model was trained on.
2. **Overhead.** The response time of normal requests, direct and through
   Sentinel.
3. **sqlmap.** A widely used real attack tool tries to find and exploit
   the SQL injection in Juice Shop's search, directly, through Sentinel, and
   through Sentinel with its evasion ("tamper") scripts.

The run takes about 10 minutes and writes `eval-results/evaluation.md`.
Afterwards choose **R** in the demo menu to reset the lab.

The ML model's own test (generated data and evasion rewrites, without
HTTP) is in [`ml-report.md`](ml-report.md).

## What the first run found

The first sqlmap run on the development machine **got through**. sqlmap
found a boolean-blind SQL injection with this payload:

```
apple%' AND CASE WHEN 5180=5180 THEN 5180 ELSE JSON(CHAR(86,109,68,105)) END AND 'NwRX%'='NwRX
```

No WAF rule matched it. The ML model scored it 0.1%, because it had never
seen attacks that start with a normal search word followed by `%'` (a LIKE
wildcard and a quote). The same happened with sqlmap's `between` tamper
script (`... AND 8627 BETWEEN 8627 AND 8627-- Xaan`). The fixes:

- New WAF rules **SQLI-008** (CASE WHEN ... THEN), **SQLI-009** (`AND 'abc'='abc`
  probes), **SQLI-010** (BETWEEN after a quote) and **SQLI-011** (strings built with
  `CHAR(65,66,...)`).
- A new training family for the ML model, `sqli-sqlmap`. Existing SQL injection
  families now sometimes start with a normal word. Both payloads now score
  above 99%.

This is what evaluating with real tools is for.

## Development run (after the fixes)

> Run on the development machine against a **stand-in shop**: a small SQLite
> app whose search has the same flaw as Juice Shop's, not the real lab. The
> overhead numbers are from that machine too. Run `bash lab/evaluate.sh`
> for numbers from the real lab.

Run 2026-11-09 19:59 against `http://localhost:3998` (direct) and `http://localhost:8098` (through Sentinel), payloads sent to `/rest/products/search?q=`.

The replay uses generated attacks (a different seed than the ML model was trained on) and the same attacks rewritten with evasion techniques. Section 3, if present, is from sqlmap, a real attack tool.

### 1. Attack replay

3000 requests in 14s. "Stopped" means Sentinel refused the request (400, 401, 403, 429 or 502), so the app never saw it.

| Traffic | Sent | Stopped by Sentinel |
|---|---|---|
| Attacks | 500 | **99.8% (499/500)** |
| Attacks rewritten to evade filters | 500 | **96.6% (483/500)** |
| Normal input (should pass) | 500 | **0.0% (0/500)** wrongly stopped |

#### Per attack family

| Family | Sent | Stopped |
|---|---|---|
| cmdi | 21 | 95.2% (20/21) |
| crlf | 28 | 100.0% (28/28) |
| file-uri | 15 | 100.0% (15/15) |
| jndi | 25 | 100.0% (25/25) |
| ldap | 27 | 100.0% (27/27) |
| nosqli | 32 | 100.0% (32/32) |
| sqli-blind | 19 | 100.0% (19/19) |
| sqli-error | 13 | 100.0% (13/13) |
| sqli-orderby | 13 | 100.0% (13/13) |
| sqli-schema | 25 | 100.0% (25/25) |
| sqli-sqlmap | 19 | 100.0% (19/19) |
| sqli-stacked | 15 | 100.0% (15/15) |
| sqli-tautology | 21 | 100.0% (21/21) |
| sqli-time | 20 | 100.0% (20/20) |
| sqli-union | 18 | 100.0% (18/18) |
| sqli-waitfor | 29 | 100.0% (29/29) |
| ssrf | 23 | 100.0% (23/23) |
| ssti | 21 | 100.0% (21/21) |
| traversal | 21 | 100.0% (21/21) |
| xss-event | 24 | 100.0% (24/24) |
| xss-script | 16 | 100.0% (16/16) |
| xss-template | 18 | 100.0% (18/18) |
| xss-uri | 18 | 100.0% (18/18) |
| xxe | 19 | 100.0% (19/19) |

Attacks that got through (examples):

- ` %0aid`

Evasion variants that got through (examples):

- `%2525252Fproc%2525252Fself%2525252Fcmdline`
- `&LT;?xMl VeRSiON=&qUOT;1.0&QUot;?&Gt;&LT;!Doctype fOO [&lt;!EnTitY xxe SYstem &QuOT;FilE:////*!50000etC*///*!5...`
- `%25252522%2525252F%2525252A%2525252A%2525252For%25252509cast%25252528%25252528select%25252Bhash%25252Bfrom%252...`
- `%25252522%2525253E%2525253Cscript%25252Btype%25252Blike%25252Btext%2525252Fjavascript%2525253Ealert%252525281%...`
- `%25252Fvar%25252Fwww%25252F..%252525252f..%252525252f..%252525252f..%252525252f..%252525252fconfig%25252Fdatab...`

### 2. Time Sentinel adds

300 normal searches, one at a time, to each.

| | median | 95th percentile | 99th percentile |
|---|---|---|---|
| Direct | 0.7 ms | 0.9 ms | 1.5 ms |
| Through Sentinel | 1.4 ms | 2.4 ms | 3.0 ms |

### 3. sqlmap

sqlmap looks for SQL injection in the shop's search (`/rest/products/search?q=apple`). "Found" means it confirmed the database can be attacked.

| Target | Found an injection | Requests |
|---|---|---|
| direct (no protection) | **yes** | 54 HTTP(s) requests |
| through Sentinel | no (sqlmap noticed a WAF/IPS) | ? |
| through Sentinel, with evasion (tamper scripts) | no (sqlmap noticed a WAF/IPS) | ? |


Many of the "got through" examples are encoded four or five times. Sentinel
decodes up to four layers. An app decodes only one, so such a payload
reaches the app still encoded and harmless. These examples aren't real
bypasses.
