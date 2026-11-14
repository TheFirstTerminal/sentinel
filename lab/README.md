# Sentinel quick demo

Sentinel in front of OWASP Juice Shop, a deliberately vulnerable shop. Two
containers, about two minutes to start. Needs Docker (and Git Bash on
Windows).

```bash
bash lab/start.sh       # or double-click "Start Sentinel.bat" on Windows
```

| Address | What |
|---|---|
| http://localhost:3000 | Juice Shop directly (unprotected) |
| http://localhost:8080 | Juice Shop through Sentinel |
| http://localhost:9000 | Sentinel's dashboard, with the live Console |

The menu sends five attacks (SQL injection, a login bypass, XSS, Log4Shell
and one only the ML model catches) to the shop directly and then through
Sentinel. Open the dashboard first (**L** prints the one-time link to create
the admin account, **D** opens it) and watch each decision appear in the
Console, with the rule, the field and the text that triggered it.

| Script | What it does |
|---|---|
| `start.sh` | Start the demo and open the menu |
| `demo.sh` | The attack menu |
| `watch.sh` | Sentinel's decisions in a terminal instead of the dashboard |
| `evaluate.sh` | Replay thousands of attacks and run sqlmap, with and without Sentinel (~10 min): `eval-results/evaluation.md` |
| `update.sh` | Pull the latest version and restart |

```bash
docker compose down -v     # stop and wipe (the admin account too)
```

The ports listen on `127.0.0.1` only, so the vulnerable shop is never
reachable from your network. To protect your own app, see
[`deploy/`](../deploy/README.md).
