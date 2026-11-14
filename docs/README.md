# Sentinel documents

The latest version of every guide lives here, next to the code. When S
publishes a new version, these files are updated at the same time.

| File | For | What it is |
|---|---|---|
| [`configuration.md`](configuration.md) | Whoever runs Sentinel | Every setting |
| [`benchmarks.md`](benchmarks.md) | Everyone | Detection per layer (including CSIC 2010), speed |
| [`ml-report.md`](ml-report.md) | Everyone | How well the ML classifier does: test data, evasion test, example explanations |
| [`evaluation.md`](evaluation.md) | Everyone | Attacking the lab from outside (replay, overhead, sqlmap) and what it found |
| [`asvs.md`](asvs.md) | Everyone | Sentinel mapped to OWASP ASVS 4.0.3, including the gaps |
| [`supply-chain.md`](supply-chain.md) | Whoever releases or installs Sentinel | SBOM, vulnerability scans, signatures, how to verify |

## Updating your copy

```bash
bash lab/update.sh
```

Pulls the latest version and restarts the lab. See [`CHANGELOG.md`](../CHANGELOG.md)
for what changed. Only S edits and pushes; everyone else only pulls, so
nothing conflicts. Any problem: talk to S.
