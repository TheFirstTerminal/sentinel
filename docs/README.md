# Sentinel documents

The guide for each version lives here, next to its code, and is updated
with every release.

| File | For | What it is |
|---|---|---|
| [`configuration.md`](configuration.md) | Whoever runs Sentinel | Every setting |
| [`benchmarks.md`](benchmarks.md) | Everyone | Detection per layer (including CSIC 2010), speed |
| [`ml-report.md`](ml-report.md) | Everyone | How well the ML classifier does: test data, evasion test, example explanations |
| [`evaluation.md`](evaluation.md) | Everyone | Attacking the lab from outside (replay, overhead, sqlmap) and what it found |
| [`asvs.md`](asvs.md) | Everyone | Sentinel mapped to OWASP ASVS 4.0.3, including the gaps |
| [`supply-chain.md`](supply-chain.md) | Whoever releases or installs Sentinel | SBOM, vulnerability scans, signatures, how to verify |
| [`../SECURITY.md`](../SECURITY.md) | Everyone | How to report a security problem privately |

## Updating your copy

```bash
bash lab/update.sh
```

Pulls the latest version and restarts the lab. See [`CHANGELOG.md`](../CHANGELOG.md)
for what changed. Questions and bug reports: [GitHub issues](https://github.com/tsxmamii/sentinel/issues).
Security problems: see [`SECURITY.md`](../SECURITY.md), not a public issue.
