# Supply chain: SBOM, scanning and signatures

Every release (a `v*` tag) is built by GitHub Actions
([`.github/workflows/release.yml`](../.github/workflows/release.yml)), not on
a laptop, so anyone can see exactly how it was made.

## What a release contains

| Item | Where |
|---|---|
| Container image | `ghcr.io/<owner>/sentinel:<version>` (and `:latest`) |
| Binaries (Linux amd64/arm64, Windows, macOS arm64) | GitHub release |
| `checksums.txt` | GitHub release (SHA-256 of every binary) |
| SBOM (SPDX JSON): every package inside the image | GitHub release, and attached to the image once signing is on |
| Build provenance (how and from which commit the image was built) | Attached to the image by Docker Buildx |

## Checks before publishing

1. **govulncheck** checks the Go code and its dependencies for known
   vulnerabilities. It reports only the ones Sentinel actually calls, so it
   doesn't raise false alarms.
2. The **SBOM** is generated from the finished image (Syft).
3. **Grype** scans the SBOM. A critical vulnerability stops the release.

CI also runs govulncheck on every push, as a report.

## Signatures (Sigstore / cosign)

Signing is **keyless**: GitHub Actions proves its identity to Sigstore, gets
a short-lived certificate for "this repository's release workflow", and
signs with it. There are no signing keys to steal or lose.

Signing records the repository name in Sigstore's public transparency log.
So **while the repository is private, the workflow skips signing**. It turns
on by itself when the repository is made public.

### Verifying (once signed)

```bash
# The image was built by this repository's release workflow:
cosign verify ghcr.io/<owner>/sentinel:<version> \
  --certificate-identity-regexp '^https://github.com/<owner>/sentinel/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Its SBOM:
cosign verify-attestation --type spdxjson ghcr.io/<owner>/sentinel:<version> \
  --certificate-identity-regexp '^https://github.com/<owner>/sentinel/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# A downloaded binary:
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/<owner>/sentinel/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksums.txt
```

## Making a release

```bash
git tag -a v0.11.0 -m "Sentinel v0.11.0"
git push origin v0.11.0
```

Then watch the **Actions** tab. The image appears under the organisation's
**Packages**. Packages from a private repository are private too; give
people access in the package's settings.
