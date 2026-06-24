# ADR-018: Build Provenance & Keyless Signing for Releases

Date: 2026-06-22

## Status

Accepted

## Context

[ADR-014](ADR-014-base-image-digest-pinning.md) and
[ADR-015](ADR-015-sha-pin-github-actions.md) closed the *inbound* supply-chain
gaps (what we build *from*). The *outbound* side was still unprotected: the
images on `ghcr.io` and the `shdg` binaries on the GitHub release had no
cryptographic provenance. A consumer pulling `shieldoo-gate:1.2.3` could not
verify it was built by this repo's CI from this repo's source, rather than
pushed by a leaked token or a typosquatted registry. For a supply-chain
*security* tool this is the credibility-critical gap, and it is the OpenSSF
Scorecard `Signed-Releases` check (T7 of the security-hardening plan).

## Decision

The release pipeline (`release.yml`) signs and attests every published artifact
using **keyless Sigstore** — Fulcio short-lived certs minted from the GitHub
Actions OIDC token, with the signature/attestation recorded in the Rekor
transparency log. No long-lived signing key is stored or managed.

1. **Images** (`shieldoo-gate`, `scanner-bridge`):
   - `docker/build-push-action` builds with `provenance: mode=max` and
     `sbom: true`, so BuildKit attaches an in-toto SLSA provenance attestation
     and a CycloneDX SBOM as OCI referrers on the pushed image.
   - `actions/attest-build-provenance` records a GitHub-hosted SLSA provenance
     attestation keyed on the pushed **index digest**, also pushed to the
     registry (`push-to-registry: true`).
   - `cosign sign` produces a keyless signature, **by digest, never by tag** —
     a tag can be re-pointed, the digest cannot.

2. **`shdg` binaries** (5 OS/arch archives): one
   `actions/attest-build-provenance` attestation covering all archives
   (`subject-path` glob).

3. **Dogfooded SBOMs**: the CycloneDX SBOMs that the release already uploads to
   the production gate are now persisted via `shdg scan --sbom-output`
   (see the `shdg` CLI), attached to the GitHub release (`*.cdx.json`), folded
   into `SHA256SUMS`, and individually signed with `cosign sign-blob --bundle`.
   Signing the *same bytes* the gate ingested means the published SBOM is the
   dogfooded one, not a re-generated approximation.

4. **Scorecard-compatible release assets** (added after initial rollout): the
   OpenSSF `Signed-Releases` check this ADR targets only inspects GitHub
   release *assets* and matches on filename suffix — it does not query ghcr OCI
   referrers, the GitHub attestations API, or recognise the `.cosign.bundle`
   extension. The Sigstore-native assets above are therefore invisible to it,
   leaving the check scored 0. To close that gap **without dropping the modern
   formats**, the release job additionally publishes:
   - a detached `<archive>.sig` + `<archive>.pem` per `shdg` archive and for
     `SHA256SUMS` (suffix `.sig` is on Scorecard's signature whitelist), and
   - the binary SLSA provenance bundle republished as `shdg-<ver>.intoto.jsonl`
     (the suffix Scorecard reads as provenance).

   These carry the *same* keyless Sigstore material as the bundle/referrer
   assets — only the filename/extension differs, so both old- and new-style
   verification work against the same release.

Permissions follow least-privilege: the workflow's top-level floor is
`contents: read`, and each job widens only what it needs
(`packages: write` + `id-token: write` + `attestations: write` on the image
job; `packages: read` on the image-scan job; `contents: write` +
`id-token: write` + `attestations: write` on the release job). New actions are
SHA-pinned per [ADR-015](ADR-015-sha-pin-github-actions.md):
`actions/attest-build-provenance` and `sigstore/cosign-installer`.

### Verification

```bash
# Image: cosign signature
cosign verify ghcr.io/<owner>/shieldoo-gate:<ver> \
  --certificate-identity-regexp 'https://github.com/<owner>/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Image / binary: SLSA provenance
gh attestation verify oci://ghcr.io/<owner>/shieldoo-gate:<ver> --repo <owner>/shieldoo-gate
gh attestation verify shdg-<ver>-linux-amd64.tar.gz --repo <owner>/shieldoo-gate

# SBOM: detached cosign bundle
cosign verify-blob --bundle sbom-gate.cdx.json.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/<owner>/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com sbom-gate.cdx.json

# Binary: detached .sig + .pem (Scorecard-compatible)
cosign verify-blob \
  --signature shdg-<ver>-linux-amd64.tar.gz.sig \
  --certificate shdg-<ver>-linux-amd64.tar.gz.pem \
  --certificate-identity-regexp 'https://github.com/<owner>/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com shdg-<ver>-linux-amd64.tar.gz
```

## Consequences

- Consumers can cryptographically verify that any image or binary originated
  from this repo's CI, keyed to an immutable digest. Fail-closed guards were
  added so the release cannot ship an incomplete `SHA256SUMS` or a signed-but-
  empty SBOM.
- **Single-platform image is published as an index.** With `provenance`/`sbom`
  enabled, BuildKit wraps the `linux/amd64` manifest in an OCI index that also
  carries the attestation manifests under an `unknown/unknown` platform entry.
  `docker pull`/`trivy image` resolve the real platform transparently; the
  `unknown/unknown` entry is expected, not a malformed multi-arch image.
- Keyless signing depends on Sigstore's public-good infrastructure (Fulcio +
  Rekor) being reachable at release time. This is the deliberate trade-off
  against managing a private key; a key-based fallback would be a future ADR.
- **Open follow-up (defense-in-depth):** the dogfooded SBOM is signed as a
  standalone blob, so a verifier cannot yet cryptographically tie
  `sbom-gate.cdx.json` to a specific image digest. The BuildKit `sbom: true`
  referrer *is* digest-bound; binding the dogfooded SBOM to the image digest
  (OCI referrer or in-predicate digest) is tracked as a later enhancement.
