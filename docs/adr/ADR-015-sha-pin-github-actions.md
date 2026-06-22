# ADR-015: Pin GitHub Actions by Commit SHA

Date: 2026-06-19

## Status

Accepted

## Context

Workflows previously referenced third-party actions by mutable tag
(`actions/checkout@v4`, `docker/build-push-action@v6`, …). A Git tag is mutable:
the action's maintainer — or an attacker who compromises their account — can
re-point `v4` at new code at any time, and that code runs in our release
pipeline with `contents: write` and `packages: write` (it pushes images to
ghcr.io and creates releases). This is the same tag-mutability supply-chain gap
that [ADR-014](ADR-014-base-image-digest-pinning.md) closes for base images,
applied to CI. It is also the single hardest-weighted control in the OpenSSF
Scorecard `Pinned-Dependencies` check.

## Decision

Every `uses:` reference in `.github/workflows/` is pinned to a full 40-character
commit SHA, with the human-readable version kept as a trailing comment:

```yaml
uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
```

The SHA is authoritative; the comment documents which release it corresponds to.
This is the form GitHub, OpenSSF, and Dependabot all recognise — Dependabot
updates the SHA *and* the comment together when it is eventually enabled. The
release pipeline (`release.yml`) is the only workflow today and the priority
target because of its write scopes; the rule applies to every workflow added
later.

Resolving a tag to its commit SHA (dereferencing annotated tags):

```
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.sha'
```

SHAs are auto-bumped by Dependabot's `github-actions` ecosystem
(`.github/dependabot.yml`, weekly); manual re-resolution remains a fallback.

## Consequences

The release pipeline now runs only reviewed action code; a hijacked upstream tag
can no longer inject steps into a build that pushes signed images. The cost is
the same staleness trade-off as ADR-014: a pinned SHA does not pick up an
action's security fixes until someone re-resolves it. Dependabot's
`github-actions` updater (`.github/dependabot.yml`) now re-resolves SHAs weekly;
manual refresh remains a fallback (at minimum when bumping a major). The trailing
version comment keeps the diff readable and makes a stale pin easy to spot in review.
