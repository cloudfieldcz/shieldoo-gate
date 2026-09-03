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

Resolving a tag to its commit SHA:

```
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.sha'
```

**This alone is only correct for a *lightweight* tag.** A ref of type `tag`
points straight at a commit, so the command above already returns the commit
SHA — e.g. `actions/checkout`'s tags are lightweight, and
`gh api repos/actions/checkout/git/ref/tags/v7.0.1 --jq '.object.sha'` returns
`3d3c42e5aac5ba805825da76410c181273ba90b1`, a commit, ready to pin.

An *annotated* tag inserts an extra Git object between the ref and the commit:
the ref points at a tag object, and the tag object points at the commit. For
those, the command above returns the tag object's SHA, not the commit's — and
that SHA is **not** a valid pin: `uses:` requires a commit, and GitHub Actions
fails a workflow using a tag-object SHA with `unable to resolve action ...
revision not found`. `github/codeql-action` uses annotated tags, so this is
not a corner case — it's the action this repo pins by SHA in every CodeQL
workflow. Concretely, for v4.37.9:

```
$ gh api repos/github/codeql-action/git/ref/tags/v4.37.9 --jq '.object.sha, .object.type'
a35ac6e6798d72df5475948b28efb89edc2e19ca
tag
```

That SHA is the tag object, not the commit — do not pin it. Dereference once
more to reach the commit it points to:

```
$ gh api repos/github/codeql-action/git/tags/a35ac6e6798d72df5475948b28efb89edc2e19ca --jq '.object.sha, .object.type'
cdf488f595d80d6e07e03d4674febd5ab45fa938
commit
```

`cdf488f595d80d6e07e03d4674febd5ab45fa938` is what actually belongs in the
`uses:` pin (and is what this repo's workflows pin for
`github/codeql-action/*@...# v4.37.9`). The `--jq '.object.type'` in both
commands is not decorative: check it before trusting `.object.sha` as a
commit — if it prints `tag`, you have not reached the commit yet and must run
the second command; only `commit` is safe to pin. Do not "simplify" this back
to the single-command form — that form is silently wrong for every annotated
tag, and the failure only surfaces later, in CI, as an unresolvable revision.

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
