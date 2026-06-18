# Security Policy

## Supported Versions

Shieldoo Gate is pre-1.0. Security fixes land on `main` and the next tagged
release. Older releases are not patched — upgrade to the latest release.

## Reporting a Vulnerability

**Do not open a public issue, PR, or discussion for a security vulnerability.**

Report it privately through **GitHub Private Vulnerability Reporting**: open the
[Security tab](https://github.com/cloudfieldcz/shieldoo-gate/security) and click
**"Report a vulnerability"**. This is our only intake channel — we do not run a
security email alias.

Please include the affected component/version, impact, and reproduction steps.

## Our Commitment

- **Initial acknowledgement:** within 5 business days.
- **Coordinated disclosure:** we aim to ship a fix and publish a GitHub Security
  Advisory within 90 days, and will credit you with your consent.

Please give us up to 90 days before any public disclosure.

## Safe Harbor

We consider good-faith security research conducted under this policy to be
authorized and will not pursue legal action for it. In return, please avoid
privacy violations, data destruction, and service disruption (no DoS), and only
test against this repository's code or your own deployment — never a public or
third-party instance you do not own.

## Scope

In scope: this repository's source code and the official container images built
from it. Out of scope: third-party dependencies (report upstream), deployments
you do not own, and findings that require an already-privileged position.
