# Community Threat Feed Contributions Portal

> A web portal and API for submitting, reviewing, and publishing reports of malicious packages to the community threat feed.

**Status:** Planned (v1.2+)
**Origin:** Initial analysis roadmap, section 15

## Problem

Shieldoo Gate consumes a community threat feed (`https://feed.shieldoo.io/malicious-packages.json`) for fast-path blocking of known-malicious packages. Currently, there is no structured way for community members to submit new malicious package reports. Reports come in ad-hoc via GitHub issues, and feed updates require manual curation.

## Proposed Solution

Build a contributions portal that enables community members to submit malicious package reports with evidence, moderators to review and approve them, and the feed to be automatically updated.

### Key Requirements

1. **Submission API:**
   - `POST /api/v1/feed/submit` — submit a new malicious package report
   - Required fields: ecosystem, package name, version(s), evidence (description, IoCs, reproduction steps)
   - Optional: SHA-256 hash, source URL, CVE references
   - Submissions go into a `PENDING` review queue

2. **Review workflow:**
   - Moderators (authenticated via OIDC) can view, approve, or reject submissions
   - Approved submissions are automatically added to the threat feed
   - Rejected submissions are archived with a reason
   - Two-reviewer requirement for CRITICAL severity entries

3. **Feed publishing:**
   - The threat feed JSON file is regenerated on approval
   - Signed with a GPG key or cosign for integrity verification
   - Published to a CDN or static hosting (GitHub Pages, S3 static website)
   - Consumers can verify the signature before applying updates

4. **OSV format compatibility:** All entries follow the [OSV schema](https://ossf.github.io/osv-schema/) for interoperability with other vulnerability databases.

5. **Portal UI:**
   - Public submission form (with anti-spam measures)
   - Moderator dashboard showing pending submissions
   - Feed browser — searchable list of all published entries
   - Submission status tracker for reporters

### How It Fits Into the Architecture

This is largely a **separate service** rather than part of the core Shieldoo Gate proxy:

- **Separate repository:** `github.com/shieldoo/threat-feed` (as mentioned in the original spec, section 16)
- **Shared schema:** The feed JSON format is already defined and consumed by Shieldoo Gate's `threatfeed.Client`
- **Integration point:** The feed URL configured in `threat_feed.url` points to the published feed. No changes needed in the core proxy — it already consumes the feed.

Optional deeper integration with Shieldoo Gate:

- **Auto-submit:** When Shieldoo Gate quarantines an artifact with high-confidence findings from multiple scanners, offer to auto-submit a report to the community feed (with admin approval).
- **Feedback loop:** When a Shieldoo Gate instance blocks a package that matches a feed entry, send an anonymized "confirmation" ping to the feed service. This helps gauge the feed's real-world impact.

### Considerations

- **Abuse prevention:** The submission API must be rate-limited and require some form of authentication (GitHub OAuth, email verification) to prevent spam and false reports.
- **Responsible disclosure:** Some malicious package reports may involve active exploits. The portal should support an embargo period where entries are visible only to verified Shieldoo Gate instances before public disclosure.
- **Legal:** Publishing a feed that names specific packages as "malicious" has legal implications. Clear criteria, evidence requirements, and a dispute/appeal process are necessary.
- **Data quality:** The feed's value depends on accuracy. False positives in the feed would cause widespread breakage across all consuming Shieldoo Gate instances. The two-reviewer requirement for critical entries helps mitigate this.
- **Decentralization:** Consider supporting multiple feed sources (official + third-party) in Shieldoo Gate's `threat_feed` config, so organizations can run private feeds alongside the public one.
