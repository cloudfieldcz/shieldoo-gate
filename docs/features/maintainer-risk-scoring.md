# Maintainer Risk Scoring & Package Reputation

> Assess the trustworthiness of packages based on maintainer history, project health signals, and behavioral patterns — catching compromised accounts and abandoned packages before they become attack vectors.

**Status:** Implemented (v1.2)
**Priority:** High
**Perspective:** Security Operations / CISO

## Problem

Most supply chain attacks exploit trust in maintainers rather than vulnerabilities in code. The attack surface includes:

- **Account takeover:** Attacker gains access to a maintainer's registry credentials (the LiteLLM scenario).
- **Maintainer handoff:** A trusted maintainer transfers ownership to an unknown party who later injects malicious code.
- **Abandoned packages:** Widely depended-upon packages with inactive maintainers become targets for acquisition or typosquatting.
- **Star-jacking:** Packages claiming popularity by pointing to unrelated high-star GitHub repositories.

Shieldoo Gate currently evaluates *artifact content* but not the *context* around who published it and whether the publication pattern is normal. Adding maintainer and package reputation signals would catch a significant class of attacks that content scanners miss.

## Proposed Solution

Add a maintainer risk scoring system that evaluates metadata about packages and their publishers, producing a risk score that feeds into the policy engine.

### Risk Signals

**High-risk signals (strong indicators):**

1. **Maintainer ownership transfer** — Package ownership recently changed to a different maintainer/organization. Especially risky if the new maintainer has no history.
2. **First publication by maintainer** — A new maintainer publishing for the first time. Low base rate of maliciousness but high impact when combined with other signals.
3. **Publication from new IP/location** — Registry APIs increasingly expose this (npm audit log, PyPI events). A package usually published from CI/CD in US suddenly published from an unusual location.
4. **Dormant package reactivated** — A package with no updates for 12+ months suddenly publishes a new version. Classic pattern for account takeover.
5. **Yanked previous versions** — If the maintainer yanks/deletes previous versions shortly after publishing a new one, this can indicate an attempt to force upgrades to a compromised version.

**Medium-risk signals (contextual):**

6. **Package age** — Packages less than 30 days old have a disproportionately high rate of being malicious (especially on PyPI/npm).
7. **Download count** — Very low download counts combined with a name similar to a popular package is suspicious.
8. **No source repository** — Packages without a linked source repository are harder to audit and more likely to be malicious.
9. **Repository mismatch** — The claimed source repository does not contain the published code, or the repository belongs to a different project.
10. **Maintainer email domain** — Free email providers (gmail, outlook) are more commonly used by attackers than organizational domains. Weak signal alone, but contributes to composite score.

**Low-risk signals (informational):**

11. **No README or documentation** — Legitimate packages usually have documentation.
12. **Unusual version numbering** — Versions like `99.0.0` or `0.0.1` that skip semver conventions.
13. **Classifier/tag anomalies** — Package classifiers that don't match the actual content.

### Risk Score Calculation

Each signal has a weight and produces a score between 0.0 and 1.0. Signals are combined using a weighted formula:

```
risk_score = 1 - ∏(1 - weight_i × signal_i)
```

This produces a composite score where multiple weak signals can add up to a significant risk, but no single weak signal dominates.

### Key Requirements

1. **Registry metadata fetching:** Fetch package metadata from upstream registries during the scan phase (maintainer info, publication history, download stats). Cache metadata to reduce upstream queries.
2. **Historical baseline:** Track maintainer and publication patterns over time. Alert when patterns deviate from established baselines.
3. **Verdict integration:** Risk scores feed into the standard scan result aggregation. A high risk score alone does not block, but it amplifies other scanner findings (e.g., SUSPICIOUS + high maintainer risk → QUARANTINE).
4. **Dashboard visibility:** Show risk score breakdown on the artifact detail page. Highlight which signals contributed.
5. **Configurable weights:** Organizations can tune signal weights based on their risk tolerance.

### Configuration

```yaml
scanners:
  reputation:
    enabled: true
    cache_ttl: "24h"                    # Cache registry metadata
    thresholds:
      high_risk: 0.7                    # Score above this = SUSPICIOUS verdict
      critical_risk: 0.9               # Score above this = MALICIOUS verdict
    signals:
      ownership_transfer:
        enabled: true
        weight: 0.8
        lookback_days: 90              # Flag transfers in the last 90 days
      dormant_reactivation:
        enabled: true
        weight: 0.7
        dormant_threshold_days: 365
      package_age:
        enabled: true
        weight: 0.3
        young_threshold_days: 30
      download_count:
        enabled: true
        weight: 0.2
        low_threshold: 100             # Flag packages with < 100 downloads
      no_source_repo:
        enabled: true
        weight: 0.3
```

### How It Fits Into the Architecture

- **Scanner:** New `ReputationScanner` in `internal/scanner/reputation/`. Implements the `Scanner` interface. Queries upstream registry APIs for metadata.
- **Database:** New `package_reputation` table (ecosystem, name, maintainer_history, risk_score, signals, last_checked). New `maintainer_profiles` table (ecosystem, username, first_seen, package_count, publication_pattern).
- **Cache:** Metadata is cached to avoid hitting upstream APIs on every request. TTL configurable (default 24h).
- **Admin UI:** Risk score gauge on artifact detail page, with expandable signal breakdown showing which factors contributed to the score.
- **Synergy with other scanners:** High reputation risk amplifies confidence of content-based scanner findings. A SUSPICIOUS verdict from obfuscation detector + high maintainer risk = escalated to QUARANTINE.

### Ecosystem Coverage

| Ecosystem | Metadata Availability | Notes |
|---|---|---|
| PyPI | Medium | JSON API exposes maintainer, upload timestamps. No download stats API (use BigQuery or estimates). |
| npm | High | Registry API includes maintainers, dist-tags, modification times, download counts (api.npmjs.org). |
| NuGet | Medium | Package metadata includes authors, publish dates. Gallery API for download counts. |
| Docker | Medium | Docker Hub API for image pulls, last push, org membership. Limited for other registries. |
| RubyGems | Medium | API exposes owners, downloads, version history. |
| Maven | Low | Central metadata is limited. POM has developer info but it's self-reported. |
| Go | Low | Module proxy has version list but minimal maintainer metadata. |

### Considerations

- **Rate limiting:** Upstream registry APIs have rate limits. Batch and cache metadata fetches. Degrade gracefully when rate-limited (skip reputation check, do not block).
- **Privacy:** Maintainer profiling raises privacy considerations. Store only publicly available metadata. Do not correlate across ecosystems by personal identity.
- **Gaming:** Sophisticated attackers may build up legitimate-looking maintainer profiles before attacking. Reputation is a signal, not a guarantee. Always combine with content analysis.
- **API stability:** Upstream registry APIs may change. Abstract registry metadata fetching behind per-ecosystem interfaces for easy adaptation.

### V2 Improvements (Implemented)

All V2 improvements identified during cross-check reviews have been implemented.

#### High Priority

| Improvement | Rationale | Source |
|---|---|---|
| Rate limiter (`golang.org/x/time/rate`) | Cold-start or cache wipe triggers burst of upstream API requests. Without throttling, PyPI/npm rate limits can ban the proxy's IP. Use per-ecosystem token-bucket limiter. | Perf, Security |
| SSRF mitigation (redirect policy, hardcoded base URLs) | Upstream metadata fetches follow HTTP redirects by default. A compromised CDN could redirect to internal addresses (AWS IMDS, internal services). Reject redirects to non-HTTPS/private IPs. | Security |
| `singleflight` deduplication for concurrent fetches | Multiple concurrent scans of different versions of the same package trigger identical metadata fetches. Use `golang.org/x/sync/singleflight` keyed by `ecosystem:name` to deduplicate. | Perf |

#### Medium Priority

| Improvement | Rationale | Source |
|---|---|---|
| Hash maintainer emails instead of plaintext | `maintainers_json` stores raw email addresses (PII). Replace with SHA-256 hashes — sufficient for ownership-change detection without GDPR exposure. | Security |
| Signal weight validation in config | Weights outside (0.0, 1.0] produce invalid composite scores. Add validation in `validateReputation()`. Warn if all-signals-active score exceeds malicious threshold. | Security |
| TTL jitter to prevent thundering herd | Fixed 24h TTL causes cache entries to expire simultaneously. Add `TTL + random(0, 2h)` jitter to spread expiry across time. | Perf |
| Lazy warm-up (async first fetch) | First scan for a new package blocks on upstream HTTP. Return CLEAN immediately, fetch metadata asynchronously, use cached result on subsequent requests. Removes reputation scanner from critical latency path. | Perf |

#### Low Priority

| Improvement | Rationale | Status |
|---|---|---|
| Prometheus metrics for cache hit/miss | `shieldoo_reputation_cache_hits_total`, `shieldoo_reputation_cache_misses_total`, `shieldoo_reputation_fetch_duration_seconds`, `shieldoo_reputation_fetch_errors_total`. | **Implemented** |
| DB cleanup job for stale reputation entries | Background goroutine at scanner startup deletes rows where `last_checked` > `retention_days` (default 30). | **Implemented** |
| 6 additional V2 signals | All 14 signals implemented: yanked_versions, unusual_versioning, maintainer_email_domain, first_publication, repo_mismatch, classifier_anomaly. See `internal/scanner/reputation/signals.go`. | **Implemented** |
| Admin UI risk score gauge | Feature spec requires "Risk score gauge on artifact detail page, with expandable signal breakdown." The scan results API already exposes findings — UI needs to render them. | Planned |
