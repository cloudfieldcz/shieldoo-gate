# SHA256 Integrity Gate — Phase 3: Fix Tag Mutability Detection

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the broken tag mutability check that compares incompatible hash formats (SHA256 hex vs SHA512 SRI / ETag signatures), making upstream content mutation detection actually work.

**Architecture:** Change the mutability check to consistently use SHA256 as the comparison format. For npm: fetch tarball URL with HEAD and compute Content-Length signature (like PyPI/NuGet), OR parse `dist.shasum` (SHA1) as a consistent comparable value. Store the upstream digest in `tag_digest_history` and use it for subsequent comparisons instead of always comparing against `artifacts.sha256`.

**Tech Stack:** Go, HTTP HEAD requests, npm registry API

**Index:** [`plan-index.md`](./2026-04-10-sha256-integrity-gate-plan-index.md)

---

## Problem

In `internal/adapter/mutability.go`:

1. **npm** (`checkNPMDigest`, line 152): Compares `dist.integrity` (SHA512 SRI format `sha512-xYz...`) against `artifacts.sha256` (hex string `a1b2c3...`). These NEVER match → always reports "changed".

2. **PyPI** (`checkPyPIDigest`, line 94): Compares `etag:xxx;cl:yyy` signature against `artifacts.sha256`. These NEVER match → always reports "changed".

3. **NuGet** (`checkNuGetDigest`, line 242): Same ETag/CL format mismatch.

4. **`tag_digest_history`** is written to but never read back for subsequent comparisons.

## Fix Strategy

Change `HandleTagMutability` to use a two-tier comparison:
1. **First check:** Compare against `tag_digest_history.digest` (the previously observed upstream signature)
2. **Fallback (first encounter):** Record the current upstream signature — no alarm (we don't know if it changed)
3. **Subsequent checks:** Compare current upstream signature against previously recorded one

This eliminates the SHA256-vs-SRI format mismatch entirely — we always compare the upstream's own format against itself from a prior observation.

---

## File Structure

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `internal/adapter/mutability.go` | Fix comparison logic in `HandleTagMutability` |
| Modify | `internal/adapter/mutability_test.go` | Fix/add tests (create if missing) |

---

### Task 1: Fix HandleTagMutability to use tag_digest_history

**Files:**
- Modify: `internal/adapter/mutability.go:314-409`

- [ ] **Step 1: Read the current file**

Re-read `internal/adapter/mutability.go` to verify current state.

- [ ] **Step 2: Change HandleTagMutability comparison logic**

Replace the current comparison approach. Instead of comparing upstream digest against `artifacts.sha256`, compare against the last recorded digest in `tag_digest_history`:

```go
func HandleTagMutability(
	ctx context.Context,
	cfg config.TagMutabilityConfig,
	db *config.GateDB,
	httpClient *http.Client,
	ecosystem, name, version, artifactID, upstreamURL string,
	r *http.Request,
	w http.ResponseWriter,
) bool {
	if !cfg.Enabled || !cfg.CheckOnCacheHit {
		return false
	}

	if IsExcludedTag(version, cfg.ExcludeTags) {
		return false
	}

	// Get the LAST OBSERVED upstream digest from tag_digest_history.
	// On first encounter this will be empty — we record and move on.
	var lastDigest string
	_ = db.Get(&lastDigest,
		`SELECT digest FROM tag_digest_history
		 WHERE ecosystem = ? AND name = ? AND tag_or_version = ?
		 ORDER BY first_seen_at DESC LIMIT 1`,
		ecosystem, name, version)

	// Fetch current upstream digest (ecosystem-specific).
	// We pass empty string as cachedSHA256 — we don't use it for comparison anymore.
	_, currentDigest, err := CheckDigestChanged(ctx, ecosystem, upstreamURL, "", httpClient)
	if err != nil {
		log.Warn().Err(err).Str("artifact", artifactID).Msg("mutability: upstream check failed, failing open")
		return false
	}
	if currentDigest == "" {
		// No usable signal from upstream.
		return false
	}

	// First encounter: record and proceed (no alarm).
	if lastDigest == "" {
		if recordErr := RecordDigestHistory(db, ecosystem, name, version, currentDigest); recordErr != nil {
			log.Error().Err(recordErr).Str("artifact", artifactID).Msg("mutability: failed to record initial digest")
		}
		return false
	}

	// Same digest as last time — no change.
	if currentDigest == lastDigest {
		return false
	}

	// DIGEST CHANGED — upstream content mutation detected!
	if recordErr := RecordDigestHistory(db, ecosystem, name, version, currentDigest); recordErr != nil {
		log.Error().Err(recordErr).Str("artifact", artifactID).Msg("mutability: failed to record new digest")
	}

	metaJSON := fmt.Sprintf(`{"old_digest":%q,"new_digest":%q}`, lastDigest, currentDigest)
	_ = WriteAuditLog(db, model.AuditEntry{
		EventType:    model.EventTagMutated,
		ArtifactID:   artifactID,
		ClientIP:     r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Reason:       "upstream digest changed",
		MetadataJSON: metaJSON,
	})

	log.Warn().
		Str("artifact", artifactID).
		Str("old_digest", lastDigest).
		Str("new_digest", currentDigest).
		Str("action", cfg.Action).
		Msg("mutability: tag mutation detected")

	switch cfg.Action {
	case "block":
		WriteJSONError(w, http.StatusForbidden, ErrorResponse{
			Error:    "blocked",
			Artifact: artifactID,
			Reason:   "upstream content changed (tag mutability detected)",
		})
		return true

	case "quarantine":
		now := time.Now().UTC()
		_, qErr := db.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
			model.StatusQuarantined, "tag mutability detected: upstream digest changed", now, artifactID,
		)
		if qErr != nil {
			log.Error().Err(qErr).Str("artifact", artifactID).Msg("mutability: failed to quarantine artifact")
		}
		WriteJSONError(w, http.StatusForbidden, ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   "upstream content changed (tag mutability detected)",
		})
		return true

	case "warn":
		return false

	default:
		log.Warn().Str("action", cfg.Action).Msg("mutability: unknown action, treating as warn")
		return false
	}
}
```

- [ ] **Step 3: Update CheckDigestChanged**

The `CheckDigestChanged` function can stay as-is — it just returns the upstream's native digest format. We no longer compare against `cachedSHA256`, so the second parameter is unused (but kept for API compatibility). The individual `checkNPMDigest`, `checkPyPIDigest`, `checkNuGetDigest` functions remain unchanged — they return the upstream's native format which is now compared against itself from a prior observation.

Note: Remove the now-unused `GetCachedArtifactSHA256` function (it was only used by the old HandleTagMutability) or leave it since it may be useful elsewhere. Check if it's used anywhere else first.

- [ ] **Step 4: Build and test**

Run: `make build && make test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/mutability.go
git commit -m "fix(mutability): compare upstream digest against prior observation, not SHA256

The old code compared SHA512-SRI (npm) or ETag+CL (PyPI/NuGet) against
SHA256 hex — formats that can never match, causing false positives.

Now uses tag_digest_history to track upstream digests and compare each
observation against the previous one. First encounter is recorded without
alarm; subsequent changes trigger the configured action."
```

---

### Task 2: Unit tests for fixed mutability

**Files:**
- Create or modify: `internal/adapter/mutability_test.go`

- [ ] **Step 1: Write tests**

Test cases:
- `TestHandleTagMutability_FirstEncounter_RecordsAndPasses` — no prior digest, records current, returns false
- `TestHandleTagMutability_SameDigest_Passes` — prior digest matches current, returns false
- `TestHandleTagMutability_DigestChanged_BlockAction_Returns403` — digest changed, action=block, returns true
- `TestHandleTagMutability_DigestChanged_QuarantineAction_Quarantines` — digest changed, action=quarantine
- `TestHandleTagMutability_Disabled_Passes` — cfg.Enabled=false, returns false
- `TestHandleTagMutability_UpstreamError_FailsOpen` — HTTP error, returns false

- [ ] **Step 2: Run tests**

Run: `go test ./internal/adapter/ -run TestHandleTagMutability -v`

- [ ] **Step 3: Commit**

```bash
git add internal/adapter/mutability_test.go
git commit -m "test(mutability): add unit tests for fixed tag mutability detection"
```
