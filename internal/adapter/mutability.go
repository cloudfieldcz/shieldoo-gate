package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// headCacheEntry stores the result of a HEAD/metadata check with a TTL.
type headCacheEntry struct {
	changed  bool
	digest   string
	err      error
	expireAt time.Time
}

// headCache is an in-memory cache for HEAD request results (60s TTL).
// Prevents N×HEAD amplification when many concurrent requests hit the same artifact.
var headCache sync.Map

const headCacheTTL = 60 * time.Second

func init() {
	go func() {
		ticker := time.NewTicker(headCacheTTL)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			headCache.Range(func(key, value any) bool {
				if e := value.(*headCacheEntry); now.After(e.expireAt) {
					headCache.Delete(key)
				}
				return true
			})
		}
	}()
}

// headCheckTimeout is the maximum time for a single upstream HEAD/metadata check.
const headCheckTimeout = 3 * time.Second

// CheckDigestChanged checks if upstream content has changed compared to cached SHA256.
// Returns (changed bool, upstreamDigest string, err error).
// On error, returns (false, "", err) — fail-open: treat as unchanged.
func CheckDigestChanged(ctx context.Context, ecosystem, upstreamURL, cachedSHA256 string, httpClient *http.Client) (bool, string, error) {
	// Check in-memory cache first.
	cacheKey := ecosystem + ":" + upstreamURL
	if entry, ok := headCache.Load(cacheKey); ok {
		e := entry.(*headCacheEntry)
		if time.Now().Before(e.expireAt) {
			return e.changed, e.digest, e.err
		}
		// Expired — remove and re-check.
		headCache.Delete(cacheKey)
	}

	var changed bool
	var digest string
	var err error

	switch ecosystem {
	case "pypi":
		changed, digest, err = checkPyPIDigest(ctx, upstreamURL, cachedSHA256, httpClient)
	case "npm":
		changed, digest, err = checkNPMDigest(ctx, upstreamURL, cachedSHA256, httpClient)
	case "nuget":
		changed, digest, err = checkNuGetDigest(ctx, upstreamURL, cachedSHA256, httpClient)
	default:
		// Unknown ecosystem — skip check.
		return false, "", nil
	}

	// Cache the result.
	headCache.Store(cacheKey, &headCacheEntry{
		changed:  changed,
		digest:   digest,
		err:      err,
		expireAt: time.Now().Add(headCacheTTL),
	})

	return changed, digest, err
}

// checkPyPIDigest performs a HEAD request to the upstream PyPI URL.
// Compares ETag (if available) or Content-Length as a weak signal.
func checkPyPIDigest(ctx context.Context, upstreamURL, cachedSHA256 string, httpClient *http.Client) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, headCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, upstreamURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("mutability: pypi HEAD request build: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("mutability: pypi HEAD request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("mutability: pypi HEAD returned %d", resp.StatusCode)
	}

	// Use ETag as the primary signal.
	etag := resp.Header.Get("ETag")
	if etag != "" {
		// ETag is an opaque string — we compare it with what we would have
		// stored. Since we don't store ETags yet, we use a synthetic digest
		// composed of "etag:" + the etag value. If the etag differs from
		// the cached SHA256 representation, it signals a change.
		// For the initial check the cachedSHA256 won't match the etag format,
		// so we use Content-Length as a secondary signal on first encounter.
		contentLength := resp.Header.Get("Content-Length")
		upstreamSignature := fmt.Sprintf("etag:%s;cl:%s", etag, contentLength)
		// We cannot directly compare an ETag with a SHA256.
		// Instead, return the ETag+CL as "digest" — the caller records it.
		// On subsequent checks, the caller will pass the previously recorded
		// digest from tag_digest_history, enabling comparison.
		return upstreamSignature != cachedSHA256, upstreamSignature, nil
	}

	// Fallback: Content-Length only (weak signal).
	contentLength := resp.Header.Get("Content-Length")
	if contentLength != "" {
		clDigest := "cl:" + contentLength
		return clDigest != cachedSHA256, clDigest, nil
	}

	// No usable signal — cannot determine change.
	return false, "", nil
}

// npmVersionMetadata is a subset of the npm registry version metadata.
type npmVersionMetadata struct {
	Dist struct {
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
}

// checkNPMDigest fetches npm version metadata and compares dist.integrity or dist.shasum.
func checkNPMDigest(ctx context.Context, upstreamURL, cachedSHA256 string, httpClient *http.Client) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, headCheckTimeout)
	defer cancel()

	// npm tarball URLs look like: https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz
	// We need the metadata URL: https://registry.npmjs.org/pkg/1.0.0
	// Extract from the tarball URL.
	metadataURL := npmTarballToMetadataURL(upstreamURL)
	if metadataURL == "" {
		return false, "", fmt.Errorf("mutability: npm cannot derive metadata URL from %s", upstreamURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("mutability: npm metadata request build: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("mutability: npm metadata request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("mutability: npm metadata returned %d", resp.StatusCode)
	}

	// Cap read at 1 MB for safety.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, "", fmt.Errorf("mutability: npm metadata read: %w", err)
	}

	var meta npmVersionMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return false, "", fmt.Errorf("mutability: npm metadata parse: %w", err)
	}

	// Prefer integrity (SHA512 SRI format).
	if meta.Dist.Integrity != "" {
		return meta.Dist.Integrity != cachedSHA256, meta.Dist.Integrity, nil
	}
	// Fallback to shasum (SHA1).
	if meta.Dist.Shasum != "" {
		return meta.Dist.Shasum != cachedSHA256, meta.Dist.Shasum, nil
	}

	return false, "", nil
}

// npmTarballToMetadataURL converts an npm tarball URL to a version metadata URL.
// Input:  https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz
// Output: https://registry.npmjs.org/is-odd/3.0.1
// Input:  https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz
// Output: https://registry.npmjs.org/@scope/pkg/1.0.0
func npmTarballToMetadataURL(tarballURL string) string {
	// Find the "/-/" separator that separates the package name from the tarball.
	idx := strings.Index(tarballURL, "/-/")
	if idx < 0 {
		return ""
	}
	baseURL := tarballURL[:idx]
	tarball := tarballURL[idx+3:] // after "/-/"

	// Tarball format: pkgname-version.tgz
	tarball = strings.TrimSuffix(tarball, ".tgz")
	tarball = strings.TrimSuffix(tarball, ".tar.gz")

	// Extract the package base name (last path component of baseURL).
	lastSlash := strings.LastIndex(baseURL, "/")
	if lastSlash < 0 {
		return ""
	}
	baseName := baseURL[lastSlash+1:]

	// Version is everything after "baseName-".
	prefix := baseName + "-"
	if !strings.HasPrefix(tarball, prefix) {
		return ""
	}
	version := tarball[len(prefix):]
	if version == "" {
		return ""
	}

	return baseURL + "/" + version
}

// checkNuGetDigest performs a HEAD request to the NuGet package URL.
// Compares ETag or Content-Length as a signal.
func checkNuGetDigest(ctx context.Context, upstreamURL, cachedSHA256 string, httpClient *http.Client) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, headCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, upstreamURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("mutability: nuget HEAD request build: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("mutability: nuget HEAD request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("mutability: nuget HEAD returned %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")
	contentLength := resp.Header.Get("Content-Length")

	if etag != "" {
		upstreamSignature := fmt.Sprintf("etag:%s;cl:%s", etag, contentLength)
		return upstreamSignature != cachedSHA256, upstreamSignature, nil
	}

	if contentLength != "" {
		clDigest := "cl:" + contentLength
		return clDigest != cachedSHA256, clDigest, nil
	}

	return false, "", nil
}

// RecordDigestHistory inserts a new digest observation into tag_digest_history.
// Uses ON CONFLICT DO NOTHING for idempotency.
func RecordDigestHistory(db *config.GateDB, ecosystem, name, version, digest string) error {
	_, err := db.Exec(
		`INSERT INTO tag_digest_history (ecosystem, name, tag_or_version, digest, first_seen_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (ecosystem, name, tag_or_version, digest) DO NOTHING`,
		ecosystem, name, version, digest, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("mutability: recording digest history: %w", err)
	}
	return nil
}

// IsExcludedTag checks if the given version/tag is in the exclude list.
func IsExcludedTag(version string, excludeTags []string) bool {
	for _, t := range excludeTags {
		if strings.EqualFold(version, t) {
			return true
		}
	}
	return false
}

// GetCachedArtifactSHA256 retrieves the SHA256 hash of a cached artifact from the DB.
func GetCachedArtifactSHA256(db *config.GateDB, artifactID string) (string, error) {
	var sha256 string
	err := db.Get(&sha256, `SELECT sha256 FROM artifacts WHERE id = ?`, artifactID)
	if err != nil {
		return "", fmt.Errorf("mutability: getting cached sha256 for %s: %w", artifactID, err)
	}
	return sha256, nil
}

// HandleTagMutability performs tag mutability detection on cache hit.
// Returns true if the request should be blocked (action=block), false otherwise.
// Fail-open: any error during detection is logged and the request proceeds normally.
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

	// Fetch current upstream digest (ecosystem-specific format: SRI, ETag, etc.).
	// We pass lastDigest so the headCache comparison is meaningful.
	_, currentDigest, err := CheckDigestChanged(ctx, ecosystem, upstreamURL, lastDigest, httpClient)
	if err != nil {
		// Fail-open: log and continue serving from cache.
		log.Warn().Err(err).Str("artifact", artifactID).Msg("mutability: upstream check failed, failing open")
		return false
	}
	if currentDigest == "" {
		// No usable signal from upstream.
		return false
	}

	// First encounter: record the upstream digest and proceed (no alarm).
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
		// Quarantine: update artifact status to QUARANTINED.
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
		// Warn: log already done above, continue serving from cache.
		return false

	default:
		// Unknown action — fail-open, just warn.
		log.Warn().Str("action", cfg.Action).Msg("mutability: unknown action, treating as warn")
		return false
	}
}

// ClearHeadCache clears the in-memory HEAD result cache. Intended for testing.
func ClearHeadCache() {
	headCache.Range(func(key, _ any) bool {
		headCache.Delete(key)
		return true
	})
}
