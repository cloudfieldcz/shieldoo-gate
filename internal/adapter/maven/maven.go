// Package maven implements a proxy adapter for Maven repository layout.
package maven

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/maven/effectivepom"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*MavenAdapter)(nil)

// scannableExtensions are file extensions that trigger the scan pipeline.
var scannableExtensions = []string{".jar", ".war", ".aar", ".zip"}

// passThroughExtensions are file extensions proxied without scanning.
var passThroughExtensions = []string{".pom", ".sha1", ".md5", ".sha256", ".asc"}

// validComponentRe matches safe path component characters.
var validComponentRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// MavenAdapter proxies Maven repository HTTP layout with artifact scanning.
type MavenAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string
	router       http.Handler
	httpClient   *http.Client
	pomResolver  *effectivepom.Resolver // nil when effective-POM resolution is disabled
}

// parsedPath holds the result of parsing a Maven repository URL path.
type parsedPath struct {
	groupID    string // e.g. "org.apache.commons"
	artifactID string // e.g. "commons-lang3"
	version    string // e.g. "3.14.0"
	filename   string // e.g. "commons-lang3-3.14.0.jar"
	classifier string // e.g. "sources" (empty if none)
	extension  string // e.g. ".jar"
	scannable  bool   // true if this file should be scanned
	passThru   bool   // true if this is metadata/checksum
}

// NewMavenAdapter creates and wires a MavenAdapter. The pomResolver may be nil
// when effective-POM parent chain resolution is disabled.
func NewMavenAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstream string,
	pomResolver *effectivepom.Resolver,
) *MavenAdapter {
	a := &MavenAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(upstream, "/"),
		httpClient:   adapter.NewProxyHTTPClient(5 * time.Minute),
		pomResolver:  pomResolver,
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *MavenAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemMaven }

// HealthCheck implements adapter.Adapter.
func (a *MavenAdapter) HealthCheck(ctx context.Context) error {
	// Maven Central returns a simple HTML page at the root.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstream+"/", nil)
	if err != nil {
		return fmt.Errorf("maven: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("maven: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maven: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *MavenAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates the chi router with the catch-all route.
func (a *MavenAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/*", a.handleRequest)
	return r
}

// handleRequest is the catch-all handler that parses Maven paths and dispatches.
func (a *MavenAdapter) handleRequest(w http.ResponseWriter, r *http.Request) {
	rawPath := chi.URLParam(r, "*")
	if rawPath == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Path traversal protection.
	cleaned := path.Clean("/" + rawPath)
	if strings.Contains(rawPath, "..") || strings.Contains(cleaned, "..") {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid path",
			Reason: "path traversal detected",
		})
		return
	}
	// Remove leading slash from cleaned path.
	cleaned = strings.TrimPrefix(cleaned, "/")

	// maven-metadata.xml at any level is pass-through.
	if strings.HasSuffix(cleaned, "/maven-metadata.xml") || cleaned == "maven-metadata.xml" {
		a.proxyPassThrough(w, r, cleaned)
		return
	}

	parsed, err := parseMavenPath(cleaned)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid path",
			Reason: err.Error(),
		})
		return
	}

	if parsed.passThru {
		a.proxyPassThrough(w, r, cleaned)
		return
	}

	if parsed.scannable {
		a.downloadScanServe(w, r, parsed, cleaned)
		return
	}

	// Fallback: proxy anything else directly.
	a.proxyPassThrough(w, r, cleaned)
}

// parseMavenPath parses a Maven repository URL path into its components.
// Expected layout: {groupPath}/{artifactId}/{version}/{filename}
// where groupPath may contain multiple segments (org/apache/commons).
func parseMavenPath(cleanPath string) (*parsedPath, error) {
	segments := strings.Split(cleanPath, "/")

	// Validate all segments.
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if !validComponentRe.MatchString(seg) {
			return nil, fmt.Errorf("path component %q contains invalid characters", seg)
		}
	}

	// Need at least: groupPath(1+) / artifactId / version / filename = 4 segments minimum.
	if len(segments) < 4 {
		return nil, fmt.Errorf("path too short for artifact download")
	}

	filename := segments[len(segments)-1]
	version := segments[len(segments)-2]
	artifactID := segments[len(segments)-3]
	groupSegments := segments[:len(segments)-3]

	if len(groupSegments) == 0 {
		return nil, fmt.Errorf("missing group path")
	}

	groupID := strings.Join(groupSegments, ".")

	p := &parsedPath{
		groupID:    groupID,
		artifactID: artifactID,
		version:    version,
		filename:   filename,
	}

	// Determine file type.
	for _, ext := range passThroughExtensions {
		if strings.HasSuffix(filename, ext) {
			p.passThru = true
			p.extension = ext
			return p, nil
		}
	}

	for _, ext := range scannableExtensions {
		if strings.HasSuffix(filename, ext) {
			p.scannable = true
			p.extension = ext
			p.classifier = parseClassifier(filename, artifactID, version, ext)
			return p, nil
		}
	}

	// Unknown extension — treat as pass-through.
	p.passThru = true
	return p, nil
}

// parseClassifier extracts the classifier from a Maven filename.
// Example: commons-lang3-3.14.0-sources.jar → classifier="sources"
func parseClassifier(filename, artifactID, version, ext string) string {
	// Expected: {artifactId}-{version}[-{classifier}].{ext}
	prefix := artifactID + "-" + version
	base := strings.TrimSuffix(filename, ext)

	if base == prefix {
		return "" // No classifier.
	}

	if strings.HasPrefix(base, prefix+"-") {
		return strings.TrimPrefix(base, prefix+"-")
	}

	return ""
}

// mavenArtifactID returns the canonical artifact ID for DB/cache lookups.
func mavenArtifactID(groupID, artifactID, version string) string {
	return fmt.Sprintf("%s:%s:%s:%s", string(scanner.EcosystemMaven), groupID, artifactID, version)
}

// handleTyposquatPreScan runs the typosquat scanner on coordName
// (groupId:artifactId form) before any upstream call. Returns true if the
// request was blocked (response already written). Returns false if the name
// is clean, no scanner is registered, or an active policy override permits
// the request. Synthetic typosquat rows always carry version="*" — typosquat
// detection is name-based, so the override scope is package-wide.
func (a *MavenAdapter) handleTyposquatPreScan(w http.ResponseWriter, r *http.Request, coordName, version string) bool {
	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), coordName, scanner.EcosystemMaven)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	// 4-segment artifact ID: maven:groupId:artifactId:*
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemMaven), coordName, adapter.TyposquatPlaceholderVersion)

	// Detached audit context — the request may cancel mid-flight but audit
	// writes must still land. Mirrors policy.hasDBOverride rationale.
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	// Active policy override allows the request through.
	if a.policyEngine != nil {
		if overrideID, hasOverride := a.policyEngine.HasOverride(r.Context(), scanner.EcosystemMaven, coordName, version); hasOverride {
			log.Info().Str("artifact", artifactID).Str("verdict", string(result.Verdict)).
				Int64("override_id", overrideID).
				Msg("typosquat pre-scan: allowed by policy override")
			_ = adapter.WriteAuditLogCtx(auditCtx, a.db, model.AuditEntry{
				EventType:    model.EventServed,
				ArtifactID:   artifactID,
				ClientIP:     r.RemoteAddr,
				UserAgent:    r.UserAgent(),
				Reason:       "typosquat pre-scan overridden",
				MetadataJSON: fmt.Sprintf(`{"override_id":%d}`, overrideID),
			})
			return false
		}
	}

	log.Warn().Str("artifact", artifactID).Str("verdict", string(result.Verdict)).
		Float32("confidence", result.Confidence).Msg("typosquat pre-scan: blocked before upstream fetch")

	if err := adapter.PersistTyposquatBlock(a.db, artifactID, scanner.EcosystemMaven, coordName, result, time.Now().UTC()); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("typosquat pre-scan: failed to persist block record")
	}

	adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
		Error:    "blocked",
		Artifact: artifactID,
		Reason:   "typosquatting detected",
	})
	_ = adapter.WriteAuditLogCtx(auditCtx, a.db, model.AuditEntry{
		EventType:  model.EventBlocked,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Reason:     typosquatBlockReason(result),
	})
	return true
}

// typosquatBlockReason returns the rich admin-only description used in audit
// log entries — keeps the popular-package name in the audit trail while the
// public 403 response stays generic.
func typosquatBlockReason(result scanner.ScanResult) string {
	if len(result.Findings) > 0 {
		return "typosquat pre-scan: " + result.Findings[0].Description
	}
	return "typosquat pre-scan: " + string(result.Verdict)
}

// proxyPassThrough forwards a request to the upstream Maven repository without scanning.
func (a *MavenAdapter) proxyPassThrough(w http.ResponseWriter, r *http.Request, repoPath string) {
	target, err := url.JoinPath(a.upstream, repoPath)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// downloadScanServe implements the full download -> scan -> policy -> serve pipeline.
func (a *MavenAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, parsed *parsedPath, repoPath string) {
	ctx := r.Context()

	artifactID := mavenArtifactID(parsed.groupID, parsed.artifactID, parsed.version)
	coordName := parsed.groupID + ":" + parsed.artifactID

	// Pre-scan for typosquatting BEFORE contacting upstream.
	// The typosquat scanner only needs the coordinate name — no file content.
	// Active policy overrides (package- or version-scoped) suppress the block.
	if a.handleTyposquatPreScan(w, r, coordName, parsed.version) {
		return
	}

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("maven: failed to check artifact status, refusing to serve")
			http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
			return
		}
		if status != nil && status.Status == model.StatusQuarantined {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "quarantined",
				Artifact: artifactID,
				Reason:   status.QuarantineReason,
			})
			_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: artifactID,
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     "quarantined (cached)",
			})
			return
		}
		// SHA256 integrity verification — FAIL-CLOSED.
		if err := adapter.VerifyCacheIntegrity(a.db, artifactID, cachedPath); err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: cache integrity violation")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "integrity_violation",
				Artifact: artifactID,
				Reason:   "cached artifact integrity check failed",
			})
			return
		}
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("maven: serving from cache")
		adapter.UpdateLastAccessedAt(a.db, artifactID)
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		// Trigger async sandbox scan (non-blocking).
		adapter.TriggerAsyncScan(r.Context(), scanner.Artifact{
			ID: artifactID, Ecosystem: scanner.EcosystemMaven, Name: parsed.groupID + ":" + parsed.artifactID, Version: parsed.version, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context — see PyPI adapter for rationale.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()

	// Re-check cache after acquiring lock.
	if cachedPath, err := a.cache.Get(pctx, artifactID); err == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("maven: failed to check artifact status, refusing to serve")
			http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
			return
		}
		if status != nil && status.Status == model.StatusQuarantined {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "quarantined",
				Artifact: artifactID,
				Reason:   status.QuarantineReason,
			})
			return
		}
		// SHA256 integrity verification on race-condition cache hit.
		if err := adapter.VerifyCacheIntegrity(a.db, artifactID, cachedPath); err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: cache integrity violation (post-lock)")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "integrity_violation",
				Artifact: artifactID,
				Reason:   "cached artifact integrity check failed",
			})
			return
		}
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		http.ServeFile(w, r, cachedPath)
		return
	}

	// 3. Download to temp file.
	upstreamURL, err := url.JoinPath(a.upstream, repoPath)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}

	tmpPath, size, sha, err := downloadToTemp(pctx, upstreamURL, a.httpClient)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("maven: failed to download from upstream")
		http.Error(w, "failed to fetch upstream artifact", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// Upstream integrity check — detect content mutation for known artifacts.
	if err := adapter.VerifyUpstreamIntegrity(a.db, artifactID, sha); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: upstream content mutation detected")
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "integrity_violation",
			Artifact: artifactID,
			Reason:   "upstream content changed since last scan — artifact quarantined, admin must delete and re-approve",
		})
		return
	}

	// 4. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemMaven,
		Name:        parsed.groupID + ":" + parsed.artifactID,
		Version:     parsed.version,
		LocalPath:   tmpPath,
		Filename:    parsed.filename,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4b. Effective POM resolution — enrich with parent-chain licenses.
	// Only for scannable extensions (JARs/WARs) and only when resolver is enabled.
	// Network failures fail-open: log warning and continue without extra licenses.
	if a.pomResolver != nil {
		coords := effectivepom.Coords{
			GroupID:    parsed.groupID,
			ArtifactID: parsed.artifactID,
			Version:    parsed.version,
		}
		if rawLicenses := a.pomResolver.Resolve(pctx, coords); len(rawLicenses) > 0 {
			// Normalize license strings to canonical SPDX IDs before passing
			// to the scanner engine. E.g. "The GNU General Public License, v2
			// with Universal FOSS Exception, v1.0" → "GPL-2.0-only".
			normalized := make([]string, 0, len(rawLicenses))
			for _, l := range rawLicenses {
				canon, _ := sbom.NameAliasToID(l)
				normalized = append(normalized, canon)
			}
			scanArtifact.ExtraLicenses = normalized
			log.Info().
				Str("artifact", artifactID).
				Strs("licenses", normalized).
				Msg("maven: effective-POM resolver found licenses via parent chain")
		}
	}

	// 5. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("maven: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("maven: scan engine error, failing open")
		scanResults = nil
	}
	for _, sr := range scanResults {
		l := log.Info().
			Str("artifact", artifactID).
			Str("scanner", sr.ScannerID).
			Str("verdict", string(sr.Verdict)).
			Float32("confidence", sr.Confidence).
			Dur("duration", sr.Duration)
		if sr.Error != nil {
			l = l.Err(sr.Error)
		}
		if len(sr.Findings) > 0 {
			l = l.Int("findings", len(sr.Findings))
		}
		l.Msg("maven: scan result")
	}

	// 6. Policy evaluation.
	policyResult := a.policyEngine.Evaluate(pctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("maven: policy decision")

	// 7. Act on policy result.
	switch policyResult.Action {
	case policy.ActionBlock:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventBlocked,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "blocked",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		return

	case policy.ActionAllowWithWarning:
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventAllowedWithWarning,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		w.Header().Set("X-Shieldoo-Warning", "MEDIUM vulnerability detected; see admin dashboard for details")
		_ = a.cache.Put(pctx, scanArtifact, tmpPath)
		http.ServeFile(w, r, tmpPath)
		adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
		return

	case policy.ActionQuarantine:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventQuarantined,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		return
	}

	// 8. Allow — cache artifact and serve.
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	http.ServeFile(w, r, tmpPath)

	// Trigger async sandbox scan (non-blocking).
	adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
	adapter.TriggerAsyncSBOMWrite(r.Context(), artifactID, scanResults)

	// Persist license metadata from effective-POM resolver so licenses are
	// visible in the API / admin UI even without a full SBOM blob.
	if len(scanArtifact.ExtraLicenses) > 0 {
		adapter.TriggerAsyncLicenseWrite(r.Context(), artifactID, scanArtifact.ExtraLicenses, "effective-pom")
	}
}

// persistArtifact writes the artifact, status, and scan results to the DB.
func (a *MavenAdapter) persistArtifact(
	artifactID string,
	sa scanner.Artifact,
	status model.Status,
	quarantineReason string,
	quarantinedAt *time.Time,
	scanResults []scanner.ScanResult,
) error {
	now := time.Now().UTC()
	art := model.Artifact{
		Ecosystem:      string(sa.Ecosystem),
		Name:           sa.Name,
		Version:        sa.Version,
		UpstreamURL:    sa.UpstreamURL,
		SHA256:         sa.SHA256,
		SizeBytes:      sa.SizeBytes,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    sa.LocalPath,
	}
	artStatus := model.ArtifactStatus{
		ArtifactID:       artifactID,
		Status:           status,
		QuarantineReason: quarantineReason,
		QuarantinedAt:    quarantinedAt,
	}
	if err := adapter.InsertArtifact(a.db, artifactID, art, artStatus); err != nil {
		return err
	}
	return adapter.InsertScanResults(a.db, artifactID, scanResults)
}

// downloadToTemp downloads url into a temporary file, returning (path, size, sha256hex, error).
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("maven: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-maven-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	// Cap artifact download at 2 GB to prevent disk exhaustion.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("maven: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
