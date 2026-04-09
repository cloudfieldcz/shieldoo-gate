// Package rubygems implements a proxy adapter for RubyGems API.
package rubygems

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
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*RubyGemsAdapter)(nil)

// validComponentRe matches safe path component characters.
var validComponentRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// RubyGemsAdapter proxies RubyGems HTTP API with artifact scanning on gem downloads.
type RubyGemsAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string
	router       http.Handler
	httpClient   *http.Client
}

// NewRubyGemsAdapter creates and wires a RubyGemsAdapter.
func NewRubyGemsAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstream string,
) *RubyGemsAdapter {
	a := &RubyGemsAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(upstream, "/"),
		httpClient:   adapter.NewProxyHTTPClient(5 * time.Minute),
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *RubyGemsAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemRubyGems }

// HealthCheck implements adapter.Adapter.
func (a *RubyGemsAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstream+"/api/v1/gems/rails.json", nil)
	if err != nil {
		return fmt.Errorf("rubygems: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rubygems: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rubygems: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *RubyGemsAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates the chi router for RubyGems API routes.
func (a *RubyGemsAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// Gem download — triggers scan pipeline.
	r.Get("/gems/{filename}", a.handleGemDownload)

	// Metadata pass-through.
	r.Get("/api/v1/gems/{name}.json", a.handlePassThrough)
	r.Get("/api/v1/versions/{name}.json", a.handlePassThrough)

	// Compressed gemspec pass-through.
	r.Get("/quick/Marshal.4.8/*", a.handlePassThrough)

	// Index files pass-through.
	r.Get("/specs.4.8.gz", a.handlePassThrough)
	r.Get("/latest_specs.4.8.gz", a.handlePassThrough)
	r.Get("/prerelease_specs.4.8.gz", a.handlePassThrough)

	return r
}

// parseGemFilename parses a gem filename into name and version.
// Gem filenames have the format: {name}-{version}.gem
// Names can contain hyphens (e.g. aws-sdk-core-3.0.0.gem).
// Platform-specific gems (e.g. nokogiri-1.16.0-x86_64-linux.gem) have the
// platform after the version; we strip it.
//
// Strategy: strip ".gem", then scan from right to find the last hyphen
// followed by a digit — that separates name from version+platform.
// Then strip any platform suffix from the version.
func parseGemFilename(filename string) (name, version string, err error) {
	if !strings.HasSuffix(filename, ".gem") {
		return "", "", fmt.Errorf("rubygems: filename %q does not end with .gem", filename)
	}

	base := strings.TrimSuffix(filename, ".gem")
	if base == "" {
		return "", "", fmt.Errorf("rubygems: empty gem filename")
	}

	// Find the last hyphen followed by a digit (scanning from right).
	splitIdx := -1
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '-' && i+1 < len(base) && unicode.IsDigit(rune(base[i+1])) {
			splitIdx = i
			break
		}
	}

	if splitIdx <= 0 {
		return "", "", fmt.Errorf("rubygems: cannot parse name/version from %q", filename)
	}

	name = base[:splitIdx]
	versionPart := base[splitIdx+1:]

	// Strip platform suffix from version if present.
	// Platform suffixes contain non-digit, non-dot characters after the version
	// digits, e.g. "1.16.0-x86_64-linux". We find the first hyphen after the
	// version number portion.
	version = stripPlatform(versionPart)

	if name == "" || version == "" {
		return "", "", fmt.Errorf("rubygems: cannot parse name/version from %q", filename)
	}

	return name, version, nil
}

// stripPlatform removes a platform suffix from a version string.
// Version strings like "1.16.0-x86_64-linux" become "1.16.0".
// Pure versions like "3.0.0" or "7.1.3.1" are returned as-is.
func stripPlatform(versionPart string) string {
	// Find the first hyphen — everything before it is the version.
	idx := strings.Index(versionPart, "-")
	if idx > 0 {
		return versionPart[:idx]
	}
	return versionPart
}

// rubygemsArtifactID returns the canonical artifact ID for DB/cache lookups.
func rubygemsArtifactID(name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", string(scanner.EcosystemRubyGems), name, version, filename)
}

// handleGemDownload handles GET /gems/{filename} — the main scan pipeline.
func (a *RubyGemsAdapter) handleGemDownload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	if filename == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Path traversal protection.
	cleaned := path.Clean("/" + filename)
	if strings.Contains(filename, "..") || strings.Contains(cleaned, "..") || strings.Contains(filename, "/") {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: "path traversal detected",
		})
		return
	}

	// Validate filename characters.
	if !validComponentRe.MatchString(filename) {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: fmt.Sprintf("filename %q contains invalid characters", filename),
		})
		return
	}

	name, version, err := parseGemFilename(filename)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: err.Error(),
		})
		return
	}

	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
			Reason: err.Error(),
		})
		return
	}
	if err := adapter.ValidateVersion(version); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid version",
			Reason: err.Error(),
		})
		return
	}

	a.downloadScanServe(w, r, name, version, filename)
}

// handlePassThrough proxies requests directly to the upstream without scanning.
func (a *RubyGemsAdapter) handlePassThrough(w http.ResponseWriter, r *http.Request) {
	// Reconstruct the upstream URL from the request path.
	reqPath := r.URL.Path

	// Path traversal protection.
	cleaned := path.Clean(reqPath)
	if strings.Contains(reqPath, "..") || strings.Contains(cleaned, "..") {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid path",
			Reason: "path traversal detected",
		})
		return
	}

	target, err := url.JoinPath(a.upstream, reqPath)
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
func (a *RubyGemsAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, name, version, filename string) {
	ctx := r.Context()
	artifactID := rubygemsArtifactID(name, version, filename)

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to check artifact status, refusing to serve")
			http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
			return
		}
		if status != nil && status.Status == model.StatusQuarantined {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "quarantined",
				Artifact: artifactID,
				Reason:   status.QuarantineReason,
			})
			_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: artifactID,
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     "quarantined (cached)",
			})
			return
		}
		adapter.UpdateLastAccessedAt(a.db, artifactID)
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		// Trigger async sandbox scan (non-blocking).
		adapter.TriggerAsyncScan(r.Context(), scanner.Artifact{
			ID: artifactID, Ecosystem: scanner.EcosystemRubyGems, Name: name, Version: version, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context — see PyPI adapter for rationale.
	pctx, pcancel := adapter.PipelineContext()
	defer pcancel()

	// Re-check cache after acquiring lock.
	if cachedPath, err := a.cache.Get(pctx, artifactID); err == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to check artifact status, refusing to serve")
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
		http.ServeFile(w, r, cachedPath)
		return
	}

	// 3. Download to temp file.
	upstreamURL, err := url.JoinPath(a.upstream, "gems", filename)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}

	tmpPath, size, sha, err := downloadToTemp(pctx, upstreamURL, a.httpClient)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to download from upstream")
		http.Error(w, "failed to fetch upstream artifact", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// 4. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemRubyGems,
		Name:        name,
		Version:     version,
		LocalPath:   tmpPath,
		Filename:    filename,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 5. Scan.
	log.Info().Str("artifact", artifactID).Msg("rubygems: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: scan engine error, failing open")
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
		l.Msg("rubygems: scan result")
	}

	// 6. Policy evaluation.
	policyResult := a.policyEngine.Evaluate(pctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("rubygems: policy decision")

	// 7. Act on policy result.
	switch policyResult.Action {
	case policy.ActionBlock:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
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

	case policy.ActionQuarantine:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
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

	case policy.ActionAllowWithWarning:
		_ = a.cache.Put(pctx, scanArtifact, tmpPath)
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventAllowedWithWarning,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		w.Header().Set("X-Shieldoo-Warning", "MEDIUM vulnerability detected; see admin dashboard for details")
		http.ServeFile(w, r, tmpPath)
		adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
		return
	}

	// 8. Allow — cache artifact and serve.
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	http.ServeFile(w, r, tmpPath)

	// Trigger async sandbox scan (non-blocking).
	adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
}

// persistArtifact writes the artifact, status, and scan results to the DB.
func (a *RubyGemsAdapter) persistArtifact(
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
		return "", 0, "", fmt.Errorf("rubygems: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("rubygems: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("rubygems: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-rubygems-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("rubygems: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	// Cap artifact download at 2 GB to prevent disk exhaustion.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("rubygems: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
