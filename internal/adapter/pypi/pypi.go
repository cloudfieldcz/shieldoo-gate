// Package pypi implements a PEP 503/691 compatible proxy adapter for PyPI.
package pypi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*PyPIAdapter)(nil)

// PyPIAdapter proxies PyPI Simple API (PEP 503) and package downloads.
type PyPIAdapter struct {
	db             *config.GateDB
	cache          cache.CacheStore
	scanEngine     *scanner.Engine
	policyEngine   *policy.Engine
	upstreamURL    string
	filesHost      string // CDN for package file downloads; defaults to pypiFilesHost
	router         http.Handler
	httpClient     *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

// NewPyPIAdapter creates and wires a PyPIAdapter.
func NewPyPIAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
	tagMutabilityCfg config.TagMutabilityConfig,
) *PyPIAdapter {
	a := &PyPIAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(upstreamURL, "/"),
		filesHost:        pypiFilesHost,
		httpClient:        adapter.NewProxyHTTPClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}

// SetFilesHost overrides the CDN host used for package file downloads.
// Intended for testing only.
func (a *PyPIAdapter) SetFilesHost(host string) {
	a.filesHost = strings.TrimRight(host, "/")
}

// Ecosystem implements adapter.Adapter.
func (a *PyPIAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemPyPI }

// HealthCheck implements adapter.Adapter.
func (a *PyPIAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/simple/", nil)
	if err != nil {
		return fmt.Errorf("pypi: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pypi: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pypi: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *PyPIAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates the chi router with all PyPI routes.
func (a *PyPIAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/simple/", a.handleSimpleIndex)
	r.Get("/simple/{package}/", a.handleSimplePackage)
	r.Get("/packages/*", a.handlePackageDownload)
	return r
}

// handleSimpleIndex proxies the PEP 503 simple index page.
func (a *PyPIAdapter) handleSimpleIndex(w http.ResponseWriter, r *http.Request) {
	a.proxyUpstream(w, r, "/simple/")
}

// handleSimplePackage proxies the per-package simple page, rewriting download
// URLs to route through the proxy's /packages/ handler so artifacts get scanned.
func (a *PyPIAdapter) handleSimplePackage(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
			Reason: err.Error(),
		})
		return
	}
	a.proxyUpstreamRewrite(w, r, "/simple/"+pkg+"/")
}

// pypiFilesHost is the CDN that serves actual PyPI package files.
const pypiFilesHost = "https://files.pythonhosted.org"

var validFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

const maxFilenameLen = 256

// PyPIArtifactID constructs a 4-segment artifact ID for PyPI.
func PyPIArtifactID(name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", string(scanner.EcosystemPyPI), name, version, filename)
}

// validateFilename checks the filename is safe for use in artifact IDs and cache paths.
func validateFilename(filename string) error {
	if len(filename) > maxFilenameLen {
		return fmt.Errorf("pypi: filename too long (%d > %d): %q", len(filename), maxFilenameLen, filename)
	}
	if !validFilenameRe.MatchString(filename) {
		return fmt.Errorf("pypi: filename contains invalid characters: %q", filename)
	}
	return nil
}

// handlePackageDownload runs the full download → scan → policy → serve pipeline.
func (a *PyPIAdapter) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	filePath := chi.URLParam(r, "*")

	// Map relative /packages/ paths back to the files CDN host.
	upstreamFull := a.filesHost + "/packages/" + filePath

	// uv requests .metadata files — proxy those directly without scanning.
	if strings.HasSuffix(filePath, ".metadata") {
		a.proxyDirect(w, r, upstreamFull)
		return
	}

	a.downloadScanServe(w, r, upstreamFull, filePath)
}

// downloadScanServe is the core scan pipeline.
func (a *PyPIAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, upstreamURL, filePath string) {
	ctx := r.Context()

	// Derive a simple artifact identifier from the path for DB/cache lookups.
	// We use path components: packages/<first>/<second>/<filename>
	parts := strings.Split(strings.Trim(filePath, "/"), "/")
	filename := parts[len(parts)-1]

	// Parse package name + version from filename (best-effort; PEP 427 wheel or sdist).
	pkgName, pkgVersion := parseFilename(filename)

	// Validate filename for safe use in artifact ID and cache paths.
	if err := validateFilename(filename); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: err.Error(),
		})
		return
	}

	artifactID := PyPIArtifactID(pkgName, pkgVersion, filename)

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		// Cached — check status before serving. Fail closed on DB errors.
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("failed to check artifact status, refusing to serve")
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
		// Tag mutability check on cache hit.
		if adapter.HandleTagMutability(ctx, a.tagMutabilityCfg, a.db, a.httpClient,
			string(scanner.EcosystemPyPI), pkgName, pkgVersion, artifactID, upstreamURL, r, w) {
			return
		}
		// Serve from cache.
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("pypi: serving from cache")
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
			ID: artifactID, Ecosystem: scanner.EcosystemPyPI, Name: pkgName, Version: pkgVersion, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Pre-scan for typosquatting BEFORE contacting upstream.
	// The typosquat scanner only needs the package name — no file content.
	// Blocking here avoids 502s for non-existent typosquat packages and
	// prevents the proxy from fetching known-bad names.
	if result, ok := a.scanEngine.PreScanTyposquat(ctx, pkgName, scanner.EcosystemPyPI); ok {
		if result.Verdict == scanner.VerdictSuspicious || result.Verdict == scanner.VerdictMalicious {
			log.Warn().Str("artifact", artifactID).Str("verdict", string(result.Verdict)).
				Float32("confidence", result.Confidence).Msg("typosquat pre-scan: blocked before upstream fetch")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "blocked",
				Artifact: artifactID,
				Reason:   "typosquatting detected: " + result.Findings[0].Description,
			})
			_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: artifactID,
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     "typosquat pre-scan: " + string(result.Verdict),
			})
			return
		}
	}

	// 3. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context for the pipeline operations.
	// Cloud storage backends (Azure Blob, S3) honor context cancellation;
	// if the client disconnects mid-scan the upload would be aborted,
	// leaving the artifact uncached. Using a dedicated pipeline context
	// ensures download, scan, and cache write always complete.
	pctx, pcancel := adapter.PipelineContext()
	defer pcancel()

	// Re-check cache after acquiring lock — another request may have completed the pipeline.
	if cachedPath, err := a.cache.Get(pctx, artifactID); err == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("failed to check artifact status, refusing to serve")
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
	tmpPath, size, sha, err := downloadToTemp(pctx, upstreamURL, a.httpClient)
	if err != nil {
		http.Error(w, "failed to fetch upstream package", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// 3. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemPyPI,
		Name:        pkgName,
		Version:     pkgVersion,
		LocalPath:   tmpPath,
		Filename:    filename,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("pypi: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("scan engine error, failing open")
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
		l.Msg("scan result")
	}

	// 5. Policy evaluation.
	policyResult := a.policyEngine.Evaluate(pctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("policy decision")

	// 6. Act on policy result.
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

	case policy.ActionAllowWithWarning:
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
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
	}

	// 7. Allow — cache artifact and serve.
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
func (a *PyPIAdapter) persistArtifact(
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

// proxyUpstream forwards a GET request to the upstream and relays the response.
func (a *PyPIAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
	target, err := url.JoinPath(a.upstreamURL, path)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	// Forward relevant headers.
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// proxyDirect fetches the given absolute URL and relays the response.
func (a *PyPIAdapter) proxyDirect(w http.ResponseWriter, r *http.Request, target string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
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

// pypiDownloadURLRe matches PyPI download URLs (files.pythonhosted.org).
var pypiDownloadURLRe = regexp.MustCompile(`https://files\.pythonhosted\.org/packages/`)

// proxyUpstreamRewrite fetches the upstream simple page and rewrites download
// URLs from files.pythonhosted.org to relative /packages/ paths so that
// package downloads are routed through the scan pipeline.
func (a *PyPIAdapter) proxyUpstreamRewrite(w http.ResponseWriter, r *http.Request, path string) {
	target, err := url.JoinPath(a.upstreamURL, path)
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

	// Cap metadata responses at 10 MB to prevent DoS from malicious upstreams.
	const maxMetadataSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Rewrite absolute download URLs to proxy-relative paths.
	rewritten := pypiDownloadURLRe.ReplaceAll(body, []byte("/packages/"))

	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue // length changed after rewrite
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rewritten)
}

// downloadToTemp downloads url into a temporary file, returning (path, size, sha256hex, error).
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("pypi: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-pypi-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	// Cap artifact download at 2 GB to prevent disk exhaustion from malicious upstreams.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("pypi: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

// parseFilename extracts (packageName, version) from a PyPI filename.
// It handles both wheel (.whl) and sdist (.tar.gz, .zip) conventions.
// Falls back to (filename, "unknown") on parse failure.
func parseFilename(filename string) (string, string) {
	// Wheel: name-version-pythonX-abiX-platformX.whl
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.SplitN(strings.TrimSuffix(filename, ".whl"), "-", 3)
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	// sdist .tar.gz
	if strings.HasSuffix(filename, ".tar.gz") {
		base := strings.TrimSuffix(filename, ".tar.gz")
		idx := strings.LastIndex(base, "-")
		if idx > 0 {
			return base[:idx], base[idx+1:]
		}
	}
	// .zip
	if strings.HasSuffix(filename, ".zip") {
		base := strings.TrimSuffix(filename, ".zip")
		idx := strings.LastIndex(base, "-")
		if idx > 0 {
			return base[:idx], base[idx+1:]
		}
	}
	return filename, "unknown"
}
