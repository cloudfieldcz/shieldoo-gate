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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*PyPIAdapter)(nil)

// PyPIAdapter proxies PyPI Simple API (PEP 503) and package downloads.
type PyPIAdapter struct {
	db           *sqlx.DB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstreamURL  string
	router       http.Handler
	httpClient   *http.Client
}

// NewPyPIAdapter creates and wires a PyPIAdapter.
func NewPyPIAdapter(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
) *PyPIAdapter {
	a := &PyPIAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstreamURL:  strings.TrimRight(upstreamURL, "/"),
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
	}
	a.router = a.buildRouter()
	return a
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

// handleSimplePackage proxies the per-package simple page.
func (a *PyPIAdapter) handleSimplePackage(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
			Reason: err.Error(),
		})
		return
	}
	a.proxyUpstream(w, r, "/simple/"+pkg+"/")
}

// handlePackageDownload runs the full download → scan → policy → serve pipeline.
func (a *PyPIAdapter) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	// chi's wildcard strip leaves "packages/" prefix intact — we just forward the full path.
	filePath := chi.URLParam(r, "*")
	upstreamPath := "/packages/" + filePath

	// Build a synthetic artifact identifier from the URL path.
	// Full scan-based identification is done after download.
	upstreamFull := a.upstreamURL + upstreamPath

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
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemPyPI), pkgName, pkgVersion)

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		// Cached — check status before serving.
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err == nil && status != nil && status.Status == model.StatusQuarantined {
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
		// Serve from cache.
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		return
	}

	// 2. Download to temp file.
	tmpPath, size, sha, err := downloadToTemp(ctx, upstreamURL, a.httpClient)
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
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	scanResults, err := a.scanEngine.ScanAll(ctx, scanArtifact)
	if err != nil {
		// Fail open.
		scanResults = nil
	}

	// 5. Policy evaluation.
	policyResult := a.policyEngine.Evaluate(ctx, scanArtifact, scanResults)

	// 6. Act on policy result.
	switch policyResult.Action {
	case policy.ActionBlock:
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
	}

	// 7. Allow — cache artifact and serve.
	_ = a.cache.Put(ctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	http.ServeFile(w, r, tmpPath)
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
	if err := adapter.InsertArtifact(a.db, art, artStatus); err != nil {
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

	size, err := io.Copy(mw, resp.Body)
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
