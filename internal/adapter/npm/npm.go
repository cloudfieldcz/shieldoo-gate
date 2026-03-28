// Package npm implements a proxy adapter for the npm Registry API.
package npm

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
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*NPMAdapter)(nil)

// NPMAdapter proxies the npm Registry API and tarball downloads.
type NPMAdapter struct {
	db               *config.GateDB
	cache            cache.CacheStore
	scanEngine       *scanner.Engine
	policyEngine     *policy.Engine
	upstreamURL      string
	router           http.Handler
	httpClient       *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

// NewNPMAdapter creates and wires an NPMAdapter.
func NewNPMAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
	tagMutabilityCfg config.TagMutabilityConfig,
) *NPMAdapter {
	a := &NPMAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(upstreamURL, "/"),
		httpClient:        &http.Client{Timeout: 5 * time.Minute},
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *NPMAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemNPM }

// HealthCheck implements adapter.Adapter.
func (a *NPMAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/", nil)
	if err != nil {
		return fmt.Errorf("npm: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("npm: health check: %w", err)
	}
	resp.Body.Close()
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *NPMAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates chi routes for the npm Registry API.
func (a *NPMAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// Scoped package support: @scope/name
	r.Get("/{package}", a.handlePackageMetadata)
	r.Get("/{package}/{version}", a.handleVersionMetadata)
	r.Get("/{package}/-/{tarball}", a.handleTarballDownload)

	// Scoped packages: /@scope/name, /@scope/name/version, /@scope/name/-/tarball
	r.Get("/@{scope}/{package}", a.handleScopedMetadata)
	r.Get("/@{scope}/{package}/{version}", a.handleScopedVersionMetadata)
	r.Get("/@{scope}/{package}/-/{tarball}", a.handleScopedTarballDownload)

	return r
}

// handlePackageMetadata proxies the package metadata JSON, rewriting tarball
// URLs so that downloads are routed through the proxy's scan pipeline.
func (a *NPMAdapter) handlePackageMetadata(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
			Reason: err.Error(),
		})
		return
	}
	a.proxyUpstreamRewrite(w, r, "/"+pkg)
}

// handleVersionMetadata proxies version-specific metadata JSON.
func (a *NPMAdapter) handleVersionMetadata(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	version := chi.URLParam(r, "version")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name"})
		return
	}
	a.proxyUpstream(w, r, "/"+pkg+"/"+version)
}

// handleTarballDownload runs the scan pipeline for npm tarballs.
func (a *NPMAdapter) handleTarballDownload(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	tarball := chi.URLParam(r, "tarball")
	upstreamPath := "/" + pkg + "/-/" + tarball
	a.downloadScanServe(w, r, a.upstreamURL+upstreamPath, pkg, tarball)
}

// handleScopedMetadata proxies metadata for @scope/package, rewriting tarball
// URLs so that downloads are routed through the proxy's scan pipeline.
func (a *NPMAdapter) handleScopedMetadata(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(scope); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid scope name"})
		return
	}
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name"})
		return
	}
	a.proxyUpstreamRewrite(w, r, "/@"+scope+"/"+pkg)
}

// handleScopedVersionMetadata proxies version metadata for @scope/package/version.
func (a *NPMAdapter) handleScopedVersionMetadata(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	pkg := chi.URLParam(r, "package")
	version := chi.URLParam(r, "version")
	if err := adapter.ValidatePackageName(scope); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid scope name"})
		return
	}
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name"})
		return
	}
	a.proxyUpstream(w, r, "/@"+scope+"/"+pkg+"/"+version)
}

// handleScopedTarballDownload runs the scan pipeline for scoped tarballs.
func (a *NPMAdapter) handleScopedTarballDownload(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	pkg := chi.URLParam(r, "package")
	tarball := chi.URLParam(r, "tarball")
	if err := adapter.ValidatePackageName(scope); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid scope name"})
		return
	}
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name"})
		return
	}
	upstreamPath := "/@" + scope + "/" + pkg + "/-/" + tarball
	fullPkg := "@" + scope + "/" + pkg
	a.downloadScanServe(w, r, a.upstreamURL+upstreamPath, fullPkg, tarball)
}

// downloadScanServe is the core scan pipeline for npm tarballs.
func (a *NPMAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, upstreamURL, pkgName, tarball string) {
	ctx := r.Context()

	// Extract version from tarball name: pkgname-1.2.3.tgz
	version := extractNPMVersion(pkgName, tarball)

	// Sanitize package name for use as artifact ID component.
	safeNamePart := strings.NewReplacer("/", "_", "@", "").Replace(pkgName)
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemNPM), safeNamePart, version)

	// 1. Check cache.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		// Fail closed: refuse to serve if we cannot verify artifact status.
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
		// Tag mutability check on cache hit.
		if adapter.HandleTagMutability(ctx, a.tagMutabilityCfg, a.db, a.httpClient,
			string(scanner.EcosystemNPM), pkgName, version, artifactID, upstreamURL, r, w) {
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
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Re-check cache after acquiring lock.
	if cachedPath, err := a.cache.Get(ctx, artifactID); err == nil {
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

	// 3. Download.
	tmpPath, size, sha, err := downloadToTemp(ctx, upstreamURL, a.httpClient)
	if err != nil {
		http.Error(w, "failed to fetch upstream package", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// 3. Build scanner artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemNPM,
		Name:        pkgName,
		Version:     version,
		LocalPath:   tmpPath,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	scanResults, _ := a.scanEngine.ScanAll(ctx, scanArtifact)

	// 5. Policy.
	policyResult := a.policyEngine.Evaluate(ctx, scanArtifact, scanResults)

	// 6. Act.
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

	// 7. Allow.
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

// persistArtifact writes artifact, status, and scan results to the DB.
func (a *NPMAdapter) persistArtifact(
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

// proxyUpstream forwards a request to the upstream registry.
func (a *NPMAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
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

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// proxyUpstreamRewrite fetches the upstream metadata JSON and rewrites tarball
// URLs so that npm clients download packages through the proxy's scan pipeline
// rather than directly from the upstream registry.
//
// The upstream registry embeds absolute tarball URLs such as:
//
//	"tarball":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"
//
// This method replaces the upstream origin (a.upstreamURL + "/") with the
// proxy's own origin ("http://" + r.Host + "/") so the npm client follows
// URLs that route back through the proxy.
func (a *NPMAdapter) proxyUpstreamRewrite(w http.ResponseWriter, r *http.Request, path string) {
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

	// Rewrite upstream tarball URLs to proxy-relative URLs so downloads pass
	// through the scan pipeline. Detect scheme from the incoming request.
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	old := []byte(`"` + a.upstreamURL + "/")
	replacement := []byte(`"` + scheme + "://" + r.Host + "/")
	rewritten := strings.ReplaceAll(string(body), string(old), string(replacement))

	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue // length may have changed after rewrite
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write([]byte(rewritten))
}

// downloadToTemp downloads url to a temp file, returning (path, size, sha256hex, error).
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("npm: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("npm: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("npm: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-npm-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("npm: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	// Cap artifact download at 2 GB to prevent disk exhaustion from malicious upstreams.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("npm: download: writing temp file: %w", err)
	}
	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

// extractNPMVersion parses the version from an npm tarball filename.
// npm tarballs are typically: pkgname-1.2.3.tgz
func extractNPMVersion(pkgName, tarball string) string {
	// For scoped packages @scope/pkg, the tarball uses just "pkg" as prefix.
	baseName := pkgName
	if idx := strings.LastIndex(baseName, "/"); idx >= 0 {
		baseName = baseName[idx+1:]
	}
	// Strip leading @ if still present.
	baseName = strings.TrimPrefix(baseName, "@")

	// Strip extension.
	tarball = strings.TrimSuffix(tarball, ".tgz")
	tarball = strings.TrimSuffix(tarball, ".tar.gz")

	// Remove package name prefix + dash.
	prefix := baseName + "-"
	if strings.HasPrefix(tarball, prefix) {
		return tarball[len(prefix):]
	}
	return "unknown"
}
