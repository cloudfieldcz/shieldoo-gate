// Package npm implements a proxy adapter for the npm Registry API.
package npm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	upstreamURL      string // default index base (back-compat; == resolver default)
	resolver         *adapter.UpstreamResolver
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
	upstreams config.UpstreamSet,
	tagMutabilityCfg config.TagMutabilityConfig,
) *NPMAdapter {
	defaultURL := upstreams.DefaultOr("https://registry.npmjs.org")
	resolver, err := adapter.NewUpstreamResolver("npm", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		// Validation happened at config load; a build error here is a programming bug.
		panic(fmt.Sprintf("npm: building upstream resolver: %v", err))
	}
	a := &NPMAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(defaultURL, "/"),
		resolver:         resolver,
		// Redirect-safe client (Phase 2): strips per-index Authorization on a
		// cross-host/scheme redirect so private-index tokens never leak.
		httpClient:       adapter.NewRedirectSafeClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *NPMAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemNPM }

// DB exposes the adapter's database handle for tests.
func (a *NPMAdapter) DB() *config.GateDB { return a.db }

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

	// npm clients (v7+) percent-encode the "/" in scoped package names,
	// sending e.g. /@alloc%2fquick-lru instead of /@alloc/quick-lru.
	// Decode %2f before routing so Chi can match the scoped routes.
	r.Use(decodeScopedPath)

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

// decodeScopedPath is middleware that decodes percent-encoded slashes in
// scoped npm package paths (e.g. /@scope%2fpkg → /@scope/pkg).
func decodeScopedPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawPath, "%2f") || strings.Contains(r.URL.RawPath, "%2F") {
			decoded, err := url.PathUnescape(r.URL.RawPath)
			if err == nil && decoded != r.URL.RawPath {
				r2 := r.Clone(r.Context())
				r2.URL.Path = decoded
				r2.URL.RawPath = ""
				next.ServeHTTP(w, r2)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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
	// Pre-scan for typosquatting BEFORE contacting upstream.
	if a.blockIfTyposquat(w, r, pkg, "") {
		return
	}
	a.serveMetadataFanOut(w, r, pkg, "/"+pkg)
}

// handleVersionMetadata proxies version-specific metadata JSON.
func (a *NPMAdapter) handleVersionMetadata(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	version := chi.URLParam(r, "version")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name"})
		return
	}
	if a.blockIfTyposquat(w, r, pkg, version) {
		return
	}
	a.proxyUpstream(w, r, "/"+pkg+"/"+version)
}

// handleTarballDownload runs the scan pipeline for npm tarballs.
func (a *NPMAdapter) handleTarballDownload(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	tarball := chi.URLParam(r, "tarball")
	idx := a.firstIndexFor(pkg)
	upstreamURL := strings.TrimRight(idx.URL, "/") + "/" + pkg + "/-/" + tarball
	a.downloadScanServe(w, r, upstreamURL, pkg, tarball, idx)
}

// firstIndexFor recovers the serving index for a download by re-resolving the
// package name (the npm download routes carry the package id, so resolution is
// deterministic — no /ext-packages/ route needed). Returns the default index
// when resolution is empty (a scoped-miss tarball: the download then fails on
// the absent upstream, which is correct — no public fallback).
func (a *NPMAdapter) firstIndexFor(pkg string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(pkg); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default index (Name "", URL "")
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
	if a.blockIfTyposquat(w, r, "@"+scope+"/"+pkg, "") {
		return
	}
	a.serveMetadataFanOut(w, r, "@"+scope+"/"+pkg, "/@"+scope+"/"+pkg)
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
	if a.blockIfTyposquat(w, r, "@"+scope+"/"+pkg, version) {
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
	fullPkg := "@" + scope + "/" + pkg
	idx := a.firstIndexFor(fullPkg)
	upstreamURL := strings.TrimRight(idx.URL, "/") + "/@" + scope + "/" + pkg + "/-/" + tarball
	a.downloadScanServe(w, r, upstreamURL, fullPkg, tarball, idx)
}

// downloadScanServe is the core scan pipeline for npm tarballs. idx is the
// serving index recovered by re-resolution; its name namespaces the artifact ID
// (eco__<index>) and its auth header is attached to the upstream download.
func (a *NPMAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, upstreamURL, pkgName, tarball string, idx adapter.ResolvedIndex) {
	ctx := r.Context()

	// Extract version from tarball name: pkgname-1.2.3.tgz
	version := extractNPMVersion(pkgName, tarball)

	// Sanitize package name for use as artifact ID component.
	safeNamePart := strings.NewReplacer("/", "_", "@", "").Replace(pkgName)
	eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNPM), idx.Name)
	artifactID := fmt.Sprintf("%s:%s:%s", eco, safeNamePart, version)
	authHeader := a.resolver.AuthHeader(idx)

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
		// Tag mutability check on cache hit.
		if adapter.HandleTagMutability(ctx, a.tagMutabilityCfg, a.db, a.httpClient,
			string(scanner.EcosystemNPM), pkgName, version, artifactID, upstreamURL, r, w) {
			return
		}
		// License policy gate — blocks if the artifact's license is disallowed
		// by the current policy, even though artifact_status is CLEAN.
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("npm: serving from cache")
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
			ID: artifactID, Ecosystem: scanner.Ecosystem(eco), Name: pkgName, Version: version, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Pre-scan for typosquatting BEFORE contacting upstream.
	if a.blockIfTyposquat(w, r, pkgName, version) {
		return
	}

	// 3. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context — see PyPI adapter for rationale.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()

	// Re-check cache after acquiring lock.
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

	// 3. Download (with per-index auth, if the serving index is authenticated).
	tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, authHeader, a.httpClient)
	if err != nil {
		http.Error(w, "failed to fetch upstream package", http.StatusBadGateway)
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

	// 3. Build scanner artifact. Ecosystem carries the namespaced segment
	// (npm__<index>) so the persisted artifact row + cache isolate per index,
	// matching the PyPI reference (the artifact ID already encodes it).
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.Ecosystem(eco),
		Name:        pkgName,
		Version:     version,
		LocalPath:   tmpPath,
		Filename:    tarball,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("npm: starting scan pipeline")
	scanReport, _ := a.scanEngine.ScanAll(pctx, scanArtifact)
	scanResults := scanReport.Results

	// 5. Policy.
	policyResult := a.policyEngine.EvaluateReport(pctx, scanArtifact, scanReport)
	if len(policyResult.ScanUnavailable) > 0 {
		adapter.AuditScanUnavailable(r.Context(), a.db, policyResult, artifactID, "pull", r.RemoteAddr, r.UserAgent())
	}

	// 6. Act.
	switch policyResult.Action {
	case policy.ActionRetryLater:
		adapter.WriteRetryLater(w, artifactID, policyResult.Reason, a.policyEngine.RetryAfter())
		return

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

	case policy.ActionAllowWithWarning:
		_ = a.cache.Put(pctx, scanArtifact, tmpPath)
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
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

	// 7. Allow.
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
	adapter.ApplyPolicyWarnings(w, r.Context(), a.db, artifactID, policyResult.Warnings)
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
	if err := adapter.InsertArtifact(a.db, artifactID, art, artStatus); err != nil {
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

// proxyOrigin returns the gate's own "<scheme>://<host>" origin (no trailing
// slash), used to rewrite upstream download URLs so clients route back through
// the scan pipeline.
func proxyOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// serveMetadataFanOut tries each resolved index for the package's metadata,
// rewriting the FIRST index that has it (200) so tarball downloads route back
// through the proxy. The default index uses the legacy serving-origin string
// replace (byte-identical to today); extra indexes use the JSON-aware
// fail-closed adapter.RewriteNPMPackumentTarballs. A claimed-namespace miss
// (no serving index) → 404 + namespaced BLOCKED audit (no public fallback).
func (a *NPMAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, pkg, path string) {
	for _, idx := range a.resolver.ResolveForPackage(pkg) {
		served, err := a.tryServeMetadata(w, r, idx, path)
		if err != nil {
			a.resolver.ObserveProbe(idx.Name, "error")
			continue
		}
		if served {
			a.resolver.ObserveProbe(idx.Name, "hit")
			return
		}
		a.resolver.ObserveProbe(idx.Name, "miss")
	}

	if claimants := a.resolver.ClaimingIndexNames(pkg); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNPM), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		safe := strings.NewReplacer("/", "_", "@", "").Replace(pkg)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, safe),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index package not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: pkg})
}

// tryServeMetadata fetches one index's metadata at path. Returns (true,nil) when
// served (200, rewritten + relayed); (false,nil) on 404; (false,err) on
// transport / non-200 / read error. A rewrite failure for an EXTRA index is FAIL
// CLOSED: it writes a 502 and returns (true,nil) so no other index is tried (the
// page we could not safely route must never reach the client).
func (a *NPMAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, path string) (bool, error) {
	target := strings.TrimRight(idx.URL, "/") + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	if h := a.resolver.AuthHeader(idx); h != "" {
		req.Header.Set("Authorization", h)
	}
	resp, err := a.resolver.Client().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("npm: index %q returned %d", idx.Name, resp.StatusCode)
	}

	// Cap metadata responses at 200 MB to prevent DoS from malicious upstreams.
	// Read one extra byte to distinguish "fits" from "exceeds" so we error out
	// cleanly instead of silently truncating the packument JSON.
	const maxMetadataSize = 200 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("npm: index %q metadata exceeds size limit", idx.Name)
	}

	var rewritten []byte
	if idx.Name == "" {
		// DEFAULT index: legacy serving-origin string replace (byte-identical).
		old := []byte(`"` + a.upstreamURL + "/")
		rewritten = []byte(strings.ReplaceAll(string(body), string(old), `"`+proxyOrigin(r)+"/"))
	} else {
		// EXTRA index: JSON-aware fail-closed tarball rewrite.
		var rerr error
		rewritten, rerr = adapter.RewriteNPMPackumentTarballs(body, idx, proxyOrigin(r))
		if rerr != nil {
			log.Error().Err(rerr).Str("index", idx.Name).Msg("SECURITY: npm packument rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
	}

	relayMetadataHeaders(w, resp, idx.Name)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rewritten)
	return true, nil
}

// relayMetadataHeaders copies upstream response headers. Extra (low-trust)
// indexes get an allowlist only (Content-Type/ETag/Last-Modified) to prevent a
// private index from injecting Set-Cookie/CSP/Link; the default index relays all
// headers (minus Content-Length, which the rewrite changed).
func relayMetadataHeaders(w http.ResponseWriter, resp *http.Response, indexName string) {
	if indexName != "" {
		for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		return
	}
	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
}

// downloadToTempAuthed downloads url to a temp file, returning (path, size,
// sha256hex, error). When authHeader is non-empty it is sent as the
// Authorization header (per-index private-registry credential); the client must
// be redirect-safe so the header is stripped on a cross-host/scheme redirect.
func downloadToTempAuthed(ctx context.Context, rawURL, authHeader string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("npm: download: building request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
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

// blockIfTyposquat runs the typosquat pre-scan and returns true if the
// request was blocked (response already written). Returns false if the
// package name is clean, the scanner is not available, or an active policy
// override permits the package through. Pass version="" for name-only
// pre-scans (metadata fetches); pass the real version on tarball requests
// so version-scoped overrides match.
func (a *NPMAdapter) blockIfTyposquat(w http.ResponseWriter, r *http.Request, pkgName, version string) bool {
	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), pkgName, scanner.EcosystemNPM)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	// Build the canonical artifact ID up front so audit logs (override-allowed
	// path included) and the synthetic-row write all reference the same ID.
	// Sanitization mirrors downloadScanServe so a later cache fetch lines up.
	// Synthetic typosquat rows always carry version="*" — override scope is
	// package-wide because typosquat detection is name-based.
	safeNamePart := strings.NewReplacer("/", "_", "@", "").Replace(pkgName)
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemNPM), safeNamePart, adapter.TyposquatPlaceholderVersion)

	// Detached audit context — the request may be canceled (slow client) but
	// audit-log writes must still land. Mirrors policy.hasDBOverride rationale.
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	// Active policy override allows the request through.
	if a.policyEngine != nil {
		if overrideID, ok := a.policyEngine.HasOverride(r.Context(), scanner.EcosystemNPM, pkgName, version); ok {
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

	// Persist a synthetic artifact + status + scan_results so the block is
	// visible in the Artifacts pane and overridable from there.
	if err := adapter.PersistTyposquatBlock(a.db, artifactID, scanner.EcosystemNPM, pkgName, result, time.Now().UTC()); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("typosquat pre-scan: failed to persist block record")
	}

	// Public 403 response: keep the reason generic so we don't leak which
	// popular package the seed flagged us against (an attacker probing names
	// could enumerate the seed otherwise). The full description still lands
	// in scan_results.findings_json and audit_log.reason for admins.
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
