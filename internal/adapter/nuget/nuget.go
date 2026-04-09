// Package nuget implements a NuGet V3 API proxy adapter.
package nuget

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
var _ adapter.Adapter = (*NuGetAdapter)(nil)

// NuGetAdapter proxies NuGet V3 API requests and scans .nupkg downloads.
type NuGetAdapter struct {
	db               *config.GateDB
	cache            cache.CacheStore
	scanEngine       *scanner.Engine
	policyEngine     *policy.Engine
	upstreamURL      string
	router           http.Handler
	httpClient       *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

// NewNuGetAdapter creates and wires a NuGetAdapter.
func NewNuGetAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
	tagMutabilityCfg config.TagMutabilityConfig,
) *NuGetAdapter {
	a := &NuGetAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(upstreamURL, "/"),
		httpClient:        adapter.NewProxyHTTPClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *NuGetAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemNuGet }

// HealthCheck implements adapter.Adapter.
func (a *NuGetAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/v3/index.json", nil)
	if err != nil {
		return fmt.Errorf("nuget: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("nuget: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nuget: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *NuGetAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates chi routes for the NuGet V3 API.
func (a *NuGetAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// Service index (NuGet V3 entry point).
	r.Get("/v3/index.json", a.handleServiceIndex)

	// Package registration (metadata).
	r.Get("/v3/registration/{id}/index.json", a.handleRegistration)

	// Flat container — package download.
	// Route: /v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg
	r.Get("/v3-flatcontainer/{id}/{version}/{filename}", a.handleNupkgDownload)

	// Catch-all for additional NuGet V3 resources (repository-signatures,
	// vulnerability info, etc.) — proxy to upstream without scanning.
	r.Get("/*", a.handlePassthrough)

	return r
}

// handleServiceIndex proxies the NuGet V3 service index, rewriting upstream
// URLs so the NuGet client routes all subsequent requests through the proxy.
// When serving over HTTP, RepositorySignatures resources are stripped because
// the NuGet client requires them to be served over HTTPS (NU1301).
func (a *NuGetAdapter) handleServiceIndex(w http.ResponseWriter, r *http.Request) {
	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if isHTTPS {
		a.proxyUpstreamRewrite(w, r, "/v3/index.json")
		return
	}

	// HTTP mode: fetch, rewrite, and strip RepositorySignatures resources.
	target, err := url.JoinPath(a.upstreamURL, "/v3/index.json")
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

	const maxMetadataSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Rewrite upstream URLs to proxy URLs.
	rewritten := strings.ReplaceAll(string(body), a.upstreamURL+"/", "http://"+r.Host+"/")

	// Strip RepositorySignatures resources — NuGet requires HTTPS for them.
	rewritten = stripRepositorySignatures(rewritten)

	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.WriteString(w, rewritten)
}

// stripRepositorySignatures removes RepositorySignatures resources from a
// NuGet V3 service index JSON. These resources require HTTPS and would cause
// NU1301 errors when the proxy is accessed over plain HTTP.
func stripRepositorySignatures(body string) string {
	var index struct {
		Version   string            `json:"version"`
		Resources []json.RawMessage `json:"resources"`
	}
	if err := json.Unmarshal([]byte(body), &index); err != nil {
		return body // not valid JSON, return as-is
	}

	var filtered []json.RawMessage
	for _, raw := range index.Resources {
		var res struct {
			Type string `json:"@type"`
		}
		if err := json.Unmarshal(raw, &res); err == nil {
			if strings.HasPrefix(res.Type, "RepositorySignatures") {
				continue
			}
		}
		filtered = append(filtered, raw)
	}
	index.Resources = filtered

	out, err := json.Marshal(index)
	if err != nil {
		return body
	}
	return string(out)
}

// handleRegistration proxies package registration (metadata) responses,
// rewriting upstream URLs so flat-container downloads go through the proxy.
func (a *NuGetAdapter) handleRegistration(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := adapter.ValidatePackageName(id); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package id",
			Reason: err.Error(),
		})
		return
	}
	a.proxyUpstreamRewrite(w, r, "/v3/registration/"+id+"/index.json")
}

// handlePassthrough proxies unrecognized NuGet API paths to upstream.
// This handles ancillary resources like repository-signatures, vulnerability
// info, and other V3 endpoints that don't need scanning.
// Only paths starting with known NuGet V3 prefixes are allowed.
func (a *NuGetAdapter) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	allowed := strings.HasPrefix(path, "/v3/") ||
		strings.HasPrefix(path, "/v3-flatcontainer/") ||
		strings.HasPrefix(path, "/v3-index/") ||
		strings.HasPrefix(path, "/v3-vulnerabilities/")
	if !allowed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	a.proxyUpstream(w, r, path)
}

// handleNupkgDownload runs the scan pipeline for .nupkg files.
func (a *NuGetAdapter) handleNupkgDownload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	filename := chi.URLParam(r, "filename")

	if err := adapter.ValidatePackageName(id); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package id",
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

	upstreamPath := "/v3-flatcontainer/" + id + "/" + version + "/" + filename
	a.downloadScanServe(w, r, a.upstreamURL+upstreamPath, id, version)
}

// downloadScanServe is the core scan pipeline for .nupkg packages.
func (a *NuGetAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, upstreamURL, pkgID, version string) {
	ctx := r.Context()
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemNuGet), pkgID, version)

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
			string(scanner.EcosystemNuGet), pkgID, version, artifactID, upstreamURL, r, w) {
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("nuget: serving from cache")
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
			ID: artifactID, Ecosystem: scanner.EcosystemNuGet, Name: pkgID, Version: version, LocalPath: cachedPath,
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
	tmpPath, size, sha, err := downloadToTemp(pctx, upstreamURL, a.httpClient)
	if err != nil {
		http.Error(w, "failed to fetch upstream package", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// 3. Build scanner artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemNuGet,
		Name:        pkgID,
		Version:     version,
		LocalPath:   tmpPath,
		Filename:    pkgID + "." + version + ".nupkg",
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("nuget: starting scan pipeline")
	scanResults, _ := a.scanEngine.ScanAll(pctx, scanArtifact)

	// 5. Policy.
	policyResult := a.policyEngine.Evaluate(pctx, scanArtifact, scanResults)

	// 6. Act.
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

	// 7. Allow.
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

// persistArtifact writes artifact, status, and scan results to the DB.
func (a *NuGetAdapter) persistArtifact(
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
func (a *NuGetAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
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

// proxyUpstreamRewrite fetches the upstream response and rewrites all
// occurrences of the upstream base URL with the proxy's own base URL
// (http://{r.Host}). This ensures that absolute URLs embedded in JSON
// responses (e.g. the NuGet V3 service index or registration pages) point
// back through the proxy so that package downloads are routed through the
// scan pipeline.
func (a *NuGetAdapter) proxyUpstreamRewrite(w http.ResponseWriter, r *http.Request, path string) {
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

	// Replace upstream base URL with the proxy's own URL so that all
	// discovery URLs in service index and registration responses resolve
	// through the proxy rather than hitting api.nuget.org directly.
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	rewritten := strings.ReplaceAll(string(body), a.upstreamURL+"/", scheme+"://"+r.Host+"/")

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
	_, _ = io.WriteString(w, rewritten)
}

// downloadToTemp downloads url to a temp file, returning (path, size, sha256hex, error).
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("nuget: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("nuget: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("nuget: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-nuget-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("nuget: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	// Cap artifact download at 2 GB to prevent disk exhaustion from malicious upstreams.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("nuget: download: writing temp file: %w", err)
	}
	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
