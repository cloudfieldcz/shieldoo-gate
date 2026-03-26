// Package nuget implements a NuGet V3 API proxy adapter.
package nuget

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
var _ adapter.Adapter = (*NuGetAdapter)(nil)

// NuGetAdapter proxies NuGet V3 API requests and scans .nupkg downloads.
type NuGetAdapter struct {
	db           *sqlx.DB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstreamURL  string
	router       http.Handler
	httpClient   *http.Client
}

// NewNuGetAdapter creates and wires a NuGetAdapter.
func NewNuGetAdapter(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
) *NuGetAdapter {
	a := &NuGetAdapter{
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

	return r
}

// handleServiceIndex proxies the NuGet V3 service index.
func (a *NuGetAdapter) handleServiceIndex(w http.ResponseWriter, r *http.Request) {
	a.proxyUpstream(w, r, "/v3/index.json")
}

// handleRegistration proxies package registration (metadata) responses.
func (a *NuGetAdapter) handleRegistration(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := adapter.ValidatePackageName(id); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package id",
			Reason: err.Error(),
		})
		return
	}
	a.proxyUpstream(w, r, "/v3/registration/"+id+"/index.json")
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
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err == nil && status != nil && status.Status == model.StatusQuarantined {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "quarantined",
				Artifact: artifactID,
				Reason:   status.QuarantineReason,
			})
			return
		}
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		return
	}

	// 2. Download.
	tmpPath, size, sha, err := downloadToTemp(ctx, upstreamURL, a.httpClient)
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
	if err := adapter.InsertArtifact(a.db, art, artStatus); err != nil {
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
	size, err := io.Copy(mw, resp.Body)
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("nuget: download: writing temp file: %w", err)
	}
	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
