// Package docker implements a read-only OCI Distribution Spec pull proxy adapter.
package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*DockerAdapter)(nil)

// DockerAdapter proxies OCI Distribution Spec read-only pull requests to an
// upstream registry (e.g. Docker Hub, GHCR, private registry).
//
// Manifests are scanned via Trivy before being served. Blobs are passed
// through directly since scanning happens at the manifest/image level.
type DockerAdapter struct {
	db          *config.GateDB
	cache       cache.CacheStore
	scanEngine  *scanner.Engine
	policyEng   *policy.Engine
	resolver    *RegistryResolver
	cfg         config.DockerUpstreamConfig
	router      http.Handler
	httpClient  *http.Client
	tokenExch   *tokenExchanger
	blobStore   *BlobStore
	pushHandler *pushHandler
}

// NewDockerAdapter creates and wires a DockerAdapter.
// If cfg.Push.Enabled, automatically initializes push support with a
// BlobStore at os.TempDir()/shieldoo-gate-blobs.
func NewDockerAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	cfg config.DockerUpstreamConfig,
) *DockerAdapter {
	httpClient := adapter.NewProxyHTTPClient(10 * time.Minute)
	a := &DockerAdapter{
		db:         db,
		cache:      cacheStore,
		scanEngine: scanEngine,
		policyEng:  policyEngine,
		resolver:   NewRegistryResolver(cfg),
		cfg:        cfg,
		httpClient: httpClient,
		tokenExch:  newTokenExchanger(httpClient),
	}
	if cfg.Push.Enabled {
		blobPath := filepath.Join(os.TempDir(), "shieldoo-gate-blobs")
		a.blobStore = NewBlobStore(blobPath)
		a.pushHandler = newPushHandler(a.blobStore)
	}
	a.router = a.buildRouter()
	return a
}

// NewDockerAdapterWithPush creates a DockerAdapter with push support enabled.
// The blobStore is used for storing pushed image blobs locally.
func NewDockerAdapterWithPush(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	cfg config.DockerUpstreamConfig,
	blobStore *BlobStore,
) *DockerAdapter {
	httpClient := adapter.NewProxyHTTPClient(10 * time.Minute)
	a := &DockerAdapter{
		db:         db,
		cache:      cacheStore,
		scanEngine: scanEngine,
		policyEng:  policyEngine,
		resolver:   NewRegistryResolver(cfg),
		cfg:        cfg,
		httpClient: httpClient,
		tokenExch:  newTokenExchanger(httpClient),
		blobStore:  blobStore,
	}
	if cfg.Push.Enabled && blobStore != nil {
		a.pushHandler = newPushHandler(blobStore)
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *DockerAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemDocker }

// HealthCheck implements adapter.Adapter.
func (a *DockerAdapter) HealthCheck(ctx context.Context) error {
	defaultURL := a.cfg.DefaultRegistry
	if defaultURL == "" {
		defaultURL = "https://registry-1.docker.io"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultURL+"/v2/", nil)
	if err != nil {
		return fmt.Errorf("docker: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("docker: health check: %w", err)
	}
	resp.Body.Close()
	// Docker registries return 200 or 401 (auth required) on /v2/ — both indicate the service is up.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("docker: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *DockerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates chi routes for the OCI Distribution Spec v2 API.
func (a *DockerAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// OCI v2 API version check.
	r.Get("/v2/", a.handleV2Check)

	// Manifests and blobs — image names can contain slashes (multi-component
	// names like "library/nginx" or "org/team/image"). We use a catch-all
	// route and parse the path manually.
	r.Get("/v2/*", a.handleV2Wildcard)

	// Push routes (POST/PUT/PATCH for uploads, HEAD for blob existence checks).
	r.Post("/v2/*", a.handleV2WildcardWrite)
	r.Put("/v2/*", a.handleV2WildcardWrite)
	r.Patch("/v2/*", a.handleV2WildcardWrite)
	r.Head("/v2/*", a.handleV2WildcardHead)

	return r
}

// handleV2Check responds with the Docker-Distribution-API-Version header as
// required by the OCI Distribution Spec. Responds locally without proxying.
func (a *DockerAdapter) handleV2Check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}

// handleV2Wildcard routes /v2/* requests to manifests or blobs handlers.
// It parses the path manually because OCI image names can contain slashes.
//
// Expected path forms:
//   - /v2/{name}/manifests/{ref}
//   - /v2/{name}/blobs/{digest}
func (a *DockerAdapter) handleV2Wildcard(w http.ResponseWriter, r *http.Request) {
	// chi wildcard gives us everything after /v2/
	wildcardPath := chi.URLParam(r, "*")

	// Try to match /manifests/ or /blobs/ as the last two-segment suffix.
	manifestsIdx := strings.LastIndex(wildcardPath, "/manifests/")
	blobsIdx := strings.LastIndex(wildcardPath, "/blobs/")

	switch {
	case manifestsIdx > 0:
		name := wildcardPath[:manifestsIdx]
		ref := wildcardPath[manifestsIdx+len("/manifests/"):]
		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		// For internal namespaces, try serving from BlobStore first.
		if a.pushHandler != nil && a.cfg.Push.Enabled && a.resolver.IsPushAllowed(name) {
			if a.serveInternalManifest(w, r, name, ref) {
				return
			}
		}

		registry, imagePath, upstreamURL, err := a.resolver.Resolve(name)
		if err != nil {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "registry not allowed",
				Reason: err.Error(),
			})
			_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: fmt.Sprintf("docker:%s:%s", name, ref),
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     err.Error(),
			})
			return
		}
		a.handleManifest(w, r, registry, imagePath, upstreamURL, ref)

	case blobsIdx > 0:
		name := wildcardPath[:blobsIdx]
		digest := wildcardPath[blobsIdx+len("/blobs/"):]
		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		// For internal namespaces, serve blobs from BlobStore.
		if a.pushHandler != nil && a.cfg.Push.Enabled && a.resolver.IsPushAllowed(name) {
			if a.serveInternalBlob(w, r, digest) {
				return
			}
		}
		registry, imagePath, upstreamURL, err := a.resolver.Resolve(name)
		if err != nil {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "registry not allowed",
				Reason: err.Error(),
			})
			return
		}
		a.proxyUpstream(w, r, upstreamURL, registry, "/v2/"+imagePath+"/blobs/"+digest)

	default:
		http.NotFound(w, r)
	}
}

// handleV2WildcardWrite routes POST/PUT/PATCH /v2/* to push handlers.
// Parses paths for blob uploads and manifest puts.
func (a *DockerAdapter) handleV2WildcardWrite(w http.ResponseWriter, r *http.Request) {
	if a.pushHandler == nil || !a.cfg.Push.Enabled {
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:  "push disabled",
			Reason: "push support is not enabled on this proxy",
		})
		return
	}

	wildcardPath := chi.URLParam(r, "*")

	// Match /blobs/uploads/ (POST initiate) or /blobs/uploads/{uuid} (PUT complete)
	uploadsIdx := strings.LastIndex(wildcardPath, "/blobs/uploads/")
	if uploadsIdx > 0 {
		name := wildcardPath[:uploadsIdx]
		suffix := wildcardPath[uploadsIdx+len("/blobs/uploads/"):]

		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		if !a.resolver.IsPushAllowed(name) {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "push not allowed",
				Reason: fmt.Sprintf("push to upstream namespace %q is forbidden", name),
			})
			return
		}

		switch {
		case suffix == "" && r.Method == http.MethodPost:
			// POST /v2/{name}/blobs/uploads/ → initiate upload
			a.pushHandler.handleBlobUploadInit(w, r, name)
			return
		case suffix != "" && r.Method == http.MethodPatch:
			// PATCH /v2/{name}/blobs/uploads/{uuid} → chunked upload data
			a.pushHandler.handleBlobUploadChunk(w, r, name, suffix)
			return
		case suffix != "" && r.Method == http.MethodPut:
			// PUT /v2/{name}/blobs/uploads/{uuid}?digest=... → complete upload
			a.pushHandler.handleBlobUploadComplete(w, r, name, suffix)
			return
		}
	}

	// Match /manifests/{ref} (PUT manifest)
	manifestsIdx := strings.LastIndex(wildcardPath, "/manifests/")
	if manifestsIdx > 0 && r.Method == http.MethodPut {
		name := wildcardPath[:manifestsIdx]
		ref := wildcardPath[manifestsIdx+len("/manifests/"):]

		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		if !a.resolver.IsPushAllowed(name) {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "push not allowed",
				Reason: fmt.Sprintf("push to upstream namespace %q is forbidden", name),
			})
			return
		}
		a.handleManifestPut(w, r, name, ref)
		return
	}

	http.NotFound(w, r)
}

// handleV2WildcardHead routes HEAD /v2/* to blob existence checks.
func (a *DockerAdapter) handleV2WildcardHead(w http.ResponseWriter, r *http.Request) {
	wildcardPath := chi.URLParam(r, "*")

	// Match /blobs/{digest} for HEAD
	blobsIdx := strings.LastIndex(wildcardPath, "/blobs/")
	if blobsIdx > 0 {
		digest := wildcardPath[blobsIdx+len("/blobs/"):]

		// Check if this is a push blob (internal namespace) with a push handler.
		if a.pushHandler != nil && a.cfg.Push.Enabled {
			name := wildcardPath[:blobsIdx]
			if a.resolver.IsPushAllowed(name) {
				a.pushHandler.handleBlobHead(w, r, digest)
				return
			}
		}

		// Fall through to upstream proxy for pull-through HEAD.
		name := wildcardPath[:blobsIdx]
		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		registry, imagePath, upstreamURL, err := a.resolver.Resolve(name)
		if err != nil {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "registry not allowed",
				Reason: err.Error(),
			})
			return
		}
		a.proxyUpstream(w, r, upstreamURL, registry, "/v2/"+imagePath+"/blobs/"+digest)
		return
	}

	http.NotFound(w, r)
}

// handleManifestPut handles PUT /v2/{name}/manifests/{ref}.
// Scans the manifest BEFORE returning success (Security Invariant #2).
func (a *DockerAdapter) handleManifestPut(w http.ResponseWriter, r *http.Request, name, ref string) {
	// Read manifest body (capped at 10 MB).
	const maxManifestSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestSize))
	if err != nil {
		log.Error().Err(err).Msg("docker push: failed to read manifest body")
		http.Error(w, "failed to read manifest", http.StatusInternalServerError)
		return
	}

	// Compute digest.
	h := sha256.Sum256(body)
	manifestDigest := "sha256:" + hex.EncodeToString(h[:])

	// Ensure repository exists.
	repo, err := EnsureRepository(a.db, "", name, true)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("docker push: failed to ensure repository")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store manifest as blob.
	if err := a.pushHandler.blobStore.Put(manifestDigest, body); err != nil {
		log.Error().Err(err).Str("digest", manifestDigest).Msg("docker push: failed to store manifest blob")
		http.Error(w, "failed to store manifest", http.StatusInternalServerError)
		return
	}

	// Build artifact ID and scanner artifact.
	safeName := MakeSafeName("", name)
	artifactID := fmt.Sprintf("docker:%s:%s", safeName, ref)

	// Write manifest to temp file for scanning.
	manifestTmp, err := writeManifestToTemp(body)
	if err != nil {
		log.Error().Err(err).Msg("docker push: failed to write manifest to temp file")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(manifestTmp)

	scanArtifact := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      safeName,
		Version:   ref,
		LocalPath: manifestTmp,
		SHA256:    hex.EncodeToString(h[:]),
		SizeBytes: int64(len(body)),
	}

	// Scan BEFORE returning success (Security Invariant #2).
	// Detach from the HTTP request context so client disconnect doesn't cancel the pipeline.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()
	scanResults, scanErr := a.scanEngine.ScanAll(pctx, scanArtifact)
	if scanErr != nil {
		log.Error().Err(scanErr).Str("artifact", artifactID).Msg("docker push: scan engine error, failing open")
		scanResults = nil
	}

	// Policy evaluation.
	policyResult := a.policyEng.Evaluate(pctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("docker push: policy decision")

	switch policyResult.Action {
	case policy.ActionBlock:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, hex.EncodeToString(h[:]), int64(len(body)), model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "blocked",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventBlocked,
			ArtifactID: artifactID,
			Reason:     policyResult.Reason,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		return
	case policy.ActionQuarantine:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, hex.EncodeToString(h[:]), int64(len(body)), model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventQuarantined,
			ArtifactID: artifactID,
			Reason:     policyResult.Reason,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		return

	case policy.ActionAllowWithWarning:
		_ = a.persistArtifact(artifactID, scanArtifact, hex.EncodeToString(h[:]), int64(len(body)), model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventAllowedWithWarning,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		_ = UpsertTag(a.db, repo.ID, ref, manifestDigest, artifactID)

		w.Header().Set("X-Shieldoo-Warning", "MEDIUM vulnerability detected; see admin dashboard for details")
		w.Header().Set("Docker-Content-Digest", manifestDigest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, ref))
		w.WriteHeader(http.StatusCreated)
		return
	}

	// Allow — persist artifact as clean and create/update tag.
	_ = a.persistArtifact(artifactID, scanArtifact, hex.EncodeToString(h[:]), int64(len(body)), model.StatusClean, "", nil, scanResults)
	_ = UpsertTag(a.db, repo.ID, ref, manifestDigest, artifactID)

	w.Header().Set("Docker-Content-Digest", manifestDigest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, ref))
	w.WriteHeader(http.StatusCreated)
}

// serveInternalManifest tries to serve a manifest for an internally-pushed image.
// Returns true if the manifest was served (or an error response was written), false to fall through to upstream.
func (a *DockerAdapter) serveInternalManifest(w http.ResponseWriter, r *http.Request, name, ref string) bool {
	// Look up the internal repository.
	repo, err := EnsureRepository(a.db, "", name, true)
	if err != nil {
		return false
	}

	// Resolve tag → manifest digest.
	tag, err := GetTag(a.db, repo.ID, ref)
	if err != nil {
		// Tag not found — not an internal image, fall through.
		return false
	}

	// Check artifact status (quarantine check).
	safeName := MakeSafeName("", name)
	artifactID := fmt.Sprintf("docker:%s:%s", safeName, ref)
	status, err := adapter.GetArtifactStatus(a.db, artifactID)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to check internal artifact status")
		http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
		return true
	}
	if status != nil && status.Status == model.StatusQuarantined {
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   status.QuarantineReason,
		})
		return true
	}

	// Fetch manifest from BlobStore.
	// Note: BlobStore is content-addressable (digest-keyed), so integrity
	// is inherent — the digest IS the content hash. No separate SHA256 check needed.
	manifestBytes, err := a.pushHandler.blobStore.Get(tag.ManifestDigest)
	if err != nil {
		log.Debug().Err(err).Str("digest", tag.ManifestDigest).Msg("docker: internal manifest not in blobstore, falling through")
		return false
	}

	log.Info().Str("artifact", artifactID).Str("digest", tag.ManifestDigest).Msg("docker: serving internal manifest from blobstore")
	adapter.UpdateLastAccessedAt(a.db, artifactID)
	w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w.Header().Set("Docker-Content-Digest", tag.ManifestDigest)
	w.Header().Set("X-Shieldoo-Scanned", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(manifestBytes)
	_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	return true
}

// serveInternalBlob tries to serve a blob from the BlobStore for internally-pushed images.
// Returns true if the blob was served, false to fall through to upstream.
func (a *DockerAdapter) serveInternalBlob(w http.ResponseWriter, _ *http.Request, digest string) bool {
	data, err := a.pushHandler.blobStore.Get(digest)
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return true
}

// handleManifest runs the full scan-on-pull pipeline for manifest requests.
func (a *DockerAdapter) handleManifest(w http.ResponseWriter, r *http.Request, registry, imagePath, upstreamURL, ref string) {
	ctx := r.Context()

	// Auto-create repository record (fire-and-forget).
	_, _ = EnsureRepository(a.db, registry, imagePath, false)

	// Artifact ID format: docker:{safeName}:{ref}
	safeName := MakeSafeName(registry, imagePath)
	artifactID := fmt.Sprintf("docker:%s:%s", safeName, ref)

	// Pre-scan for typosquatting BEFORE pulling the image. Pull-only
	// (decision A): push to internal namespaces uses a separate handler
	// and is NOT gated by typosquat.
	if a.blockIfTyposquat(w, r, registry, imagePath, safeName) {
		return
	}

	// 1. Check if already in cache with a known status. Fail closed on DB errors.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		// Cached — check status before serving. Fail closed on DB errors.
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to check artifact status, refusing to serve")
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
		// Serve cached manifest.
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEng, a.db, artifactID) {
			return
		}
		adapter.UpdateLastAccessedAt(a.db, artifactID)
		manifestBytes, err := os.ReadFile(cachedPath)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to read cached manifest")
			http.Error(w, "internal error reading cached manifest", http.StatusInternalServerError)
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("docker: serving from cache")
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("X-Shieldoo-Scanned", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifestBytes)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		// Trigger async sandbox scan (non-blocking).
		adapter.TriggerAsyncScan(r.Context(), scanner.Artifact{
			ID: artifactID, Ecosystem: scanner.EcosystemDocker, Name: safeName, Version: ref, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEng)
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context — see PyPI adapter for rationale.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()

	// 3. Re-check cache after acquiring lock — another request may have completed the pipeline.
	if cachedPath, err := a.cache.Get(pctx, artifactID); err == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to check artifact status after lock, refusing to serve")
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
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEng, a.db, artifactID) {
			return
		}
		manifestBytes, err := os.ReadFile(cachedPath)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to read cached manifest after lock")
			http.Error(w, "internal error reading cached manifest", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifestBytes)
		return
	}

	// 4. Download manifest from upstream (capped at 10 MB).
	manifestBytes, manifestContentType, err := a.fetchManifest(pctx, r, upstreamURL, registry, imagePath, ref)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to fetch manifest from upstream")
		http.Error(w, "failed to fetch manifest from upstream", http.StatusBadGateway)
		return
	}

	// 5. Download full image to temp OCI tarball for scanning.
	// Build the image ref: strip any http:// or https:// scheme from upstreamURL for crane.
	upstreamHost := strings.TrimPrefix(strings.TrimPrefix(upstreamURL, "https://"), "http://")
	// Docker Hub images must use index.docker.io for crane to handle OAuth2 token exchange.
	if upstreamHost == "registry-1.docker.io" {
		upstreamHost = "index.docker.io"
	}
	imageRef := upstreamHost + "/" + imagePath + ":" + ref
	// For plain tag refs (not digests), crane uses the ref as-is.
	// If ref looks like a digest (sha256:...), use @ notation.
	if strings.HasPrefix(ref, "sha256:") {
		imageRef = upstreamHost + "/" + imagePath + "@" + ref
	}

	craneOpts := []crane.Option{
		crane.WithContext(pctx),
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	tarPath, tarSize, tarSHA, err := pullImageToTar(pctx, imageRef, craneOpts...)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Str("image_ref", imageRef).Msg("docker: failed to pull image for scanning")
		http.Error(w, "failed to pull image for scanning", http.StatusBadGateway)
		return
	}
	defer os.Remove(tarPath)

	// Compute SHA256 of manifest for the artifact record.
	manifestHash := sha256.Sum256(manifestBytes)
	manifestSHA := hex.EncodeToString(manifestHash[:])

	// Upstream integrity check — detect content mutation for known artifacts.
	if err := adapter.VerifyUpstreamIntegrity(a.db, artifactID, manifestSHA); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: upstream content mutation detected")
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "integrity_violation",
			Artifact: artifactID,
			Reason:   "upstream content changed since last scan — artifact quarantined, admin must delete and re-approve",
		})
		return
	}

	// 6. Build scanner.Artifact (point at tarball for scanning).
	// IMPORTANT: Name is set to safeName (not imagePath) so model.Artifact.ID() matches artifactID.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemDocker,
		Name:        safeName,
		Version:     ref,
		LocalPath:   tarPath,
		SHA256:      tarSHA,
		SizeBytes:   tarSize,
		UpstreamURL: upstreamURL + "/v2/" + imagePath + "/manifests/" + ref,
	}

	// 7. Scan via scan engine.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("docker: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("docker: scan engine error, failing open")
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
		l.Msg("docker: scan result")
	}

	// 8. Policy evaluation.
	policyResult := a.policyEng.Evaluate(pctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("docker: policy decision")

	// 9. Act on policy result.
	switch policyResult.Action {
	case policy.ActionBlock:
		now := time.Now().UTC()
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusQuarantined, policyResult.Reason, &now, scanResults)
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
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusQuarantined, policyResult.Reason, &now, scanResults)
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
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventAllowedWithWarning,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})

		// Cache manifest before serving.
		manifestTmp, tmpErr := writeManifestToTemp(manifestBytes)
		if tmpErr != nil {
			log.Error().Err(tmpErr).Str("artifact", artifactID).Msg("docker: failed to write manifest to temp file for caching (allow-with-warning)")
		} else {
			defer os.Remove(manifestTmp)
			cacheArtifact := scanner.Artifact{
				ID:          artifactID,
				Ecosystem:   scanner.EcosystemDocker,
				Name:        safeName,
				Version:     ref,
				LocalPath:   manifestTmp,
				SHA256:      manifestSHA,
				SizeBytes:   int64(len(manifestBytes)),
				UpstreamURL: scanArtifact.UpstreamURL,
			}
			_ = a.cache.Put(pctx, cacheArtifact, manifestTmp)
		}

		w.Header().Set("X-Shieldoo-Warning", "MEDIUM vulnerability detected; see admin dashboard for details")
		if manifestContentType != "" {
			w.Header().Set("Content-Type", manifestContentType)
		} else {
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		}
		w.Header().Set("X-Shieldoo-Scanned", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(manifestBytes))
		adapter.TriggerAsyncScan(r.Context(), scanArtifact, scanArtifact.LocalPath, a.db, a.policyEng)
		return
	}

	// 10. Allow — cache manifest and serve.
	// Write manifest to a temp file for caching (cache.Put expects a file path).
	manifestTmp, err := writeManifestToTemp(manifestBytes)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to write manifest to temp file for caching")
		// Still serve the manifest even if caching fails.
	} else {
		defer os.Remove(manifestTmp)
		// Store the manifest (not the tarball) in cache so subsequent requests are fast.
		cacheArtifact := scanner.Artifact{
			ID:          artifactID,
			Ecosystem:   scanner.EcosystemDocker,
			Name:        safeName,
			Version:     ref,
			LocalPath:   manifestTmp,
			SHA256:      manifestSHA,
			SizeBytes:   int64(len(manifestBytes)),
			UpstreamURL: scanArtifact.UpstreamURL,
		}
		_ = a.cache.Put(pctx, cacheArtifact, manifestTmp)
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusClean, "", nil, scanResults)
	}

	_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})

	if manifestContentType != "" {
		w.Header().Set("Content-Type", manifestContentType)
	} else {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	}
	w.Header().Set("X-Shieldoo-Scanned", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, bytes.NewReader(manifestBytes))

	// Trigger async sandbox scan (non-blocking).
	adapter.TriggerAsyncScan(r.Context(), scanArtifact, scanArtifact.LocalPath, a.db, a.policyEng)
	adapter.TriggerAsyncSBOMWrite(r.Context(), artifactID, scanResults)
}

// fetchManifest downloads the manifest from the upstream registry.
// Returns the manifest body (capped at 10 MB), the content-type, and any error.
// SECURITY: Uses per-registry credentials from config, NOT client Authorization header.
func (a *DockerAdapter) fetchManifest(ctx context.Context, r *http.Request, upstreamURL, registryHost, name, ref string) ([]byte, string, error) {
	target := upstreamURL + "/v2/" + name + "/manifests/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: building request: %w", err)
	}

	// Forward Accept header (needed for manifest negotiation).
	if v := r.Header.Get("Accept"); v != "" {
		req.Header.Set("Accept", v)
	}

	// SECURITY: Use per-registry credentials from config, NOT client's Authorization header.
	if auth := a.resolver.AuthForRegistry(registryHost); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: %w", err)
	}

	// Handle 401 — Bearer token exchange (Docker Registry v2 auth flow).
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("Www-Authenticate")
		resp.Body.Close()
		realm, service, scope, ok := parseWwwAuthenticate(wwwAuth)
		if !ok {
			return nil, "", fmt.Errorf("docker: fetch manifest: 401 but no parseable Www-Authenticate header")
		}
		token, tokenErr := a.tokenExch.exchangeToken(ctx, realm, service, scope)
		if tokenErr != nil {
			return nil, "", fmt.Errorf("docker: fetch manifest: token exchange: %w", tokenErr)
		}
		// Retry with Bearer token.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err2 != nil {
			return nil, "", fmt.Errorf("docker: fetch manifest: building retry request: %w", err2)
		}
		if v := r.Header.Get("Accept"); v != "" {
			req2.Header.Set("Accept", v)
		}
		req2.Header.Set("Authorization", "Bearer "+token)
		resp, err = a.httpClient.Do(req2)
		if err != nil {
			return nil, "", fmt.Errorf("docker: fetch manifest: retry after token exchange: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("docker: fetch manifest: upstream returned %d", resp.StatusCode)
	}

	// Cap manifest responses at 10 MB.
	const maxManifestSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: reading body: %w", err)
	}

	// SECURITY: Verify manifest digest matches upstream's claim.
	if upstreamDigest := resp.Header.Get("Docker-Content-Digest"); upstreamDigest != "" {
		h := sha256.Sum256(body)
		computed := "sha256:" + hex.EncodeToString(h[:])
		if computed != upstreamDigest {
			return nil, "", fmt.Errorf("docker: manifest digest mismatch: computed %s, upstream claims %s", computed, upstreamDigest)
		}
	}

	return body, resp.Header.Get("Content-Type"), nil
}

// pullImageToTar pulls the image using crane and saves it as an OCI tarball.
// Returns (tarPath, sizeBytes, sha256hex, error).
func pullImageToTar(ctx context.Context, imageRef string, opts ...crane.Option) (string, int64, string, error) {
	img, err := crane.Pull(imageRef, opts...)
	if err != nil {
		return "", 0, "", fmt.Errorf("docker: crane pull %s: %w", imageRef, err)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-docker-*.tar")
	if err != nil {
		return "", 0, "", fmt.Errorf("docker: creating temp tar file: %w", err)
	}
	tmp.Close()

	if err := crane.Save(img, imageRef, tmp.Name()); err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("docker: saving image tarball: %w", err)
	}

	// Compute size and SHA256 of the saved tarball.
	f, err := os.Open(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("docker: opening image tarball: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("docker: hashing image tarball: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

// writeManifestToTemp writes manifest bytes to a temporary file and returns its path.
func writeManifestToTemp(manifestBytes []byte) (string, error) {
	tmp, err := os.CreateTemp("", "shieldoo-gate-docker-manifest-*.json")
	if err != nil {
		return "", fmt.Errorf("docker: creating manifest temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := tmp.Write(manifestBytes); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("docker: writing manifest temp file: %w", err)
	}
	return tmp.Name(), nil
}

// persistArtifact writes the artifact, status, and scan results to the DB.
func (a *DockerAdapter) persistArtifact(
	artifactID string,
	sa scanner.Artifact,
	manifestSHA string,
	manifestSize int64,
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
		SHA256:         manifestSHA,
		SizeBytes:      manifestSize,
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

// proxyUpstream forwards the request to the upstream registry and relays the response.
// Used for blob pass-through only.
// SECURITY: Uses per-registry credentials from config, NOT client Authorization header.
func (a *DockerAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, upstreamURL, registryHost, path string) {
	target := upstreamURL + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}

	// Forward Accept header only. NEVER forward Authorization from client.
	if v := r.Header.Get("Accept"); v != "" {
		req.Header.Set("Accept", v)
	}
	// Use per-registry credentials from config.
	if auth := a.resolver.AuthForRegistry(registryHost); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}

	// Handle 401 — Bearer token exchange (Docker Registry v2 auth flow).
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("Www-Authenticate")
		resp.Body.Close()
		realm, service, scope, ok := parseWwwAuthenticate(wwwAuth)
		if ok {
			token, tokenErr := a.tokenExch.exchangeToken(r.Context(), realm, service, scope)
			if tokenErr != nil {
				log.Error().Err(tokenErr).Str("target", target).Msg("docker: proxy upstream: token exchange failed")
				http.Error(w, "upstream auth failed", http.StatusBadGateway)
				return
			}
			// Retry with Bearer token.
			req2, err2 := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
			if err2 != nil {
				http.Error(w, "upstream request error", http.StatusInternalServerError)
				return
			}
			if v := r.Header.Get("Accept"); v != "" {
				req2.Header.Set("Accept", v)
			}
			req2.Header.Set("Authorization", "Bearer "+token)
			resp, err = a.httpClient.Do(req2)
			if err != nil {
				http.Error(w, "upstream unreachable", http.StatusBadGateway)
				return
			}
		}
		// If Www-Authenticate was not parseable, fall through and proxy the 401 as-is.
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

// blockIfTyposquat runs the typosquat scanner on a Docker pull request before
// any upstream interaction. Returns true if the pull was blocked (response
// already written). Returns false if the image name is clean, no typosquat
// scanner is registered, or an active policy override permits the pull.
//
// imageNameForScan derivation: for Docker Hub paths (registry == "docker.io")
// that begin with "library/", the prefix is stripped before consulting the
// scanner so the bare-name seed entries match. For non-library/ paths and
// non-Docker-Hub registries, the imagePath is passed as-is.
//
// The synthetic typosquat row uses safeName so the artifact ID matches the
// existing post-scan path's MakeSafeName() shape. version="*" per decision C.
//
// Pull only (decision A) — handleManifestPut never calls this helper.
func (a *DockerAdapter) blockIfTyposquat(w http.ResponseWriter, r *http.Request, registry, imagePath, safeName string) bool {
	imageNameForScan := imagePath
	if registry == "docker.io" && strings.HasPrefix(imagePath, "library/") {
		imageNameForScan = strings.TrimPrefix(imagePath, "library/")
	}

	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), imageNameForScan, scanner.EcosystemDocker)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	// Synthetic 3-segment ID: docker:{safeName}:* — drops the ref slot from
	// the full runtime ID (typosquat is name-based; one row covers all tags).
	artifactID := fmt.Sprintf("docker:%s:%s", safeName, adapter.TyposquatPlaceholderVersion)

	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	if a.policyEng != nil {
		// Override scope is name-based: match by safeName, ignoring the ref.
		if overrideID, hasOverride := a.policyEng.HasOverride(r.Context(), scanner.EcosystemDocker, safeName, ""); hasOverride {
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
		Float32("confidence", result.Confidence).Msg("typosquat pre-scan: blocked before upstream pull")

	if err := adapter.PersistTyposquatBlock(a.db, artifactID, scanner.EcosystemDocker, safeName, result, time.Now().UTC()); err != nil {
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
// log entries — keeps the popular-image name in the audit trail while the
// public 403 response stays generic.
func typosquatBlockReason(result scanner.ScanResult) string {
	if len(result.Findings) > 0 {
		return "typosquat pre-scan: " + result.Findings[0].Description
	}
	return "typosquat pre-scan: " + string(result.Verdict)
}

// validateDockerName returns an error if the image name contains unsafe characters.
// Docker image names are of the form: [registry/][namespace/]repository
func validateDockerName(name string) error {
	if name == "" {
		return fmt.Errorf("docker: image name must not be empty")
	}
	// Allow alphanumeric, dash, underscore, dot, slash, colon (for port), and @ for digest refs.
	for _, c := range name {
		if !isDockerNameChar(c) {
			return fmt.Errorf("docker: image name %q contains invalid character %q", name, c)
		}
	}
	// Prevent path traversal.
	if strings.Contains(name, "..") {
		return fmt.Errorf("docker: image name %q contains path traversal sequence", name)
	}
	return nil
}

func isDockerNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '/' || c == ':' || c == '@'
}
