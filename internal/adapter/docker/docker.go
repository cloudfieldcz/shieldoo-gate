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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
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
	db          *sqlx.DB
	cache       cache.CacheStore
	scanEngine  *scanner.Engine
	policyEng   *policy.Engine
	upstreamURL string
	router      http.Handler
	httpClient  *http.Client
}

// NewDockerAdapter creates and wires a DockerAdapter.
func NewDockerAdapter(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreamURL string,
) *DockerAdapter {
	a := &DockerAdapter{
		db:          db,
		cache:       cacheStore,
		scanEngine:  scanEngine,
		policyEng:   policyEngine,
		upstreamURL: strings.TrimRight(upstreamURL, "/"),
		httpClient:  &http.Client{Timeout: 10 * time.Minute},
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *DockerAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemDocker }

// HealthCheck implements adapter.Adapter.
func (a *DockerAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/v2/", nil)
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

	return r
}

// handleV2Check responds with the Docker-Distribution-API-Version header as
// required by the OCI Distribution Spec.
func (a *DockerAdapter) handleV2Check(w http.ResponseWriter, r *http.Request) {
	// Try to proxy to upstream to preserve auth challenges, but if upstream
	// is unreachable, return a synthetic 200 with the required header.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.upstreamURL+"/v2/", nil)
	if err != nil {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	// Forward Authorization header if present.
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		// Fail gracefully — return the required header.
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	// Ensure the version header is always present.
	if w.Header().Get("Docker-Distribution-API-Version") == "" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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
		a.handleManifest(w, r, name, ref)

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
		a.proxyUpstream(w, r, "/v2/"+name+"/blobs/"+digest)

	default:
		http.NotFound(w, r)
	}
}

// handleManifest runs the full scan-on-pull pipeline for manifest requests.
func (a *DockerAdapter) handleManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	ctx := r.Context()

	// Artifact ID format: docker:{name}:{ref}
	artifactID := fmt.Sprintf("docker:%s:%s", name, ref)

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
			_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: artifactID,
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     "quarantined (cached)",
			})
			return
		}
		// Serve cached manifest.
		manifestBytes, err := os.ReadFile(cachedPath)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to read cached manifest")
			http.Error(w, "internal error reading cached manifest", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifestBytes)
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

	// 3. Re-check cache after acquiring lock — another request may have completed the pipeline.
	if cachedPath, err := a.cache.Get(ctx, artifactID); err == nil {
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
	manifestBytes, manifestContentType, err := a.fetchManifest(ctx, r, name, ref)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("docker: failed to fetch manifest from upstream")
		http.Error(w, "failed to fetch manifest from upstream", http.StatusBadGateway)
		return
	}

	// 5. Download full image to temp OCI tarball for scanning.
	// Build the image ref: strip any http:// or https:// scheme from upstreamURL for crane.
	upstreamHost := strings.TrimPrefix(strings.TrimPrefix(a.upstreamURL, "https://"), "http://")
	imageRef := upstreamHost + "/" + name + ":" + ref
	// For plain tag refs (not digests), crane uses the ref as-is.
	// If ref looks like a digest (sha256:...), use @ notation.
	if strings.HasPrefix(ref, "sha256:") {
		imageRef = upstreamHost + "/" + name + "@" + ref
	}

	tarPath, tarSize, tarSHA, err := pullImageToTar(ctx, imageRef)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Str("image_ref", imageRef).Msg("docker: failed to pull image for scanning")
		http.Error(w, "failed to pull image for scanning", http.StatusBadGateway)
		return
	}
	defer os.Remove(tarPath)

	// Compute SHA256 of manifest for the artifact record.
	manifestHash := sha256.Sum256(manifestBytes)
	manifestSHA := hex.EncodeToString(manifestHash[:])

	// 6. Build scanner.Artifact (point at tarball for scanning).
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemDocker,
		Name:        name,
		Version:     ref,
		LocalPath:   tarPath,
		SHA256:      tarSHA,
		SizeBytes:   tarSize,
		UpstreamURL: a.upstreamURL + "/v2/" + name + "/manifests/" + ref,
	}

	// 7. Scan via scan engine.
	log.Info().Str("artifact", artifactID).Msg("docker: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(ctx, scanArtifact)
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
	policyResult := a.policyEng.Evaluate(ctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("docker: policy decision")

	// 9. Act on policy result.
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
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusQuarantined, policyResult.Reason, &now, scanResults)
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
			Name:        name,
			Version:     ref,
			LocalPath:   manifestTmp,
			SHA256:      manifestSHA,
			SizeBytes:   int64(len(manifestBytes)),
			UpstreamURL: scanArtifact.UpstreamURL,
		}
		_ = a.cache.Put(ctx, cacheArtifact, manifestTmp)
		_ = a.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)), model.StatusClean, "", nil, scanResults)
	}

	_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
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
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, bytes.NewReader(manifestBytes))
}

// fetchManifest downloads the manifest from the upstream registry.
// Returns the manifest body (capped at 10 MB), the content-type, and any error.
func (a *DockerAdapter) fetchManifest(ctx context.Context, r *http.Request, name, ref string) ([]byte, string, error) {
	target := a.upstreamURL + "/v2/" + name + "/manifests/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: building request: %w", err)
	}

	// Forward relevant headers.
	for _, hdr := range []string{"Accept", "Authorization"} {
		if v := r.Header.Get(hdr); v != "" {
			req.Header.Set(hdr, v)
		}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: %w", err)
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

	return body, resp.Header.Get("Content-Type"), nil
}

// pullImageToTar pulls the image using crane and saves it as an OCI tarball.
// Returns (tarPath, sizeBytes, sha256hex, error).
func pullImageToTar(ctx context.Context, imageRef string) (string, int64, string, error) {
	img, err := crane.Pull(imageRef, crane.WithContext(ctx))
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
	if err := adapter.InsertArtifact(a.db, art, artStatus); err != nil {
		return err
	}
	return adapter.InsertScanResults(a.db, artifactID, scanResults)
}

// proxyUpstream forwards the request to the upstream registry and relays the response.
// Used for blob pass-through only.
func (a *DockerAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
	target := a.upstreamURL + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}

	// Forward relevant headers: Accept, Authorization, Docker-specific.
	for _, hdr := range []string{"Accept", "Authorization", "Docker-Content-Digest"} {
		if v := r.Header.Get(hdr); v != "" {
			req.Header.Set(hdr, v)
		}
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
