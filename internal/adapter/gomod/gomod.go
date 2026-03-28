// Package gomod implements a proxy adapter for the Go module proxy protocol (GOPROXY).
package gomod

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
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/mod/module"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*GoModAdapter)(nil)

// requestType classifies a parsed GOPROXY protocol request.
type requestType int

const (
	reqVersionList requestType = iota
	reqVersionInfo
	reqGoMod
	reqZipDownload
	reqLatest
)

// parsedRequest holds the result of parsing a GOPROXY protocol URL.
type parsedRequest struct {
	modulePath string      // decoded module path, e.g. "github.com/Foo/Bar"
	version    string      // e.g. "v1.2.3" (empty for list/latest)
	reqType    requestType // which endpoint was matched
}

// GoModAdapter proxies Go module proxy protocol with artifact scanning on .zip downloads.
type GoModAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string
	router       http.Handler
	httpClient   *http.Client
}

// NewGoModAdapter creates and wires a GoModAdapter.
func NewGoModAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstream string,
) *GoModAdapter {
	a := &GoModAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(upstream, "/"),
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *GoModAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemGo }

// HealthCheck implements adapter.Adapter.
func (a *GoModAdapter) HealthCheck(ctx context.Context) error {
	// proxy.golang.org returns 200 on root.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstream+"/", nil)
	if err != nil {
		return fmt.Errorf("gomod: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gomod: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("gomod: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *GoModAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates the chi router with the catch-all route.
func (a *GoModAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/*", a.handleRequest)
	return r
}

// handleRequest is the catch-all handler that parses GOPROXY paths and dispatches.
func (a *GoModAdapter) handleRequest(w http.ResponseWriter, r *http.Request) {
	rawPath := chi.URLParam(r, "*")
	if rawPath == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	parsed, err := parseGoModRequest(rawPath)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid request",
			Reason: err.Error(),
		})
		return
	}

	switch parsed.reqType {
	case reqZipDownload:
		a.downloadScanServe(w, r, parsed, rawPath)
	default:
		// list, info, mod, latest — all pass-through
		a.proxyPassThrough(w, r, rawPath)
	}
}

// parseGoModRequest parses a GOPROXY protocol URL path into its components.
//
// Expected patterns:
//
//	{escaped_module}/@v/list
//	{escaped_module}/@v/{version}.info
//	{escaped_module}/@v/{version}.mod
//	{escaped_module}/@v/{version}.zip
//	{escaped_module}/@latest
//
// Module paths may contain slashes (e.g. github.com/!foo/!bar).
func parseGoModRequest(rawPath string) (*parsedRequest, error) {
	// Path traversal protection.
	if strings.Contains(rawPath, "..") {
		return nil, fmt.Errorf("path traversal detected")
	}

	// SSRF protection: reject control characters, null bytes, query/fragment markers.
	if err := validateModuleURLPath(rawPath); err != nil {
		return nil, err
	}

	// Check for /@latest suffix first.
	if strings.HasSuffix(rawPath, "/@latest") {
		escapedModule := strings.TrimSuffix(rawPath, "/@latest")
		modulePath, err := unescapeModulePath(escapedModule)
		if err != nil {
			return nil, fmt.Errorf("invalid module path: %w", err)
		}
		return &parsedRequest{
			modulePath: modulePath,
			reqType:    reqLatest,
		}, nil
	}

	// Find /@v/ separator.
	idx := strings.Index(rawPath, "/@v/")
	if idx < 0 {
		return nil, fmt.Errorf("missing /@v/ in path")
	}

	escapedModule := rawPath[:idx]
	remainder := rawPath[idx+4:] // everything after "/@v/"

	modulePath, err := unescapeModulePath(escapedModule)
	if err != nil {
		return nil, fmt.Errorf("invalid module path: %w", err)
	}

	// Classify the remainder.
	if remainder == "list" {
		return &parsedRequest{
			modulePath: modulePath,
			reqType:    reqVersionList,
		}, nil
	}

	if strings.HasSuffix(remainder, ".info") {
		version := strings.TrimSuffix(remainder, ".info")
		return &parsedRequest{
			modulePath: modulePath,
			version:    version,
			reqType:    reqVersionInfo,
		}, nil
	}

	if strings.HasSuffix(remainder, ".mod") {
		version := strings.TrimSuffix(remainder, ".mod")
		return &parsedRequest{
			modulePath: modulePath,
			version:    version,
			reqType:    reqGoMod,
		}, nil
	}

	if strings.HasSuffix(remainder, ".zip") {
		version := strings.TrimSuffix(remainder, ".zip")
		return &parsedRequest{
			modulePath: modulePath,
			version:    version,
			reqType:    reqZipDownload,
		}, nil
	}

	return nil, fmt.Errorf("unrecognised action in path: %s", remainder)
}

// unescapeModulePath decodes a GOPROXY-encoded module path.
// Uses golang.org/x/mod/module.UnescapePath for correctness.
func unescapeModulePath(escaped string) (string, error) {
	decoded, err := module.UnescapePath(escaped)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// validateModuleURLPath rejects paths containing characters unsafe for URL construction.
func validateModuleURLPath(p string) error {
	for _, r := range p {
		if r == 0 {
			return fmt.Errorf("null byte in path")
		}
		if r == '?' || r == '#' {
			return fmt.Errorf("query/fragment marker %q in path", string(r))
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("control character in path")
		}
	}
	return nil
}

// gomodArtifactID returns the canonical artifact ID for DB/cache lookups.
func gomodArtifactID(modulePath, version string) string {
	return fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemGo), modulePath, version)
}

// proxyPassThrough forwards a request to the upstream Go module proxy without scanning.
func (a *GoModAdapter) proxyPassThrough(w http.ResponseWriter, r *http.Request, rawPath string) {
	target, err := url.JoinPath(a.upstream, rawPath)
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

// downloadScanServe implements the full download -> scan -> policy -> serve pipeline for .zip files.
func (a *GoModAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, parsed *parsedRequest, rawPath string) {
	ctx := r.Context()

	artifactID := gomodArtifactID(parsed.modulePath, parsed.version)

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: failed to check artifact status, refusing to serve")
			http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
			return
		}
		if status != nil && status.Status == model.StatusQuarantined {
			// Go convention: 410 Gone for blocked modules.
			adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
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
		w.Header().Set("Content-Type", "application/zip")
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		// Trigger async sandbox scan (non-blocking).
		adapter.TriggerAsyncScan(r.Context(), scanner.Artifact{
			ID: artifactID, Ecosystem: scanner.EcosystemGo, Name: parsed.modulePath, Version: parsed.version, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Re-check cache after acquiring lock.
	if cachedPath, err := a.cache.Get(ctx, artifactID); err == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: failed to check artifact status, refusing to serve")
			http.Error(w, "internal error checking artifact status", http.StatusServiceUnavailable)
			return
		}
		if status != nil && status.Status == model.StatusQuarantined {
			adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
				Error:    "quarantined",
				Artifact: artifactID,
				Reason:   status.QuarantineReason,
			})
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		http.ServeFile(w, r, cachedPath)
		return
	}

	// 3. Download to temp file.
	upstreamURL, err := url.JoinPath(a.upstream, rawPath)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}

	tmpPath, size, sha, err := downloadToTemp(ctx, upstreamURL, a.httpClient)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: failed to download from upstream")
		http.Error(w, "failed to fetch upstream artifact", http.StatusBadGateway)
		return
	}
	defer os.Remove(tmpPath)

	// 4. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemGo,
		Name:        parsed.modulePath,
		Version:     parsed.version,
		LocalPath:   tmpPath,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 5. Scan.
	log.Info().Str("artifact", artifactID).Msg("gomod: starting scan pipeline")
	scanResults, err := a.scanEngine.ScanAll(ctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: scan engine error, failing open")
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
		l.Msg("gomod: scan result")
	}

	// 6. Policy evaluation.
	policyResult := a.policyEngine.Evaluate(ctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("gomod: policy decision")

	// 7. Act on policy result.
	switch policyResult.Action {
	case policy.ActionBlock:
		_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
			EventType:  model.EventBlocked,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     policyResult.Reason,
		})
		adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
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
		adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		return
	}

	// 8. Allow — cache artifact and serve.
	_ = a.cache.Put(ctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	w.Header().Set("Content-Type", "application/zip")
	http.ServeFile(w, r, tmpPath)

	// Trigger async sandbox scan (non-blocking).
	adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
}

// persistArtifact writes the artifact, status, and scan results to the DB.
func (a *GoModAdapter) persistArtifact(
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

// downloadToTemp downloads url into a temporary file, returning (path, size, sha256hex, error).
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("gomod: download: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("gomod: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("gomod: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-gomod-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("gomod: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	// Cap artifact download at 2 GB to prevent disk exhaustion.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("gomod: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
