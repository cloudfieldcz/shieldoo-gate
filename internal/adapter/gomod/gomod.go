// Package gomod implements a proxy adapter for the Go module proxy protocol (GOPROXY).
package gomod

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
	upstream     string // default index base (back-compat; == resolver default)
	resolver     *adapter.UpstreamResolver
	router       http.Handler
	httpClient   *http.Client
}

// NewGoModAdapter creates and wires a GoModAdapter.
func NewGoModAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
) *GoModAdapter {
	defaultURL := upstreams.DefaultOr("https://proxy.golang.org")
	resolver, err := adapter.NewUpstreamResolver("go", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		panic(fmt.Sprintf("gomod: building upstream resolver: %v", err))
	}
	a := &GoModAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(defaultURL, "/"),
		resolver:     resolver,
		// redirect-safe: per-index credentials must be stripped on cross-host/scheme redirect.
		httpClient: adapter.NewRedirectSafeClient(5 * time.Minute),
	}
	a.router = a.buildRouter()
	return a
}

// DB exposes the adapter's database handle for tests.
func (a *GoModAdapter) DB() *config.GateDB { return a.db }

// idxURL returns the index URL, falling back to the default upstream for the
// default index (empty Name/URL).
func (a *GoModAdapter) idxURL(idx adapter.ResolvedIndex) string {
	if idx.URL != "" {
		return idx.URL
	}
	return a.upstream
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

	// Pre-scan for typosquatting on .info, .mod, and .zip requests only.
	// /@v/list and /@latest are skipped (decision B) — they're the name-only
	// enumeration phase used by `go mod tidy` and gating them adds latency
	// without preventing real exploitation (the actual fetch is .info/.mod/.zip).
	switch parsed.reqType {
	case reqVersionInfo, reqGoMod, reqZipDownload:
		if a.blockIfTyposquat(w, r, parsed.modulePath, parsed.version) {
			return
		}
	}

	switch parsed.reqType {
	case reqZipDownload:
		idx := a.firstIndexFor(parsed.modulePath)
		a.downloadScanServe(w, r, idx, parsed, rawPath)
	default:
		// list, info, mod, latest — fan out across indexes (verbatim relay; GOPROXY
		// metadata carries no download URLs, so there is nothing to rewrite).
		a.serveMetadataFanOut(w, r, parsed.modulePath, rawPath)
	}
}

// firstIndexFor recovers the serving index for a download by re-resolving the
// module path (the .zip route carries it). Returns the default index when
// resolution is empty (a scoped-miss download: the fetch then 404s on the absent
// upstream — correct, no public fallback).
func (a *GoModAdapter) firstIndexFor(modulePath string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(modulePath); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}

// serveMetadataFanOut tries each resolved index for the module's metadata,
// serving the first that has it (200) verbatim. A claimed-namespace miss →
// 404 + namespaced BLOCKED audit (no public fallback — dependency-confusion guard).
func (a *GoModAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, modulePath, rawPath string) {
	for _, idx := range a.resolver.ResolveForPackage(modulePath) {
		served, err := a.tryServeMetadata(w, r, idx, rawPath)
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
	if claimants := a.resolver.ClaimingIndexNames(modulePath); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemGo), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, modulePath),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index module not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// tryServeMetadata fetches one index's metadata at rawPath. (true,nil)=served;
// (false,nil)=404/410; (false,err)=transport/non-200/oversize. The body is
// relayed verbatim (size-capped — no download URLs to rewrite for GOPROXY).
func (a *GoModAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, rawPath string) (bool, error) {
	target, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), rawPath)
	if err != nil {
		return false, err
	}
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
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("gomod: index %q returned %d", idx.Name, resp.StatusCode)
	}
	// Cap the metadata body from a low-trust extra index (GOPROXY list/.info/.mod/
	// @latest are tiny). Read fully so the size guard runs before bytes reach the
	// client; fail closed on exceed.
	const maxMetadataSize = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("gomod: index %q metadata exceeds size limit", idx.Name)
	}
	if idx.Name == "" {
		for key, vals := range resp.Header {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
	} else {
		for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return true, nil
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

// blockIfTyposquat runs the typosquat scanner on modulePath before any
// upstream call. Returns true if the request was blocked (response already
// written with HTTP 410 Gone — the GOPROXY convention for "module not
// available, do not retry"). Returns false if the path is clean, no scanner
// is registered, or an active policy override permits the request.
//
// Synthetic typosquat rows always carry version="*" — typosquat detection
// is name-based, so the override scope is module-path-wide. The artifact ID
// uses the "go:" prefix (EcosystemGo = "go", not "gomod").
func (a *GoModAdapter) blockIfTyposquat(w http.ResponseWriter, r *http.Request, modulePath, version string) bool {
	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), modulePath, scanner.EcosystemGo)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemGo), modulePath, adapter.TyposquatPlaceholderVersion)

	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	if a.policyEngine != nil {
		if overrideID, hasOverride := a.policyEngine.HasOverride(r.Context(), scanner.EcosystemGo, modulePath, version); hasOverride {
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

	if err := adapter.PersistTyposquatBlock(a.db, artifactID, scanner.EcosystemGo, modulePath, result, time.Now().UTC()); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("typosquat pre-scan: failed to persist block record")
	}

	// 410 Gone is the GOPROXY convention for "this module is not available
	// — do not retry credentials". Appropriate for typosquat blocks: it tells
	// the Go client to give up immediately rather than churning through
	// auth retries.
	adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
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
// public 410 response stays generic.
func typosquatBlockReason(result scanner.ScanResult) string {
	if len(result.Findings) > 0 {
		return "typosquat pre-scan: " + result.Findings[0].Description
	}
	return "typosquat pre-scan: " + string(result.Verdict)
}

// downloadScanServe implements the full download -> scan -> policy -> serve pipeline for .zip files.
func (a *GoModAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, parsed *parsedRequest, rawPath string) {
	ctx := r.Context()

	// Namespace the artifact ID by the serving index (eco__<index>); the default
	// index keeps the bare eco. The scanner Ecosystem stays canonical (go).
	eco := adapter.NamespacedEcosystem(string(scanner.EcosystemGo), idx.Name)
	artifactID := fmt.Sprintf("%s:%s:%s", eco, parsed.modulePath, parsed.version)

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
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("gomod: serving from cache")
		adapter.UpdateLastAccessedAt(a.db, artifactID)
		w.Header().Set("Content-Type", "application/zip")
		http.ServeFile(w, r, cachedPath)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventServed,
			ArtifactID: artifactID,
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		})
		// Trigger async sandbox scan (non-blocking).
		adapter.TriggerAsyncScan(r.Context(), scanner.Artifact{
			ID: artifactID, Ecosystem: scanner.Ecosystem(eco), Name: parsed.modulePath, Version: parsed.version, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context — see PyPI adapter for rationale.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()

	// Re-check cache after acquiring lock.
	if cachedPath, err := a.cache.Get(pctx, artifactID); err == nil {
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
		w.Header().Set("Content-Type", "application/zip")
		http.ServeFile(w, r, cachedPath)
		return
	}

	// 3. Download to temp file.
	upstreamURL, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), rawPath)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}

	tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: failed to download from upstream")
		http.Error(w, "failed to fetch upstream artifact", http.StatusBadGateway)
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

	// 4. Build scanner.Artifact. Ecosystem carries the namespaced segment
	// (go__<index>) so the persisted artifact row + cache isolate per index,
	// matching the PyPI/npm reference (the artifact ID already encodes it).
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.Ecosystem(eco),
		Name:        parsed.modulePath,
		Version:     parsed.version,
		LocalPath:   tmpPath,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4b. License detection — Trivy does not support Go modules, so we scan
	// LICENSE-family files in the module zip with google/licensecheck. The
	// resulting SPDX IDs feed both the scanner engine (for policy enforcement
	// on Go artifacts) and async sbom_metadata persistence after serving.
	if extra := extractLicensesFromGoModuleZip(tmpPath); len(extra) > 0 {
		scanArtifact.ExtraLicenses = extra
		log.Info().
			Str("artifact", artifactID).
			Strs("licenses", extra).
			Msg("gomod: detected licenses in module zip")
	}

	// 5. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("gomod: starting scan pipeline")
	scanReport, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("gomod: scan engine error")
	}
	scanResults := scanReport.Results
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
	policyResult := a.policyEngine.EvaluateReport(pctx, scanArtifact, scanReport)
	if len(policyResult.ScanUnavailable) > 0 {
		adapter.AuditScanUnavailable(r.Context(), a.db, policyResult, artifactID, "pull", r.RemoteAddr, r.UserAgent())
	}
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("gomod: policy decision")

	// 7. Act on policy result.
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
		adapter.WriteJSONError(w, http.StatusGone, adapter.ErrorResponse{
			Error:    "blocked",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		return

	case policy.ActionAllowWithWarning:
		_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
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
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
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
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: artifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
	w.Header().Set("Content-Type", "application/zip")
	http.ServeFile(w, r, tmpPath)

	// Trigger async sandbox scan (non-blocking).
	adapter.TriggerAsyncScan(r.Context(), scanArtifact, tmpPath, a.db, a.policyEngine)
	adapter.TriggerAsyncSBOMWrite(r.Context(), artifactID, scanResults)

	// Persist detected licenses so they appear in sbom_metadata / admin UI
	// even though Trivy does not emit an SBOM for Go modules.
	if len(scanArtifact.ExtraLicenses) > 0 {
		adapter.TriggerAsyncLicenseWrite(r.Context(), artifactID, scanArtifact.ExtraLicenses, "gomod-licensecheck")
	}
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
	if err := adapter.InsertArtifact(a.db, artifactID, art, artStatus); err != nil {
		return err
	}
	return adapter.InsertScanResults(a.db, artifactID, scanResults)
}

// downloadToTempAuthed downloads url into a temporary file, returning (path,
// size, sha256hex, error). When authHeader is non-empty it is sent as the
// Authorization header (per-index private-proxy credential); the client must be
// redirect-safe so the header is stripped on a cross-host/scheme redirect.
func downloadToTempAuthed(ctx context.Context, rawURL, authHeader string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("gomod: download: building request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
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
