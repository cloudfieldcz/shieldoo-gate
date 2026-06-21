// Package rubygems implements a proxy adapter for RubyGems API.
package rubygems

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
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*RubyGemsAdapter)(nil)

// validComponentRe matches safe path component characters.
var validComponentRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// RubyGemsAdapter proxies RubyGems HTTP API with artifact scanning on gem downloads.
type RubyGemsAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string // default index base (back-compat; == resolver default)
	resolver     *adapter.UpstreamResolver
	router       http.Handler
	httpClient   *http.Client
}

// NewRubyGemsAdapter creates and wires a RubyGemsAdapter.
func NewRubyGemsAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
) *RubyGemsAdapter {
	defaultURL := upstreams.DefaultOr("https://rubygems.org")
	resolver, err := adapter.NewUpstreamResolver("rubygems", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		panic(fmt.Sprintf("rubygems: building upstream resolver: %v", err))
	}
	a := &RubyGemsAdapter{
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
func (a *RubyGemsAdapter) DB() *config.GateDB { return a.db }

// idxURL returns the index URL, falling back to the default upstream for the
// default index (empty Name/URL).
func (a *RubyGemsAdapter) idxURL(idx adapter.ResolvedIndex) string {
	if idx.URL != "" {
		return idx.URL
	}
	return a.upstream
}

// Ecosystem implements adapter.Adapter.
func (a *RubyGemsAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemRubyGems }

// HealthCheck implements adapter.Adapter.
func (a *RubyGemsAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstream+"/api/v1/gems/rails.json", nil)
	if err != nil {
		return fmt.Errorf("rubygems: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rubygems: health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rubygems: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *RubyGemsAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates the chi router for RubyGems API routes.
func (a *RubyGemsAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// Gem download — triggers scan pipeline.
	r.Get("/gems/{filename}", a.handleGemDownload)

	// Per-gem metadata — fan out across indexes (rewrites gem_uri fail-closed for extra indexes).
	r.Get("/api/v1/gems/{name}.json", a.handleGemMetadata)
	r.Get("/api/v1/versions/{name}.json", a.handleVersionsMetadata)
	// Compact index (modern Bundler) — per-gem, relay-only, fans out. (Phase 6 S1 fix.)
	r.Get("/info/{name}", a.handleInfo)

	// Compressed gemspec pass-through (legacy gemspec — default-only).
	r.Get("/quick/Marshal.4.8/*", a.handlePassThrough)

	// Whole-index files pass-through (not per-package; default-only — cannot
	// enumerate private gems, by the settled ordered-fallback non-merge design).
	r.Get("/specs.4.8.gz", a.handlePassThrough)
	r.Get("/latest_specs.4.8.gz", a.handlePassThrough)
	r.Get("/prerelease_specs.4.8.gz", a.handlePassThrough)

	return r
}

// proxyOrigin reconstructs the gate's own origin ("<scheme>://<host>") from the
// inbound request, so rewritten download URLs point back at the gate.
func proxyOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (a *RubyGemsAdapter) handleGemMetadata(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/api/v1/gems/"+name+".json", true) // rewrite gem_uri
}

func (a *RubyGemsAdapter) handleVersionsMetadata(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/api/v1/versions/"+name+".json", false) // no download URL → no rewrite
}

// handleInfo serves the compact-index per-gem file (modern Bundler). It carries
// per-version numbers + checksums but NO download URL, so it is relay-only — the
// value is in fanning it out (a scoped name resolves only to its claiming index).
func (a *RubyGemsAdapter) handleInfo(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/info/"+name, false) // no download URL → no rewrite
}

// serveMetadataFanOut tries each resolved index for the gem's metadata, serving
// the first that has it (200). The default index relays verbatim (byte-identical
// to today). Extra indexes relay an allowlist of headers and, when rewriteGemURI
// is set, rewrite gem_uri fail-closed (502 on a foreign host / non-JSON). A
// claimed-namespace miss → 404 + audit.
func (a *RubyGemsAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, name, path string, rewriteGemURI bool) {
	for _, idx := range a.resolver.ResolveForPackage(name) {
		served, err := a.tryServeMetadata(w, r, idx, path, rewriteGemURI)
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
	if claimants := a.resolver.ClaimingIndexNames(name); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemRubyGems), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, name),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index gem not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: name})
}

// tryServeMetadata fetches one index's metadata at path. (true,nil)=served;
// (false,nil)=404; (false,err)=transport/non-200/rewrite error. A rewrite
// failure for an EXTRA index is FAIL CLOSED: writes 502, returns (true,nil).
func (a *RubyGemsAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, path string, rewriteGemURI bool) (bool, error) {
	target := strings.TrimRight(a.idxURL(idx), "/") + path
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
		return false, fmt.Errorf("rubygems: index %q returned %d", idx.Name, resp.StatusCode)
	}
	const maxMetadataSize = 64 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("rubygems: index %q metadata exceeds size limit", idx.Name)
	}

	out := body
	if idx.Name != "" && rewriteGemURI {
		rewritten, rerr := adapter.RewriteRubyGemsGemURI(body, idx, proxyOrigin(r))
		if rerr != nil {
			log.Error().Err(rerr).Str("index", idx.Name).Msg("SECURITY: rubygems gem_uri rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
		out = rewritten
	}
	relayMetadataHeaders(w, resp, idx.Name)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	return true, nil
}

// relayMetadataHeaders copies upstream headers. Extra (low-trust) indexes get an
// allowlist only; the default index relays all (minus Content-Length).
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

// parseGemFilename parses a gem filename into name and version.
// Gem filenames have the format: {name}-{version}.gem
// Names can contain hyphens (e.g. aws-sdk-core-3.0.0.gem).
// Platform-specific gems (e.g. nokogiri-1.16.0-x86_64-linux.gem) have the
// platform after the version; we strip it.
//
// Strategy: strip ".gem", then scan from right to find the last hyphen
// followed by a digit — that separates name from version+platform.
// Then strip any platform suffix from the version.
func parseGemFilename(filename string) (name, version string, err error) {
	if !strings.HasSuffix(filename, ".gem") {
		return "", "", fmt.Errorf("rubygems: filename %q does not end with .gem", filename)
	}

	base := strings.TrimSuffix(filename, ".gem")
	if base == "" {
		return "", "", fmt.Errorf("rubygems: empty gem filename")
	}

	// Find the last hyphen followed by a digit (scanning from right).
	splitIdx := -1
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '-' && i+1 < len(base) && unicode.IsDigit(rune(base[i+1])) {
			splitIdx = i
			break
		}
	}

	if splitIdx <= 0 {
		return "", "", fmt.Errorf("rubygems: cannot parse name/version from %q", filename)
	}

	name = base[:splitIdx]
	versionPart := base[splitIdx+1:]

	// Strip platform suffix from version if present.
	// Platform suffixes contain non-digit, non-dot characters after the version
	// digits, e.g. "1.16.0-x86_64-linux". We find the first hyphen after the
	// version number portion.
	version = stripPlatform(versionPart)

	if name == "" || version == "" {
		return "", "", fmt.Errorf("rubygems: cannot parse name/version from %q", filename)
	}

	return name, version, nil
}

// stripPlatform removes a platform suffix from a version string.
// Version strings like "1.16.0-x86_64-linux" become "1.16.0".
// Pure versions like "3.0.0" or "7.1.3.1" are returned as-is.
func stripPlatform(versionPart string) string {
	// Find the first hyphen — everything before it is the version.
	idx := strings.Index(versionPart, "-")
	if idx > 0 {
		return versionPart[:idx]
	}
	return versionPart
}

// rubygemsArtifactID returns the canonical artifact ID for DB/cache lookups.
func rubygemsArtifactID(name, version, filename string) string {
	return rubygemsArtifactIDFor(string(scanner.EcosystemRubyGems), name, version, filename)
}

// rubygemsArtifactIDFor builds the artifact ID for a (possibly namespaced) eco.
func rubygemsArtifactIDFor(eco, name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", eco, name, version, filename)
}

// handleTyposquatPreScan runs the typosquat scanner on name before any
// upstream call. Returns true if the request was blocked (response already
// written). Returns false if the name is clean, no scanner is registered, or
// an active policy override permits the request. Synthetic typosquat rows
// always carry version="*" — typosquat detection is name-based, so the
// override scope is package-wide regardless of the request's gem version.
func (a *RubyGemsAdapter) handleTyposquatPreScan(w http.ResponseWriter, r *http.Request, name, version string) bool {
	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), name, scanner.EcosystemRubyGems)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	// Synthetic 3-segment ID: rubygems:name:* (drop the filename slot — the
	// override scope is name-based and a single row represents all versions).
	artifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemRubyGems), name, adapter.TyposquatPlaceholderVersion)

	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	if a.policyEngine != nil {
		if overrideID, hasOverride := a.policyEngine.HasOverride(r.Context(), scanner.EcosystemRubyGems, name, version); hasOverride {
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

	if err := adapter.PersistTyposquatBlock(a.db, artifactID, scanner.EcosystemRubyGems, name, result, time.Now().UTC()); err != nil {
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
// log entries — keeps the popular-package name in the audit trail while the
// public 403 response stays generic.
func typosquatBlockReason(result scanner.ScanResult) string {
	if len(result.Findings) > 0 {
		return "typosquat pre-scan: " + result.Findings[0].Description
	}
	return "typosquat pre-scan: " + string(result.Verdict)
}

// handleGemDownload handles GET /gems/{filename} — the main scan pipeline.
func (a *RubyGemsAdapter) handleGemDownload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	if filename == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Path traversal protection.
	cleaned := path.Clean("/" + filename)
	if strings.Contains(filename, "..") || strings.Contains(cleaned, "..") || strings.Contains(filename, "/") {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: "path traversal detected",
		})
		return
	}

	// Validate filename characters.
	if !validComponentRe.MatchString(filename) {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: fmt.Sprintf("filename %q contains invalid characters", filename),
		})
		return
	}

	name, version, err := parseGemFilename(filename)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: err.Error(),
		})
		return
	}

	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
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

	idx := a.firstIndexFor(name)
	a.downloadScanServe(w, r, idx, name, version, filename)
}

// firstIndexFor recovers the serving index for a download by re-resolving the
// gem name (the /gems/ route carries the name). Returns the default index when
// resolution is empty (a scoped-miss download: the fetch then 404s on the absent
// upstream — correct, no public fallback).
func (a *RubyGemsAdapter) firstIndexFor(name string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(name); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}

// handlePassThrough proxies requests directly to the upstream without scanning.
func (a *RubyGemsAdapter) handlePassThrough(w http.ResponseWriter, r *http.Request) {
	// Reconstruct the upstream URL from the request path.
	reqPath := r.URL.Path

	// Path traversal protection.
	cleaned := path.Clean(reqPath)
	if strings.Contains(reqPath, "..") || strings.Contains(cleaned, "..") {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid path",
			Reason: "path traversal detected",
		})
		return
	}

	target, err := url.JoinPath(a.upstream, reqPath)
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

// downloadScanServe implements the full download -> scan -> policy -> serve pipeline.
func (a *RubyGemsAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, name, version, filename string) {
	ctx := r.Context()
	// Namespace the artifact ID by the serving index (eco__<index>); the default
	// index keeps the bare eco. The scanner Ecosystem stays canonical (rubygems).
	eco := adapter.NamespacedEcosystem(string(scanner.EcosystemRubyGems), idx.Name)
	artifactID := rubygemsArtifactIDFor(eco, name, version, filename)

	// Pre-scan for typosquatting BEFORE contacting upstream.
	if a.handleTyposquatPreScan(w, r, name, version) {
		return
	}

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		status, err := adapter.GetArtifactStatus(a.db, artifactID)
		if err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to check artifact status, refusing to serve")
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
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("rubygems: serving from cache")
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
			ID: artifactID, Ecosystem: scanner.Ecosystem(eco), Name: name, Version: version, LocalPath: cachedPath,
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
			log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to check artifact status, refusing to serve")
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

	// 3. Download to temp file from the resolved serving index (with its auth).
	upstreamURL, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), "gems", filename)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}

	tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: failed to download from upstream")
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
	// (rubygems__<index>) so the persisted artifact row + cache isolate per index,
	// matching the PyPI/npm reference (the artifact ID already encodes it).
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.Ecosystem(eco),
		Name:        name,
		Version:     version,
		LocalPath:   tmpPath,
		Filename:    filename,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 5. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("rubygems: starting scan pipeline")
	scanReport, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rubygems: scan engine error")
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
		l.Msg("rubygems: scan result")
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
		Msg("rubygems: policy decision")

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

	// 8. Allow — cache artifact and serve.
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

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

// persistArtifact writes the artifact, status, and scan results to the DB.
func (a *RubyGemsAdapter) persistArtifact(
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
// Authorization header (per-index private-source credential); the client must be
// redirect-safe so the header is stripped on a cross-host/scheme redirect.
func downloadToTempAuthed(ctx context.Context, rawURL, authHeader string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("rubygems: download: building request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("rubygems: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("rubygems: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-rubygems-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("rubygems: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	// Cap artifact download at 2 GB to prevent disk exhaustion.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("rubygems: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
