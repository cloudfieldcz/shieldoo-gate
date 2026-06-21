// Package pypi implements a PEP 503/691 compatible proxy adapter for PyPI.
package pypi

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
	"regexp"
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
var _ adapter.Adapter = (*PyPIAdapter)(nil)

// PyPIAdapter proxies PyPI Simple API (PEP 503) and package downloads.
type PyPIAdapter struct {
	db               *config.GateDB
	cache            cache.CacheStore
	scanEngine       *scanner.Engine
	policyEngine     *policy.Engine
	upstreamURL      string // default index base (back-compat; == resolver default)
	filesHost        string // CDN for package file downloads; defaults to pypiFilesHost
	resolver         *adapter.UpstreamResolver
	router           http.Handler
	httpClient       *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

// NewPyPIAdapter creates and wires a PyPIAdapter.
func NewPyPIAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
	tagMutabilityCfg config.TagMutabilityConfig,
) *PyPIAdapter {
	defaultURL := upstreams.DefaultOr("https://pypi.org")
	resolver, err := adapter.NewUpstreamResolver("pypi", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		// Validation happened at config load; a build error here is a programming bug.
		panic(fmt.Sprintf("pypi: building upstream resolver: %v", err))
	}
	a := &PyPIAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(defaultURL, "/"),
		filesHost:        pypiFilesHost,
		resolver:         resolver,
		httpClient:       adapter.NewRedirectSafeClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}

// SetFilesHost overrides the CDN host used for package file downloads.
// Intended for testing only.
func (a *PyPIAdapter) SetFilesHost(host string) {
	a.filesHost = strings.TrimRight(host, "/")
}

// SetHTTPClient overrides the HTTP client used for artifact downloads.
// Intended for testing only — allows tests to inject a client that trusts
// self-signed TLS certificates from httptest.NewTLSServer.
func (a *PyPIAdapter) SetHTTPClient(c *http.Client) {
	a.httpClient = c
}

// DB returns the underlying GateDB. Intended for testing only.
func (a *PyPIAdapter) DB() *config.GateDB { return a.db }

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

// indexContext carries the serving index's identity through the download pipeline.
// name=="" and auth=="" for the default index (byte-identical behaviour).
type indexContext struct {
	name string // "" for the default index
	auth string // Authorization header value, or ""
}

// extIndexNameRe validates extra-index names: lowercase alphanum + hyphens only.
// This is the SSRF guard — reject any name that could forge a URL component.
var extIndexNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// ecosystemSeg returns the ecosystem string for the given index context:
// bare "pypi" for the default index, "pypi__<name>" for extra indexes.
func (a *PyPIAdapter) ecosystemSeg(ic indexContext) string {
	return adapter.NamespacedEcosystem(string(scanner.EcosystemPyPI), ic.name)
}

// pypiArtifactIDForEco builds a 4-segment artifact ID with an explicit ecosystem segment.
func pypiArtifactIDForEco(eco, name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", eco, name, version, filename)
}

// buildRouter creates the chi router with all PyPI routes.
func (a *PyPIAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/simple/", a.handleSimpleIndex)
	r.Get("/simple/{package}/", a.handleSimplePackage)
	r.Get("/packages/*", a.handlePackageDownload)
	r.Get("/ext-packages/{index}/*", a.handleExtraPackageDownload)
	return r
}

// handleExtraPackageDownload runs the full download → scan → policy → serve pipeline
// for artifacts fetched from a named extra index. It is the target of the rewritten
// download URLs produced by RewriteExtraIndexSimplePage.
//
// Security invariants:
//   - SSRF: the {index} name is validated against extIndexNameRe AND resolved via the
//     resolver before any upstream URL is constructed. Unknown/forged names → 404.
//   - Path-traversal: any ".." segment in the wildcard file path → 404.
//   - Artifacts are stored under the namespaced ecosystem "pypi__<index>" and go through
//     the full scan+cache pipeline — never served unscanned.
//   - Per-index auth is attached to the upstream request via a.resolver.AuthHeader.
func (a *PyPIAdapter) handleExtraPackageDownload(w http.ResponseWriter, r *http.Request) {
	index := chi.URLParam(r, "index")

	// SSRF guard: validate name format before touching the resolver.
	if !extIndexNameRe.MatchString(index) {
		http.NotFound(w, r)
		return
	}
	idx, ok := a.resolver.IndexByName(index)
	if !ok {
		http.NotFound(w, r)
		return
	}

	filePath := chi.URLParam(r, "*")

	// Path-traversal defence-in-depth (S6): percent-decode the wildcard first so
	// that %2e%2e (encoded "..") is caught alongside the literal form. We check the
	// DECODED segments but keep the original filePath for constructing the upstream
	// URL — only the traversal guard uses the decoded form.
	decoded, err := url.PathUnescape(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == ".." {
			http.NotFound(w, r)
			return
		}
	}

	// Determine the base URL for file downloads: FilesHost if set, otherwise the index URL.
	filesBase := idx.FilesHost
	if filesBase == "" {
		filesBase = idx.URL
	}
	upstreamFull := strings.TrimRight(filesBase, "/") + "/" + filePath

	ic := indexContext{name: index, auth: a.resolver.AuthHeader(idx)}

	// PEP 658 .metadata files — relay directly (size-capped, header-allowlisted, authed).
	if strings.HasSuffix(filePath, ".metadata") {
		a.proxyDirectAuthed(w, r, upstreamFull, ic.auth)
		return
	}

	a.downloadScanServeWithCtx(w, r, upstreamFull, filePath, ic)
}

// handleSimpleIndex proxies the PEP 503 simple index page.
func (a *PyPIAdapter) handleSimpleIndex(w http.ResponseWriter, r *http.Request) {
	a.proxyUpstream(w, r, "/simple/")
}

// handleSimplePackage fans out across all resolved indexes for the package,
// in fallback order, rewriting download URLs so artifacts route through the
// scan pipeline. Scoped packages (claimed by a named index) NEVER fall back
// to the default/public index — a scoped miss returns 404 with an audit row.
func (a *PyPIAdapter) handleSimplePackage(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid package name",
			Reason: err.Error(),
		})
		return
	}
	indexes := a.resolver.ResolveForPackage(pkg)
	for _, idx := range indexes {
		served, err := a.tryServeSimple(w, r, idx, pkg)
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
	// Nothing served — audit a scoped miss if the name was claimed.
	if claimants := a.resolver.ClaimingIndexNames(pkg); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemPyPI), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, CanonicalName(pkg)),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index package not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{
		Error:    "not found",
		Artifact: pkg,
		Reason:   "package not found on any configured index",
	})
}

// tryServeSimple fetches the simple page for pkg from idx, rewrites download
// URLs, and writes the response. Returns (true, nil) on success, (false, nil)
// on 404, (false, err) on any other upstream error.
func (a *PyPIAdapter) tryServeSimple(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, pkg string) (bool, error) {
	pageURL, err := url.JoinPath(idx.URL, "/simple/"+pkg+"/")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, pageURL, nil)
	if err != nil {
		return false, err
	}
	if idx.Name == "" {
		// Default index: relay the client's Accept header unchanged (byte-identical behaviour).
		if accept := r.Header.Get("Accept"); accept != "" {
			req.Header.Set("Accept", accept)
		}
	} else {
		// FIX A: Extra (lower-trust) indexes — force HTML so the upstream cannot
		// return PEP 691 JSON (which the href regex cannot parse, causing a fail-open
		// bypass). PEP 691 JSON is not yet supported for extra indexes.
		req.Header.Set("Accept", "text/html, application/vnd.pypi.simple.v1+html;q=0.9")
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
		return false, fmt.Errorf("pypi: index %q returned %d", idx.Name, resp.StatusCode)
	}
	const maxMetadataSize = 200 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("pypi: index %q metadata exceeds size limit", idx.Name)
	}
	var rewritten []byte
	if idx.Name == "" {
		// Default index: use the existing regex rewrite (byte-identical behaviour).
		rewritten = pypiDownloadURLRe.ReplaceAll(body, []byte("/packages/"))
	} else {
		// FIX A: Validate Content-Type for extra indexes — non-HTML means the upstream
		// ignored the forced Accept header and returned JSON (or something else). Fail
		// closed: serving verbatim JSON would bypass all scanning because the href regex
		// matches nothing in JSON.
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/vnd.pypi.simple.v1+html") {
			log.Error().
				Str("index", idx.Name).
				Str("package", pkg).
				Str("content_type", resp.Header.Get("Content-Type")).
				Msg("SECURITY: extra index returned non-HTML simple page, refusing to serve (would bypass scanning)")
			http.Error(w, "upstream metadata is not HTML; refusing to serve (would bypass scanning)", http.StatusBadGateway)
			return true, nil
		}
		var rerr error
		rewritten, rerr = adapter.RewriteExtraIndexSimplePage(body, idx, pageURL)
		if rerr != nil {
			log.Error().Err(rerr).Str("index", idx.Name).Str("package", pkg).
				Msg("SECURITY: simple-page rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
	}
	// FIX E: Header relay — extra indexes use an allowlist to prevent a low-trust
	// upstream from injecting Set-Cookie, CSP, Link, etc. The default index keeps
	// the existing full relay (byte-identical behaviour).
	if idx.Name == "" {
		// Default index: existing behaviour — relay all but Content-Length.
		for key, vals := range resp.Header {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
	} else {
		// Extra (lower-trust) index: allowlist only.
		for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rewritten)
	return true, nil
}

// pypiFilesHost is the CDN that serves actual PyPI package files.
const pypiFilesHost = "https://files.pythonhosted.org"

var validFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

const maxFilenameLen = 256

// PyPIArtifactID constructs a 4-segment artifact ID for PyPI.
func PyPIArtifactID(name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", string(scanner.EcosystemPyPI), name, version, filename)
}

// validateFilename checks the filename is safe for use in artifact IDs and cache paths.
func validateFilename(filename string) error {
	if len(filename) > maxFilenameLen {
		return fmt.Errorf("pypi: filename too long (%d > %d): %q", len(filename), maxFilenameLen, filename)
	}
	if !validFilenameRe.MatchString(filename) {
		return fmt.Errorf("pypi: filename contains invalid characters: %q", filename)
	}
	return nil
}

// handlePackageDownload runs the full download → scan → policy → serve pipeline.
func (a *PyPIAdapter) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	filePath := chi.URLParam(r, "*")

	// Map relative /packages/ paths back to the files CDN host.
	upstreamFull := a.filesHost + "/packages/" + filePath

	// uv requests .metadata files — proxy those directly without scanning.
	if strings.HasSuffix(filePath, ".metadata") {
		a.proxyDirect(w, r, upstreamFull)
		return
	}

	// Default index: indexContext with empty name/auth → bare "pypi" ecosystem, no auth header.
	a.downloadScanServeWithCtx(w, r, upstreamFull, filePath, indexContext{})
}

// proxyDirectAuthed fetches the given absolute URL, attaches an optional Authorization
// header, and relays the response with a size cap and a safe header allowlist.
// Used for PEP 658 .metadata files from extra indexes.
func (a *PyPIAdapter) proxyDirectAuthed(w http.ResponseWriter, r *http.Request, target, auth string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Safe header allowlist — prevent a low-trust upstream from injecting
	// Set-Cookie, CSP, Link, etc. into the client response.
	for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}

	// Size cap: 10 MB for .metadata files (PEP 658).
	const maxMetadataBytes int64 = 10 << 20
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxMetadataBytes))
}

// downloadScanServeWithCtx is the core scan pipeline.
// ic carries the serving index identity; ic.name=="" means the default PyPI index
// (bare "pypi" ecosystem, no auth header — byte-identical to the old behaviour).
func (a *PyPIAdapter) downloadScanServeWithCtx(w http.ResponseWriter, r *http.Request, upstreamURL, filePath string, ic indexContext) {
	ctx := r.Context()

	// Derive a simple artifact identifier from the path for DB/cache lookups.
	// We use path components: packages/<first>/<second>/<filename>
	parts := strings.Split(strings.Trim(filePath, "/"), "/")
	filename := parts[len(parts)-1]

	// Parse package name + version from filename (best-effort; PEP 427 wheel or sdist).
	pkgName, pkgVersion := parseFilename(filename)

	// Validate filename for safe use in artifact ID and cache paths.
	if err := validateFilename(filename); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid filename",
			Reason: err.Error(),
		})
		return
	}

	// Build artifact ID using the namespaced ecosystem segment.
	// Default index (ic.name=="") → bare "pypi:...", extra index → "pypi__<name>:...".
	artifactID := pypiArtifactIDForEco(a.ecosystemSeg(ic), pkgName, pkgVersion, filename)

	// 1. Check if already in cache with a known status.
	cachedPath, cacheErr := a.cache.Get(ctx, artifactID)
	if cacheErr == nil {
		// Cached — check status before serving. Fail closed on DB errors.
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
		// Tag mutability check on cache hit.
		if adapter.HandleTagMutability(ctx, a.tagMutabilityCfg, a.db, a.httpClient,
			a.ecosystemSeg(ic), pkgName, pkgVersion, artifactID, upstreamURL, r, w) {
			return
		}
		if adapter.CheckCacheHitLicensePolicy(w, r.Context(), a.policyEngine, a.db, artifactID) {
			return
		}
		// Serve from cache.
		log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("pypi: serving from cache")
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
			ID: artifactID, Ecosystem: scanner.Ecosystem(a.ecosystemSeg(ic)), Name: pkgName, Version: pkgVersion, LocalPath: cachedPath,
		}, cachedPath, a.db, a.policyEngine)
		return
	}

	// 2. Pre-scan for typosquatting BEFORE contacting upstream.
	// The typosquat scanner only needs the package name — no file content.
	// Blocking here avoids 502s for non-existent typosquat packages and
	// prevents the proxy from fetching known-bad names. Active policy
	// overrides (package- or version-scoped) suppress the block so admins
	// can allow legitimate-but-similar names through.
	if a.handleTyposquatPreScan(w, r, pkgName, pkgVersion) {
		return
	}

	// 3. Acquire per-artifact lock to prevent concurrent download/scan races.
	unlock := adapter.ArtifactLocker.Lock(artifactID)
	defer unlock()

	// Detach from the HTTP request context for the pipeline operations.
	// Cloud storage backends (Azure Blob, S3) honor context cancellation;
	// if the client disconnects mid-scan the upload would be aborted,
	// leaving the artifact uncached. Using a dedicated pipeline context
	// ensures download, scan, and cache write always complete.
	pctx, pcancel := adapter.PipelineContextFrom(r.Context())
	defer pcancel()

	// Re-check cache after acquiring lock — another request may have completed the pipeline.
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

	// 3. Download to temp file (attach per-index auth if present).
	tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, ic.auth, a.httpClient)
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

	// 3. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.Ecosystem(a.ecosystemSeg(ic)),
		Name:        pkgName,
		Version:     pkgVersion,
		LocalPath:   tmpPath,
		Filename:    filename,
		SHA256:      sha,
		SizeBytes:   size,
		UpstreamURL: upstreamURL,
	}

	// 4. Scan.
	log.Info().Str("artifact", artifactID).Str("client", r.RemoteAddr).Msg("pypi: starting scan pipeline")
	scanReport, err := a.scanEngine.ScanAll(pctx, scanArtifact)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("scan engine error")
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
		l.Msg("scan result")
	}

	// 5. Policy evaluation.
	policyResult := a.policyEngine.EvaluateReport(pctx, scanArtifact, scanReport)
	if len(policyResult.ScanUnavailable) > 0 {
		adapter.AuditScanUnavailable(r.Context(), a.db, policyResult, artifactID, "pull", r.RemoteAddr, r.UserAgent())
	}
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("policy decision")

	// 6. Act on policy result.
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
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "quarantined",
			Artifact: artifactID,
			Reason:   policyResult.Reason,
		})
		return
	}

	// 7. Allow — cache artifact and serve.
	_ = a.cache.Put(pctx, scanArtifact, tmpPath)
	_ = a.persistArtifact(artifactID, scanArtifact, model.StatusClean, "", nil, scanResults)

	// Emit any non-blocking policy warnings (license, etc.) before writing the body.
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
	// Persist SBOM asynchronously (non-blocking) if any scanner produced one.
	adapter.TriggerAsyncSBOMWrite(r.Context(), artifactID, scanResults)
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
	if err := adapter.InsertArtifact(a.db, artifactID, art, artStatus); err != nil {
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

// proxyDirect fetches the given absolute URL and relays the response.
func (a *PyPIAdapter) proxyDirect(w http.ResponseWriter, r *http.Request, target string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
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

// pypiDownloadURLRe matches PyPI download URLs (files.pythonhosted.org).
var pypiDownloadURLRe = regexp.MustCompile(`https://files\.pythonhosted\.org/packages/`)

// downloadToTemp downloads url into a temporary file, returning (path, size, sha256hex, error).
// For the default index (no auth). Delegates to downloadToTempAuthed with auth="".
func downloadToTemp(ctx context.Context, rawURL string, client *http.Client) (string, int64, string, error) {
	return downloadToTempAuthed(ctx, rawURL, "", client)
}

// downloadToTempAuthed downloads rawURL into a temporary file, optionally attaching an
// Authorization header. Returns (tmpPath, size, sha256hex, error).
// Cap: 2 GB to prevent disk exhaustion from malicious upstreams.
func downloadToTempAuthed(ctx context.Context, rawURL, auth string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: building request: %w", err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
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

	// Cap artifact download at 2 GB to prevent disk exhaustion from malicious upstreams.
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("pypi: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

// parseFilename extracts (packageName, version) from a PyPI filename.
// It handles both wheel (.whl) and sdist (.tar.gz, .zip) conventions.
// Falls back to (filename, "unknown") on parse failure.
//
// The returned package name is normalized to its PEP 503 canonical form
// (lowercase, runs of `-`/`_`/`.` collapsed to `-`) so artifact rows, allowlist
// matching, and admin UI search are all keyed on a single identifier
// independent of whether the source was a wheel filename (PEP 427, underscores)
// or a simple-index URL (PEP 503, hyphens). The filename argument itself is
// returned unmodified by callers — only the extracted name is canonicalized.
func parseFilename(filename string) (string, string) {
	rawName, version := splitNameVersion(filename)
	if rawName == "" {
		return filename, "unknown"
	}
	return CanonicalName(rawName), version
}

// handleTyposquatPreScan runs the typosquat scanner on pkgName before any
// upstream fetch. Returns true when the request was blocked (response already
// written) and false when the request should continue down the normal pipeline
// (clean name, scanner unavailable, or active policy override).
//
// The synthetic artifact ID always uses version="*" — typosquat detection is
// name-based, so the override scope is always package-wide. This ID is
// distinct from the per-version artifactID used by the rest of the pipeline,
// so a future legitimate fetch under a real version doesn't collide.
func (a *PyPIAdapter) handleTyposquatPreScan(w http.ResponseWriter, r *http.Request, pkgName, pkgVersion string) bool {
	result, ok := a.scanEngine.PreScanTyposquat(r.Context(), pkgName, scanner.EcosystemPyPI)
	if !ok {
		return false
	}
	if result.Verdict != scanner.VerdictSuspicious && result.Verdict != scanner.VerdictMalicious {
		return false
	}

	typosquatArtifactID := fmt.Sprintf("%s:%s:%s", string(scanner.EcosystemPyPI), pkgName, adapter.TyposquatPlaceholderVersion)

	// Detached audit context — request may cancel, audit must land.
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()

	if a.policyEngine != nil {
		if overrideID, hasOverride := a.policyEngine.HasOverride(r.Context(), scanner.EcosystemPyPI, pkgName, pkgVersion); hasOverride {
			log.Info().Str("artifact", typosquatArtifactID).Str("verdict", string(result.Verdict)).
				Int64("override_id", overrideID).
				Msg("typosquat pre-scan: allowed by policy override")
			_ = adapter.WriteAuditLogCtx(auditCtx, a.db, model.AuditEntry{
				EventType:    model.EventServed,
				ArtifactID:   typosquatArtifactID,
				ClientIP:     r.RemoteAddr,
				UserAgent:    r.UserAgent(),
				Reason:       "typosquat pre-scan overridden",
				MetadataJSON: fmt.Sprintf(`{"override_id":%d}`, overrideID),
			})
			return false
		}
	}

	log.Warn().Str("artifact", typosquatArtifactID).Str("verdict", string(result.Verdict)).
		Float32("confidence", result.Confidence).Msg("typosquat pre-scan: blocked before upstream fetch")
	if err := adapter.PersistTyposquatBlock(a.db, typosquatArtifactID, scanner.EcosystemPyPI, pkgName, result, time.Now().UTC()); err != nil {
		log.Error().Err(err).Str("artifact", typosquatArtifactID).Msg("typosquat pre-scan: failed to persist block record")
	}

	// Public 403 reason kept generic so attackers can't enumerate the seed;
	// rich description is preserved in scan_results.findings_json and
	// audit_log.reason for admins.
	adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
		Error:    "blocked",
		Artifact: typosquatArtifactID,
		Reason:   "typosquatting detected",
	})
	auditReason := "typosquat pre-scan: " + string(result.Verdict)
	if len(result.Findings) > 0 {
		auditReason = "typosquat pre-scan: " + result.Findings[0].Description
	}
	_ = adapter.WriteAuditLogCtx(auditCtx, a.db, model.AuditEntry{
		EventType:  model.EventBlocked,
		ArtifactID: typosquatArtifactID,
		ClientIP:   r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Reason:     auditReason,
	})
	return true
}

// splitNameVersion splits a PyPI filename into its raw (pre-canonical) name
// and version components, or returns ("", "") on parse failure.
func splitNameVersion(filename string) (string, string) {
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
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return base[:idx], base[idx+1:]
		}
	}
	// .zip
	if strings.HasSuffix(filename, ".zip") {
		base := strings.TrimSuffix(filename, ".zip")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return base[:idx], base[idx+1:]
		}
	}
	return "", ""
}
