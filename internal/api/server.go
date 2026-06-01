// Package api implements the REST API server for Shieldoo Gate.
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Server is the REST API server.
type Server struct {
	db            *config.GateDB
	cacheStore    cache.CacheStore
	scanEngine    *scanner.Engine
	policyEngine  *policy.Engine
	uiDir         string
	dockerConfig  config.DockerUpstreamConfig
	syncSvc       *docker.SyncService
	oidcMw           *auth.OIDCMiddleware
	adminChain       *auth.AdminAuthChain
	patMw            *auth.PATBearerMiddleware
	authHandlers     *auth.AuthHandlers
	authEnabled      bool
	proxyAuthEnabled bool
	publicURLs       config.PublicURLsConfig
	onRescanQueued   func()
	projectSvc       project.Service
	sbomStore        sbom.Storage
	sbomGenerator    *sbom.Generator
	licenseResolver  *license.Resolver
	vulnDeps         VulnDeps
	aiDeps           AIDeps
	rateLimiter      *auth.RateLimiter
	scanSched        *scanScheduler
}

// NewServer creates a new Server with the given dependencies.
func NewServer(db *config.GateDB, cacheStore cache.CacheStore, scanEngine *scanner.Engine, policyEngine *policy.Engine) *Server {
	return &Server{
		db:           db,
		cacheStore:   cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		uiDir:        "/var/www/shieldoo-gate/ui",
	}
}

// SetAuth configures OIDC authentication middleware and handlers.
// When called, protected routes will require a valid Bearer token or session cookie.
func (s *Server) SetAuth(oidcMw *auth.OIDCMiddleware, authHandlers *auth.AuthHandlers) {
	s.oidcMw = oidcMw
	s.authHandlers = authHandlers
	s.authEnabled = true
}

// SetAdminAuthChain registers the PAT-Bearer + OIDC chain used by the admin API.
// Called after SetAuth when proxy_auth is enabled.
func (s *Server) SetAdminAuthChain(chain *auth.AdminAuthChain, pat *auth.PATBearerMiddleware) {
	s.adminChain = chain
	s.patMw = pat
}

// SetRateLimiter wires the per-token rate limiter used on scan-upload, ignore-create,
// AI-draft, and SBOM download endpoints.
func (s *Server) SetRateLimiter(rl *auth.RateLimiter) {
	s.rateLimiter = rl
}

// RateLimiter returns the wired limiter so feature wiring can add its own
// dimension overrides. Nil before SetRateLimiter has been called.
func (s *Server) RateLimiter() *auth.RateLimiter {
	return s.rateLimiter
}

// SetRescanNotifier sets a callback invoked when a manual rescan is queued,
// allowing the rescan scheduler to wake up immediately.
func (s *Server) SetRescanNotifier(fn func()) {
	s.onRescanQueued = fn
}

// SetProxyAuth configures proxy auth state so that API key management routes
// are registered only when both OIDC auth and proxy auth are enabled.
func (s *Server) SetProxyAuth(proxyAuthEnabled, authEnabled bool) {
	s.proxyAuthEnabled = proxyAuthEnabled && authEnabled
}

// SetPublicURLs configures the public-facing URLs for each ecosystem proxy.
func (s *Server) SetPublicURLs(cfg config.PublicURLsConfig) {
	s.publicURLs = cfg
}

// SetDockerConfig sets the Docker upstream configuration for the registries endpoint.
func (s *Server) SetDockerConfig(cfg config.DockerUpstreamConfig) {
	s.dockerConfig = cfg
}

// SetSyncService sets the Docker sync service for the manual sync trigger endpoint.
func (s *Server) SetSyncService(svc *docker.SyncService) {
	s.syncSvc = svc
}

// SetProjectService wires the project registry for admin API routes.
func (s *Server) SetProjectService(svc project.Service) {
	s.projectSvc = svc
}

// Routes returns a chi.Router with all API routes registered.
// When auth is enabled, admin API routes require a valid OIDC token.
// Health, metrics, and auth flow endpoints remain unauthenticated.
func (s *Server) Routes() chi.Router {
	r := chi.NewRouter()

	r.Use(auth.Recoverer)
	r.Use(middleware.RealIP)

	// Health endpoint — always unauthenticated.
	r.Get("/api/v1/health", s.handleHealth)

	// Prometheus metrics — always unauthenticated.
	r.Handle("/metrics", promhttp.Handler())

	// Auth flow endpoints (unauthenticated — they implement the login flow).
	if s.authEnabled && s.authHandlers != nil {
		r.Route("/auth", func(r chi.Router) {
			r.Get("/login", s.authHandlers.HandleLogin)
			r.Get("/callback", s.authHandlers.HandleCallback)
			r.Post("/logout", s.authHandlers.HandleLogout)
			r.Post("/refresh", s.authHandlers.HandleRefresh)
		})
	}

	// Public scan-upload endpoint — protected by PAT scan:upload scope, NOT by OIDC.
	// Mounted outside the OIDC group so a CI runner can authenticate with a token.
	if s.VulnEnabled() {
		r.Group(func(r chi.Router) {
			if s.patMw != nil {
				r.Use(s.patMw.Authenticate)
			}
			r.Use(auth.RequireScope("scan:upload"))
			if s.rateLimiter != nil {
				r.Use(s.rateLimiter.Middleware("scan-upload"))
			}
			r.Post("/api/v1/projects/{label}/components/{name}/scans", s.handleScanUpload)
		})
	}

	// Protected admin API routes.
	r.Group(func(r chi.Router) {
		switch {
		case s.adminChain != nil:
			r.Use(s.adminChain.Authenticate)
		case s.authEnabled && s.oidcMw != nil:
			r.Use(s.oidcMw.Authenticate)
		}

		r.Route("/api/v1", func(r chi.Router) {
			// Artifacts
			r.Get("/artifacts", s.handleListArtifacts)
			r.Get("/artifacts/{id}", s.handleGetArtifact)
			r.Get("/artifacts/{id}/scan-results", s.handleGetArtifactScanResults)
			if s.sbomStore != nil {
				r.Get("/artifacts/{id}/sbom", s.handleGetArtifactSBOM)
				r.Get("/artifacts/{id}/licenses", s.handleGetArtifactLicenses)
			}
			r.Post("/artifacts/{id}/rescan", s.handleRescanArtifact)
			r.Post("/artifacts/{id}/quarantine", s.handleQuarantineArtifact)
			r.Post("/artifacts/{id}/release", s.handleReleaseArtifact)
			r.Post("/artifacts/{id}/override", s.handleCreateArtifactOverride)
			r.Delete("/artifacts/{id}", s.handleDeleteArtifact)

			// Audit log
			r.Get("/audit", s.handleListAudit)

			// Policy overrides
			r.Get("/overrides", s.handleListOverrides)
			r.Post("/overrides", s.handleCreateOverride)
			r.Delete("/overrides/{id}", s.handleRevokeOverride)

			// Stats
			r.Get("/stats/summary", s.handleStatsSummary)
			r.Get("/stats/blocked", s.handleStatsBlocked)

			// Threat feed
			r.Get("/feed", s.handleListFeed)
			r.Post("/feed/refresh", s.handleRefreshFeed)

			// Docker management
			r.Get("/docker/repositories", s.handleListDockerRepositories)
			r.Get("/docker/repositories/{id}/tags", s.handleListDockerTags)
			r.Post("/docker/repositories/{id}/tags", s.handleCreateDockerTag)
			r.Delete("/docker/repositories/{id}/tags/{tag}", s.handleDeleteDockerTag)
			r.Post("/docker/sync/{id}", s.handleDockerSync)
			r.Get("/docker/registries", s.handleListDockerRegistries)

			// Admin actions
			r.Post("/admin/rescan-quarantined", s.handleRescanQuarantined)
			r.Get("/admin/policy-mode", s.handleGetPolicyMode)
			r.Put("/admin/policy-mode", s.handleSetPolicyMode)

			// Public URLs for usage instructions
			r.Get("/public-urls", s.handlePublicURLs)

			// Project registry
			if s.projectSvc != nil {
				r.Get("/projects", s.handleListProjects)
				r.Post("/projects", s.handleCreateProject)
				r.Get("/projects/{id}", s.handleGetProject)
				r.Patch("/projects/{id}", s.handleUpdateProject)
				r.Delete("/projects/{id}", s.handleDisableProject)
				r.Get("/projects/{id}/artifacts", s.handleListProjectArtifacts)
				// SBOM export route is always registered when the project
				// registry is up — the handler itself returns 501 when SBOM
				// is disabled in config (s.sbomGenerator == nil). This way the
				// API matches the OpenAPI spec (501 = feature off) instead of
				// returning chi's generic 404, and clients can distinguish
				// "SBOM disabled" from "project not found".
				r.Group(func(r chi.Router) {
					if s.rateLimiter != nil {
						r.Use(s.rateLimiter.Middleware("sbom-download"))
					}
					r.Get("/projects/{id}/sbom", s.handleGetProjectSBOM)
				})
				r.Get("/projects/{id}/license-policy", s.handleGetProjectLicensePolicy)
				r.Put("/projects/{id}/license-policy", s.handlePutProjectLicensePolicy)
				r.Delete("/projects/{id}/license-policy", s.handleDeleteProjectLicensePolicy)
				r.Get("/projects/{id}/overrides", s.handleListProjectOverrides)
				r.Post("/projects/{id}/overrides", s.handleCreateProjectOverride)
				r.Post("/projects/{id}/overrides/{overrideId}/revoke", s.handleRevokeProjectOverride)
			}

			// Global license policy (runtime-mutable; overrides YAML).
			if s.licenseResolver != nil {
				r.Get("/policy/licenses", s.handleGetGlobalLicensePolicy)
				r.Put("/policy/licenses", s.handlePutGlobalLicensePolicy)
				r.Delete("/policy/licenses", s.handleDeleteGlobalLicensePolicy)
			}

			// API key management (only when auth + proxy_auth are both enabled)
			if s.proxyAuthEnabled {
				r.Post("/api-keys", s.handleCreateAPIKey)
				r.Get("/api-keys", s.handleListAPIKeys)
				r.Delete("/api-keys/{id}", s.handleRevokeAPIKey)
			}

			// Vulnerability scan routes.
			if s.VulnEnabled() {
				r.Get("/vulnerabilities/components", s.handleListVulnerabilities)
				r.Get("/vulnerabilities/components/{id}", s.handleGetComponent)
				r.Patch("/vulnerabilities/components/{id}", s.handleUpdateComponent)
				r.Get("/vulnerabilities/components/{id}/scans", s.handleListScanRuns)
				r.Get("/vulnerabilities/components/{id}/ignores", s.handleListIgnores)
				// Mutating ignore endpoints are rate-limited on two dimensions:
				//   ignore-create-token : per-token global (covers fan-out)
				//   ignore-create-comp  : per-(token,component) — prevents one comp
				//                          from exhausting the global token quota.
				r.Group(func(r chi.Router) {
					if s.rateLimiter != nil {
						r.Use(s.rateLimiter.Middleware("ignore-create-token"))
						r.Use(s.rateLimiter.MiddlewareByPath("ignore-create-comp", "id"))
					}
					r.Post("/vulnerabilities/components/{id}/ignores", s.handleCreateIgnore)
					r.Delete("/vulnerabilities/components/{id}/ignores/{ignoreId}", s.handleRevokeIgnore)
				})
				r.Group(func(r chi.Router) {
					if s.rateLimiter != nil {
						r.Use(s.rateLimiter.Middleware("rescan"))
					}
					r.Post("/vulnerabilities/components/{id}/rescan", s.handleManualRescan)
				})
				r.Get("/vulnerabilities/scan-runs/{id}", s.handleGetScanRun)
				r.Get("/vulnerabilities/scan-runs/{id}/findings", s.handleGetScanRunFindings)
				r.Group(func(r chi.Router) {
					if s.rateLimiter != nil {
						r.Use(s.rateLimiter.Middleware("sbom-download"))
					}
					r.Get("/vulnerabilities/scan-runs/{id}/sbom", s.handleGetScanRunSBOM)
				})
				r.Get("/vulnerabilities/summary", s.handleVulnSummary)
				r.Get("/vulnerabilities/badge", s.handleVulnBadge)
				if s.projectSvc != nil {
					r.Get("/projects/{id}/components", s.handleListComponentsByProject)
				}
			}

			// AI surfaces (registered ONLY when ai_features.enabled = true; 404 by absence).
			if s.AIEnabled() {
				r.Get("/ai/anomalies", s.handleListAnomalies)
				r.Post("/ai/anomalies/{id}/acknowledge", s.handleAcknowledgeAnomaly)
				r.Get("/ai/components/{id}/fix-path", s.handleFixPathInsight)
				r.Group(func(r chi.Router) {
					if s.rateLimiter != nil {
						r.Use(s.rateLimiter.Middleware("ai-draft"))
					}
					r.Post("/ai/draft-ignore-reason", s.handleDraftIgnoreReason)
				})
			}
		})

		// Authenticated userinfo endpoint (requires valid session).
		if s.authEnabled && s.authHandlers != nil {
			r.Get("/auth/userinfo", s.authHandlers.HandleUserInfo)
		}
	})

	// Serve admin UI (SPA fallback)
	r.Get("/*", s.serveSPA)

	return r
}

// serveSPA serves the React SPA from uiDir with fallback to index.html.
// When auth is enabled, HTML page requests (SPA routes) require a valid
// session cookie — otherwise the browser is redirected to /auth/login.
// Static assets (JS, CSS, images) are always served without auth so the
// login page itself can load.
func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.uiDir, filepath.Clean(r.URL.Path))

	// Prevent path traversal
	if !strings.HasPrefix(path, s.uiDir) {
		http.NotFound(w, r)
		return
	}

	// Check if this is an SPA route (file doesn't exist on disk → index.html fallback).
	// Static assets (JS/CSS/images) exist on disk and are served without auth.
	_, statErr := os.Stat(path)
	isSPARoute := os.IsNotExist(statErr)

	if isSPARoute && s.authEnabled {
		cookie, err := r.Cookie("shieldoo_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
	}

	if isSPARoute {
		http.ServeFile(w, r, filepath.Join(s.uiDir, "index.html"))
		return
	}
	http.ServeFile(w, r, path)
}
