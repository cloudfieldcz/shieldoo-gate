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
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
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
	authHandlers     *auth.AuthHandlers
	authEnabled      bool
	proxyAuthEnabled bool
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

// SetProxyAuth configures proxy auth state so that API key management routes
// are registered only when both OIDC auth and proxy auth are enabled.
func (s *Server) SetProxyAuth(proxyAuthEnabled, authEnabled bool) {
	s.proxyAuthEnabled = proxyAuthEnabled && authEnabled
}

// SetDockerConfig sets the Docker upstream configuration for the registries endpoint.
func (s *Server) SetDockerConfig(cfg config.DockerUpstreamConfig) {
	s.dockerConfig = cfg
}

// SetSyncService sets the Docker sync service for the manual sync trigger endpoint.
func (s *Server) SetSyncService(svc *docker.SyncService) {
	s.syncSvc = svc
}

// Routes returns a chi.Router with all API routes registered.
// When auth is enabled, admin API routes require a valid OIDC token.
// Health, metrics, and auth flow endpoints remain unauthenticated.
func (s *Server) Routes() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
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

	// Protected admin API routes.
	r.Group(func(r chi.Router) {
		if s.authEnabled && s.oidcMw != nil {
			r.Use(s.oidcMw.Authenticate)
		}

		r.Route("/api/v1", func(r chi.Router) {
			// Artifacts
			r.Get("/artifacts", s.handleListArtifacts)
			r.Get("/artifacts/{id}", s.handleGetArtifact)
			r.Get("/artifacts/{id}/scan-results", s.handleGetArtifactScanResults)
			r.Post("/artifacts/{id}/rescan", s.handleRescanArtifact)
			r.Post("/artifacts/{id}/quarantine", s.handleQuarantineArtifact)
			r.Post("/artifacts/{id}/release", s.handleReleaseArtifact)
			r.Post("/artifacts/{id}/override", s.handleCreateArtifactOverride)

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

			// API key management (only when auth + proxy_auth are both enabled)
			if s.proxyAuthEnabled {
				r.Post("/api-keys", s.handleCreateAPIKey)
				r.Get("/api-keys", s.handleListAPIKeys)
				r.Delete("/api-keys/{id}", s.handleRevokeAPIKey)
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
