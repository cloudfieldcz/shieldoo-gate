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
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Server is the REST API server.
type Server struct {
	db           *config.GateDB
	cacheStore   cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	uiDir        string
	dockerConfig config.DockerUpstreamConfig
	syncSvc      *docker.SyncService
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

// SetDockerConfig sets the Docker upstream configuration for the registries endpoint.
func (s *Server) SetDockerConfig(cfg config.DockerUpstreamConfig) {
	s.dockerConfig = cfg
}

// SetSyncService sets the Docker sync service for the manual sync trigger endpoint.
func (s *Server) SetSyncService(svc *docker.SyncService) {
	s.syncSvc = svc
}

// Routes returns a chi.Router with all API routes registered.
func (s *Server) Routes() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	r.Route("/api/v1", func(r chi.Router) {
		// Health
		r.Get("/health", s.handleHealth)

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
	})

	// Prometheus metrics
	r.Handle("/metrics", promhttp.Handler())

	// Serve admin UI (SPA fallback)
	r.Get("/*", s.serveSPA)

	return r
}

// serveSPA serves the React SPA from uiDir with fallback to index.html.
func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.uiDir, filepath.Clean(r.URL.Path))

	// Prevent path traversal
	if !strings.HasPrefix(path, s.uiDir) {
		http.NotFound(w, r)
		return
	}

	// If the file exists, serve it; otherwise fall back to index.html for SPA routing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.ServeFile(w, r, filepath.Join(s.uiDir, "index.html"))
		return
	}
	http.ServeFile(w, r, path)
}
