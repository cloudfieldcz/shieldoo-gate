// Package api implements the REST API server for Shieldoo Gate.
package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Server is the REST API server.
type Server struct {
	db           *sqlx.DB
	cacheStore   cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
}

// NewServer creates a new Server with the given dependencies.
func NewServer(db *sqlx.DB, cacheStore cache.CacheStore, scanEngine *scanner.Engine, policyEngine *policy.Engine) *Server {
	return &Server{
		db:           db,
		cacheStore:   cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
	}
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

		// Stats
		r.Get("/stats/summary", s.handleStatsSummary)
		r.Get("/stats/blocked", s.handleStatsBlocked)

		// Threat feed
		r.Get("/feed", s.handleListFeed)
		r.Post("/feed/refresh", s.handleRefreshFeed)
	})

	// Prometheus metrics
	r.Handle("/metrics", promhttp.Handler())

	return r
}
