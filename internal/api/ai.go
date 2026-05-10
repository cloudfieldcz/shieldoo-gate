package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
)

// AIDeps bundles AI-surface services and feature-flag state for the API server.
type AIDeps struct {
	Enabled       bool
	Anomaly       *ai.AnomalyDetector
	FixPath       *ai.FixPathAnalyzer
	Drafter       *ai.IgnoreReasonDrafter
}

// SetAIDeps wires the AI surfaces; routes are registered only when Enabled=true.
func (s *Server) SetAIDeps(d AIDeps) {
	s.aiDeps = d
}

// AIEnabled returns true when the feature flag and at least one surface is on.
func (s *Server) AIEnabled() bool { return s.aiDeps.Enabled }

// handleListAnomalies returns recent anomalies not yet acknowledged by viewer.
func (s *Server) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	email := ""
	if user != nil {
		email = user.Email
	}
	anomalies, err := ai.ListAnomalies(r.Context(), s.db, email, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": anomalies})
}

// handleAcknowledgeAnomaly inserts a per-user acknowledgment row.
func (s *Server) handleAcknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user := auth.UserFromContext(r.Context())
	email := ""
	if user != nil {
		email = user.Email
	}
	if email == "" {
		writeError(w, http.StatusUnauthorized, "user identity required")
		return
	}
	if err := ai.AcknowledgeAnomaly(r.Context(), s.db, id, email); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFixPathInsight returns the fix-path recommendation for a component's latest run.
func (s *Server) handleFixPathInsight(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if s.aiDeps.FixPath == nil {
		writeError(w, http.StatusNotFound, "fix-path analyzer disabled")
		return
	}
	comp, err := s.vulnDeps.Component.Get(r.Context(), id)
	if err != nil || comp.LastScanID == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	insight, err := s.aiDeps.FixPath.Analyze(r.Context(), *comp.LastScanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, insight)
}

// handleDraftIgnoreReason calls the scanner-bridge LLM via gRPC.
type draftRequest struct {
	ComponentID    int64  `json:"component_id"`
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

func (s *Server) handleDraftIgnoreReason(w http.ResponseWriter, r *http.Request) {
	var req draftRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	comp, err := s.vulnDeps.Component.Get(r.Context(), req.ComponentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "component not found")
		return
	}
	if !comp.AIEnabled || comp.RepoURL == "" {
		writeError(w, http.StatusServiceUnavailable, "ai disabled for this component")
		return
	}
	if s.aiDeps.Drafter == nil {
		writeError(w, http.StatusServiceUnavailable, "drafter not configured")
		return
	}
	user := auth.UserFromContext(r.Context())
	email := ""
	if user != nil {
		email = user.Email
	}
	resp, err := s.aiDeps.Drafter.Draft(r.Context(), ai.DraftRequest{
		ComponentID:    comp.ID,
		CVEID:          req.CVEID,
		PackageName:    req.PackageName,
		PackageVersion: req.PackageVersion,
		RepoURL:        comp.RepoURL,
		OperatorEmail:  email,
	})
	if err != nil {
		if errors.Is(err, ai.ErrDrafterDisabled) {
			writeError(w, http.StatusServiceUnavailable, "ai drafter disabled")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reason": resp.Reason})
}
