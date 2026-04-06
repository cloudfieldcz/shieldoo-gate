package api

import (
	"encoding/json"
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
)

// handleGetPolicyMode handles GET /api/v1/admin/policy-mode.
func (s *Server) handleGetPolicyMode(w http.ResponseWriter, r *http.Request) {
	mode := s.policyEngine.Mode()
	writeJSON(w, http.StatusOK, map[string]string{
		"mode": mode.String(),
	})
}

// handleSetPolicyMode handles PUT /api/v1/admin/policy-mode.
func (s *Server) handleSetPolicyMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	parsed, err := policy.ParsePolicyMode(req.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.policyEngine.SetMode(parsed)

	writeJSON(w, http.StatusOK, map[string]string{
		"mode": parsed.String(),
	})
}
