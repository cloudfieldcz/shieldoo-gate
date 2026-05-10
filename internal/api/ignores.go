package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
)

type ignoreCreateRequest struct {
	CVEID          string  `json:"cve_id"`
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	Reason         string  `json:"reason"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
	AIDraftAccepted bool   `json:"ai_draft_accepted"`
	AgainstRunID   int64   `json:"against_run_id"`
}

// handleListIgnores returns active ignores for a component. With ?include=expired
// it additionally returns recently revoked ignores in a separate `expired` array,
// so the UI can render a "restore" panel without a second round-trip.
func (s *Server) handleListIgnores(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rows, err := s.vulnDeps.Ignore.ListActive(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"items": rows}
	if r.URL.Query().Get("include") == "expired" {
		expired, err := s.vulnDeps.Ignore.ListRecentRevoked(r.Context(), id, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp["expired"] = expired
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateIgnore creates a CVE ignore.
func (s *Server) handleCreateIgnore(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req ignoreCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CVEID = strings.TrimSpace(req.CVEID)
	req.PackageName = strings.TrimSpace(req.PackageName)
	if req.CVEID == "" || req.PackageName == "" {
		writeError(w, http.StatusBadRequest, "cve_id and package_name required")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_at (RFC3339)")
			return
		}
		expiresAt = &t
	}
	user := auth.UserFromContext(r.Context())
	byEmail := ""
	if user != nil {
		byEmail = user.Email
	}
	ig, err := s.vulnDeps.Ignore.Create(r.Context(), id, req.CVEID, req.PackageName, req.PackageVersion, req.Reason,
		expiresAt, req.AIDraftAccepted, byEmail, req.AgainstRunID)
	if err != nil {
		switch {
		case errors.Is(err, component.ErrIgnoreExists):
			writeError(w, http.StatusConflict, "ignore already exists")
		case errors.Is(err, component.ErrInvalidName):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, component.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "ignore cap reached")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, ig)
}

// handleRevokeIgnore revokes an ignore.
func (s *Server) handleRevokeIgnore(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	ignoreID, err := pathInt64(r, "ignoreId")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ignoreId")
		return
	}
	user := auth.UserFromContext(r.Context())
	byEmail := ""
	if user != nil {
		byEmail = user.Email
	}
	if err := s.vulnDeps.Ignore.Revoke(r.Context(), ignoreID, byEmail); err != nil {
		if errors.Is(err, component.ErrIgnoreNotFound) {
			writeError(w, http.StatusNotFound, "ignore not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
