package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
)

// licensePolicyView is the JSON shape for GET /projects/{id}/license-policy.
type licensePolicyView struct {
	ProjectID     int64    `json:"project_id"`
	Mode          string   `json:"mode"` // "inherit" | "override" | "disabled"
	Blocked       []string `json:"blocked,omitempty"`
	Warned        []string `json:"warned,omitempty"`
	Allowed       []string `json:"allowed,omitempty"`
	UnknownAction string   `json:"unknown_action,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	UpdatedBy     string   `json:"updated_by,omitempty"`
	// Source reports which policy is effective at runtime ("global" or
	// "project:<label>"). Used by the UI to explain inheritance.
	EffectiveSource string `json:"effective_source,omitempty"`
}

type licensePolicyUpdate struct {
	Mode          string   `json:"mode"`
	Blocked       []string `json:"blocked"`
	Warned        []string `json:"warned"`
	Allowed       []string `json:"allowed"`
	UnknownAction string   `json:"unknown_action"`
}

// SetLicenseResolver wires the license resolver so the API can invalidate the
// per-project cache after updates.
func (s *Server) SetLicenseResolver(r *license.Resolver) {
	s.licenseResolver = r
}

// handleGetProjectLicensePolicy returns the per-project override row (or inherit).
func (s *Server) handleGetProjectLicensePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}

	view := licensePolicyView{
		ProjectID:       id,
		Mode:            "inherit",
		EffectiveSource: "global",
	}

	var row struct {
		Mode          string  `db:"mode"`
		BlockedJSON   *string `db:"blocked_json"`
		WarnedJSON    *string `db:"warned_json"`
		AllowedJSON   *string `db:"allowed_json"`
		UnknownAction *string `db:"unknown_action"`
		UpdatedAt     string  `db:"updated_at"`
		UpdatedBy     *string `db:"updated_by"`
	}
	err = s.db.Get(&row,
		`SELECT mode, blocked_json, warned_json, allowed_json, unknown_action,
		        updated_at, updated_by
		 FROM project_license_policy WHERE project_id = ?`, id)
	if err == nil {
		view.Mode = row.Mode
		view.UpdatedAt = row.UpdatedAt
		if row.BlockedJSON != nil {
			_ = json.Unmarshal([]byte(*row.BlockedJSON), &view.Blocked)
		}
		if row.WarnedJSON != nil {
			_ = json.Unmarshal([]byte(*row.WarnedJSON), &view.Warned)
		}
		if row.AllowedJSON != nil {
			_ = json.Unmarshal([]byte(*row.AllowedJSON), &view.Allowed)
		}
		if row.UnknownAction != nil {
			view.UnknownAction = *row.UnknownAction
		}
		if row.UpdatedBy != nil {
			view.UpdatedBy = *row.UpdatedBy
		}
	}

	// Annotate runtime source.
	switch view.Mode {
	case "override":
		view.EffectiveSource = "project-override"
	case "disabled":
		view.EffectiveSource = "disabled"
	}

	writeJSON(w, http.StatusOK, view)
}

// handlePutProjectLicensePolicy upserts the project override. Per-project
// overrides apply in both lazy and strict projects modes (see ADR-004) — the
// override is an admin-authored DB row, independent of the lazy/strict auth
// model.
func (s *Server) handlePutProjectLicensePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}

	var body licensePolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	switch body.Mode {
	case "inherit", "override", "disabled":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be 'inherit'|'override'|'disabled'"})
		return
	}

	blockedJSON, _ := json.Marshal(body.Blocked)
	warnedJSON, _ := json.Marshal(body.Warned)
	allowedJSON, _ := json.Marshal(body.Allowed)

	actor := ""
	if u := auth.UserFromContext(r.Context()); u != nil {
		actor = u.Email
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO project_license_policy
		     (project_id, mode, blocked_json, warned_json, allowed_json, unknown_action, updated_at, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (project_id) DO UPDATE SET
		     mode           = excluded.mode,
		     blocked_json   = excluded.blocked_json,
		     warned_json    = excluded.warned_json,
		     allowed_json   = excluded.allowed_json,
		     unknown_action = excluded.unknown_action,
		     updated_at     = excluded.updated_at,
		     updated_by     = excluded.updated_by`,
		id, body.Mode, string(blockedJSON), string(warnedJSON), string(allowedJSON), body.UnknownAction, now, actor,
	)
	if err != nil {
		log.Error().Err(err).Int64("project_id", id).Msg("api: upsert license policy failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save policy"})
		return
	}
	if s.licenseResolver != nil {
		s.licenseResolver.InvalidateProject(id)
	}
	s.triggerLicenseReEvaluation(fmt.Sprintf("project %d license policy updated", id))
	s.handleGetProjectLicensePolicy(w, r) // return refreshed view
}

// handleDeleteProjectLicensePolicy removes the per-project override row so the
// project reverts to inheriting the global policy. Returns the refreshed view
// (which will show mode=inherit).
func (s *Server) handleDeleteProjectLicensePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	_, err = s.db.ExecContext(r.Context(),
		`DELETE FROM project_license_policy WHERE project_id = ?`, id)
	if err != nil {
		log.Error().Err(err).Int64("project_id", id).Msg("api: delete project license policy failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	if s.licenseResolver != nil {
		s.licenseResolver.InvalidateProject(id)
	}
	s.triggerLicenseReEvaluation(fmt.Sprintf("project %d license policy deleted", id))
	s.handleGetProjectLicensePolicy(w, r)
}
