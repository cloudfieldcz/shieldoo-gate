package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// projectOverrideRequest is the body of POST /api/v1/projects/{id}/overrides.
type projectOverrideRequest struct {
	Ecosystem string `json:"ecosystem"`            // e.g. "npm"
	Name      string `json:"name"`                 // package name as used by the registry
	Version   string `json:"version,omitempty"`    // exact version (required when Scope=="version")
	Scope     string `json:"scope"`                // "package" | "version"
	Kind      string `json:"kind"`                 // "allow" | "deny"
	Reason    string `json:"reason"`               // free-form, mandatory for audit traceability
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339; empty = no expiry
}

// projectOverrideRevokeRequest is the body of POST /overrides/{overrideId}/revoke.
type projectOverrideRevokeRequest struct {
	Reason string `json:"reason"`
}

// projectOverrideResponse mirrors a single policy_overrides row in the API surface.
type projectOverrideResponse struct {
	ID         int64      `json:"id"`
	ProjectID  int64      `json:"project_id"`
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Scope      string     `json:"scope"`
	Kind       string     `json:"kind"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Revoked    bool       `json:"revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// handleCreateProjectOverride writes a new per-project policy override.
//
// POST /api/v1/projects/{id}/overrides
//
// Whitelist (kind=allow) lets the package through despite a license/scan
// block; blacklist (kind=deny) blocks it even when policy would allow it.
// scope="package" applies to every version, scope="version" to the exact
// version field. Returns 409 if an active override of the same (eco, name,
// version, scope, kind) already exists for this project.
func (s *Server) handleCreateProjectOverride(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}

	// Confirm project exists — avoid leaving FK-orphaned overrides behind if
	// the URL id is bogus.
	if _, err := s.projectSvc.GetByID(projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}
		log.Error().Err(err).Int64("project_id", projectID).Msg("api: project lookup failed")
		writeError(w, http.StatusInternalServerError, "project lookup failed")
		return
	}

	var req projectOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ecosystem == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "ecosystem and name are required")
		return
	}
	switch req.Scope {
	case "package":
		req.Version = "" // package-scope ignores version
	case "version":
		if req.Version == "" {
			writeError(w, http.StatusBadRequest, "version is required when scope=version")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "scope must be 'package' or 'version'")
		return
	}
	if req.Kind != "allow" && req.Kind != "deny" {
		writeError(w, http.StatusBadRequest, "kind must be 'allow' or 'deny'")
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required for audit traceability")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		t = t.UTC()
		expiresAt = &t
	}

	now := time.Now().UTC()
	userEmail := userEmailFromRequest(r)

	res, err := s.db.ExecContext(r.Context(),
		`INSERT INTO policy_overrides
		   (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)`,
		req.Ecosystem, req.Name, req.Version, req.Scope, projectID, req.Kind, req.Reason, userEmail, now, expiresAt)
	if err != nil {
		// SQLite unique-constraint message and Postgres "duplicate key" both
		// surface as a generic error here. Try a duplicate lookup so the
		// caller gets a meaningful 409 response.
		if isDuplicateOverride(s, r, projectID, req) {
			writeError(w, http.StatusConflict, "an active override of the same (package, version, scope, kind) already exists for this project")
			return
		}
		log.Error().Err(err).Int64("project_id", projectID).Msg("api: insert project override failed")
		writeError(w, http.StatusInternalServerError, "failed to create override")
		return
	}
	overrideID, _ := res.LastInsertId()

	_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:    model.EventOverrideCreated,
		ProjectID:    &projectID,
		Reason:       fmt.Sprintf("project override #%d created (kind=%s scope=%s %s:%s%s%s)", overrideID, req.Kind, req.Scope, req.Ecosystem, req.Name, ifNotEmpty(":", req.Version), ifNotEmpty(" reason=", req.Reason)),
		UserEmail:    userEmail,
		MetadataJSON: fmt.Sprintf(`{"override_id":%d,"kind":%q,"scope":%q,"ecosystem":%q,"name":%q,"version":%q}`, overrideID, req.Kind, req.Scope, req.Ecosystem, req.Name, req.Version),
	})

	writeJSON(w, http.StatusCreated, projectOverrideResponse{
		ID:        overrideID,
		ProjectID: projectID,
		Ecosystem: req.Ecosystem,
		Name:      req.Name,
		Version:   req.Version,
		Scope:     req.Scope,
		Kind:      req.Kind,
		Reason:    req.Reason,
		CreatedBy: userEmail,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	})
}

// handleRevokeProjectOverride sets revoked=true on a project's override.
//
// POST /api/v1/projects/{id}/overrides/{overrideId}/revoke
//
// Idempotent — revoking an already-revoked override is a no-op (200 OK).
// Returns 404 if the override doesn't exist or doesn't belong to this project.
func (s *Server) handleRevokeProjectOverride(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	overrideID, err := strconv.ParseInt(chi.URLParam(r, "overrideId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid override id")
		return
	}

	var req projectOverrideRevokeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional

	now := time.Now().UTC()
	userEmail := userEmailFromRequest(r)

	res, err := s.db.ExecContext(r.Context(),
		`UPDATE policy_overrides
		    SET revoked = TRUE, revoked_at = ?
		  WHERE id = ? AND project_id = ? AND revoked = FALSE`,
		now, overrideID, projectID)
	if err != nil {
		log.Error().Err(err).Int64("override_id", overrideID).Msg("api: revoke override failed")
		writeError(w, http.StatusInternalServerError, "failed to revoke override")
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		// Distinguish "doesn't belong here / not found" from "already revoked".
		var ownerProject sql.NullInt64
		var alreadyRevoked sql.NullBool
		err = s.db.QueryRowContext(r.Context(),
			`SELECT project_id, revoked FROM policy_overrides WHERE id = ?`, overrideID).
			Scan(&ownerProject, &alreadyRevoked)
		if errors.Is(err, sql.ErrNoRows) || !ownerProject.Valid || ownerProject.Int64 != projectID {
			writeError(w, http.StatusNotFound, "override not found in this project")
			return
		}
		// Already revoked — return success silently (idempotent).
		writeJSON(w, http.StatusOK, map[string]any{"id": overrideID, "revoked": true, "already_revoked": true})
		return
	}

	_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:    model.EventOverrideRevoked,
		ProjectID:    &projectID,
		Reason:       fmt.Sprintf("project override #%d revoked%s", overrideID, ifNotEmpty(": ", req.Reason)),
		UserEmail:    userEmail,
		MetadataJSON: fmt.Sprintf(`{"override_id":%d,"revoke_reason":%q}`, overrideID, req.Reason),
	})

	writeJSON(w, http.StatusOK, map[string]any{"id": overrideID, "revoked": true})
}

// isDuplicateOverride reports whether an active override matching req already
// exists for the project, so the create handler can map a unique-constraint
// failure to a 409.
func isDuplicateOverride(s *Server, r *http.Request, projectID int64, req projectOverrideRequest) bool {
	var n int
	err := s.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE project_id = ? AND ecosystem = ? AND name = ? AND version = ?
		    AND scope = ? AND kind = ? AND revoked = FALSE`,
		projectID, req.Ecosystem, req.Name, req.Version, req.Scope, req.Kind).Scan(&n)
	return err == nil && n > 0
}

// ifNotEmpty returns prefix+s when s is non-empty, otherwise "". Used to
// keep audit reason strings tidy without conditional branches.
func ifNotEmpty(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}
