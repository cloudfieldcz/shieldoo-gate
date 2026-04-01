package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

type createOverrideRequest struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Scope     string `json:"scope"`
	Reason    string `json:"reason"`
}

func (req createOverrideRequest) validate() error {
	if req.Ecosystem == "" || req.Name == "" {
		return fmt.Errorf("ecosystem and name are required")
	}
	if req.Scope != "version" && req.Scope != "package" {
		return fmt.Errorf("scope must be 'version' or 'package'")
	}
	if req.Scope == "version" && req.Version == "" {
		return fmt.Errorf("version is required when scope is 'version'")
	}
	return nil
}

// handleListOverrides handles GET /api/v1/overrides.
func (s *Server) handleListOverrides(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r.URL.Query())
	offset := (page - 1) * perPage
	activeOnly := r.URL.Query().Get("active") == "true"
	ecosystemFilter := r.URL.Query().Get("ecosystem")
	nameFilter := r.URL.Query().Get("name")

	// Build WHERE clauses
	var conditions []string
	var countArgs []any
	if activeOnly {
		conditions = append(conditions, `revoked = FALSE`)
	}
	if ecosystemFilter != "" {
		conditions = append(conditions, `ecosystem = ?`)
		countArgs = append(countArgs, ecosystemFilter)
	}
	if nameFilter != "" {
		conditions = append(conditions, `name LIKE ?`)
		countArgs = append(countArgs, "%"+nameFilter+"%")
	}

	where := ""
	if len(conditions) > 0 {
		where = ` WHERE ` + strings.Join(conditions, ` AND `)
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM policy_overrides` + where
	if err := s.db.QueryRowContext(r.Context(), countQuery, countArgs...).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count overrides")
		return
	}

	query := `SELECT id, ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked, revoked_at
	          FROM policy_overrides` + where + ` ORDER BY ecosystem ASC, name ASC LIMIT ? OFFSET ?`
	args := append(countArgs, perPage, offset)

	rows, err := s.db.QueryxContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query overrides")
		return
	}
	defer rows.Close()

	items := make([]model.PolicyOverride, 0, perPage)
	for rows.Next() {
		var row model.PolicyOverride
		if err := rows.StructScan(&row); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan override row")
			return
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating override rows")
		return
	}

	writeJSON(w, http.StatusOK, paginatedResponse{
		Data:    items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// handleCreateOverride handles POST /api/v1/overrides.
func (s *Server) handleCreateOverride(w http.ResponseWriter, r *http.Request) {
	var req createOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// If scope is package, clear version
	version := req.Version
	if req.Scope == "package" {
		version = ""
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	// Create override (unique index prevents duplicates for active overrides)
	var overrideID int64
	_, _ = tx.ExecContext(r.Context(),
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 'api', ?, FALSE)
		 ON CONFLICT DO NOTHING`,
		req.Ecosystem, req.Name, version, req.Scope, req.Reason, now)
	err = tx.QueryRowxContext(r.Context(),
		`SELECT id FROM policy_overrides
		 WHERE ecosystem = ? AND name = ? AND version = ? AND scope = ? AND revoked = FALSE`,
		req.Ecosystem, req.Name, version, req.Scope).Scan(&overrideID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve override")
		return
	}

	// If a matching artifact is quarantined, release it
	artifactID := fmt.Sprintf("%s:%s:%s", req.Ecosystem, req.Name, req.Version)
	if req.Scope == "version" && req.Version != "" {
		_, _ = tx.ExecContext(r.Context(),
			`UPDATE artifact_status SET status = 'CLEAN', released_at = ?
			 WHERE artifact_id = ? AND status = 'QUARANTINED'`,
			now, artifactID)
	}

	// Audit log
	userEmail := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, ?, ?, ?, ?)`,
		now, model.EventOverrideCreated, artifactID, req.Reason, userEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventOverrideCreated,
		ArtifactID: artifactID,
		Reason:     req.Reason,
		UserEmail:  userEmail,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        overrideID,
		"ecosystem": req.Ecosystem,
		"name":      req.Name,
		"version":   version,
		"scope":     req.Scope,
		"reason":    req.Reason,
	})
}

// handleRevokeOverride handles DELETE /api/v1/overrides/{id}.
func (s *Server) handleRevokeOverride(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid override ID")
		return
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	// Get override details for audit log
	var override model.PolicyOverride
	err = tx.QueryRowxContext(r.Context(),
		`SELECT id, ecosystem, name, version, scope, reason, created_by, created_at, revoked
		 FROM policy_overrides WHERE id = ?`, id).StructScan(&override)
	if err != nil {
		writeError(w, http.StatusNotFound, "override not found")
		return
	}
	if override.Revoked {
		writeError(w, http.StatusConflict, "override is already revoked")
		return
	}

	_, err = tx.ExecContext(r.Context(),
		`UPDATE policy_overrides SET revoked = TRUE, revoked_at = ? WHERE id = ?`,
		now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke override")
		return
	}

	artifactID := fmt.Sprintf("%s:%s:%s", override.Ecosystem, override.Name, override.Version)
	userEmail := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, ?, ?, ?, ?)`,
		now, model.EventOverrideRevoked, artifactID, fmt.Sprintf("revoked override #%d", id), userEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventOverrideRevoked,
		ArtifactID: artifactID,
		Reason:     fmt.Sprintf("revoked override #%d", id),
		UserEmail:  userEmail,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "revoked",
		"id":     idStr,
	})
}

// handleCreateArtifactOverride handles POST /api/v1/artifacts/{id}/override.
// This is a convenience endpoint that creates an override from an artifact ID.
func (s *Server) handleCreateArtifactOverride(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)

	// Parse artifact ID: "ecosystem:name:version" or "ecosystem:name:version:filename"
	parts := strings.SplitN(id, ":", 4)
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "invalid artifact ID format, expected ecosystem:name:version[:filename]")
		return
	}

	// Check artifact exists
	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	// Parse optional request body for reason and scope
	var body struct {
		Reason string `json:"reason"`
		Scope  string `json:"scope"`
	}
	body.Scope = "version" // default
	body.Reason = "false positive"
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Scope != "version" && body.Scope != "package" {
		body.Scope = "version"
	}

	version := parts[2]
	if body.Scope == "package" {
		version = ""
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	// Create override (unique index prevents duplicates for active overrides)
	var overrideID int64
	_, _ = tx.ExecContext(r.Context(),
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 'api', ?, FALSE)
		 ON CONFLICT DO NOTHING`,
		parts[0], parts[1], version, body.Scope, body.Reason, now)
	err = tx.QueryRowxContext(r.Context(),
		`SELECT id FROM policy_overrides
		 WHERE ecosystem = ? AND name = ? AND version = ? AND scope = ? AND revoked = FALSE`,
		parts[0], parts[1], version, body.Scope).Scan(&overrideID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve override")
		return
	}

	// Release artifact from quarantine if applicable
	_, _ = tx.ExecContext(r.Context(),
		`UPDATE artifact_status SET status = 'CLEAN', released_at = ?
		 WHERE artifact_id = ? AND status = 'QUARANTINED'`,
		now, id)

	// Audit log
	userEmail2 := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, ?, ?, ?, ?)`,
		now, model.EventOverrideCreated, id, body.Reason, userEmail2)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventOverrideCreated,
		ArtifactID: id,
		Reason:     body.Reason,
		UserEmail:  userEmail2,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          overrideID,
		"artifact_id": id,
		"scope":       body.Scope,
		"reason":      body.Reason,
	})
}
