package api

import (
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// handleListAudit handles GET /api/v1/audit.
// Supports pagination (page, per_page) and optional event_type filter.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r.URL.Query())
	offset := (page - 1) * perPage
	eventType := r.URL.Query().Get("event_type")

	// Count total rows (with optional filter).
	var total int
	if eventType != "" {
		if err := s.db.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM audit_log WHERE event_type = ?`, eventType).Scan(&total); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to count audit entries")
			return
		}
	} else {
		if err := s.db.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to count audit entries")
			return
		}
	}

	// Query rows.
	var query string
	var args []any
	const cols = `id, ts, event_type,
				 COALESCE(artifact_id, '') AS artifact_id,
				 COALESCE(client_ip, '') AS client_ip,
				 COALESCE(user_agent, '') AS user_agent,
				 COALESCE(reason, '') AS reason,
				 COALESCE(metadata_json, '') AS metadata_json,
				 COALESCE(user_email, '') AS user_email,
				 project_id`
	if eventType != "" {
		query = `SELECT ` + cols + `
				 FROM audit_log
				 WHERE event_type = ?
				 ORDER BY ts DESC
				 LIMIT ? OFFSET ?`
		args = []any{eventType, perPage, offset}
	} else {
		query = `SELECT ` + cols + `
				 FROM audit_log
				 ORDER BY ts DESC
				 LIMIT ? OFFSET ?`
		args = []any{perPage, offset}
	}

	rows, err := s.db.QueryxContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}
	defer rows.Close()

	entries := make([]model.AuditEntry, 0, perPage)
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.StructScan(&e); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan audit entry")
			return
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating audit entries")
		return
	}

	writeJSON(w, http.StatusOK, paginatedResponse{
		Data:    entries,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}
