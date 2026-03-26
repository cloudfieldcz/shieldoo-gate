package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// artifactWithStatus combines an artifact row with its status row.
type artifactWithStatus struct {
	model.Artifact
	Status           string     `db:"status" json:"status,omitempty"`
	QuarantineReason string     `db:"quarantine_reason" json:"quarantine_reason,omitempty"`
	QuarantinedAt    *time.Time `db:"quarantined_at" json:"quarantined_at,omitempty"`
	ReleasedAt       *time.Time `db:"released_at" json:"released_at,omitempty"`
}

type paginatedResponse struct {
	Items   any `json:"items"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

func parsePagination(q url.Values) (page, perPage int) {
	page, _ = strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ = strconv.Atoi(q.Get("per_page"))
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	return page, perPage
}

// handleListArtifacts handles GET /api/v1/artifacts.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r.URL.Query())
	offset := (page - 1) * perPage

	var total int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts`).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count artifacts")
		return
	}

	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT a.ecosystem, a.name, a.version, a.upstream_url, a.sha256,
		        a.size_bytes, a.cached_at, a.last_accessed_at, a.storage_path,
		        COALESCE(s.status, 'PENDING_SCAN') AS status,
		        COALESCE(s.quarantine_reason, '') AS quarantine_reason,
		        s.quarantined_at, s.released_at
		 FROM artifacts a
		 LEFT JOIN artifact_status s ON a.id = s.artifact_id
		 ORDER BY a.cached_at DESC
		 LIMIT ? OFFSET ?`, perPage, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query artifacts")
		return
	}
	defer rows.Close()

	items := make([]artifactWithStatus, 0, perPage)
	for rows.Next() {
		var row artifactWithStatus
		if err := rows.StructScan(&row); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan artifact row")
			return
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating artifact rows")
		return
	}

	writeJSON(w, http.StatusOK, paginatedResponse{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// handleGetArtifact handles GET /api/v1/artifacts/{id}.
func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var row artifactWithStatus
	err := s.db.QueryRowxContext(r.Context(),
		`SELECT a.ecosystem, a.name, a.version, a.upstream_url, a.sha256,
		        a.size_bytes, a.cached_at, a.last_accessed_at, a.storage_path,
		        COALESCE(s.status, 'PENDING_SCAN') AS status,
		        COALESCE(s.quarantine_reason, '') AS quarantine_reason,
		        s.quarantined_at, s.released_at
		 FROM artifacts a
		 LEFT JOIN artifact_status s ON a.id = s.artifact_id
		 WHERE a.id = ?`, id).StructScan(&row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "artifact not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query artifact")
		return
	}

	writeJSON(w, http.StatusOK, row)
}

// handleGetArtifactScanResults handles GET /api/v1/artifacts/{id}/scan-results.
func (s *Server) handleGetArtifactScanResults(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Verify artifact exists.
	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact existence")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT id, artifact_id, scanned_at, scanner_name, scanner_version,
		        verdict, confidence, findings_json, duration_ms
		 FROM scan_results
		 WHERE artifact_id = ?
		 ORDER BY scanned_at DESC`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query scan results")
		return
	}
	defer rows.Close()

	results := make([]model.ScanResult, 0)
	for rows.Next() {
		var sr model.ScanResult
		if err := rows.StructScan(&sr); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan result row")
			return
		}
		results = append(results, sr)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating scan result rows")
		return
	}

	writeJSON(w, http.StatusOK, results)
}

// handleRescanArtifact handles POST /api/v1/artifacts/{id}/rescan.
func (s *Server) handleRescanArtifact(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact existence")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "rescan queued",
	})
}

// handleQuarantineArtifact handles POST /api/v1/artifacts/{id}/quarantine.
func (s *Server) handleQuarantineArtifact(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now().UTC()

	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact existence")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO artifact_status (artifact_id, status, quarantined_at)
		 VALUES (?, 'QUARANTINED', ?)
		 ON CONFLICT(artifact_id) DO UPDATE SET status='QUARANTINED', quarantined_at=excluded.quarantined_at`,
		id, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to quarantine artifact")
		return
	}

	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		 VALUES (?, 'QUARANTINED', ?, 'manual quarantine via API')`,
		now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "QUARANTINED",
		"artifact_id": id,
	})
}

// handleReleaseArtifact handles POST /api/v1/artifacts/{id}/release.
func (s *Server) handleReleaseArtifact(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now().UTC()

	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact existence")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO artifact_status (artifact_id, status, released_at)
		 VALUES (?, 'CLEAN', ?)
		 ON CONFLICT(artifact_id) DO UPDATE SET status='CLEAN', released_at=excluded.released_at`,
		id, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to release artifact")
		return
	}

	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		 VALUES (?, 'RELEASED', ?, 'manual release via API')`,
		now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "CLEAN",
		"artifact_id": id,
	})
}
