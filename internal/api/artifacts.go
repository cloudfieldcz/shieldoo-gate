package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// artifactDBRow is used for scanning DB rows that join artifacts + artifact_status.
type artifactDBRow struct {
	model.Artifact
	Status           string     `db:"status"`
	QuarantineReason string     `db:"quarantine_reason"`
	QuarantinedAt    *time.Time `db:"quarantined_at"`
	ReleasedAt       *time.Time `db:"released_at"`
}

// artifactStatusResponse is the nested status object the UI expects.
type artifactStatusResponse struct {
	Status           string     `json:"status"`
	QuarantineReason string     `json:"quarantine_reason,omitempty"`
	QuarantinedAt    *time.Time `json:"quarantined_at,omitempty"`
	ReleasedAt       *time.Time `json:"released_at,omitempty"`
}

// artifactResponse is the JSON shape returned by list/get endpoints.
type artifactResponse struct {
	ID             string                 `json:"id"`
	Ecosystem      string                 `json:"ecosystem"`
	Name           string                 `json:"name"`
	Version        string                 `json:"version"`
	UpstreamURL    string                 `json:"upstream_url"`
	SHA256         string                 `json:"sha256"`
	SizeBytes      int64                  `json:"size_bytes"`
	CachedAt       time.Time              `json:"cached_at"`
	LastAccessedAt time.Time              `json:"last_accessed_at"`
	StoragePath    string                 `json:"storage_path"`
	Status         artifactStatusResponse `json:"status"`
}

// artifactID extracts and URL-decodes the {id} route parameter.
// Artifact IDs contain colons (e.g. "pypi:requests:2.32.3") which get
// percent-encoded by browsers; Chi may return the raw encoded form.
func artifactID(r *http.Request) string {
	raw := chi.URLParam(r, "id")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func toArtifactResponse(row artifactDBRow) artifactResponse {
	return artifactResponse{
		ID:             row.Artifact.ID(),
		Ecosystem:      row.Ecosystem,
		Name:           row.Name,
		Version:        row.Version,
		UpstreamURL:    row.UpstreamURL,
		SHA256:         row.SHA256,
		SizeBytes:      row.SizeBytes,
		CachedAt:       row.CachedAt,
		LastAccessedAt: row.LastAccessedAt,
		StoragePath:    row.StoragePath,
		Status: artifactStatusResponse{
			Status:           row.Status,
			QuarantineReason: row.QuarantineReason,
			QuarantinedAt:    row.QuarantinedAt,
			ReleasedAt:       row.ReleasedAt,
		},
	}
}

type paginatedResponse struct {
	Data    any `json:"data"`
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

	items := make([]artifactResponse, 0, perPage)
	for rows.Next() {
		var row artifactDBRow
		if err := rows.StructScan(&row); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan artifact row")
			return
		}
		items = append(items, toArtifactResponse(row))
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating artifact rows")
		return
	}

	writeJSON(w, http.StatusOK, paginatedResponse{
		Data:    items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// handleGetArtifact handles GET /api/v1/artifacts/{id}.
func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)

	var row artifactDBRow
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

	// Fetch scan results for the detail view.
	scanRows, err := s.db.QueryxContext(r.Context(),
		`SELECT id, artifact_id, scanned_at, scanner_name, scanner_version,
		        verdict, confidence, findings_json, duration_ms
		 FROM scan_results
		 WHERE artifact_id = ?
		 ORDER BY scanned_at DESC`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query scan results")
		return
	}
	defer scanRows.Close()

	scanResults := make([]model.ScanResult, 0)
	for scanRows.Next() {
		var sr model.ScanResult
		if err := scanRows.StructScan(&sr); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan result row")
			return
		}
		scanResults = append(scanResults, sr)
	}

	resp := toArtifactResponse(row)
	type detailResponse struct {
		artifactResponse
		ScanResults []model.ScanResult `json:"scan_results"`
	}
	writeJSON(w, http.StatusOK, detailResponse{
		artifactResponse: resp,
		ScanResults:      scanResults,
	})
}

// handleGetArtifactScanResults handles GET /api/v1/artifacts/{id}/scan-results.
func (s *Server) handleGetArtifactScanResults(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)

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
	id := artifactID(r)
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
		`INSERT INTO artifact_status (artifact_id, status, rescan_due_at)
		 VALUES (?, 'PENDING_SCAN', ?)
		 ON CONFLICT(artifact_id) DO UPDATE SET status='PENDING_SCAN', rescan_due_at=excluded.rescan_due_at`,
		id, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to queue rescan")
		return
	}

	userEmail := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, ?, ?, 'manual rescan via API', ?)`,
		now, string(model.EventRescanQueued), id, userEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventRescanQueued,
		ArtifactID: id,
		Reason:     "manual rescan via API",
		UserEmail:  userEmail,
	})

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":      "PENDING_SCAN",
		"artifact_id": id,
		"message":     "rescan queued",
	})
}

// handleQuarantineArtifact handles POST /api/v1/artifacts/{id}/quarantine.
func (s *Server) handleQuarantineArtifact(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)
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

	userEmail := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, 'QUARANTINED', ?, 'manual quarantine via API', ?)`,
		now, id, userEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventQuarantined,
		ArtifactID: id,
		Reason:     "manual quarantine via API",
		UserEmail:  userEmail,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "QUARANTINED",
		"artifact_id": id,
	})
}

// handleReleaseArtifact handles POST /api/v1/artifacts/{id}/release.
func (s *Server) handleReleaseArtifact(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)
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
		 ON CONFLICT(artifact_id) DO UPDATE SET
		     status='CLEAN',
		     released_at=excluded.released_at,
		     quarantine_reason='',
		     quarantined_at=NULL,
		     rescan_due_at=NULL`,
		id, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to release artifact")
		return
	}

	userEmail := userEmailFromRequest(r)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, 'RELEASED', ?, 'manual release via API', ?)`,
		now, id, userEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	adapter.DispatchAlert(model.AuditEntry{
		EventType:  model.EventReleased,
		ArtifactID: id,
		Reason:     "manual release via API",
		UserEmail:  userEmail,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "CLEAN",
		"artifact_id": id,
	})
}

// userEmailFromRequest extracts the authenticated user's email from the request context.
// Returns an empty string when auth is disabled or no user is present.
func userEmailFromRequest(r *http.Request) string {
	if user := auth.UserFromContext(r.Context()); user != nil {
		return user.Email
	}
	return ""
}
