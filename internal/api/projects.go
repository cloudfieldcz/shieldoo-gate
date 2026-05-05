package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

type projectCreateRequest struct {
	Label       string `json:"label"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
}

type projectUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// handleListProjects returns all projects.
func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.projectSvc.List()
	if err != nil {
		log.Error().Err(err).Msg("api: list projects failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list projects"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

// handleCreateProject explicitly provisions a project (required for strict mode).
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req projectCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
		return
	}
	p, err := s.projectSvc.Create(req.Label, req.DisplayName, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, project.ErrInvalidLabel):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, project.ErrCapReached):
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		default:
			log.Error().Err(err).Str("label", req.Label).Msg("api: create project failed")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create project"})
		}
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// handleGetProject returns a project by ID.
func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	p, err := s.projectSvc.GetByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: get project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get project"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleUpdateProject patches display_name, description, or enabled.
func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	var req projectUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.projectSvc.Update(id, req.DisplayName, req.Description, req.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: update project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update project"})
		return
	}
	p, _ := s.projectSvc.GetByID(id)
	writeJSON(w, http.StatusOK, p)
}

// handleDisableProject soft-disables a project (metadata only in v1.2).
func (s *Server) handleDisableProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	if err := s.projectSvc.Disable(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: disable project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable project"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// projectArtifactRow is the per-row payload of GET /projects/{id}/artifacts.
//
// A row may originate from any of three sources, deduped by
// (ecosystem, name, version):
//   - artifact_project_usage   → "pulled" by the project (decision=CLEAN by default)
//   - audit_log LICENSE_BLOCKED → "blocked attempt" (decision=BLOCKED_LICENSE)
//   - policy_overrides          → active per-project override (decision=WHITELISTED|BLACKLISTED)
//
// When multiple sources contribute, override > license-block > pulled wins for
// the displayed `decision`. Unset fields are omitted from JSON.
type projectArtifactRow struct {
	ID            string     `json:"id,omitempty"`
	Ecosystem     string     `json:"ecosystem"`
	Name          string     `json:"name"`
	Version       string     `json:"version,omitempty"`
	Decision      string     `json:"decision"` // CLEAN | BLOCKED_LICENSE | WHITELISTED | BLACKLISTED
	FirstUsedAt   *time.Time `json:"first_used_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	UseCount      int64      `json:"use_count,omitempty"`
	Licenses      []string   `json:"licenses,omitempty"`
	BlockedLicense string    `json:"blocked_license,omitempty"`
	LastBlockedAt *time.Time `json:"last_blocked_at,omitempty"`
	BlockCount    int64      `json:"block_count,omitempty"`
	OverrideID    int64      `json:"override_id,omitempty"`
	OverrideKind  string     `json:"override_kind,omitempty"` // allow | deny
	OverrideScope string     `json:"override_scope,omitempty"`
	OverrideReason string    `json:"override_reason,omitempty"`
	OverrideExpiresAt *time.Time `json:"override_expires_at,omitempty"`
}

// rowKey identifies a project artifact row across the three source tables.
// version="" is the package-scope key used by package-scoped overrides.
type rowKey struct{ Ecosystem, Name, Version string }

// handleListProjectArtifacts returns the project's per-package decisions —
// pulled artifacts, license-blocked attempts (from audit_log), and active
// per-project overrides — merged into a single list keyed on
// (ecosystem, name, version).
func (s *Server) handleListProjectArtifacts(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}

	merged := make(map[rowKey]*projectArtifactRow)

	// 1) Pulled artifacts.
	if err := s.loadProjectPulledArtifacts(r, id, merged); err != nil {
		log.Error().Err(err).Int64("project_id", id).Msg("api: list project artifacts: pulled")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list artifacts"})
		return
	}

	// 2) Blocked-by-license attempts (derived from audit_log).
	if err := s.loadProjectBlockedAttempts(r, id, merged); err != nil {
		log.Warn().Err(err).Int64("project_id", id).Msg("api: list project artifacts: blocked attempts")
	}

	// 3) Active per-project overrides — these can stand alone (no traffic yet).
	if err := s.loadProjectOverrides(r, id, merged); err != nil {
		log.Warn().Err(err).Int64("project_id", id).Msg("api: list project artifacts: overrides")
	}

	// Serialize: stable order — most-recently active first, then alphabetical.
	out := make([]*projectArtifactRow, 0, len(merged))
	for _, row := range merged {
		out = append(out, row)
	}
	sortProjectArtifactRows(out)

	// Batch-load SBOM licenses for entries that have a real artifact ID.
	s.attachLicensesToRows(r, out)

	writeJSON(w, http.StatusOK, map[string]any{"artifacts": out})
}

// loadProjectPulledArtifacts seeds the merged map with rows the project has
// actually pulled (artifact_project_usage).
func (s *Server) loadProjectPulledArtifacts(r *http.Request, projectID int64, merged map[rowKey]*projectArtifactRow) error {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT a.id, a.ecosystem, a.name, a.version,
		        apu.first_used_at, apu.last_used_at, apu.use_count
		 FROM artifact_project_usage apu
		 JOIN artifacts a ON a.id = apu.artifact_id
		 WHERE apu.project_id = ?
		 ORDER BY apu.last_used_at DESC
		 LIMIT 500`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id          string
			ecosystem   string
			name        string
			version     string
			firstUsedAt time.Time
			lastUsedAt  time.Time
			useCount    int64
		)
		if err := rows.Scan(&id, &ecosystem, &name, &version, &firstUsedAt, &lastUsedAt, &useCount); err != nil {
			log.Warn().Err(err).Msg("api: scan pulled artifact row failed")
			continue
		}
		key := rowKey{ecosystem, name, version}
		merged[key] = &projectArtifactRow{
			ID:          id,
			Ecosystem:   ecosystem,
			Name:        name,
			Version:     version,
			Decision:    "CLEAN",
			FirstUsedAt: pointerToTime(firstUsedAt),
			LastUsedAt:  pointerToTime(lastUsedAt),
			UseCount:    useCount,
		}
	}
	return rows.Err()
}

// loadProjectBlockedAttempts adds (or upgrades) rows for license-block events
// recorded against this project. Rows are derived from audit_log, grouped by
// (ecosystem, name, version) parsed out of the artifact_id column.
//
// audit_log artifact_id format is "<ecosystem>:<name>:<version>[:filename]" —
// see internal/adapter/*.go fmt.Sprintf("%s:%s:%s", ...). We split conservatively:
// first segment = ecosystem, last segment = version (dropping a trailing
// :filename for tarball IDs is impossible from the audit row alone, so we
// recover the artifact's real (eco, name, version) by joining on the
// artifacts table when present, falling back to a parsed split otherwise.
func (s *Server) loadProjectBlockedAttempts(r *http.Request, projectID int64, merged map[rowKey]*projectArtifactRow) error {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT al.artifact_id, MAX(al.ts) AS last_ts, COUNT(*) AS block_count, MAX(al.reason) AS reason
		   FROM audit_log al
		  WHERE al.project_id = ? AND al.event_type = ?
		  GROUP BY al.artifact_id
		  ORDER BY MAX(al.ts) DESC
		  LIMIT 500`, projectID, string(model.EventLicenseBlocked))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		// MAX(ts) loses driver type fidelity (SQLite returns the value as
		// string, Postgres as time.Time), so scan into anys and coerce.
		var (
			artifactID string
			lastTSAny  any
			blockCount int64
			reasonAny  any
		)
		if err := rows.Scan(&artifactID, &lastTSAny, &blockCount, &reasonAny); err != nil {
			log.Warn().Err(err).Msg("api: scan blocked-attempt row failed")
			continue
		}

		eco, name, ver := s.resolveArtifactTuple(r, artifactID)
		if eco == "" {
			continue // unparseable — skip rather than poison the list
		}
		key := rowKey{eco, name, ver}

		reason := coerceString(reasonAny)
		blockedLicense := extractLicenseFromReason(reason)
		blockedAt := coerceTime(lastTSAny)

		row, exists := merged[key]
		if !exists {
			row = &projectArtifactRow{
				ID:        artifactID,
				Ecosystem: eco,
				Name:      name,
				Version:   ver,
			}
			merged[key] = row
		}
		row.BlockedLicense = blockedLicense
		if !blockedAt.IsZero() {
			t := blockedAt.UTC()
			row.LastBlockedAt = &t
		}
		row.BlockCount = blockCount
		// Promote decision unless it's already overridden (overrides land later
		// and will set decision themselves).
		if row.Decision == "" || row.Decision == "CLEAN" {
			row.Decision = "BLOCKED_LICENSE"
		}
	}
	return rows.Err()
}

// loadProjectOverrides folds active per-project overrides into the merged
// list. These take precedence in the displayed `decision`.
func (s *Server) loadProjectOverrides(r *http.Request, projectID int64, merged map[rowKey]*projectArtifactRow) error {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT id, ecosystem, name, version, scope, kind, reason, expires_at
		   FROM policy_overrides
		  WHERE project_id = ? AND revoked = FALSE
		    AND (expires_at IS NULL OR expires_at > ?)
		  ORDER BY created_at DESC
		  LIMIT 500`, projectID, time.Now().UTC())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id        int64
			ecosystem string
			name      string
			version   string
			scope     string
			kind      string
			reason    string
			expiresAt sql.NullTime
		)
		if err := rows.Scan(&id, &ecosystem, &name, &version, &scope, &kind, &reason, &expiresAt); err != nil {
			log.Warn().Err(err).Msg("api: scan override row failed")
			continue
		}
		// Package-scope overrides target every version — match by version="".
		key := rowKey{ecosystem, name, version}
		row, exists := merged[key]
		if !exists {
			row = &projectArtifactRow{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}
			merged[key] = row
		}
		row.OverrideID = id
		row.OverrideKind = kind
		row.OverrideScope = scope
		row.OverrideReason = reason
		if expiresAt.Valid {
			t := expiresAt.Time.UTC()
			row.OverrideExpiresAt = &t
		}
		switch kind {
		case "allow":
			row.Decision = "WHITELISTED"
		case "deny":
			row.Decision = "BLACKLISTED"
		}
	}
	return rows.Err()
}

// resolveArtifactTuple returns (ecosystem, name, version) for an audit-log
// artifact ID. Prefers a JOIN against the artifacts table for accuracy
// (tarball IDs include a trailing :filename that string parsing can't
// distinguish from the version). Returns ("", "", "") when no resolution
// is possible.
func (s *Server) resolveArtifactTuple(r *http.Request, artifactID string) (string, string, string) {
	if artifactID == "" {
		return "", "", ""
	}
	var eco, name, ver string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT ecosystem, name, version FROM artifacts WHERE id = ?`, artifactID,
	).Scan(&eco, &name, &ver)
	if err == nil {
		return eco, name, ver
	}
	// Fallback: parse the ID. Format is "<eco>:<name>:<version>" (3 segments)
	// or 4+ segments for maven group:artifact:version or pypi tarball IDs.
	// Take first segment as eco, last as version, middle as name.
	first := strings.IndexByte(artifactID, ':')
	if first < 0 {
		return "", "", ""
	}
	last := strings.LastIndexByte(artifactID, ':')
	if last <= first {
		return "", "", ""
	}
	return artifactID[:first], artifactID[first+1 : last], artifactID[last+1:]
}

// attachLicensesToRows batch-loads SBOM licenses for rows with a real
// artifact ID and merges them in.
func (s *Server) attachLicensesToRows(r *http.Request, rows []*projectArtifactRow) {
	if len(rows) == 0 {
		return
	}
	ids := make(map[string]int, len(rows))
	for i, row := range rows {
		if row.ID != "" {
			ids[row.ID] = i
		}
	}
	if len(ids) == 0 {
		return
	}
	lRows, err := s.db.QueryxContext(r.Context(),
		`SELECT artifact_id, licenses_json FROM sbom_metadata WHERE licenses_json != '[]'`)
	if err != nil {
		return
	}
	defer lRows.Close()
	for lRows.Next() {
		var aid, lj string
		if err := lRows.Scan(&aid, &lj); err != nil {
			continue
		}
		idx, ok := ids[aid]
		if !ok {
			continue
		}
		var lics []string
		if err := json.Unmarshal([]byte(lj), &lics); err == nil && len(lics) > 0 {
			rows[idx].Licenses = lics
		}
	}
}

// sortProjectArtifactRows orders rows by most-recent activity first, then
// alphabetically for stable display.
func sortProjectArtifactRows(rows []*projectArtifactRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		ti, tj := mostRecentActivity(rows[i]), mostRecentActivity(rows[j])
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		if rows[i].Ecosystem != rows[j].Ecosystem {
			return rows[i].Ecosystem < rows[j].Ecosystem
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Version < rows[j].Version
	})
}

func mostRecentActivity(row *projectArtifactRow) time.Time {
	var t time.Time
	if row.LastUsedAt != nil && row.LastUsedAt.After(t) {
		t = *row.LastUsedAt
	}
	if row.LastBlockedAt != nil && row.LastBlockedAt.After(t) {
		t = *row.LastBlockedAt
	}
	return t
}

func pointerToTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

// coerceTime normalizes a value coming back from `MAX(ts)` across drivers
// (SQLite returns string, Postgres returns time.Time). Unknown shapes return
// the zero time.
func coerceTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		// SQLite default DATETIME format is "YYYY-MM-DD HH:MM:SS" plus
		// optional fractional seconds and timezone.
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
		} {
			if parsed, err := time.Parse(layout, t); err == nil {
				return parsed
			}
		}
	case []byte:
		return coerceTime(string(t))
	}
	return time.Time{}
}

// coerceString reads a textual column value across drivers.
func coerceString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	}
	return ""
}

// extractLicenseFromReason pulls the SPDX expression out of a license-block
// reason. Evaluator reasons look like "license: <SPDX> blocked by policy" —
// we return the token after "license: " up to the next space.
func extractLicenseFromReason(reason string) string {
	idx := strings.Index(reason, "license: ")
	if idx < 0 {
		return ""
	}
	rest := reason[idx+len("license: "):]
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		return rest[:end]
	}
	return rest
}
