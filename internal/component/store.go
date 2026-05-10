package component

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// Store is the data-access layer for components, scan_runs, scan_findings, cve_ignores.
type Store struct {
	db *config.GateDB
}

// NewStore constructs a Store backed by the provided GateDB.
func NewStore(db *config.GateDB) *Store {
	return &Store{db: db}
}

// componentColumns is the canonical SELECT projection for the components table.
const componentColumns = `id, project_id, name,
	COALESCE(display_name, '') AS display_name,
	COALESCE(description, '')  AS description,
	ecosystem,
	COALESCE(repo_url, '')     AS repo_url,
	ai_enabled, enabled, created_at, created_via, last_scan_id`

// GetComponent returns the component with the given id, or sql.ErrNoRows.
func (s *Store) GetComponent(ctx context.Context, id int64) (*Component, error) {
	var c Component
	err := s.db.GetContext(ctx, &c,
		`SELECT `+componentColumns+` FROM components WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetComponentByName returns the component with the given (project_id, name) tuple.
func (s *Store) GetComponentByName(ctx context.Context, projectID int64, name string) (*Component, error) {
	var c Component
	err := s.db.GetContext(ctx, &c,
		`SELECT `+componentColumns+` FROM components WHERE project_id = ? AND name = ?`,
		projectID, name)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListComponentsByProject returns all components for a project ordered by created_at DESC.
func (s *Store) ListComponentsByProject(ctx context.Context, projectID int64) ([]*Component, error) {
	rows := []Component{}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT `+componentColumns+` FROM components
		 WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*Component, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// CountComponentsByProject returns the number of rows in components for projectID.
func (s *Store) CountComponentsByProject(ctx context.Context, projectID int64) (int, error) {
	var n int
	err := s.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM components WHERE project_id = ?`, projectID)
	return n, err
}

// CreateComponent inserts a new component row, enforcing the per-project cap via
// INSERT ... SELECT WHERE (SELECT COUNT(*)...) < cap. Returns the freshly-inserted row.
func (s *Store) CreateComponent(ctx context.Context, projectID int64, name, ecosystem, createdVia string, maxPerProject int) (*Component, error) {
	if maxPerProject <= 0 {
		// No cap — direct insert with ON CONFLICT.
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO components (project_id, name, ecosystem, created_via, enabled, ai_enabled)
			 VALUES (?, ?, ?, ?, TRUE, TRUE)
			 ON CONFLICT (project_id, name) DO NOTHING`,
			projectID, name, ecosystem, createdVia)
		if err != nil {
			return nil, fmt.Errorf("component: insert: %w", err)
		}
		return s.GetComponentByName(ctx, projectID, name)
	}

	// TOCTOU-safe cap check.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO components (project_id, name, ecosystem, created_via, enabled, ai_enabled)
		 SELECT ?, ?, ?, ?, TRUE, TRUE
		 WHERE (SELECT COUNT(*) FROM components WHERE project_id = ?) < ?
		 ON CONFLICT (project_id, name) DO NOTHING`,
		projectID, name, ecosystem, createdVia, projectID, maxPerProject)
	if err != nil {
		return nil, fmt.Errorf("component: capped insert: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		// Either ON CONFLICT (component exists) or cap reached. Disambiguate.
		existing, err2 := s.GetComponentByName(ctx, projectID, name)
		if err2 == nil {
			return existing, nil
		}
		return nil, ErrCapReached
	}
	return s.GetComponentByName(ctx, projectID, name)
}

// UpdateComponent applies partial updates to a component row. Nil fields are skipped.
func (s *Store) UpdateComponent(ctx context.Context, id int64, displayName, description, repoURL *string, enabled, aiEnabled *bool) error {
	setClauses := []string{}
	args := []any{}
	if displayName != nil {
		setClauses = append(setClauses, "display_name = ?")
		args = append(args, *displayName)
	}
	if description != nil {
		setClauses = append(setClauses, "description = ?")
		args = append(args, *description)
	}
	if repoURL != nil {
		setClauses = append(setClauses, "repo_url = ?")
		args = append(args, *repoURL)
	}
	if enabled != nil {
		setClauses = append(setClauses, "enabled = ?")
		args = append(args, *enabled)
	}
	if aiEnabled != nil {
		setClauses = append(setClauses, "ai_enabled = ?")
		args = append(args, *aiEnabled)
	}
	if len(setClauses) == 0 {
		return nil
	}
	args = append(args, id)
	q := "UPDATE components SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

// DeleteComponent attempts to hard-delete a component row. Returns an error if any
// cve_ignores rows reference it (FK ON DELETE RESTRICT).
func (s *Store) DeleteComponent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM components WHERE id = ?`, id)
	return err
}

// SetLastScanID updates components.last_scan_id pointer.
func (s *Store) SetLastScanID(ctx context.Context, componentID, scanRunID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE components SET last_scan_id = ? WHERE id = ?`,
		scanRunID, componentID)
	return err
}

// scanRunColumns is the canonical SELECT projection for the scan_runs table.
const scanRunColumns = `id, component_id, trigger, status, sbom_blob_path, sbom_size_bytes,
	sbom_format, sbom_sha256, started_at, finished_at,
	COALESCE(scanner_status, '') AS scanner_status,
	critical_count, high_count, medium_count, low_count,
	new_critical_count, new_high_count, component_count,
	COALESCE(error_message, '') AS error_message,
	integrity_violated`

// CreateScanRun inserts a pending scan_run row.
//
// Uses INSERT ... RETURNING id so we don't rely on LastInsertId() — lib/pq
// (Postgres) returns ErrNotSupported from that method, which would 500 the
// upload handler. Modern SQLite (3.35+, the version the embedded driver pins
// to) supports RETURNING natively.
func (s *Store) CreateScanRun(ctx context.Context, componentID int64, trigger, blobPath, sha256, format string, sizeBytes int64) (*ScanRun, error) {
	var id int64
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format, sbom_sha256, started_at)
		 VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
		 RETURNING id`,
		componentID, trigger, blobPath, sizeBytes, format, sha256, time.Now().UTC()).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("scan_run: insert: %w", err)
	}
	return s.GetScanRun(ctx, id)
}

// GetScanRun returns a scan_run row by id.
func (s *Store) GetScanRun(ctx context.Context, id int64) (*ScanRun, error) {
	var r ScanRun
	err := s.db.GetContext(ctx, &r,
		`SELECT `+scanRunColumns+` FROM scan_runs WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListScanRunsByComponent returns up to `limit` scan_runs for a component,
// ordered by id DESC so cursor-based pagination is stable. cursor=0 means
// "first page" (no cursor filter); cursor>0 returns rows with id < cursor.
//
// Ordering switches from started_at DESC to id DESC because the keyset cursor
// must be a monotonically-decreasing ordering key, and started_at can have
// ties when a backfill loads multiple runs in the same second.
func (s *Store) ListScanRunsByComponent(ctx context.Context, componentID, cursor int64, limit int) ([]*ScanRun, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows := []ScanRun{}
	if cursor > 0 {
		err := s.db.SelectContext(ctx, &rows,
			`SELECT `+scanRunColumns+` FROM scan_runs
			 WHERE component_id = ? AND id < ?
			 ORDER BY id DESC LIMIT ?`, componentID, cursor, limit)
		if err != nil {
			return nil, err
		}
	} else {
		err := s.db.SelectContext(ctx, &rows,
			`SELECT `+scanRunColumns+` FROM scan_runs
			 WHERE component_id = ?
			 ORDER BY id DESC LIMIT ?`, componentID, limit)
		if err != nil {
			return nil, err
		}
	}
	out := make([]*ScanRun, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// UpdateScanRunStatus updates status, scanner_status JSON, finished_at, error_message,
// and severity counters all in one round-trip.
func (s *Store) UpdateScanRunStatus(ctx context.Context, runID int64, status string,
	scannerStatus map[string]string, errorMessage string,
	critical, high, medium, low, newCritical, newHigh, componentCount int64,
) error {
	statusJSON, _ := json.Marshal(scannerStatus)
	now := time.Now().UTC()
	var finishedAt sql.NullTime
	if status == StatusDone || status == StatusFailed {
		finishedAt = sql.NullTime{Time: now, Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs
		   SET status = ?, scanner_status = ?, finished_at = ?,
		       error_message = ?,
		       critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
		       new_critical_count = ?, new_high_count = ?,
		       component_count = ?
		 WHERE id = ?`,
		status, string(statusJSON), finishedAt, errorMessage,
		critical, high, medium, low, newCritical, newHigh, componentCount, runID)
	return err
}

// FindPreviousSuccessfulRun returns the most recent done scan_run for a component
// with id < runID. Returns sql.ErrNoRows if none exists.
func (s *Store) FindPreviousSuccessfulRun(ctx context.Context, componentID, runID int64) (*ScanRun, error) {
	var r ScanRun
	err := s.db.GetContext(ctx, &r,
		`SELECT `+scanRunColumns+` FROM scan_runs
		 WHERE component_id = ? AND id < ? AND status = 'done'
		 ORDER BY id DESC LIMIT 1`, componentID, runID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// MarkIntegrityViolated sets integrity_violated=1 on the run.
func (s *Store) MarkIntegrityViolated(ctx context.Context, runID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET integrity_violated = TRUE WHERE id = ?`, runID)
	return err
}

// findingColumns is the canonical SELECT projection for scan_findings.
const findingColumns = `id, scan_run_id, component_id, cve_id, package_name, package_version,
	ecosystem, severity,
	COALESCE(cvss_score, 0) AS cvss_score,
	COALESCE(fixed_version, '') AS fixed_version,
	COALESCE(summary, '') AS summary,
	detected_by, is_suppressed, suppressed_by`

// FindingsByRun returns all scan_findings rows for a run.
func (s *Store) FindingsByRun(ctx context.Context, runID int64) ([]*ScanFinding, error) {
	rows := []ScanFinding{}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT `+findingColumns+` FROM scan_findings WHERE scan_run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	out := make([]*ScanFinding, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// InsertFindings bulk-inserts findings using multi-row VALUES. Default 100 rows/stmt.
func (s *Store) InsertFindings(ctx context.Context, findings []*ScanFinding) error {
	if len(findings) == 0 {
		return nil
	}
	const batchSize = 100
	for start := 0; start < len(findings); start += batchSize {
		end := start + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[start:end]
		placeholders := make([]string, 0, len(batch))
		args := make([]any, 0, len(batch)*12)
		for _, f := range batch {
			placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
			args = append(args,
				f.ScanRunID, f.ComponentID, f.CVEID, f.PackageName, f.PackageVersion,
				f.Ecosystem, f.Severity, f.CVSSScore, f.FixedVersion, f.Summary,
				f.DetectedBy, f.IsSuppressed)
		}
		q := `INSERT INTO scan_findings
			(scan_run_id, component_id, cve_id, package_name, package_version,
			 ecosystem, severity, cvss_score, fixed_version, summary,
			 detected_by, is_suppressed) VALUES ` + strings.Join(placeholders, ",")
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("scan_findings: bulk insert: %w", err)
		}
	}
	return nil
}

// ignoreColumns is the canonical SELECT projection for cve_ignores.
const ignoreColumns = `id, component_id, cve_id, package_name,
	COALESCE(package_version, '') AS package_version,
	reason, ai_draft_accepted, expires_at, created_against_run_id,
	created_by_email, created_at, revoked_at,
	COALESCE(revoked_by_email, '') AS revoked_by_email`

// CreateIgnore inserts a cve_ignores row. Returns ErrIgnoreExists on unique violation.
// Uses RETURNING id for Postgres compatibility (lib/pq doesn't support
// LastInsertId; modern SQLite ≥3.35 supports RETURNING).
func (s *Store) CreateIgnore(ctx context.Context, ig *Ignore) (*Ignore, error) {
	var id int64
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO cve_ignores
		   (component_id, cve_id, package_name, package_version, reason,
		    ai_draft_accepted, expires_at, created_against_run_id,
		    created_by_email, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 RETURNING id`,
		ig.ComponentID, ig.CVEID, ig.PackageName, nullIfEmpty(ig.PackageVersion), ig.Reason,
		ig.AIDraftAccepted, ig.ExpiresAt, ig.CreatedAgainstRunID,
		ig.CreatedByEmail, time.Now().UTC()).Scan(&id)
	if err != nil {
		// Unique-violation surface; both backends carry "UNIQUE" / "duplicate" in error text.
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "duplicate") {
			return nil, ErrIgnoreExists
		}
		return nil, fmt.Errorf("cve_ignores: insert: %w", err)
	}
	return s.GetIgnore(ctx, id)
}

// GetIgnore returns an ignore row by id.
func (s *Store) GetIgnore(ctx context.Context, id int64) (*Ignore, error) {
	var ig Ignore
	err := s.db.GetContext(ctx, &ig,
		`SELECT `+ignoreColumns+` FROM cve_ignores WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &ig, nil
}

// RevokeIgnore sets revoked_at + revoked_by_email. Idempotent on already-revoked rows.
func (s *Store) RevokeIgnore(ctx context.Context, id int64, byEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cve_ignores SET revoked_at = ?, revoked_by_email = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), byEmail, id)
	return err
}

// ListActiveIgnores returns all active (not revoked) ignores for a component.
func (s *Store) ListActiveIgnores(ctx context.Context, componentID int64) ([]*Ignore, error) {
	rows := []Ignore{}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT `+ignoreColumns+` FROM cve_ignores
		 WHERE component_id = ? AND revoked_at IS NULL
		 ORDER BY created_at DESC`, componentID)
	if err != nil {
		return nil, err
	}
	out := make([]*Ignore, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// ListExpiredIgnores returns ignores past expires_at and not yet expired-event-emitted.
// Caller is responsible for emitting the expired event and tracking which were processed.
func (s *Store) ListExpiredIgnores(ctx context.Context, now time.Time) ([]*Ignore, error) {
	rows := []Ignore{}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT `+ignoreColumns+` FROM cve_ignores
		 WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?`, now)
	if err != nil {
		return nil, err
	}
	out := make([]*Ignore, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// ListRecentRevokedIgnores returns ignores whose revoked_at falls after the
// given cutoff. Surfaces just-expired entries in the UI so users can
// re-create them without typing the reason from scratch.
func (s *Store) ListRecentRevokedIgnores(ctx context.Context, componentID int64, since time.Time) ([]*Ignore, error) {
	rows := []Ignore{}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT `+ignoreColumns+` FROM cve_ignores
		 WHERE component_id = ? AND revoked_at IS NOT NULL AND revoked_at > ?
		 ORDER BY revoked_at DESC LIMIT 100`, componentID, since)
	if err != nil {
		return nil, err
	}
	out := make([]*Ignore, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// FindActiveIgnoresForRun returns active ignores keyed by (cve_id, package_name)
// for the component owning runID. Used by ApplySuppression / scan-time suppression.
func (s *Store) FindActiveIgnoresForRun(ctx context.Context, runID int64) (map[string]int64, error) {
	componentID, err := s.componentIDForRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	rows := []struct {
		ID          int64  `db:"id"`
		CVEID       string `db:"cve_id"`
		PackageName string `db:"package_name"`
	}{}
	err = s.db.SelectContext(ctx, &rows,
		`SELECT id, cve_id, package_name FROM cve_ignores
		 WHERE component_id = ? AND revoked_at IS NULL`, componentID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int64, len(rows))
	for _, r := range rows {
		m[r.CVEID+"|"+r.PackageName] = r.ID
	}
	return m, nil
}

// ApplySuppression marks every scan_findings row in runID matching (component_id, cve_id, package_name)
// of the supplied ignoreID as suppressed. Per-package semantics: version is NOT in predicate.
func (s *Store) ApplySuppression(ctx context.Context, ignoreID, runID int64) error {
	ignore, err := s.GetIgnore(ctx, ignoreID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE scan_findings
		   SET is_suppressed = TRUE, suppressed_by = ?
		 WHERE scan_run_id = ?
		   AND component_id = ?
		   AND cve_id = ?
		   AND package_name = ?`,
		ignoreID, runID, ignore.ComponentID, ignore.CVEID, ignore.PackageName)
	return err
}

// ClearSuppression undoes ApplySuppression. Idempotent.
func (s *Store) ClearSuppression(ctx context.Context, ignoreID, runID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_findings
		   SET is_suppressed = FALSE, suppressed_by = NULL
		 WHERE scan_run_id = ? AND suppressed_by = ?`,
		runID, ignoreID)
	return err
}

// LatestDoneRunID returns the most recent done run id for a component, or sql.ErrNoRows.
func (s *Store) LatestDoneRunID(ctx context.Context, componentID int64) (int64, error) {
	var id int64
	err := s.db.GetContext(ctx, &id,
		`SELECT id FROM scan_runs
		 WHERE component_id = ? AND status = 'done'
		 ORDER BY id DESC LIMIT 1`, componentID)
	return id, err
}

func (s *Store) componentIDForRun(ctx context.Context, runID int64) (int64, error) {
	var componentID int64
	err := s.db.GetContext(ctx, &componentID,
		`SELECT component_id FROM scan_runs WHERE id = ?`, runID)
	return componentID, err
}

// nullIfEmpty returns sql.NullString.Null=true when s == "".
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// IsNotFound returns true when err matches sql.ErrNoRows.
func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
