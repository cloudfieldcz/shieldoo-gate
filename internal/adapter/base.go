package adapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/cloudfieldcz/shieldoo-gate/internal/alert"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// globalAlerter holds the package-level alerter set during initialization.
var globalAlerter atomic.Pointer[alert.Alerter]

// SetAlerter stores the alerter for use by WriteAuditLog and DispatchAlert.
func SetAlerter(a alert.Alerter) {
	globalAlerter.Store(&a)
}

// DispatchAlert sends an alert without writing to audit_log.
// Use when audit_log was already written (e.g., in API handler transactions).
func DispatchAlert(entry model.AuditEntry) {
	if a := globalAlerter.Load(); a != nil {
		(*a).Dispatch(context.Background(), entry)
	}
}

// ArtifactLocker provides per-artifact-ID locking so that only one
// download/scan pipeline runs for a given artifact at a time.
// Subsequent requests for the same artifact wait for the first to complete.
var ArtifactLocker artifactLocker

type artifactLocker struct {
	locks sync.Map // map[string]*sync.Mutex
}

// Lock acquires a lock for the given artifact ID.
// Returns an unlock function that must be called when done.
func (al *artifactLocker) Lock(artifactID string) func() {
	val, _ := al.locks.LoadOrStore(artifactID, &sync.Mutex{})
	mu := val.(*sync.Mutex)
	mu.Lock()
	return func() { mu.Unlock() }
}

// validNameRe matches safe package name characters — no path traversal or shell metacharacters.
var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// ValidatePackageName returns an error if name contains unsafe characters.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("adapter: package name must not be empty")
	}
	if !validNameRe.MatchString(name) {
		return fmt.Errorf("adapter: package name %q contains invalid characters", name)
	}
	return nil
}

// ValidateVersion returns an error if version contains unsafe characters.
func ValidateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("adapter: version must not be empty")
	}
	if !validNameRe.MatchString(version) {
		return fmt.Errorf("adapter: version %q contains invalid characters", version)
	}
	return nil
}

// ErrorResponse is the JSON body returned for blocked or quarantined requests.
type ErrorResponse struct {
	Error      string `json:"error"`
	Artifact   string `json:"artifact,omitempty"`
	Reason     string `json:"reason,omitempty"`
	DetailsURL string `json:"details_url,omitempty"`
}

// WriteJSONError writes a JSON-encoded ErrorResponse with the given HTTP status.
func WriteJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteAuditLog inserts an AuditEntry into the audit_log table.
// Timestamp is set to now if zero.
func WriteAuditLog(db *sqlx.DB, entry model.AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_, err := db.Exec(
		`INSERT INTO audit_log (ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp,
		entry.EventType,
		entry.ArtifactID,
		entry.ClientIP,
		entry.UserAgent,
		entry.Reason,
		entry.MetadataJSON,
	)
	if err != nil {
		return fmt.Errorf("adapter: writing audit log: %w", err)
	}
	if a := globalAlerter.Load(); a != nil {
		(*a).Dispatch(context.Background(), entry)
	}
	return nil
}

// GetArtifactStatus retrieves the current status of an artifact by ID.
// Returns (nil, nil) when no row is found.
func GetArtifactStatus(db *sqlx.DB, artifactID string) (*model.ArtifactStatus, error) {
	var status model.ArtifactStatus
	err := db.Get(&status,
		`SELECT artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id
		 FROM artifact_status WHERE artifact_id = ?`, artifactID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("adapter: getting artifact status for %s: %w", artifactID, err)
	}
	return &status, nil
}

// InsertScanResults persists a slice of scanner.ScanResult rows for the given artifactID.
func InsertScanResults(db *sqlx.DB, artifactID string, results []scanner.ScanResult) error {
	for _, r := range results {
		findingsJSON, err := json.Marshal(r.Findings)
		if err != nil {
			return fmt.Errorf("adapter: marshalling findings for %s: %w", artifactID, err)
		}
		scannerVersion := ""
		_, err = db.Exec(
			`INSERT INTO scan_results (artifact_id, scanned_at, scanner_name, scanner_version, verdict, confidence, findings_json, duration_ms)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			artifactID,
			r.ScannedAt,
			r.ScannerID,
			scannerVersion,
			string(r.Verdict),
			r.Confidence,
			string(findingsJSON),
			r.Duration.Milliseconds(),
		)
		if err != nil {
			return fmt.Errorf("adapter: inserting scan result for %s/%s: %w", artifactID, r.ScannerID, err)
		}
	}
	return nil
}

// InsertArtifact transactionally inserts the artifact row and its initial status row.
func InsertArtifact(db *sqlx.DB, artifact model.Artifact, status model.ArtifactStatus) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("adapter: beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	artifactID := artifact.ID()
	_, err = tx.Exec(
		`INSERT OR REPLACE INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID,
		artifact.Ecosystem,
		artifact.Name,
		artifact.Version,
		artifact.UpstreamURL,
		artifact.SHA256,
		artifact.SizeBytes,
		artifact.CachedAt,
		artifact.LastAccessedAt,
		artifact.StoragePath,
	)
	if err != nil {
		return fmt.Errorf("adapter: inserting artifact %s: %w", artifactID, err)
	}

	_, err = tx.Exec(
		`INSERT OR REPLACE INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		artifactID,
		status.Status,
		status.QuarantineReason,
		status.QuarantinedAt,
		status.ReleasedAt,
		status.RescanDueAt,
		status.LastScanID,
	)
	if err != nil {
		return fmt.Errorf("adapter: inserting artifact status for %s: %w", artifactID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("adapter: committing artifact insert for %s: %w", artifactID, err)
	}
	return nil
}
