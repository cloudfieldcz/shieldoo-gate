// Package component implements the Component registry and vulnerability-scan
// pipeline (ScanRun lifecycle, CVE ignore lifecycle, delta computation).
//
// A Component is a technology unit (a service, a Docker image, a Python lockfile)
// that belongs to a Project and gets scanned periodically against OSV and Trivy
// using a CycloneDX SBOM uploaded by CI.
package component

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

// Component represents one technology component owned by a Project.
type Component struct {
	ID          int64     `db:"id" json:"id"`
	ProjectID   int64     `db:"project_id" json:"project_id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name,omitempty"`
	Description string    `db:"description" json:"description,omitempty"`
	Ecosystem   string    `db:"ecosystem" json:"ecosystem"`
	RepoURL     string    `db:"repo_url" json:"repo_url,omitempty"`
	AIEnabled   bool      `db:"ai_enabled" json:"ai_enabled"`
	Enabled     bool      `db:"enabled" json:"enabled"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	CreatedVia  string    `db:"created_via" json:"created_via"`
	LastScanID  *int64    `db:"last_scan_id" json:"last_scan_id,omitempty"`
}

// ScanRun represents one scan attempt against a Component's SBOM.
type ScanRun struct {
	ID                 int64      `db:"id" json:"id"`
	ComponentID        int64      `db:"component_id" json:"component_id"`
	Trigger            string     `db:"trigger" json:"trigger"`
	Status             string     `db:"status" json:"status"`
	SBOMBlobPath       string     `db:"sbom_blob_path" json:"sbom_blob_path"`
	SBOMSizeBytes      int64      `db:"sbom_size_bytes" json:"sbom_size_bytes"`
	SBOMFormat         string     `db:"sbom_format" json:"sbom_format"`
	SBOMSHA256         string     `db:"sbom_sha256" json:"sbom_sha256"`
	StartedAt          time.Time  `db:"started_at" json:"started_at"`
	FinishedAt         *time.Time `db:"finished_at" json:"finished_at,omitempty"`
	ScannerStatus      string     `db:"scanner_status" json:"scanner_status,omitempty"`
	CriticalCount      int64      `db:"critical_count" json:"critical_count"`
	HighCount          int64      `db:"high_count" json:"high_count"`
	MediumCount        int64      `db:"medium_count" json:"medium_count"`
	LowCount           int64      `db:"low_count" json:"low_count"`
	NewCriticalCount   int64      `db:"new_critical_count" json:"new_critical_count"`
	NewHighCount       int64      `db:"new_high_count" json:"new_high_count"`
	ComponentCount     int64      `db:"component_count" json:"component_count"`
	ErrorMessage       string     `db:"error_message" json:"error_message,omitempty"`
	IntegrityViolated  bool       `db:"integrity_violated" json:"integrity_violated"`
}

// ScanFinding is one (CVE, package, version) finding in a scan run.
type ScanFinding struct {
	ID             int64   `db:"id" json:"id"`
	ScanRunID      int64   `db:"scan_run_id" json:"scan_run_id"`
	ComponentID    int64   `db:"component_id" json:"component_id"`
	CVEID          string  `db:"cve_id" json:"cve_id"`
	PackageName    string  `db:"package_name" json:"package_name"`
	PackageVersion string  `db:"package_version" json:"package_version"`
	Ecosystem      string  `db:"ecosystem" json:"ecosystem"`
	Severity       string  `db:"severity" json:"severity"`
	CVSSScore      float64 `db:"cvss_score" json:"cvss_score,omitempty"`
	FixedVersion   string  `db:"fixed_version" json:"fixed_version,omitempty"`
	Summary        string  `db:"summary" json:"summary,omitempty"`
	DetectedBy     string  `db:"detected_by" json:"detected_by"` // JSON array of scanner IDs
	IsSuppressed   bool    `db:"is_suppressed" json:"is_suppressed"`
	SuppressedBy   *int64  `db:"suppressed_by" json:"suppressed_by,omitempty"`
}

// Ignore represents a CVE suppression entry for a Component.
type Ignore struct {
	ID                  int64      `db:"id" json:"id"`
	ComponentID         int64      `db:"component_id" json:"component_id"`
	CVEID               string     `db:"cve_id" json:"cve_id"`
	PackageName         string     `db:"package_name" json:"package_name"`
	PackageVersion      string     `db:"package_version" json:"package_version,omitempty"`
	Reason              string     `db:"reason" json:"reason"`
	AIDraftAccepted     bool       `db:"ai_draft_accepted" json:"ai_draft_accepted"`
	ExpiresAt           *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	CreatedAgainstRunID *int64     `db:"created_against_run_id" json:"created_against_run_id,omitempty"`
	CreatedByEmail      string     `db:"created_by_email" json:"created_by_email"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	RevokedAt           *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	RevokedByEmail      string     `db:"revoked_by_email" json:"revoked_by_email,omitempty"`
}

// AggregatedFinding is a Finding plus the list of scanners that detected it.
type AggregatedFinding struct {
	ScanFinding
	DetectedScanners []string `json:"detected_scanners"`
}

// Trigger constants.
const (
	TriggerUpload  = "upload"
	TriggerRescan  = "rescan"
	TriggerManual  = "manual"
)

// Status constants.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// Severity ordering used by the engine and aggregator.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// Errors returned by the component services.
var (
	ErrInvalidName      = errors.New("component: invalid name")
	ErrComponentExists  = errors.New("component: already exists")
	ErrNotFound         = errors.New("component: not found")
	ErrCapReached       = errors.New("component: max component count reached")
	ErrInvalidSBOM      = errors.New("component: invalid sbom")
	ErrSBOMTooLarge     = errors.New("component: sbom too large")
	ErrUnsupportedMedia = errors.New("component: unsupported content type")
	ErrIgnoreExists     = errors.New("component: active ignore already exists")
	ErrIgnoreNotFound   = errors.New("component: ignore not found")
	ErrRateLimited      = errors.New("component: rate limit exceeded")
)

// componentNameRegex mirrors NormalizeLabel from the project package, slightly extended
// to allow '/' and '.' for filesystem-path-like names common in lockfiles.
var componentNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,255}$`)

// ValidateComponentName returns true if the supplied name passes the canonical regex
// AND contains no NUL or control characters and no '..' path-traversal segment.
func ValidateComponentName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.Contains(name, "..") {
		return false
	}
	return componentNameRegex.MatchString(name)
}

// Service is the admin API for Component CRUD.
type Service interface {
	Resolve(ctx context.Context, projectID int64, name string, autoCreate bool, ecosystem string) (*Component, error)
	Get(ctx context.Context, id int64) (*Component, error)
	GetByName(ctx context.Context, projectID int64, name string) (*Component, error)
	ListByProject(ctx context.Context, projectID int64) ([]*Component, error)
	List(ctx context.Context, filter ListFilter) ([]*ListRow, error)
	Update(ctx context.Context, id int64, displayName, description, repoURL *string, enabled *bool, aiEnabled *bool) error
	Delete(ctx context.Context, id int64) error
}

// ListFilter is the filter passed to Service.List for the top-level Vulnerabilities page.
//
// Pagination has two mutually-exclusive modes:
//   - Offset:  classical LIMIT/OFFSET — backwards-compatible, simple, but
//              scans OFFSET+LIMIT rows and re-shuffles when data changes mid-paging.
//   - Cursor:  opaque keyset cursor produced by the previous page's
//              `next_cursor` response field. When set, ORDER BY collapses to
//              `id DESC` so the cursor is stable and lookups are O(LIMIT).
//
// Cursor wins over Offset when both are provided.
type ListFilter struct {
	ProjectLabel  string
	Ecosystem     string
	SeverityFloor string
	HasNew        bool
	Query         string
	Limit         int
	Offset        int
	// Cursor, when non-empty, is an opaque last-id cursor returned by a prior
	// call's `next_cursor` field. Implementation uses `id < cursor` semantics.
	Cursor string
}

// ListRow is a denormalized row for Screen 1 / Screen 3 list queries.
type ListRow struct {
	Component
	ProjectLabel     string     `db:"project_label" json:"project_label"`
	LastScanAt       *time.Time `db:"last_scan_at" json:"last_scan_at,omitempty"`
	LastScanTrigger  string     `db:"last_scan_trigger" json:"last_scan_trigger,omitempty"`
	CriticalCount    int64      `db:"critical_count" json:"critical_count"`
	HighCount        int64      `db:"high_count" json:"high_count"`
	MediumCount      int64      `db:"medium_count" json:"medium_count"`
	LowCount         int64      `db:"low_count" json:"low_count"`
	NewCriticalCount int64      `db:"new_critical_count" json:"new_critical_count"`
	NewHighCount     int64      `db:"new_high_count" json:"new_high_count"`
	Stale            bool       `db:"stale" json:"stale"`
}

// ScanService is the SBOM-upload + scan-run lifecycle interface.
type ScanService interface {
	// Submit accepts an SBOM stream, validates it, stores the blob, inserts a pending
	// scan_run row, and returns the new run id.
	Submit(ctx context.Context, componentID int64, sbom io.Reader, sizeHint int64, contentType, trigger, byEmail string) (*ScanRun, error)
	// Run executes the scan synchronously: fetches blob, runs scanners, aggregates
	// findings, writes scan_findings, updates scan_runs counts, writes audit log.
	Run(ctx context.Context, runID int64) error
	Get(ctx context.Context, runID int64) (*ScanRun, error)
	// ListByComponent returns up to `limit` runs for a component, ordered by
	// scan_runs.id DESC. When cursor != 0 the result is keyset-paginated:
	// only rows with id < cursor are returned. The ordering matches creation
	// order, so id-based cursors are stable across calls.
	ListByComponent(ctx context.Context, componentID int64, cursor int64, limit int) ([]*ScanRun, error)
	GetSBOM(ctx context.Context, runID int64) (data []byte, err error)
	Findings(ctx context.Context, runID int64) ([]*ScanFinding, error)
}

// IgnoreService manages CVE suppression lifecycle.
type IgnoreService interface {
	Create(ctx context.Context, componentID int64, cveID, packageName, packageVersion, reason string,
		expiresAt *time.Time, aiDraftAccepted bool, byEmail string, againstRunID int64) (*Ignore, error)
	Revoke(ctx context.Context, id int64, byEmail string) error
	Get(ctx context.Context, id int64) (*Ignore, error)
	ListActive(ctx context.Context, componentID int64) ([]*Ignore, error)
	ListExpired(ctx context.Context, now time.Time) ([]*Ignore, error)
	// ListRecentRevoked returns ignores revoked within the last `since` duration
	// for the given component. Used by the UI to render an "expired ignores" pane
	// where each row offers a Restore action that re-creates the ignore.
	ListRecentRevoked(ctx context.Context, componentID int64, since time.Duration) ([]*Ignore, error)
	// ApplySuppression sets is_suppressed=1 on every scan_findings row in runID matching
	// (component_id, cve_id, package_name). Per-package semantics — version is NOT in the predicate.
	ApplySuppression(ctx context.Context, ignoreID, runID int64) error
	// ClearSuppression sets is_suppressed=0, suppressed_by=NULL on every scan_findings row in runID
	// where suppressed_by=ignoreID. Idempotent.
	ClearSuppression(ctx context.Context, ignoreID, runID int64) error
}
