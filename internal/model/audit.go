package model

import "time"

type EventType string

const (
	EventServed          EventType = "SERVED"
	EventBlocked         EventType = "BLOCKED"
	EventQuarantined     EventType = "QUARANTINED"
	EventScanUnavailable EventType = "SCAN_UNAVAILABLE"
	EventReleased        EventType = "RELEASED"
	EventScanned         EventType = "SCANNED"
	EventOverrideCreated EventType = "OVERRIDE_CREATED"
	EventOverrideRevoked EventType = "OVERRIDE_REVOKED"
	EventTagMutated      EventType = "TAG_MUTATED"
	EventRescanQueued       EventType = "RESCAN_QUEUED"
	EventAllowedWithWarning EventType = "ALLOWED_WITH_WARNING"
	EventIntegrityViolation EventType = "INTEGRITY_VIOLATION"
	EventArtifactDeleted    EventType = "ARTIFACT_DELETED"
)

type AuditEntry struct {
	ID           int64     `db:"id" json:"id"`
	Timestamp    time.Time `db:"ts" json:"ts"`
	EventType    EventType `db:"event_type" json:"event_type"`
	ArtifactID   string    `db:"artifact_id" json:"artifact_id,omitempty"`
	ClientIP     string    `db:"client_ip" json:"client_ip,omitempty"`
	UserAgent    string    `db:"user_agent" json:"user_agent,omitempty"`
	Reason       string    `db:"reason" json:"reason,omitempty"`
	MetadataJSON string    `db:"metadata_json" json:"metadata_json,omitempty"`
	UserEmail    string    `db:"user_email" json:"user_email,omitempty"`
	ProjectID    *int64    `db:"project_id" json:"project_id,omitempty"`
	// Vuln-scan lifecycle FK-shaped columns (migration 035). Nullable; not enforced as FKs
	// because audit_log is append-only forensic evidence (CLAUDE.md security invariant #5).
	ComponentID *int64 `db:"component_id" json:"component_id,omitempty"`
	ScanRunID   *int64 `db:"scan_run_id"  json:"scan_run_id,omitempty"`
	IgnoreID    *int64 `db:"ignore_id"    json:"ignore_id,omitempty"`
	APIKeyID    *int64 `db:"api_key_id"   json:"api_key_id,omitempty"`
}

// License policy + project-related event types (v1.2).
const (
	EventLicenseBlocked      EventType = "LICENSE_BLOCKED"
	EventLicenseWarned       EventType = "LICENSE_WARNED"
	EventLicenseCheckSkipped EventType = "LICENSE_CHECK_SKIPPED"
	EventProjectNotFound     EventType = "PROJECT_NOT_FOUND"
	EventSBOMGenerated       EventType = "SBOM_GENERATED"

	// EventScannerVerdictDowngraded records when version-diff downgrades a scanner
	// verdict (MALICIOUS → SUSPICIOUS, or SUSPICIOUS → CLEAN below MinConfidence).
	// MetadataJSON has shape: {"scanner":"version-diff","original_verdict":"MALICIOUS",
	// "downgraded_verdict":"SUSPICIOUS","ai_confidence":0.92,"reason":"asymmetric-diff-downgrade"}
	EventScannerVerdictDowngraded EventType = "SCANNER_VERDICT_DOWNGRADED"
)

// Vulnerability scan event types (action events written unconditionally to audit_log).
const (
	EventSBOMUploaded         EventType = "sbom_uploaded"
	EventScanRunFailed        EventType = "scan_run_failed"
	EventRescanTriggered      EventType = "rescan_triggered"
	EventIgnoreCreated        EventType = "ignore_created"
	EventIgnoreRevoked        EventType = "ignore_revoked"
	EventIgnoreExpired        EventType = "ignore_expired"
	EventAIDraftCalled        EventType = "ai_draft_called"
	EventAIDraftAccepted      EventType = "ai_draft_accepted"
	EventAnomalyAcknowledged  EventType = "anomaly_acknowledged"
	EventAPIKeyScopeChanged   EventType = "api_key_scope_changed"
	EventSuperTokenUsed       EventType = "super_token_used"
	EventRepoURLChanged       EventType = "repo_url_changed"
	EventSBOMIntegrityViolation EventType = "sbom_integrity_violation"
)

// Vulnerability scan alert event types (consumed by the alerter; opt-in via Settings → Alerting).
const (
	EventScanNewCritical    EventType = "scan.new_critical"
	EventScanNewHigh        EventType = "scan.new_high"
	EventScanAnomaly        EventType = "scan.anomaly_detected"
	EventScanIgnoreExpired  EventType = "ignore.expired"
)
