package model

import (
	"fmt"
	"time"
)

type Status string

const (
	StatusClean       Status = "CLEAN"
	StatusSuspicious  Status = "SUSPICIOUS"
	StatusQuarantined Status = "QUARANTINED"
	StatusPendingScan Status = "PENDING_SCAN"
)

type Artifact struct {
	Ecosystem      string    `db:"ecosystem" json:"ecosystem"`
	Name           string    `db:"name" json:"name"`
	Version        string    `db:"version" json:"version"`
	UpstreamURL    string    `db:"upstream_url" json:"upstream_url"`
	SHA256         string    `db:"sha256" json:"sha256"`
	SizeBytes      int64     `db:"size_bytes" json:"size_bytes"`
	CachedAt       time.Time `db:"cached_at" json:"cached_at"`
	LastAccessedAt time.Time `db:"last_accessed_at" json:"last_accessed_at"`
	StoragePath    string    `db:"storage_path" json:"storage_path"`
}

func (a Artifact) ID() string {
	return fmt.Sprintf("%s:%s:%s", a.Ecosystem, a.Name, a.Version)
}

type ArtifactStatus struct {
	ArtifactID       string     `db:"artifact_id" json:"artifact_id"`
	Status           Status     `db:"status" json:"status"`
	QuarantineReason string     `db:"quarantine_reason" json:"quarantine_reason,omitempty"`
	QuarantinedAt    *time.Time `db:"quarantined_at" json:"quarantined_at,omitempty"`
	ReleasedAt       *time.Time `db:"released_at" json:"released_at,omitempty"`
	RescanDueAt      *time.Time `db:"rescan_due_at" json:"rescan_due_at,omitempty"`
	LastScanID       *int64     `db:"last_scan_id" json:"last_scan_id,omitempty"`
}

func (s ArtifactStatus) IsServable() bool {
	return s.Status != StatusQuarantined
}
