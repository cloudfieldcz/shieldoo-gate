package model

import "time"

type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	IoCs        []string `json:"iocs,omitempty"`
}

type ScanResult struct {
	ID             int64     `db:"id" json:"id"`
	ArtifactID     string    `db:"artifact_id" json:"artifact_id"`
	ScannedAt      time.Time `db:"scanned_at" json:"scanned_at"`
	ScannerName    string    `db:"scanner_name" json:"scanner_name"`
	ScannerVersion string    `db:"scanner_version" json:"scanner_version"`
	Verdict        Verdict   `db:"verdict" json:"verdict"`
	Confidence     float32   `db:"confidence" json:"confidence"`
	FindingsJSON   string    `db:"findings_json" json:"findings_json"`
	DurationMs     int64     `db:"duration_ms" json:"duration_ms"`
}
