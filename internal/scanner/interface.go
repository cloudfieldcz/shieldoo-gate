package scanner

import (
	"context"
	"time"
)

type Ecosystem string

const (
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemDocker Ecosystem = "docker"
	EcosystemNuGet  Ecosystem = "nuget"
	EcosystemMaven    Ecosystem = "maven"
	EcosystemRubyGems Ecosystem = "rubygems"
	EcosystemGo       Ecosystem = "go"
)

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

type Artifact struct {
	ID          string
	Ecosystem   Ecosystem
	Name        string
	Version     string
	LocalPath   string
	Filename    string // original filename (e.g. "requests-2.32.3-py3-none-any.whl")
	SHA256      string
	SizeBytes   int64
	UpstreamURL string
}

type Finding struct {
	Severity    Severity
	Category    string
	Description string
	Location    string
	IoCs        []string
}

type ScanResult struct {
	Verdict    Verdict
	Confidence float32
	Findings   []Finding
	ScannerID  string
	Duration   time.Duration
	ScannedAt  time.Time
	Error      error
}

type Scanner interface {
	Name() string
	Version() string
	SupportedEcosystems() []Ecosystem
	Scan(ctx context.Context, artifact Artifact) (ScanResult, error)
	HealthCheck(ctx context.Context) error
}
