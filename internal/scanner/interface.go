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
	// ExtraLicenses holds additional license strings discovered outside the
	// normal scan path (e.g. Maven effective-POM parent chain resolution).
	// Populated by the adapter before ScanAll; merged into ScanResult.Licenses
	// by the Trivy scanner alongside its own extraction results.
	ExtraLicenses []string
}

type Finding struct {
	Severity    Severity
	Category    string
	Description string
	Location    string
	IoCs        []string
}

type ScanResult struct {
	Verdict        Verdict
	Confidence     float32
	Findings       []Finding
	ScannerID      string
	ScannerVersion string
	Duration       time.Duration
	ScannedAt      time.Time
	Error          error

	// SBOMContent is the serialized SBOM produced by the scanner (e.g. Trivy
	// in CycloneDX mode). Empty for scanners that do not produce SBOMs.
	SBOMContent []byte
	// SBOMFormat is the format string (e.g. "cyclonedx-json").
	SBOMFormat string
	// Licenses is a pre-extracted, deduplicated list of SPDX IDs from the SBOM.
	// Used by the license evaluator so the blob does not need to be re-parsed.
	Licenses []string
}

type Scanner interface {
	Name() string
	Version() string
	SupportedEcosystems() []Ecosystem
	Scan(ctx context.Context, artifact Artifact) (ScanResult, error)
	HealthCheck(ctx context.Context) error
}
