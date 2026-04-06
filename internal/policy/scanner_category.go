package policy

import "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"

// ScannerCategory classifies scanners for effective severity calculation.
type ScannerCategory int

const (
	// CategoryVulnerability covers scanners that report known CVEs (osv, trivy).
	CategoryVulnerability ScannerCategory = iota
	// CategoryBehavioral covers scanners that detect supply chain attack patterns.
	CategoryBehavioral
	// CategoryIntegrity covers scanners that verify artifact integrity (hash, threat-feed).
	CategoryIntegrity
)

// behavioralScanners maps scanner IDs to the behavioral category.
// Behavioral scanner findings have a minimum effective severity of HIGH
// to prevent severity-downgrade attacks in balanced/permissive mode.
var behavioralScanners = map[string]bool{
	"guarddog":                true,
	"ai-scanner":             true,
	"exfil-detector":         true,
	"install-hook-analyzer":  true,
	"pth-inspector":          true,
	"obfuscation-detector":   true,
}

// ScannerCategoryFor returns the category of a scanner by its ID.
func ScannerCategoryFor(scannerID string) ScannerCategory {
	if behavioralScanners[scannerID] {
		return CategoryBehavioral
	}
	switch scannerID {
	case "hash-verifier", "builtin-threat-feed":
		return CategoryIntegrity
	}
	return CategoryVulnerability
}

// EffectiveSeverity applies the scanner category floor to a finding's severity.
// Behavioral scanner findings are elevated to at least HIGH to prevent
// severity-downgrade attacks where a crafted package triggers SUSPICIOUS+MEDIUM
// from a behavioral scanner and would slip through balanced/permissive mode.
func EffectiveSeverity(severity scanner.Severity, scannerID string) scanner.Severity {
	if ScannerCategoryFor(scannerID) == CategoryBehavioral {
		if severityRank(severity) < severityRank(scanner.SeverityHigh) {
			return scanner.SeverityHigh
		}
	}
	return severity
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityInfo:
		return 0
	case scanner.SeverityLow:
		return 1
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityHigh:
		return 3
	case scanner.SeverityCritical:
		return 4
	default:
		return 0
	}
}

// SeverityAtLeastHigh returns true if the severity is HIGH or CRITICAL.
func SeverityAtLeastHigh(s scanner.Severity) bool {
	return severityRank(s) >= severityRank(scanner.SeverityHigh)
}
