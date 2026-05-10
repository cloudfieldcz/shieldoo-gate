package manifest

import (
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// SeverityFromCVSS maps a CVSS v3 base score to a scanner.Severity using the canonical
// FIRST.org thresholds: CRITICAL ≥9, HIGH ≥7, MEDIUM ≥4, LOW >0, INFO=0.
func SeverityFromCVSS(score float64) scanner.Severity {
	switch {
	case score >= 9.0:
		return scanner.SeverityCritical
	case score >= 7.0:
		return scanner.SeverityHigh
	case score >= 4.0:
		return scanner.SeverityMedium
	case score > 0:
		return scanner.SeverityLow
	}
	return scanner.SeverityInfo
}

// SeverityFromString normalizes a free-text severity label (CRITICAL/HIGH/...) into the
// canonical scanner.Severity. Unknown labels return SeverityInfo.
func SeverityFromString(raw string) scanner.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM", "MODERATE":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	case "INFO", "NEGLIGIBLE", "UNKNOWN":
		return scanner.SeverityInfo
	}
	return scanner.SeverityInfo
}

// ScoreFromCVSSVector parses the BaseScore prefix of a CVSS v3 vector if present.
// Returns 0 when the vector cannot be confidently parsed; the caller should fall back
// to SeverityFromString. CVSS vector parsing is intentionally minimal — Trivy/OSV both
// supply a `score` numeric field next to the vector when available.
func ScoreFromCVSSVector(vector string) float64 {
	// CVSS v3 vector strings start with `CVSS:3.x/...` and don't carry a base score
	// inline. The OSV severity entry shape is {"type":"CVSS_V3","score":"<vector>"} —
	// where score is the vector, not a number. We treat the vector as opaque here and
	// rely on the parallel `score: <number>` field surfaced by both OSV and Trivy.
	_ = vector
	return 0
}
