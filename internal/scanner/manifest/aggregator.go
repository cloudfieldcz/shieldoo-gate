package manifest

import (
	"encoding/json"
	"sort"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// AggregatedFinding is a Finding plus the list of scanners that detected it.
type AggregatedFinding struct {
	Finding
	DetectedBy []string
}

// Aggregate dedupes findings across scanners by (cve_id, package_name, package_version).
// When two scanners disagree on severity or CVSS score, the maximum is taken.
func Aggregate(outcomes []ScanOutcome) []AggregatedFinding {
	type key struct{ cve, pkg, ver string }
	bucket := map[key]*AggregatedFinding{}
	for _, oc := range outcomes {
		for _, f := range oc.Findings {
			k := key{f.CVEID, f.PackageName, f.PackageVersion}
			existing := bucket[k]
			if existing == nil {
				ag := AggregatedFinding{Finding: f, DetectedBy: []string{oc.ScannerID}}
				bucket[k] = &ag
				continue
			}
			if severityOrder(f.Severity) > severityOrder(existing.Severity) {
				existing.Severity = f.Severity
			}
			if f.CVSSScore > existing.CVSSScore {
				existing.CVSSScore = f.CVSSScore
			}
			if existing.FixedVersion == "" && f.FixedVersion != "" {
				existing.FixedVersion = f.FixedVersion
			}
			if existing.Summary == "" && f.Summary != "" {
				existing.Summary = f.Summary
			}
			if !contains(existing.DetectedBy, oc.ScannerID) {
				existing.DetectedBy = append(existing.DetectedBy, oc.ScannerID)
			}
		}
	}
	out := make([]AggregatedFinding, 0, len(bucket))
	for _, v := range bucket {
		sort.Strings(v.DetectedBy)
		out = append(out, *v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

// DetectedByJSON marshals the DetectedBy slice into a stable JSON array string for
// storage in scan_findings.detected_by.
func DetectedByJSON(names []string) string {
	if len(names) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(names)
	return string(b)
}

func severityOrder(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 5
	case scanner.SeverityHigh:
		return 4
	case scanner.SeverityMedium:
		return 3
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 1
	}
	return 0
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
