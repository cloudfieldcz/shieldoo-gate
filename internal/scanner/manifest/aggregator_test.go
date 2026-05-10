package manifest

import (
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func TestAggregate_DedupeAndMaxSeverity(t *testing.T) {
	osv := ScanOutcome{ScannerID: "osv", Findings: []Finding{
		{CVEID: "CVE-1", PackageName: "lodash", PackageVersion: "4.17.20", Severity: scanner.SeverityHigh},
	}}
	trivy := ScanOutcome{ScannerID: "trivy", Findings: []Finding{
		{CVEID: "CVE-1", PackageName: "lodash", PackageVersion: "4.17.20", Severity: scanner.SeverityCritical, CVSSScore: 9.8},
		{CVEID: "CVE-2", PackageName: "moment", PackageVersion: "2.29.0", Severity: scanner.SeverityMedium},
	}}
	out := Aggregate([]ScanOutcome{osv, trivy})
	if len(out) != 2 {
		t.Fatalf("expected 2 aggregated findings, got %d", len(out))
	}
	for _, f := range out {
		if f.CVEID == "CVE-1" {
			if f.Severity != scanner.SeverityCritical {
				t.Errorf("expected max severity CRITICAL, got %s", f.Severity)
			}
			if len(f.DetectedBy) != 2 {
				t.Errorf("expected 2 scanners, got %v", f.DetectedBy)
			}
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  scanner.Severity
	}{
		{9.5, scanner.SeverityCritical},
		{7.5, scanner.SeverityHigh},
		{5.0, scanner.SeverityMedium},
		{2.0, scanner.SeverityLow},
		{0.0, scanner.SeverityInfo},
	}
	for _, c := range cases {
		got := SeverityFromCVSS(c.score)
		if got != c.want {
			t.Errorf("SeverityFromCVSS(%f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestParseCycloneDX(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"requests","version":"2.10.0","purl":"pkg:pypi/requests@2.10.0","type":"library"}]}`)
	comps, err := ParseCycloneDXComponents(body)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if comps[0].Ecosystem != "PyPI" {
		t.Errorf("expected PyPI ecosystem, got %s", comps[0].Ecosystem)
	}
}
