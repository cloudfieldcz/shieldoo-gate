package component

import (
	"context"
	"encoding/json"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest"
)

// ManifestScanInvoker adapts a manifest.Engine to ScannerInvoker so the ScanService
// can drive the OSV+Trivy pipeline without depending on the manifest package directly
// in tests.
type ManifestScanInvoker struct {
	Engine *manifest.Engine
}

// Scan implements ScannerInvoker.
func (m *ManifestScanInvoker) Scan(ctx context.Context, run *ScanRun, sbom []byte) (*ScanResult, error) {
	if m.Engine == nil {
		return &ScanResult{ScannerStatus: map[string]string{"engine": "noop"}}, nil
	}
	mf := manifest.Manifest{
		SBOMBytes:      sbom,
		ComponentCount: int(run.ComponentCount),
	}
	outcomes := m.Engine.ScanAll(ctx, mf)
	agg := manifest.Aggregate(outcomes)

	statusMap := map[string]string{}
	for _, oc := range outcomes {
		statusMap[oc.ScannerID] = oc.Status
	}

	res := &ScanResult{ScannerStatus: statusMap}
	for _, f := range agg {
		res.Findings = append(res.Findings, &ScanFinding{
			CVEID:          f.CVEID,
			PackageName:    f.PackageName,
			PackageVersion: f.PackageVersion,
			Ecosystem:      f.Ecosystem,
			Severity:       string(f.Severity),
			CVSSScore:      f.CVSSScore,
			FixedVersion:   f.FixedVersion,
			Summary:        f.Summary,
			DetectedBy:     manifest.DetectedByJSON(f.DetectedBy),
		})
	}
	res.ComponentCount = int64(run.ComponentCount)
	// Severity counters get filled by ScanService.Run after suppression.
	return res, nil
}

// ParseDetectedBy is a helper used by the API layer to convert the JSON-encoded
// scan_findings.detected_by column back into a slice for client responses.
func ParseDetectedBy(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
