package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// finding is a terse constructor for the delta tests, which only ever care about the
// four fields ComputeDelta reads.
func finding(cve, pkg, version, severity string) *ScanFinding {
	return &ScanFinding{CVEID: cve, PackageName: pkg, PackageVersion: version, Severity: severity}
}

func suppressed(f *ScanFinding) *ScanFinding {
	f.IsSuppressed = true
	return f
}

func TestComputeDelta_SuppressedVendoredCopy_RegressionOnOurCopyReportedNew(t *testing.T) {
	// gate-image carries stdlib twice: once from the bundled trivy binary (the CVE
	// there is suppressed by a version-pinned ignore) and once from our own binary.
	// A version-blind key made the suppressed copy mask a regression in ours.
	prev := []*ScanFinding{
		suppressed(finding("CVE-2026-1000", "stdlib", "1.24.6", SeverityCritical)),
	}
	curr := []*ScanFinding{
		suppressed(finding("CVE-2026-1000", "stdlib", "1.24.6", SeverityCritical)),
		finding("CVE-2026-1000", "stdlib", "1.27.1", SeverityCritical),
	}

	d := ComputeDelta(curr, prev)

	require.Len(t, d.NewCritical, 1, "a regression on our own copy must fire even while the vendored copy is suppressed")
	assert.Equal(t, "1.27.1", d.NewCritical[0].PackageVersion)
	assert.Empty(t, d.ResolvedCVEs)
}

func TestComputeDelta_PackageBumpCarryingTheCVE_ReportsNewAndNotResolved(t *testing.T) {
	// The deliberate false positive: the vulnerable artefact changed, so the finding is
	// new; the CVE is still actionable, so it is not resolved. The two halves must never
	// contradict each other.
	prev := []*ScanFinding{finding("CVE-2026-2000", "golang.org/x/net", "0.30.0", SeverityCritical)}
	curr := []*ScanFinding{finding("CVE-2026-2000", "golang.org/x/net", "0.31.0", SeverityCritical)}

	d := ComputeDelta(curr, prev)

	require.Len(t, d.NewCritical, 1, "the CVE now sits on a different version, which is a different vulnerable artefact")
	assert.Equal(t, "0.31.0", d.NewCritical[0].PackageVersion)
	assert.Empty(t, d.ResolvedCVEs, "a CVE that is still open must never be reported resolved just because the version moved")
}

func TestComputeDelta_PackageBumpDroppingTheCVE_ReportsResolved(t *testing.T) {
	prev := []*ScanFinding{finding("CVE-2026-2000", "golang.org/x/net", "0.30.0", SeverityCritical)}
	curr := []*ScanFinding{finding("CVE-2026-3000", "golang.org/x/net", "0.31.0", SeverityHigh)}

	d := ComputeDelta(curr, prev)

	assert.Equal(t, []string{"CVE-2026-2000"}, d.ResolvedCVEs)
	require.Len(t, d.NewHigh, 1)
	assert.Empty(t, d.NewCritical)
}

func TestComputeDelta_CVEStillOpenOnAnotherPackage_NotReportedResolved(t *testing.T) {
	// The same CVE id can land on two packages. Resolution is per-CVE, so it only
	// counts once nothing actionable is left anywhere in the run.
	prev := []*ScanFinding{
		finding("CVE-2026-4000", "libxml2", "2.13.0", SeverityHigh),
		finding("CVE-2026-4000", "libxml2-utils", "2.13.0", SeverityHigh),
	}
	curr := []*ScanFinding{
		finding("CVE-2026-4000", "libxml2-utils", "2.13.0", SeverityHigh),
	}

	d := ComputeDelta(curr, prev)

	assert.Empty(t, d.ResolvedCVEs, "the CVE is still listed on the component, so it is not resolved")
}

func TestComputeDelta_OnlySuppressedCopyRemains_ReportedResolved(t *testing.T) {
	// Our copy was fixed; only the suppressed vendored copy is left. Nothing actionable
	// remains, so the operator's CVE is resolved.
	prev := []*ScanFinding{
		suppressed(finding("CVE-2026-1000", "stdlib", "1.24.6", SeverityCritical)),
		finding("CVE-2026-1000", "stdlib", "1.27.1", SeverityCritical),
	}
	curr := []*ScanFinding{
		suppressed(finding("CVE-2026-1000", "stdlib", "1.24.6", SeverityCritical)),
	}

	d := ComputeDelta(curr, prev)

	assert.Equal(t, []string{"CVE-2026-1000"}, d.ResolvedCVEs)
	assert.Empty(t, d.NewCritical)
}

func TestComputeDelta_PreviouslySuppressedFindingNowActive_NotReportedNew(t *testing.T) {
	// An ignore expiring un-suppresses an existing finding. The ignore lifecycle has its
	// own audit event; the same artefact must not also be alerted as a new CVE.
	prev := []*ScanFinding{suppressed(finding("CVE-2026-5000", "requests", "2.32.3", SeverityCritical))}
	curr := []*ScanFinding{finding("CVE-2026-5000", "requests", "2.32.3", SeverityCritical)}

	d := ComputeDelta(curr, prev)

	assert.Empty(t, d.NewCritical)
	assert.Empty(t, d.ResolvedCVEs)
}

func TestComputeDelta_PackageNameContainingTheOldSeparator_DoesNotCollide(t *testing.T) {
	// The previous implementation keyed on cve+"|"+package. A package literally named
	// `stdlib|1.24.6` then produced the same key as `stdlib` at version `1.24.6`, so one
	// silently masked the other. Package names come from operator-uploaded CycloneDX.
	prev := []*ScanFinding{finding("CVE-2026-6000", "stdlib|1.24.6", "", SeverityCritical)}
	curr := []*ScanFinding{finding("CVE-2026-6000", "stdlib", "1.24.6", SeverityCritical)}

	d := ComputeDelta(curr, prev)

	require.Len(t, d.NewCritical, 1, "a genuinely different package must not be masked by a crafted name")
	assert.Equal(t, "stdlib", d.NewCritical[0].PackageName)
}

func TestComputeDelta_ResolvedCVEs_SortedAndDeduplicated(t *testing.T) {
	// Two packages, one CVE each, plus a CVE that sits on both. Map iteration order must
	// not reach the output: alerts derived from it are written to an append-only table.
	prev := []*ScanFinding{
		finding("CVE-2026-9000", "pkgA", "1.0", SeverityHigh),
		finding("CVE-2026-7000", "pkgA", "1.0", SeverityHigh),
		finding("CVE-2026-7000", "pkgB", "2.0", SeverityHigh),
		finding("CVE-2026-8000", "pkgB", "2.0", SeverityHigh),
	}

	for i := 0; i < 20; i++ {
		d := ComputeDelta(nil, prev)
		assert.Equal(t, []string{"CVE-2026-7000", "CVE-2026-8000", "CVE-2026-9000"}, d.ResolvedCVEs)
	}
}

func TestComputeDelta_NoPreviousRun_EverythingUnsuppressedIsNew(t *testing.T) {
	curr := []*ScanFinding{
		finding("CVE-2026-1", "a", "1.0", SeverityCritical),
		finding("CVE-2026-2", "b", "1.0", SeverityHigh),
		finding("CVE-2026-3", "c", "1.0", SeverityMedium),
	}

	d := ComputeDelta(curr, nil)

	assert.Len(t, d.NewCritical, 1)
	assert.Len(t, d.NewHigh, 1, "MEDIUM and below never alert")
	assert.Empty(t, d.ResolvedCVEs)
}
