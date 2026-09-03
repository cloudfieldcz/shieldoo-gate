package component

import (
	"context"
	"fmt"
	"sort"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// Delta is the diff between two scan runs (current vs previous).
//
// The two halves are measured at deliberately different granularities — see
// ComputeDelta, and docs/adr/ADR-022-version-aware-scan-delta.md for the reasoning.
type Delta struct {
	// NewCritical / NewHigh are the unsuppressed findings whose exact
	// (cve, package, version) triple was absent from the previous run.
	NewCritical []*ScanFinding
	NewHigh     []*ScanFinding
	// ResolvedCVEs are CVE ids that had at least one unsuppressed finding on the
	// previous run and have none now, at any version of any package. Sorted and
	// deduplicated so the same input always produces the same list.
	ResolvedCVEs []string
}

// findingKey identifies one vulnerable artefact: a CVE against a specific version of a
// specific package.
//
// It is a comparable struct rather than a delimited string on purpose, for the same
// reason IgnoreKey is (see store.go). Package names and versions arrive in
// operator-uploaded CycloneDX and are not trusted input: with a "|"-joined key a
// package literally named `stdlib|1.24.6` produces the exact key a finding for `stdlib`
// at version `1.24.6` produces, so one could mask the other. The consequence here is a
// missed alert rather than a suppressed finding, but the shape is the same and there is
// no reason to keep it.
type findingKey struct {
	CVEID          string
	PackageName    string
	PackageVersion string
}

func keyOf(f *ScanFinding) findingKey {
	return findingKey{CVEID: f.CVEID, PackageName: f.PackageName, PackageVersion: f.PackageVersion}
}

// ComputeDelta compares two finding sets and returns the New / Resolved partitions.
//
// The two halves are keyed differently, and that asymmetry is the design:
//
//   - "New" is keyed on the full (cve_id, package_name, package_version) triple. A
//     component can carry the same package twice at different versions — gate-image
//     ships our Go binary and the bundled trivy binary, so `stdlib` appears twice — and
//     a version-blind key let one copy mask the other. If a CVE on the vendored copy is
//     suppressed and our own binary then regresses to the same vulnerable version, the
//     version-blind key was already present and scan.new_critical never fired, even
//     though the finding was counted and shown in the UI.
//
//   - "Resolved" is keyed on the CVE id alone, over unsuppressed findings only. A CVE
//     is resolved when it stops being actionable for this component — no unsuppressed
//     finding anywhere in the current run. Measuring it on the triple would report a
//     CVE as resolved every time the package it sits on is bumped, including when the
//     new version still carries it.
//
// The consequence, stated plainly: bumping a package that still carries the CVE
// re-alerts it against the new version and does not report it resolved. That is a
// false positive by choice. The alternative — treating a CVE as already-known for a
// package at every version — is what produced the missed regression above, and on a
// security alert an extra line costs attention while a missing one costs coverage.
//
// Suppressed findings never appear in "new": they don't surface to the user, so they
// shouldn't fire alerts either. They do participate in the previous-run key set, so a
// finding that was suppressed last run and is unsuppressed now is not re-alerted as
// new — the ignore lifecycle has its own events for that.
func ComputeDelta(current, previous []*ScanFinding) Delta {
	prevSeen := make(map[findingKey]struct{}, len(previous))
	for _, f := range previous {
		prevSeen[keyOf(f)] = struct{}{}
	}

	var d Delta
	for _, f := range current {
		if f.IsSuppressed {
			continue
		}
		if _, ok := prevSeen[keyOf(f)]; ok {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			d.NewCritical = append(d.NewCritical, f)
		case SeverityHigh:
			d.NewHigh = append(d.NewHigh, f)
		}
	}

	currActive := activeCVEs(current)
	var resolved []string
	for cve := range activeCVEs(previous) {
		if _, ok := currActive[cve]; !ok {
			resolved = append(resolved, cve)
		}
	}
	sort.Strings(resolved)
	d.ResolvedCVEs = resolved
	return d
}

// activeCVEs is the set of CVE ids with at least one unsuppressed finding. It answers
// "is this CVE still actionable for the component", which is what resolution is
// measured on — a set membership test, not a representative finding, so nothing
// depends on which of several findings sharing a CVE happens to be visited last.
func activeCVEs(findings []*ScanFinding) map[string]struct{} {
	m := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		m[f.CVEID] = struct{}{}
	}
	return m
}

// EmitAlerts converts a Delta into a list of audit-log entries for downstream alerters.
// Returns (newCriticalCount, newHighCount, alerts).
func EmitAlerts(d Delta, run *ScanRun, comp *Component) (int64, int64, []model.AuditEntry) {
	var alerts []model.AuditEntry
	if len(d.NewCritical) > 0 {
		alerts = append(alerts, model.AuditEntry{
			EventType:    model.EventScanNewCritical,
			Reason:       fmt.Sprintf("%d new CRITICAL CVE(s) on %s", len(d.NewCritical), comp.Name),
			MetadataJSON: detailJSON("new_critical", d.NewCritical),
		})
	}
	if len(d.NewHigh) > 0 {
		alerts = append(alerts, model.AuditEntry{
			EventType:    model.EventScanNewHigh,
			Reason:       fmt.Sprintf("%d new HIGH CVE(s) on %s", len(d.NewHigh), comp.Name),
			MetadataJSON: detailJSON("new_high", d.NewHigh),
		})
	}
	return int64(len(d.NewCritical)), int64(len(d.NewHigh)), alerts
}

func detailJSON(key string, findings []*ScanFinding) string {
	if len(findings) == 0 {
		return "{}"
	}
	out := `{"` + key + `":[`
	for i, f := range findings {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"cve":%q,"pkg":%q,"version":%q}`, f.CVEID, f.PackageName, f.PackageVersion)
	}
	out += "]}"
	return out
}

// DeltaFunc is the function shape passed into ScanServiceDeps.DeltaFunc.
func DeltaFunc(store *Store) func(ctx context.Context, run *ScanRun, prev *ScanRun, current []*ScanFinding) (int64, int64, []model.AuditEntry, error) {
	return func(ctx context.Context, run *ScanRun, prev *ScanRun, current []*ScanFinding) (int64, int64, []model.AuditEntry, error) {
		var prevFindings []*ScanFinding
		if prev != nil {
			pf, err := store.FindingsByRun(ctx, prev.ID)
			if err != nil {
				return 0, 0, nil, err
			}
			prevFindings = pf
		}
		comp, err := store.GetComponent(ctx, run.ComponentID)
		if err != nil {
			return 0, 0, nil, err
		}
		d := ComputeDelta(current, prevFindings)
		nc, nh, alerts := EmitAlerts(d, run, comp)
		return nc, nh, alerts, nil
	}
}
