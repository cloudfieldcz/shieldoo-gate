package component

import (
	"context"
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// Delta is the diff between two scan runs (current vs previous).
type Delta struct {
	NewCritical  []*ScanFinding
	NewHigh      []*ScanFinding
	ResolvedCVEs []string
}

// ComputeDelta compares two finding sets keyed on (cve_id, package_name) and returns
// the New / Resolved partitions. Suppressed findings are excluded from "new" — they
// don't surface to the user, so they shouldn't fire alerts either.
func ComputeDelta(current, previous []*ScanFinding) Delta {
	prevKeys := keysOf(previous)
	currKeys := keysOf(current)

	var d Delta
	for _, f := range current {
		if f.IsSuppressed {
			continue
		}
		k := f.CVEID + "|" + f.PackageName
		if _, ok := prevKeys[k]; ok {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			d.NewCritical = append(d.NewCritical, f)
		case SeverityHigh:
			d.NewHigh = append(d.NewHigh, f)
		}
	}
	for k, p := range prevKeys {
		if _, ok := currKeys[k]; !ok && !p.IsSuppressed {
			d.ResolvedCVEs = append(d.ResolvedCVEs, p.CVEID)
		}
	}
	return d
}

func keysOf(findings []*ScanFinding) map[string]*ScanFinding {
	m := make(map[string]*ScanFinding, len(findings))
	for _, f := range findings {
		m[f.CVEID+"|"+f.PackageName] = f
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
