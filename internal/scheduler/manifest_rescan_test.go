package scheduler_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scheduler"
)

// captureLogs redirects the global zerolog logger into a buffer for the duration of
// the test and returns it.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

// TestManifestRescan_InFlightComponent_LogsSkip pins the visibility fix: a component
// excluded from the sweep by the in-flight predicate must say so at WARN. The silent
// exclusion is what let scan_runs.id=355 wedge a component for three months.
func TestManifestRescan_InFlightComponent_LogsSkip(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "scanner-bridge-image")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 2160)

	buf := captureLogs(t)
	s := scheduler.NewManifestRescanScheduler(scheduler.ManifestRescanConfig{}, db, nil, nil)
	s.RunOnce(context.Background())

	out := buf.String()
	assert.Contains(t, out, "manifest_rescan: component skipped, scan already in flight")
	assert.Contains(t, out, `"level":"warn"`)
	assert.Contains(t, out, `"run_id":`)
	assert.Contains(t, out, `"run_status":"running"`)
	assert.Contains(t, out, `"age":`)
	assert.Contains(t, out, `"component_id":`)
}

// TestManifestRescan_NoInFlightRun_LogsNothing is the negative branch: a healthy
// component must not produce a skip line every cycle.
func TestManifestRescan_NoInFlightRun_LogsNothing(t *testing.T) {
	db := reaperTestDB(t)
	// No last_scan_id and no runs at all — nothing is in flight, so the sweep must
	// be silent.
	seedReaperComponent(t, db, "gate")

	buf := captureLogs(t)
	s := scheduler.NewManifestRescanScheduler(scheduler.ManifestRescanConfig{}, db, nil, nil)
	s.RunOnce(context.Background())

	assert.NotContains(t, buf.String(), "scan already in flight")
}

// TestManifestRescan_InFlightWithoutLastScan_LogsNothing asserts a component that has
// never had an SBOM pushed is not reported: rescanOne skips it regardless, so its
// exclusion carries no information.
func TestManifestRescan_InFlightWithoutLastScan_LogsNothing(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "brand-new")
	seedStaleRun(t, db, componentID, "pending", 0)

	buf := captureLogs(t)
	s := scheduler.NewManifestRescanScheduler(scheduler.ManifestRescanConfig{}, db, nil, nil)
	s.RunOnce(context.Background())

	assert.NotContains(t, buf.String(), "scan already in flight")
}
