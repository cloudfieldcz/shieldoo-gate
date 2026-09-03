package scheduler_test

import (
	"bytes"
	"context"
	"testing"
	"time"

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
	assert.Contains(t, out, `"component_id":`)
	assert.Contains(t, out, `"stuck":true`, "a run past the grace must be greppable")
	// Exact rendering, not just presence: zerolog's Dur() would emit a bare unlabelled
	// millisecond count here, and eyeball-triage of this one line is the deliverable.
	assert.Contains(t, out, `"age":"2160h0m0s"`)
	assert.NotContains(t, out, `"age":7776000000`)
}

// TestManifestRescan_RecentInFlight_LogsInfoNotWarn is the severity gradient. In steady
// state the reaper clears real wedges within an hour while this sweep runs every 6h, so
// nearly every line here is a benign overlap with a manual rescan or an upload. Logging
// those at WARN would train the operator to ignore the only line that matters.
func TestManifestRescan_RecentInFlight_LogsInfoNotWarn(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "gate")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 0) // started just now

	buf := captureLogs(t)
	s := scheduler.NewManifestRescanScheduler(scheduler.ManifestRescanConfig{}, db, nil, nil)
	s.RunOnce(context.Background())

	out := buf.String()
	assert.Contains(t, out, "manifest_rescan: component skipped, scan already in flight")
	assert.Contains(t, out, `"level":"info"`)
	assert.Contains(t, out, `"stuck":false`)
	assert.NotContains(t, out, `"level":"warn"`, "a benign overlap must not log at WARN")
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

// The skip line's grace has to track the scan budget the operator configured. With the
// default 5m timeout the 15m floor stands; an operator running a 30m timeout would
// otherwise get a WARN for every legitimately slow scan.
func TestManifestRescan_LongTimeout_WidensTheSkipGrace(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "slow-image")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 1) // one hour in

	buf := captureLogs(t)
	// 2 x 45m = 1h30m of grace, so a one-hour-old run is still a benign overlap.
	s := scheduler.NewManifestRescanScheduler(
		scheduler.ManifestRescanConfig{Timeout: 45 * time.Minute}, db, nil, nil)
	s.RunOnce(context.Background())

	out := buf.String()
	assert.Contains(t, out, "manifest_rescan: component skipped, scan already in flight")
	assert.Contains(t, out, `"stuck":false`)
	assert.Contains(t, out, `"grace":"1h30m0s"`, "the line must say which grace it judged against")
	assert.NotContains(t, out, `"level":"warn"`)
}

// The floor still dominates a short timeout: 2 x 5m is below 15m, so a 20-minute-old run
// is still reported as stuck.
func TestManifestRescan_ShortTimeout_KeepsTheFifteenMinuteFloor(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "quick-image")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 1)

	buf := captureLogs(t)
	s := scheduler.NewManifestRescanScheduler(
		scheduler.ManifestRescanConfig{Timeout: 5 * time.Minute}, db, nil, nil)
	s.RunOnce(context.Background())

	out := buf.String()
	assert.Contains(t, out, `"grace":"15m0s"`)
	assert.Contains(t, out, `"stuck":true`)
	assert.Contains(t, out, `"level":"warn"`)
}
