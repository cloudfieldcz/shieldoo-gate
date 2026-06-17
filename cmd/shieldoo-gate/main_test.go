//go:build !e2e

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain_ConfigAndDBInit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "test.db")
	cachePath := filepath.Join(dir, "cache")

	err := os.WriteFile(cfgPath, []byte(`
server:
  host: "127.0.0.1"
ports:
  pypi: 15000
  npm: 14873
  nuget: 15001
  docker: 15002
  admin: 18080
cache:
  backend: "local"
  local:
    path: "`+cachePath+`"
    max_size_gb: 1
database:
  backend: "sqlite"
  sqlite:
    path: "`+dbPath+`"
scanners:
  parallel: true
  timeout: "10s"
log:
  level: "debug"
  format: "text"
`), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	db, err := config.InitDB(cfg.Database)
	require.NoError(t, err)
	defer db.Close()
}

type criticalityTestScanner struct{ name string }

func (n criticalityTestScanner) Name() string    { return n.name }
func (n criticalityTestScanner) Version() string  { return "test" }
func (n criticalityTestScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI}
}
func (n criticalityTestScanner) Scan(context.Context, scanner.Artifact) (scanner.ScanResult, error) {
	return scanner.ScanResult{ScannerID: n.name, Verdict: scanner.VerdictClean}, nil
}
func (n criticalityTestScanner) HealthCheck(context.Context) error { return nil }

func TestValidateScannerCriticality_UnknownBestEffortScannerIsTolerated(t *testing.T) {
	// A best_effort entry for a scanner that is not registered (e.g. an optional
	// scanner disabled in config, like the example config's ai-scanner/
	// version-diff entries) is a harmless no-op — unlisted already means
	// best-effort. Startup must not fail.
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "guarddog"}},
		map[string]scanner.Criticality{"ai-scanner": scanner.CriticalityBestEffort},
		policy.ScanErrorModeQuarantine,
	)

	require.NoError(t, err)
}

func TestValidateScannerCriticality_MissingRequiredScannerReturnsError(t *testing.T) {
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "builtin-threat-feed"}},
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired},
		policy.ScanErrorModeQuarantine,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "required scanner")
}

func TestValidateScannerCriticality_MissingRequiredScannerAllowedInFailOpen(t *testing.T) {
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "builtin-threat-feed"}},
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired},
		policy.ScanErrorModeFailOpen,
	)

	require.NoError(t, err)
}

func TestValidateScannerCriticality_NoRequiredScannerWarnsButSucceeds(t *testing.T) {
	// on_scan_error=quarantine but every registered scanner is best-effort:
	// fail-closed is inert. This is a misconfiguration we warn about, not a
	// fatal error — startup must still succeed.
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "guarddog"}},
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityBestEffort},
		policy.ScanErrorModeQuarantine,
	)

	require.NoError(t, err)
}

func TestHasRegisteredRequiredScanner(t *testing.T) {
	registered := map[string]struct{}{"guarddog": {}, "trivy": {}}

	// Required scanner present and registered.
	assert.True(t, hasRegisteredRequiredScanner(registered,
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}))

	// Required scanner configured but not registered → not satisfied.
	assert.False(t, hasRegisteredRequiredScanner(registered,
		map[string]scanner.Criticality{"osv": scanner.CriticalityRequired}))

	// Only best-effort entries → not satisfied.
	assert.False(t, hasRegisteredRequiredScanner(registered,
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityBestEffort}))

	// Empty criticality → not satisfied.
	assert.False(t, hasRegisteredRequiredScanner(registered,
		map[string]scanner.Criticality{}))
}
