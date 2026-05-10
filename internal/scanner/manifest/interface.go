// Package manifest is the SBOM-oriented scanner pipeline used by the vulnerability-scan
// feature. Unlike the per-artifact `internal/scanner.Scanner` interface, ManifestScanner
// takes an entire CycloneDX SBOM and returns a list of findings.
package manifest

import (
	"context"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Manifest is the input to a ManifestScanner.
type Manifest struct {
	SBOMPath       string // local path to the CycloneDX SBOM JSON
	SBOMBytes      []byte // optional in-memory copy
	Ecosystem      string // primary ecosystem hint (or "multi")
	ComponentCount int
}

// Finding is a single (CVE, package, version) record produced by a manifest scanner.
type Finding struct {
	CVEID          string
	PackageName    string
	PackageVersion string
	Ecosystem      string
	Severity       scanner.Severity
	CVSSScore      float64
	FixedVersion   string
	Summary        string
	URL            string // upstream advisory URL
}

// ScanOutcome aggregates one scanner's contribution to a manifest scan.
type ScanOutcome struct {
	ScannerID      string
	ScannerVersion string
	Findings       []Finding
	Status         string // "ok" / "timeout" / "error"
	Error          error
	Duration       time.Duration
}

// ManifestScanner is the contract implemented by per-tool integrations.
type ManifestScanner interface {
	Name() string
	Version() string
	Scan(ctx context.Context, m Manifest) (ScanOutcome, error)
	HealthCheck(ctx context.Context) error
}

// Engine orchestrates parallel ManifestScanner invocations under a shared timeout.
type Engine struct {
	scanners []ManifestScanner
	timeout  time.Duration
}

// NewEngine constructs an Engine with the supplied scanners and per-scan timeout.
func NewEngine(scanners []ManifestScanner, timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Engine{scanners: scanners, timeout: timeout}
}

// ScanAll runs all registered scanners in parallel and returns one outcome per scanner.
// Scanners that error are reported via ScanOutcome.Status="error" rather than aborting
// the pipeline (fail-open semantics).
func (e *Engine) ScanAll(ctx context.Context, m Manifest) []ScanOutcome {
	if len(e.scanners) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	results := make([]ScanOutcome, len(e.scanners))
	done := make(chan int, len(e.scanners))
	for i, sc := range e.scanners {
		go func(idx int, scn ManifestScanner) {
			start := time.Now()
			out, err := scn.Scan(ctx, m)
			out.ScannerID = scn.Name()
			out.ScannerVersion = scn.Version()
			if out.Duration == 0 {
				out.Duration = time.Since(start)
			}
			if err != nil {
				if out.Status == "" {
					out.Status = "error"
				}
				out.Error = err
			} else if out.Status == "" {
				out.Status = "ok"
			}
			results[idx] = out
			done <- idx
		}(i, sc)
	}
	for range e.scanners {
		<-done
	}
	return results
}
