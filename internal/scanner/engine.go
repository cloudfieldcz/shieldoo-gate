package scanner

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Engine orchestrates multiple scanners in parallel with timeout and fail-open semantics.
// MaxConcurrentScans limits how many artifacts can be scanned simultaneously to avoid
// overwhelming the scanner bridge with too many concurrent gRPC calls.
type Engine struct {
	scanners []Scanner
	timeout  time.Duration
	sem      *semaphore.Weighted
}

// NewEngine creates a new Engine with the given scanners and per-scan timeout.
// maxConcurrentScans limits how many ScanAll calls can run in parallel (0 = unlimited).
func NewEngine(scanners []Scanner, timeout time.Duration, maxConcurrentScans int64) *Engine {
	var sem *semaphore.Weighted
	if maxConcurrentScans > 0 {
		sem = semaphore.NewWeighted(maxConcurrentScans)
	}
	return &Engine{
		scanners: scanners,
		timeout:  timeout,
		sem:      sem,
	}
}

// ScanAll runs all scanners that support the artifact's ecosystem in parallel.
// It applies a per-scan timeout and uses fail-open semantics: scanner errors or
// timeouts result in VerdictClean with the error recorded, never VerdictMalicious.
// Optional excludeNames allows skipping specific scanners by name.
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact, excludeNames ...string) ([]ScanResult, error) {
	excludeSet := make(map[string]struct{}, len(excludeNames))
	for _, n := range excludeNames {
		excludeSet[n] = struct{}{}
	}

	var applicable []Scanner
	for _, s := range e.scanners {
		if _, excluded := excludeSet[s.Name()]; excluded {
			continue
		}
		for _, eco := range s.SupportedEcosystems() {
			if eco == artifact.Ecosystem {
				applicable = append(applicable, s)
				break
			}
		}
	}

	if len(applicable) == 0 {
		return nil, nil
	}

	// Limit concurrent artifact scans to avoid overwhelming the scanner bridge.
	if e.sem != nil {
		if err := e.sem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		defer e.sem.Release(1)
	}

	scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var mu sync.Mutex
	results := make([]ScanResult, 0, len(applicable))
	var wg sync.WaitGroup

	for _, s := range applicable {
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			start := time.Now()
			result, err := sc.Scan(scanCtx, artifact)
			if err != nil {
				result = ScanResult{
					Verdict:   VerdictClean,
					ScannerID: sc.Name(),
					Error:     err,
				}
			}
			result.Duration = time.Since(start)
			result.ScannedAt = start
			if result.ScannerID == "" {
				result.ScannerID = sc.Name()
			}
			if result.ScannerVersion == "" {
				result.ScannerVersion = sc.Version()
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(s)
	}

	wg.Wait()

	// Merge ExtraLicenses provided by the adapter (e.g. Maven effective-POM
	// parent chain resolution). These licenses are discovered outside the
	// normal scanner path and need to be injected into results so the policy
	// engine can evaluate them. Adapters must pre-normalize ExtraLicenses
	// via sbom.NameAliasToID before setting them on the artifact.
	if len(artifact.ExtraLicenses) > 0 {
		extraResult := ScanResult{
			Verdict:   VerdictClean,
			ScannerID: "extra-licenses",
			ScannedAt: time.Now(),
			Licenses:  artifact.ExtraLicenses,
		}
		results = append(results, extraResult)
	}

	return results, nil
}

// AsyncScanner is implemented by scanners that run outside the synchronous
// scan path (e.g., the gVisor sandbox scanner). They are invoked after the
// artifact has been served to the client.
type AsyncScanner interface {
	ScanAsync(ctx context.Context, artifact Artifact, localPath string, callback func(ScanResult))
	Name() string
	Close() error
}

// PreScanTyposquat runs only the builtin-typosquat scanner on a name-only
// artifact. This allows adapters to block typosquats before contacting
// upstream, avoiding 502s for non-existent packages and catching typosquats
// on metadata-only requests. Returns the ScanResult and true if the scanner
// was found, or a zero ScanResult and false if no typosquat scanner is
// registered.
func (e *Engine) PreScanTyposquat(ctx context.Context, name string, ecosystem Ecosystem) (ScanResult, bool) {
	for _, s := range e.scanners {
		if s.Name() != "builtin-typosquat" {
			continue
		}
		artifact := Artifact{
			Name:      name,
			Ecosystem: ecosystem,
		}
		result, err := s.Scan(ctx, artifact)
		if err != nil {
			return ScanResult{
				Verdict:   VerdictClean,
				ScannerID: s.Name(),
				Error:     err,
			}, true
		}
		return result, true
	}
	return ScanResult{}, false
}

// HealthCheck runs HealthCheck on all registered scanners in parallel and
// returns a map of scanner name to error (nil means healthy).
//
// Scanners run concurrently because each one may perform I/O (subprocess fork,
// HTTP request, gRPC call) that takes a non-trivial fraction of the caller's
// deadline. Running sequentially would let a slow scanner consume the budget
// of the ones that follow it, producing spurious DeadlineExceeded / SIGKILL
// errors even when every individual scanner is healthy.
func (e *Engine) HealthCheck(ctx context.Context) map[string]error {
	status := make(map[string]error, len(e.scanners))
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, s := range e.scanners {
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			err := sc.HealthCheck(ctx)
			mu.Lock()
			status[sc.Name()] = err
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return status
}
