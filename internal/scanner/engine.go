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

// HealthCheck runs HealthCheck on all registered scanners and returns a map of
// scanner name to error (nil means healthy).
func (e *Engine) HealthCheck(ctx context.Context) map[string]error {
	status := make(map[string]error)
	for _, s := range e.scanners {
		status[s.Name()] = s.HealthCheck(ctx)
	}
	return status
}
