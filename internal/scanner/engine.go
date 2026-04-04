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

// ScanAsync dispatches an asynchronous scan using the given AsyncScanner.
// The callback is invoked when the scan completes; it should evaluate policy
// and quarantine the artifact if needed. This method returns immediately.
func (e *Engine) ScanAsync(ctx context.Context, artifact Artifact, localPath string, asyncScanner AsyncScanner, callback func(ScanResult)) {
	asyncScanner.ScanAsync(ctx, artifact, localPath, callback)
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
