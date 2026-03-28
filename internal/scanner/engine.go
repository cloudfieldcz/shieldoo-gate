package scanner

import (
	"context"
	"sync"
	"time"
)

// Engine orchestrates multiple scanners in parallel with timeout and fail-open semantics.
type Engine struct {
	scanners []Scanner
	timeout  time.Duration
}

// NewEngine creates a new Engine with the given scanners and per-scan timeout.
func NewEngine(scanners []Scanner, timeout time.Duration) *Engine {
	return &Engine{
		scanners: scanners,
		timeout:  timeout,
	}
}

// ScanAll runs all scanners that support the artifact's ecosystem in parallel.
// It applies a per-scan timeout and uses fail-open semantics: scanner errors or
// timeouts result in VerdictClean with the error recorded, never VerdictMalicious.
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact) ([]ScanResult, error) {
	var applicable []Scanner
	for _, s := range e.scanners {
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
