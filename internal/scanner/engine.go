package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Engine orchestrates multiple scanners in parallel with timeout, bounded
// retry, and per-scanner circuit breaking. Scanner failures are reported
// explicitly in ScanReport so that required-scanner outages can fail closed at
// the policy layer instead of silently degrading to a clean verdict.
// MaxConcurrentScans limits how many artifacts can be scanned simultaneously to
// avoid overwhelming the scanner bridge with too many concurrent gRPC calls.
type Engine struct {
	scanners []Scanner
	timeout  time.Duration
	sem      *semaphore.Weighted

	retryMaxAttempts int
	retryBackoff     time.Duration
	criticality      map[string]Criticality
	breakers         map[string]*scanCircuit
}

// EngineOption customizes an Engine at construction time.
type EngineOption func(*Engine)

// WithRetry sets the bounded retry budget for retryable scanner errors.
func WithRetry(maxAttempts int, backoff time.Duration) EngineOption {
	return func(e *Engine) {
		if maxAttempts > 0 {
			e.retryMaxAttempts = maxAttempts
		}
		if backoff > 0 {
			e.retryBackoff = backoff
		}
	}
}

// WithCriticality declares which scanners are required vs best-effort, keyed by
// scanner Name(). Required scanners cannot be excluded from a scan.
func WithCriticality(criticality map[string]Criticality) EngineOption {
	return func(e *Engine) {
		e.criticality = make(map[string]Criticality, len(criticality))
		for name, value := range criticality {
			e.criticality[name] = value
		}
	}
}

// NewEngine creates a new Engine with the given scanners and per-scan timeout.
// maxConcurrentScans limits how many ScanAll calls can run in parallel (0 = unlimited).
func NewEngine(scanners []Scanner, timeout time.Duration, maxConcurrentScans int64, opts ...EngineOption) *Engine {
	var sem *semaphore.Weighted
	if maxConcurrentScans > 0 {
		sem = semaphore.NewWeighted(maxConcurrentScans)
	}
	e := &Engine{
		scanners:         scanners,
		timeout:          timeout,
		sem:              sem,
		retryMaxAttempts: 1,
		retryBackoff:     200 * time.Millisecond,
		criticality:      map[string]Criticality{},
		breakers:         map[string]*scanCircuit{},
	}
	for _, opt := range opts {
		opt(e)
	}
	for _, sc := range scanners {
		e.breakers[sc.Name()] = newScanCircuit(5, time.Minute)
	}
	return e
}

// RegisteredScannerNames returns the names of all registered scanners.
func (e *Engine) RegisteredScannerNames() []string {
	names := make([]string, 0, len(e.scanners))
	for _, s := range e.scanners {
		names = append(names, s.Name())
	}
	return names
}

func (e *Engine) criticalityFor(name string) Criticality {
	if e.criticality[name] == CriticalityRequired {
		return CriticalityRequired
	}
	return CriticalityBestEffort
}

// ScanAll runs all scanners that support the artifact's ecosystem in parallel
// and returns a ScanReport describing scan completeness. Retryable errors are
// retried per the engine's retry budget; failures are recorded in
// report.Errored rather than degraded to a clean verdict. Optional excludeNames
// skips best-effort scanners (recorded in report.Skipped); required scanners
// cannot be excluded.
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact, excludeNames ...string) (ScanReport, error) {
	excludeSet := make(map[string]struct{}, len(excludeNames))
	for _, n := range excludeNames {
		excludeSet[n] = struct{}{}
	}

	var applicable []Scanner
	report := ScanReport{Errored: map[string]*ScanError{}}
	for _, s := range e.scanners {
		supports := false
		for _, eco := range s.SupportedEcosystems() {
			if eco == artifact.Ecosystem {
				supports = true
				break
			}
		}
		if !supports {
			continue
		}
		if _, excluded := excludeSet[s.Name()]; excluded && e.criticalityFor(s.Name()) != CriticalityRequired {
			report.Skipped = append(report.Skipped, s.Name())
			continue
		}
		applicable = append(applicable, s)
		report.Expected = append(report.Expected, s.Name())
	}

	if len(applicable) == 0 {
		if len(artifact.ExtraLicenses) > 0 {
			report.Results = append(report.Results, ScanResult{
				Verdict:   VerdictClean,
				ScannerID: "extra-licenses",
				ScannedAt: time.Now(),
				Licenses:  artifact.ExtraLicenses,
			})
		}
		return report, nil
	}

	// Limit concurrent artifact scans to avoid overwhelming the scanner bridge.
	if e.sem != nil {
		if err := e.sem.Acquire(ctx, 1); err != nil {
			scanErr := ClassifyScanError(err)
			for _, sc := range applicable {
				report.Errored[sc.Name()] = scanErr
				scannerErrorsTotal.WithLabelValues(sc.Name(), scanErr.Kind.String()).Inc()
			}
			return report, err
		}
		defer e.sem.Release(1)
	}

	scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range applicable {
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			result, scanErr := e.scanOne(scanCtx, sc, artifact)
			mu.Lock()
			defer mu.Unlock()
			if scanErr != nil {
				report.Errored[sc.Name()] = scanErr
				scannerErrorsTotal.WithLabelValues(sc.Name(), scanErr.Kind.String()).Inc()
				return
			}
			report.Results = append(report.Results, result)
		}(s)
	}
	wg.Wait()

	// Merge ExtraLicenses provided by the adapter (e.g. Maven effective-POM
	// parent chain resolution). These licenses are discovered outside the
	// normal scanner path and need to be injected into results so the policy
	// engine can evaluate them. Adapters must pre-normalize ExtraLicenses
	// via sbom.NameAliasToID before setting them on the artifact.
	if len(artifact.ExtraLicenses) > 0 {
		report.Results = append(report.Results, ScanResult{
			Verdict:   VerdictClean,
			ScannerID: "extra-licenses",
			ScannedAt: time.Now(),
			Licenses:  artifact.ExtraLicenses,
		})
	}

	return report, nil
}

// scanOne runs a single scanner with circuit-breaker gating and bounded retry
// of retryable errors. It returns either a successful result or a classified
// *ScanError.
func (e *Engine) scanOne(ctx context.Context, sc Scanner, artifact Artifact) (ScanResult, *ScanError) {
	breaker := e.breakers[sc.Name()]
	if breaker != nil && breaker.isOpen() {
		circuitBreakerState.WithLabelValues(sc.Name()).Set(1)
		return ScanResult{}, NewScanError(ErrKindOverload, fmt.Errorf("%s scanner circuit open", sc.Name()))
	}
	circuitBreakerState.WithLabelValues(sc.Name()).Set(0)

	attempts := e.retryMaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	backoff := e.retryBackoff
	if backoff <= 0 {
		backoff = 200 * time.Millisecond
	}

	var lastErr *ScanError
	for attempt := 1; attempt <= attempts; attempt++ {
		start := time.Now()
		result, err := sc.Scan(ctx, artifact)
		if err == nil && result.Error != nil {
			err = result.Error
		}
		if err == nil {
			if result.ScannerID == "" {
				result.ScannerID = sc.Name()
			}
			if result.ScannerVersion == "" {
				result.ScannerVersion = sc.Version()
			}
			result.Duration = time.Since(start)
			result.ScannedAt = start
			if breaker != nil {
				breaker.recordSuccess()
			}
			return result, nil
		}

		lastErr = ClassifyScanError(err)
		if !lastErr.Retryable() || attempt == attempts {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			lastErr = ClassifyScanError(ctx.Err())
			attempt = attempts
		case <-timer.C:
		}
		backoff *= 2
	}

	if breaker != nil {
		breaker.recordFailure()
	}
	return ScanResult{}, lastErr
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
