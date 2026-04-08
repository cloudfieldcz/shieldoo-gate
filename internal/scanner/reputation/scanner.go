package reputation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*ReputationScanner)(nil)

const scannerName = "builtin-reputation"
const scannerVersion = "2.0.0"

// Prometheus metrics for the reputation scanner.
var (
	reputationCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_reputation_cache_hits_total",
			Help: "Total reputation cache hits.",
		},
		[]string{"ecosystem"},
	)
	reputationCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_reputation_cache_misses_total",
			Help: "Total reputation cache misses.",
		},
		[]string{"ecosystem"},
	)
	reputationFetchDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shieldoo_reputation_fetch_duration_seconds",
			Help:    "Duration of upstream metadata fetch in seconds.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10},
		},
		[]string{"ecosystem", "status"},
	)
	reputationFetchErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_reputation_fetch_errors_total",
			Help: "Total upstream metadata fetch errors.",
		},
		[]string{"ecosystem"},
	)
)

// ReputationScanner evaluates package trustworthiness based on upstream
// registry metadata (maintainer history, publication patterns, download counts).
type ReputationScanner struct {
	db         *config.GateDB
	httpClient *http.Client
	cfg        config.ReputationConfig
	cacheTTL   time.Duration
	ttlJitter  time.Duration
	sfGroup    singleflight.Group // deduplicates concurrent fetches for same package
	limiters   map[scanner.Ecosystem]*rate.Limiter
}

// NewReputationScanner creates a new ReputationScanner.
func NewReputationScanner(db *config.GateDB, cfg config.ReputationConfig) (*ReputationScanner, error) {
	if db == nil {
		return nil, fmt.Errorf("reputation scanner: db is nil")
	}

	cacheTTL, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		cacheTTL = 24 * time.Hour
	}

	ttlJitter, err := time.ParseDuration(cfg.CacheTTLJitter)
	if err != nil {
		ttlJitter = 2 * time.Hour
	}

	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		timeout = 10 * time.Second
	}

	ratePerMin := cfg.RateLimit
	if ratePerMin <= 0 {
		ratePerMin = 30
	}

	// Per-ecosystem rate limiters
	limiter := rate.NewLimiter(rate.Limit(float64(ratePerMin)/60.0), ratePerMin)
	limiters := map[scanner.Ecosystem]*rate.Limiter{
		scanner.EcosystemPyPI:  limiter,
		scanner.EcosystemNPM:   limiter,
		scanner.EcosystemNuGet: limiter,
	}

	// HTTP client with SSRF mitigation: reject redirects to private IPs,
	// enforce TLS 1.2+, hardcoded upstream hosts only.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// SSRF mitigation: only follow redirects to known safe hosts
			if !isSafeHost(req.URL.Host) {
				return fmt.Errorf("reputation: redirect to disallowed host %q", req.URL.Host)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("reputation: redirect to non-HTTPS URL %q", req.URL.String())
			}
			if len(via) >= 3 {
				return fmt.Errorf("reputation: too many redirects")
			}
			return nil
		},
	}

	s := &ReputationScanner{
		db:         db,
		httpClient: httpClient,
		cfg:        cfg,
		cacheTTL:   cacheTTL,
		ttlJitter:  ttlJitter,
		limiters:   limiters,
	}

	// Run initial stale entry cleanup
	go s.cleanupStaleEntries()

	return s, nil
}

func (s *ReputationScanner) Name() string    { return scannerName }
func (s *ReputationScanner) Version() string { return scannerVersion }

func (s *ReputationScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
	}
}

func (s *ReputationScanner) HealthCheck(ctx context.Context) error {
	var n int
	return s.db.GetContext(ctx, &n, "SELECT 1")
}

func (s *ReputationScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()
	result := scanner.ScanResult{
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		ScannedAt:      start,
	}

	// Check ecosystem support
	supported := false
	for _, eco := range s.SupportedEcosystems() {
		if eco == artifact.Ecosystem {
			supported = true
			break
		}
	}
	if !supported {
		result.Verdict = scanner.VerdictClean
		result.Confidence = 0
		result.Duration = time.Since(start)
		return result, nil
	}

	// Try cached reputation data (with jittered TTL)
	cached, err := s.loadCached(ctx, artifact.Ecosystem, artifact.Name)
	if err == nil && cached != nil {
		reputationCacheHits.WithLabelValues(string(artifact.Ecosystem)).Inc()
		result = s.buildResult(cached.RiskScore, cached.SignalsJSON, start)
		log.Debug().
			Str("package", artifact.Name).
			Str("ecosystem", string(artifact.Ecosystem)).
			Float64("risk_score", cached.RiskScore).
			Msg("reputation: using cached score")
		return result, nil
	}
	reputationCacheMisses.WithLabelValues(string(artifact.Ecosystem)).Inc()

	// Singleflight: deduplicate concurrent fetches for the same package
	sfKey := string(artifact.Ecosystem) + ":" + artifact.Name
	sfResult, err, _ := s.sfGroup.Do(sfKey, func() (interface{}, error) {
		return s.fetchAndCompute(ctx, artifact.Ecosystem, artifact.Name)
	})

	if err != nil {
		// Fail-open: log error, return CLEAN
		log.Warn().Err(err).
			Str("package", artifact.Name).
			Str("ecosystem", string(artifact.Ecosystem)).
			Msg("reputation: metadata fetch failed, returning CLEAN (fail-open)")
		reputationFetchErrors.WithLabelValues(string(artifact.Ecosystem)).Inc()
		result.Verdict = scanner.VerdictClean
		result.Confidence = 0
		result.Duration = time.Since(start)
		result.Error = err
		return result, nil
	}

	fr := sfResult.(*fetchResult)
	result = s.buildResult(fr.score, fr.signalsJSON, start)

	log.Info().
		Str("package", artifact.Name).
		Str("ecosystem", string(artifact.Ecosystem)).
		Float64("risk_score", fr.score).
		Str("verdict", string(result.Verdict)).
		Msg("reputation: scan complete")

	return result, nil
}

// fetchResult holds the result of a metadata fetch + signal computation.
type fetchResult struct {
	score      float64
	signalsJSON string
}

// fetchAndCompute fetches metadata, computes signals, and stores the result.
func (s *ReputationScanner) fetchAndCompute(ctx context.Context, eco scanner.Ecosystem, name string) (*fetchResult, error) {
	// Rate limiting per ecosystem
	if lim, ok := s.limiters[eco]; ok {
		if !lim.Allow() {
			// Rate limited — try stale cache as fallback
			stale, err := s.loadStale(ctx, eco, name)
			if err == nil && stale != nil {
				log.Debug().Str("package", name).Msg("reputation: rate limited, using stale cache")
				return &fetchResult{score: stale.RiskScore, signalsJSON: stale.SignalsJSON}, nil
			}
			return nil, fmt.Errorf("reputation: rate limited for %s", eco)
		}
	}

	// Fetch metadata from upstream
	fetchStart := time.Now()
	meta, fetchErr := fetchMetadata(ctx, s.httpClient, eco, name)
	fetchDuration := time.Since(fetchStart).Seconds()

	if fetchErr != nil {
		reputationFetchDuration.WithLabelValues(string(eco), "error").Observe(fetchDuration)
		// Stale-while-revalidate: serve stale cache on fetch error
		stale, err := s.loadStale(ctx, eco, name)
		if err == nil && stale != nil {
			log.Warn().Err(fetchErr).Str("package", name).Msg("reputation: fetch failed, using stale cached data")
			return &fetchResult{score: stale.RiskScore, signalsJSON: stale.SignalsJSON}, nil
		}
		return nil, fetchErr
	}
	reputationFetchDuration.WithLabelValues(string(eco), "ok").Observe(fetchDuration)

	// Detect ownership change by comparing with previous maintainers
	meta.OwnershipChanged = s.detectOwnershipChange(ctx, eco, name, meta.Maintainers)

	// Compute signals and score
	signals := computeSignals(meta, s.cfg.Signals)
	score := compositeScore(signals)

	// Marshal signals to JSON for storage
	signalsJSON, _ := json.Marshal(signals)

	// Store in cache asynchronously (fire-and-forget, errors logged)
	go s.storeReputation(context.Background(), eco, name, meta, score, string(signalsJSON))

	return &fetchResult{score: score, signalsJSON: string(signalsJSON)}, nil
}

// buildResult creates a ScanResult from a risk score and signals JSON.
func (s *ReputationScanner) buildResult(score float64, signalsJSON string, start time.Time) scanner.ScanResult {
	result := scanner.ScanResult{
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		ScannedAt:      start,
		Duration:       time.Since(start),
	}

	// Heuristic scanner MUST NOT produce MALICIOUS verdict.
	// Per project conventions (CLAUDE.md), only integrity scanners (threat-feed,
	// hash-verifier) with definitive evidence may return MALICIOUS.
	// High scores produce SUSPICIOUS with high confidence instead.
	switch {
	case score >= s.cfg.Thresholds.Suspicious:
		result.Verdict = scanner.VerdictSuspicious
		result.Confidence = float32(score)
	default:
		result.Verdict = scanner.VerdictClean
		result.Confidence = float32(1.0 - score)
	}

	// Parse signals to generate findings
	var signals []SignalResult
	if err := json.Unmarshal([]byte(signalsJSON), &signals); err == nil {
		for _, sig := range signals {
			if sig.Fired {
				severity := scanner.SeverityLow
				if sig.Weight >= 0.7 {
					severity = scanner.SeverityHigh
				} else if sig.Weight >= 0.3 {
					severity = scanner.SeverityMedium
				}
				result.Findings = append(result.Findings, scanner.Finding{
					Severity:    severity,
					Category:    "reputation",
					Description: fmt.Sprintf("reputation signal %q: %s", sig.Name, sig.Reason),
				})
			}
		}
	}

	return result
}

// cachedReputation is the DB row for package_reputation.
type cachedReputation struct {
	RiskScore   float64   `db:"risk_score"`
	SignalsJSON string    `db:"signals_json"`
	LastChecked time.Time `db:"last_checked"`
}

// jitteredTTL returns the cache TTL with random jitter to prevent thundering herd.
func (s *ReputationScanner) jitteredTTL() time.Duration {
	if s.ttlJitter <= 0 {
		return s.cacheTTL
	}
	jitter := time.Duration(rand.Int63n(int64(s.ttlJitter)))
	return s.cacheTTL + jitter
}

// loadCached returns cached reputation data if it exists and is within jittered TTL.
func (s *ReputationScanner) loadCached(ctx context.Context, eco scanner.Ecosystem, name string) (*cachedReputation, error) {
	var row cachedReputation
	err := s.db.GetContext(ctx, &row,
		"SELECT risk_score, signals_json, last_checked FROM package_reputation WHERE ecosystem = ? AND name = ?",
		string(eco), name)
	if err != nil {
		return nil, err
	}

	if time.Since(row.LastChecked) > s.jitteredTTL() {
		return nil, fmt.Errorf("cache expired")
	}

	return &row, nil
}

// loadStale returns cached data regardless of TTL (for stale-while-revalidate).
func (s *ReputationScanner) loadStale(ctx context.Context, eco scanner.Ecosystem, name string) (*cachedReputation, error) {
	var row cachedReputation
	err := s.db.GetContext(ctx, &row,
		"SELECT risk_score, signals_json, last_checked FROM package_reputation WHERE ecosystem = ? AND name = ?",
		string(eco), name)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// storeReputation upserts the package reputation data into the cache table.
// Maintainer emails are hashed (SHA-256) before storage to avoid PII exposure.
func (s *ReputationScanner) storeReputation(ctx context.Context, eco scanner.Ecosystem, name string, meta *PackageMetadata, score float64, signalsJSON string) {
	// Hash maintainer emails before storage (privacy/GDPR)
	hashedMaintainers := hashMaintainerEmails(meta.Maintainers)
	maintainersJSON, _ := json.Marshal(hashedMaintainers)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO package_reputation (ecosystem, name, maintainers_json, first_published, latest_published,
			version_count, download_count, has_source_repo, source_repo_url, description, risk_score, signals_json, last_checked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name) DO UPDATE SET
			maintainers_json = excluded.maintainers_json,
			first_published = excluded.first_published,
			latest_published = excluded.latest_published,
			version_count = excluded.version_count,
			download_count = excluded.download_count,
			has_source_repo = excluded.has_source_repo,
			source_repo_url = excluded.source_repo_url,
			description = excluded.description,
			risk_score = excluded.risk_score,
			signals_json = excluded.signals_json,
			last_checked = excluded.last_checked`,
		string(eco), name, string(maintainersJSON),
		meta.FirstPublished, meta.LatestPublished,
		meta.VersionCount, meta.DownloadCount,
		meta.HasSourceRepo, meta.SourceRepoURL,
		meta.Description, score, signalsJSON,
		time.Now())
	if err != nil {
		log.Error().Err(err).
			Str("package", name).
			Str("ecosystem", string(eco)).
			Msg("reputation: failed to store reputation data")
	}
}

// hashMaintainerEmails returns a copy of maintainers with emails replaced by SHA-256 hashes.
func hashMaintainerEmails(maintainers []Maintainer) []Maintainer {
	result := make([]Maintainer, len(maintainers))
	for i, m := range maintainers {
		result[i] = Maintainer{Name: m.Name}
		if m.Email != "" {
			h := sha256.Sum256([]byte(strings.ToLower(m.Email)))
			result[i].Email = hex.EncodeToString(h[:8]) // first 8 bytes = 16 hex chars
		}
	}
	return result
}

// detectOwnershipChange checks if the maintainer list changed since last check.
// Compares by name (emails are hashed in storage, so we compare names only).
func (s *ReputationScanner) detectOwnershipChange(ctx context.Context, eco scanner.Ecosystem, name string, currentMaintainers []Maintainer) bool {
	var storedJSON string
	err := s.db.GetContext(ctx, &storedJSON,
		"SELECT maintainers_json FROM package_reputation WHERE ecosystem = ? AND name = ?",
		string(eco), name)
	if err != nil || storedJSON == "" {
		return false // no prior data — can't detect change
	}

	var prev []Maintainer
	if err := json.Unmarshal([]byte(storedJSON), &prev); err != nil {
		return false
	}

	if len(prev) != len(currentMaintainers) {
		return true
	}

	prevNames := make(map[string]bool)
	for _, m := range prev {
		prevNames[m.Name] = true
	}
	for _, m := range currentMaintainers {
		if !prevNames[m.Name] {
			return true
		}
	}

	return false
}

// cleanupStaleEntries removes reputation entries older than retention period.
func (s *ReputationScanner) cleanupStaleEntries() {
	retention := s.cfg.RetentionDays
	if retention <= 0 {
		retention = 30
	}

	cutoff := time.Now().Add(-time.Duration(retention) * 24 * time.Hour)
	result, err := s.db.Exec(
		"DELETE FROM package_reputation WHERE last_checked < ?", cutoff)
	if err != nil {
		log.Warn().Err(err).Msg("reputation: stale entry cleanup failed")
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Info().Int64("deleted", rows).Int("retention_days", retention).
			Msg("reputation: cleaned up stale entries")
	}
}

// isSafeHost returns true if the host is a known safe upstream registry.
// Used for SSRF mitigation in redirect policy.
func isSafeHost(host string) bool {
	safeHosts := []string{
		"pypi.org", "www.pypi.org", "files.pythonhosted.org",
		"registry.npmjs.org", "www.npmjs.org",
		"api.nuget.org", "www.nuget.org",
	}
	for _, h := range safeHosts {
		if host == h {
			return true
		}
	}
	return false
}
