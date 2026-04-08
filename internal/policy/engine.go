package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// EngineConfig configures the policy engine thresholds and allowlist.
type EngineConfig struct {
	Mode                        PolicyMode
	BlockIfVerdict              scanner.Verdict
	QuarantineIfVerdict         scanner.Verdict
	MinimumConfidence           float32
	BehavioralMinimumConfidence float32
	Allowlist                   []string
	AITriage                    config.AITriageConfig
}

// TriageClient is the interface for AI triage calls (Phase 3).
type TriageClient interface {
	Triage(ctx context.Context, req TriageRequest) (TriageResponse, error)
}

// TriageRequest holds the input for an AI triage call.
type TriageRequest struct {
	Ecosystem string
	Name      string
	Version   string
	Findings  []TaggedFinding
}

// TriageResponse holds the AI triage decision.
type TriageResponse struct {
	Decision   string  // "ALLOW" or "QUARANTINE"
	Confidence float32
	Explanation string
	ModelUsed  string
	TokensUsed int
	CacheHit   bool
}

// TriageCacheStore is the interface for triage decision caching (Phase 3).
type TriageCacheStore interface {
	Get(key string) (*TriageResponse, error)
	Set(key string, resp TriageResponse, ttl time.Duration) error
}

// Engine evaluates scan results against policy rules and returns a PolicyResult.
type Engine struct {
	mu             sync.RWMutex
	cfg            EngineConfig
	allowlist      []AllowlistEntry
	db             *config.GateDB
	triageClient   TriageClient
	triageCache    TriageCacheStore
	circuitBreaker *CircuitBreaker
	rateLimiter    *TriageRateLimiter
	cacheTTL       time.Duration
}

// NewEngine creates a new Engine with the supplied configuration.
// db may be nil — in that case only static allowlist is used.
// triageClient and triageCache may be nil — triage features degrade gracefully.
func NewEngine(cfg EngineConfig, db *config.GateDB, opts ...EngineOption) *Engine {
	var parsed []AllowlistEntry
	for _, raw := range cfg.Allowlist {
		entry, err := ParseAllowlistEntry(raw)
		if err == nil {
			parsed = append(parsed, entry)
		}
	}
	e := &Engine{cfg: cfg, allowlist: parsed, db: db}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// EngineOption configures optional Engine dependencies.
type EngineOption func(*Engine)

// WithTriageClient sets the AI triage client on the engine.
func WithTriageClient(tc TriageClient) EngineOption {
	return func(e *Engine) { e.triageClient = tc }
}

// WithTriageCache sets the triage cache store on the engine.
func WithTriageCache(cs TriageCacheStore) EngineOption {
	return func(e *Engine) { e.triageCache = cs }
}

// WithCircuitBreaker sets the circuit breaker on the engine.
func WithCircuitBreaker(cb *CircuitBreaker) EngineOption {
	return func(e *Engine) { e.circuitBreaker = cb }
}

// WithRateLimiter sets the rate limiter on the engine.
func WithRateLimiter(rl *TriageRateLimiter) EngineOption {
	return func(e *Engine) { e.rateLimiter = rl }
}

// Mode returns the current policy evaluation mode.
func (e *Engine) Mode() PolicyMode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Mode
}

// SetMode changes the policy evaluation mode at runtime.
func (e *Engine) SetMode(m PolicyMode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Mode = m
}

// WithCacheTTL sets the triage cache TTL.
func WithCacheTTL(ttl time.Duration) EngineOption {
	return func(e *Engine) { e.cacheTTL = ttl }
}

// hasDBOverride checks if there is an active, non-revoked, non-expired override
// in the database for the given artifact.
func (e *Engine) hasDBOverride(ctx context.Context, artifact scanner.Artifact) bool {
	if e.db == nil {
		return false
	}

	// Use a fresh context — the HTTP request context may already be canceled
	// by the time policy evaluation runs (e.g. client disconnected during scan).
	// Override checks must succeed regardless of client state.
	dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().UTC()
	var count int
	err := e.db.QueryRowContext(dbCtx,
		`SELECT COUNT(*) FROM policy_overrides
		 WHERE ecosystem = ? AND name = ? AND revoked = FALSE
		   AND (expires_at IS NULL OR expires_at > ?)
		   AND (scope = 'package' OR (scope = 'version' AND version = ?))`,
		string(artifact.Ecosystem), artifact.Name, now, artifact.Version,
	).Scan(&count)
	if err != nil {
		log.Error().Err(err).
			Str("ecosystem", string(artifact.Ecosystem)).
			Str("name", artifact.Name).
			Str("version", artifact.Version).
			Msg("hasDBOverride: query error")
		return false
	}
	return count > 0
}

// Evaluate applies the policy to the given artifact and scan results.
// DB overrides are checked first, then static allowlist, then verdict rules.
func (e *Engine) Evaluate(ctx context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) PolicyResult {
	// DB override check — highest priority.
	if e.hasDBOverride(ctx, artifact) {
		return PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("policy override: %s:%s:%s", artifact.Ecosystem, artifact.Name, artifact.Version),
		}
	}

	// Static allowlist check.
	if isAllowlisted(artifact, e.allowlist) {
		return PolicyResult{
			Action: ActionAllow,
			Reason: "artifact is in allowlist",
		}
	}

	aggCfg := AggregationConfig{
		MinConfidence:           e.cfg.MinimumConfidence,
		BehavioralMinConfidence: e.cfg.BehavioralMinimumConfidence,
	}
	agg := Aggregate(scanResults, aggCfg)

	switch {
	case agg.Verdict == scanner.VerdictMalicious:
		return PolicyResult{
			Action: ActionBlock,
			Reason: fmt.Sprintf("verdict %s meets block threshold", agg.Verdict),
		}
	case agg.Verdict == scanner.VerdictSuspicious:
		return e.evaluateSuspicious(ctx, artifact, &agg)
	default:
		return PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("verdict %s is below action thresholds", agg.Verdict),
		}
	}
}

// evaluateSuspicious handles SUSPICIOUS verdicts based on the configured policy mode.
func (e *Engine) evaluateSuspicious(ctx context.Context, artifact scanner.Artifact, agg *AggregatedResult) PolicyResult {
	maxSev := agg.MaxEffectiveSeverity()
	suspFindings := agg.SuspiciousFindings()

	// SUSPICIOUS without findings is an anomaly — always quarantine.
	if len(suspFindings) == 0 {
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: "suspicious verdict with no findings — anomaly",
		}
	}

	switch e.Mode() {
	case PolicyModeStrict:
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("strict mode: verdict SUSPICIOUS (effective severity %s)", maxSev),
		}

	case PolicyModeBalanced:
		if SeverityAtLeastHigh(maxSev) {
			return PolicyResult{
				Action: ActionQuarantine,
				Reason: fmt.Sprintf("balanced mode: effective severity %s >= HIGH", maxSev),
			}
		}
		// MEDIUM severity in balanced mode → AI triage (Phase 3) or degraded fallback.
		if !e.cfg.AITriage.Enabled || e.triageClient == nil {
			// Degraded balanced mode: no AI triage available → quarantine.
			return PolicyResult{
				Action: ActionQuarantine,
				Reason: fmt.Sprintf("balanced mode (degraded): effective severity %s, AI triage disabled", maxSev),
			}
		}
		// Phase 3 will add: cache lookup → AI triage call → result handling.
		// For now, placeholder that will be replaced in Phase 3.
		return e.triageSuspicious(ctx, artifact, agg, maxSev)

	case PolicyModePermissive:
		if SeverityAtLeastHigh(maxSev) {
			return PolicyResult{
				Action: ActionQuarantine,
				Reason: fmt.Sprintf("permissive mode: effective severity %s >= HIGH", maxSev),
			}
		}
		return PolicyResult{
			Action: ActionAllowWithWarning,
			Reason: fmt.Sprintf("permissive mode: effective severity %s allowed with warning", maxSev),
		}

	default:
		// Unknown mode — safe fallback to strict behavior.
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("unknown mode: verdict SUSPICIOUS, falling back to quarantine"),
		}
	}
}

// triageSuspicious handles AI triage for balanced mode MEDIUM severity findings.
func (e *Engine) triageSuspicious(ctx context.Context, artifact scanner.Artifact, agg *AggregatedResult, maxSev scanner.Severity) PolicyResult {
	cacheTTL := e.cacheTTL
	if cacheTTL == 0 {
		cacheTTL = 168 * time.Hour // default 7 days
	}

	return EvaluateWithTriage(
		ctx, artifact, agg, maxSev,
		e.triageClient, e.triageCache,
		e.circuitBreaker, e.rateLimiter,
		e.cfg.AITriage.MinConfidence, cacheTTL,
	)
}
