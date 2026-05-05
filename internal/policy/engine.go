package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
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

	// license + SBOM integration (Phase 3). nil when disabled.
	licenseEval     license.Evaluator
	licenseResolver *license.Resolver
	sbomStore       sbom.Storage
	onSBOMError     license.Action // allow | warn | block
	licenseEnabled  bool
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

// WithLicenseEvaluator wires SPDX-based license policy evaluation.
// resolver provides the effective policy per project; sbomStore provides the
// pre-extracted license list for each artifact. Both are required — passing
// nil for either disables license enforcement entirely.
func WithLicenseEvaluator(eval license.Evaluator, resolver *license.Resolver, sbomStore sbom.Storage, onSBOMError license.Action) EngineOption {
	return func(e *Engine) {
		if eval == nil || resolver == nil || sbomStore == nil {
			return
		}
		e.licenseEval = eval
		e.licenseResolver = resolver
		e.sbomStore = sbomStore
		if onSBOMError == "" {
			onSBOMError = license.ActionAllow
		}
		e.onSBOMError = onSBOMError
		e.licenseEnabled = true
	}
}

// LicenseResolver exposes the wired resolver so callers (e.g. the admin API)
// can push runtime-mutable global-policy changes in without reaching into
// private fields. Returns nil when license enforcement is not enabled.
func (e *Engine) LicenseResolver() *license.Resolver {
	return e.licenseResolver
}

// OnSBOMError returns the configured behavior for artifacts that lack SBOM
// data. Thread-safe.
func (e *Engine) OnSBOMError() license.Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.onSBOMError
}

// SetOnSBOMError updates the on_sbom_error action at runtime. Thread-safe.
// Accepts the three license.Action values; any other value is ignored.
func (e *Engine) SetOnSBOMError(a license.Action) {
	switch a {
	case license.ActionAllow, license.ActionWarn, license.ActionBlock:
	default:
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onSBOMError = a
}

// Override kinds. An "allow" override lets a package through despite a block;
// a "deny" override blocks a package despite an allowance. Per-project deny
// always beats per-project allow which always beats global allow.
const (
	OverrideKindAllow = "allow"
	OverrideKindDeny  = "deny"
)

// lookupOverride resolves the most specific active override for the given
// (ecosystem, name, version) tuple in the request's project context. Returns
// the matching row's ID, its kind ("allow" or "deny"), and true on a hit.
//
// Resolution precedence:
//  1. Per-project DENY  (project_id = current, kind = 'deny')
//  2. Per-project ALLOW (project_id = current, kind = 'allow')
//  3. Global ALLOW       (project_id IS NULL, kind = 'allow')
//
// Within a tier the most recently created row wins. The project is read from
// ctx via project.FromContext — when no project is on context only the global
// tier is consulted (matches typosquat back-compat semantics).
//
// Pass version="" for name-only requests; only package-scoped overrides will
// match in that case.
func (e *Engine) lookupOverride(ctx context.Context, ecosystem scanner.Ecosystem, name, version string) (int64, string, bool) {
	if e == nil || e.db == nil {
		return 0, "", false
	}

	var projectID int64
	if proj := project.FromContext(ctx); proj != nil {
		projectID = proj.ID
	}

	// Detach from request context — the HTTP request context may already be
	// canceled by the time policy evaluation runs (e.g. client disconnected
	// during scan). Override checks must succeed regardless of client state.
	dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().UTC()

	if projectID > 0 {
		if id, ok := e.queryOverride(dbCtx, ecosystem, name, version, OverrideKindDeny, &projectID, now); ok {
			return id, OverrideKindDeny, true
		}
		if id, ok := e.queryOverride(dbCtx, ecosystem, name, version, OverrideKindAllow, &projectID, now); ok {
			return id, OverrideKindAllow, true
		}
	}
	if id, ok := e.queryOverride(dbCtx, ecosystem, name, version, OverrideKindAllow, nil, now); ok {
		return id, OverrideKindAllow, true
	}
	return 0, "", false
}

// queryOverride runs one tier of the precedence ladder. projectID == nil means
// "global rows only" (project_id IS NULL); a non-nil pointer means rows scoped
// to that project.
func (e *Engine) queryOverride(ctx context.Context, ecosystem scanner.Ecosystem, name, version, kind string, projectID *int64, now time.Time) (int64, bool) {
	var (
		id  int64
		err error
	)
	if projectID == nil {
		err = e.db.QueryRowContext(ctx,
			`SELECT id FROM policy_overrides
			 WHERE ecosystem = ? AND name = ? AND revoked = FALSE
			   AND kind = ? AND project_id IS NULL
			   AND (expires_at IS NULL OR expires_at > ?)
			   AND (scope = 'package' OR (scope = 'version' AND version = ?))
			 ORDER BY created_at DESC, id DESC LIMIT 1`,
			string(ecosystem), name, kind, now, version,
		).Scan(&id)
	} else {
		err = e.db.QueryRowContext(ctx,
			`SELECT id FROM policy_overrides
			 WHERE ecosystem = ? AND name = ? AND revoked = FALSE
			   AND kind = ? AND project_id = ?
			   AND (expires_at IS NULL OR expires_at > ?)
			   AND (scope = 'package' OR (scope = 'version' AND version = ?))
			 ORDER BY created_at DESC, id DESC LIMIT 1`,
			string(ecosystem), name, kind, *projectID, now, version,
		).Scan(&id)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false
		}
		log.Error().Err(err).
			Str("ecosystem", string(ecosystem)).
			Str("name", name).
			Str("version", version).
			Str("kind", kind).
			Msg("queryOverride: query error")
		return 0, false
	}
	return id, true
}

// lookupOverrideByArtifactID resolves an override using the artifact's
// (ecosystem, name, version) read from the artifacts table. Used by the
// cache-hit license path which only has the opaque artifact ID. Same
// precedence as lookupOverride.
func (e *Engine) lookupOverrideByArtifactID(ctx context.Context, artifactID string) (int64, string, bool) {
	if e == nil || e.db == nil || artifactID == "" {
		return 0, "", false
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		ecosystem string
		name      string
		version   string
	)
	err := e.db.QueryRowContext(dbCtx,
		`SELECT ecosystem, name, version FROM artifacts WHERE id = ?`,
		artifactID,
	).Scan(&ecosystem, &name, &version)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Error().Err(err).Str("artifact_id", artifactID).Msg("lookupOverrideByArtifactID: artifact lookup error")
		}
		return 0, "", false
	}
	return e.lookupOverride(ctx, scanner.Ecosystem(ecosystem), name, version)
}

// HasOverride returns the matching override's ID and true if there is an
// active, non-revoked, non-expired ALLOW override that would let the given
// (ecosystem, name, version) tuple through. Both per-project and global ALLOW
// overrides match; the project is resolved from ctx. DENY overrides are not
// returned here — they are surfaced through Evaluate / EvaluateLicensesOnly.
//
// This signature is preserved for the typosquat pre-scan path, where the only
// meaningful question is "should this be let through despite the typosquat
// suspicion." The override ID is recorded in audit-log MetadataJSON so
// operators can trace which override let a request through.
//
// Pass version="" for name-only requests (only package-scoped overrides will
// match); pass the real version for tarball-level requests.
func (e *Engine) HasOverride(ctx context.Context, ecosystem scanner.Ecosystem, name, version string) (int64, bool) {
	id, kind, ok := e.lookupOverride(ctx, ecosystem, name, version)
	if !ok || kind != OverrideKindAllow {
		return 0, false
	}
	return id, true
}

// Evaluate applies the policy to the given artifact and scan results.
// DB overrides are checked first, then static allowlist, then verdict rules.
func (e *Engine) Evaluate(ctx context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) PolicyResult {
	// DB override check — highest priority.
	if id, kind, ok := e.lookupOverride(ctx, artifact.Ecosystem, artifact.Name, artifact.Version); ok {
		switch kind {
		case OverrideKindDeny:
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("project policy override (deny): %s:%s:%s [override_id=%d]", artifact.Ecosystem, artifact.Name, artifact.Version, id),
			}
		case OverrideKindAllow:
			return PolicyResult{
				Action: ActionAllow,
				Reason: fmt.Sprintf("policy override: %s:%s:%s", artifact.Ecosystem, artifact.Name, artifact.Version),
			}
		}
	}

	// Static allowlist check.
	if isAllowlisted(artifact, e.allowlist) {
		return PolicyResult{
			Action: ActionAllow,
			Reason: "artifact is in allowlist",
		}
	}

	// License policy check (between allowlist and verdict aggregation). License
	// violations are authoritative — they short-circuit the rest of the policy
	// evaluation because a legally-blocked license is not something that scan
	// findings can override. Warnings (non-blocking) are merged into the final
	// PolicyResult at the end.
	licResult, licHandled := e.evaluateLicenses(ctx, artifact, scanResults)
	if licHandled {
		return licResult
	}
	licWarnings := licResult.Warnings

	aggCfg := AggregationConfig{
		MinConfidence:           e.cfg.MinimumConfidence,
		BehavioralMinConfidence: e.cfg.BehavioralMinimumConfidence,
	}
	agg := Aggregate(scanResults, aggCfg)

	var result PolicyResult
	switch {
	case agg.Verdict == scanner.VerdictMalicious:
		result = PolicyResult{
			Action: ActionBlock,
			Reason: fmt.Sprintf("verdict %s meets block threshold", agg.Verdict),
		}
	case agg.Verdict == scanner.VerdictSuspicious:
		result = e.evaluateSuspicious(ctx, artifact, &agg)
	default:
		result = PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("verdict %s is below action thresholds", agg.Verdict),
		}
	}
	if len(licWarnings) > 0 {
		result.Warnings = append(licWarnings, result.Warnings...)
	}
	return result
}

// EvaluateLicensesOnly checks stored SBOM licenses against the current policy
// without requiring scan results. Designed for the cache-hit serve path where
// a full scan is not performed. Returns ActionBlock when the artifact has a
// license that is blocked by the current policy.
//
// FAIL-CLOSED: returns ActionBlock on DB/resolver errors so that a broken
// metadata lookup cannot silently bypass license enforcement. This is stricter
// than evaluateLicenses() (used on fresh-scan path) which fails open.
func (e *Engine) EvaluateLicensesOnly(ctx context.Context, artifactID string) PolicyResult {
	// Override check runs ahead of the licenseEnabled gate so per-project
	// deny / allow decisions still apply when license enforcement is off.
	// Lookup degrades gracefully (returns false) when the artifacts row is
	// missing or the DB is nil.
	if id, kind, ok := e.lookupOverrideByArtifactID(ctx, artifactID); ok {
		switch kind {
		case OverrideKindDeny:
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("project policy override (deny) for %s [override_id=%d]", artifactID, id),
			}
		case OverrideKindAllow:
			return PolicyResult{
				Action: ActionAllow,
				Reason: fmt.Sprintf("policy override: %s", artifactID),
			}
		}
	}

	if !e.licenseEnabled {
		return PolicyResult{Action: ActionAllow}
	}

	// Resolve project from context.
	proj := project.FromContext(ctx)
	projectID := int64(0)
	projectLabel := ""
	if proj != nil {
		projectID = proj.ID
		projectLabel = proj.Label
	}

	pol, err := e.licenseResolver.ResolveForProject(ctx, projectID, projectLabel)
	if err != nil {
		if isContextError(err) {
			// Client disconnected or pipeline timeout — no point issuing
			// a fail-closed block + audit entry for a response nobody
			// will read.
			return PolicyResult{Action: ActionAllow}
		}
		// FAIL-CLOSED: resolver error blocks the request.
		log.Error().Err(err).Int64("project_id", projectID).Str("artifact_id", artifactID).
			Msg("policy: cache-hit license check: resolver error — blocking (fail-closed)")
		return PolicyResult{
			Action: ActionBlock,
			Reason: fmt.Sprintf("license: policy resolver error for %s (fail-closed)", artifactID),
		}
	}
	if license.IsDisabled(pol) {
		return PolicyResult{Action: ActionAllow}
	}

	// Load licenses from sbom_metadata.
	var licenses []string
	if e.sbomStore != nil {
		meta, err := e.sbomStore.GetMetadata(ctx, artifactID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			if isContextError(err) {
				// See resolver branch above — canceled / deadline means
				// the client is gone, don't pollute the audit log.
				return PolicyResult{Action: ActionAllow}
			}
			// FAIL-CLOSED: DB error blocks the request.
			log.Error().Err(err).Str("artifact_id", artifactID).
				Msg("policy: cache-hit license check: metadata read error — blocking (fail-closed)")
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("license: metadata read error for %s (fail-closed)", artifactID),
			}
		}
		if meta != nil {
			licenses = meta.Licenses()
		}
	}

	if len(licenses) == 0 {
		// No license data — apply on_sbom_error.
		switch e.onSBOMError {
		case license.ActionBlock:
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("license: SBOM unavailable for %s, on_sbom_error=block", artifactID),
			}
		case license.ActionWarn:
			return PolicyResult{
				Action:   ActionAllow,
				Warnings: []string{"license: SBOM unavailable — policy check skipped"},
			}
		default:
			return PolicyResult{Action: ActionAllow}
		}
	}

	decision := e.licenseEval.Evaluate(ctx, pol, licenses)
	switch decision.Action {
	case license.ActionBlock:
		return PolicyResult{Action: ActionBlock, Reason: decision.Reason}
	case license.ActionWarn:
		return PolicyResult{Action: ActionAllow, Warnings: []string{decision.Reason}}
	}
	return PolicyResult{Action: ActionAllow}
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

// evaluateLicenses applies license policy. Returns (result, true) if the
// license policy makes a definitive decision (block or warn with a message);
// returns (zero, false) if the evaluator is disabled / not applicable and the
// caller should continue to verdict aggregation.
//
// Warnings are accumulated on the returned result and flow through to the
// adapter serve path so downstream can emit X-Shieldoo-Warning headers.
//
// Source-of-license design:
//   - Prefer Trivy's pre-extracted ScanResult.Licenses when any scanner
//     populated it. This avoids a DB round-trip on the hot scan path.
//   - Fall back to sbom_metadata.licenses_json when the scan did not emit
//     licenses (e.g. version-diff or cache-hit re-evaluation paths).
//   - If no licenses are available anywhere, apply on_sbom_error policy.
func (e *Engine) evaluateLicenses(ctx context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) (PolicyResult, bool) {
	if !e.licenseEnabled {
		return PolicyResult{}, false
	}

	// Resolve project from context (Phase 1 middleware puts it there).
	proj := project.FromContext(ctx)
	projectID := int64(0)
	projectLabel := ""
	if proj != nil {
		projectID = proj.ID
		projectLabel = proj.Label
	}

	pol, err := e.licenseResolver.ResolveForProject(ctx, projectID, projectLabel)
	if err != nil {
		log.Warn().Err(err).Int64("project_id", projectID).Msg("policy: resolve license policy failed — allowing")
		return PolicyResult{}, false
	}

	// "disabled" mode for this project → skip.
	if license.IsDisabled(pol) {
		return PolicyResult{}, false
	}

	// Gather licenses: scan results first, then sbom_metadata fallback.
	var licenses []string
	for _, sr := range scanResults {
		if len(sr.Licenses) > 0 {
			licenses = append(licenses, sr.Licenses...)
		}
	}
	if len(licenses) == 0 {
		meta, err := e.sbomStore.GetMetadata(ctx, artifact.ID)
		if err == nil && meta != nil {
			licenses = meta.Licenses()
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.Warn().Err(err).Str("artifact_id", artifact.ID).Msg("policy: sbom metadata read failed")
		}
	}

	if len(licenses) == 0 {
		// No license data available — apply on_sbom_error.
		switch e.onSBOMError {
		case license.ActionBlock:
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("license: SBOM unavailable for %s, on_sbom_error=block", artifact.ID),
			}, true
		case license.ActionWarn:
			return PolicyResult{
				Warnings: []string{"license: SBOM unavailable — policy check skipped"},
			}, false // allow the rest of pipeline to run; just carry the warning forward
		default: // allow
			return PolicyResult{}, false
		}
	}

	decision := e.licenseEval.Evaluate(ctx, pol, licenses)
	switch decision.Action {
	case license.ActionBlock:
		return PolicyResult{
			Action: ActionBlock,
			Reason: decision.Reason,
		}, true
	case license.ActionWarn:
		// Non-terminal — attach warning and defer to verdict rules.
		return PolicyResult{
			Warnings: []string{decision.Reason},
		}, false
	}
	return PolicyResult{}, false
}

// isContextError reports whether err originated from the request/pipeline
// context being canceled or hitting its deadline. The cache-hit license
// evaluator treats these as "client gone" (not a real DB/resolver fault)
// so they do not trigger a fail-closed block + audit log entry.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
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
