package policy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

// --- gRPC Triage Client ---

// GRPCTriageClient implements TriageClient using the scanner-bridge gRPC endpoint.
type GRPCTriageClient struct {
	client  pb.ScannerBridgeClient
	closer  func() error
	timeout time.Duration
}

// NewGRPCTriageClient dials the scanner bridge and returns a triage client.
func NewGRPCTriageClient(socketPath string, timeout time.Duration) (*GRPCTriageClient, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("triage client: dialing bridge at %s: %w", socketPath, err)
	}
	client := pb.NewScannerBridgeClient(conn)
	return &GRPCTriageClient{
		client:  client,
		closer:  conn.Close,
		timeout: timeout,
	}, nil
}

// Close releases the gRPC connection.
func (c *GRPCTriageClient) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

// Triage calls the TriageFindings gRPC endpoint.
func (c *GRPCTriageClient) Triage(ctx context.Context, req TriageRequest) (TriageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Convert tagged findings to proto Finding messages.
	var protoFindings []*pb.Finding
	for _, tf := range req.Findings {
		protoFindings = append(protoFindings, &pb.Finding{
			Severity:    string(tf.Severity),
			Category:    tf.Category,
			Description: tf.Description,
			Location:    tf.Location,
			Iocs:        tf.IoCs,
		})
	}

	resp, err := c.client.TriageFindings(ctx, &pb.TriageRequest{
		Ecosystem: req.Ecosystem,
		Name:      req.Name,
		Version:   req.Version,
		Findings:  protoFindings,
	})
	if err != nil {
		return TriageResponse{}, fmt.Errorf("triage gRPC call: %w", err)
	}

	// Validate response.
	decision := strings.ToUpper(resp.Decision)
	if decision != "ALLOW" && decision != "QUARANTINE" {
		log.Warn().Str("decision", resp.Decision).Msg("triage: invalid decision from bridge, defaulting to QUARANTINE")
		decision = "QUARANTINE"
	}

	confidence := resp.Confidence
	if confidence < 0 || confidence > 1 {
		log.Warn().Float32("confidence", confidence).Msg("triage: invalid confidence from bridge, defaulting to QUARANTINE")
		return TriageResponse{
			Decision:   "QUARANTINE",
			Confidence: 0,
			Explanation: "invalid confidence value from AI triage",
			ModelUsed:  resp.ModelUsed,
			TokensUsed: int(resp.TokensUsed),
		}, nil
	}

	// Sanitize explanation: truncate to 500 chars, strip control characters.
	explanation := resp.Explanation
	if len(explanation) > 500 {
		explanation = explanation[:500]
	}

	return TriageResponse{
		Decision:    decision,
		Confidence:  confidence,
		Explanation: explanation,
		ModelUsed:   resp.ModelUsed,
		TokensUsed:  int(resp.TokensUsed),
	}, nil
}

// --- DB-backed Triage Cache ---

// DBTriageCacheStore implements TriageCacheStore using the database.
type DBTriageCacheStore struct {
	db *config.GateDB
}

// NewDBTriageCacheStore creates a cache store backed by the triage_cache table.
func NewDBTriageCacheStore(db *config.GateDB) *DBTriageCacheStore {
	return &DBTriageCacheStore{db: db}
}

// TriageCacheKey computes a cache key from the artifact and findings.
func TriageCacheKey(ecosystem, name, version string, findings []TaggedFinding) string {
	// Sort findings for deterministic key.
	type findingKey struct {
		Severity    string
		Category    string
		Description string
		ScannerID   string
	}
	var keys []findingKey
	for _, f := range findings {
		keys = append(keys, findingKey{
			Severity:    string(f.Severity),
			Category:    f.Category,
			Description: f.Description,
			ScannerID:   f.ScannerID,
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := json.Marshal(keys[i])
		b, _ := json.Marshal(keys[j])
		return string(a) < string(b)
	})

	data, _ := json.Marshal(struct {
		Eco      string       `json:"eco"`
		Name     string       `json:"name"`
		Version  string       `json:"ver"`
		Findings []findingKey `json:"f"`
	}{ecosystem, name, version, keys})

	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// Get retrieves a cached triage decision. Returns nil if not found or expired.
func (s *DBTriageCacheStore) Get(key string) (*TriageResponse, error) {
	var row struct {
		Decision    string    `db:"decision"`
		Confidence  float32   `db:"confidence"`
		Explanation string    `db:"explanation"`
		ModelUsed   string    `db:"model_used"`
		ExpiresAt   time.Time `db:"expires_at"`
	}

	err := s.db.Get(&row,
		`SELECT decision, confidence, explanation, model_used, expires_at
		 FROM triage_cache WHERE cache_key = ?`, key)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("triage cache get: %w", err)
	}

	if time.Now().UTC().After(row.ExpiresAt) {
		// Expired — treat as miss.
		return nil, nil
	}

	return &TriageResponse{
		Decision:    row.Decision,
		Confidence:  row.Confidence,
		Explanation: row.Explanation,
		ModelUsed:   row.ModelUsed,
		CacheHit:    true,
	}, nil
}

// Set stores a triage decision in the cache.
func (s *DBTriageCacheStore) Set(key string, resp TriageResponse, ttl time.Duration) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO triage_cache (cache_key, ecosystem, name, version, decision, confidence, explanation, model_used, created_at, expires_at)
		 VALUES (?, '', '', '', ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(cache_key) DO UPDATE SET decision=excluded.decision, confidence=excluded.confidence, explanation=excluded.explanation, model_used=excluded.model_used, created_at=excluded.created_at, expires_at=excluded.expires_at`,
		key, resp.Decision, resp.Confidence, resp.Explanation, resp.ModelUsed, now, now.Add(ttl))
	if err != nil {
		return fmt.Errorf("triage cache set: %w", err)
	}
	return nil
}

// --- Circuit Breaker ---

// CircuitBreaker tracks consecutive failures and enters cooldown.
type CircuitBreaker struct {
	mu              sync.Mutex
	failures        int
	threshold       int
	cooldown        time.Duration
	openUntil       time.Time
}

// NewCircuitBreaker creates a circuit breaker with the given threshold and cooldown.
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// IsOpen returns true if the circuit breaker is currently open (in cooldown).
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.failures >= cb.threshold {
		if time.Now().Before(cb.openUntil) {
			return true
		}
		// Cooldown expired — reset.
		cb.failures = 0
	}
	return false
}

// RecordSuccess resets the failure counter.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

// RecordFailure increments the failure counter and opens the circuit if threshold is reached.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		cb.openUntil = time.Now().Add(cb.cooldown)
		log.Warn().Int("failures", cb.failures).Dur("cooldown", cb.cooldown).Msg("triage circuit breaker opened")
	}
}

// --- Rate Limiter helper ---

// TriageRateLimiter wraps a simple token-bucket rate limiter for triage calls.
type TriageRateLimiter struct {
	mu        sync.Mutex
	tokens    int
	maxTokens int
	lastRefill time.Time
	interval   time.Duration
}

// NewTriageRateLimiter creates a rate limiter allowing maxPerMinute calls per minute.
func NewTriageRateLimiter(maxPerMinute int) *TriageRateLimiter {
	return &TriageRateLimiter{
		tokens:     maxPerMinute,
		maxTokens:  maxPerMinute,
		lastRefill: time.Now(),
		interval:   time.Minute,
	}
}

// Allow returns true if a triage call is allowed under the rate limit.
func (rl *TriageRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	if elapsed >= rl.interval {
		rl.tokens = rl.maxTokens
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

// --- Triage metadata for audit log ---

// TriageMetadata is the JSON structure stored in audit_log.metadata_json.
type TriageMetadata struct {
	Decision    string  `json:"decision"`
	Confidence  float32 `json:"confidence"`
	Explanation string  `json:"explanation"`
	ModelUsed   string  `json:"model_used"`
	TokensUsed  int     `json:"tokens_used"`
	CacheHit    bool    `json:"cache_hit"`
}

// FindingSummary returns a human-readable summary of findings for logging.
func FindingSummary(findings []TaggedFinding) string {
	if len(findings) == 0 {
		return "no findings"
	}
	var parts []string
	for _, f := range findings {
		eff := EffectiveSeverity(f.Severity, f.ScannerID)
		parts = append(parts, fmt.Sprintf("[%s/%s] %s: %s",
			f.ScannerID, eff, f.Category,
			truncate(f.Description, 80)))
	}
	return strings.Join(parts, "; ")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// BuildTriageMetadataJSON creates the metadata_json string for audit log entries.
func BuildTriageMetadataJSON(resp TriageResponse) string {
	meta := map[string]interface{}{
		"ai_triage": TriageMetadata{
			Decision:    resp.Decision,
			Confidence:  resp.Confidence,
			Explanation: resp.Explanation,
			ModelUsed:   resp.ModelUsed,
			TokensUsed:  resp.TokensUsed,
			CacheHit:    resp.CacheHit,
		},
	}
	data, _ := json.Marshal(meta)
	return string(data)
}

// --- Wiring: integrate triage into evaluateSuspicious ---

// InitTriageInfra creates triage infrastructure (client, cache, circuit breaker, rate limiter)
// from config. Returns nil values if triage is not enabled.
func InitTriageInfra(cfg config.AITriageConfig, bridgeSocket string, db *config.GateDB) (
	TriageClient, TriageCacheStore, *CircuitBreaker, *TriageRateLimiter, error,
) {
	if !cfg.Enabled {
		return nil, nil, nil, nil, nil
	}

	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		timeout = 5 * time.Second
	}

	client, err := NewGRPCTriageClient(bridgeSocket, timeout)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("triage: creating gRPC client: %w", err)
	}

	var cache TriageCacheStore
	if db != nil {
		cache = NewDBTriageCacheStore(db)
	}

	cbCooldown, err := time.ParseDuration(cfg.CircuitBreakerCooldown)
	if err != nil {
		cbCooldown = 60 * time.Second
	}
	cb := NewCircuitBreaker(cfg.CircuitBreakerThreshold, cbCooldown)

	rl := NewTriageRateLimiter(cfg.RateLimit)

	return client, cache, cb, rl, nil
}

// EvaluateWithTriage performs AI triage for balanced mode MEDIUM severity findings.
// It handles cache lookup, rate limiting, circuit breaking, and fallback.
func EvaluateWithTriage(
	ctx context.Context,
	artifact scanner.Artifact,
	agg *AggregatedResult,
	maxSev scanner.Severity,
	triageClient TriageClient,
	triageCache TriageCacheStore,
	cb *CircuitBreaker,
	rl *TriageRateLimiter,
	minConfidence float32,
	cacheTTL time.Duration,
) PolicyResult {
	suspFindings := agg.SuspiciousFindings()

	// Build cache key.
	cacheKey := TriageCacheKey(
		string(artifact.Ecosystem), artifact.Name, artifact.Version, suspFindings)

	// Check cache first.
	if triageCache != nil {
		cached, err := triageCache.Get(cacheKey)
		if err != nil {
			log.Error().Err(err).Msg("triage cache lookup error")
		}
		if cached != nil {
			return triageResultToPolicy(cached, maxSev, minConfidence)
		}
	}

	// Circuit breaker check.
	if cb != nil && cb.IsOpen() {
		log.Warn().Msg("triage circuit breaker open — fallback to QUARANTINE")
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("balanced mode: circuit breaker open, effective severity %s", maxSev),
		}
	}

	// Rate limiter check.
	if rl != nil && !rl.Allow() {
		log.Warn().Msg("triage rate limit exceeded — fallback to QUARANTINE")
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("balanced mode: rate limit exceeded, effective severity %s", maxSev),
		}
	}

	// Call AI triage.
	req := TriageRequest{
		Ecosystem: string(artifact.Ecosystem),
		Name:      artifact.Name,
		Version:   artifact.Version,
		Findings:  suspFindings,
	}

	resp, err := triageClient.Triage(ctx, req)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifact.ID).Msg("triage call failed — fallback to QUARANTINE")
		if cb != nil {
			cb.RecordFailure()
		}
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("balanced mode: triage error, effective severity %s", maxSev),
		}
	}

	log.Info().
		Str("artifact", artifact.ID).
		Str("decision", resp.Decision).
		Float32("confidence", resp.Confidence).
		Str("explanation", truncate(resp.Explanation, 100)).
		Msg("triage result received")

	// Success — reset circuit breaker.
	if cb != nil {
		cb.RecordSuccess()
	}

	// Cache the result.
	if triageCache != nil {
		if err := triageCache.Set(cacheKey, resp, cacheTTL); err != nil {
			log.Error().Err(err).Msg("triage cache store error")
		}
	}

	return triageResultToPolicy(&resp, maxSev, minConfidence)
}

// triageResultToPolicy converts a triage response to a policy result.
func triageResultToPolicy(resp *TriageResponse, maxSev scanner.Severity, minConfidence float32) PolicyResult {
	if resp.Confidence < minConfidence {
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("balanced mode: triage confidence %.2f < threshold %.2f, effective severity %s",
				resp.Confidence, minConfidence, maxSev),
		}
	}

	if resp.Decision == "QUARANTINE" {
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("balanced mode: AI triage decided QUARANTINE (confidence %.2f): %s",
				resp.Confidence, resp.Explanation),
		}
	}

	return PolicyResult{
		Action: ActionAllowWithWarning,
		Reason: fmt.Sprintf("balanced mode: AI triage decided ALLOW (confidence %.2f): %s",
			resp.Confidence, resp.Explanation),
	}
}
