package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// EngineConfig configures the policy engine thresholds and allowlist.
type EngineConfig struct {
	BlockIfVerdict      scanner.Verdict
	QuarantineIfVerdict scanner.Verdict
	MinimumConfidence   float32
	Allowlist           []string
}

// Engine evaluates scan results against policy rules and returns a PolicyResult.
type Engine struct {
	cfg       EngineConfig
	allowlist []AllowlistEntry
	db        *config.GateDB
}

// NewEngine creates a new Engine with the supplied configuration.
// db may be nil — in that case only static allowlist is used.
func NewEngine(cfg EngineConfig, db *config.GateDB) *Engine {
	var parsed []AllowlistEntry
	for _, raw := range cfg.Allowlist {
		entry, err := ParseAllowlistEntry(raw)
		if err == nil {
			parsed = append(parsed, entry)
		}
	}
	return &Engine{cfg: cfg, allowlist: parsed, db: db}
}

// hasDBOverride checks if there is an active, non-revoked, non-expired override
// in the database for the given artifact.
func (e *Engine) hasDBOverride(ctx context.Context, artifact scanner.Artifact) bool {
	if e.db == nil {
		return false
	}

	now := time.Now().UTC()
	var count int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policy_overrides
		 WHERE ecosystem = ? AND name = ? AND revoked = FALSE
		   AND (expires_at IS NULL OR expires_at > ?)
		   AND (scope = 'package' OR (scope = 'version' AND version = ?))`,
		string(artifact.Ecosystem), artifact.Name, now, artifact.Version,
	).Scan(&count)
	if err != nil {
		// Fail open — DB errors should not block artifacts
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

	aggCfg := AggregationConfig{MinConfidence: e.cfg.MinimumConfidence}
	agg := Aggregate(scanResults, aggCfg)

	switch {
	case agg.Verdict == e.cfg.BlockIfVerdict:
		return PolicyResult{
			Action: ActionBlock,
			Reason: fmt.Sprintf("verdict %s meets block threshold", agg.Verdict),
		}
	case agg.Verdict == e.cfg.QuarantineIfVerdict:
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("verdict %s meets quarantine threshold", agg.Verdict),
		}
	default:
		return PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("verdict %s is below action thresholds", agg.Verdict),
		}
	}
}
