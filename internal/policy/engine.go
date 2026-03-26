package policy

import (
	"context"
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// EngineConfig configures the policy engine thresholds and allowlist.
type EngineConfig struct {
	// BlockIfVerdict is the verdict that triggers a block action (e.g. "MALICIOUS").
	BlockIfVerdict scanner.Verdict
	// QuarantineIfVerdict is the verdict that triggers quarantine (e.g. "SUSPICIOUS").
	QuarantineIfVerdict scanner.Verdict
	// MinimumConfidence is forwarded to the aggregator.
	MinimumConfidence float32
	// Allowlist is a list of "eco:name:==version" entries that override block/quarantine.
	Allowlist []string
}

// Engine evaluates scan results against policy rules and returns a PolicyResult.
type Engine struct {
	cfg       EngineConfig
	allowlist []AllowlistEntry
}

// NewEngine creates a new Engine with the supplied configuration.
// Invalid allowlist entries are ignored (logged in production; skipped in tests).
func NewEngine(cfg EngineConfig) *Engine {
	var parsed []AllowlistEntry
	for _, raw := range cfg.Allowlist {
		entry, err := ParseAllowlistEntry(raw)
		if err == nil {
			parsed = append(parsed, entry)
		}
	}
	return &Engine{cfg: cfg, allowlist: parsed}
}

// Evaluate applies the policy to the given artifact and scan results.
// Allowlist entries are checked first; matching artifacts are always allowed.
func (e *Engine) Evaluate(_ context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) PolicyResult {
	// Allowlist check — overrides everything.
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
