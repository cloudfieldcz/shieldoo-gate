package policy

import "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"

const threatFeedScannerID = "builtin-threat-feed"

// AggregationConfig controls how scan results are aggregated into a single verdict.
type AggregationConfig struct {
	MinConfidence float32
}

// AggregatedResult holds the combined verdict and all findings from multiple scanners.
type AggregatedResult struct {
	Verdict  scanner.Verdict
	Findings []scanner.Finding
}

// Aggregate combines multiple ScanResults into a single AggregatedResult.
//
// Rules (in priority order):
//  1. If any result comes from the threat-feed scanner with verdict MALICIOUS,
//     return MALICIOUS immediately (fast-path).
//  2. Skip results whose confidence is below cfg.MinConfidence.
//  3. Among remaining results, MALICIOUS > SUSPICIOUS > CLEAN.
//  4. Scanner errors (result.Error != nil) are treated as CLEAN (fail-open).
//  5. No valid results → CLEAN.
func Aggregate(results []scanner.ScanResult, cfg AggregationConfig) AggregatedResult {
	var allFindings []scanner.Finding

	// Pass 1: threat-feed fast-path.
	for _, r := range results {
		if r.ScannerID == threatFeedScannerID && r.Verdict == scanner.VerdictMalicious {
			return AggregatedResult{
				Verdict:  scanner.VerdictMalicious,
				Findings: r.Findings,
			}
		}
	}

	// Pass 2: aggregate by highest verdict above confidence threshold.
	verdict := scanner.VerdictClean

	for _, r := range results {
		// Skip errored results (fail-open).
		if r.Error != nil {
			continue
		}
		// Skip low-confidence results.
		if r.Confidence < cfg.MinConfidence {
			continue
		}

		allFindings = append(allFindings, r.Findings...)

		switch r.Verdict {
		case scanner.VerdictMalicious:
			verdict = scanner.VerdictMalicious
		case scanner.VerdictSuspicious:
			if verdict != scanner.VerdictMalicious {
				verdict = scanner.VerdictSuspicious
			}
		}
	}

	return AggregatedResult{
		Verdict:  verdict,
		Findings: allFindings,
	}
}
