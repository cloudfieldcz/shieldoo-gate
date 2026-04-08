package policy

import "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"

const threatFeedScannerID = "builtin-threat-feed"

// AggregationConfig controls how scan results are aggregated into a single verdict.
type AggregationConfig struct {
	MinConfidence float32
	// BehavioralMinConfidence is the confidence threshold for behavioral scanners
	// (guarddog, ai-scanner, exfil-detector, etc.). Behavioral scanners detect
	// novel supply chain attack patterns where even moderate confidence warrants
	// review. Defaults to MinConfidence / 2 if zero.
	BehavioralMinConfidence float32
}

// TaggedFinding associates a finding with the scanner that produced it.
type TaggedFinding struct {
	scanner.Finding
	ScannerID      string
	ScannerVerdict scanner.Verdict
}

// AggregatedResult holds the combined verdict and all findings from multiple scanners.
type AggregatedResult struct {
	Verdict  scanner.Verdict
	Findings []scanner.Finding
	// Tagged holds findings with scanner attribution for severity-aware evaluation.
	Tagged []TaggedFinding
}

// SuspiciousFindings returns findings only from scanners that reported SUSPICIOUS or higher.
func (a *AggregatedResult) SuspiciousFindings() []TaggedFinding {
	var result []TaggedFinding
	for _, tf := range a.Tagged {
		if tf.ScannerVerdict == scanner.VerdictSuspicious || tf.ScannerVerdict == scanner.VerdictMalicious {
			result = append(result, tf)
		}
	}
	return result
}

// MaxEffectiveSeverity returns the highest effective severity among findings
// from scanners that contributed to the SUSPICIOUS verdict.
// If no findings exist (anomaly), returns HIGH as a safe default.
func (a *AggregatedResult) MaxEffectiveSeverity() scanner.Severity {
	suspicious := a.SuspiciousFindings()
	if len(suspicious) == 0 {
		// SUSPICIOUS without findings is an anomaly — treat as HIGH.
		return scanner.SeverityHigh
	}

	maxRank := -1
	maxSev := scanner.SeverityInfo
	for _, tf := range suspicious {
		eff := EffectiveSeverity(tf.Severity, tf.ScannerID)
		r := severityRank(eff)
		if r > maxRank {
			maxRank = r
			maxSev = eff
		}
	}
	return maxSev
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
	var tagged []TaggedFinding

	// Pass 1: threat-feed fast-path.
	for _, r := range results {
		if r.ScannerID == threatFeedScannerID && r.Verdict == scanner.VerdictMalicious {
			var tf []TaggedFinding
			for _, f := range r.Findings {
				tf = append(tf, TaggedFinding{Finding: f, ScannerID: r.ScannerID, ScannerVerdict: r.Verdict})
			}
			return AggregatedResult{
				Verdict:  scanner.VerdictMalicious,
				Findings: r.Findings,
				Tagged:   tf,
			}
		}
	}

	// Pass 2: aggregate by highest verdict above confidence threshold.
	verdict := scanner.VerdictClean

	// Behavioral scanners use a lower confidence threshold because they detect
	// novel supply chain attack patterns where even moderate signals matter.
	behavioralMin := cfg.BehavioralMinConfidence
	if behavioralMin == 0 {
		behavioralMin = cfg.MinConfidence / 2
	}

	for _, r := range results {
		// Skip errored results (fail-open).
		if r.Error != nil {
			continue
		}
		// Skip low-confidence results. Behavioral scanners use a lower threshold.
		minConf := cfg.MinConfidence
		if ScannerCategoryFor(r.ScannerID) == CategoryBehavioral {
			minConf = behavioralMin
		}
		if r.Confidence < minConf {
			continue
		}

		allFindings = append(allFindings, r.Findings...)
		for _, f := range r.Findings {
			tagged = append(tagged, TaggedFinding{Finding: f, ScannerID: r.ScannerID, ScannerVerdict: r.Verdict})
		}

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
		Tagged:   tagged,
	}
}
