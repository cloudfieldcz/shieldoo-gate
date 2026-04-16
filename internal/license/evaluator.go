package license

import (
	"context"
	"fmt"
	"strings"
)

// NewEvaluator returns a stateless Evaluator.
func NewEvaluator() Evaluator { return evaluatorImpl{} }

type evaluatorImpl struct{}

// Evaluate walks each license string (possibly an SPDX expression) and
// returns the first matching decision that causes a non-allow action.
// When all licenses are allowed, the returned Decision has Action=allow.
func (e evaluatorImpl) Evaluate(_ context.Context, policy Policy, licenses []string) Decision {
	blockedSet := stringSliceToSet(policy.Blocked)
	warnedSet := stringSliceToSet(policy.Warned)
	allowedSet := stringSliceToSet(policy.Allowed)
	hasAllowlist := len(allowedSet) > 0

	// isAllowed is the per-ID policy check used by expression evaluation.
	// A leaf is "allowed" if it is not blocked AND (no allowlist OR in
	// allowlist). Unknown handling is folded in at the expression level
	// (below) because OR expressions can include unknown leaves.
	isAllowed := func(rawID string) bool {
		id := normalizeID(rawID)
		if _, blocked := blockedSet[id]; blocked {
			return false
		}
		if hasAllowlist {
			if _, ok := allowedSet[id]; !ok {
				return false
			}
		}
		return true
	}

	// Track worst observed action.
	worst := Decision{Action: ActionAllow, PolicySource: policy.Source, Rule: RuleAllowed}
	promote := func(d Decision) {
		if actionSeverity(d.Action) > actionSeverity(worst.Action) {
			worst = d
		}
	}

	for _, raw := range licenses {
		lic := strings.TrimSpace(raw)
		if lic == "" {
			continue
		}

		// Simple identifier fast path.
		if !containsExpressionOp(lic) {
			dec := evaluateLeaf(lic, policy, blockedSet, warnedSet, allowedSet)
			promote(dec)
			if dec.Action == ActionBlock {
				return dec
			}
			continue
		}

		// Expression — parse + evaluate.
		expr, _ := ParseExpression(lic)

		// First check: does any leaf match a blocked entry? For SPDX OR with
		// any_allowed semantics, one allowed operand can still pass — but
		// for AND semantics a single blocked leaf blocks the whole thing.
		allowsExpr := evaluateExpression(expr, isAllowed, policy.OrSemantics)
		if allowsExpr {
			// Report as the first leaf for audit readability.
			leaves := collectLeaves(expr)
			if warnMatched, which := anyInSet(leaves, warnedSet); warnMatched {
				promote(Decision{
					Action: ActionWarn, Rule: RuleWarned, MatchedLicense: which,
					Reason:       fmt.Sprintf("license %q matches warn list", which),
					PolicySource: policy.Source,
				})
			}
			continue
		}

		// Expression failed — pick best reason. If any leaf is explicitly
		// blocked, surface that; otherwise surface "not in allowlist".
		leaves := collectLeaves(expr)
		if blockedMatch, which := anyInSet(leaves, blockedSet); blockedMatch {
			dec := Decision{
				Action: ActionBlock, Rule: RuleBlocked, MatchedLicense: which,
				Reason:       fmt.Sprintf("license %q blocked by %s policy", which, policy.Source),
				PolicySource: policy.Source,
			}
			promote(dec)
			return dec
		}
		if hasAllowlist {
			// None in allowlist.
			which := ""
			if len(leaves) > 0 {
				which = leaves[0]
			}
			dec := Decision{
				Action: ActionBlock, Rule: RuleNotInAllowlist, MatchedLicense: which,
				Reason:       fmt.Sprintf("license expression %q not in allowlist (%s)", lic, policy.Source),
				PolicySource: policy.Source,
			}
			promote(dec)
			return dec
		}
		// Fall back to unknown_action for the whole expression.
		dec := unknownDecision(policy, lic)
		promote(dec)
		if dec.Action == ActionBlock {
			return dec
		}
	}
	return worst
}

// evaluateLeaf handles a single SPDX identifier (no expression operators).
func evaluateLeaf(id string, policy Policy, blocked, warned, allowed map[string]struct{}) Decision {
	norm := normalizeID(id)
	if _, ok := blocked[norm]; ok {
		return Decision{
			Action: ActionBlock, Rule: RuleBlocked, MatchedLicense: id,
			Reason:       fmt.Sprintf("license %q blocked by %s policy", id, policy.Source),
			PolicySource: policy.Source,
		}
	}
	if _, ok := warned[norm]; ok {
		// Warn-listed; continue but mark action.
		return Decision{
			Action: ActionWarn, Rule: RuleWarned, MatchedLicense: id,
			Reason:       fmt.Sprintf("license %q matches warn list", id),
			PolicySource: policy.Source,
		}
	}
	if len(allowed) > 0 {
		if _, ok := allowed[norm]; !ok {
			return Decision{
				Action: ActionBlock, Rule: RuleNotInAllowlist, MatchedLicense: id,
				Reason:       fmt.Sprintf("license %q not in allowlist (%s)", id, policy.Source),
				PolicySource: policy.Source,
			}
		}
		// In allowlist → allow.
		return Decision{Action: ActionAllow, Rule: RuleAllowed, MatchedLicense: id, PolicySource: policy.Source}
	}
	// No allowlist; unknown id → apply unknown_action.
	return unknownDecision(policy, id)
}

func unknownDecision(policy Policy, id string) Decision {
	switch policy.UnknownAction {
	case UnknownBlock:
		return Decision{
			Action: ActionBlock, Rule: RuleUnknown, MatchedLicense: id,
			Reason:       fmt.Sprintf("unknown license %q blocked by %s unknown_action=block", id, policy.Source),
			PolicySource: policy.Source,
		}
	case UnknownWarn:
		return Decision{
			Action: ActionWarn, Rule: RuleUnknown, MatchedLicense: id,
			Reason:       fmt.Sprintf("unknown license %q warned by %s unknown_action=warn", id, policy.Source),
			PolicySource: policy.Source,
		}
	default: // UnknownAllow or empty
		return Decision{
			Action: ActionAllow, Rule: RuleUnknown, MatchedLicense: id,
			PolicySource: policy.Source,
		}
	}
}

func containsExpressionOp(s string) bool {
	upper := strings.ToUpper(s)
	return strings.Contains(upper, " OR ") || strings.Contains(upper, " AND ") || strings.Contains(upper, " WITH ") || strings.Contains(upper, "(")
}

func anyInSet(items []string, set map[string]struct{}) (bool, string) {
	for _, s := range items {
		if _, ok := set[normalizeID(s)]; ok {
			return true, s
		}
	}
	return false, ""
}

func actionSeverity(a Action) int {
	switch a {
	case ActionBlock:
		return 2
	case ActionWarn:
		return 1
	default:
		return 0
	}
}
