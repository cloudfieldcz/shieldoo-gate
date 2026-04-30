// Package license implements SPDX-based license policy evaluation.
//
// Design notes:
//   - The effective policy is resolved from the global YAML config plus an
//     optional per-project override row (`project_license_policy`). Per-project
//     overrides apply in both lazy and strict projects modes; the override is
//     an admin-authored row in the DB, so it does not depend on the lazy/strict
//     auth model. See ADR-004.
//   - License expressions ("MIT OR Apache-2.0") are evaluated with the
//     configured or_semantics: "any_allowed" (default) or "all_allowed".
package license

import (
	"context"
	"strings"
)

// Action is the outcome of license evaluation for a single artifact.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// UnknownAction controls how unknown/unrecognized SPDX IDs are handled.
type UnknownAction string

const (
	UnknownAllow UnknownAction = "allow"
	UnknownWarn  UnknownAction = "warn"
	UnknownBlock UnknownAction = "block"
)

// OrSemantics controls how SPDX OR expressions ("MIT OR Apache-2.0") are evaluated.
type OrSemantics string

const (
	// OrAnyAllowed (default) — at least one operand must be allowed.
	OrAnyAllowed OrSemantics = "any_allowed"
	// OrAllAllowed — every operand must be allowed. Stricter.
	OrAllAllowed OrSemantics = "all_allowed"
)

// Rule is the "why" behind a Decision.
type Rule string

const (
	RuleBlocked         Rule = "blocked"
	RuleWarned          Rule = "warned"
	RuleNotInAllowlist  Rule = "not-in-allowlist"
	RuleUnknown         Rule = "unknown"
	RuleAllowed         Rule = "allowed"
	RuleInherit         Rule = "inherit-global"
	RuleDisabled        Rule = "disabled"
)

// Policy is the effective license policy for a single evaluation.
type Policy struct {
	Blocked       []string
	Warned        []string
	Allowed       []string // whitelist mode if non-empty
	UnknownAction UnknownAction
	OrSemantics   OrSemantics
	Source        string // "global" | "project:{label}" — used in audit / error messages
}

// Decision is the per-artifact outcome.
type Decision struct {
	Action          Action
	Reason          string
	MatchedLicense  string // the SPDX ID or expression that triggered the action
	Rule            Rule
	PolicySource    string // copy of Policy.Source
}

// Evaluator evaluates a list of SPDX IDs (from the SBOM) against an effective
// policy. The implementation is pure/stateless so callers may invoke it
// concurrently.
type Evaluator interface {
	Evaluate(ctx context.Context, policy Policy, licenses []string) Decision
}

// normalizeID lowercases and trims whitespace for comparisons. SPDX IDs are
// case-insensitive per spec §8.
func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// stringSliceToSet creates a set keyed by normalized SPDX IDs.
func stringSliceToSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[normalizeID(s)] = struct{}{}
	}
	return out
}
