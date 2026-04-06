package policy

import "fmt"

// PolicyMode describes the policy evaluation mode for SUSPICIOUS verdicts.
type PolicyMode int

const (
	// PolicyModeStrict quarantines all SUSPICIOUS artifacts regardless of severity.
	PolicyModeStrict PolicyMode = iota
	// PolicyModeBalanced uses severity + AI triage for MEDIUM; quarantines HIGH+.
	PolicyModeBalanced
	// PolicyModePermissive allows MEDIUM with warning; quarantines HIGH+.
	PolicyModePermissive
)

// String returns the config-friendly string representation of the mode.
func (m PolicyMode) String() string {
	switch m {
	case PolicyModeStrict:
		return "strict"
	case PolicyModeBalanced:
		return "balanced"
	case PolicyModePermissive:
		return "permissive"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// ParsePolicyMode converts a config string to PolicyMode.
// Empty string defaults to strict (backward compatible).
func ParsePolicyMode(s string) (PolicyMode, error) {
	switch s {
	case "", "strict":
		return PolicyModeStrict, nil
	case "balanced":
		return PolicyModeBalanced, nil
	case "permissive":
		return PolicyModePermissive, nil
	default:
		return 0, fmt.Errorf("policy: unknown mode %q (valid: strict, balanced, permissive)", s)
	}
}
