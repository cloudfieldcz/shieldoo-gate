package license

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluator_BlockedLicense_Blocks(t *testing.T) {
	pol := Policy{Blocked: []string{"GPL-3.0-only"}, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"GPL-3.0-only"})
	assert.Equal(t, ActionBlock, d.Action)
	assert.Equal(t, RuleBlocked, d.Rule)
	assert.Contains(t, d.Reason, "global")
}

func TestEvaluator_WarnedLicense_Warns(t *testing.T) {
	pol := Policy{Warned: []string{"LGPL-2.1-only"}, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"LGPL-2.1-only"})
	assert.Equal(t, ActionWarn, d.Action)
	assert.Equal(t, RuleWarned, d.Rule)
}

func TestEvaluator_WhitelistMode_AllowsOnlyListed(t *testing.T) {
	pol := Policy{Allowed: []string{"MIT", "Apache-2.0"}, Source: "global"}
	allow := NewEvaluator().Evaluate(context.Background(), pol, []string{"MIT"})
	assert.Equal(t, ActionAllow, allow.Action)
	block := NewEvaluator().Evaluate(context.Background(), pol, []string{"BSD-3-Clause"})
	assert.Equal(t, ActionBlock, block.Action)
	assert.Equal(t, RuleNotInAllowlist, block.Rule)
}

func TestEvaluator_Unknown_AppliesUnknownAction(t *testing.T) {
	polBlock := Policy{UnknownAction: UnknownBlock, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), polBlock, []string{"Some-Weird-License-1.0"})
	assert.Equal(t, ActionBlock, d.Action)
	assert.Equal(t, RuleUnknown, d.Rule)

	polAllow := Policy{UnknownAction: UnknownAllow, Source: "global"}
	d2 := NewEvaluator().Evaluate(context.Background(), polAllow, []string{"Some-Weird-License-1.0"})
	assert.Equal(t, ActionAllow, d2.Action)
}

func TestEvaluator_DualLicense_OR_AnyAllowed(t *testing.T) {
	pol := Policy{
		Allowed:     []string{"MIT"},
		OrSemantics: OrAnyAllowed,
		Source:      "global",
	}
	// MIT OR Apache-2.0 — MIT is allowed → pass
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"MIT OR Apache-2.0"})
	assert.Equal(t, ActionAllow, d.Action)
}

func TestEvaluator_DualLicense_OR_AllAllowed_FailsWhenOneDenied(t *testing.T) {
	pol := Policy{
		Allowed:     []string{"MIT"},
		OrSemantics: OrAllAllowed,
		Source:      "global",
	}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"MIT OR Apache-2.0"})
	assert.Equal(t, ActionBlock, d.Action)
}

func TestEvaluator_DualLicense_AND_AllRequired(t *testing.T) {
	polBlock := Policy{Blocked: []string{"GPL-3.0-only"}, Source: "global"}
	// GPL-3.0-only AND MIT — GPL is blocked → overall blocked.
	d := NewEvaluator().Evaluate(context.Background(), polBlock, []string{"GPL-3.0-only AND MIT"})
	assert.Equal(t, ActionBlock, d.Action)
	assert.Equal(t, RuleBlocked, d.Rule)
}

func TestEvaluator_WITH_IgnoresException(t *testing.T) {
	pol := Policy{Allowed: []string{"Apache-2.0"}, Source: "global"}
	// "Apache-2.0 WITH LLVM-exception" — exception is ignored, base license allowed.
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"Apache-2.0 WITH LLVM-exception"})
	assert.Equal(t, ActionAllow, d.Action)
}

func TestEvaluator_Parens_Recursive(t *testing.T) {
	pol := Policy{Allowed: []string{"MIT", "Apache-2.0"}, OrSemantics: OrAnyAllowed, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"(MIT OR Apache-2.0) AND MIT"})
	assert.Equal(t, ActionAllow, d.Action)
}

func TestEvaluator_BlockBeatsWarn(t *testing.T) {
	pol := Policy{Blocked: []string{"GPL-3.0-only"}, Warned: []string{"MIT"}, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"MIT", "GPL-3.0-only"})
	assert.Equal(t, ActionBlock, d.Action)
}

func TestEvaluator_EmptyLicenses_ReturnsAllow(t *testing.T) {
	pol := Policy{Blocked: []string{"GPL-3.0-only"}, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, nil)
	assert.Equal(t, ActionAllow, d.Action)
}

func TestEvaluator_CaseInsensitive(t *testing.T) {
	pol := Policy{Blocked: []string{"GPL-3.0-only"}, Source: "global"}
	d := NewEvaluator().Evaluate(context.Background(), pol, []string{"gpl-3.0-only"})
	assert.Equal(t, ActionBlock, d.Action)
}

func TestParseExpression_BasicAndAnd(t *testing.T) {
	expr, err := ParseExpression("MIT AND Apache-2.0")
	assert.NoError(t, err)
	leaves := collectLeaves(expr)
	assert.ElementsMatch(t, []string{"MIT", "Apache-2.0"}, leaves)
}

func TestParseExpression_Malformed_FallsBackToSingleIdent(t *testing.T) {
	// "OR" by itself is malformed; parser marks error but returns a best-effort node.
	expr, err := ParseExpression("OR")
	assert.Error(t, err)
	_ = expr
}
