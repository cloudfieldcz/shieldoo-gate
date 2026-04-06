package policy_test

import (
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyMode_Validation_ValidModes(t *testing.T) {
	tests := []struct {
		input    string
		expected policy.PolicyMode
	}{
		{"", policy.PolicyModeStrict},
		{"strict", policy.PolicyModeStrict},
		{"balanced", policy.PolicyModeBalanced},
		{"permissive", policy.PolicyModePermissive},
	}
	for _, tt := range tests {
		m, err := policy.ParsePolicyMode(tt.input)
		require.NoError(t, err, "input=%q", tt.input)
		assert.Equal(t, tt.expected, m, "input=%q", tt.input)
	}
}

func TestPolicyMode_Validation_UnknownMode_Error(t *testing.T) {
	_, err := policy.ParsePolicyMode("balaced") // typo
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown mode")
}

func TestPolicyMode_FromString(t *testing.T) {
	m, _ := policy.ParsePolicyMode("balanced")
	assert.Equal(t, "balanced", m.String())

	m, _ = policy.ParsePolicyMode("strict")
	assert.Equal(t, "strict", m.String())

	m, _ = policy.ParsePolicyMode("permissive")
	assert.Equal(t, "permissive", m.String())
}

func TestEngine_Mode_DefaultStrict(t *testing.T) {
	e := policy.NewEngine(policy.EngineConfig{Mode: policy.PolicyModeStrict}, nil)
	assert.Equal(t, policy.PolicyModeStrict, e.Mode())
}

func TestEngine_SetMode_ChangesMode(t *testing.T) {
	e := policy.NewEngine(policy.EngineConfig{Mode: policy.PolicyModeStrict}, nil)
	assert.Equal(t, policy.PolicyModeStrict, e.Mode())

	e.SetMode(policy.PolicyModeBalanced)
	assert.Equal(t, policy.PolicyModeBalanced, e.Mode())

	e.SetMode(policy.PolicyModePermissive)
	assert.Equal(t, policy.PolicyModePermissive, e.Mode())
}
