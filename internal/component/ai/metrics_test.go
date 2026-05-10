package ai_test

import (
	"context"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBudget_DisabledAllowsAll(t *testing.T) {
	b := ai.NewTokenBudget(0)
	for i := 0; i < 10; i++ {
		assert.True(t, b.Allow(), "budget≤0 must always allow")
	}
}

func TestTokenBudget_EnforcesDailyMax(t *testing.T) {
	b := ai.NewTokenBudget(3)
	assert.True(t, b.Allow())
	assert.True(t, b.Allow())
	assert.True(t, b.Allow())
	assert.False(t, b.Allow(), "4th call must be denied")
	assert.Equal(t, int64(3), b.Used(), "Used() must reflect successful spends only")
}

// TestDraft_BudgetExceededReturnsError ensures ErrTokenBudgetExceeded surfaces
// before ErrDrafterDisabled when the drafter is enabled but the budget is
// drained. Without this gate, an enabled drafter without scanner-bridge would
// burn budget on every 503.
func TestDraft_BudgetExceededReturnsError(t *testing.T) {
	d := ai.NewIgnoreReasonDrafter(true).WithTokenBudget(ai.NewTokenBudget(1))
	// First call: exhaust budget. Will return ErrDrafterDisabled because the
	// scanner-bridge stub is not connected — but the budget is now spent.
	_, _ = d.Draft(context.Background(), ai.DraftRequest{})
	// Second call: budget exceeded should win over disabled.
	_, err := d.Draft(context.Background(), ai.DraftRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ai.ErrTokenBudgetExceeded)
}

func TestDraft_DisabledReturnsErr(t *testing.T) {
	d := ai.NewIgnoreReasonDrafter(false)
	_, err := d.Draft(context.Background(), ai.DraftRequest{})
	assert.ErrorIs(t, err, ai.ErrDrafterDisabled)
}
