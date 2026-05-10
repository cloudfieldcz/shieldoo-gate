package ai_test

import (
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselineCache_GetReturnsFreshEntry(t *testing.T) {
	c := ai.NewBaselineCache(time.Hour)
	c.Set(42, 5.5, 1.2, 14)

	got, ok := c.Get(42)
	require.True(t, ok)
	assert.InDelta(t, 5.5, got.Mean, 1e-9)
	assert.InDelta(t, 1.2, got.Stddev, 1e-9)
	assert.Equal(t, 14, got.Samples)
	assert.WithinDuration(t, time.Now(), got.RefreshedAt, time.Second)
}

func TestBaselineCache_MissReturnsFalse(t *testing.T) {
	c := ai.NewBaselineCache(time.Hour)
	_, ok := c.Get(99)
	assert.False(t, ok)
}

func TestBaselineCache_StaleEntryIsTreatedAsMiss(t *testing.T) {
	// maxAge=1ns guarantees the entry is stale by the time we Get it.
	c := ai.NewBaselineCache(time.Nanosecond)
	c.Set(7, 1.0, 0.5, 10)
	time.Sleep(10 * time.Millisecond)
	_, ok := c.Get(7)
	assert.False(t, ok, "entry older than maxAge should be a miss")
}

func TestBaselineCache_LenTracksEntries(t *testing.T) {
	c := ai.NewBaselineCache(time.Hour)
	assert.Equal(t, 0, c.Len())
	c.Set(1, 1, 1, 1)
	c.Set(2, 1, 1, 1)
	c.Set(1, 2, 2, 2) // overwrite
	assert.Equal(t, 2, c.Len())
}
