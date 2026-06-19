package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// Migration 039 must add a NOT NULL id_token column and the session must round-trip it.
func TestGateDB_SessionIDToken_RoundTrips(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	now := time.Now().UTC()
	sess := model.Session{
		ID:         "sess-1",
		Subject:    "sub-1",
		Email:      "op@example.com",
		Name:       "Op",
		IDToken:    "raw.id.token",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}
	require.NoError(t, db.CreateSession(sess))

	got, err := db.GetSession("sess-1")
	require.NoError(t, err)
	assert.Equal(t, "raw.id.token", got.IDToken)
}
