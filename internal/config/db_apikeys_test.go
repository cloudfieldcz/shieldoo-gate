package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *GateDB {
	t.Helper()
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAPIKey_InsertsAndReturnsID(t *testing.T) {
	db := setupTestDB(t)

	id, err := db.CreateAPIKey("abc123hash", "test-key", "user@example.com")
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))
}

func TestGetAPIKeyByHash_Found(t *testing.T) {
	db := setupTestDB(t)

	_, err := db.CreateAPIKey("hash1", "my-key", "owner@example.com")
	require.NoError(t, err)

	key, err := db.GetAPIKeyByHash("hash1")
	require.NoError(t, err)
	assert.Equal(t, "my-key", key.Name)
	assert.Equal(t, "owner@example.com", key.OwnerEmail)
	assert.True(t, key.Enabled)
}

func TestGetAPIKeyByHash_NotFound(t *testing.T) {
	db := setupTestDB(t)

	_, err := db.GetAPIKeyByHash("nonexistent")
	assert.Error(t, err)
}

func TestGetAPIKeyByHash_DisabledKeyNotReturned(t *testing.T) {
	db := setupTestDB(t)

	id, err := db.CreateAPIKey("hashX", "revoked-key", "user@example.com")
	require.NoError(t, err)
	require.NoError(t, db.RevokeAPIKey(id))

	_, err = db.GetAPIKeyByHash("hashX")
	assert.Error(t, err)
}

func TestListAPIKeys_ReturnsAll(t *testing.T) {
	db := setupTestDB(t)

	_, err := db.CreateAPIKey("h1", "key1", "a@example.com")
	require.NoError(t, err)
	_, err = db.CreateAPIKey("h2", "key2", "b@example.com")
	require.NoError(t, err)

	keys, err := db.ListAPIKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestRevokeAPIKey_DisablesKey(t *testing.T) {
	db := setupTestDB(t)

	id, err := db.CreateAPIKey("hash_revoke", "to-revoke", "user@example.com")
	require.NoError(t, err)

	err = db.RevokeAPIKey(id)
	require.NoError(t, err)

	// Key should not be findable by hash (disabled).
	_, err = db.GetAPIKeyByHash("hash_revoke")
	assert.Error(t, err)
}

func TestRevokeAPIKey_NotFound(t *testing.T) {
	db := setupTestDB(t)

	err := db.RevokeAPIKey(99999)
	assert.Error(t, err)
}

func TestTouchAPIKeyLastUsed_UpdatesTimestamp(t *testing.T) {
	db := setupTestDB(t)

	id, err := db.CreateAPIKey("hash_touch", "touch-key", "user@example.com")
	require.NoError(t, err)

	// Initially last_used_at is nil.
	key, err := db.GetAPIKeyByHash("hash_touch")
	require.NoError(t, err)
	assert.Nil(t, key.LastUsedAt)

	// Touch and verify.
	require.NoError(t, db.TouchAPIKeyLastUsed(id))
	key, err = db.GetAPIKeyByHash("hash_touch")
	require.NoError(t, err)
	assert.NotNil(t, key.LastUsedAt)
}
