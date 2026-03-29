package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

func setupTestServer(t *testing.T) (*Server, *config.GateDB) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	s := &Server{db: db}
	return s, db
}

func TestCreateAPIKey_GeneratesValidKey(t *testing.T) {
	s, _ := setupTestServer(t)

	body := `{"name":"ci-pipeline"}`
	req := httptest.NewRequest("POST", "/api/v1/api-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp apiKeyCreateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ci-pipeline", resp.Name)
	assert.True(t, resp.Enabled)
	assert.True(t, strings.HasPrefix(resp.Token, "sgw_"), "token should have sgw_ prefix")
	assert.Greater(t, len(resp.Token), 40, "token should be at least 40 chars")
}

func TestCreateAPIKey_ReturnsPlaintextOnce(t *testing.T) {
	s, db := setupTestServer(t)

	body := `{"name":"one-time"}`
	req := httptest.NewRequest("POST", "/api/v1/api-keys", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleCreateAPIKey(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp apiKeyCreateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Token)

	// Verify hash is in DB, not plaintext.
	keys, err := db.ListAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	// The key_hash should be a hex SHA-256 (64 chars).
	assert.Len(t, keys[0].KeyHash, 64)
	assert.NotEqual(t, resp.Token, keys[0].KeyHash, "plaintext should not be stored as hash")
}

func TestListAPIKeys_NoHashes(t *testing.T) {
	s, db := setupTestServer(t)

	_, err := db.CreateAPIKey("somehash", "key1", "user@example.com")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	s.handleListAPIKeys(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var keys []model.APIKey
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&keys))
	require.Len(t, keys, 1)
	assert.Equal(t, "key1", keys[0].Name)
	// KeyHash should be empty due to json:"-" tag.
	assert.Empty(t, keys[0].KeyHash, "hash should never appear in API response")
}

func TestRevokeAPIKey_DisablesKey(t *testing.T) {
	s, db := setupTestServer(t)

	id, err := db.CreateAPIKey("revhash", "to-revoke", "user@example.com")
	require.NoError(t, err)

	// Set up chi URL param.
	r := chi.NewRouter()
	r.Delete("/api/v1/api-keys/{id}", s.handleRevokeAPIKey)

	req := httptest.NewRequest("DELETE", "/api/v1/api-keys/"+itoa(id), nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify key is disabled.
	_, err = db.GetAPIKeyByHash("revhash")
	assert.Error(t, err, "revoked key should not be found")
}

func TestCreateAPIKey_MissingName_Returns400(t *testing.T) {
	s, _ := setupTestServer(t)

	body := `{"name":""}`
	req := httptest.NewRequest("POST", "/api/v1/api-keys", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func itoa(i int64) string {
	return fmt.Sprintf("%d", i)
}
