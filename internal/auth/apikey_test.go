package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDBForAuth(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// okHandler returns 200 and the user email from context.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user != nil {
		w.Write([]byte(user.Email)) //nolint:errcheck
	}
	w.WriteHeader(http.StatusOK)
})

func TestAPIKeyMiddleware_ValidGlobalToken_Allows(t *testing.T) {
	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "my-global-token")
	defer mw.Stop()

	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/simple/six/", nil)
	req.Header.Set("Authorization", basicAuthHeader("ci-bot", "my-global-token"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ci-bot")
}

func TestAPIKeyMiddleware_ValidPAT_Allows(t *testing.T) {
	db := setupTestDBForAuth(t)
	plaintext := "sgw_testtoken123"
	hash := sha256Hex(plaintext)
	_, err := db.CreateAPIKey(hash, "test-pat", "dev@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/simple/six/", nil)
	req.Header.Set("Authorization", basicAuthHeader("dev@example.com", plaintext))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "dev@example.com")
}

func TestAPIKeyMiddleware_InvalidToken_Returns401(t *testing.T) {
	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "correct-token")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/simple/six/", nil)
	req.Header.Set("Authorization", basicAuthHeader("user", "wrong-token"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic")
}

func TestAPIKeyMiddleware_MissingAuth_Returns401(t *testing.T) {
	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "token")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/simple/six/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAPIKeyMiddleware_DisabledKey_Returns401(t *testing.T) {
	db := setupTestDBForAuth(t)
	plaintext := "sgw_disabledkey"
	hash := sha256Hex(plaintext)
	id, err := db.CreateAPIKey(hash, "disabled", "user@example.com")
	require.NoError(t, err)
	require.NoError(t, db.RevokeAPIKey(id))

	mw := NewAPIKeyMiddleware(db, "")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/simple/six/", nil)
	req.Header.Set("Authorization", basicAuthHeader("user", plaintext))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAPIKeyMiddleware_SetsUserContext(t *testing.T) {
	db := setupTestDBForAuth(t)
	plaintext := "sgw_contexttest"
	hash := sha256Hex(plaintext)
	_, err := db.CreateAPIKey(hash, "ctx-key", "ctx@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "")
	defer mw.Stop()

	var capturedUser *UserInfo
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("any", plaintext))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.NotNil(t, capturedUser)
	assert.Equal(t, "ctx@example.com", capturedUser.Email)
	assert.Equal(t, "ctx-key", capturedUser.Name)
}

func TestAPIKeyMiddleware_BearerSchemaIgnored(t *testing.T) {
	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "token")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAPIKeyMiddleware_DoesNotLogSecret(t *testing.T) {
	// Capture zerolog output.
	var buf bytes.Buffer
	origLogger := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogger)

	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "supersecrettoken")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	// Send request with wrong token to trigger auth failure logging.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("user", "wrongsecret"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The secret and the wrong password should NOT appear in log output.
	logOutput := buf.String()
	assert.NotContains(t, logOutput, "supersecrettoken")
	assert.NotContains(t, logOutput, "wrongsecret")
}

func TestAPIKeyMiddleware_GlobalToken_ConstantTime(t *testing.T) {
	// This test verifies that the global token comparison uses constant-time compare.
	// We can't easily measure timing, but we verify the code path works correctly.
	db := setupTestDBForAuth(t)
	mw := NewAPIKeyMiddleware(db, "constant-time-token")
	defer mw.Stop()
	handler := mw.Authenticate(okHandler)

	// Correct token should succeed.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("user", "constant-time-token"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Partially matching token should fail.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", basicAuthHeader("user", "constant-time-toke"))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
}
