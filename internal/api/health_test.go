package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestHandleHealth_NoScanEngine_ReturnsOK(t *testing.T) {
	srv := api.NewServer(nil, nil, nil, nil)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

func TestHandlePublicURLs_Empty_ReturnsEmptyStrings(t *testing.T) {
	srv := api.NewServer(nil, nil, nil, nil)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public-urls", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	// All fields should be absent (omitempty) or empty
	assert.Empty(t, body["pypi"])
	assert.Empty(t, body["npm"])
}

func TestHandlePublicURLs_Configured_ReturnsURLs(t *testing.T) {
	srv := api.NewServer(nil, nil, nil, nil)
	srv.SetPublicURLs(config.PublicURLsConfig{
		PyPI:   "https://pypi.example.com",
		NPM:    "https://npm.example.com",
		Docker: "https://cr.example.com",
	})
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public-urls", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "https://pypi.example.com", body["pypi"])
	assert.Equal(t, "https://npm.example.com", body["npm"])
	assert.Equal(t, "https://cr.example.com", body["docker"])
}
