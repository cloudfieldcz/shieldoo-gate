package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
)

func TestHandleGetPolicyMode_ReturnsCurrentMode(t *testing.T) {
	eng := policy.NewEngine(policy.EngineConfig{Mode: policy.PolicyModeBalanced}, nil)
	srv := api.NewServer(nil, nil, nil, eng)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/policy-mode", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "balanced", body["mode"])
}

func TestHandleSetPolicyMode_ValidMode_UpdatesEngine(t *testing.T) {
	eng := policy.NewEngine(policy.EngineConfig{Mode: policy.PolicyModeStrict}, nil)
	srv := api.NewServer(nil, nil, nil, eng)
	router := srv.Routes()

	body := `{"mode":"permissive"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/policy-mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "permissive", resp["mode"])

	// Verify engine was updated.
	assert.Equal(t, policy.PolicyModePermissive, eng.Mode())
}

func TestHandleSetPolicyMode_InvalidMode_Returns400(t *testing.T) {
	eng := policy.NewEngine(policy.EngineConfig{Mode: policy.PolicyModeStrict}, nil)
	srv := api.NewServer(nil, nil, nil, eng)
	router := srv.Routes()

	body := `{"mode":"yolo"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/policy-mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Engine should remain unchanged.
	assert.Equal(t, policy.PolicyModeStrict, eng.Mode())
}
