package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
)

func TestHandleCreateOverride_Success(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	body := `{"ecosystem":"pypi","name":"requests","version":"2.32.3","scope":"version","reason":"false positive"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/overrides", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "pypi", resp["ecosystem"])
	assert.Equal(t, "requests", resp["name"])
	assert.Equal(t, "version", resp["scope"])
}

func TestHandleCreateOverride_InvalidScope(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	body := `{"ecosystem":"pypi","name":"requests","version":"2.32.3","scope":"invalid","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/overrides", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleListOverrides_Paginated(t *testing.T) {
	srv, db := newTestServer(t)
	now := time.Now().UTC()

	// Insert 3 overrides
	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
			 VALUES ('pypi', 'pkg', ?, 'version', 'test', 'test', ?, 0)`,
			i, now)
		require.NoError(t, err)
	}

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/overrides?page=1&per_page=2", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data    []any `json:"data"`
		Page    int   `json:"page"`
		PerPage int   `json:"per_page"`
		Total   int   `json:"total"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, 2, resp.PerPage)
}

func TestHandleRevokeOverride_Success(t *testing.T) {
	srv, db := newTestServer(t)
	now := time.Now().UTC()

	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'fp', 'test', ?, 0)`, now)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/overrides/1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify revoked in DB
	var revoked int
	err = db.QueryRow(`SELECT revoked FROM policy_overrides WHERE id = 1`).Scan(&revoked)
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestHandleRevokeOverride_AlreadyRevoked_Returns409(t *testing.T) {
	srv, db := newTestServer(t)
	now := time.Now().UTC()

	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'fp', 'test', ?, 1, ?)`, now, now)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/overrides/1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandleCreateArtifactOverride_ReleasesQuarantined(t *testing.T) {
	srv, db := newTestServer(t)
	now := time.Now().UTC()

	// Insert a quarantined artifact
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES ('pypi:requests:2.32.3', 'pypi', 'requests', '2.32.3', 'https://pypi.org/...', 'abc', 1000, ?, ?, '/tmp/test')`,
		now, now)
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantined_at)
		 VALUES ('pypi:requests:2.32.3', 'QUARANTINED', ?)`, now)
	require.NoError(t, err)

	router := srv.Routes()
	body := `{"reason":"false positive","scope":"version"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/pypi:requests:2.32.3/override", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	// Verify artifact is now CLEAN
	var status string
	err = db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'pypi:requests:2.32.3'`).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "CLEAN", status)
}

// Ensure Server is exported (compile-time check).
var _ = (*api.Server)(nil)
