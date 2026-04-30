package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
)

// withChiURLParam injects {key=value} into chi's URL-param context so an
// in-process call to a handler that uses chi.URLParam resolves the value.
func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// insertTestProject inserts a project row whose `created_via` simulates either
// a lazy auto-created project or an admin-created one. Returns the new row id.
func insertTestProject(t *testing.T, db *config.GateDB, label, createdVia string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, created_via, created_at, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		label, label, createdVia, time.Now().UTC(),
	)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestPutProjectLicensePolicy_OverrideAllowed_LazyProject(t *testing.T) {
	// ADR-004: per-project overrides are no longer gated on projects.mode.
	// A PUT with mode=override on a lazy-created project must succeed.
	s, db := setupTestServer(t)
	id := insertTestProject(t, db, "mvaiag", "lazy")
	idStr := strconv.FormatInt(id, 10)

	body := `{"mode":"override","blocked":["GPL-3.0-only"],"warned":[],"allowed":["MIT","Apache-2.0"],"unknown_action":"warn"}`
	req := httptest.NewRequest("PUT", "/api/v1/projects/"+idStr+"/license-policy", strings.NewReader(body))
	req = withUser(req, "admin@example.com", "Admin")
	req = withChiURLParam(req, "id", idStr)
	rec := httptest.NewRecorder()

	s.handlePutProjectLicensePolicy(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"override must be accepted on a lazy-created project (ADR-004); body=%s", rec.Body.String())

	var view licensePolicyView
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&view))
	assert.Equal(t, "override", view.Mode)
	assert.Equal(t, "project-override", view.EffectiveSource)
	assert.Equal(t, []string{"MIT", "Apache-2.0"}, view.Allowed)
}

func TestGetProjectLicensePolicy_NoStrictRequiredField(t *testing.T) {
	// ADR-004: strict_required is no longer emitted. The response must not
	// contain the field even on a lazy-created project with a stored override.
	s, db := setupTestServer(t)
	id := insertTestProject(t, db, "mvaiag", "lazy")
	idStr := strconv.FormatInt(id, 10)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO project_license_policy
		   (project_id, mode, blocked_json, warned_json, allowed_json, unknown_action, updated_at, updated_by)
		 VALUES (?, 'override', '[]', '[]', '["MIT"]', 'warn', ?, 'admin@example.com')`,
		id, now,
	)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/projects/"+idStr+"/license-policy", nil)
	req = withChiURLParam(req, "id", idStr)
	rec := httptest.NewRecorder()
	s.handleGetProjectLicensePolicy(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, present := raw["strict_required"]
	assert.False(t, present, "strict_required must not be present in the response (ADR-004)")
	assert.Equal(t, "project-override", raw["effective_source"])
}

func TestResolver_LazyMode_HonorsProjectOverride(t *testing.T) {
	// ADR-004: the resolver no longer gates per-project overrides on
	// projects.mode. A stored override row must be honored regardless.
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	id := insertTestProject(t, db, "mvaiag", "lazy")
	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO project_license_policy
		   (project_id, mode, blocked_json, warned_json, allowed_json, unknown_action, updated_at, updated_by)
		 VALUES (?, 'override', '["GPL-3.0-only"]', '[]', '["MIT"]', 'warn', ?, 'admin@example.com')`,
		id, now,
	)
	require.NoError(t, err)

	resolver := license.NewResolver(db, license.ResolverConfig{
		Global: license.Policy{Blocked: []string{"AGPL-3.0-only"}, Source: "global"},
	})
	pol, err := resolver.ResolveForProject(t.Context(), id, "mvaiag")
	require.NoError(t, err)
	assert.Equal(t, []string{"GPL-3.0-only"}, pol.Blocked, "override blocklist must win over global")
	assert.Equal(t, []string{"MIT"}, pol.Allowed)
}
