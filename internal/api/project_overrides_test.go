package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

// newTestServerWithProjects extends newTestServer with a project service so
// the per-project override + artifact-list handlers work end to end.
func newTestServerWithProjects(t *testing.T) (*api.Server, *config.GateDB, project.Service) {
	t.Helper()
	srv, db := newTestServer(t)
	svc, err := project.NewService(project.Config{Mode: project.ModeStrict}, db)
	require.NoError(t, err)
	t.Cleanup(svc.Stop)
	srv.SetProjectService(svc)
	return srv, db, svc
}

func seedProject(t *testing.T, svc project.Service, label string) int64 {
	t.Helper()
	p, err := svc.Create(label, "", "")
	require.NoError(t, err)
	return p.ID
}

func TestCreateProjectOverride_Allow_PersistsAndAudits(t *testing.T) {
	srv, db, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	body := map[string]string{
		"ecosystem": "npm",
		"name":      "left-pad",
		"scope":     "package",
		"kind":      "allow",
		"reason":    "approved by legal",
	}
	resp := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())

	var got map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
	assert.Equal(t, float64(projectID), got["project_id"])
	assert.Equal(t, "allow", got["kind"])
	assert.Equal(t, "package", got["scope"])

	// Row landed in DB with correct project_id and kind.
	var n int
	require.NoError(t, db.Get(&n,
		`SELECT COUNT(*) FROM policy_overrides WHERE project_id = ? AND kind = 'allow' AND name = 'left-pad' AND revoked = FALSE`,
		projectID))
	assert.Equal(t, 1, n)

	// Audit row written.
	var auditCount int
	require.NoError(t, db.Get(&auditCount,
		`SELECT COUNT(*) FROM audit_log WHERE event_type = ? AND project_id = ?`,
		string(model.EventOverrideCreated), projectID))
	assert.Equal(t, 1, auditCount)
}

func TestCreateProjectOverride_VersionScopeRequiresVersion(t *testing.T) {
	srv, _, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	body := map[string]string{
		"ecosystem": "pypi",
		"name":      "requests",
		"scope":     "version", // no version supplied
		"kind":      "deny",
		"reason":    "banned",
	}
	resp := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "version is required")
}

func TestCreateProjectOverride_DuplicateActiveReturns409(t *testing.T) {
	srv, _, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	body := map[string]string{
		"ecosystem": "npm", "name": "lodash", "scope": "package", "kind": "deny", "reason": "banned",
	}
	resp := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
	require.Equal(t, http.StatusCreated, resp.Code)

	// Second create with the same kind/scope/package — must 409.
	resp = doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
	assert.Equal(t, http.StatusConflict, resp.Code)
}

func TestCreateProjectOverride_AllowAndDenyCanCoexist(t *testing.T) {
	// The unique-active index keys on kind, so an allow and a deny on the
	// same package are independent rows. Useful when a user wants to layer
	// "deny version 1.0.0 specifically, but allow the package generally" —
	// the deny wins by precedence.
	srv, _, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	for _, kind := range []string{"allow", "deny"} {
		body := map[string]string{
			"ecosystem": "npm", "name": "foo", "scope": "package", "kind": kind, "reason": "test",
		}
		resp := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
		require.Equal(t, http.StatusCreated, resp.Code, "kind=%s body=%s", kind, resp.Body.String())
	}
}

func TestCreateProjectOverride_RejectsUnknownProject(t *testing.T) {
	srv, _, _ := newTestServerWithProjects(t)
	body := map[string]string{
		"ecosystem": "npm", "name": "x", "scope": "package", "kind": "allow", "reason": "x",
	}
	resp := doJSON(t, srv, http.MethodPost, "/api/v1/projects/9999/overrides", body)
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestRevokeProjectOverride_MarksRowAndAudits(t *testing.T) {
	srv, db, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	body := map[string]string{
		"ecosystem": "npm", "name": "left-pad", "scope": "package", "kind": "allow", "reason": "test",
	}
	createResp := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", projectID), body)
	require.Equal(t, http.StatusCreated, createResp.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &created))
	overrideID := int64(created["id"].(float64))

	revoke := doJSON(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/overrides/%d/revoke", projectID, overrideID),
		map[string]string{"reason": "no longer needed"})
	require.Equal(t, http.StatusOK, revoke.Code, revoke.Body.String())

	var revoked bool
	require.NoError(t, db.Get(&revoked, `SELECT revoked FROM policy_overrides WHERE id = ?`, overrideID))
	assert.True(t, revoked)

	var revokeAudit int
	require.NoError(t, db.Get(&revokeAudit,
		`SELECT COUNT(*) FROM audit_log WHERE event_type = ? AND project_id = ?`,
		string(model.EventOverrideRevoked), projectID))
	assert.Equal(t, 1, revokeAudit)
}

func TestRevokeProjectOverride_OtherProject_Returns404(t *testing.T) {
	srv, _, svc := newTestServerWithProjects(t)
	a := seedProject(t, svc, "acme")
	b := seedProject(t, svc, "beta")

	create := doJSON(t, srv, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/overrides", a), map[string]string{
		"ecosystem": "npm", "name": "lodash", "scope": "package", "kind": "deny", "reason": "test",
	})
	require.Equal(t, http.StatusCreated, create.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(create.Body.Bytes(), &got))
	overrideID := int64(got["id"].(float64))

	// Project B tries to revoke project A's override.
	revoke := doJSON(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/overrides/%d/revoke", b, overrideID), nil)
	assert.Equal(t, http.StatusNotFound, revoke.Code)
}

func TestListProjectArtifacts_MergesPulledBlockedAndOverrides(t *testing.T) {
	srv, db, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	now := time.Now().UTC()

	// 1) Pulled artifact (will appear with decision=CLEAN).
	insertTestArtifact(t, db, "npm:axios:1.6.0", "npm", "axios", "1.6.0")
	_, err := db.Exec(
		`INSERT INTO artifact_project_usage (project_id, artifact_id, first_used_at, last_used_at, use_count)
		 VALUES (?, ?, ?, ?, 1)`, projectID, "npm:axios:1.6.0", now, now)
	require.NoError(t, err)

	// 2) Blocked-by-license entry (audit_log row only, no pulled record).
	insertTestArtifact(t, db, "pypi:gpltool:1.0", "pypi", "gpltool", "1.0")
	_, err = db.Exec(
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, project_id)
		 VALUES (?, ?, ?, 'license: GPL-3.0-only blocked by policy', ?)`,
		now, string(model.EventLicenseBlocked), "pypi:gpltool:1.0", projectID)
	require.NoError(t, err)

	// 3) Active per-project allow override on a package never pulled.
	createResp := doJSON(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/overrides", projectID),
		map[string]string{"ecosystem": "npm", "name": "left-pad", "scope": "package", "kind": "allow", "reason": "test"})
	require.Equal(t, http.StatusCreated, createResp.Code)

	resp := doRequest(t, srv, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/artifacts", projectID), nil)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var listResp struct {
		Artifacts []map[string]any `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listResp))
	require.Len(t, listResp.Artifacts, 3)

	byName := map[string]map[string]any{}
	for _, row := range listResp.Artifacts {
		byName[row["name"].(string)] = row
	}

	require.Contains(t, byName, "axios")
	assert.Equal(t, "CLEAN", byName["axios"]["decision"])

	require.Contains(t, byName, "gpltool")
	assert.Equal(t, "BLOCKED_LICENSE", byName["gpltool"]["decision"])
	assert.Equal(t, "GPL-3.0-only", byName["gpltool"]["blocked_license"])

	require.Contains(t, byName, "left-pad")
	assert.Equal(t, "WHITELISTED", byName["left-pad"]["decision"])
}

func TestListProjectArtifacts_PackageScopeOverride_AbsorbsVersionRows(t *testing.T) {
	// Regression: a "any version" (package-scope) whitelist used to render
	// twice — once as the blocked concrete-version row and once as the
	// version="" override row. The package-scope override must absorb every
	// (ecosystem, name, *) sibling so the user sees a single WHITELISTED row.
	srv, db, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	now := time.Now().UTC()

	// Two blocked attempts on different versions plus one pulled clean row.
	insertTestArtifact(t, db, "npm:chalk:5.4.1", "npm", "chalk", "5.4.1")
	insertTestArtifact(t, db, "npm:chalk:5.3.0", "npm", "chalk", "5.3.0")
	insertTestArtifact(t, db, "npm:chalk:4.0.0", "npm", "chalk", "4.0.0")

	for _, ver := range []string{"5.4.1", "5.3.0"} {
		_, err := db.Exec(
			`INSERT INTO audit_log (ts, event_type, artifact_id, reason, project_id)
			 VALUES (?, ?, ?, 'license: MIT blocked by policy', ?)`,
			now, string(model.EventLicenseBlocked), "npm:chalk:"+ver, projectID)
		require.NoError(t, err)
	}
	_, err := db.Exec(
		`INSERT INTO artifact_project_usage (project_id, artifact_id, first_used_at, last_used_at, use_count)
		 VALUES (?, ?, ?, ?, 3)`, projectID, "npm:chalk:4.0.0", now, now)
	require.NoError(t, err)

	// Whitelist any version.
	createResp := doJSON(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/overrides", projectID),
		map[string]string{"ecosystem": "npm", "name": "chalk", "scope": "package", "kind": "allow", "reason": "approved"})
	require.Equal(t, http.StatusCreated, createResp.Code, createResp.Body.String())

	resp := doRequest(t, srv, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/artifacts", projectID), nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var listResp struct {
		Artifacts []map[string]any `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listResp))
	require.Len(t, listResp.Artifacts, 1, "package-scope override must collapse all version siblings into one row")

	row := listResp.Artifacts[0]
	assert.Equal(t, "WHITELISTED", row["decision"])
	assert.Equal(t, "package", row["override_scope"])
	// Aggregated stats: 2 blocks + 3 uses preserved across the merged rows.
	assert.EqualValues(t, 2, row["block_count"])
	assert.EqualValues(t, 3, row["use_count"])
}

func TestListProjectArtifacts_OverrideUpgradesBlockedDecision(t *testing.T) {
	// A package that's both license-blocked AND has an active allow override
	// should display as WHITELISTED (override wins over block).
	srv, db, svc := newTestServerWithProjects(t)
	projectID := seedProject(t, svc, "acme")

	now := time.Now().UTC()
	insertTestArtifact(t, db, "pypi:foo:1.0", "pypi", "foo", "1.0")
	_, err := db.Exec(
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, project_id)
		 VALUES (?, ?, ?, 'license: AGPL-3.0 blocked by policy', ?)`,
		now, string(model.EventLicenseBlocked), "pypi:foo:1.0", projectID)
	require.NoError(t, err)

	createResp := doJSON(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/overrides", projectID),
		map[string]string{"ecosystem": "pypi", "name": "foo", "version": "1.0", "scope": "version", "kind": "allow", "reason": "approved"})
	require.Equal(t, http.StatusCreated, createResp.Code, createResp.Body.String())

	resp := doRequest(t, srv, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/artifacts", projectID), nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var listResp struct {
		Artifacts []map[string]any `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listResp))
	require.Len(t, listResp.Artifacts, 1)
	assert.Equal(t, "WHITELISTED", listResp.Artifacts[0]["decision"])
	assert.Equal(t, "AGPL-3.0", listResp.Artifacts[0]["blocked_license"])
}

// --- HTTP helpers --------------------------------------------------------

func doRequest(t *testing.T, srv *api.Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func doJSON(t *testing.T, srv *api.Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		return doRequest(t, srv, method, path, nil)
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return doRequest(t, srv, method, path, encoded)
}
