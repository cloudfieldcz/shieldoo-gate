package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
)

// VulnDeps bundles the optional vuln-scan dependencies wired into the API server.
type VulnDeps struct {
	Component   component.Service
	ScanService component.ScanService
	Ignore      component.IgnoreService
	Store       *component.Store
	Audit       *auth.AuditWriter
}

// SetVulnDeps wires the vuln-scan service implementations into the api.Server.
func (s *Server) SetVulnDeps(d VulnDeps) {
	s.vulnDeps = d
}

// VulnEnabled returns true when vuln-scan dependencies have been wired.
func (s *Server) VulnEnabled() bool {
	return s.vulnDeps.Component != nil
}

// componentResponse is the wire shape returned to the admin UI.
type componentResponse struct {
	ID          int64  `json:"id"`
	ProjectID   int64  `json:"project_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Ecosystem   string `json:"ecosystem"`
	RepoURL     string `json:"repo_url,omitempty"`
	AIEnabled   bool   `json:"ai_enabled"`
	Enabled     bool   `json:"enabled"`
	LastScanID  *int64 `json:"last_scan_id,omitempty"`
}

func toComponentResponse(c *component.Component) componentResponse {
	return componentResponse{
		ID:          c.ID,
		ProjectID:   c.ProjectID,
		Name:        c.Name,
		DisplayName: c.DisplayName,
		Description: c.Description,
		Ecosystem:   c.Ecosystem,
		RepoURL:     c.RepoURL,
		AIEnabled:   c.AIEnabled,
		Enabled:     c.Enabled,
		LastScanID:  c.LastScanID,
	}
}

// handleListVulnerabilities returns the top-level Screen 1 list rows.
func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	q := r.URL.Query()
	filter := component.ListFilter{
		ProjectLabel:  q.Get("project"),
		Ecosystem:     q.Get("ecosystem"),
		SeverityFloor: strings.ToUpper(q.Get("severity_floor")),
		HasNew:        q.Get("has_new") == "true" || q.Get("has_new") == "1",
		Query:         q.Get("q"),
		Cursor:        q.Get("cursor"),
	}
	if v, _ := strconv.Atoi(q.Get("limit")); v > 0 {
		filter.Limit = v
	}
	if v, _ := strconv.Atoi(q.Get("offset")); v > 0 {
		filter.Offset = v
	}
	rows, err := s.vulnDeps.Component.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"items": rows}
	// next_cursor when cursor mode requested AND we filled the page (likely more rows).
	// Clients page until next_cursor is absent. The opaque value is the last
	// row's id — re-encoded on each round-trip to leave room for richer cursors
	// later without a wire-format break.
	if filter.Cursor != "" || (filter.Limit > 0 && len(rows) >= filter.Limit) {
		// Keyset cursor mode: emit next_cursor when the page filled and a tail
		// exists. The handler doesn't know whether a tail exists, so the simple
		// rule "page filled → likely more" is good enough; the client keeps
		// paging until it gets a short page.
		if len(rows) > 0 && (filter.Cursor != "" || (filter.Limit > 0 && len(rows) == filter.Limit)) {
			resp["next_cursor"] = strconv.FormatInt(rows[len(rows)-1].ID, 10)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleGetComponent returns a single component by id.
func (s *Server) handleGetComponent(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.vulnDeps.Component.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, component.ErrNotFound) {
			writeError(w, http.StatusNotFound, "component not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toComponentResponse(c))
}

// handleListComponentsByProject returns components owned by a project.
func (s *Server) handleListComponentsByProject(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	projectID, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	rows, err := s.vulnDeps.Component.ListByProject(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]componentResponse, len(rows))
	for i, c := range rows {
		out[i] = toComponentResponse(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// componentUpdateRequest is the JSON body for PATCH /vulnerabilities/components/:id.
type componentUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	RepoURL     *string `json:"repo_url,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	AIEnabled   *bool   `json:"ai_enabled,omitempty"`
}

func (s *Server) handleUpdateComponent(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req componentUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.vulnDeps.Component.Update(r.Context(), id, req.DisplayName, req.Description, req.RepoURL, req.Enabled, req.AIEnabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListScanRuns returns the Scan history tab.
func (s *Server) handleListScanRuns(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	limit := 100
	if v, _ := strconv.Atoi(r.URL.Query().Get("limit")); v > 0 {
		limit = v
	}
	var cursor int64
	if cs := r.URL.Query().Get("cursor"); cs != "" {
		v, err := strconv.ParseInt(cs, 10, 64)
		if err != nil || v <= 0 {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		cursor = v
	}
	runs, err := s.vulnDeps.ScanService.ListByComponent(r.Context(), id, cursor, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"items": runs}
	// Emit next_cursor when the page is full — the client keeps paging until
	// it receives a short page (no next_cursor).
	if len(runs) > 0 && len(runs) == limit {
		resp["next_cursor"] = strconv.FormatInt(runs[len(runs)-1].ID, 10)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleGetScanRun returns a single run.
func (s *Server) handleGetScanRun(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	run, err := s.vulnDeps.ScanService.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleGetScanRunFindings returns findings for a run.
func (s *Server) handleGetScanRunFindings(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	findings, err := s.vulnDeps.ScanService.Findings(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings})
}

// handleGetScanRunSBOM streams the SBOM blob.
func (s *Server) handleGetScanRunSBOM(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	body, err := s.vulnDeps.ScanService.GetSBOM(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// pathInt64 extracts a path parameter as int64.
func pathInt64(r *http.Request, name string) (int64, error) {
	raw := chi.URLParam(r, name)
	if raw == "" {
		return 0, errInvalidPath
	}
	return strconv.ParseInt(raw, 10, 64)
}

var errInvalidPath = errors.New("invalid path param")
