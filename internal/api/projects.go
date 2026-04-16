package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

type projectCreateRequest struct {
	Label       string `json:"label"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
}

type projectUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// handleListProjects returns all projects.
func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.projectSvc.List()
	if err != nil {
		log.Error().Err(err).Msg("api: list projects failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list projects"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

// handleCreateProject explicitly provisions a project (required for strict mode).
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req projectCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
		return
	}
	p, err := s.projectSvc.Create(req.Label, req.DisplayName, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, project.ErrInvalidLabel):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, project.ErrCapReached):
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		default:
			log.Error().Err(err).Str("label", req.Label).Msg("api: create project failed")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create project"})
		}
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// handleGetProject returns a project by ID.
func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	p, err := s.projectSvc.GetByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: get project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get project"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleUpdateProject patches display_name, description, or enabled.
func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	var req projectUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.projectSvc.Update(id, req.DisplayName, req.Description, req.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: update project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update project"})
		return
	}
	p, _ := s.projectSvc.GetByID(id)
	writeJSON(w, http.StatusOK, p)
}

// handleDisableProject soft-disables a project (metadata only in v1.2).
func (s *Server) handleDisableProject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}
	if err := s.projectSvc.Disable(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
			return
		}
		log.Error().Err(err).Int64("id", id).Msg("api: disable project failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable project"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListProjectArtifacts returns the artifacts the project has pulled.
func (s *Server) handleListProjectArtifacts(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid project id"})
		return
	}

	// Use QueryxContext so the GateDB wrapper rebinds ? → $1 for Postgres.
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT a.id, a.ecosystem, a.name, a.version,
		        apu.first_used_at, apu.last_used_at, apu.use_count
		 FROM artifact_project_usage apu
		 JOIN artifacts a ON a.id = apu.artifact_id
		 WHERE apu.project_id = ?
		 ORDER BY apu.last_used_at DESC
		 LIMIT 500`, id)
	if err != nil {
		log.Error().Err(err).Int64("project_id", id).Msg("api: list project artifacts failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list artifacts"})
		return
	}
	defer rows.Close()

	type row struct {
		ID          string   `db:"id"            json:"id"`
		Ecosystem   string   `db:"ecosystem"     json:"ecosystem"`
		Name        string   `db:"name"          json:"name"`
		Version     string   `db:"version"       json:"version"`
		FirstUsedAt string   `db:"first_used_at" json:"first_used_at"`
		LastUsedAt  string   `db:"last_used_at"  json:"last_used_at"`
		UseCount    int64    `db:"use_count"     json:"use_count"`
		Licenses    []string `db:"-"             json:"licenses,omitempty"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.StructScan(&r); err != nil {
			log.Warn().Err(err).Msg("api: scan project artifact row failed")
			continue
		}
		out = append(out, r)
	}

	// Batch-load SBOM licenses.
	if len(out) > 0 {
		licMap := make(map[string]string)
		lRows, lErr := s.db.QueryxContext(r.Context(),
			`SELECT artifact_id, licenses_json FROM sbom_metadata WHERE licenses_json != '[]'`)
		if lErr == nil {
			defer lRows.Close()
			for lRows.Next() {
				var aid, lj string
				if err := lRows.Scan(&aid, &lj); err == nil {
					licMap[aid] = lj
				}
			}
		}
		for i := range out {
			if lj, ok := licMap[out[i].ID]; ok {
				var lics []string
				if json.Unmarshal([]byte(lj), &lics) == nil && len(lics) > 0 {
					out[i].Licenses = lics
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"artifacts": out})
}
