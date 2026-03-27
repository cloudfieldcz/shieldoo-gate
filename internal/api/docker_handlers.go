package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
)

// handleListDockerRepositories returns all Docker repositories, optionally filtered by registry.
// GET /api/v1/docker/repositories?registry=ghcr.io
func (s *Server) handleListDockerRepositories(w http.ResponseWriter, r *http.Request) {
	registry := r.URL.Query().Get("registry")

	repos, err := docker.ListRepositories(s.db, registry)
	if err != nil {
		log.Error().Err(err).Msg("api: listing docker repositories")
		writeError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	if repos == nil {
		repos = []docker.DockerRepository{}
	}

	writeJSON(w, http.StatusOK, repos)
}

// handleListDockerTags returns all tags for a given Docker repository.
// GET /api/v1/docker/repositories/{id}/tags
func (s *Server) handleListDockerTags(w http.ResponseWriter, r *http.Request) {
	repoID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	// Verify the repository exists.
	_, err = docker.GetRepositoryByID(s.db, repoID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "repository not found")
			return
		}
		log.Error().Err(err).Int64("repo_id", repoID).Msg("api: getting docker repository")
		writeError(w, http.StatusInternalServerError, "failed to get repository")
		return
	}

	tags, err := docker.ListTags(s.db, repoID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Msg("api: listing docker tags")
		writeError(w, http.StatusInternalServerError, "failed to list tags")
		return
	}

	if tags == nil {
		tags = []docker.DockerTag{}
	}

	writeJSON(w, http.StatusOK, tags)
}

// createTagRequest is the JSON body for POST /api/v1/docker/repositories/{id}/tags.
type createTagRequest struct {
	Tag            string `json:"tag"`
	ManifestDigest string `json:"manifest_digest"`
}

// handleCreateDockerTag creates or moves a tag on a Docker repository.
// POST /api/v1/docker/repositories/{id}/tags
func (s *Server) handleCreateDockerTag(w http.ResponseWriter, r *http.Request) {
	repoID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	var req createTagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Tag == "" || req.ManifestDigest == "" {
		writeError(w, http.StatusBadRequest, "tag and manifest_digest are required")
		return
	}

	// Verify the repository exists.
	_, err = docker.GetRepositoryByID(s.db, repoID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "repository not found")
			return
		}
		log.Error().Err(err).Int64("repo_id", repoID).Msg("api: getting docker repository")
		writeError(w, http.StatusInternalServerError, "failed to get repository")
		return
	}

	// Check if the tag already exists with a different digest (tag move).
	existingTags, err := docker.ListTags(s.db, repoID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Msg("api: listing tags for move detection")
		writeError(w, http.StatusInternalServerError, "failed to check existing tags")
		return
	}

	tagMoved := false
	for _, t := range existingTags {
		if t.Tag == req.Tag && t.ManifestDigest != req.ManifestDigest {
			tagMoved = true
			break
		}
	}

	if err := docker.UpsertTag(s.db, repoID, req.Tag, req.ManifestDigest, ""); err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Str("tag", req.Tag).Msg("api: upserting docker tag")
		writeError(w, http.StatusInternalServerError, "failed to create tag")
		return
	}

	resp := map[string]any{
		"tag":             req.Tag,
		"manifest_digest": req.ManifestDigest,
		"tag_moved":       tagMoved,
	}

	if tagMoved {
		log.Info().
			Int64("repo_id", repoID).
			Str("tag", req.Tag).
			Str("new_digest", req.ManifestDigest).
			Msg("api: docker tag moved, re-scan recommended")
		resp["rescan_triggered"] = true
	}

	writeJSON(w, http.StatusCreated, resp)
}

// handleDeleteDockerTag removes a tag from a Docker repository.
// DELETE /api/v1/docker/repositories/{id}/tags/{tag}
func (s *Server) handleDeleteDockerTag(w http.ResponseWriter, r *http.Request) {
	repoID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	tag := chi.URLParam(r, "tag")
	if tag == "" {
		writeError(w, http.StatusBadRequest, "tag is required")
		return
	}

	if err := docker.DeleteTag(s.db, repoID, tag); err != nil {
		// DeleteTag returns an error if the tag was not found.
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "tag not found")
			return
		}
		// The function uses a custom "not found" error message, check for it.
		if err.Error() == "docker: tag "+tag+" not found" {
			writeError(w, http.StatusNotFound, "tag not found")
			return
		}
		log.Error().Err(err).Int64("repo_id", repoID).Str("tag", tag).Msg("api: deleting docker tag")
		writeError(w, http.StatusInternalServerError, "failed to delete tag")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDockerSync triggers a manual sync for a Docker repository.
// POST /api/v1/docker/sync/{id}
func (s *Server) handleDockerSync(w http.ResponseWriter, r *http.Request) {
	repoID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	if s.syncSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "sync service is not enabled")
		return
	}

	// Verify the repository exists.
	repo, err := docker.GetRepositoryByID(s.db, repoID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "repository not found")
			return
		}
		log.Error().Err(err).Int64("repo_id", repoID).Msg("api: getting docker repository for sync")
		writeError(w, http.StatusInternalServerError, "failed to get repository")
		return
	}

	// Trigger sync in background.
	go s.syncSvc.SyncRepositoryByID(context.Background(), repo.ID)

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "sync queued for repository " + repo.Name,
	})
}

// registryResponse is the JSON shape for a single registry entry in the registries list.
type registryResponse struct {
	Host string `json:"host"`
	URL  string `json:"url"`
}

// handleListDockerRegistries returns the list of allowed Docker registries from config.
// GET /api/v1/docker/registries
func (s *Server) handleListDockerRegistries(w http.ResponseWriter, r *http.Request) {
	registries := make([]registryResponse, 0, len(s.dockerConfig.AllowedRegistries))
	for _, reg := range s.dockerConfig.AllowedRegistries {
		registries = append(registries, registryResponse{
			Host: reg.Host,
			URL:  reg.URL,
		})
	}

	writeJSON(w, http.StatusOK, registries)
}
