package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
)

// SetSBOMStorage wires the SBOM storage layer. When non-nil the SBOM endpoints
// are active.
func (s *Server) SetSBOMStorage(st sbom.Storage) {
	s.sbomStore = st
}

// handleGetArtifactSBOM returns the raw CycloneDX SBOM for an artifact.
func (s *Server) handleGetArtifactSBOM(w http.ResponseWriter, r *http.Request) {
	if s.sbomStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "sbom disabled"})
		return
	}
	id := artifactID(r)
	blob, format, err := s.sbomStore.Read(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "sbom not found for artifact"})
			return
		}
		log.Error().Err(err).Str("artifact_id", id).Msg("api: sbom read failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sbom read failed"})
		return
	}
	// CycloneDX JSON MIME type per spec.
	if format == sbom.FormatCycloneDXJSON {
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

// handleGetArtifactLicenses returns the pre-extracted SPDX ID list for an artifact.
func (s *Server) handleGetArtifactLicenses(w http.ResponseWriter, r *http.Request) {
	if s.sbomStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "sbom disabled"})
		return
	}
	id := artifactID(r)
	meta, err := s.sbomStore.GetMetadata(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no sbom for artifact"})
			return
		}
		log.Error().Err(err).Str("artifact_id", id).Msg("api: sbom metadata read failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
		return
	}
	var ids []string
	if meta.LicensesJSON != "" {
		_ = json.Unmarshal([]byte(meta.LicensesJSON), &ids)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"artifact_id":     meta.ArtifactID,
		"licenses":        ids,
		"component_count": meta.ComponentCount,
		"generator":       meta.Generator,
		"generated_at":    meta.GeneratedAt,
	})
}
