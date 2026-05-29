package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
)

// SetSBOMStorage wires the SBOM storage layer. When non-nil the SBOM endpoints
// are active.
func (s *Server) SetSBOMStorage(st sbom.Storage) {
	s.sbomStore = st
}

// SetSBOMGenerator wires the on-demand CycloneDX 1.5 generator used by the
// per-project SBOM export endpoint. Wired only when SBOM is enabled in config;
// when nil the route is not registered.
func (s *Server) SetSBOMGenerator(g *sbom.Generator) {
	s.sbomGenerator = g
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

// handleGetProjectSBOM streams a freshly-generated CycloneDX 1.5 SBOM that
// enumerates every artifact the project has pulled through the proxy.
//
// Output is generated on every call (never cached) — the set of artifacts the
// project has used changes with each pull, and a cached SBOM would lie about
// coverage. Empty projects still produce a valid SBOM with `components: []`.
//
// Filename header pattern: sbom-<label>-YYYYMMDD.cdx.json so the browser
// "Save As" dialog suggests a meaningful name.
func (s *Server) handleGetProjectSBOM(w http.ResponseWriter, r *http.Request) {
	// projectSvc is guaranteed non-nil here — the route is only registered
	// inside the `if s.projectSvc != nil` block in Server.Routes(). Only the
	// SBOM-disabled-in-config case (sbomGenerator == nil) needs to be handled.
	if s.sbomGenerator == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "sbom disabled"})
		return
	}
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
		log.Error().Err(err).Int64("project_id", id).Msg("api: project SBOM lookup failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	blob, err := s.sbomGenerator.ForProject(r.Context(), p)
	if err != nil {
		log.Error().Err(err).Int64("project_id", id).Msg("api: project SBOM generation failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sbom generation failed"})
		return
	}

	// Audit the export. SBOM aggregates every artifact this project has
	// pulled — operators need to know "who exported what about us, when"
	// for compliance and incident response. Failure to audit is logged but
	// does not block the download (best-effort, mirrors the pattern used
	// by override + license audit writes elsewhere in this package).
	if err := adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:    model.EventSBOMGenerated,
		ProjectID:    &id,
		UserEmail:    userEmailFromRequest(r),
		ClientIP:     r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Reason:       fmt.Sprintf("project SBOM exported (%d bytes)", len(blob)),
		MetadataJSON: fmt.Sprintf(`{"project_label":%q,"size_bytes":%d,"format":"cyclonedx-1.5-json"}`, p.Label, len(blob)),
	}); err != nil {
		log.Warn().Err(err).Int64("project_id", id).Msg("api: failed to write SBOM audit entry")
	}

	filename := fmt.Sprintf("sbom-%s-%s.cdx.json", p.Label, time.Now().UTC().Format("20060102"))
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.5")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
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
