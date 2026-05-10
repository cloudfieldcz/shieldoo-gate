package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
)

// handleScanUpload accepts a CycloneDX SBOM and creates a new scan run.
// Route: POST /api/v1/projects/:label/components/:name/scans
// Auth: PAT with scope `scan:upload` (or global super-token).
// Status codes: 202, 400 (component name regex), 401, 403, 413, 415, 422, 429.
func (s *Server) handleScanUpload(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	label := chi.URLParam(r, "label")
	name := chi.URLParam(r, "name")
	if label == "" || name == "" {
		writeError(w, http.StatusBadRequest, "label and name are required")
		return
	}
	if !component.ValidateComponentName(name) {
		writeError(w, http.StatusBadRequest, "invalid component name")
		return
	}
	if s.projectSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "project service not initialized")
		return
	}
	proj, err := s.projectSvc.GetByLabel(label)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	// MaxBytesReader to enforce hard byte cap before any disk write.
	r.Body = http.MaxBytesReader(w, r.Body, component.DefaultSBOMLimits().MaxBytes)
	contentType := r.Header.Get("Content-Type")

	// Resolve / lazy-create the component.
	ecosystem := r.URL.Query().Get("ecosystem")
	if ecosystem == "" {
		ecosystem = "multi"
	}
	comp, err := s.vulnDeps.Component.Resolve(r.Context(), proj.ID, name, true, ecosystem)
	if err != nil {
		switch {
		case errors.Is(err, component.ErrCapReached):
			writeError(w, http.StatusTooManyRequests, "component cap reached")
		case errors.Is(err, component.ErrInvalidName):
			writeError(w, http.StatusBadRequest, "invalid component name")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	user := auth.UserFromContext(r.Context())
	byEmail := ""
	if user != nil {
		byEmail = user.Email
	}

	run, err := s.vulnDeps.ScanService.Submit(r.Context(), comp.ID, r.Body, r.ContentLength, contentType, component.TriggerUpload, byEmail)
	if err != nil {
		switch {
		case errors.Is(err, component.ErrSBOMTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "sbom too large")
		case errors.Is(err, component.ErrUnsupportedMedia):
			writeError(w, http.StatusUnsupportedMediaType, "unsupported content type")
		case errors.Is(err, component.ErrInvalidSBOM):
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Async scan invocation.
	go func() {
		_ = s.vulnDeps.ScanService.Run(s.detachedCtx(), run.ID)
	}()

	w.Header().Set("Location", "/api/v1/vulnerabilities/scan-runs/")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_run_id":    run.ID,
		"component_id":   comp.ID,
		"detail_url":     "/api/v1/vulnerabilities/scan-runs/" + formatInt64(run.ID),
	})
}
