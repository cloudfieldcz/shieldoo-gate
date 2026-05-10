package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// detachedCtx returns a context with a sane timeout but unrelated to the request
// lifetime, suitable for "fire and forget" goroutines (the scan runner).
func (s *Server) detachedCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}

// handleManualRescan triggers an immediate rescan of a component using the latest stored SBOM.
func (s *Server) handleManualRescan(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	id, err := pathInt64(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	comp, err := s.vulnDeps.Component.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, component.ErrNotFound) {
			writeError(w, http.StatusNotFound, "component not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if comp.LastScanID == nil {
		writeError(w, http.StatusBadRequest, "no prior scan to rescan; upload an SBOM first")
		return
	}
	body, err := s.vulnDeps.ScanService.GetSBOM(r.Context(), *comp.LastScanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user := auth.UserFromContext(r.Context())
	byEmail := ""
	if user != nil {
		byEmail = user.Email
	}
	run, err := s.vulnDeps.ScanService.Submit(r.Context(), comp.ID, bytesReader(body), int64(len(body)),
		"application/vnd.cyclonedx+json", component.TriggerManual, byEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.vulnDeps.Audit != nil {
		cid := comp.ID
		rid := run.ID
		_ = s.vulnDeps.Audit.WriteVulnEvent(r.Context(), model.AuditEntry{
			EventType:   model.EventRescanTriggered,
			ComponentID: &cid,
			ScanRunID:   &rid,
			UserEmail:   byEmail,
		})
	}
	go func() { _ = s.vulnDeps.ScanService.Run(s.detachedCtx(), run.ID) }()
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_run_id": run.ID})
}

// bytesReader wraps a []byte as io.Reader without importing bytes.
type byteSliceReader struct {
	data []byte
	pos  int
}

func (b *byteSliceReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, ioEOF()
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func bytesReader(b []byte) *byteSliceReader { return &byteSliceReader{data: b} }
