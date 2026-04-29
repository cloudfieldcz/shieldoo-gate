package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// healthResponse is the JSON body returned by GET /api/v1/health.
type healthResponse struct {
	Status   string                 `json:"status"`
	Scanners map[string]scannerInfo `json:"scanners,omitempty"`
}

type scannerInfo struct {
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

// handleHealth returns the service health status including scanner health checks.
//
// The 10 s budget is the ceiling for all scanner health checks combined.
// Engine.HealthCheck runs them in parallel, so the slowest scanner — typically
// trivy's `trivy version` fork+exec or the OSV API round-trip — sets the floor.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp := healthResponse{
		Status: "ok",
	}

	if s.scanEngine != nil {
		scannerStatuses := s.scanEngine.HealthCheck(ctx)
		resp.Scanners = make(map[string]scannerInfo, len(scannerStatuses))
		for name, err := range scannerStatuses {
			info := scannerInfo{Healthy: err == nil}
			if err != nil {
				info.Error = err.Error()
			}
			resp.Scanners[name] = info
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePublicURLs returns the configured public-facing URLs for each ecosystem proxy.
func (s *Server) handlePublicURLs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.publicURLs)
}

// writeJSON serialises v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error body.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
