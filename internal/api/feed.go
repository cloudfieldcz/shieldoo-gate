package api

import (
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// handleListFeed handles GET /api/v1/feed.
func (s *Server) handleListFeed(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT sha256, ecosystem, package_name, version, reported_at, source_url, iocs_json
		 FROM threat_feed
		 ORDER BY reported_at DESC
		 LIMIT 1000`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query threat feed")
		return
	}
	defer rows.Close()

	entries := make([]model.ThreatFeedEntry, 0)
	for rows.Next() {
		var e model.ThreatFeedEntry
		if err := rows.StructScan(&e); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan threat feed entry")
			return
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating threat feed entries")
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

// handleRefreshFeed handles POST /api/v1/feed/refresh.
// The actual feed refresh requires the threatfeed.Client which would be injected in production.
// For now the endpoint acknowledges the request and returns 202 Accepted.
func (s *Server) handleRefreshFeed(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "threat feed refresh queued",
	})
}
