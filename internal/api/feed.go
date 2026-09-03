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
//
// The refresh runs detached from the request: a feed fetch plus upsert can
// outlast the client's patience, and the caller only needs to know the work
// started. The outcome is not in this response — it is already written by then —
// so the refresher is responsible for reporting it. The wired implementation
// (threatfeed.Client.RefreshNow) is the same entry point the periodic loop uses,
// so a manual refresh produces the same escalating log line and moves the same
// shieldoo_gate_threat_feed_* metrics as a scheduled one. Its error is dropped
// here rather than logged twice.
//
// When no refresher is wired the endpoint reports 501. It previously answered
// 202 "queued" unconditionally while doing nothing at all, which is the worst
// possible reply to an operator chasing a dead feed: it certifies that something
// happened and leaves them looking for a second fault that does not exist.
func (s *Server) handleRefreshFeed(w http.ResponseWriter, _ *http.Request) {
	if s.feedRefresher == nil {
		writeError(w, http.StatusNotImplemented, "threat feed refresh is not available: no threat feed is configured")
		return
	}

	refresh := s.feedRefresher
	ctx := s.detachedCtx()
	go func() {
		_ = refresh(ctx)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "threat feed refresh queued",
	})
}
