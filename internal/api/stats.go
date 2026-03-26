package api

import (
	"net/http"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// periodStats holds counts for a single time window.
type periodStats struct {
	Served      int64 `json:"served"`
	Blocked     int64 `json:"blocked"`
	Quarantined int64 `json:"quarantined"`
	Released    int64 `json:"released"`
	Scanned     int64 `json:"scanned"`
}

// summaryResponse is the JSON body for GET /api/v1/stats/summary.
type summaryResponse struct {
	Last24h periodStats `json:"last_24h"`
	Last7d  periodStats `json:"last_7d"`
	Last30d periodStats `json:"last_30d"`
}

func (s *Server) queryPeriodStats(r *http.Request, since time.Time) (periodStats, error) {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT event_type, COUNT(*) AS cnt
		 FROM audit_log
		 WHERE ts >= ?
		 GROUP BY event_type`, since)
	if err != nil {
		return periodStats{}, err
	}
	defer rows.Close()

	var ps periodStats
	for rows.Next() {
		var eventType string
		var cnt int64
		if err := rows.Scan(&eventType, &cnt); err != nil {
			return periodStats{}, err
		}
		switch model.EventType(eventType) {
		case model.EventServed:
			ps.Served = cnt
		case model.EventBlocked:
			ps.Blocked = cnt
		case model.EventQuarantined:
			ps.Quarantined = cnt
		case model.EventReleased:
			ps.Released = cnt
		case model.EventScanned:
			ps.Scanned = cnt
		}
	}
	return ps, rows.Err()
}

// handleStatsSummary handles GET /api/v1/stats/summary.
func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	h24, err := s.queryPeriodStats(r, now.Add(-24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query 24h stats")
		return
	}

	d7, err := s.queryPeriodStats(r, now.Add(-7*24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query 7d stats")
		return
	}

	d30, err := s.queryPeriodStats(r, now.Add(-30*24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query 30d stats")
		return
	}

	writeJSON(w, http.StatusOK, summaryResponse{
		Last24h: h24,
		Last7d:  d7,
		Last30d: d30,
	})
}

// blockedEntry is a row from the audit_log for a BLOCKED event.
type blockedEntry struct {
	ID         int64     `db:"id" json:"id"`
	Timestamp  time.Time `db:"ts" json:"ts"`
	ArtifactID string    `db:"artifact_id" json:"artifact_id,omitempty"`
	ClientIP   string    `db:"client_ip" json:"client_ip,omitempty"`
	Reason     string    `db:"reason" json:"reason,omitempty"`
}

// handleStatsBlocked handles GET /api/v1/stats/blocked.
func (s *Server) handleStatsBlocked(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT id, ts, artifact_id, client_ip, reason
		 FROM audit_log
		 WHERE event_type = 'BLOCKED'
		 ORDER BY ts DESC
		 LIMIT 500`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query blocked artifacts")
		return
	}
	defer rows.Close()

	entries := make([]blockedEntry, 0)
	for rows.Next() {
		var e blockedEntry
		if err := rows.StructScan(&e); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan blocked entry")
			return
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating blocked entries")
		return
	}

	writeJSON(w, http.StatusOK, entries)
}
