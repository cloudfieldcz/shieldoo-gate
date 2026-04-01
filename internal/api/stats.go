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

// artifactStats holds counts of artifacts by their current status.
type artifactStats struct {
	Total       int64 `json:"total"`
	Clean       int64 `json:"clean"`
	Suspicious  int64 `json:"suspicious"`
	Quarantined int64 `json:"quarantined"`
	PendingScan int64 `json:"pending_scan"`
}

// requestStats holds request-level counters from the audit log.
type requestStats struct {
	Served24h  int64 `json:"served_24h"`
	Blocked24h int64 `json:"blocked_24h"`
	ServedAll  int64 `json:"served_all"`
	BlockedAll int64 `json:"blocked_all"`
}

// summaryResponse is the JSON body for GET /api/v1/stats/summary.
// Fields match the frontend StatsSummary type.
type summaryResponse struct {
	Artifacts artifactStats                `json:"artifacts"`
	Requests  requestStats                 `json:"requests"`
	ByPeriod  map[string]map[string]int64  `json:"by_period"`
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
	ctx := r.Context()

	// Total artifacts count.
	var totalArtifacts int64
	_ = s.db.GetContext(ctx, &totalArtifacts, `SELECT COUNT(*) FROM artifacts`)

	// Artifact status breakdown.
	type statusRow struct {
		Status string `db:"status"`
		Cnt    int64  `db:"cnt"`
	}
	var statusRows []statusRow
	_ = s.db.SelectContext(ctx, &statusRows,
		`SELECT status, COUNT(*) AS cnt FROM artifact_status GROUP BY status`)

	var arts artifactStats
	arts.Total = totalArtifacts
	for _, sr := range statusRows {
		switch sr.Status {
		case "CLEAN":
			arts.Clean = sr.Cnt
		case "SUSPICIOUS":
			arts.Suspicious = sr.Cnt
		case "QUARANTINED":
			arts.Quarantined = sr.Cnt
		case "PENDING_SCAN":
			arts.PendingScan = sr.Cnt
		}
	}

	// Audit log totals (all time + last 24h).
	now := time.Now().UTC()
	allTime, _ := s.queryPeriodStats(r, time.Time{})
	h24, _ := s.queryPeriodStats(r, now.Add(-24*time.Hour))

	reqs := requestStats{
		Served24h:  h24.Served,
		Blocked24h: h24.Blocked,
		ServedAll:  allTime.Served,
		BlockedAll: allTime.Blocked,
	}

	// Build by_period: daily buckets for last 7 days.
	byPeriod := make(map[string]map[string]int64)
	for i := 6; i >= 0; i-- {
		dayStart := now.AddDate(0, 0, -i).Truncate(24 * time.Hour)
		dayEnd := dayStart.Add(24 * time.Hour)
		label := dayStart.Format("2006-01-02")

		rows, err := s.db.QueryxContext(ctx,
			`SELECT event_type, COUNT(*) AS cnt
			 FROM audit_log
			 WHERE ts >= ? AND ts < ?
			 GROUP BY event_type`, dayStart, dayEnd)
		if err != nil {
			continue
		}
		bucket := map[string]int64{"served": 0, "blocked": 0, "quarantined": 0}
		for rows.Next() {
			var eventType string
			var cnt int64
			if err := rows.Scan(&eventType, &cnt); err != nil {
				continue
			}
			switch model.EventType(eventType) {
			case model.EventServed:
				bucket["served"] = cnt
			case model.EventBlocked:
				bucket["blocked"] = cnt
			case model.EventQuarantined:
				bucket["quarantined"] = cnt
			}
		}
		rows.Close()
		byPeriod[label] = bucket
	}

	writeJSON(w, http.StatusOK, summaryResponse{
		Artifacts: arts,
		Requests:  reqs,
		ByPeriod:  byPeriod,
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
