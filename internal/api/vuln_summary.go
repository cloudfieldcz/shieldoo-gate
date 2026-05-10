package api

import (
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"
)

// badgeFlight collapses concurrent /vulnerabilities/badge polls into a single
// SQL query. The sidebar polls this every 30s on every open tab, so without
// collapsing each user fans out to N tabs * polls/min DB hits. Result is not
// cached across calls — we rely on duplicate-suppression only.
var badgeFlight singleflight.Group

// handleVulnSummary returns the dashboard card stats: total CRITICAL, HIGH, MEDIUM,
// LOW, count of components with new CRITICAL since 24h, count of stale components.
//
// The time-window predicates use Go-computed cutoff timestamps as parameters
// rather than backend-specific expressions (SQLite's datetime('now', '-1 day')
// vs Postgres's now() - interval). This is the only way to keep one SQL string
// portable across both backends.
func (s *Server) handleVulnSummary(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	// JSON tags must match the snake_case contract the UI consumes
	// (ui/src/api/vulnerabilities.ts:104). Without them, Go marshals as
	// PascalCase (TotalCritical) and the UI silently reads undefined → 0.
	type aggregate struct {
		TotalCritical             int64 `db:"total_critical"           json:"total_critical"`
		TotalHigh                 int64 `db:"total_high"               json:"total_high"`
		TotalMedium               int64 `db:"total_medium"             json:"total_medium"`
		TotalLow                  int64 `db:"total_low"                json:"total_low"`
		ComponentsWithNewCritical int64 `db:"components_new_critical"  json:"components_new_critical"`
		StaleComponents           int64 `db:"stale_components"         json:"stale_components"`
	}
	now := time.Now().UTC()
	since24h := now.Add(-24 * time.Hour)
	since30d := now.Add(-30 * 24 * time.Hour)

	var agg aggregate
	if err := s.db.GetContext(r.Context(), &agg,
		`SELECT
		   COALESCE(SUM(sr.critical_count),0) AS total_critical,
		   COALESCE(SUM(sr.high_count),0)     AS total_high,
		   COALESCE(SUM(sr.medium_count),0)   AS total_medium,
		   COALESCE(SUM(sr.low_count),0)      AS total_low,
		   (SELECT COUNT(DISTINCT sr2.component_id)
		      FROM scan_runs sr2
		      WHERE sr2.started_at > ? AND sr2.new_critical_count > 0)
		     AS components_new_critical,
		   (SELECT COUNT(*) FROM components c2
		      LEFT JOIN scan_runs sr3 ON sr3.id = c2.last_scan_id
		      WHERE c2.enabled = TRUE
		        AND (sr3.id IS NULL OR sr3.started_at < ?))
		     AS stale_components
		 FROM components c
		 LEFT JOIN scan_runs sr ON sr.id = c.last_scan_id
		 WHERE c.enabled = TRUE`,
		since24h, since30d); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, agg)
}

// handleVulnBadge returns the count of components with new CRITICAL since 24h.
// Polled by the sidebar at 30s intervals; concurrent polls are collapsed via
// singleflight so the underlying DB sees one query per in-flight burst.
func (s *Server) handleVulnBadge(w http.ResponseWriter, r *http.Request) {
	if !s.VulnEnabled() {
		writeError(w, http.StatusServiceUnavailable, "vuln scan not enabled")
		return
	}
	since24h := time.Now().UTC().Add(-24 * time.Hour)
	v, err, _ := badgeFlight.Do("vuln-badge", func() (any, error) {
		var count int64
		err := s.db.GetContext(r.Context(), &count,
			`SELECT COUNT(DISTINCT sr.component_id) FROM scan_runs sr
			 WHERE sr.started_at > ? AND sr.new_critical_count > 0`, since24h)
		return count, err
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": v})
}
