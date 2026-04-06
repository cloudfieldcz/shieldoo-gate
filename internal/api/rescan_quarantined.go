package api

import (
	"net/http"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// handleRescanQuarantined moves all QUARANTINED artifacts to PENDING_SCAN.
// POST /api/v1/admin/rescan-quarantined
func (s *Server) handleRescanQuarantined(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	// Count quarantined artifacts first.
	var count int
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM artifact_status WHERE status = 'QUARANTINED'`,
	).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count quarantined artifacts")
		return
	}

	if count == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"queued":  0,
			"message": "No quarantined artifacts to rescan",
		})
		return
	}

	// Update all QUARANTINED to PENDING_SCAN.
	_, err := s.db.ExecContext(r.Context(),
		`UPDATE artifact_status SET status = 'PENDING_SCAN', rescan_due_at = ? WHERE status = 'QUARANTINED'`,
		now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to queue rescans")
		return
	}

	// Write audit log for each queued artifact.
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT artifact_id FROM artifact_status WHERE status = 'PENDING_SCAN' AND rescan_due_at = ?`, now)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var artID string
			if rows.Scan(&artID) == nil {
				_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
					EventType:  model.EventRescanQueued,
					ArtifactID: artID,
					Reason:     "bulk rescan-quarantined via admin API",
				})
			}
		}
	}

	// Notify rescan scheduler to wake up.
	if s.onRescanQueued != nil {
		s.onRescanQueued()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"queued":  count,
		"message": "Quarantined artifacts queued for rescan",
	})
}
