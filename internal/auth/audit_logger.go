package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/alert"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// AuditWriter wraps audit_log INSERTs for the new vuln-scan EventTypes.
// All writes carry the new nullable FK-shaped columns (component_id, scan_run_id,
// ignore_id, api_key_id) added by migration 035.
type AuditWriter struct {
	db       *config.GateDB
	alerter  alert.Alerter
}

// NewAuditWriter constructs an AuditWriter.
func NewAuditWriter(db *config.GateDB) *AuditWriter {
	return &AuditWriter{db: db}
}

// WithAlerter wires an Alerter so each successful WriteVulnEvent fan-outs to
// the configured alert channels. Channel-level event filters decide which
// EventTypes actually reach a given channel; this method does no filtering.
func (w *AuditWriter) WithAlerter(a alert.Alerter) *AuditWriter {
	w.alerter = a
	return w
}

// WriteVulnEvent inserts an AuditEntry into audit_log, populating the vuln-scan
// extension columns. Timestamp defaults to now when zero. On success, the entry
// is also dispatched to the alerter (if configured) so webhook/Slack/email
// channels can deliver it.
func (w *AuditWriter) WriteVulnEvent(ctx context.Context, e model.AuditEntry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	_, err := w.db.ExecContext(ctx,
		`INSERT INTO audit_log
		   (ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json,
		    user_email, project_id, component_id, scan_run_id, ignore_id, api_key_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.EventType, e.ArtifactID, e.ClientIP, e.UserAgent,
		e.Reason, e.MetadataJSON, e.UserEmail, e.ProjectID,
		e.ComponentID, e.ScanRunID, e.IgnoreID, e.APIKeyID)
	if err != nil {
		return fmt.Errorf("audit_logger: insert: %w", err)
	}
	if w.alerter != nil {
		w.alerter.Dispatch(ctx, e)
	}
	return nil
}
