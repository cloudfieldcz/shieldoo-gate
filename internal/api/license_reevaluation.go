package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
)

// licenseReEvalMu prevents concurrent re-evaluation goroutines from racing.
var licenseReEvalMu sync.Mutex

// licenseQuarantineReasonPrefix is the marker written into quarantine_reason
// when an artifact is quarantined by the license policy re-evaluator. Only
// rows with this prefix are eligible for automatic release when the policy
// changes back to allow the license. Scanner-originated quarantines MUST NOT
// be released by license policy changes.
const licenseQuarantineReasonPrefix = "license policy:"

// triggerLicenseReEvaluation asynchronously re-evaluates all CLEAN artifacts
// with SBOM metadata against the current license policy. Artifacts with
// blocked licenses are quarantined; artifacts previously quarantined by
// license policy (not by scanners) are released if their license is now
// allowed.
//
// Called from PUT/DELETE on global and project license policy endpoints.
// Uses a mutex to prevent concurrent re-evaluation goroutines from racing.
func (s *Server) triggerLicenseReEvaluation(reason string) {
	if s.policyEngine == nil || s.sbomStore == nil {
		return
	}

	go func() {
		licenseReEvalMu.Lock()
		defer licenseReEvalMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		log.Info().Str("reason", reason).Msg("license re-evaluation: starting")

		var quarantined, released, errors int

		// Process in batches of 500 (keyset pagination) to avoid long-held reads.
		const batchSize = 500
		lastID := ""

		for {
			if ctx.Err() != nil {
				log.Warn().Err(ctx.Err()).Msg("license re-evaluation: context expired")
				break
			}

			type row struct {
				ArtifactID       string  `db:"artifact_id"`
				Status           string  `db:"status"`
				QuarantineReason *string `db:"quarantine_reason"`
				LicensesJSON     string  `db:"licenses_json"`
			}
			var rows []row

			err := s.db.SelectContext(ctx, &rows,
				`SELECT a.artifact_id, a.status, a.quarantine_reason, s.licenses_json
				 FROM artifact_status a
				 JOIN sbom_metadata s ON a.artifact_id = s.artifact_id
				 WHERE s.licenses_json != '[]'
				   AND a.artifact_id > ?
				 ORDER BY a.artifact_id
				 LIMIT ?`, lastID, batchSize)
			if err != nil {
				log.Error().Err(err).Msg("license re-evaluation: query failed")
				break
			}
			if len(rows) == 0 {
				break
			}

			for _, r := range rows {
				lastID = r.ArtifactID

				result := s.policyEngine.EvaluateLicensesOnly(ctx, r.ArtifactID)

				switch {
				case result.Action == policy.ActionBlock && r.Status != string(model.StatusQuarantined):
					// License blocked and artifact not quarantined → quarantine it.
					now := time.Now().UTC()
					qReason := fmt.Sprintf("%s %s", licenseQuarantineReasonPrefix, result.Reason)
					if _, err := s.db.ExecContext(ctx,
						`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
						string(model.StatusQuarantined), qReason, now, r.ArtifactID,
					); err != nil {
						log.Error().Err(err).Str("artifact_id", r.ArtifactID).Msg("license re-evaluation: quarantine failed")
						errors++
						continue
					}
					_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
						EventType:  model.EventLicenseBlocked,
						ArtifactID: r.ArtifactID,
						Reason:     fmt.Sprintf("license re-evaluation: %s", result.Reason),
					})
					quarantined++

				case result.Action == policy.ActionAllow && r.Status == string(model.StatusQuarantined):
					// License now allowed and artifact is quarantined.
					// ONLY release if quarantined BY LICENSE POLICY (not by scanner).
					qr := ""
					if r.QuarantineReason != nil {
						qr = *r.QuarantineReason
					}
					if !strings.HasPrefix(qr, licenseQuarantineReasonPrefix) {
						continue // scanner-quarantined, do not touch
					}
					if _, err := s.db.ExecContext(ctx,
						`UPDATE artifact_status SET status = ?, quarantine_reason = '', quarantined_at = NULL WHERE artifact_id = ?`,
						string(model.StatusClean), r.ArtifactID,
					); err != nil {
						log.Error().Err(err).Str("artifact_id", r.ArtifactID).Msg("license re-evaluation: release failed")
						errors++
						continue
					}
					// Parse licenses for audit metadata.
					var licenses []string
					_ = json.Unmarshal([]byte(r.LicensesJSON), &licenses)
					_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
						EventType:  model.EventServed, // reuse SERVED as "released by policy change"
						ArtifactID: r.ArtifactID,
						Reason:     fmt.Sprintf("license re-evaluation: released — licenses %v now allowed", licenses),
					})
					released++
				}
			}

			if len(rows) < batchSize {
				break
			}
		}

		log.Info().
			Int("quarantined", quarantined).
			Int("released", released).
			Int("errors", errors).
			Str("reason", reason).
			Msg("license re-evaluation: complete")
	}()
}
