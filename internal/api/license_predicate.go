package api

import "strings"

// isLicenseQuarantineReason returns true when the artifact_status.quarantine_reason
// indicates a license-policy block (as opposed to a scanner verdict, typosquat,
// or other reason). Reuses the canonical prefix from license_reevaluation.go so
// the two stay in sync — if the writer's prefix moves, the read predicate moves
// with it.
//
// Used by handleReleaseArtifact to refuse a global Release on a license block:
// license decisions are project-scoped, so a global override has the wrong
// blast radius. The handler instead returns 409 with a next_action hint
// pointing the operator at the per-project override flow.
func isLicenseQuarantineReason(reason string) bool {
	if reason == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(reason), strings.ToLower(licenseQuarantineReasonPrefix))
}
