// Package sbom implements Software Bill of Materials generation and storage.
//
// The scan engine emits a CycloneDX JSON SBOM from Trivy (single-run, with
// vuln and license scanners). This package is responsible for:
//   - Parsing the CycloneDX blob to extract component licenses (SPDX IDs).
//   - Sanitizing internal cache paths from the SBOM before persistence
//     (prevents leaking infrastructure details via the admin API).
//   - Writing the blob via BlobStore (asynchronously by default so scan
//     throughput is unaffected).
//   - Recording DB metadata (artifact_id → blob_path, size, licenses,
//     component count, generator).
//
// See docs/features/sbom-generation.md for the user-facing description.
package sbom

import (
	"encoding/json"
	"time"
)

// Format identifiers used across the codebase.
const (
	FormatCycloneDXJSON = "cyclonedx-json"
)

// Metadata describes a stored SBOM. The blob itself lives in a BlobStore.
type Metadata struct {
	ArtifactID     string    `db:"artifact_id"     json:"artifact_id"`
	Format         string    `db:"format"          json:"format"`
	BlobPath       string    `db:"blob_path"       json:"blob_path"`
	SizeBytes      int64     `db:"size_bytes"      json:"size_bytes"`
	ComponentCount int       `db:"component_count" json:"component_count"`
	LicensesJSON   string    `db:"licenses_json"   json:"-"`
	GeneratedAt    time.Time `db:"generated_at"    json:"generated_at"`
	Generator      string    `db:"generator"       json:"generator"`
}

// Licenses returns the decoded list of SPDX identifiers extracted from the SBOM.
func (m *Metadata) Licenses() []string {
	if m == nil || m.LicensesJSON == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(m.LicensesJSON), &out); err != nil {
		return nil
	}
	return out
}

// ExtractResult is the parsed information extracted from a CycloneDX SBOM.
type ExtractResult struct {
	ComponentCount int
	Licenses       []string // canonical SPDX IDs, deduplicated
	Generator      string
}
