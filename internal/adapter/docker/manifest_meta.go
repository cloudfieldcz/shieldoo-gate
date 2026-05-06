package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// ManifestMetaSchemaVersion pins the parser interpretation. Bumping this constant
// alone does NOT trigger a re-parse of existing rows — to re-process, add a new
// numbered data migration that upserts rows where schema_version < this constant.
const ManifestMetaSchemaVersion = 1

// maxManifestMetaInput bounds parser memory. Matches the upstream-handler cap
// (maxManifestSize = 10 MB) so the parser is no more permissive than the writer.
const maxManifestMetaInput = 10 << 20

// Attestation manifest indicators per the BuildKit spec.
//
// https://docs.docker.com/build/attestations/attestation-storage/
const (
	attestationConfigMediaType    = "application/vnd.in-toto+json"
	attestationReferenceTypeKey   = "vnd.docker.reference.type"
	attestationReferenceTypeValue = "attestation-manifest"
)

// ManifestMeta is the parsed view of a Docker/OCI manifest body that the UI surfaces.
type ManifestMeta struct {
	MediaType      string
	IsIndex        bool
	IsAttestation  bool
	TotalSizeBytes *int64
	LayerCount     *int
	Architecture   string
	OS             string
	SchemaVersion  int
}

// internal JSON shape covering all four media types we parse. Index manifests
// populate `Manifests`; image manifests populate `Config` + `Layers`. Optional
// `Platform` may appear on per-arch manifest entries inside an index, and
// occasionally at the top level of single-arch manifests.
type manifestProbe struct {
	MediaType   string `json:"mediaType"`
	Manifests   []struct {
		Platform *struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform,omitempty"`
	} `json:"manifests,omitempty"`
	Config *struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
	} `json:"config,omitempty"`
	Layers []struct {
		Size int64 `json:"size"`
	} `json:"layers,omitempty"`
	Platform *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ParseManifestMeta inspects a Docker/OCI manifest body and extracts size/shape data.
// Returns an error only for oversized input or malformed JSON; unknown media types
// fall back to (IsIndex=false, TotalSizeBytes=nil) so the row is still persisted.
//
// Defense-in-depth invariants:
//   - body length is rejected if > maxManifestMetaInput
//   - layer/config sizes are summed with overflow saturation: any negative individual
//     size or any addition that would exceed math.MaxInt64 yields TotalSizeBytes=nil
//     rather than a wrapped negative number
func ParseManifestMeta(body []byte) (ManifestMeta, error) {
	if len(body) > maxManifestMetaInput {
		return ManifestMeta{}, fmt.Errorf("manifest body exceeds %d bytes", maxManifestMetaInput)
	}

	var p manifestProbe
	if err := json.Unmarshal(body, &p); err != nil {
		return ManifestMeta{}, fmt.Errorf("manifest_meta: parse JSON: %w", err)
	}

	meta := ManifestMeta{
		MediaType:     p.MediaType,
		SchemaVersion: ManifestMetaSchemaVersion,
	}

	// Index manifests carry `manifests[]` and have no `layers[]`.
	if len(p.Manifests) > 0 {
		meta.IsIndex = true
		return meta, nil
	}

	// Image manifest path. layer_count is always derivable.
	layerCount := len(p.Layers)
	meta.LayerCount = &layerCount

	// Optional platform info from manifest body itself (rare; mostly comes from
	// the parent index's manifests[].platform, which is not visible here).
	if p.Platform != nil {
		meta.Architecture = p.Platform.Architecture
		meta.OS = p.Platform.OS
	}

	// Attestation detection: BuildKit emits regular image manifests whose config
	// blob is in-toto JSON, often paired with a reference-type annotation.
	if p.Config != nil && p.Config.MediaType == attestationConfigMediaType {
		meta.IsAttestation = true
	}
	if v := p.Annotations[attestationReferenceTypeKey]; v == attestationReferenceTypeValue {
		meta.IsAttestation = true
	}

	// Overflow-safe sum: config.size + sum(layers[].size).
	//
	// Any negative individual size or any addition that would exceed MaxInt64
	// yields TotalSizeBytes=nil (saturate to "unknown"). Returns nil rather than
	// surfacing a wrapped negative number to the UI.
	var total int64
	overflow := false
	if p.Config != nil {
		if p.Config.Size < 0 {
			overflow = true
		} else {
			total = p.Config.Size
		}
	}
	if !overflow {
		for _, l := range p.Layers {
			if l.Size < 0 || total > math.MaxInt64-l.Size {
				overflow = true
				break
			}
			total += l.Size
		}
	}
	if !overflow {
		t := total
		meta.TotalSizeBytes = &t
	}

	return meta, nil
}

// UpsertManifestMeta writes a docker_manifest_meta row. Idempotent on artifact_id.
func UpsertManifestMeta(ctx context.Context, db *config.GateDB, artifactID string, m ManifestMeta) error {
	if artifactID == "" {
		return fmt.Errorf("manifest_meta: artifact_id is required")
	}
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx,
		`INSERT INTO docker_manifest_meta
		     (artifact_id, media_type, is_index, is_attestation, total_size_bytes, layer_count, architecture, os, schema_version, parsed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (artifact_id) DO UPDATE SET
		     media_type       = excluded.media_type,
		     is_index         = excluded.is_index,
		     is_attestation   = excluded.is_attestation,
		     total_size_bytes = excluded.total_size_bytes,
		     layer_count      = excluded.layer_count,
		     architecture     = excluded.architecture,
		     os               = excluded.os,
		     schema_version   = excluded.schema_version,
		     parsed_at        = excluded.parsed_at`,
		artifactID, m.MediaType, m.IsIndex, m.IsAttestation, m.TotalSizeBytes, m.LayerCount, nullableString(m.Architecture), nullableString(m.OS), m.SchemaVersion, now,
	)
	if err != nil {
		return fmt.Errorf("manifest_meta: upsert %s: %w", artifactID, err)
	}
	return nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
