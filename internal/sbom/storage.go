package sbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// Storage is the public interface for persisting and retrieving SBOMs.
type Storage interface {
	// Write parses the SBOM, sanitizes internal paths, persists the blob
	// (via the configured BlobStore) and records metadata in the DB.
	// scannerLicenses are optional pre-extracted SPDX IDs from the scanner's
	// license extractor — they are merged with whatever Parse() finds in
	// the CycloneDX blob. This ensures metadata is complete even when the
	// blob has 0 components (common for single-artifact scans).
	// Returns the extracted metadata.
	Write(ctx context.Context, artifactID, format string, raw []byte, scannerLicenses []string) (*Metadata, error)

	// WriteLicensesOnly persists a metadata-only row with the given licenses.
	// Used when licenses are discovered without a full SBOM (e.g. Maven
	// effective-POM parent chain resolution). No blob is stored.
	WriteLicensesOnly(ctx context.Context, artifactID string, licenses []string, generator string) error

	// Read returns the raw SBOM bytes for the given artifact ID.
	Read(ctx context.Context, artifactID string) ([]byte, string, error)

	// Delete removes the blob + metadata row. Safe to call multiple times.
	Delete(ctx context.Context, artifactID string) error

	// GetMetadata returns the SBOM metadata without loading the blob.
	// Returns sql.ErrNoRows if the artifact has no SBOM.
	GetMetadata(ctx context.Context, artifactID string) (*Metadata, error)
}

// storageImpl persists SBOMs in a BlobStore and metadata in *GateDB.
type storageImpl struct {
	blobs       cache.BlobStore
	db          *config.GateDB
	cachePrefix string // sanitized out of SBOM JSON before writing
	generator   string // default generator string if SBOM lacks one
}

// NewStorage returns a Storage using blobs for payload and db for metadata.
// cachePrefix is sanitized from SBOM contents (e.g. "/var/cache/shieldoo-gate").
func NewStorage(db *config.GateDB, blobs cache.BlobStore, cachePrefix string) Storage {
	return &storageImpl{
		blobs:       blobs,
		db:          db,
		cachePrefix: cachePrefix,
	}
}

// blobPath returns the storage path for an artifact's SBOM blob.
// The path is content-addressed by the artifact ID prefix (first 2 chars of
// the sha256 hash when present, otherwise a hash of the ID) so large numbers
// of artifacts don't land in a single directory.
func blobPath(artifactID string) string {
	// SBOMs are small; a two-level shard is enough.
	clean := strings.ReplaceAll(artifactID, ":", "_")
	if clean == "" {
		clean = "unknown"
	}
	prefix := clean
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.ToSlash(filepath.Join("sbom", prefix, clean+".cdx.json"))
}

func (s *storageImpl) Write(ctx context.Context, artifactID, format string, raw []byte, scannerLicenses []string) (*Metadata, error) {
	if artifactID == "" {
		return nil, fmt.Errorf("sbom: empty artifactID")
	}
	if format == "" {
		format = FormatCycloneDXJSON
	}

	// 1. Sanitize internal paths.
	sanitized := Sanitize(raw, s.cachePrefix)

	// 2. Parse for metadata (component count, licenses).
	ext, parseErr := Parse(sanitized)
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("artifact_id", artifactID).Msg("sbom: parse failed — storing anyway")
	}

	// Merge scanner-extracted licenses (from the per-ecosystem metadata
	// extractor) into the parsed result. This is necessary because Trivy's
	// CycloneDX output often has 0 components for single-artifact scans,
	// but the license extractor finds licenses from package.json, METADATA,
	// nuspec, pom.xml, etc.
	if len(scannerLicenses) > 0 {
		seen := make(map[string]struct{}, len(ext.Licenses))
		for _, l := range ext.Licenses {
			seen[l] = struct{}{}
		}
		for _, l := range scannerLicenses {
			if _, ok := seen[l]; !ok {
				ext.Licenses = append(ext.Licenses, l)
				seen[l] = struct{}{}
			}
		}
	}

	// 3. Persist blob (best-effort for metadata purposes).
	path := blobPath(artifactID)
	if err := s.blobs.PutBlob(ctx, path, sanitized); err != nil {
		log.Warn().Err(err).Str("artifact_id", artifactID).Msg("sbom: blob write failed, persisting metadata anyway")
		path = "" // no blob available — metadata is still valuable
	}

	generator := ext.Generator
	if generator == "" {
		generator = "unknown"
	}

	licJSON, err := json.Marshal(ext.Licenses)
	if err != nil {
		licJSON = []byte("[]")
	}

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sbom_metadata
		     (artifact_id, format, blob_path, size_bytes, component_count, licenses_json, generated_at, generator)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (artifact_id) DO UPDATE SET
		     format          = excluded.format,
		     blob_path       = excluded.blob_path,
		     size_bytes      = excluded.size_bytes,
		     component_count = excluded.component_count,
		     licenses_json   = excluded.licenses_json,
		     generated_at    = excluded.generated_at,
		     generator       = excluded.generator`,
		artifactID, format, path, int64(len(sanitized)), ext.ComponentCount, string(licJSON), now, generator,
	); err != nil {
		return nil, fmt.Errorf("sbom: persist metadata: %w", err)
	}

	return &Metadata{
		ArtifactID:     artifactID,
		Format:         format,
		BlobPath:       path,
		SizeBytes:      int64(len(sanitized)),
		ComponentCount: ext.ComponentCount,
		LicensesJSON:   string(licJSON),
		GeneratedAt:    now,
		Generator:      generator,
	}, nil
}

func (s *storageImpl) WriteLicensesOnly(ctx context.Context, artifactID string, licenses []string, generator string) error {
	if artifactID == "" || len(licenses) == 0 {
		return nil
	}
	if generator == "" {
		generator = "effective-pom"
	}
	licJSON, err := json.Marshal(licenses)
	if err != nil {
		licJSON = []byte("[]")
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sbom_metadata
		     (artifact_id, format, blob_path, size_bytes, component_count, licenses_json, generated_at, generator)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (artifact_id) DO UPDATE SET
		     licenses_json   = excluded.licenses_json,
		     generated_at    = excluded.generated_at,
		     generator       = excluded.generator`,
		artifactID, "licenses-only", "", 0, 0, string(licJSON), now, generator,
	); err != nil {
		return fmt.Errorf("sbom: persist license metadata: %w", err)
	}
	return nil
}

func (s *storageImpl) Read(ctx context.Context, artifactID string) ([]byte, string, error) {
	meta, err := s.GetMetadata(ctx, artifactID)
	if err != nil {
		return nil, "", err
	}
	if meta.BlobPath == "" {
		return nil, "", fmt.Errorf("sbom: blob unavailable for %s (metadata-only row)", artifactID)
	}
	blob, err := s.blobs.GetBlob(ctx, meta.BlobPath)
	if err != nil {
		return nil, "", fmt.Errorf("sbom: read blob %s: %w", meta.BlobPath, err)
	}
	return blob, meta.Format, nil
}

func (s *storageImpl) Delete(ctx context.Context, artifactID string) error {
	meta, err := s.GetMetadata(ctx, artifactID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if meta.BlobPath != "" {
		if err := s.blobs.DeleteBlob(ctx, meta.BlobPath); err != nil {
			// Log but continue — metadata row must still be removed so stats don't lie.
			log.Warn().Err(err).Str("path", meta.BlobPath).Msg("sbom: blob delete failed; removing metadata anyway")
		}
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sbom_metadata WHERE artifact_id = ?`, artifactID); err != nil {
		return fmt.Errorf("sbom: delete metadata: %w", err)
	}
	return nil
}

func (s *storageImpl) GetMetadata(ctx context.Context, artifactID string) (*Metadata, error) {
	var m Metadata
	err := s.db.GetContext(ctx, &m,
		`SELECT artifact_id, format, blob_path, size_bytes, component_count,
		        licenses_json, generated_at, generator
		 FROM sbom_metadata WHERE artifact_id = ?`, artifactID)
	if err != nil {
		return nil, err
	}
	return &m, nil
}
