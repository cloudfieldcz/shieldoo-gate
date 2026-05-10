package scheduler

import (
	"context"
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
)

// BlobLister is the optional interface a BlobStore may implement to enumerate blobs
// under a path prefix. Backends that do not implement it short-circuit the sweeper.
type BlobLister interface {
	ListBlobs(ctx context.Context, prefix string) ([]string, error)
}

// OrphanBlobSweeper reclaims SBOM blobs that have no corresponding scan_runs row.
// Runs once at startup. Crash-window blobs from the retention reaper are reclaimed here.
type OrphanBlobSweeper struct {
	db     *config.GateDB
	blob   cache.BlobStore
	prefix string
}

// NewOrphanBlobSweeper constructs a sweeper. prefix defaults to "sboms/components/".
func NewOrphanBlobSweeper(db *config.GateDB, blob cache.BlobStore, prefix string) *OrphanBlobSweeper {
	if prefix == "" {
		prefix = "sboms/components/"
	}
	return &OrphanBlobSweeper{db: db, blob: blob, prefix: prefix}
}

// Sweep enumerates blobs under prefix and unlinks any not referenced by a scan_runs row.
// Returns (deletedCount, error). When the BlobStore does not implement BlobLister this
// is a no-op (skipped logged at debug).
func (s *OrphanBlobSweeper) Sweep(ctx context.Context) (int, error) {
	lister, ok := s.blob.(BlobLister)
	if !ok {
		log.Debug().Msg("orphan_blob_sweeper: blob store does not implement BlobLister; skipping")
		return 0, nil
	}
	paths, err := lister.ListBlobs(ctx, s.prefix)
	if err != nil {
		return 0, fmt.Errorf("orphan_blob_sweeper: list: %w", err)
	}
	if len(paths) == 0 {
		return 0, nil
	}
	// Pull all referenced blob paths into memory; workload is bounded by retention KeepN.
	referenced := map[string]struct{}{}
	rows := []struct {
		Path string `db:"sbom_blob_path"`
	}{}
	if err := s.db.SelectContext(ctx, &rows, `SELECT sbom_blob_path FROM scan_runs`); err != nil {
		return 0, err
	}
	for _, r := range rows {
		referenced[r.Path] = struct{}{}
	}
	deleted := 0
	for _, p := range paths {
		if _, ok := referenced[p]; ok {
			continue
		}
		if err := s.blob.DeleteBlob(ctx, p); err != nil {
			log.Warn().Err(err).Str("path", p).Msg("orphan_blob_sweeper: delete failed")
			continue
		}
		deleted++
	}
	if deleted > 0 {
		log.Info().Int("deleted", deleted).Msg("orphan_blob_sweeper: reclaimed orphans")
	}
	return deleted, nil
}
