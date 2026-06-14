package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

// MigrateConfig configures a one-shot push-blob migration.
type MigrateConfig struct {
	LegacyDir      string        // e.g. os.TempDir()/shieldoo-gate-blobs
	Dest           *BlobStore    // durable destination
	Concurrency    int64         // max parallel blob copies (default 2)
	PerBlobTimeout time.Duration // default 5m
}

// MigrateSummary reports the outcome of a migration run.
type MigrateSummary struct {
	Migrated int
	Skipped  int // already present / verified equal
	Failed   int // digest mismatch or copy error (retained locally)
	Bytes    int64
}

// migrateResult is the per-blob outcome aggregated by MigratePushBlobs.
type migrateResult struct {
	bytes    int64
	migrated bool
	failed   bool
}

// MigratePushBlobs moves blobs from the legacy local layout
// {LegacyDir}/blobs/{algo}/{prefix}/{hex} into the durable store. It recomputes
// SHA-256 BEFORE writing (treats LegacyDir as untrusted), copies, then removes the
// local copy. A digest mismatch is moved aside (.corrupt) and counted as failed.
// Idempotent: content-addressed, safe to re-run.
func MigratePushBlobs(ctx context.Context, cfg MigrateConfig) (MigrateSummary, error) {
	var sum MigrateSummary
	if cfg.Concurrency <= 0 {
		// Each worker holds a whole blob in memory (os.ReadFile), and legacy blobs
		// are capped at 2 GB. Default low so the one-shot command cannot OOM:
		// ceiling ≈ Concurrency × 2 GB. Operators may raise it on a roomy host.
		cfg.Concurrency = 2
	}
	if cfg.PerBlobTimeout <= 0 {
		cfg.PerBlobTimeout = 5 * time.Minute
	}
	blobsRoot := filepath.Join(cfg.LegacyDir, "blobs")
	if _, err := os.Stat(blobsRoot); err != nil {
		if os.IsNotExist(err) {
			return sum, nil // nothing to migrate
		}
		return sum, fmt.Errorf("migrate: stat %s: %w", blobsRoot, err)
	}

	semw := semaphore.NewWeighted(cfg.Concurrency)
	// Collect files first (simple, bounded by inode count), then copy with bounded
	// parallelism. Aggregate counters are updated by a single reader goroutine over a
	// channel to keep them race-free under -race.
	results := make(chan migrateResult, 64)
	var files []string
	err := filepath.WalkDir(blobsRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(d.Name()) == ".corrupt" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return sum, fmt.Errorf("migrate: walk %s: %w", blobsRoot, err)
	}

	done := make(chan struct{})
	go func() {
		for r := range results {
			if r.migrated {
				sum.Migrated++
				sum.Bytes += r.bytes
			}
			if r.failed {
				sum.Failed++
			}
		}
		close(done)
	}()

	for _, path := range files {
		if err := semw.Acquire(ctx, 1); err != nil {
			break
		}
		go func(p string) {
			defer semw.Release(1)
			results <- migrateOne(ctx, cfg, p)
		}(path)
	}
	// Drain: re-acquire all slots to wait for in-flight workers.
	drainErr := semw.Acquire(ctx, cfg.Concurrency)
	close(results)
	<-done

	if drainErr != nil {
		// Context cancelled/timed out mid-run: the summary is PARTIAL. Return an
		// error so the CLI exits non-zero — an interrupted migration must not look
		// like success.
		log.Warn().Err(drainErr).Int("migrated", sum.Migrated).Int("failed", sum.Failed).
			Msg("push blob migration interrupted (partial)")
		return sum, fmt.Errorf("migration interrupted before completion: %w", drainErr)
	}
	log.Info().Int("migrated", sum.Migrated).Int("failed", sum.Failed).
		Int64("bytes", sum.Bytes).Msg("push blob migration complete")
	return sum, nil
}

// migrateOne verifies and copies a single legacy blob file. The expected digest is
// derived from the path: {algo}/{prefix}/{hex} → {algo}:{hex}.
func migrateOne(ctx context.Context, cfg MigrateConfig, path string) migrateResult {
	var res migrateResult
	algo := filepath.Base(filepath.Dir(filepath.Dir(path)))
	hexName := filepath.Base(path)
	expected := algo + ":" + hexName

	data, err := os.ReadFile(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("migrate: read failed (retained)")
		res.failed = true
		return res
	}
	sum := sha256.Sum256(data)
	if algo != "sha256" || hex.EncodeToString(sum[:]) != hexName {
		log.Error().Str("path", path).Str("expected", expected).
			Msg("migrate: digest mismatch, moving aside (.corrupt)")
		_ = os.Rename(path, path+".corrupt")
		res.failed = true
		return res
	}

	cctx, cancel := context.WithTimeout(ctx, cfg.PerBlobTimeout)
	defer cancel()
	if err := cfg.Dest.Put(cctx, expected, data); err != nil {
		log.Error().Err(err).Str("digest", expected).Msg("migrate: durable put failed (retained)")
		res.failed = true
		return res
	}
	if err := os.Remove(path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("migrate: durable write ok but local remove failed")
	}
	res.bytes = int64(len(data))
	res.migrated = true
	return res
}
