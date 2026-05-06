package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// manifestBackfillName matches the docs/plans/2026-05-06-docker-image-size.md
// migration number; tracked in data_migrations to guarantee single-run.
const manifestBackfillName = "028_docker_manifest_meta_backfill"

// backfillMaxBacklog short-circuits the eager path when the pending count is
// too large for runDataMigrations' 10-minute ceiling and falls back to lazy-
// on-read. Sized for ~5 ms/row local-disk parses; remote backends would blow
// the budget at much smaller counts.
const backfillMaxBacklog = 50_000

// maxBackfillManifestSize bounds the per-row read so a poisoned cache file
// can't OOM the parser. The handler caps at 10 MB; we allow 15 MB of slack
// for format drift while still keeping the parser bounded.
const maxBackfillManifestSize = 15 << 20

// backfillProgressEvery emits an INFO log every N rows so operators watching
// startup logs see progress on large backfills.
const backfillProgressEvery = 1000

// RunManifestMetaBackfill walks every docker artifact that has no
// docker_manifest_meta sidecar, parses its cached manifest body, and upserts
// the sidecar row. Idempotent: the migration is recorded in data_migrations,
// and per-row UPSERTs make a partial run safe to retry.
//
// Cache misses, oversize bodies, and parse errors are logged and skipped — the
// migration NEVER fails the boot.
//
// Tempfile lifecycle: remote cache backends (S3/Azure/GCS) return a fresh
// tempfile under os.TempDir() per Get; we defer-remove those. The local
// backend returns a stable path inside the cache root and must NOT be removed.
// Detection is by path prefix on os.TempDir() — robust across all backends
// without coupling to a specific store type.
func RunManifestMetaBackfill(ctx context.Context, db *config.GateDB, store cache.CacheStore) error {
	if store == nil {
		log.Info().Msg(manifestBackfillName + ": cache store nil; skipping")
		return nil
	}

	if err := ensureDataMigrationsTable(ctx, db); err != nil {
		return fmt.Errorf("%s: prepare data_migrations: %w", manifestBackfillName, err)
	}

	var applied int
	if err := db.GetContext(ctx, &applied,
		`SELECT COUNT(*) FROM data_migrations WHERE name = ?`, manifestBackfillName,
	); err != nil {
		return fmt.Errorf("%s: read data_migrations: %w", manifestBackfillName, err)
	}
	if applied > 0 {
		return nil
	}

	var pending int
	if err := db.GetContext(ctx, &pending,
		`SELECT COUNT(*) FROM artifacts a
		 LEFT JOIN docker_manifest_meta m ON m.artifact_id = a.id
		 WHERE a.ecosystem = ? AND m.artifact_id IS NULL`,
		"docker",
	); err != nil {
		return fmt.Errorf("%s: count pending: %w", manifestBackfillName, err)
	}

	log.Info().Int("pending", pending).Msg(manifestBackfillName + ": starting")

	if pending > backfillMaxBacklog {
		log.Warn().Int("pending", pending).Int("threshold", backfillMaxBacklog).
			Msg(manifestBackfillName + ": backlog too large for eager backfill — marking applied; UI will read NULL until lazy-on-read is implemented")
		return markMigrationApplied(ctx, db, manifestBackfillName)
	}

	if pending == 0 {
		return markMigrationApplied(ctx, db, manifestBackfillName)
	}

	type row struct {
		ID string `db:"id"`
	}
	var rows []row
	if err := db.SelectContext(ctx, &rows,
		`SELECT a.id FROM artifacts a
		 LEFT JOIN docker_manifest_meta m ON m.artifact_id = a.id
		 WHERE a.ecosystem = ? AND m.artifact_id IS NULL
		 ORDER BY a.id`,
		"docker",
	); err != nil {
		return fmt.Errorf("%s: list pending: %w", manifestBackfillName, err)
	}

	tmpDir := os.TempDir()
	processed, succeeded, skipped := 0, 0, 0
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			log.Warn().Err(err).Int("processed", processed).Int("total", len(rows)).
				Msg(manifestBackfillName + ": context expired before completion")
			return err
		}
		processed++

		// Defense in depth — LocalCacheStore.Get already validates, but failing
		// here on a malformed stored ID is cheaper than rolling through cache.Get.
		if !validBackfillID(r.ID) {
			log.Warn().Str("artifact", r.ID).Msg(manifestBackfillName + ": invalid id; skipping")
			skipped++
			continue
		}

		path, err := store.Get(ctx, r.ID)
		if err != nil {
			if errors.Is(err, cache.ErrNotFound) {
				log.Info().Str("artifact", r.ID).Msg(manifestBackfillName + ": cache miss; skipping")
			} else {
				log.Warn().Err(err).Str("artifact", r.ID).Msg(manifestBackfillName + ": cache get error; skipping")
			}
			skipped++
			continue
		}
		if isUnderTempDir(path, tmpDir) {
			defer os.Remove(path)
		}

		body, err := readBoundedFile(path, maxBackfillManifestSize)
		if err != nil {
			log.Warn().Err(err).Str("artifact", r.ID).Str("path", path).Msg(manifestBackfillName + ": read error; skipping")
			skipped++
			continue
		}

		meta, err := ParseManifestMeta(body)
		if err != nil {
			log.Warn().Err(err).Str("artifact", r.ID).Msg(manifestBackfillName + ": parse error; skipping")
			skipped++
			continue
		}

		if err := UpsertManifestMeta(ctx, db, r.ID, meta); err != nil {
			log.Error().Err(err).Str("artifact", r.ID).Msg(manifestBackfillName + ": upsert error; skipping")
			skipped++
			continue
		}
		succeeded++

		if processed%backfillProgressEvery == 0 {
			log.Info().Int("processed", processed).Int("total", len(rows)).
				Int("succeeded", succeeded).Int("skipped", skipped).
				Msg(manifestBackfillName + ": progress")
		}
	}

	log.Info().Int("processed", processed).Int("succeeded", succeeded).Int("skipped", skipped).
		Msg(manifestBackfillName + ": complete")

	return markMigrationApplied(ctx, db, manifestBackfillName)
}

// readBoundedFile opens path and reads up to limit+1 bytes. Returns an error
// if the file is larger than limit so a poisoned cache can't OOM the parser.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("manifest body exceeds %d bytes", limit)
	}
	return body, nil
}

// isUnderTempDir reports whether path is rooted at tmpDir. Used to identify
// remote-backend tempfiles vs the local backend's stable cache layout — only
// the former should be removed after read.
func isUnderTempDir(path, tmpDir string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	tmp, err := filepath.Abs(tmpDir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(tmp, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// validBackfillID rejects ids whose components contain path-traversal characters.
// LocalCacheStore.Get re-validates; this is purely an early-skip optimization
// that also keeps Warn logs clean.
func validBackfillID(id string) bool {
	parts := strings.SplitN(id, ":", 4)
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if strings.Contains(p, "..") || strings.ContainsAny(p, "/\\") || strings.ContainsRune(p, 0) {
			return false
		}
	}
	return true
}

func ensureDataMigrationsTable(ctx context.Context, db *config.GateDB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS data_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  TIMESTAMP NOT NULL
	)`)
	return err
}

func markMigrationApplied(ctx context.Context, db *config.GateDB, name string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO data_migrations (name, applied_at) VALUES (?, ?)
		 ON CONFLICT (name) DO NOTHING`,
		name, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("mark %s applied: %w", name, err)
	}
	return nil
}
