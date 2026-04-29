package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// dataMigration is a Go-level migration that runs after the SQL migrations
// in `migrations/{sqlite,postgres}/`. Used when the rewrite logic is more
// natural in Go than in SQL — e.g. when canonicalization rules already exist
// as a Go function and reimplementing them in cross-dialect SQL would be
// fragile.
type dataMigration struct {
	name string
	fn   func(context.Context, *sqlx.DB) error
}

var dataMigrations = []dataMigration{
	{name: "024_pypi_canonical_names", fn: migratePyPICanonicalNames},
}

// runDataMigrations applies any pending Go-level data migrations. Tracked in
// the `data_migrations` table independently of `schema_migrations` so the
// numbering aligns with SQL migration version numbers.
func runDataMigrations(db *sqlx.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS data_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  TIMESTAMP NOT NULL
	)`); err != nil {
		return fmt.Errorf("config: creating data_migrations: %w", err)
	}
	for _, m := range dataMigrations {
		var count int
		_ = db.Get(&count, db.Rebind("SELECT COUNT(*) FROM data_migrations WHERE name = ?"), m.name)
		if count > 0 {
			continue
		}
		log.Info().Str("migration", m.name).Msg("applying data migration")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err := m.fn(ctx, db)
		cancel()
		if err != nil {
			return fmt.Errorf("config: data migration %s: %w", m.name, err)
		}
		if _, err := db.Exec(db.Rebind("INSERT INTO data_migrations (name, applied_at) VALUES (?, ?)"), m.name, time.Now().UTC()); err != nil {
			return fmt.Errorf("config: marking data migration %s applied: %w", m.name, err)
		}
		log.Info().Str("migration", m.name).Msg("data migration applied")
	}
	return nil
}

// migratePyPICanonicalNames rewrites every PyPI artifact (and dependent rows)
// to use PEP 503 canonical names. See docs/plans/pypi-canonical-name-normalization.md
// for the full design rationale.
//
// Because FK constraints on dependent tables are not declared with ON UPDATE
// CASCADE, we cannot UPDATE artifacts.id in place. The rewrite is therefore
// done as INSERT-new + UPDATE-children + DELETE-old, all inside a single
// transaction so the database is never observed in an inconsistent state.
func migratePyPICanonicalNames(ctx context.Context, db *sqlx.DB) error {
	type pypiRow struct {
		ID      string `db:"id"`
		Name    string `db:"name"`
		Version string `db:"version"`
	}
	var rows []pypiRow
	if err := db.SelectContext(ctx, &rows,
		db.Rebind(`SELECT id, name, version FROM artifacts WHERE ecosystem = ?`),
		string(scanner.EcosystemPyPI),
	); err != nil {
		return fmt.Errorf("listing pypi artifacts: %w", err)
	}

	rewrites := 0
	for _, r := range rows {
		canon := scanner.CanonicalPackageName(scanner.EcosystemPyPI, r.Name)
		if canon == r.Name {
			continue
		}
		newID := rewriteArtifactID(r.ID, canon)
		if newID == "" {
			log.Warn().Str("artifact", r.ID).Msg("skipping pypi canonical-name migration: artifact ID has fewer than 3 segments")
			continue
		}
		if err := rewritePyPIArtifact(ctx, db, r.ID, newID, canon); err != nil {
			return fmt.Errorf("rewrite %s -> %s: %w", r.ID, newID, err)
		}
		rewrites++
	}
	log.Info().Int("rewrites", rewrites).Msg("pypi artifact canonical-name migration: artifacts done")

	// Side tables that key on (ecosystem, name) — not artifact_id — also need
	// the name canonicalized so future lookups by canonical name find them.
	// We use UPDATE ... WHERE name <> canonical(name), evaluating canonical()
	// in Go via a per-row UPDATE (cross-dialect, idempotent).
	if err := canonicalizePyPISideTable(ctx, db, "policy_overrides", []string{"id"}); err != nil {
		return err
	}
	if err := canonicalizePyPISideTable(ctx, db, "triage_cache", []string{"cache_key"}); err != nil {
		return err
	}
	if err := canonicalizePyPISideTable(ctx, db, "package_reputation", []string{"id"}); err != nil {
		return err
	}
	// popular_packages has PRIMARY KEY (ecosystem, name); collapsing two rows
	// into one is plausible if the popular-packages feed already reports both
	// spellings. We delete the non-canonical row in that case.
	if err := canonicalizePopularPackagesPyPI(ctx, db); err != nil {
		return err
	}
	return nil
}

// rewriteArtifactID replaces segment 2 (the package name) of an artifact ID
// with the canonical name, leaving the ecosystem, version, and filename
// segments untouched. Returns "" if the input ID has fewer than 3 segments.
func rewriteArtifactID(id, canonicalName string) string {
	parts := strings.SplitN(id, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	parts[1] = canonicalName
	return strings.Join(parts, ":")
}

// rewritePyPIArtifact moves all references from oldID to newID atomically.
// Children are updated *before* the old artifact row is deleted; the new row
// is inserted *first* so child UPDATEs always have a valid FK target.
func rewritePyPIArtifact(ctx context.Context, db *sqlx.DB, oldID, newID, newName string) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// 1. Insert a copy of the artifact row under the new id+name.
	if _, err := tx.ExecContext(ctx, db.Rebind(`
		INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		SELECT ?, ecosystem, ?, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path
		FROM artifacts WHERE id = ?`),
		newID, newName, oldID,
	); err != nil {
		return fmt.Errorf("insert new artifact row: %w", err)
	}

	// 2. Repoint every dependent table. Order is irrelevant — the new artifact
	//    row already exists, so each UPDATE's FK check sees a valid target.
	for _, q := range []string{
		`UPDATE scan_results            SET artifact_id      = ? WHERE artifact_id      = ?`,
		`UPDATE artifact_status         SET artifact_id      = ? WHERE artifact_id      = ?`,
		`UPDATE audit_log               SET artifact_id      = ? WHERE artifact_id      = ?`,
		`UPDATE version_diff_results    SET artifact_id      = ? WHERE artifact_id      = ?`,
		`UPDATE version_diff_results    SET previous_artifact = ? WHERE previous_artifact = ?`,
		`UPDATE artifact_project_usage  SET artifact_id      = ? WHERE artifact_id      = ?`,
		`UPDATE sbom_metadata           SET artifact_id      = ? WHERE artifact_id      = ?`,
	} {
		if _, err := tx.ExecContext(ctx, db.Rebind(q), newID, oldID); err != nil {
			return fmt.Errorf("repoint %q: %w", q, err)
		}
	}

	// 3. Delete the old artifact row. All ON DELETE CASCADE children were
	//    repointed in step 2, so this is a clean detach with no data loss.
	if _, err := tx.ExecContext(ctx, db.Rebind(`DELETE FROM artifacts WHERE id = ?`), oldID); err != nil {
		return fmt.Errorf("delete old artifact row: %w", err)
	}

	return tx.Commit()
}

// canonicalizePyPISideTable rewrites the `name` column of a side table for any
// PyPI rows whose name is not already canonical. Each row is updated in its
// own statement so we can compute canonical() in Go (cross-dialect). The
// `pkCols` argument names the primary-key columns used to address each row.
func canonicalizePyPISideTable(ctx context.Context, db *sqlx.DB, table string, pkCols []string) error {
	if len(pkCols) == 0 {
		return fmt.Errorf("canonicalizePyPISideTable: %s has no pk cols", table)
	}
	pkSelect := strings.Join(pkCols, ", ")
	q := fmt.Sprintf(`SELECT %s, name FROM %s WHERE ecosystem = ?`, pkSelect, table)
	rows, err := db.QueryxContext(ctx, db.Rebind(q), string(scanner.EcosystemPyPI))
	if err != nil {
		return fmt.Errorf("listing %s for pypi: %w", table, err)
	}
	type updateRec struct {
		pkVals  []any
		newName string
	}
	var updates []updateRec
	for rows.Next() {
		dest := make([]any, len(pkCols)+1)
		ptrs := make([]any, len(pkCols)+1)
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return fmt.Errorf("scanning %s: %w", table, err)
		}
		nameStr, _ := dest[len(pkCols)].(string)
		canon := scanner.CanonicalPackageName(scanner.EcosystemPyPI, nameStr)
		if canon == nameStr {
			continue
		}
		updates = append(updates, updateRec{pkVals: dest[:len(pkCols)], newName: canon})
	}
	rows.Close()

	whereParts := make([]string, len(pkCols))
	for i, col := range pkCols {
		whereParts[i] = col + " = ?"
	}
	updateSQL := fmt.Sprintf(`UPDATE %s SET name = ? WHERE %s`, table, strings.Join(whereParts, " AND "))
	for _, u := range updates {
		args := append([]any{u.newName}, u.pkVals...)
		if _, err := db.ExecContext(ctx, db.Rebind(updateSQL), args...); err != nil {
			return fmt.Errorf("updating %s: %w", table, err)
		}
	}
	if len(updates) > 0 {
		log.Info().Str("table", table).Int("rewrites", len(updates)).Msg("pypi canonical-name migration: side table done")
	}
	return nil
}

// canonicalizePopularPackagesPyPI handles the popular_packages PRIMARY KEY
// (ecosystem, name) collision case: if both `strawberry-graphql` and
// `strawberry_graphql` rows exist, we keep the canonical row (or, if absent,
// rename the non-canonical one) and delete the duplicate.
func canonicalizePopularPackagesPyPI(ctx context.Context, db *sqlx.DB) error {
	type row struct {
		Name string `db:"name"`
	}
	var allRows []row
	if err := db.SelectContext(ctx, &allRows,
		db.Rebind(`SELECT name FROM popular_packages WHERE ecosystem = ?`),
		string(scanner.EcosystemPyPI),
	); err != nil {
		return fmt.Errorf("listing popular_packages pypi: %w", err)
	}
	existing := make(map[string]bool, len(allRows))
	for _, r := range allRows {
		existing[r.Name] = true
	}
	rewrites := 0
	for _, r := range allRows {
		canon := scanner.CanonicalPackageName(scanner.EcosystemPyPI, r.Name)
		if canon == r.Name {
			continue
		}
		if existing[canon] {
			// Canonical row already exists — drop the duplicate.
			if _, err := db.ExecContext(ctx,
				db.Rebind(`DELETE FROM popular_packages WHERE ecosystem = ? AND name = ?`),
				string(scanner.EcosystemPyPI), r.Name,
			); err != nil {
				return fmt.Errorf("deleting popular_packages duplicate: %w", err)
			}
		} else {
			// Rename non-canonical row in place.
			if _, err := db.ExecContext(ctx,
				db.Rebind(`UPDATE popular_packages SET name = ? WHERE ecosystem = ? AND name = ?`),
				canon, string(scanner.EcosystemPyPI), r.Name,
			); err != nil {
				return fmt.Errorf("renaming popular_packages row: %w", err)
			}
			existing[canon] = true
		}
		rewrites++
	}
	if rewrites > 0 {
		log.Info().Int("rewrites", rewrites).Msg("pypi canonical-name migration: popular_packages done")
	}
	return nil
}
