-- Schema migrations tracking table (run-once semantics for future migrations).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version  INTEGER PRIMARY KEY,
    applied_at DATETIME NOT NULL
);

-- Docker repositories table.
CREATE TABLE IF NOT EXISTS docker_repositories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    registry       TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    is_internal    INTEGER NOT NULL DEFAULT 0,
    created_at     DATETIME NOT NULL,
    last_synced_at DATETIME,
    sync_enabled   INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_repos_registry_name ON docker_repositories(registry, name);
