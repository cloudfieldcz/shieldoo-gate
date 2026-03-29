-- Schema migrations tracking table (run-once semantics for future migrations).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version  INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL
);

-- Docker repositories table.
CREATE TABLE IF NOT EXISTS docker_repositories (
    id             SERIAL PRIMARY KEY,
    registry       TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    is_internal    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL,
    last_synced_at TIMESTAMPTZ,
    sync_enabled   BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_repos_registry_name ON docker_repositories(registry, name);
