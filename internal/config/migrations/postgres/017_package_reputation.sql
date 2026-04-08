CREATE TABLE IF NOT EXISTS package_reputation (
    id               SERIAL PRIMARY KEY,
    ecosystem        TEXT NOT NULL,
    name             TEXT NOT NULL,
    maintainers_json TEXT,
    first_published  TIMESTAMP,
    latest_published TIMESTAMP,
    version_count    INTEGER,
    download_count   INTEGER,
    has_source_repo  BOOLEAN NOT NULL DEFAULT FALSE,
    source_repo_url  TEXT,
    description      TEXT,
    risk_score       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    signals_json     TEXT NOT NULL DEFAULT '{}',
    last_checked     TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_package_reputation_eco_name
    ON package_reputation(ecosystem, name);
