CREATE TABLE IF NOT EXISTS package_reputation (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem        TEXT NOT NULL,
    name             TEXT NOT NULL,
    maintainers_json TEXT,
    first_published  DATETIME,
    latest_published DATETIME,
    version_count    INTEGER,
    download_count   INTEGER,
    has_source_repo  BOOLEAN NOT NULL DEFAULT 0,
    source_repo_url  TEXT,
    description      TEXT,
    risk_score       REAL NOT NULL DEFAULT 0.0,
    signals_json     TEXT NOT NULL DEFAULT '{}',
    last_checked     DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_package_reputation_eco_name
    ON package_reputation(ecosystem, name);
