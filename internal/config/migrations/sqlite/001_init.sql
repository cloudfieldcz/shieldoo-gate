CREATE TABLE IF NOT EXISTS artifacts (
    id               TEXT PRIMARY KEY,
    ecosystem        TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT NOT NULL,
    upstream_url     TEXT NOT NULL,
    sha256           TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    cached_at        DATETIME NOT NULL,
    last_accessed_at DATETIME NOT NULL,
    storage_path     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
    scanned_at      DATETIME NOT NULL,
    scanner_name    TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    confidence      REAL NOT NULL,
    findings_json   TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_status (
    artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id),
    status           TEXT NOT NULL,
    quarantine_reason TEXT,
    quarantined_at   DATETIME,
    released_at      DATETIME,
    rescan_due_at    DATETIME,
    last_scan_id     INTEGER REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            DATETIME NOT NULL,
    event_type    TEXT NOT NULL,
    artifact_id   TEXT,
    client_ip     TEXT,
    user_agent    TEXT,
    reason        TEXT,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS threat_feed (
    sha256       TEXT PRIMARY KEY,
    ecosystem    TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version      TEXT,
    reported_at  DATETIME NOT NULL,
    source_url   TEXT,
    iocs_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_artifacts_ecosystem_name ON artifacts(ecosystem, name);
CREATE INDEX IF NOT EXISTS idx_scan_results_artifact ON scan_results(artifact_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_threat_feed_ecosystem ON threat_feed(ecosystem, package_name);
