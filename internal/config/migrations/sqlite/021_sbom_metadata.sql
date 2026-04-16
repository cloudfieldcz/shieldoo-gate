-- SBOM metadata (1:1 with artifacts). The blob itself lives in the blob store.
-- licenses_json is the pre-extracted JSON array of SPDX IDs — enables fast
-- license evaluation without loading the full SBOM blob.
CREATE TABLE IF NOT EXISTS sbom_metadata (
    artifact_id     TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    format          TEXT NOT NULL,
    blob_path       TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    licenses_json   TEXT NOT NULL DEFAULT '[]',
    generated_at    DATETIME NOT NULL,
    generator       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sbom_generated_at ON sbom_metadata(generated_at);
