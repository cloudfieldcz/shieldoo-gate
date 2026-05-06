-- Docker manifest metadata sidecar (1:1 with artifacts where ecosystem='docker').
-- Stores parsed image-size and shape data so the UI can show real "image size"
-- (config.size + sum(layers[].size)) instead of the manifest JSON byte count.
CREATE TABLE IF NOT EXISTS docker_manifest_meta (
    artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    media_type       TEXT NOT NULL,
    is_index         INTEGER NOT NULL DEFAULT 0,
    is_attestation   INTEGER NOT NULL DEFAULT 0,
    total_size_bytes INTEGER,
    layer_count      INTEGER,
    architecture     TEXT,
    os               TEXT,
    schema_version   INTEGER NOT NULL DEFAULT 1,
    parsed_at        DATETIME NOT NULL
);
