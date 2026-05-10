-- Per-user dismissal of anomaly banners. Insert-only; revocation is a row delete.
CREATE TABLE IF NOT EXISTS anomaly_acknowledgments (
    anomaly_id      INTEGER NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    user_email      TEXT    NOT NULL,
    acknowledged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (anomaly_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_anomaly_acks_user ON anomaly_acknowledgments(user_email, acknowledged_at);
