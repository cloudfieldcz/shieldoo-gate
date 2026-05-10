-- Anomalies: 3σ deviation events emitted by the AI AnomalyDetector.
CREATE TABLE IF NOT EXISTS anomalies (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id           INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    detected_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    triggering_run_id      INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    severity_delta         INTEGER NOT NULL,
    baseline_mean          REAL    NOT NULL,
    baseline_stddev        REAL    NOT NULL,
    sigma                  REAL    NOT NULL,
    summary                TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anomalies_component_detected ON anomalies(component_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_detected ON anomalies(detected_at DESC);
