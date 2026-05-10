CREATE TABLE IF NOT EXISTS anomalies (
    id                     BIGSERIAL PRIMARY KEY,
    component_id           BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    detected_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    triggering_run_id      BIGINT REFERENCES scan_runs(id) ON DELETE SET NULL,
    severity_delta         BIGINT NOT NULL,
    baseline_mean          DOUBLE PRECISION NOT NULL,
    baseline_stddev        DOUBLE PRECISION NOT NULL,
    sigma                  DOUBLE PRECISION NOT NULL,
    summary                TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anomalies_component_detected ON anomalies(component_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_detected ON anomalies(detected_at DESC);
