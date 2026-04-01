CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_overrides_unique_active
    ON policy_overrides(ecosystem, name, version, scope)
    WHERE revoked = FALSE;
