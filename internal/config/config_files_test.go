package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoConfigFiles are complete gate configs that MUST load + validate.
// Helm values.yaml and the configmap template are intentionally excluded — they
// are chart inputs / Go-template text, not standalone gate configs (the chart is
// render-verified separately with `helm template`).
//
// `.deploy/config.yaml` is the production config; it is gitignored (it lives
// out-of-band, carries deployment specifics) so it is absent on a fresh checkout/CI.
// It is validated when present (a local dev's copy) and skipped otherwise — see the
// os.Stat guard below.
var repoConfigFiles = []string{
	"config.example.yaml",
	"docker/config.yaml",
	"examples/deploy/config.yaml",
	".deploy/config.yaml",
	"tests/e2e-shell/config.e2e.yaml",
}

// TestCommittedConfigs_LoadAndValidate is a regression guard: every committed gate
// config must Load() and Validate() cleanly. It protects the hand-maintained YAML
// (e.g. the multi-upstream-index `default:`/`extra_indexes` restructure) from silent
// typos — a wrong indent or `extra_index` vs `extra_indexes` fails here immediately.
func TestCommittedConfigs_LoadAndValidate(t *testing.T) {
	// The deploy/prod configs inject runtime-only secrets via env (never committed —
	// they carry credentials/URLs): the postgres DSN and the OIDC issuer/client.
	// Provide placeholders so Validate() exercises the real config shape rather than
	// failing on the by-design missing secrets. Harmless for the sqlite/no-auth
	// configs, which simply ignore them.
	t.Setenv("SGW_DATABASE_POSTGRES_DSN", "postgres://sgw:sgw@localhost:5432/shieldoo?sslmode=disable")
	t.Setenv("SGW_AUTH_ISSUER_URL", "https://issuer.example.com")
	t.Setenv("SGW_AUTH_CLIENT_ID", "shieldoo-gate-test")

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	for _, rel := range repoConfigFiles {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(repoRoot, rel)
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				t.Skipf("%s not present (gitignored / absent on this checkout)", rel)
			}
			cfg, err := Load(path)
			require.NoError(t, err, "Load(%s) must succeed", rel)
			require.NotNil(t, cfg)
			assert.NoError(t, cfg.Validate(), "Validate(%s) must succeed", rel)
		})
	}
}
