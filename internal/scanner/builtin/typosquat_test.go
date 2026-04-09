package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// newTestScanner creates a TyposquatScanner backed by a temporary in-memory SQLite DB.
func newTestScanner(t *testing.T, cfg config.TyposquatConfig) *TyposquatScanner {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	if cfg.MaxEditDistance == 0 {
		cfg.MaxEditDistance = 2
	}
	if cfg.TopPackagesCount == 0 {
		cfg.TopPackagesCount = 5000
	}
	cfg.Enabled = true

	s, err := NewTyposquatScanner(db, cfg)
	require.NoError(t, err)
	return s
}

func TestTyposquatScanner_ExactPopularName_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "requests-2.32.0", Ecosystem: scanner.EcosystemPyPI, Name: "requests",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestTyposquatScanner_EditDistance1_ReturnsSuspicious(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "reqeusts-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: "reqeusts",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.GreaterOrEqual(t, result.Confidence, float32(0.80))
	require.NotEmpty(t, result.Findings)
	assert.Equal(t, "edit-distance", result.Findings[0].Category)
}

func TestTyposquatScanner_EditDistanceTooFar_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "xyzbadname-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: "xyzbadname",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestTyposquatScanner_Homoglyph_ReturnsSuspicious(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	// "l0dash" - digit 0 substituted for letter o in "lodash"
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "l0dash-1.0.0", Ecosystem: scanner.EcosystemNPM, Name: "l0dash",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	hasHomoglyph := false
	for _, f := range result.Findings {
		if f.Category == "homoglyph-match" {
			hasHomoglyph = true
		}
	}
	assert.True(t, hasHomoglyph, "expected homoglyph-match finding")
}

func TestTyposquatScanner_Combosquat_ReturnsSuspicious(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "requests-utils-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: "requests-utils",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	hasCombosquat := false
	for _, f := range result.Findings {
		if f.Category == "combosquatting" {
			hasCombosquat = true
		}
	}
	assert.True(t, hasCombosquat, "expected combosquatting finding")
}

func TestTyposquatScanner_NamespaceConfusion_ReturnsSuspicious(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{
		InternalNamespaces: []string{"@mycompany/"},
	})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "mycompany-utils-1.0.0", Ecosystem: scanner.EcosystemNPM, Name: "@mycompany/utils",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.GreaterOrEqual(t, result.Confidence, float32(0.95))
	require.NotEmpty(t, result.Findings)
	assert.Equal(t, "namespace-confusion", result.Findings[0].Category)
}

func TestTyposquatScanner_ScopedNPM_ExactMatch_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	// @babel/core is the modern scoped version of babel-core (rank #27 in seed data).
	// normalizeName must strip "@" and replace "/" with "-" so that
	// @babel/core normalizes to "babel-core" and matches exactly.
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "npm:babel_core:7.29.0", Ecosystem: scanner.EcosystemNPM, Name: "@babel/core",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict,
		"@babel/core must match popular babel-core, not be flagged as typosquat")
}

func TestNormalizeName_ScopedNPM_StripsAtAndSlash(t *testing.T) {
	assert.Equal(t, "babel-core", normalizeName("@babel/core"))
	assert.Equal(t, "types-node", normalizeName("@types/node"))
	assert.Equal(t, "angular-core", normalizeName("@angular/core"))
	assert.Equal(t, "vue-reactivity", normalizeName("@vue/reactivity"))
}

func TestTyposquatScanner_UnrelatedName_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "my-unique-package-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: "my-unique-package",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestTyposquatScanner_Allowlist_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{
		Allowlist: []string{"reqeusts"},
	})
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "reqeusts-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: "reqeusts",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict, "allowlisted package should be clean")
}

func TestTyposquatScanner_LongName_ReturnsClean(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	longName := strings.Repeat("a", 200)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "long-1.0.0", Ecosystem: scanner.EcosystemPyPI, Name: longName,
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict, "name > 128 chars should skip")
}

func TestTyposquatScanner_SupportedEcosystems(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	ecosystems := s.SupportedEcosystems()
	assert.Len(t, ecosystems, 7)
}

func TestTyposquatScanner_HealthCheck_WithData(t *testing.T) {
	s := newTestScanner(t, config.TyposquatConfig{})
	err := s.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestLevenshtein_KnownDistances(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"kitten", "sitting", 3},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"requests", "reqeusts", 2},
		{"lodash", "l0dash", 1},
	}
	for _, tc := range tests {
		got := Levenshtein(tc.a, tc.b)
		assert.Equal(t, tc.want, got, "levenshtein(%q, %q)", tc.a, tc.b)
	}
}
