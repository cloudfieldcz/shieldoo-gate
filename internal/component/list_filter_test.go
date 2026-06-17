package component_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// Project labels are stored normalized (lowercased+trimmed) on creation, so the
// Vulnerabilities page project filter must normalize its input too — otherwise a
// mixed-case or padded filter never matches the stored label.
func TestList_ProjectFilter_NormalizesCaseAndWhitespace(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Project labels are always stored lowercase (see internal/project.NormalizeLabel).
	res, err := db.Exec(`INSERT INTO projects (label, display_name, created_via, created_at, enabled)
	                     VALUES ('team-a', 'Team A', 'api', CURRENT_TIMESTAMP, 1)`)
	require.NoError(t, err)
	projectID, err := res.LastInsertId()
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                  VALUES (?, 'billing-api', 'pypi', 1)`, projectID)
	require.NoError(t, err)

	svc := component.NewService(component.ServiceConfig{}, component.NewStore(db))

	cases := []struct {
		name   string
		filter string
	}{
		{"exact", "team-a"},
		{"uppercase", "Team-A"},
		{"padded", "  team-a  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := svc.List(context.Background(), component.ListFilter{ProjectLabel: tc.filter})
			require.NoError(t, err)
			require.Len(t, rows, 1, "filter %q should match the 'team-a' project", tc.filter)
			assert.Equal(t, "team-a", rows[0].ProjectLabel)
		})
	}

	// A non-matching label still filters everything out.
	rows, err := svc.List(context.Background(), component.ListFilter{ProjectLabel: "team-b"})
	require.NoError(t, err)
	assert.Empty(t, rows)
}
