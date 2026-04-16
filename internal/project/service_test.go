package project

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func newTestService(t *testing.T, cfg Config) (*serviceImpl, *config.GateDB) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1) // in-memory SQLite: one connection per test
	t.Cleanup(func() { db.Close() })

	svc, err := NewService(cfg, db)
	require.NoError(t, err)
	t.Cleanup(func() { svc.Stop() })

	impl, ok := svc.(*serviceImpl)
	require.True(t, ok)
	return impl, db
}

func TestNormalizeLabel_LowercasesAndValidates(t *testing.T) {
	cases := []struct {
		in   string
		out  string
		ok   bool
	}{
		{"myapp", "myapp", true},
		{"MyApp", "myapp", true},
		{"my-app_01", "my-app_01", true},
		{"  spaces  ", "spaces", true},
		{"", "", false},
		{"-leading-dash", "-leading-dash", false},
		{"bad@chars", "bad@chars", false},
		{"toolonglabel_toolonglabel_toolonglabel_toolonglabel_toolonglabel_x", "toolonglabel_toolonglabel_toolonglabel_toolonglabel_toolonglabel_x", false},
	}
	for _, c := range cases {
		out, ok := NormalizeLabel(c.in, nil)
		assert.Equal(t, c.out, out, "in=%q", c.in)
		assert.Equal(t, c.ok, ok, "in=%q", c.in)
	}
}

func TestService_Resolve_NewLabel_CreatesLazyProject(t *testing.T) {
	svc, db := newTestService(t, Config{Mode: ModeLazy})

	p, err := svc.Resolve(context.Background(), "team-alpha", "pat-hash-A")
	require.NoError(t, err)
	assert.Equal(t, "team-alpha", p.Label)
	assert.Equal(t, "lazy", p.CreatedVia)
	assert.True(t, p.Enabled)

	// Row exists in DB.
	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM projects WHERE label = ?`, "team-alpha"))
	assert.Equal(t, 1, count)
}

func TestService_Resolve_MixedCase_NormalizesToLowercase(t *testing.T) {
	svc, db := newTestService(t, Config{Mode: ModeLazy})

	_, err := svc.Resolve(context.Background(), "MyApp", "pat")
	require.NoError(t, err)

	// Second call with different case must not create a second row.
	_, err = svc.Resolve(context.Background(), "MYAPP", "pat")
	require.NoError(t, err)

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM projects WHERE label = 'myapp'`))
	assert.Equal(t, 1, count)
}

func TestService_Resolve_EmptyLabel_UsesDefault(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeLazy, DefaultLabel: "default"})
	p, err := svc.Resolve(context.Background(), "", "pat")
	require.NoError(t, err)
	assert.Equal(t, "default", p.Label)
}

func TestService_Resolve_InvalidLabel_ReturnsError(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeLazy})
	_, err := svc.Resolve(context.Background(), "bad@chars", "pat")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidLabel)
}

func TestService_Resolve_StrictMode_UnknownLabel_Fails(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeStrict})
	_, err := svc.Resolve(context.Background(), "never-created", "pat")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProjectNotFound)
}

func TestService_Resolve_StrictMode_KnownLabel_Succeeds(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeStrict})
	// Pre-provision via explicit Create.
	_, err := svc.Create("preprovisioned", "", "")
	require.NoError(t, err)

	p, err := svc.Resolve(context.Background(), "preprovisioned", "pat")
	require.NoError(t, err)
	assert.Equal(t, "preprovisioned", p.Label)
}

func TestService_Resolve_HardCap_Returns429(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeLazy, MaxCount: 2})
	// 'default' is already seeded — so MaxCount=2 allows ONE new label.
	_, err := svc.Resolve(context.Background(), "p1", "pat")
	require.NoError(t, err)
	_, err = svc.Resolve(context.Background(), "p2", "pat")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCapReached)
}

func TestService_Resolve_RateLimit_PerIdentity(t *testing.T) {
	// 2/hour, burst 2.
	svc, _ := newTestService(t, Config{Mode: ModeLazy, LazyCreateRate: 2})
	// 2 bursts allowed, 3rd fails for same identity.
	_, err := svc.Resolve(context.Background(), "a", "idA")
	require.NoError(t, err)
	_, err = svc.Resolve(context.Background(), "b", "idA")
	require.NoError(t, err)
	_, err = svc.Resolve(context.Background(), "c", "idA")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRateLimited)
	// Different identity still OK.
	_, err = svc.Resolve(context.Background(), "d", "idB")
	require.NoError(t, err)
}

func TestService_Resolve_Concurrent_NoDuplicateRows(t *testing.T) {
	svc, db := newTestService(t, Config{Mode: ModeLazy})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Resolve(context.Background(), "race", "identityX")
			if err != nil && !errors.Is(err, ErrRateLimited) {
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM projects WHERE label = 'race'`))
	assert.Equal(t, 1, count)
}

func TestService_Resolve_CacheHit_NoDBQuery(t *testing.T) {
	svc, db := newTestService(t, Config{Mode: ModeLazy})
	p1, err := svc.Resolve(context.Background(), "cached", "pat")
	require.NoError(t, err)
	// Remove underlying row, cache should still return project.
	_, err = db.Exec(`DELETE FROM projects WHERE label = 'cached'`)
	require.NoError(t, err)

	p2, err := svc.Resolve(context.Background(), "cached", "pat")
	require.NoError(t, err)
	assert.Equal(t, p1.ID, p2.ID)
}

func TestService_Update_InvalidatesCache(t *testing.T) {
	svc, _ := newTestService(t, Config{Mode: ModeLazy})
	p, err := svc.Resolve(context.Background(), "edit-me", "pat")
	require.NoError(t, err)

	dn := "Edited Display Name"
	require.NoError(t, svc.Update(p.ID, &dn, nil, nil))

	reloaded, err := svc.Resolve(context.Background(), "edit-me", "pat")
	require.NoError(t, err)
	assert.Equal(t, "Edited Display Name", reloaded.DisplayName)
}

func TestService_RecordUsage_Debounced(t *testing.T) {
	svc, db := newTestService(t, Config{Mode: ModeLazy, UsageFlushPeriod: 50 * time.Millisecond})
	// Create artifact row (FK constraint).
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES ('pypi:req-1','pypi','requests','1.0','u','s',1,?,?,'/tmp')`, time.Now(), time.Now())
	require.NoError(t, err)

	p, err := svc.Resolve(context.Background(), "team", "pat")
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		svc.RecordUsage(p.ID, "pypi:req-1")
	}
	// Wait for flush.
	time.Sleep(150 * time.Millisecond)

	var useCount int
	require.NoError(t, db.Get(&useCount,
		`SELECT use_count FROM artifact_project_usage WHERE artifact_id = 'pypi:req-1' AND project_id = ?`, p.ID))
	assert.Equal(t, 5, useCount)
}

func TestContext_RoundTrip(t *testing.T) {
	p := &Project{ID: 42, Label: "ctx"}
	ctx := WithContext(context.Background(), p)
	got := FromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, int64(42), got.ID)
	// Nil project is preserved as absence (not stored).
	assert.Nil(t, FromContext(context.Background()))
}
