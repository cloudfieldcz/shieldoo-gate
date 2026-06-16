package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func newSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	s := NewSessionStore(db, time.Hour)
	t.Cleanup(s.Stop)
	return s
}

func TestSessionStore_CreateAndValidate(t *testing.T) {
	s := newSessionStore(t)
	id, err := s.Create(&UserInfo{Subject: "sub-1", Email: "op@example.com", Name: "Op"})
	require.NoError(t, err)
	require.NotEmpty(t, id)

	u, ok := s.Validate(id)
	require.True(t, ok)
	assert.Equal(t, "sub-1", u.Subject)
	assert.Equal(t, "op@example.com", u.Email)
}

func TestSessionStore_UnknownID_Invalid(t *testing.T) {
	s := newSessionStore(t)
	u, ok := s.Validate("does-not-exist")
	assert.False(t, ok)
	assert.Nil(t, u)
	// Empty ID must never validate.
	_, ok = s.Validate("")
	assert.False(t, ok)
}

func TestSessionStore_Expired_IsInvalidAndDeleted(t *testing.T) {
	s := newSessionStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return base }

	id, err := s.Create(&UserInfo{Email: "op@example.com"})
	require.NoError(t, err)

	// Jump past the TTL.
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	_, ok := s.Validate(id)
	assert.False(t, ok, "expired session must not validate")

	// The expired row must have been deleted (reset clock; still gone).
	s.now = func() time.Time { return base }
	_, ok = s.Validate(id)
	assert.False(t, ok, "expired session must be purged on validate")
}

func TestSessionStore_Delete_RevokesImmediately(t *testing.T) {
	s := newSessionStore(t)
	id, err := s.Create(&UserInfo{Email: "op@example.com"})
	require.NoError(t, err)

	s.Delete(id)
	_, ok := s.Validate(id)
	assert.False(t, ok, "deleted session must be revoked at once (logout)")
}

func TestSessionStore_Refresh_SlidesExpiry(t *testing.T) {
	s := newSessionStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return base }

	id, err := s.Create(&UserInfo{Email: "op@example.com"})
	require.NoError(t, err)

	// Just before original expiry, refresh extends the window by another TTL.
	s.now = func() time.Time { return base.Add(59 * time.Minute) }
	ok, err := s.Refresh(id)
	require.NoError(t, err)
	assert.True(t, ok)

	// Past the ORIGINAL expiry but within the refreshed window — still valid.
	s.now = func() time.Time { return base.Add(90 * time.Minute) }
	_, ok = s.Validate(id)
	assert.True(t, ok, "refreshed session should still be valid past original expiry")
}

func TestSessionStore_Refresh_ExpiredFails(t *testing.T) {
	s := newSessionStore(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return base }
	id, err := s.Create(&UserInfo{Email: "op@example.com"})
	require.NoError(t, err)

	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	ok, err := s.Refresh(id)
	require.NoError(t, err)
	assert.False(t, ok, "expired session cannot be refreshed")
}
