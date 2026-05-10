package component

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// IgnoreServiceConfig holds runtime configuration for IgnoreService.
type IgnoreServiceConfig struct {
	MaxActivePerComponent int           // hard cap; default 100
	DefaultExpiry         time.Duration // when no expires_at supplied; 0 = never
	MaxReasonLength       int           // default 1000
}

func (c IgnoreServiceConfig) withDefaults() IgnoreServiceConfig {
	if c.MaxActivePerComponent == 0 {
		c.MaxActivePerComponent = 100
	}
	if c.MaxReasonLength == 0 {
		c.MaxReasonLength = 1000
	}
	return c
}

type ignoreServiceImpl struct {
	cfg   IgnoreServiceConfig
	store *Store
	audit AuditWriter
}

// NewIgnoreService constructs an IgnoreService.
func NewIgnoreService(cfg IgnoreServiceConfig, store *Store, audit AuditWriter) IgnoreService {
	return &ignoreServiceImpl{
		cfg:   cfg.withDefaults(),
		store: store,
		audit: audit,
	}
}

// Create inserts a cve_ignores row, applies suppression to the latest done run, and
// writes an ignore_created audit row.
func (s *ignoreServiceImpl) Create(ctx context.Context, componentID int64, cveID, packageName, packageVersion, reason string,
	expiresAt *time.Time, aiDraftAccepted bool, byEmail string, againstRunID int64) (*Ignore, error) {

	if cveID == "" || packageName == "" {
		return nil, fmt.Errorf("%w: cveID/packageName required", ErrInvalidName)
	}
	if reason == "" || len(reason) > s.cfg.MaxReasonLength {
		return nil, fmt.Errorf("%w: reason length 1..%d", ErrInvalidName, s.cfg.MaxReasonLength)
	}
	if expiresAt != nil && expiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("%w: expires_at must be in future", ErrInvalidName)
	}

	// Per-component active-ignore cap enforced application-side (no SQL constraint).
	active, err := s.store.ListActiveIgnores(ctx, componentID)
	if err != nil {
		return nil, err
	}
	if len(active) >= s.cfg.MaxActivePerComponent {
		return nil, ErrRateLimited
	}

	ig := &Ignore{
		ComponentID:     componentID,
		CVEID:           cveID,
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		Reason:          reason,
		AIDraftAccepted: aiDraftAccepted,
		ExpiresAt:       expiresAt,
		CreatedByEmail:  byEmail,
	}
	if againstRunID > 0 {
		v := againstRunID
		ig.CreatedAgainstRunID = &v
	}
	created, err := s.store.CreateIgnore(ctx, ig)
	if err != nil {
		return nil, err
	}

	// Apply suppression to the latest done run for this component.
	latestID, err := s.store.LatestDoneRunID(ctx, componentID)
	if err == nil {
		_ = s.store.ApplySuppression(ctx, created.ID, latestID)
	} else if !errors.Is(err, sql.ErrNoRows) {
		// Not fatal — log but continue.
	}

	if s.audit != nil {
		_ = s.audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:   model.EventIgnoreCreated,
			ComponentID: ptrInt64(componentID),
			IgnoreID:    ptrInt64(created.ID),
			ScanRunID:   ig.CreatedAgainstRunID,
			UserEmail:   byEmail,
			Reason:      fmt.Sprintf("%s on %s", cveID, packageName),
			MetadataJSON: fmt.Sprintf(`{"ai_draft_accepted":%v}`, aiDraftAccepted),
		})
		if aiDraftAccepted {
			_ = s.audit.WriteVulnEvent(ctx, model.AuditEntry{
				EventType:   model.EventAIDraftAccepted,
				ComponentID: ptrInt64(componentID),
				IgnoreID:    ptrInt64(created.ID),
				UserEmail:   byEmail,
			})
		}
	}
	return created, nil
}

// Revoke marks an ignore revoked, clears suppression on the latest run, audits.
func (s *ignoreServiceImpl) Revoke(ctx context.Context, id int64, byEmail string) error {
	ig, err := s.store.GetIgnore(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIgnoreNotFound
		}
		return err
	}
	if ig.RevokedAt != nil {
		return nil // idempotent
	}
	if err := s.store.RevokeIgnore(ctx, id, byEmail); err != nil {
		return err
	}
	latestID, err := s.store.LatestDoneRunID(ctx, ig.ComponentID)
	if err == nil {
		_ = s.store.ClearSuppression(ctx, id, latestID)
	}
	if s.audit != nil {
		_ = s.audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:   model.EventIgnoreRevoked,
			ComponentID: ptrInt64(ig.ComponentID),
			IgnoreID:    ptrInt64(id),
			UserEmail:   byEmail,
			Reason:      fmt.Sprintf("%s on %s", ig.CVEID, ig.PackageName),
		})
	}
	return nil
}

// Get returns an ignore by id.
func (s *ignoreServiceImpl) Get(ctx context.Context, id int64) (*Ignore, error) {
	ig, err := s.store.GetIgnore(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIgnoreNotFound
	}
	return ig, err
}

// ListActive returns all non-revoked ignores for a component.
func (s *ignoreServiceImpl) ListActive(ctx context.Context, componentID int64) ([]*Ignore, error) {
	return s.store.ListActiveIgnores(ctx, componentID)
}

// ListExpired returns ignores past expires_at.
func (s *ignoreServiceImpl) ListExpired(ctx context.Context, now time.Time) ([]*Ignore, error) {
	return s.store.ListExpiredIgnores(ctx, now)
}

// ListRecentRevoked returns ignores revoked within the given duration. Defaults
// to a 60-day window when `since` is non-positive so the UI panel doesn't grow
// unbounded.
func (s *ignoreServiceImpl) ListRecentRevoked(ctx context.Context, componentID int64, since time.Duration) ([]*Ignore, error) {
	if since <= 0 {
		since = 60 * 24 * time.Hour
	}
	return s.store.ListRecentRevokedIgnores(ctx, componentID, time.Now().UTC().Add(-since))
}

// ApplySuppression delegates to the store.
func (s *ignoreServiceImpl) ApplySuppression(ctx context.Context, ignoreID, runID int64) error {
	return s.store.ApplySuppression(ctx, ignoreID, runID)
}

// ClearSuppression delegates to the store.
func (s *ignoreServiceImpl) ClearSuppression(ctx context.Context, ignoreID, runID int64) error {
	return s.store.ClearSuppression(ctx, ignoreID, runID)
}
