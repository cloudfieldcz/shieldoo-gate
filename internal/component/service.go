package component

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

// ServiceConfig holds runtime configuration for the component service.
type ServiceConfig struct {
	MaxComponentsPerProject int           // hard cap (default 200)
	StaleThreshold          time.Duration // default 30d
}

func (c ServiceConfig) withDefaults() ServiceConfig {
	if c.MaxComponentsPerProject == 0 {
		c.MaxComponentsPerProject = 200
	}
	if c.StaleThreshold == 0 {
		c.StaleThreshold = 30 * 24 * time.Hour
	}
	return c
}

type serviceImpl struct {
	cfg   ServiceConfig
	store *Store
}

// NewService constructs a Service backed by a Store.
func NewService(cfg ServiceConfig, store *Store) Service {
	return &serviceImpl{cfg: cfg.withDefaults(), store: store}
}

// Resolve returns the component identified by (projectID, name). When autoCreate is true
// and the component does not exist, lazy-create it (subject to the per-project cap).
func (s *serviceImpl) Resolve(ctx context.Context, projectID int64, name string, autoCreate bool, ecosystem string) (*Component, error) {
	if !ValidateComponentName(name) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	c, err := s.store.GetComponentByName(ctx, projectID, name)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !autoCreate {
		return nil, ErrNotFound
	}
	if ecosystem == "" {
		ecosystem = "multi"
	}
	created, err := s.store.CreateComponent(ctx, projectID, name, ecosystem, "lazy", s.cfg.MaxComponentsPerProject)
	if err != nil {
		return nil, err
	}
	if created == nil {
		return nil, ErrNotFound
	}
	return created, nil
}

// Get returns a component by id.
func (s *serviceImpl) Get(ctx context.Context, id int64) (*Component, error) {
	c, err := s.store.GetComponent(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// GetByName returns a component by (projectID, name).
func (s *serviceImpl) GetByName(ctx context.Context, projectID int64, name string) (*Component, error) {
	c, err := s.store.GetComponentByName(ctx, projectID, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListByProject returns all components owned by a project.
func (s *serviceImpl) ListByProject(ctx context.Context, projectID int64) ([]*Component, error) {
	return s.store.ListComponentsByProject(ctx, projectID)
}

// List returns the denormalized rows for the top-level Vulnerabilities page.
// Filtering is best-effort across SQLite/Postgres. Severity-floor is approximated as
// "any of {critical,high,medium} > 0 depending on floor."
func (s *serviceImpl) List(ctx context.Context, filter ListFilter) ([]*ListRow, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	staleThreshold := s.cfg.StaleThreshold
	staleCutoff := time.Now().UTC().Add(-staleThreshold)

	q := `SELECT c.id, c.project_id, c.name,
		COALESCE(c.display_name, '') AS display_name,
		COALESCE(c.description, '')  AS description,
		c.ecosystem,
		COALESCE(c.repo_url, '')     AS repo_url,
		c.ai_enabled, c.enabled, c.created_at, c.created_via, c.last_scan_id,
		p.label AS project_label,
		sr.started_at AS last_scan_at,
		COALESCE(sr.trigger, '') AS last_scan_trigger,
		COALESCE(sr.critical_count, 0) AS critical_count,
		COALESCE(sr.high_count, 0)     AS high_count,
		COALESCE(sr.medium_count, 0)   AS medium_count,
		COALESCE(sr.low_count, 0)      AS low_count,
		COALESCE(sr.new_critical_count, 0) AS new_critical_count,
		COALESCE(sr.new_high_count, 0)     AS new_high_count,
		(CASE WHEN sr.started_at IS NULL THEN 0
		      WHEN sr.started_at < ? THEN 1
		      ELSE 0 END) AS stale
	FROM components c
	JOIN projects p ON p.id = c.project_id
	LEFT JOIN scan_runs sr ON sr.id = c.last_scan_id
	WHERE c.enabled = TRUE`

	args := []any{staleCutoff}
	// Project labels are stored normalized (lowercased+trimmed) on creation, so
	// normalize the filter value the same way — otherwise a mixed-case or padded
	// filter from the UI never matches the stored label. See project.NormalizeLabel.
	if label, _ := project.NormalizeLabel(filter.ProjectLabel, nil); label != "" {
		q += ` AND p.label = ?`
		args = append(args, label)
	}
	if filter.Ecosystem != "" {
		q += ` AND c.ecosystem = ?`
		args = append(args, filter.Ecosystem)
	}
	if filter.HasNew {
		q += ` AND (COALESCE(sr.new_critical_count, 0) > 0 OR COALESCE(sr.new_high_count, 0) > 0)`
	}
	if filter.SeverityFloor != "" {
		switch filter.SeverityFloor {
		case SeverityCritical:
			q += ` AND COALESCE(sr.critical_count, 0) > 0`
		case SeverityHigh:
			q += ` AND (COALESCE(sr.critical_count, 0) > 0 OR COALESCE(sr.high_count, 0) > 0)`
		case SeverityMedium:
			q += ` AND (COALESCE(sr.critical_count, 0) > 0 OR COALESCE(sr.high_count, 0) > 0 OR COALESCE(sr.medium_count, 0) > 0)`
		}
	}
	if filter.Query != "" {
		q += ` AND (c.name LIKE ? OR p.label LIKE ?)`
		needle := "%" + filter.Query + "%"
		args = append(args, needle, needle)
	}
	// Pagination: cursor mode wins over offset when both supplied. Cursor mode
	// collapses ORDER BY to id DESC so the keyset is stable and the query is
	// O(LIMIT) regardless of how deep the user has paged.
	if filter.Cursor != "" {
		cursorID, err := strconv.ParseInt(filter.Cursor, 10, 64)
		if err != nil || cursorID <= 0 {
			return nil, fmt.Errorf("component: list: invalid cursor %q", filter.Cursor)
		}
		q += ` AND c.id < ? ORDER BY c.id DESC LIMIT ?`
		args = append(args, cursorID, limit)
	} else {
		q += ` ORDER BY COALESCE(sr.critical_count, 0) DESC, sr.started_at DESC, c.id DESC LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	}

	rows := []ListRow{}
	if err := s.store.db.SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, fmt.Errorf("component: list: %w", err)
	}
	out := make([]*ListRow, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// Update applies partial mutations.
func (s *serviceImpl) Update(ctx context.Context, id int64, displayName, description, repoURL *string, enabled *bool, aiEnabled *bool) error {
	return s.store.UpdateComponent(ctx, id, displayName, description, repoURL, enabled, aiEnabled)
}

// Delete hard-deletes the component (FK ON DELETE RESTRICT will block when ignores exist).
func (s *serviceImpl) Delete(ctx context.Context, id int64) error {
	return s.store.DeleteComponent(ctx, id)
}
