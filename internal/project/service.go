package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// Config holds runtime configuration for the project service.
type Config struct {
	Mode             Mode          // "lazy" | "strict"
	DefaultLabel     string        // empty Basic auth username fallback
	LabelRegex       string        // optional override for default regex
	MaxCount         int           // hard cap (0 = unlimited)
	LazyCreateRate   int           // new projects per hour per identity (0 = unlimited)
	CacheSize        int           // LRU entries
	CacheTTL         time.Duration // LRU expiry
	UsageFlushPeriod time.Duration // debounced usage upsert interval (default 30s)
}

func (c Config) withDefaults() Config {
	if c.Mode == "" {
		c.Mode = ModeLazy
	}
	if c.DefaultLabel == "" {
		c.DefaultLabel = DefaultLabel
	}
	if c.MaxCount == 0 {
		c.MaxCount = 1000
	}
	if c.LazyCreateRate == 0 {
		c.LazyCreateRate = 10
	}
	if c.CacheSize == 0 {
		c.CacheSize = 512
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = 5 * time.Minute
	}
	if c.UsageFlushPeriod == 0 {
		c.UsageFlushPeriod = 30 * time.Second
	}
	return c
}

// serviceImpl implements Service with LRU caching + per-identity rate limiting +
// debounced usage upsert (sync.Map + periodic flush).
type serviceImpl struct {
	cfg   Config
	db    *config.GateDB
	re    *regexp.Regexp
	cache *lru.LRU[string, *Project]

	// Per-identity rate limiters (PAT hash → limiter). In-memory only.
	limitersMu sync.Mutex
	limiters   map[string]*rate.Limiter

	// Debounced usage tracker: (artifactID, projectID) → {firstUse, lastUse, count}.
	usageMu sync.Mutex
	usage   map[usageKey]*usageBuf

	stopFlush chan struct{}
	wg        sync.WaitGroup
}

type usageKey struct {
	artifactID string
	projectID  int64
}

type usageBuf struct {
	firstUsed time.Time
	lastUsed  time.Time
	count     int64
}

// NewService creates a new project service and starts the background usage flush.
func NewService(cfg Config, db *config.GateDB) (Service, error) {
	cfg = cfg.withDefaults()
	re := defaultLabelRegex
	if cfg.LabelRegex != "" {
		r, err := regexp.Compile(cfg.LabelRegex)
		if err != nil {
			return nil, fmt.Errorf("project: compile label regex %q: %w", cfg.LabelRegex, err)
		}
		re = r
	}

	cache := lru.NewLRU[string, *Project](cfg.CacheSize, nil, cfg.CacheTTL)

	s := &serviceImpl{
		cfg:       cfg,
		db:        db,
		re:        re,
		cache:     cache,
		limiters:  make(map[string]*rate.Limiter),
		usage:     make(map[usageKey]*usageBuf),
		stopFlush: make(chan struct{}),
	}

	s.wg.Add(1)
	go s.flushLoop()
	return s, nil
}

// Resolve normalizes rawLabel (lowercase + regex) and returns the matching project.
// identity is used for per-identity rate limiting on lazy-create (pass the PAT
// SHA-256 hash, or "global-token" for the shared global token).
func (s *serviceImpl) Resolve(ctx context.Context, rawLabel string, identity string) (*Project, error) {
	// Empty Basic auth username → default project fallback.
	if strings.TrimSpace(rawLabel) == "" {
		rawLabel = s.cfg.DefaultLabel
	}

	label, ok := NormalizeLabel(rawLabel, s.re)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidLabel, rawLabel)
	}

	// 1. LRU cache
	if p, ok := s.cache.Get(label); ok {
		return p, nil
	}

	// 2. SELECT (read-only, no write lock).
	p, err := s.getByLabelCtx(ctx, label)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if p != nil {
		s.cache.Add(label, p)
		return p, nil
	}

	// 3. Unknown label — decide by mode.
	if s.cfg.Mode == ModeStrict {
		return nil, fmt.Errorf("%w: %q", ErrProjectNotFound, label)
	}

	// 4. Lazy-create: rate-limit check per identity.
	if !s.rateLimiterFor(identity).Allow() {
		return nil, fmt.Errorf("%w: identity=%s", ErrRateLimited, redactIdentity(identity))
	}

	// 5. Hard cap check.
	if s.cfg.MaxCount > 0 {
		var count int
		if err := s.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM projects`); err != nil {
			return nil, fmt.Errorf("project: count: %w", err)
		}
		if count >= s.cfg.MaxCount {
			return nil, ErrCapReached
		}
	}

	// 6. INSERT OR IGNORE + SELECT — race-safe via UNIQUE constraint.
	// Use TRUE literal so the statement is portable across SQLite (INTEGER
	// affinity) and PostgreSQL (BOOLEAN).
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (label, display_name, created_via, created_at, enabled)
		 VALUES (?, ?, 'lazy', ?, TRUE)
		 ON CONFLICT (label) DO NOTHING`,
		label, label, now,
	); err != nil {
		return nil, fmt.Errorf("project: insert-or-ignore: %w", err)
	}

	p, err = s.getByLabelCtx(ctx, label)
	if err != nil {
		return nil, fmt.Errorf("project: re-select after insert: %w", err)
	}
	s.cache.Add(label, p)
	log.Info().Str("label", label).Str("via", "lazy").Msg("project: lazy-created")
	return p, nil
}

func (s *serviceImpl) rateLimiterFor(identity string) *rate.Limiter {
	if s.cfg.LazyCreateRate <= 0 {
		// unlimited
		return rate.NewLimiter(rate.Inf, 0)
	}
	key := identity
	if key == "" {
		key = "anonymous"
	}
	s.limitersMu.Lock()
	defer s.limitersMu.Unlock()
	if l, ok := s.limiters[key]; ok {
		return l
	}
	// N new projects per hour, burst = N.
	perHour := float64(s.cfg.LazyCreateRate) / 3600.0
	l := rate.NewLimiter(rate.Limit(perHour), s.cfg.LazyCreateRate)
	s.limiters[key] = l
	return l
}

func (s *serviceImpl) getByLabelCtx(ctx context.Context, label string) (*Project, error) {
	var p Project
	err := s.db.GetContext(ctx, &p,
		`SELECT id, label, COALESCE(display_name, '') AS display_name,
		        COALESCE(description, '') AS description,
		        created_at, created_via, enabled
		 FROM projects WHERE label = ?`, label)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *serviceImpl) GetByID(id int64) (*Project, error) {
	var p Project
	err := s.db.Get(&p,
		`SELECT id, label, COALESCE(display_name, '') AS display_name,
		        COALESCE(description, '') AS description,
		        created_at, created_via, enabled
		 FROM projects WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *serviceImpl) GetByLabel(label string) (*Project, error) {
	return s.getByLabelCtx(context.Background(), label)
}

func (s *serviceImpl) List() ([]*Project, error) {
	rows := []Project{}
	err := s.db.Select(&rows,
		`SELECT id, label, COALESCE(display_name, '') AS display_name,
		        COALESCE(description, '') AS description,
		        created_at, created_via, enabled
		 FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	out := make([]*Project, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

func (s *serviceImpl) Create(label, displayName, description string) (*Project, error) {
	norm, ok := NormalizeLabel(label, s.re)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidLabel, label)
	}
	if s.cfg.MaxCount > 0 {
		var count int
		if err := s.db.Get(&count, `SELECT COUNT(*) FROM projects`); err != nil {
			return nil, err
		}
		if count >= s.cfg.MaxCount {
			return nil, ErrCapReached
		}
	}
	now := time.Now().UTC()
	dn := displayName
	if dn == "" {
		dn = norm
	}
	res, err := s.db.Exec(
		`INSERT INTO projects (label, display_name, description, created_via, created_at, enabled)
		 VALUES (?, ?, ?, 'api', ?, TRUE)`,
		norm, dn, description, now,
	)
	if err != nil {
		return nil, fmt.Errorf("project: create: %w", err)
	}
	_ = res
	p, err := s.getByLabelCtx(context.Background(), norm)
	if err != nil {
		return nil, err
	}
	s.cache.Add(norm, p)
	return p, nil
}

func (s *serviceImpl) Update(id int64, displayName, description *string, enabled *bool) error {
	// Retrieve the label to invalidate cache later.
	p, err := s.GetByID(id)
	if err != nil {
		return err
	}
	setClauses := []string{}
	args := []any{}
	if displayName != nil {
		setClauses = append(setClauses, "display_name = ?")
		args = append(args, *displayName)
	}
	if description != nil {
		setClauses = append(setClauses, "description = ?")
		args = append(args, *description)
	}
	if enabled != nil {
		setClauses = append(setClauses, "enabled = ?")
		// Pass bool so pq driver uses BOOLEAN on Postgres; SQLite accepts
		// 0/1 integer via reflection of bool.
		args = append(args, *enabled)
	}
	if len(setClauses) == 0 {
		return nil
	}
	args = append(args, id)
	query := "UPDATE projects SET " + joinStrings(setClauses, ", ") + " WHERE id = ?"
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("project: update: %w", err)
	}
	s.cache.Remove(p.Label)
	return nil
}

func (s *serviceImpl) Disable(id int64) error {
	f := false
	return s.Update(id, nil, nil, &f)
}

func (s *serviceImpl) InvalidateCache(label string) {
	s.cache.Remove(label)
}

// RecordUsage buffers a usage event for debounced upsert.
func (s *serviceImpl) RecordUsage(projectID int64, artifactID string) {
	if projectID <= 0 || artifactID == "" {
		return
	}
	key := usageKey{artifactID: artifactID, projectID: projectID}
	now := time.Now().UTC()
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if buf, ok := s.usage[key]; ok {
		buf.lastUsed = now
		buf.count++
		return
	}
	s.usage[key] = &usageBuf{firstUsed: now, lastUsed: now, count: 1}
}

func (s *serviceImpl) flushLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.UsageFlushPeriod)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.flushUsage()
		case <-s.stopFlush:
			s.flushUsage()
			return
		}
	}
}

func (s *serviceImpl) flushUsage() {
	s.usageMu.Lock()
	batch := s.usage
	s.usage = make(map[usageKey]*usageBuf)
	s.usageMu.Unlock()

	if len(batch) == 0 {
		return
	}
	for k, v := range batch {
		// Upsert: insert new row OR update last_used_at + use_count.
		_, err := s.db.Exec(
			`INSERT INTO artifact_project_usage
			     (artifact_id, project_id, first_used_at, last_used_at, use_count)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT (artifact_id, project_id)
			 DO UPDATE SET last_used_at = excluded.last_used_at,
			               use_count   = artifact_project_usage.use_count + excluded.use_count`,
			k.artifactID, k.projectID, v.firstUsed, v.lastUsed, v.count,
		)
		if err != nil {
			log.Warn().Err(err).
				Str("artifact_id", k.artifactID).
				Int64("project_id", k.projectID).
				Msg("project: usage upsert failed")
		}
	}
}

// Stop flushes pending usage records and terminates the background goroutine.
func (s *serviceImpl) Stop() {
	select {
	case <-s.stopFlush:
		return // already stopped
	default:
	}
	close(s.stopFlush)
	s.wg.Wait()
}

// redactIdentity returns a truncated/redacted form of a PAT hash for log output.
func redactIdentity(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, sep)
}
