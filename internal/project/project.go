// Package project implements the project registry — each Basic auth username
// (lowercased, regex-validated) resolves to a Project record. In lazy mode,
// unknown labels auto-create projects (rate-limited, hard-capped); in strict
// mode, unknown labels are rejected.
//
// Project identification is the basis for per-project license policy, audit
// segmentation, and artifact usage reporting.
package project

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Project represents a single project registry entry.
type Project struct {
	ID          int64     `db:"id"           json:"id"`
	Label       string    `db:"label"        json:"label"`
	DisplayName string    `db:"display_name" json:"display_name,omitempty"`
	Description string    `db:"description"  json:"description,omitempty"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
	CreatedVia  string    `db:"created_via"  json:"created_via"`
	Enabled     bool      `db:"enabled"      json:"enabled"`
}

// Mode controls how unknown labels are handled during Resolve.
type Mode string

const (
	// ModeLazy auto-creates unknown projects (rate-limited, capped).
	ModeLazy Mode = "lazy"
	// ModeStrict rejects unknown labels with ErrProjectNotFound.
	ModeStrict Mode = "strict"

	// DefaultLabel is the fallback label used when Basic auth username is empty.
	DefaultLabel = "default"

	// LabelMaxLength is the maximum allowed label length (after normalization).
	LabelMaxLength = 64
)

// Errors returned by Service.Resolve.
var (
	// ErrInvalidLabel indicates a label failed regex validation.
	ErrInvalidLabel = errors.New("project: invalid label")
	// ErrProjectNotFound indicates strict mode saw an unknown label.
	ErrProjectNotFound = errors.New("project: unknown label (strict mode)")
	// ErrRateLimited indicates the per-identity lazy-create rate limit was exceeded.
	ErrRateLimited = errors.New("project: lazy-create rate limit exceeded")
	// ErrCapReached indicates the global max project count is reached.
	ErrCapReached = errors.New("project: max project count reached")
)

// defaultLabelRegex matches lowercase labels of 1-64 chars: [a-z0-9_-], starting with alnum.
var defaultLabelRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NormalizeLabel lowercases and trims the label. Returns the normalized form and
// whether the label is syntactically valid against the provided regex (or the
// default regex if re is nil).
func NormalizeLabel(raw string, re *regexp.Regexp) (string, bool) {
	label := strings.ToLower(strings.TrimSpace(raw))
	if label == "" {
		return "", false
	}
	r := re
	if r == nil {
		r = defaultLabelRegex
	}
	if !r.MatchString(label) {
		return label, false
	}
	return label, true
}

// Service is the interface exposed to middleware and admin API.
type Service interface {
	// Resolve normalizes the label and returns the matching project.
	// identity is used for per-identity rate limiting on lazy-create.
	Resolve(ctx context.Context, rawLabel string, identity string) (*Project, error)

	// RecordUsage tracks that project used artifactID. Non-blocking — debounced
	// to an in-memory map that is flushed periodically.
	RecordUsage(projectID int64, artifactID string)

	// GetByID, GetByLabel, List — admin API.
	GetByID(id int64) (*Project, error)
	GetByLabel(label string) (*Project, error)
	List() ([]*Project, error)

	// Create explicitly provisions a project (strict mode pre-provisioning, admin API).
	Create(label, displayName, description string) (*Project, error)

	// Update patches display_name / description / enabled.
	Update(id int64, displayName, description *string, enabled *bool) error

	// Disable sets enabled=false (soft-disable, metadata only in v1.2).
	Disable(id int64) error

	// InvalidateCache evicts a label from the LRU (called after Update/Disable).
	InvalidateCache(label string)

	// Stop flushes pending usage upserts and shuts down background goroutines.
	Stop()
}

// ContextKey is a typed key for storing *Project in a request context.
type ContextKey struct{}

// WithContext returns a new context carrying p.
func WithContext(ctx context.Context, p *Project) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, ContextKey{}, p)
}

// FromContext returns the project in ctx, or nil if absent.
func FromContext(ctx context.Context) *Project {
	p, _ := ctx.Value(ContextKey{}).(*Project)
	return p
}
