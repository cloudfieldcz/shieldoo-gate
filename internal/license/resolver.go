package license

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// Resolver produces the effective Policy for a given project, taking into
// account the global config + the per-project override row (if any).
//
// Concurrency: Resolver is safe for use by many goroutines. Internally it
// uses an LRU cache keyed by project_id so the hot path reads at most one
// DB row per project per cache window.
type Resolver struct {
	db         *config.GateDB
	global     Policy // currently-effective global (may be YAML or DB-derived)
	yamlGlobal Policy // immutable copy of startup YAML values — used by ResetToYAML
	cache      *lru.LRU[int64, *Policy]
	mu         sync.Mutex // guards global pointer swaps if SetGlobal is called
}

// ResolverConfig configures a Resolver.
type ResolverConfig struct {
	Global    Policy
	CacheSize int
	CacheTTL  time.Duration
}

// NewResolver creates a Resolver backed by the given DB.
func NewResolver(db *config.GateDB, cfg ResolverConfig) *Resolver {
	if cfg.CacheSize == 0 {
		cfg.CacheSize = 256
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &Resolver{
		db:         db,
		global:     cfg.Global,
		yamlGlobal: cfg.Global, // remember original YAML values
		cache:      lru.NewLRU[int64, *Policy](cfg.CacheSize, nil, cfg.CacheTTL),
	}
}

// Global returns the current global policy.
func (r *Resolver) Global() Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.global
}

// SetGlobal replaces the global policy at runtime and flushes the per-project
// cache (per-project entries that inherit from global would otherwise keep
// returning stale values). Safe for concurrent use.
func (r *Resolver) SetGlobal(p Policy) {
	r.mu.Lock()
	r.global = p
	r.mu.Unlock()
	r.cache.Purge()
}

// YAMLGlobal returns a copy of the original YAML-loaded global policy captured
// at construction time. Used by the DELETE /policy/licenses handler to revert
// from a runtime edit back to the file-config values.
func (r *Resolver) YAMLGlobal() Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.yamlGlobal
}

// ResetToYAML swaps the live global back to the YAML values that were loaded
// at startup. Equivalent to SetGlobal(YAMLGlobal()) — purges the per-project
// cache so inheritors see the reverted values immediately.
func (r *Resolver) ResetToYAML() {
	r.mu.Lock()
	r.global = r.yamlGlobal
	r.mu.Unlock()
	r.cache.Purge()
}

// ResolveForProject returns the effective policy for the project with the
// given ID. If projectID == 0, the global policy is returned.
func (r *Resolver) ResolveForProject(ctx context.Context, projectID int64, projectLabel string) (Policy, error) {
	r.mu.Lock()
	global := r.global
	r.mu.Unlock()

	// projectID == 0 means "no project context" — fall back to global.
	if projectID == 0 {
		return global, nil
	}

	if cached, ok := r.cache.Get(projectID); ok {
		return *cached, nil
	}

	var row projectPolicyRow
	err := r.db.GetContext(ctx, &row,
		`SELECT mode, COALESCE(blocked_json, '') AS blocked_json,
		        COALESCE(warned_json, '') AS warned_json,
		        COALESCE(allowed_json, '') AS allowed_json,
		        COALESCE(unknown_action, '') AS unknown_action
		 FROM project_license_policy WHERE project_id = ?`, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No override → use global.
			r.cache.Add(projectID, &global)
			return global, nil
		}
		return Policy{}, fmt.Errorf("license: resolve for project %d: %w", projectID, err)
	}

	effective := global
	effective.Source = "global"

	switch row.Mode {
	case "disabled":
		// Signal via sentinel source so caller can short-circuit.
		effective = Policy{Source: "project:" + projectLabel + ":disabled"}
	case "override":
		effective.Source = "project:" + projectLabel
		if row.BlockedJSON != "" {
			_ = json.Unmarshal([]byte(row.BlockedJSON), &effective.Blocked)
		}
		if row.WarnedJSON != "" {
			_ = json.Unmarshal([]byte(row.WarnedJSON), &effective.Warned)
		}
		if row.AllowedJSON != "" {
			_ = json.Unmarshal([]byte(row.AllowedJSON), &effective.Allowed)
		}
		if row.UnknownAction != "" {
			effective.UnknownAction = UnknownAction(row.UnknownAction)
		}
	default:
		// "inherit" or unknown → keep global, but mark source.
		effective.Source = "global (inherited by project:" + projectLabel + ")"
	}
	r.cache.Add(projectID, &effective)
	return effective, nil
}

// InvalidateProject evicts a cached policy — call after upsert/delete on the
// project_license_policy table.
func (r *Resolver) InvalidateProject(projectID int64) {
	r.cache.Remove(projectID)
}

// IsDisabled reports whether a Policy was produced via a "disabled" row.
func IsDisabled(p Policy) bool {
	return len(p.Blocked) == 0 && len(p.Warned) == 0 && len(p.Allowed) == 0 &&
		p.UnknownAction == "" &&
		endsWith(p.Source, ":disabled")
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

type projectPolicyRow struct {
	Mode          string `db:"mode"`
	BlockedJSON   string `db:"blocked_json"`
	WarnedJSON    string `db:"warned_json"`
	AllowedJSON   string `db:"allowed_json"`
	UnknownAction string `db:"unknown_action"`
}
