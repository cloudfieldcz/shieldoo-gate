package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/rs/zerolog/log"
)

// IgnoreExpiryConfig controls the expiry watcher.
type IgnoreExpiryConfig struct {
	Interval time.Duration // default 1h
}

// AuditWriter is the contract used to emit ignore_expired events.
type AuditWriter interface {
	WriteVulnEvent(ctx context.Context, e model.AuditEntry) error
}

// IgnoreExpiryWatcher polls cve_ignores hourly and emits ignore_expired events for
// transitions across expires_at.
type IgnoreExpiryWatcher struct {
	cfg     IgnoreExpiryConfig
	db      *config.GateDB
	ignore  component.IgnoreService
	audit   AuditWriter
	stop    chan struct{}
	doneC   chan struct{}
	emitted map[int64]bool // per-process dedupe
}

// NewIgnoreExpiryWatcher constructs the watcher.
func NewIgnoreExpiryWatcher(cfg IgnoreExpiryConfig, db *config.GateDB, ignore component.IgnoreService, audit AuditWriter) *IgnoreExpiryWatcher {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	return &IgnoreExpiryWatcher{
		cfg:     cfg,
		db:      db,
		ignore:  ignore,
		audit:   audit,
		stop:    make(chan struct{}),
		doneC:   make(chan struct{}),
		emitted: make(map[int64]bool),
	}
}

// Start runs the loop.
func (w *IgnoreExpiryWatcher) Start(ctx context.Context) {
	go func() {
		defer close(w.doneC)
		t := time.NewTicker(w.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.stop:
				return
			case <-t.C:
				w.RunOnce(ctx)
			}
		}
	}()
}

// Stop signals the loop to exit.
func (w *IgnoreExpiryWatcher) Stop() {
	select {
	case <-w.stop:
		return
	default:
		close(w.stop)
	}
	<-w.doneC
}

// RunOnce performs a single expiry sweep.
func (w *IgnoreExpiryWatcher) RunOnce(ctx context.Context) {
	expired, err := w.ignore.ListExpired(ctx, time.Now().UTC())
	if err != nil {
		log.Warn().Err(err).Msg("ignore_expiry: list")
		return
	}
	for _, ig := range expired {
		if w.emitted[ig.ID] {
			continue
		}
		w.emitted[ig.ID] = true
		if w.audit != nil {
			cid := ig.ComponentID
			id := ig.ID
			_ = w.audit.WriteVulnEvent(ctx, model.AuditEntry{
				EventType:   model.EventIgnoreExpired,
				ComponentID: &cid,
				IgnoreID:    &id,
				Reason:      fmt.Sprintf("ignore expired: %s on %s", ig.CVEID, ig.PackageName),
			})
		}
	}
}
