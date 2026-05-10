package ai

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics for AI surfaces. Registered on package init so the /metrics
// endpoint exposes them whether or not ai_features.enabled is true — that keeps
// dashboards stable across config flips.
var (
	draftCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_ai_draft_calls_total",
			Help: "Total number of /ai/draft-ignore-reason invocations by outcome.",
		},
		[]string{"outcome"}, // ok | disabled | budget_exceeded | error
	)
	draftDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shieldoo_ai_draft_duration_seconds",
			Help:    "Latency of the scanner-bridge DraftIgnoreReason RPC.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"outcome"},
	)
	anomalyEvaluatedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shieldoo_ai_anomaly_evaluations_total",
			Help: "Total number of 3σ anomaly evaluations performed (post-scan-run).",
		},
	)
	anomalyDetectedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shieldoo_ai_anomaly_detections_total",
			Help: "Total number of anomalies persisted (3σ exceeded baseline).",
		},
	)
	tokenBudgetUsedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shieldoo_ai_token_budget_used_total",
			Help: "Cumulative number of /ai/draft-ignore-reason calls accounted against the daily budget.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		draftCallsTotal,
		draftDuration,
		anomalyEvaluatedTotal,
		anomalyDetectedTotal,
		tokenBudgetUsedTotal,
	)
}

// recordDraftOutcome stamps both the counter and histogram for a Draft call.
// Only the drafter and its tests should reach for this.
func recordDraftOutcome(outcome string, dur time.Duration) {
	draftCallsTotal.WithLabelValues(outcome).Inc()
	draftDuration.WithLabelValues(outcome).Observe(dur.Seconds())
}

// TokenBudget enforces a soft ceiling on /ai/draft-ignore-reason calls per UTC
// day. The counter is process-local — restarts reset it. Multi-replica deploys
// either rely on the upstream rate-limiter or accept the looser bound.
type TokenBudget struct {
	dailyMax  int64
	used      atomic.Int64
	resetAtNs atomic.Int64 // unix nanos
}

// NewTokenBudget constructs a budget. dailyMax≤0 disables enforcement so callers
// can wire it unconditionally.
func NewTokenBudget(dailyMax int) *TokenBudget {
	b := &TokenBudget{dailyMax: int64(dailyMax)}
	b.resetAtNs.Store(nextMidnightUTC().UnixNano())
	return b
}

// Allow tries to spend one budget unit. Returns true when the call may proceed.
// On day rollover it resets the counter atomically before evaluating.
func (b *TokenBudget) Allow() bool {
	if b == nil || b.dailyMax <= 0 {
		return true
	}
	now := time.Now().UTC()
	if reset := b.resetAtNs.Load(); now.UnixNano() >= reset {
		// Race-tolerant rollover: only the first goroutine to swap wins; others
		// see an already-rotated counter and proceed against the new window.
		if b.resetAtNs.CompareAndSwap(reset, nextMidnightUTC().UnixNano()) {
			b.used.Store(0)
		}
	}
	if b.used.Add(1) > b.dailyMax {
		// Refund the over-budget increment so the gauge tracks attempts allowed.
		b.used.Add(-1)
		return false
	}
	tokenBudgetUsedTotal.Inc()
	return true
}

// Used returns the count consumed in the current window. Useful for tests.
func (b *TokenBudget) Used() int64 {
	if b == nil {
		return 0
	}
	return b.used.Load()
}

func nextMidnightUTC() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}
