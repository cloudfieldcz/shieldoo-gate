package alert

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// Default configuration values.
const (
	DefaultBufferSize       = 256
	DefaultMaxRetries       = 3
	DefaultRetryBaseDelay   = 1 * time.Second
	DefaultCircuitThreshold = 5
	DefaultCooldown         = 60 * time.Second
)

// Alerter sends notifications for audit events.
type Alerter interface {
	// Dispatch sends an alert for the given audit entry.
	// Must be non-blocking (channel send internally).
	Dispatch(ctx context.Context, entry model.AuditEntry)
	// Close gracefully shuts down the alerter, flushing pending alerts.
	Close() error
}

// ChannelSender is the interface that concrete alert channels implement.
type ChannelSender interface {
	Send(ctx context.Context, payload AlertPayload) error
	Name() string
}

// HTTPError represents an HTTP error with a status code, allowing
// the retry logic to distinguish client errors (4xx) from server errors.
type HTTPError struct {
	StatusCode int
	Err        error
}

func (e *HTTPError) Error() string { return e.Err.Error() }
func (e *HTTPError) Unwrap() error { return e.Err }

// isClientError returns true if the error is an HTTP 4xx error.
func isClientError(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= http.StatusBadRequest && httpErr.StatusCode < http.StatusInternalServerError
	}
	return false
}

// Prometheus metrics.
var (
	alertsDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_alerts_dropped_total",
			Help: "Total number of alerts dropped due to full buffer.",
		},
		[]string{"channel"},
	)
	alertsSentTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_alerts_sent_total",
			Help: "Total number of alerts successfully sent.",
		},
		[]string{"channel"},
	)
	alertsFailedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_alerts_failed_total",
			Help: "Total number of alerts that failed after all retries.",
		},
		[]string{"channel"},
	)
)

func init() {
	prometheus.MustRegister(alertsDroppedTotal, alertsSentTotal, alertsFailedTotal)
}

// ChannelWorker processes alerts for a single channel in its own goroutine.
type ChannelWorker struct {
	channel           ChannelSender
	on                map[model.EventType]bool // filter; nil = ALL events
	queue             chan AlertPayload
	limiter           *rate.Limiter
	wg                sync.WaitGroup
	cancel            context.CancelFunc
	ctx               context.Context
	consecutiveFails  int
	cooldownUntil     time.Time
	circuitThreshold  int
	cooldownDuration  time.Duration
	maxRetries        int
	retryBaseDelay    time.Duration
}

// ChannelConfig holds configuration for creating a ChannelWorker.
type ChannelConfig struct {
	Channel          ChannelSender
	EventFilter      []model.EventType       // nil or empty = all events
	BufferSize       int                     // default 256
	RateLimit        rate.Limit              // events per second; 0 = unlimited
	RateBurst        int                     // burst size for rate limiter
	CircuitThreshold int                     // consecutive failures before cooldown; default 5
	CooldownDuration time.Duration           // cooldown after circuit opens; default 60s
	MaxRetries       int                     // max retry attempts; default 3
	RetryBaseDelay   time.Duration           // base delay for exponential backoff; default 1s
}

func newChannelWorker(cfg ChannelConfig) *ChannelWorker {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	circuitThreshold := cfg.CircuitThreshold
	if circuitThreshold <= 0 {
		circuitThreshold = DefaultCircuitThreshold
	}
	cooldown := cfg.CooldownDuration
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	retryBase := cfg.RetryBaseDelay
	if retryBase <= 0 {
		retryBase = DefaultRetryBaseDelay
	}

	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		burst := cfg.RateBurst
		if burst <= 0 {
			burst = 1
		}
		limiter = rate.NewLimiter(cfg.RateLimit, burst)
	}

	var on map[model.EventType]bool
	if len(cfg.EventFilter) > 0 {
		on = make(map[model.EventType]bool, len(cfg.EventFilter))
		for _, et := range cfg.EventFilter {
			on[et] = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &ChannelWorker{
		channel:          cfg.Channel,
		on:               on,
		queue:            make(chan AlertPayload, bufSize),
		limiter:          limiter,
		cancel:           cancel,
		ctx:              ctx,
		circuitThreshold: circuitThreshold,
		cooldownDuration: cooldown,
		maxRetries:       maxRetries,
		retryBaseDelay:   retryBase,
	}

	w.wg.Add(1)
	go w.run()

	return w
}

// matches returns true if the event type passes this worker's filter.
func (w *ChannelWorker) matches(eventType model.EventType) bool {
	if w.on == nil {
		return true // nil filter = all events
	}
	return w.on[eventType]
}

// dispatch attempts a non-blocking send to the worker queue.
// Returns false if the queue is full (alert dropped).
func (w *ChannelWorker) dispatch(payload AlertPayload) bool {
	select {
	case w.queue <- payload:
		return true
	default:
		alertsDroppedTotal.WithLabelValues(w.channel.Name()).Inc()
		log.Warn().
			Str("channel", w.channel.Name()).
			Str("event_type", payload.EventType).
			Msg("alert dropped: buffer full")
		return false
	}
}

// run is the worker goroutine that reads from the queue and sends alerts.
func (w *ChannelWorker) run() {
	defer w.wg.Done()

	for payload := range w.queue {
		w.processPayload(payload)
	}
}

// processPayload handles rate limiting, circuit breaker, and retry logic.
func (w *ChannelWorker) processPayload(payload AlertPayload) {
	name := w.channel.Name()

	// Circuit breaker: skip if in cooldown.
	if w.consecutiveFails >= w.circuitThreshold {
		now := time.Now()
		if now.Before(w.cooldownUntil) {
			alertsFailedTotal.WithLabelValues(name).Inc()
			log.Debug().
				Str("channel", name).
				Time("cooldown_until", w.cooldownUntil).
				Msg("circuit breaker open, skipping alert")
			return
		}
		// Cooldown expired, reset circuit.
		w.consecutiveFails = 0
	}

	// Rate limiter.
	if w.limiter != nil {
		if err := w.limiter.Wait(w.ctx); err != nil {
			return // context cancelled
		}
	}

	// Retry with exponential backoff.
	var lastErr error
	for attempt := range w.maxRetries {
		if err := w.channel.Send(w.ctx, payload); err != nil {
			lastErr = err
			// Do not retry on client errors (4xx).
			if isClientError(err) {
				log.Warn().Err(err).
					Str("channel", name).
					Msg("alert send failed with client error, not retrying")
				break
			}

			delay := w.retryBaseDelay * (1 << attempt)
			log.Warn().Err(err).
				Str("channel", name).
				Int("attempt", attempt+1).
				Dur("retry_in", delay).
				Msg("alert send failed, retrying")

			select {
			case <-time.After(delay):
				continue
			case <-w.ctx.Done():
				return
			}
		} else {
			// Success.
			w.consecutiveFails = 0
			alertsSentTotal.WithLabelValues(name).Inc()
			return
		}
	}

	// All retries exhausted.
	w.consecutiveFails++
	if w.consecutiveFails >= w.circuitThreshold {
		w.cooldownUntil = time.Now().Add(w.cooldownDuration)
		log.Error().
			Str("channel", name).
			Dur("cooldown", w.cooldownDuration).
			Msg("circuit breaker opened")
	}
	alertsFailedTotal.WithLabelValues(name).Inc()
	log.Error().Err(lastErr).
		Str("channel", name).
		Msg("alert send failed after all retries")
}

// close stops the worker and waits for it to drain.
func (w *ChannelWorker) close() {
	close(w.queue)
	w.wg.Wait()
	w.cancel()
}

// MultiAlerter dispatches alerts to multiple channel workers.
type MultiAlerter struct {
	workers []*ChannelWorker
}

// Compile-time interface check.
var _ Alerter = (*MultiAlerter)(nil)

// NewMultiAlerter creates a MultiAlerter with workers for each channel config.
func NewMultiAlerter(configs []ChannelConfig) *MultiAlerter {
	workers := make([]*ChannelWorker, len(configs))
	for i, cfg := range configs {
		workers[i] = newChannelWorker(cfg)
	}
	return &MultiAlerter{workers: workers}
}

// Dispatch converts the audit entry to a payload and fans out to all matching workers.
func (m *MultiAlerter) Dispatch(ctx context.Context, entry model.AuditEntry) {
	payload := NewAlertPayload(entry)

	for _, w := range m.workers {
		if w.matches(entry.EventType) {
			w.dispatch(payload)
		}
	}
}

// Close gracefully shuts down all workers, flushing pending alerts.
func (m *MultiAlerter) Close() error {
	for _, w := range m.workers {
		w.close()
	}
	return nil
}
