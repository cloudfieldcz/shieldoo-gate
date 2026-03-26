package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for Shieldoo Gate.
// promauto registers them automatically on the default registry, and is
// safe to use from multiple test binaries because each test binary gets its
// own process-level registry state.
var (
	// RequestsTotal counts proxy requests by ecosystem and action (served/blocked/quarantined).
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_requests_total",
			Help: "Total number of proxy requests handled.",
		},
		[]string{"ecosystem", "action"},
	)

	// ScanDuration measures scan latency by scanner name.
	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "shieldoo_gate_scan_duration_seconds",
			Help:    "Scan duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"scanner"},
	)

	// CacheSizeBytes tracks the total cache size in bytes per ecosystem.
	CacheSizeBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_cache_size_bytes",
			Help: "Current cache size in bytes per ecosystem.",
		},
		[]string{"ecosystem"},
	)

	// CacheHitsTotal counts cache hits per ecosystem.
	CacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_cache_hits_total",
			Help: "Total number of cache hits.",
		},
		[]string{"ecosystem"},
	)

	// CacheMissesTotal counts cache misses per ecosystem.
	CacheMissesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_cache_misses_total",
			Help: "Total number of cache misses.",
		},
		[]string{"ecosystem"},
	)

	// BlockedTotal counts blocked artifacts by ecosystem and reason.
	BlockedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_blocked_total",
			Help: "Total number of blocked artifact requests.",
		},
		[]string{"ecosystem", "reason"},
	)

	// QuarantinedTotal counts quarantined artifacts per ecosystem.
	QuarantinedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_quarantined_total",
			Help: "Total number of quarantined artifacts.",
		},
		[]string{"ecosystem"},
	)

	// ScannerErrorsTotal counts scanner errors per scanner.
	ScannerErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_scanner_errors_total",
			Help: "Total number of scanner errors.",
		},
		[]string{"scanner"},
	)
)
