package scanner

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	scannerErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_scanner_errors_total",
			Help: "Total number of inline scanner errors by scanner and kind.",
		},
		[]string{"scanner", "kind"},
	)

	circuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_circuit_breaker_state",
			Help: "Inline scanner circuit breaker state, 1=open and 0=closed.",
		},
		[]string{"scanner"},
	)
)
