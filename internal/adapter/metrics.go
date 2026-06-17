package adapter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var scanErrorModeAppliedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_scan_error_mode_applied_total",
		Help: "Total number of required scanner failure policy decisions by mode and path.",
	},
	[]string{"mode", "path"},
)
