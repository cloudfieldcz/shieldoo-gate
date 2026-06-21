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

// upstreamIndexProbeTotal counts metadata-probe outcomes per ecosystem/index.
// result ∈ {hit, miss, error}. "hit" = index served the package; "miss" = 404;
// "error" = transport/timeout (feeds the circuit breaker).
var upstreamIndexProbeTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_upstream_index_probe_total",
		Help: "Upstream multi-index metadata probe outcomes by ecosystem, index, and result.",
	},
	[]string{"ecosystem", "index", "result"},
)

// upstreamScopedMissTotal counts scoped-namespace lookups that found no serving
// index (404, no fallback). A rising count can indicate a compromised/unreachable
// private index masking a claimed namespace — also audited per request.
var upstreamScopedMissTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_upstream_scoped_miss_total",
		Help: "Scoped multi-index package lookups that returned 404 with no fallback.",
	},
	[]string{"ecosystem"},
)
