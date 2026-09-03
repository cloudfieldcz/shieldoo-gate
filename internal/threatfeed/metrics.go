package threatfeed

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Refresh outcome label values for refreshTotal.
const (
	resultSuccess = "success"
	resultFailure = "failure"
)

// Feed health metrics.
//
// All four gauges are label-free so they exist on /metrics from process start,
// with an explicit zero, rather than appearing only once something has
// happened. That matters here: the failure this instrumentation exists to
// surface is a feed that has *never* loaded, and an absent time series is
// indistinguishable from a scraper that never reached the process.
//
// The gauges are deliberately readable together:
//
//	enabled=0                                   → feed switched off, nothing to alert on
//	enabled=1, last_success_timestamp=0         → never loaded since this process started
//	enabled=1, last_success_timestamp=0, entries=0 → never loaded, ever: builtin-threat-feed
//	                                              is matching every artifact against an
//	                                              empty table and always returning CLEAN
//	enabled=1, last_success_timestamp=T, now-T large → loaded once, now stale
//
// entries is the persistent half of that picture: last_success_timestamp is
// in-process state and resets to 0 on restart, whereas entries reflects the
// threat_feed table the scanner actually queries and survives restarts.
var (
	refreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_threat_feed_refresh_total",
			Help: "Total number of threat feed refresh attempts by result.",
		},
		[]string{"result"},
	)

	refreshConsecutiveFailures = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_threat_feed_consecutive_failures",
			Help: "Number of threat feed refresh failures since the last success.",
		},
	)

	lastSuccessTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_threat_feed_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful threat feed refresh, 0 if the feed has never loaded since process start.",
		},
	)

	feedEntries = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_threat_feed_entries",
			Help: "Number of rows in the local threat_feed table, i.e. the entries builtin-threat-feed matches against. 0 means the scanner cannot detect anything.",
		},
	)

	feedEnabled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_threat_feed_enabled",
			Help: "1 when the threat feed client is configured and running, 0 when the feed is disabled.",
		},
	)
)

// entriesUnknown is the entry count used when the threat_feed table could not
// be counted (DB error, cancelled context). It is deliberately negative so it
// can never be mistaken for an empty feed.
const entriesUnknown int64 = -1

// markEnabled records that a threat feed refresh loop is running.
//
// Called from Client.Run, not from NewClient: the gauge asserts "the feed is
// being refreshed", which is a fact about a running loop rather than about an
// object existing. Without a call to this the enabled gauge stays 0, which is
// what an operator alert must key off to avoid firing on deployments that run
// with the feed switched off.
func markEnabled() {
	feedEnabled.Set(1)
	// Materialise both counter series so a zero success count is visible as
	// "0 successes out of N attempts" rather than as a missing series.
	refreshTotal.WithLabelValues(resultSuccess).Add(0)
	refreshTotal.WithLabelValues(resultFailure).Add(0)
}

// recordRefreshSuccess updates the feed metrics after a successful refresh.
// entries is the row count of the local threat_feed table, or entriesUnknown.
func recordRefreshSuccess(at time.Time, entries int64) {
	refreshTotal.WithLabelValues(resultSuccess).Inc()
	refreshConsecutiveFailures.Set(0)
	lastSuccessTimestamp.Set(float64(at.Unix()))
	setFeedEntries(entries)
}

// recordRefreshFailure updates the feed metrics after a failed refresh.
// consecutive is the number of failures since the last success.
func recordRefreshFailure(consecutive int, entries int64) {
	refreshTotal.WithLabelValues(resultFailure).Inc()
	refreshConsecutiveFailures.Set(float64(consecutive))
	setFeedEntries(entries)
}

// setFeedEntries publishes the local feed size, leaving the previous value in
// place when the count could not be taken.
func setFeedEntries(entries int64) {
	if entries == entriesUnknown {
		return
	}
	feedEntries.Set(float64(entries))
}
