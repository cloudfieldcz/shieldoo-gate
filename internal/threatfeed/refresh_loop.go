package threatfeed

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// escalateAfterConsecutiveFailures is how many consecutive refresh failures are
// tolerated at WARN before the failure is logged at ERROR.
//
// Three, at the default 1 h refresh interval, means roughly three hours of an
// unrefreshed feed before the loud line — long enough that a single upstream
// blip, a redeploy of the feed host or a transient DNS failure stays quiet, and
// short enough that a genuinely broken feed is loud within a working morning.
// A line that fires for every benign hiccup is a line operators learn to
// ignore, which is exactly how the original single WARN became invisible.
//
// The threshold is deliberately NOT configurable: it is a log level, not
// policy, and the case that actually matters — an empty feed — bypasses it
// entirely (see refreshFailureLevel).
const escalateAfterConsecutiveFailures = 3

// refreshFailureLevel picks the log level for a failed refresh.
//
// An empty local feed is ERROR from the very first failure: with zero rows in
// threat_feed the builtin-threat-feed scanner returns CLEAN with confidence 1
// for every artifact it is asked about, so the gate is reporting a check it is
// not performing. There is no "wait and see" version of that. A non-empty feed
// is merely going stale, which is worth a WARN until it has persisted.
func refreshFailureLevel(consecutiveFailures int, entries int64) zerolog.Level {
	if entries == 0 {
		return zerolog.ErrorLevel
	}
	if consecutiveFailures >= escalateAfterConsecutiveFailures {
		return zerolog.ErrorLevel
	}
	return zerolog.WarnLevel
}

// Run refreshes the feed once immediately and then on every tick of interval,
// logging each outcome, until ctx is cancelled. It is meant to be run in its
// own goroutine; refresh errors are never fatal.
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	c.refreshAndLog(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshAndLog(ctx)
		}
	}
}

// emptyFeedConsequence spells out what an empty threat_feed table costs. It is
// appended to every message describing one, because the entry count on its own
// reads as a statistic rather than as a scanner that has stopped detecting.
const emptyFeedConsequence = "builtin-threat-feed is returning CLEAN for every artifact without checking anything"

// refreshAndLog performs one refresh and emits exactly one log line describing
// the result, at a level that rises with how bad the situation is.
func (c *Client) refreshAndLog(ctx context.Context) {
	out := c.refreshOnce(ctx)

	if out.err == nil {
		// A refresh that succeeds and leaves the table empty is the same
		// fail-open as one that never completes — the scanner has nothing to
		// match against either way. An upstream serving a valid but empty
		// document (truncated publish, misconfigured CDN, feed emptied at the
		// source) must not be reported as a healthy refresh just because the
		// HTTP exchange went well.
		if out.entries == 0 {
			log.Error().
				Int64("feed_entries", out.entries).
				Msg("threat feed refreshed successfully but the feed is empty: " + emptyFeedConsequence)
			return
		}
		log.Info().Int64("feed_entries", out.entries).Msg("threat feed refresh completed")
		return
	}

	ev := log.WithLevel(refreshFailureLevel(out.consecutiveFailures, out.entries)).
		Err(out.err).
		Int("consecutive_failures", out.consecutiveFailures).
		Int64("feed_entries", out.entries)

	if out.lastSuccess.IsZero() {
		ev = ev.Bool("ever_loaded", false)
	} else {
		ev = ev.Str("stale_for", time.Since(out.lastSuccess).Round(time.Second).String())
	}

	if out.entries == 0 {
		ev.Msg("threat feed refresh failed and the local feed is empty: " + emptyFeedConsequence)
		return
	}
	ev.Msg("threat feed refresh failed; still matching against the last feed contents")
}
