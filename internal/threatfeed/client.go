package threatfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// FeedEntry represents a single malicious artifact entry from the community threat feed.
type FeedEntry struct {
	SHA256      string   `json:"sha256"`
	Ecosystem   string   `json:"ecosystem"`
	PackageName string   `json:"package_name"`
	Versions    []string `json:"versions"`
	ReportedAt  string   `json:"reported_at"`
	SourceURL   string   `json:"source_url"`
	IoCs        []string `json:"iocs"`
}

// FeedResponse is the top-level JSON structure returned by the threat feed endpoint.
type FeedResponse struct {
	SchemaVersion string      `json:"schema_version"`
	Updated       string      `json:"updated"`
	Entries       []FeedEntry `json:"entries"`
}

// Client polls a remote threat feed URL and stores entries in the local database.
type Client struct {
	db         *config.GateDB
	feedURL    string
	httpClient *http.Client

	mu                  sync.Mutex
	consecutiveFailures int
	lastSuccess         time.Time // zero value: never refreshed successfully in this process
}

// NewClient creates a new Client using the given database handle and feed URL.
func NewClient(db *config.GateDB, feedURL string) *Client {
	markEnabled()
	return &Client{
		db:      db,
		feedURL: feedURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// refreshOutcome is the observable result of one refresh attempt: what went
// wrong (if anything), how big the local feed is now, and how long the feed has
// been failing. The refresh loop turns this into a log line and the metrics
// helpers turn it into gauges.
type refreshOutcome struct {
	err                 error
	entries             int64 // rows in threat_feed, or entriesUnknown
	consecutiveFailures int
	lastSuccess         time.Time // zero: never loaded in this process
}

// refreshOnce runs one refresh, records the outcome in the client state and in
// the Prometheus metrics, and returns it.
//
// It reports nothing. RefreshNow is the only entry point that turns an outcome
// into a log line, and it is what both the periodic loop and POST
// /api/v1/feed/refresh call — a feed that has silently stopped loading is the
// failure this package exists to make visible, so there is deliberately no
// exported way to refresh without reporting.
func (c *Client) refreshOnce(ctx context.Context) refreshOutcome {
	err := c.fetchAndStore(ctx)
	now := time.Now()

	// Count against a context that survives cancellation of ctx so a shutdown
	// mid-refresh still reports the feed size it left behind.
	countCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	entries := c.countEntries(countCtx)

	// State and metrics move together under the lock so concurrent refreshes
	// cannot publish gauges that disagree with the state they were derived from.
	c.mu.Lock()
	defer c.mu.Unlock()

	if err == nil {
		c.consecutiveFailures = 0
		c.lastSuccess = now
		recordRefreshSuccess(now, entries)
	} else {
		c.consecutiveFailures++
		recordRefreshFailure(c.consecutiveFailures, entries)
	}

	return refreshOutcome{
		err:                 err,
		entries:             entries,
		consecutiveFailures: c.consecutiveFailures,
		lastSuccess:         c.lastSuccess,
	}
}

// countEntries returns the number of rows in the local threat_feed table, or
// entriesUnknown when the count could not be taken.
func (c *Client) countEntries(ctx context.Context) int64 {
	var n int64
	if err := c.db.GetContext(ctx, &n, "SELECT COUNT(*) FROM threat_feed"); err != nil {
		return entriesUnknown
	}
	return n
}

// fetchAndStore performs the actual fetch and upsert.
func (c *Client) fetchAndStore(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.feedURL, nil)
	if err != nil {
		return fmt.Errorf("threatfeed: creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("threatfeed: fetching feed from %s: %w", c.feedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("threatfeed: unexpected status %d from %s", resp.StatusCode, c.feedURL)
	}

	var feedResp FeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feedResp); err != nil {
		return fmt.Errorf("threatfeed: decoding response: %w", err)
	}

	for _, entry := range feedResp.Entries {
		iocsJSON, err := json.Marshal(entry.IoCs)
		if err != nil {
			return fmt.Errorf("threatfeed: marshalling IoCs for %s: %w", entry.SHA256, err)
		}

		_, err = c.db.ExecContext(ctx,
			`INSERT INTO threat_feed
			 (sha256, ecosystem, package_name, version, reported_at, source_url, iocs_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (sha256) DO UPDATE SET
			     ecosystem = EXCLUDED.ecosystem, package_name = EXCLUDED.package_name,
			     version = EXCLUDED.version, reported_at = EXCLUDED.reported_at,
			     source_url = EXCLUDED.source_url, iocs_json = EXCLUDED.iocs_json`,
			entry.SHA256,
			entry.Ecosystem,
			entry.PackageName,
			firstVersion(entry.Versions),
			entry.ReportedAt,
			entry.SourceURL,
			string(iocsJSON),
		)
		if err != nil {
			return fmt.Errorf("threatfeed: inserting entry %s: %w", entry.SHA256, err)
		}
	}

	return nil
}

// firstVersion returns the first element of versions or an empty string.
func firstVersion(versions []string) string {
	if len(versions) > 0 {
		return versions[0]
	}
	return ""
}
