package threatfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
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
	db         *sqlx.DB
	feedURL    string
	httpClient *http.Client
}

// NewClient creates a new Client using the given database handle and feed URL.
func NewClient(db *sqlx.DB, feedURL string) *Client {
	return &Client{
		db:      db,
		feedURL: feedURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Refresh fetches the threat feed and upserts all entries into the threat_feed table.
// It returns an error if the HTTP request fails or the response cannot be parsed.
func (c *Client) Refresh(ctx context.Context) error {
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
			`INSERT OR REPLACE INTO threat_feed
			 (sha256, ecosystem, package_name, version, reported_at, source_url, iocs_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
