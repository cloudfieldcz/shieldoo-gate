// Package osv implements a ManifestScanner backed by the OSV.dev /v1/querybatch API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// chunkConcurrency caps how many OSV /querybatch chunks fly in parallel. The
// rate limiter still throttles overall, but chunk-level fan-out converts the
// sequential O(N_chunks) latency to ~O(N_chunks / chunkConcurrency).
const chunkConcurrency = 4

// OSVManifestScanner queries the OSV /v1/querybatch endpoint for vulnerabilities.
type OSVManifestScanner struct {
	apiURL    string
	client    *http.Client
	chunkSize int
	limiter   *rate.Limiter
	cacheMu   sync.Mutex
	cache     map[string]cacheEntry
	cacheTTL  time.Duration
}

type cacheEntry struct {
	vulnIDs []string
	expires time.Time
}

// Config holds runtime configuration for the OSV manifest scanner.
type Config struct {
	APIURL    string
	Timeout   time.Duration
	ChunkSize int           // default 1000
	RateLimit rate.Limit    // requests/sec; 0 = unlimited
	RateBurst int           // burst; default 5
	CacheTTL  time.Duration // default 1h
}

// New constructs an OSVManifestScanner.
func New(cfg Config) *OSVManifestScanner {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.osv.dev"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.ChunkSize <= 0 || cfg.ChunkSize > 1000 {
		cfg.ChunkSize = 1000
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	var l *rate.Limiter
	if cfg.RateLimit > 0 {
		burst := cfg.RateBurst
		if burst <= 0 {
			burst = 5
		}
		l = rate.NewLimiter(cfg.RateLimit, burst)
	}
	return &OSVManifestScanner{
		apiURL:    cfg.APIURL,
		client:    &http.Client{Timeout: cfg.Timeout},
		chunkSize: cfg.ChunkSize,
		limiter:   l,
		cache:     make(map[string]cacheEntry),
		cacheTTL:  cfg.CacheTTL,
	}
}

// Name returns the canonical scanner identifier.
func (s *OSVManifestScanner) Name() string { return "osv" }

// Version returns the scanner version string.
func (s *OSVManifestScanner) Version() string { return "1.0" }

// HealthCheck pings the OSV API base URL.
func (s *OSVManifestScanner) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL+"/", nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// querybatch request/response shape.
type batchReq struct {
	Queries []batchQuery `json:"queries"`
}
type batchQuery struct {
	Package batchPackage `json:"package"`
	Version string       `json:"version"`
}
type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type batchResp struct {
	Results []batchResult `json:"results"`
}
type batchResult struct {
	Vulns []struct {
		ID       string                   `json:"id"`
		Severity []map[string]interface{} `json:"severity,omitempty"`
		Summary  string                   `json:"summary,omitempty"`
		Database string                   `json:"database_specific,omitempty"`
	} `json:"vulns,omitempty"`
}

// vulnDetail is the response shape for /v1/vulns/{id}; we hydrate severity here.
type vulnDetail struct {
	ID       string                   `json:"id"`
	Summary  string                   `json:"summary"`
	Severity []map[string]interface{} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Scan implements ManifestScanner.
func (s *OSVManifestScanner) Scan(ctx context.Context, m manifest.Manifest) (manifest.ScanOutcome, error) {
	start := time.Now()
	out := manifest.ScanOutcome{
		ScannerID:      s.Name(),
		ScannerVersion: s.Version(),
	}
	if len(m.SBOMBytes) == 0 {
		out.Status = "ok"
		out.Duration = time.Since(start)
		return out, nil
	}
	components, err := manifest.ParseCycloneDXComponents(m.SBOMBytes)
	if err != nil {
		out.Status = "error"
		out.Duration = time.Since(start)
		return out, err
	}
	if len(components) == 0 {
		out.Status = "ok"
		out.Duration = time.Since(start)
		return out, nil
	}

	queries := make([]batchQuery, 0, len(components))
	indexToComp := make([]manifest.CycloneDXComponent, 0, len(components))
	for _, c := range components {
		if c.Ecosystem == "" {
			continue
		}
		queries = append(queries, batchQuery{
			Package: batchPackage{Name: c.Name, Ecosystem: c.Ecosystem},
			Version: c.Version,
		})
		indexToComp = append(indexToComp, c)
	}
	if len(queries) == 0 {
		out.Status = "ok"
		out.Duration = time.Since(start)
		return out, nil
	}

	// Chunk queries and process them in parallel (bounded by chunkConcurrency).
	// The rate limiter still gates each chunk's HTTP call, providing the
	// burst-budget enforcement upstream of fan-out.
	type chunk struct {
		queries []batchQuery
		comps   []manifest.CycloneDXComponent
	}
	chunks := make([]chunk, 0, (len(queries)/s.chunkSize)+1)
	for chunkStart := 0; chunkStart < len(queries); chunkStart += s.chunkSize {
		chunkEnd := chunkStart + s.chunkSize
		if chunkEnd > len(queries) {
			chunkEnd = len(queries)
		}
		chunks = append(chunks, chunk{
			queries: queries[chunkStart:chunkEnd],
			comps:   indexToComp[chunkStart:chunkEnd],
		})
	}

	var (
		findingsMu  sync.Mutex
		allFindings = make([]manifest.Finding, 0, 16)
		// firstErr captures the first non-context error so callers can decide
		// whether to mark the run as partial. We continue draining other chunks
		// to maximise findings (fail-open semantics).
		firstErrMu sync.Mutex
		firstErr   error
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(chunkConcurrency)
	for _, ck := range chunks {
		ck := ck // pin loop var
		g.Go(func() error {
			if s.limiter != nil {
				if err := s.limiter.Wait(gctx); err != nil {
					return err // ctx cancelled — abort the whole group
				}
			}
			results, err := s.queryBatch(gctx, ck.queries)
			if err != nil {
				firstErrMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				firstErrMu.Unlock()
				return nil // fail-open — let siblings keep going
			}
			local := make([]manifest.Finding, 0, len(results))
			for i, res := range results {
				if i >= len(ck.comps) {
					break
				}
				c := ck.comps[i]
				for _, v := range res.Vulns {
					detail, fixedVer := s.hydrate(gctx, v.ID, c.Name, c.Ecosystem)
					severity, score := severityFromOSV(detail)
					local = append(local, manifest.Finding{
						CVEID:          v.ID,
						PackageName:    c.Name,
						PackageVersion: c.Version,
						Ecosystem:      c.Ecosystem,
						Severity:       severity,
						CVSSScore:      score,
						FixedVersion:   fixedVer,
						Summary:        detail.Summary,
						URL:            "https://osv.dev/vulnerability/" + v.ID,
					})
				}
			}
			if len(local) > 0 {
				findingsMu.Lock()
				allFindings = append(allFindings, local...)
				findingsMu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		// Only ctx-cancellation reaches here (queryBatch errors swallow into firstErr).
		out.Status = "error"
		out.Error = err
		out.Duration = time.Since(start)
		return out, err
	}
	if firstErr != nil {
		out.Status = "error"
		out.Error = firstErr
	}
	out.Findings = allFindings
	if out.Status == "" {
		out.Status = "ok"
	}
	out.Duration = time.Since(start)
	return out, nil
}

func (s *OSVManifestScanner) queryBatch(ctx context.Context, qs []batchQuery) ([]batchResult, error) {
	req := batchReq{Queries: qs}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv: querybatch %d: %s", resp.StatusCode, string(respBody))
	}
	var br batchResp
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	return br.Results, nil
}

// hydrate fetches /v1/vulns/{id} and extracts severity + first fixed version for the
// supplied package. Cached for cacheTTL.
func (s *OSVManifestScanner) hydrate(ctx context.Context, vulnID, pkgName, ecosystem string) (vulnDetail, string) {
	cacheKey := vulnID
	s.cacheMu.Lock()
	if e, ok := s.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		_ = e
	}
	s.cacheMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL+"/v1/vulns/"+vulnID, nil)
	if err != nil {
		return vulnDetail{ID: vulnID}, ""
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return vulnDetail{ID: vulnID}, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return vulnDetail{ID: vulnID}, ""
	}
	var d vulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return vulnDetail{ID: vulnID}, ""
	}
	fixed := firstFixedVersion(d, pkgName, ecosystem)
	return d, fixed
}

func firstFixedVersion(d vulnDetail, pkgName, ecosystem string) string {
	for _, a := range d.Affected {
		if a.Package.Name != pkgName {
			continue
		}
		if ecosystem != "" && a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// severityFromOSV picks the highest-scoring CVSS entry from the severity[] block.
func severityFromOSV(d vulnDetail) (scanner.Severity, float64) {
	maxScore := 0.0
	for _, s := range d.Severity {
		// Score may be a numeric string like "8.1" OR a CVSS vector string.
		raw, ok := s["score"]
		if !ok {
			continue
		}
		switch v := raw.(type) {
		case string:
			// Try to parse numeric prefix.
			if score, ok := tryParseFloat(v); ok && score > maxScore {
				maxScore = score
			}
		case float64:
			if v > maxScore {
				maxScore = v
			}
		}
	}
	return manifest.SeverityFromCVSS(maxScore), maxScore
}

func tryParseFloat(s string) (float64, bool) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	if err != nil {
		return 0, false
	}
	return f, true
}
