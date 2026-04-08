package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// PackageMetadata holds upstream registry metadata about a package.
type PackageMetadata struct {
	Ecosystem          scanner.Ecosystem
	Name               string
	Maintainers        []Maintainer
	FirstPublished     time.Time
	LatestPublished    time.Time
	PreviousPublished  time.Time // second-to-last release timestamp (for dormancy detection)
	VersionCount       int
	RecentVersionCount int // versions published in last 7 days
	DownloadCount      int // -1 means unavailable
	HasSourceRepo      bool
	SourceRepoURL      string
	Description        string
	OwnershipChanged   bool // true if maintainers differ from prior check (detected externally)
	// V2 fields
	LatestVersion         string // latest version string (for unusual versioning detection)
	YankedVersionCount    int    // number of yanked/deleted versions
	MaintainerPackageCount int   // number of packages by the primary maintainer (-1 = unknown)
	RepoNameMismatch      bool   // true if source repo name doesn't match package name
	ClassifierAnomaly     bool   // true if classifiers appear inconsistent
}

// Maintainer holds basic maintainer identity from upstream registry.
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// fetchMetadata dispatches to the per-ecosystem fetcher.
func fetchMetadata(ctx context.Context, client *http.Client, ecosystem scanner.Ecosystem, name string) (*PackageMetadata, error) {
	switch ecosystem {
	case scanner.EcosystemPyPI:
		return fetchPyPIMetadata(ctx, client, name)
	case scanner.EcosystemNPM:
		return fetchNPMMetadata(ctx, client, name)
	case scanner.EcosystemNuGet:
		return fetchNuGetMetadata(ctx, client, name)
	default:
		return nil, fmt.Errorf("reputation: unsupported ecosystem %s", ecosystem)
	}
}

// --- PyPI ---

type pypiResponse struct {
	Info struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		Summary         string `json:"summary"`
		Description     string `json:"description"`
		Author          string `json:"author"`
		AuthorEmail     string `json:"author_email"`
		Maintainer      string `json:"maintainer"`
		MaintainerEmail string `json:"maintainer_email"`
		ProjectURL      string `json:"project_url"`
		ProjectURLs     map[string]string `json:"project_urls"`
		HomePage        string `json:"home_page"`
		Classifiers     []string `json:"classifiers"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime string `json:"upload_time"`
		Yanked     bool   `json:"yanked"`
	} `json:"releases"`
}

func fetchPyPIMetadata(ctx context.Context, client *http.Client, name string) (*PackageMetadata, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("reputation: pypi request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return doPyPIFetch(client, req, name)
}

// doPyPIFetch performs the HTTP request and parses the PyPI response.
// Extracted for testability (tests inject httptest.Server URLs).
func doPyPIFetch(client *http.Client, req *http.Request, name string) (*PackageMetadata, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation: pypi fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reputation: pypi %s returned %d", name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reputation: pypi read body %s: %w", name, err)
	}

	var data pypiResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("reputation: pypi parse %s: %w", name, err)
	}

	meta := &PackageMetadata{
		Ecosystem:              scanner.EcosystemPyPI,
		Name:                   name,
		VersionCount:           len(data.Releases),
		DownloadCount:          -1, // PyPI JSON API does not expose download counts
		Description:            data.Info.Summary,
		LatestVersion:          data.Info.Version,
		MaintainerPackageCount: -1, // not available from PyPI single-package API
	}

	// Parse maintainers
	if data.Info.Author != "" {
		meta.Maintainers = append(meta.Maintainers, Maintainer{
			Name:  data.Info.Author,
			Email: data.Info.AuthorEmail,
		})
	}
	if data.Info.Maintainer != "" && data.Info.Maintainer != data.Info.Author {
		meta.Maintainers = append(meta.Maintainers, Maintainer{
			Name:  data.Info.Maintainer,
			Email: data.Info.MaintainerEmail,
		})
	}

	// Parse source repo from project_urls
	meta.HasSourceRepo, meta.SourceRepoURL = extractSourceRepo(data.Info.ProjectURLs, data.Info.HomePage)

	// Detect repo name mismatch (source repo doesn't contain package name)
	if meta.HasSourceRepo && meta.SourceRepoURL != "" {
		meta.RepoNameMismatch = detectRepoMismatch(name, meta.SourceRepoURL)
	}

	// Parse release timestamps and count yanked versions
	var timestamps []time.Time
	for _, files := range data.Releases {
		hasYanked := false
		for _, f := range files {
			if f.Yanked {
				hasYanked = true
			}
			if t, err := time.Parse("2006-01-02T15:04:05", f.UploadTime); err == nil {
				timestamps = append(timestamps, t)
				break // one timestamp per version is enough
			}
		}
		if hasYanked {
			meta.YankedVersionCount++
		}
	}

	if len(timestamps) > 0 {
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })
		meta.FirstPublished = timestamps[0]
		meta.LatestPublished = timestamps[len(timestamps)-1]
		if len(timestamps) >= 2 {
			meta.PreviousPublished = timestamps[len(timestamps)-2]
		}

		// Count recent versions (last 7 days)
		cutoff := time.Now().Add(-7 * 24 * time.Hour)
		for _, t := range timestamps {
			if t.After(cutoff) {
				meta.RecentVersionCount++
			}
		}
	}

	return meta, nil
}

// --- npm ---

type npmResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DistTags    struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Maintainers []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"maintainers"`
	Time       map[string]string `json:"time"`
	Repository struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repository"`
	Homepage string `json:"homepage"`
}

func fetchNPMMetadata(ctx context.Context, client *http.Client, name string) (*PackageMetadata, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("reputation: npm request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return doNPMFetch(client, req, name)
}

// doNPMFetch performs the HTTP request and parses the npm response.
// Extracted for testability.
func doNPMFetch(client *http.Client, req *http.Request, name string) (*PackageMetadata, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation: npm fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reputation: npm %s returned %d", name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reputation: npm read body %s: %w", name, err)
	}

	var data npmResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("reputation: npm parse %s: %w", name, err)
	}

	meta := &PackageMetadata{
		Ecosystem:              scanner.EcosystemNPM,
		Name:                   name,
		DownloadCount:          -1, // requires separate API call (api.npmjs.org/downloads)
		Description:            data.Description,
		LatestVersion:          data.DistTags.Latest,
		MaintainerPackageCount: -1,
	}

	// Maintainers
	for _, m := range data.Maintainers {
		meta.Maintainers = append(meta.Maintainers, Maintainer{Name: m.Name, Email: m.Email})
	}

	// Source repo
	if data.Repository.URL != "" {
		meta.HasSourceRepo = true
		meta.SourceRepoURL = data.Repository.URL
	} else if data.Homepage != "" && (strings.Contains(data.Homepage, "github.com") || strings.Contains(data.Homepage, "gitlab.com")) {
		meta.HasSourceRepo = true
		meta.SourceRepoURL = data.Homepage
	}

	// Detect repo name mismatch
	if meta.HasSourceRepo && meta.SourceRepoURL != "" {
		meta.RepoNameMismatch = detectRepoMismatch(name, meta.SourceRepoURL)
	}

	// Parse timestamps from "time" field (npm includes "created", "modified", and per-version timestamps)
	var timestamps []time.Time
	versionCount := 0
	for key, ts := range data.Time {
		if key == "created" || key == "modified" {
			continue
		}
		versionCount++
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			timestamps = append(timestamps, t)
		}
	}
	meta.VersionCount = versionCount

	if len(timestamps) > 0 {
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })
		meta.FirstPublished = timestamps[0]
		meta.LatestPublished = timestamps[len(timestamps)-1]
		if len(timestamps) >= 2 {
			meta.PreviousPublished = timestamps[len(timestamps)-2]
		}

		cutoff := time.Now().Add(-7 * 24 * time.Hour)
		for _, t := range timestamps {
			if t.After(cutoff) {
				meta.RecentVersionCount++
			}
		}
	}

	return meta, nil
}

// --- NuGet ---

type nugetCatalogResponse struct {
	Items []struct {
		Items []struct {
			CatalogEntry struct {
				ID          string   `json:"id"`
				Version     string   `json:"version"`
				Description string   `json:"description"`
				Authors     string   `json:"authors"`
				ProjectURL  string   `json:"projectUrl"`
				Published   string   `json:"published"`
			} `json:"catalogEntry"`
		} `json:"items"`
	} `json:"items"`
}

func fetchNuGetMetadata(ctx context.Context, client *http.Client, name string) (*PackageMetadata, error) {
	lowerName := strings.ToLower(name)
	url := fmt.Sprintf("https://api.nuget.org/v3/registration5-gz-semver2/%s/index.json", lowerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("reputation: nuget request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation: nuget fetch %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reputation: nuget %s returned %d", name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reputation: nuget read body %s: %w", name, err)
	}

	var data nugetCatalogResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("reputation: nuget parse %s: %w", name, err)
	}

	meta := &PackageMetadata{
		Ecosystem:     scanner.EcosystemNuGet,
		Name:          name,
		DownloadCount: -1,
	}

	var timestamps []time.Time
	for _, page := range data.Items {
		for _, item := range page.Items {
			entry := item.CatalogEntry
			meta.VersionCount++

			if meta.Description == "" {
				meta.Description = entry.Description
			}

			if entry.Authors != "" && len(meta.Maintainers) == 0 {
				meta.Maintainers = append(meta.Maintainers, Maintainer{Name: entry.Authors})
			}

			if entry.ProjectURL != "" && !meta.HasSourceRepo {
				meta.HasSourceRepo = true
				meta.SourceRepoURL = entry.ProjectURL
			}

			if t, err := time.Parse(time.RFC3339, entry.Published); err == nil {
				timestamps = append(timestamps, t)
			}
		}
	}

	if len(timestamps) > 0 {
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].Before(timestamps[j]) })
		meta.FirstPublished = timestamps[0]
		meta.LatestPublished = timestamps[len(timestamps)-1]
		if len(timestamps) >= 2 {
			meta.PreviousPublished = timestamps[len(timestamps)-2]
		}

		cutoff := time.Now().Add(-7 * 24 * time.Hour)
		for _, t := range timestamps {
			if t.After(cutoff) {
				meta.RecentVersionCount++
			}
		}
	}

	return meta, nil
}

// extractSourceRepo finds a source repository URL from PyPI project_urls or homepage.
func extractSourceRepo(projectURLs map[string]string, homePage string) (bool, string) {
	// Check project_urls for common source repository keys
	sourceKeys := []string{"Source", "Source Code", "Repository", "Code", "GitHub", "Homepage"}
	for _, key := range sourceKeys {
		if url, ok := projectURLs[key]; ok && isSourceRepoURL(url) {
			return true, url
		}
	}
	// Case-insensitive fallback
	for key, url := range projectURLs {
		lower := strings.ToLower(key)
		if (strings.Contains(lower, "source") || strings.Contains(lower, "repo") || strings.Contains(lower, "code")) && isSourceRepoURL(url) {
			return true, url
		}
	}
	// Check homepage
	if isSourceRepoURL(homePage) {
		return true, homePage
	}
	return false, ""
}

// isSourceRepoURL returns true if the URL looks like a source repository.
func isSourceRepoURL(url string) bool {
	if url == "" {
		return false
	}
	hosts := []string{"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht"}
	for _, h := range hosts {
		if strings.Contains(url, h) {
			return true
		}
	}
	return false
}

// detectRepoMismatch checks if the source repo URL contains the package name.
// A mismatch suggests the package may be claiming a different project's repository.
func detectRepoMismatch(packageName, repoURL string) bool {
	normalizedPkg := strings.ToLower(strings.ReplaceAll(packageName, "-", ""))
	normalizedPkg = strings.ReplaceAll(normalizedPkg, "_", "")
	normalizedURL := strings.ToLower(repoURL)

	// Extract repo name from URL path (last path segment, strip .git)
	parts := strings.Split(strings.TrimSuffix(normalizedURL, ".git"), "/")
	if len(parts) == 0 {
		return false
	}
	repoName := parts[len(parts)-1]
	repoName = strings.ReplaceAll(repoName, "-", "")
	repoName = strings.ReplaceAll(repoName, "_", "")

	// Check if package name appears in repo name or vice versa
	if strings.Contains(repoName, normalizedPkg) || strings.Contains(normalizedPkg, repoName) {
		return false // names are related
	}

	// Also check the org/user name in path for scoped packages
	if len(parts) >= 2 {
		orgName := strings.ReplaceAll(parts[len(parts)-2], "-", "")
		orgName = strings.ReplaceAll(orgName, "_", "")
		if strings.Contains(normalizedPkg, orgName) {
			return false // package name contains the org name
		}
	}

	return true // names don't match — potential mismatch
}
