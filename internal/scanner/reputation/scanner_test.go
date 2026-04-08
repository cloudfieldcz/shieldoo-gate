package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// --- Composite score tests ---

func TestCompositeScore_NoSignals_ReturnsZero(t *testing.T) {
	score := compositeScore(nil)
	assert.Equal(t, 0.0, score)
}

func TestCompositeScore_NoFiredSignals_ReturnsZero(t *testing.T) {
	signals := []SignalResult{
		{Name: "a", Fired: false, Weight: 0.5},
		{Name: "b", Fired: false, Weight: 0.8},
	}
	score := compositeScore(signals)
	assert.Equal(t, 0.0, score)
}

func TestCompositeScore_SingleHighSignal_ReturnsWeightedValue(t *testing.T) {
	signals := []SignalResult{
		{Name: "dormant_reactivation", Fired: true, Weight: 0.7},
	}
	score := compositeScore(signals)
	assert.InDelta(t, 0.7, score, 0.001)
}

func TestCompositeScore_MultipleSignals_CombinesCorrectly(t *testing.T) {
	signals := []SignalResult{
		{Name: "package_age", Fired: true, Weight: 0.3},
		{Name: "no_source_repo", Fired: true, Weight: 0.3},
	}
	score := compositeScore(signals)
	assert.InDelta(t, 0.51, score, 0.001)
}

func TestCompositeScore_AllSignalsFired_ReturnsHighScore(t *testing.T) {
	signals := []SignalResult{
		{Name: "a", Fired: true, Weight: 0.3},
		{Name: "b", Fired: true, Weight: 0.3},
		{Name: "c", Fired: true, Weight: 0.7},
		{Name: "d", Fired: true, Weight: 0.8},
	}
	score := compositeScore(signals)
	assert.InDelta(t, 0.9706, score, 0.001)
	assert.True(t, score > 0.9)
}

func TestCompositeScore_MixedFiredAndNot(t *testing.T) {
	signals := []SignalResult{
		{Name: "a", Fired: true, Weight: 0.5},
		{Name: "b", Fired: false, Weight: 0.9},
		{Name: "c", Fired: true, Weight: 0.3},
	}
	score := compositeScore(signals)
	assert.InDelta(t, 0.65, score, 0.001)
}

func TestCompositeScore_SingleWeightOne_ReturnsOne(t *testing.T) {
	signals := []SignalResult{{Name: "critical", Fired: true, Weight: 1.0}}
	score := compositeScore(signals)
	assert.InDelta(t, 1.0, score, 0.001)
}

func TestCompositeScore_SingleWeightZero_ReturnsZero(t *testing.T) {
	signals := []SignalResult{{Name: "noop", Fired: true, Weight: 0.0}}
	score := compositeScore(signals)
	assert.InDelta(t, 0.0, score, 0.001)
}

func TestCompositeScore_IsMonotonic(t *testing.T) {
	base := []SignalResult{{Name: "a", Fired: true, Weight: 0.3}}
	extended := []SignalResult{
		{Name: "a", Fired: true, Weight: 0.3},
		{Name: "b", Fired: true, Weight: 0.2},
	}
	assert.True(t, compositeScore(extended) >= compositeScore(base))
}

func TestCompositeScore_NaN_SafeWithEmptySlice(t *testing.T) {
	score := compositeScore([]SignalResult{})
	assert.False(t, math.IsNaN(score))
	assert.Equal(t, 0.0, score)
}

// --- V1 signal computation tests ---

func defaultSignalsCfg() config.ReputationSignals {
	return config.ReputationSignals{
		PackageAge:            config.SignalConfig{Enabled: true, Weight: 0.3},
		LowDownloads:          config.SignalConfig{Enabled: true, Weight: 0.2},
		NoSourceRepo:          config.SignalConfig{Enabled: true, Weight: 0.3},
		DormantReactivation:   config.SignalConfig{Enabled: true, Weight: 0.7},
		FewVersions:           config.SignalConfig{Enabled: true, Weight: 0.15},
		NoDescription:         config.SignalConfig{Enabled: true, Weight: 0.1},
		VersionCountSpike:     config.SignalConfig{Enabled: true, Weight: 0.4},
		OwnershipChange:       config.SignalConfig{Enabled: true, Weight: 0.8},
		YankedVersions:        config.SignalConfig{Enabled: true, Weight: 0.6},
		UnusualVersioning:     config.SignalConfig{Enabled: true, Weight: 0.2},
		MaintainerEmailDomain: config.SignalConfig{Enabled: true, Weight: 0.15},
		FirstPublication:      config.SignalConfig{Enabled: true, Weight: 0.25},
		RepoMismatch:          config.SignalConfig{Enabled: true, Weight: 0.4},
		ClassifierAnomaly:     config.SignalConfig{Enabled: true, Weight: 0.15},
	}
}

func TestComputeSignals_LegitimatePackage_NoSignalsFired(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-365 * 24 * time.Hour),
		LatestPublished:        time.Now().Add(-24 * time.Hour),
		PreviousPublished:      time.Now().Add(-48 * time.Hour),
		VersionCount:           20,
		DownloadCount:          10000,
		HasSourceRepo:          true,
		SourceRepoURL:          "https://github.com/user/mypackage",
		Description:            "A great package",
		LatestVersion:          "2.1.0",
		MaintainerPackageCount: 5,
		Maintainers:            []Maintainer{{Name: "user", Email: "user@company.com"}},
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		assert.False(t, sig.Fired, "signal %s should not fire for legitimate package", sig.Name)
	}
}

func TestComputeSignals_NewPackage_PackageAgeFires(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-7 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          500,
		HasSourceRepo:          true,
		Description:            "A new package",
		MaintainerPackageCount: -1,
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		if sig.Name == "package_age" {
			assert.True(t, sig.Fired)
			return
		}
	}
	t.Fatal("package_age signal not found")
}

func TestComputeSignals_DormantPackage_DormantReactivationFires(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-3 * 365 * 24 * time.Hour),
		LatestPublished:        time.Now().Add(-1 * time.Hour),
		PreviousPublished:      time.Now().Add(-2 * 365 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          1000,
		HasSourceRepo:          true,
		Description:            "Revived package",
		MaintainerPackageCount: -1,
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		if sig.Name == "dormant_reactivation" {
			assert.True(t, sig.Fired)
			return
		}
	}
	t.Fatal("dormant_reactivation signal not found")
}

func TestComputeSignals_DisabledSignal_NotIncluded(t *testing.T) {
	cfg := defaultSignalsCfg()
	cfg.PackageAge.Enabled = false
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-1 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          500,
		HasSourceRepo:          true,
		Description:            "New package",
		MaintainerPackageCount: -1,
	}
	signals := computeSignals(meta, cfg)
	for _, sig := range signals {
		assert.NotEqual(t, "package_age", sig.Name)
	}
}

// --- V2 signal tests ---

func TestComputeSignals_YankedVersions_Fires(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-90 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          500,
		HasSourceRepo:          true,
		Description:            "Package with yanked versions",
		YankedVersionCount:     3,
		MaintainerPackageCount: -1,
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		if sig.Name == "yanked_versions" {
			assert.True(t, sig.Fired)
			assert.Contains(t, sig.Reason, "3 previous versions were yanked")
			return
		}
	}
	t.Fatal("yanked_versions signal not found")
}

func TestComputeSignals_UnusualVersioning_Fires(t *testing.T) {
	tests := []struct {
		version string
		unusual bool
	}{
		{"99.0.0", true},
		{"0.0.0", true},
		{"0.0.1", true},
		{"1.0.0", false},
		{"2.31.0", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.unusual, isUnusualVersion(tt.version))
		})
	}
}

func TestComputeSignals_MaintainerEmailDomain_AllFreeEmails(t *testing.T) {
	assert.True(t, allFreeEmailDomains([]Maintainer{
		{Name: "user1", Email: "user1@gmail.com"},
		{Name: "user2", Email: "user2@outlook.com"},
	}))
}

func TestComputeSignals_MaintainerEmailDomain_MixedEmails(t *testing.T) {
	assert.False(t, allFreeEmailDomains([]Maintainer{
		{Name: "user1", Email: "user1@gmail.com"},
		{Name: "user2", Email: "user2@company.com"},
	}))
}

func TestComputeSignals_MaintainerEmailDomain_NoEmails(t *testing.T) {
	assert.False(t, allFreeEmailDomains([]Maintainer{{Name: "user1"}}))
}

func TestComputeSignals_FirstPublication_SinglePackage(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-90 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          500,
		HasSourceRepo:          true,
		Description:            "Package by new maintainer",
		MaintainerPackageCount: 1,
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		if sig.Name == "first_publication" {
			assert.True(t, sig.Fired)
			return
		}
	}
	t.Fatal("first_publication signal not found")
}

func TestComputeSignals_RepoMismatch_Fires(t *testing.T) {
	meta := &PackageMetadata{
		FirstPublished:         time.Now().Add(-90 * 24 * time.Hour),
		VersionCount:           5,
		DownloadCount:          500,
		HasSourceRepo:          true,
		SourceRepoURL:          "https://github.com/popular/unrelated-project",
		RepoNameMismatch:       true,
		Description:            "Package with mismatched repo",
		MaintainerPackageCount: -1,
	}
	signals := computeSignals(meta, defaultSignalsCfg())
	for _, sig := range signals {
		if sig.Name == "repo_mismatch" {
			assert.True(t, sig.Fired)
			return
		}
	}
	t.Fatal("repo_mismatch signal not found")
}

// --- Repo mismatch detection tests ---

func TestDetectRepoMismatch_MatchingNames(t *testing.T) {
	assert.False(t, detectRepoMismatch("requests", "https://github.com/psf/requests"))
	assert.False(t, detectRepoMismatch("my-package", "https://github.com/user/my-package.git"))
	assert.False(t, detectRepoMismatch("mypackage", "https://github.com/user/my-package"))
}

func TestDetectRepoMismatch_MismatchingNames(t *testing.T) {
	assert.True(t, detectRepoMismatch("evil-package", "https://github.com/popular/cool-project"))
}

func TestDetectRepoMismatch_ScopedPackage(t *testing.T) {
	assert.False(t, detectRepoMismatch("myorg-utils", "https://github.com/myorg/utils"))
}

// --- Email hashing tests ---

func TestHashMaintainerEmails_HashesEmail(t *testing.T) {
	maintainers := []Maintainer{
		{Name: "User", Email: "user@example.com"},
		{Name: "NoEmail"},
	}
	hashed := hashMaintainerEmails(maintainers)
	assert.Equal(t, "User", hashed[0].Name)
	assert.NotEqual(t, "user@example.com", hashed[0].Email)
	assert.Len(t, hashed[0].Email, 16) // 8 bytes = 16 hex chars
	assert.Equal(t, "NoEmail", hashed[1].Name)
	assert.Empty(t, hashed[1].Email)
}

func TestHashMaintainerEmails_CaseInsensitive(t *testing.T) {
	h1 := hashMaintainerEmails([]Maintainer{{Name: "a", Email: "User@Example.COM"}})
	h2 := hashMaintainerEmails([]Maintainer{{Name: "a", Email: "user@example.com"}})
	assert.Equal(t, h1[0].Email, h2[0].Email)
}

// --- SSRF mitigation tests ---

func TestIsSafeHost(t *testing.T) {
	assert.True(t, isSafeHost("pypi.org"))
	assert.True(t, isSafeHost("registry.npmjs.org"))
	assert.True(t, isSafeHost("api.nuget.org"))
	assert.False(t, isSafeHost("evil.com"))
	assert.False(t, isSafeHost("169.254.169.254"))
	assert.False(t, isSafeHost("localhost"))
}

// --- Metadata parsing tests ---

func TestFetchPyPIMetadata_ValidResponse_ParsesCorrectly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"info": map[string]interface{}{
				"name":        "requests",
				"version":     "2.32.0",
				"summary":     "HTTP library",
				"author":      "Kenneth Reitz",
				"author_email": "me@example.com",
				"project_urls": map[string]string{
					"Source": "https://github.com/psf/requests",
				},
			},
			"releases": map[string]interface{}{
				"2.28.0": []map[string]interface{}{
					{"upload_time": "2022-06-10T12:00:00", "yanked": false},
				},
				"2.31.0": []map[string]interface{}{
					{"upload_time": "2023-05-22T12:00:00", "yanked": true},
				},
				"2.32.0": []map[string]interface{}{
					{"upload_time": "2024-01-15T12:00:00", "yanked": false},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	meta, err := fetchPyPIMetadataFrom(server.URL, server.Client(), "requests")
	require.NoError(t, err)

	assert.Equal(t, "requests", meta.Name)
	assert.Equal(t, 3, meta.VersionCount)
	assert.Equal(t, "HTTP library", meta.Description)
	assert.Equal(t, "2.32.0", meta.LatestVersion)
	assert.True(t, meta.HasSourceRepo)
	assert.Equal(t, 1, meta.YankedVersionCount) // 2.31.0 is yanked
	assert.Len(t, meta.Maintainers, 1)
}

func TestFetchPyPIMetadata_404_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	_, err := fetchPyPIMetadataFrom(server.URL, server.Client(), "nonexistent")
	assert.Error(t, err)
}

func TestFetchNPMMetadata_ValidResponse_ParsesCorrectly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"name":        "lodash",
			"description": "Utility library",
			"dist-tags":   map[string]string{"latest": "4.17.21"},
			"maintainers": []map[string]string{
				{"name": "jdalton", "email": "john@example.com"},
			},
			"time": map[string]string{
				"created":  "2012-04-23T00:00:00.000Z",
				"modified": "2024-01-01T00:00:00.000Z",
				"4.17.0":   "2017-01-15T00:00:00.000Z",
				"4.17.21":  "2021-02-20T00:00:00.000Z",
			},
			"repository": map[string]string{
				"type": "git",
				"url":  "https://github.com/lodash/lodash.git",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	meta, err := fetchNPMMetadataFrom(server.URL, server.Client(), "lodash")
	require.NoError(t, err)

	assert.Equal(t, "lodash", meta.Name)
	assert.Equal(t, 2, meta.VersionCount)
	assert.Equal(t, "Utility library", meta.Description)
	assert.Equal(t, "4.17.21", meta.LatestVersion)
	assert.True(t, meta.HasSourceRepo)
	assert.Len(t, meta.Maintainers, 1)
}

// --- Scanner interface tests ---

func TestReputationScanner_InterfaceCompliance(t *testing.T) {
	s := &ReputationScanner{
		cfg: config.ReputationConfig{
			Thresholds: config.ReputationThresholds{Suspicious: 0.5, Malicious: 0.8},
		},
	}
	assert.Equal(t, scannerName, s.Name())
	assert.Equal(t, scannerVersion, s.Version())
	assert.Contains(t, s.SupportedEcosystems(), scanner.EcosystemPyPI)
	assert.Contains(t, s.SupportedEcosystems(), scanner.EcosystemNPM)
	assert.Contains(t, s.SupportedEcosystems(), scanner.EcosystemNuGet)
}

func TestBuildResult_CleanScore(t *testing.T) {
	s := &ReputationScanner{
		cfg: config.ReputationConfig{
			Thresholds: config.ReputationThresholds{Suspicious: 0.5, Malicious: 0.8},
		},
	}
	signals := []SignalResult{{Name: "a", Fired: false, Weight: 0.3}}
	signalsJSON, _ := json.Marshal(signals)
	result := s.buildResult(0.1, string(signalsJSON), time.Now())
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestBuildResult_SuspiciousScore(t *testing.T) {
	s := &ReputationScanner{
		cfg: config.ReputationConfig{
			Thresholds: config.ReputationThresholds{Suspicious: 0.5, Malicious: 0.8},
		},
	}
	signals := []SignalResult{
		{Name: "package_age", Fired: true, Weight: 0.3, Reason: "less than 30 days"},
		{Name: "no_source_repo", Fired: true, Weight: 0.3, Reason: "no source repo"},
	}
	signalsJSON, _ := json.Marshal(signals)
	result := s.buildResult(0.51, string(signalsJSON), time.Now())
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.Len(t, result.Findings, 2)
}

func TestBuildResult_HighScore_StillSuspicious(t *testing.T) {
	s := &ReputationScanner{
		cfg: config.ReputationConfig{
			Thresholds: config.ReputationThresholds{Suspicious: 0.5, Malicious: 0.8},
		},
	}
	signals := []SignalResult{
		{Name: "ownership_change", Fired: true, Weight: 0.8, Reason: "maintainers changed"},
		{Name: "dormant_reactivation", Fired: true, Weight: 0.7, Reason: "dormant"},
	}
	signalsJSON, _ := json.Marshal(signals)
	result := s.buildResult(0.85, string(signalsJSON), time.Now())
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.Len(t, result.Findings, 2)
	for _, f := range result.Findings {
		assert.Equal(t, scanner.SeverityHigh, f.Severity)
	}
}

// --- Source repo detection tests ---

func TestExtractSourceRepo_GitHubURL(t *testing.T) {
	has, url := extractSourceRepo(map[string]string{"Source": "https://github.com/user/repo"}, "")
	assert.True(t, has)
	assert.Equal(t, "https://github.com/user/repo", url)
}

func TestExtractSourceRepo_FallbackToHomepage(t *testing.T) {
	has, url := extractSourceRepo(nil, "https://github.com/user/repo")
	assert.True(t, has)
	assert.Equal(t, "https://github.com/user/repo", url)
}

func TestExtractSourceRepo_NoRepo(t *testing.T) {
	has, _ := extractSourceRepo(nil, "https://example.com")
	assert.False(t, has)
}

func TestExtractSourceRepo_CaseInsensitiveKey(t *testing.T) {
	has, _ := extractSourceRepo(map[string]string{"source code": "https://github.com/user/repo"}, "")
	assert.True(t, has)
}

// --- Helper to call fetch functions with custom URL ---

func fetchPyPIMetadataFrom(baseURL string, client *http.Client, name string) (*PackageMetadata, error) {
	url := fmt.Sprintf("%s/pypi/%s/json", baseURL, name)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return doPyPIFetch(client, req, name)
}

func fetchNPMMetadataFrom(baseURL string, client *http.Client, name string) (*PackageMetadata, error) {
	url := fmt.Sprintf("%s/%s", baseURL, name)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return doNPMFetch(client, req, name)
}
