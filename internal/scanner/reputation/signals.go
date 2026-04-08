package reputation

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// SignalResult holds the evaluation result for a single reputation signal.
type SignalResult struct {
	Name    string  `json:"name"`
	Fired   bool    `json:"fired"`
	Weight  float64 `json:"weight"`
	Reason  string  `json:"reason,omitempty"`
}

// computeSignals evaluates all enabled reputation signals against package metadata.
func computeSignals(meta *PackageMetadata, cfg config.ReputationSignals) []SignalResult {
	var results []SignalResult

	now := time.Now()

	// --- V1 signals ---

	// 1. Package age — less than 30 days old
	if cfg.PackageAge.Enabled {
		fired := false
		reason := ""
		if !meta.FirstPublished.IsZero() {
			age := now.Sub(meta.FirstPublished)
			if age < 30*24*time.Hour {
				fired = true
				reason = "package is less than 30 days old"
			}
		}
		results = append(results, SignalResult{
			Name:   "package_age",
			Fired:  fired,
			Weight: cfg.PackageAge.Weight,
			Reason: reason,
		})
	}

	// 2. Low downloads — fewer than 100 downloads
	if cfg.LowDownloads.Enabled {
		fired := false
		reason := ""
		if meta.DownloadCount >= 0 && meta.DownloadCount < 100 {
			fired = true
			reason = "fewer than 100 downloads"
		}
		results = append(results, SignalResult{
			Name:   "low_downloads",
			Fired:  fired,
			Weight: cfg.LowDownloads.Weight,
			Reason: reason,
		})
	}

	// 3. No source repository
	if cfg.NoSourceRepo.Enabled {
		fired := !meta.HasSourceRepo
		reason := ""
		if fired {
			reason = "no source repository linked"
		}
		results = append(results, SignalResult{
			Name:   "no_source_repo",
			Fired:  fired,
			Weight: cfg.NoSourceRepo.Weight,
			Reason: reason,
		})
	}

	// 4. Dormant reactivation — no update for 12+ months, then new version
	if cfg.DormantReactivation.Enabled {
		fired := false
		reason := ""
		if !meta.LatestPublished.IsZero() && !meta.PreviousPublished.IsZero() {
			gap := meta.LatestPublished.Sub(meta.PreviousPublished)
			if gap > 365*24*time.Hour {
				fired = true
				reason = "package reactivated after 12+ months of dormancy"
			}
		}
		results = append(results, SignalResult{
			Name:   "dormant_reactivation",
			Fired:  fired,
			Weight: cfg.DormantReactivation.Weight,
			Reason: reason,
		})
	}

	// 5. Few versions — only 1 version published
	if cfg.FewVersions.Enabled {
		fired := meta.VersionCount == 1
		reason := ""
		if fired {
			reason = "only 1 version published"
		}
		results = append(results, SignalResult{
			Name:   "few_versions",
			Fired:  fired,
			Weight: cfg.FewVersions.Weight,
			Reason: reason,
		})
	}

	// 6. No description
	if cfg.NoDescription.Enabled {
		fired := meta.Description == ""
		reason := ""
		if fired {
			reason = "no package description"
		}
		results = append(results, SignalResult{
			Name:   "no_description",
			Fired:  fired,
			Weight: cfg.NoDescription.Weight,
			Reason: reason,
		})
	}

	// 7. Version count spike — 10+ versions published in last 7 days
	if cfg.VersionCountSpike.Enabled {
		fired := false
		reason := ""
		if meta.RecentVersionCount > 0 && meta.RecentVersionCount >= 10 {
			fired = true
			reason = "10+ versions published in the last 7 days"
		}
		results = append(results, SignalResult{
			Name:   "version_count_spike",
			Fired:  fired,
			Weight: cfg.VersionCountSpike.Weight,
			Reason: reason,
		})
	}

	// 8. Ownership change — maintainers changed recently (detected via metadata diff)
	if cfg.OwnershipChange.Enabled {
		fired := meta.OwnershipChanged
		reason := ""
		if fired {
			reason = "maintainer list changed recently"
		}
		results = append(results, SignalResult{
			Name:   "ownership_change",
			Fired:  fired,
			Weight: cfg.OwnershipChange.Weight,
			Reason: reason,
		})
	}

	// --- V2 signals ---

	// 9. Yanked versions — previous versions were yanked/deleted
	if cfg.YankedVersions.Enabled {
		fired := meta.YankedVersionCount > 0
		reason := ""
		if fired {
			reason = fmt.Sprintf("%d previous versions were yanked/deleted", meta.YankedVersionCount)
		}
		results = append(results, SignalResult{
			Name:   "yanked_versions",
			Fired:  fired,
			Weight: cfg.YankedVersions.Weight,
			Reason: reason,
		})
	}

	// 10. Unusual versioning — version numbers like 99.0.0 or 0.0.1 that skip conventions
	if cfg.UnusualVersioning.Enabled {
		fired := isUnusualVersion(meta.LatestVersion)
		reason := ""
		if fired {
			reason = fmt.Sprintf("unusual version numbering: %s", meta.LatestVersion)
		}
		results = append(results, SignalResult{
			Name:   "unusual_versioning",
			Fired:  fired,
			Weight: cfg.UnusualVersioning.Weight,
			Reason: reason,
		})
	}

	// 11. Maintainer email domain — all maintainers use free email providers
	if cfg.MaintainerEmailDomain.Enabled {
		fired := allFreeEmailDomains(meta.Maintainers)
		reason := ""
		if fired && len(meta.Maintainers) > 0 {
			reason = "all maintainer emails use free providers (gmail, outlook, etc.)"
		}
		results = append(results, SignalResult{
			Name:   "maintainer_email_domain",
			Fired:  fired,
			Weight: cfg.MaintainerEmailDomain.Weight,
			Reason: reason,
		})
	}

	// 12. First publication — maintainer has only one package
	if cfg.FirstPublication.Enabled {
		fired := meta.MaintainerPackageCount >= 0 && meta.MaintainerPackageCount <= 1
		reason := ""
		if fired {
			reason = "maintainer has published only this package"
		}
		results = append(results, SignalResult{
			Name:   "first_publication",
			Fired:  fired,
			Weight: cfg.FirstPublication.Weight,
			Reason: reason,
		})
	}

	// 13. Repository mismatch — source repo URL doesn't match package name
	if cfg.RepoMismatch.Enabled {
		fired := meta.HasSourceRepo && meta.RepoNameMismatch
		reason := ""
		if fired {
			reason = "source repository name does not match package name"
		}
		results = append(results, SignalResult{
			Name:   "repo_mismatch",
			Fired:  fired,
			Weight: cfg.RepoMismatch.Weight,
			Reason: reason,
		})
	}

	// 14. Classifier anomaly — package classifiers don't match content indicators
	if cfg.ClassifierAnomaly.Enabled {
		fired := meta.ClassifierAnomaly
		reason := ""
		if fired {
			reason = "package classifiers appear inconsistent"
		}
		results = append(results, SignalResult{
			Name:   "classifier_anomaly",
			Fired:  fired,
			Weight: cfg.ClassifierAnomaly.Weight,
			Reason: reason,
		})
	}

	return results
}

// compositeScore computes the weighted composite risk score from signal results.
// Formula: risk = 1 - ∏(1 - weight_i × signal_i)
// where signal_i is 1.0 if fired, 0.0 otherwise.
func compositeScore(signals []SignalResult) float64 {
	product := 1.0
	for _, s := range signals {
		if s.Fired {
			product *= (1.0 - s.Weight)
		}
	}
	return 1.0 - product
}

// unusualVersionRe matches version numbers that skip semver conventions.
var unusualVersionRe = regexp.MustCompile(`^(0\.0\.[01]|[5-9]\d\.\d+\.\d+|\d+\.\d+\.\d+\.\d+\.\d+)$`)

// isUnusualVersion returns true if the version string looks unusual.
func isUnusualVersion(version string) bool {
	if version == "" {
		return false
	}
	return unusualVersionRe.MatchString(version)
}

// freeEmailDomains is a set of common free email providers.
var freeEmailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true,
	"outlook.com": true, "hotmail.com": true, "live.com": true,
	"yahoo.com": true, "yahoo.co.uk": true,
	"protonmail.com": true, "proton.me": true,
	"mail.com": true, "aol.com": true,
	"icloud.com": true, "me.com": true,
	"yandex.ru": true, "yandex.com": true,
	"qq.com": true, "163.com": true,
}

// allFreeEmailDomains returns true if ALL maintainer emails use free providers.
// Returns false if there are no maintainers or no emails.
func allFreeEmailDomains(maintainers []Maintainer) bool {
	if len(maintainers) == 0 {
		return false
	}
	hasEmail := false
	for _, m := range maintainers {
		if m.Email == "" {
			continue
		}
		hasEmail = true
		parts := strings.SplitN(m.Email, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		if !freeEmailDomains[domain] {
			return false // at least one org email
		}
	}
	return hasEmail // true only if all emails checked were free
}

