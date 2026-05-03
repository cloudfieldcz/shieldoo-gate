package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"golang.org/x/text/unicode/norm"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*TyposquatScanner)(nil)

// maxNameLength is the guard against DoS via extremely long package names.
const maxNameLength = 128

// PopularPackage holds a popular package name and its pre-computed normalized
// and homoglyph-skeleton forms. Pre-computing both at scanner construction
// removes per-Scan() recomputation on the hot path (homoglyph check runs once
// against every popular package per artifact).
type PopularPackage struct {
	Name              string
	Normalized        string
	HomoglyphSkeleton string
	Rank              int
}

// TyposquatScanner detects typosquatting, homoglyph substitution, combosquatting,
// and namespace confusion by checking package names against popular packages.
type TyposquatScanner struct {
	popularPackages map[scanner.Ecosystem][]PopularPackage
	allowlistSet    map[string]bool
	cfg             config.TyposquatConfig
}

// NewTyposquatScanner creates a new TyposquatScanner. It loads popular packages
// from the database. If the DB table is empty, it seeds it from embedded data.
// Returns error if DB access fails entirely.
func NewTyposquatScanner(db *config.GateDB, cfg config.TyposquatConfig) (*TyposquatScanner, error) {
	s := &TyposquatScanner{
		popularPackages: make(map[scanner.Ecosystem][]PopularPackage),
		allowlistSet:    make(map[string]bool),
		cfg:             cfg,
	}

	for _, name := range cfg.Allowlist {
		s.allowlistSet[normalizeName(name)] = true
	}

	// Apply seed on every startup (INSERT OR IGNORE) so newly-added entries from
	// code updates propagate to existing DBs without manual intervention. The
	// PRIMARY KEY (ecosystem, name) makes this idempotent — existing entries
	// (whether from earlier seed runs or future UI-managed edits) are preserved.
	if err := seedPopularPackages(db); err != nil {
		log.Warn().Err(err).Msg("builtin-typosquat: failed to seed popular packages")
	}

	// Load popular packages from DB.
	type row struct {
		Ecosystem string `db:"ecosystem"`
		Name      string `db:"name"`
		Rank      int    `db:"rank"`
	}
	var rows []row
	query := "SELECT ecosystem, name, rank FROM popular_packages WHERE rank <= ? ORDER BY ecosystem, rank"
	if err := db.Select(&rows, query, cfg.TopPackagesCount); err != nil {
		return nil, fmt.Errorf("builtin-typosquat: load popular packages: %w", err)
	}

	for _, r := range rows {
		eco := scanner.Ecosystem(r.Ecosystem)
		s.popularPackages[eco] = append(s.popularPackages[eco], PopularPackage{
			Name:              r.Name,
			Normalized:        normalizeName(r.Name),
			HomoglyphSkeleton: normalizeHomoglyphs(r.Name),
			Rank:              r.Rank,
		})
	}

	total := 0
	for _, pkgs := range s.popularPackages {
		total += len(pkgs)
	}
	log.Info().Int("total_packages", total).Int("ecosystems", len(s.popularPackages)).Msg("builtin-typosquat scanner initialized")

	return s, nil
}

func (s *TyposquatScanner) Name() string    { return "builtin-typosquat" }
func (s *TyposquatScanner) Version() string { return "1.0.0" }

func (s *TyposquatScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemRubyGems,
		scanner.EcosystemNuGet,
		scanner.EcosystemMaven,
		scanner.EcosystemGo,
		scanner.EcosystemDocker,
	}
}

func (s *TyposquatScanner) HealthCheck(_ context.Context) error {
	total := 0
	for _, pkgs := range s.popularPackages {
		total += len(pkgs)
	}
	if total == 0 {
		return fmt.Errorf("builtin-typosquat: popular packages map is empty")
	}
	return nil
}

// Scan checks the artifact name against popular packages using 4 strategies.
func (s *TyposquatScanner) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	name := artifact.Name
	// Guard against extremely long names (DoS prevention).
	if utf8.RuneCountInString(name) > maxNameLength {
		return buildResult(s.Name(), start, scanner.VerdictClean, 1.0, nil), nil
	}

	normalized := normalizeName(name)

	// Check allowlist.
	if s.allowlistSet[normalized] {
		return buildResult(s.Name(), start, scanner.VerdictClean, 1.0, nil), nil
	}

	// Get popular packages for this ecosystem only (MANDATORY ecosystem filter).
	popular := s.popularPackages[artifact.Ecosystem]
	if len(popular) == 0 {
		return buildResult(s.Name(), start, scanner.VerdictClean, 1.0, nil), nil
	}

	var findings []scanner.Finding

	// Strategy 1: Exact match - if it IS the popular package, it's clean.
	for _, pkg := range popular {
		if normalized == pkg.Normalized {
			return buildResult(s.Name(), start, scanner.VerdictClean, 1.0, nil), nil
		}
	}

	// Strategy 2: Edit distance check.
	findings = append(findings, s.checkEditDistance(normalized, popular)...)

	// Strategy 3: Homoglyph detection.
	findings = append(findings, s.checkHomoglyph(name, popular)...)

	// Strategy 4: Combosquatting.
	findings = append(findings, s.checkCombosquat(normalized, popular)...)

	// Strategy 5: Namespace confusion.
	findings = append(findings, s.checkNamespaceConfusion(name)...)

	if len(findings) > 0 {
		// Use the highest confidence from all findings.
		var maxConf float32 = 0.75 // default (combosquatting baseline)
		for _, f := range findings {
			switch f.Category {
			case "namespace-confusion":
				if maxConf < 0.95 {
					maxConf = 0.95
				}
			case "homoglyph-match":
				if maxConf < 0.90 {
					maxConf = 0.90
				}
			case "edit-distance":
				if maxConf < 0.85 {
					maxConf = 0.85
				}
			case "combosquatting":
				if maxConf < 0.75 {
					maxConf = 0.75
				}
			}
		}
		return buildResult(s.Name(), start, scanner.VerdictSuspicious, maxConf, findings), nil
	}

	return buildResult(s.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// checkEditDistance compares the name against popular packages using Levenshtein distance.
func (s *TyposquatScanner) checkEditDistance(normalized string, popular []PopularPackage) []scanner.Finding {
	var findings []scanner.Finding
	maxDist := s.cfg.MaxEditDistance
	nameLen := utf8.RuneCountInString(normalized)

	// Proportion guard: for short names, cap the effective edit distance so
	// that it never exceeds 40% of the name length. Without this, 2–3 char
	// names like "qs", "pg", "npm" produce excessive false positives.
	proportionMax := nameLen * 2 / 5 // floor(nameLen * 0.4)
	if proportionMax < maxDist {
		maxDist = proportionMax
	}
	if maxDist <= 0 {
		return nil
	}

	for _, pkg := range popular {
		pkgLen := utf8.RuneCountInString(pkg.Normalized)
		// MANDATORY length pre-filter: skip if length difference exceeds maxDist.
		if abs(nameLen-pkgLen) > maxDist {
			continue
		}
		dist := Levenshtein(normalized, pkg.Normalized)
		if dist > 0 && dist <= maxDist {
			findings = append(findings, scanner.Finding{
				Severity:    scanner.SeverityHigh,
				Category:    "edit-distance",
				Description: fmt.Sprintf("Package name %q is within edit distance %d of popular package %q (rank #%d)", normalized, dist, pkg.Name, pkg.Rank),
				IoCs:        []string{pkg.Name},
			})
		}
	}
	return findings
}

// checkHomoglyph normalizes homoglyphs and compares against popular packages.
// Uses pkg.HomoglyphSkeleton (pre-computed at scanner construction) so this
// hot-path call doesn't recompute the same skeletons on every artifact.
func (s *TyposquatScanner) checkHomoglyph(name string, popular []PopularPackage) []scanner.Finding {
	var findings []scanner.Finding
	skeleton := normalizeHomoglyphs(name)
	normalized := normalizeName(name)

	for _, pkg := range popular {
		// Only flag if the skeleton matches but the original name differs.
		if skeleton == pkg.HomoglyphSkeleton && normalized != pkg.Normalized {
			findings = append(findings, scanner.Finding{
				Severity:    scanner.SeverityHigh,
				Category:    "homoglyph-match",
				Description: fmt.Sprintf("Package name %q uses character substitution to mimic popular package %q", name, pkg.Name),
				IoCs:        []string{pkg.Name},
			})
		}
	}
	return findings
}

// checkCombosquat checks if the name is a popular package name with a common suffix/prefix.
func (s *TyposquatScanner) checkCombosquat(normalized string, popular []PopularPackage) []scanner.Finding {
	var findings []scanner.Finding
	suffixes := s.cfg.CombosquatSuffixes
	if len(suffixes) == 0 {
		suffixes = []string{"-utils", "-helper", "-lib", "-dev", "-tool", "-sdk"}
	}

	for _, pkg := range popular {
		for _, suffix := range suffixes {
			if normalized == pkg.Normalized+suffix || normalized == suffix[1:]+"-"+pkg.Normalized {
				findings = append(findings, scanner.Finding{
					Severity:    scanner.SeverityMedium,
					Category:    "combosquatting",
					Description: fmt.Sprintf("Package name %q is a combosquat of popular package %q (suffix %q)", normalized, pkg.Name, suffix),
					IoCs:        []string{pkg.Name, suffix},
				})
			}
		}
	}
	return findings
}

// checkNamespaceConfusion checks if the name matches an internal namespace prefix.
func (s *TyposquatScanner) checkNamespaceConfusion(name string) []scanner.Finding {
	var findings []scanner.Finding
	for _, ns := range s.cfg.InternalNamespaces {
		if strings.HasPrefix(name, ns) {
			findings = append(findings, scanner.Finding{
				Severity:    scanner.SeverityCritical,
				Category:    "namespace-confusion",
				Description: fmt.Sprintf("Package name %q matches internal namespace prefix %q", name, ns),
				IoCs:        []string{ns},
			})
		}
	}
	return findings
}

// --- Helper functions ---

// normalizeName lowercases, applies NFKC normalization, and normalizes separators.
// For scoped npm packages (@scope/name), it strips the "@" and replaces "/" with "-"
// so that e.g. "@babel/core" normalizes to "babel-core" (matching the unscoped name).
func normalizeName(name string) string {
	name = norm.NFKC.String(name)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "@", "")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// homoglyphMap maps confusable characters to their ASCII equivalents.
var homoglyphMap = map[rune]rune{
	'0':      'o',
	'1':      'l',
	'5':      's',
	'8':      'b',
	'\u0430': 'a', // Cyrillic a
	'\u0435': 'e', // Cyrillic e
	'\u043e': 'o', // Cyrillic o
	'\u0440': 'p', // Cyrillic p
	'\u0441': 'c', // Cyrillic c
	'\u0443': 'y', // Cyrillic y
	'\u0445': 'x', // Cyrillic x
	'\u0456': 'i', // Cyrillic i
	'\u03bf': 'o', // Greek omicron
	'\u03b1': 'a', // Greek alpha
}

// normalizeHomoglyphs applies NFKC + confusable character substitution.
func normalizeHomoglyphs(name string) string {
	name = norm.NFKC.String(name)
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		if mapped, ok := homoglyphMap[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	result := b.String()
	result = strings.ReplaceAll(result, "_", "-")
	result = strings.ReplaceAll(result, ".", "-")
	return result
}

// Levenshtein computes the Levenshtein edit distance between two strings.
// Exported for testing from builtin_test package.
func Levenshtein(a, b string) int {
	aRunes := []rune(a)
	bRunes := []rune(b)
	aLen := len(aRunes)
	bLen := len(bRunes)

	if aLen == 0 {
		return bLen
	}
	if bLen == 0 {
		return aLen
	}

	// Use single-row optimization to save memory.
	prev := make([]int, bLen+1)
	curr := make([]int, bLen+1)
	for j := 0; j <= bLen; j++ {
		prev[j] = j
	}

	for i := 1; i <= aLen; i++ {
		curr[0] = i
		for j := 1; j <= bLen; j++ {
			cost := 1
			if aRunes[i-1] == bRunes[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,
				curr[j-1]+1,
				prev[j-1]+cost,
			)
		}
		prev, curr = curr, prev
	}
	return prev[bLen]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// seedPopularPackages inserts embedded seed data into the popular_packages table.
func seedPopularPackages(db *config.GateDB) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("builtin-typosquat: begin seed tx: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	// ON CONFLICT DO NOTHING is supported by both SQLite (>=3.24) and PostgreSQL.
	// Idempotent: existing entries (from earlier seeds or future UI edits) are preserved,
	// only newly-added seed entries are inserted.
	query := `INSERT INTO popular_packages (ecosystem, name, rank, last_updated)
	          VALUES (?, ?, ?, ?)
	          ON CONFLICT (ecosystem, name) DO NOTHING`

	for eco, names := range popularPackageSeed {
		for i, name := range names {
			if _, err := tx.Exec(query, string(eco), name, i+1, now); err != nil {
				return fmt.Errorf("builtin-typosquat: seed %s/%s: %w", eco, name, err)
			}
		}
	}

	return tx.Commit()
}
