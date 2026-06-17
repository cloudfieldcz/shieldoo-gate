// Package tmpjanitor periodically reclaims stale, process-owned scratch that
// Trivy, the manifest SBOM scanner, and the protocol adapters leave behind in
// the shared /tmp volume when a scan times out, crashes, or the host process is
// hard-killed (SIGKILL/OOM) mid-scan.
//
// The leak it backstops is *missing cleanup*, not where the data lives: the
// happy-path defer/RemoveAll handles ordinary completion, and this janitor is
// the defence-in-depth backstop for the one case a defer cannot cover — a hard
// kill of the whole process. See docs/scanners.md ("Scratch cleanup").
//
// Safety is by construction (no scan-activity tracking, no locks, no races):
// the janitor deletes only entries whose name matches a Shieldoo-owned prefix
// and whose top-level mtime is older than maxAge — a threshold set far above
// the scan timeout, so an in-flight scan's scratch is always "too fresh" to
// remove. /tmp also holds the gRPC socket and the Docker push blob store and
// carries attacker-influenced content (decompressed package payloads with
// arbitrary names, symlinks, mtimes), so the sweep is deliberately narrow:
// direct children only, top-level Lstat mtime only, symlinks skipped, a name
// denylist, and a regular-files-only guard on the adapter-staging prefix.
//
// Note on the Docker push blob store: as of ADR-009 pushed blobs live in the
// durable cache.BlobStore (docker-push/ namespace), NOT in /tmp. A
// /tmp/shieldoo-gate-blobs directory can still exist as a LEGACY pre-migration
// store (cmd/shieldoo-gate/main.go warns operators to run -migrate-push-blobs);
// until migrated it remains the sole copy of those pushed images. The denylist
// + files-only guard keep that legacy directory out of scope so the janitor
// never destroys images pending migration.
package tmpjanitor

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

// Prometheus metrics. Defined here (not in internal/api) so tmpjanitor does not
// import internal/api — promauto registers on the default registry, which the
// admin /metrics endpoint serves via promhttp.Handler(). Net-new metrics: there
// is no reusable cleanup-metric precedent in the codebase.
var (
	reclaimedBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shieldoo_gate_tmpjanitor_reclaimed_bytes_total",
		Help: "Total bytes reclaimed by the scratch temp janitor.",
	})
	reclaimedEntriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shieldoo_gate_tmpjanitor_reclaimed_entries_total",
		Help: "Total top-level entries reclaimed by the scratch temp janitor.",
	})
	skippedEntriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shieldoo_gate_tmpjanitor_skipped_entries_total",
		Help: "Total entries the scratch temp janitor matched but failed to remove.",
	})
	// lastSweepTimestamp going stale is the thread-death signal operators
	// monitor — a recurring disk-full incident cannot be watched by log-grep.
	lastSweepTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shieldoo_gate_tmpjanitor_last_sweep_timestamp_seconds",
		Help: "Unix timestamp of the last completed scratch temp janitor sweep.",
	})
)

// DefaultInterval is the period between sweeps.
const DefaultInterval = 10 * time.Minute

// DefaultMaxDelete caps entries removed per sweep. The first post-deploy sweep
// faces the existing backlog (33 GB+ observed); an uncapped RemoveAll over
// thousands of inodes is one blocking metadata storm that contends with
// in-flight scans and can push a borderline scan past its timeout (fail-open
// CLEAN). Capping drains the backlog over several cycles; only stale entries
// count toward the cap, so fresh scratch never blocks the drain.
const DefaultMaxDelete = 100

// Rule describes a name prefix the janitor owns and what entry kinds under that
// prefix it may delete. Constraint 4: the shieldoo-gate- staging prefix is
// files-only so the legacy Docker push blob store (shieldoo-gate-blobs, a
// directory pending -migrate-push-blobs per ADR-009) is structurally out of
// scope on top of the explicit denylist.
type Rule struct {
	Prefix     string
	AllowFiles bool
	AllowDirs  bool
}

// DefaultRules sweeps os.TempDir() for:
//   - shieldoo-trivy-*    : Trivy per-scan scratch dirs (+ the redirected SBOM
//     temp) and the legacy extraction dirs; files and dirs.
//   - shieldoo-sbom-*     : the manifest scanner's SBOM temp files (covered
//     only when not redirected under the trivy prefix); files only.
//   - shieldoo-gate-*     : adapter staging temps, always created as files via
//     os.CreateTemp; FILES ONLY — never a directory, which keeps the legacy
//     shieldoo-gate-blobs push blob store (a dir, pending migration) out of
//     scope.
//   - shieldoo-{azblob,s3,gcs}-cache-* : cloud cache download-to-temp scratch
//     (issue #24). Each backend's Get downloads a blob to os.CreateTemp and
//     returns the path to a consumer (serve + async sandbox scan) that outlives
//     the call; an in-process 5-min cleanup goroutine handles the happy path but
//     is abandoned on a hard kill/restart, orphaning the temp (970 MB observed
//     in prod). Always regular files; FILES ONLY.
//   - semgrep-*           : scratch left by semgrep, which GuardDog invokes in
//     the scanner-bridge and which escapes the bridge's TMPDIR redirect into the
//     shared /tmp (issue #24). semgrep is semgrep's own naming, but only our
//     scan runs semgrep in that container, so owning the prefix is safe; it
//     makes both files and dirs.
func DefaultRules() []Rule {
	return []Rule{
		{Prefix: "shieldoo-trivy-", AllowFiles: true, AllowDirs: true},
		{Prefix: "shieldoo-sbom-", AllowFiles: true, AllowDirs: false},
		{Prefix: "shieldoo-gate-", AllowFiles: true, AllowDirs: false},
		{Prefix: "shieldoo-azblob-cache-", AllowFiles: true, AllowDirs: false},
		{Prefix: "shieldoo-s3-cache-", AllowFiles: true, AllowDirs: false},
		{Prefix: "shieldoo-gcs-cache-", AllowFiles: true, AllowDirs: false},
		{Prefix: "semgrep-", AllowFiles: true, AllowDirs: true},
	}
}

// Config configures a Janitor.
type Config struct {
	// Dir is the target directory swept (os.TempDir() in production — the same
	// resolver the adapters and scanners use, keeping target and leak location
	// in lockstep).
	Dir string
	// MaxAge: entries whose top-level mtime is older than this are eligible.
	MaxAge time.Duration
	// Interval between sweeps. Defaults to DefaultInterval when zero.
	Interval time.Duration
	// MaxDelete caps deletions per sweep. Defaults to DefaultMaxDelete when zero.
	MaxDelete int
	// Rules selects which prefixes/kinds are in scope. Defaults to DefaultRules().
	Rules []Rule
	// Denylist holds exact basenames never to delete even if they match a rule
	// (defence in depth against a same-prefix decoy planted next to a protected
	// path). In production: the gRPC socket basename and "shieldoo-gate-blobs".
	Denylist []string
}

// Janitor sweeps a directory for stale, process-owned scratch.
type Janitor struct {
	dir       string
	maxAge    time.Duration
	interval  time.Duration
	maxDelete int
	rules     []Rule
	denylist  map[string]struct{}
}

// New constructs a Janitor, applying defaults for unset fields.
func New(cfg Config) *Janitor {
	j := &Janitor{
		dir:       cfg.Dir,
		maxAge:    cfg.MaxAge,
		interval:  cfg.Interval,
		maxDelete: cfg.MaxDelete,
		rules:     cfg.Rules,
		denylist:  make(map[string]struct{}, len(cfg.Denylist)),
	}
	if j.interval <= 0 {
		j.interval = DefaultInterval
	}
	if j.maxDelete <= 0 {
		j.maxDelete = DefaultMaxDelete
	}
	if len(j.rules) == 0 {
		j.rules = DefaultRules()
	}
	for _, name := range cfg.Denylist {
		if name != "" {
			j.denylist[name] = struct{}{}
		}
	}
	return j
}

// Run does an initial sweep, then sweeps on a ticker until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) {
	log.Info().
		Str("dir", j.dir).
		Dur("interval", j.interval).
		Dur("max_age", j.maxAge).
		Int("max_delete", j.maxDelete).
		Msg("tmpjanitor: starting scratch sweep")

	j.Sweep(time.Now())

	t := time.NewTicker(j.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("tmpjanitor: stopped")
			return
		case <-t.C:
			j.Sweep(time.Now())
		}
	}
}

// candidate is an eligible entry awaiting deletion, carried with its mtime so
// the per-sweep cap can delete oldest-first without a second stat pass.
type candidate struct {
	name  string
	isDir bool
	mtime time.Time
}

// Sweep removes eligible entries in j.dir whose top-level mtime is older than
// maxAge relative to now, up to maxDelete (oldest-first). It returns the number
// of entries deleted. It does filesystem I/O so it is not pure, but is
// deterministic given a clock and a fixed tree (tested against t.TempDir()).
//
// TOCTOU-safe rules (Constraint 4): direct children only via os.ReadDir; age
// from the top-level entry's Lstat mtime only (never recurse for the age
// decision); symlinks skipped entirely; names containing "/" or ".." rejected;
// denylisted basenames never removed; the shieldoo-gate- prefix restricted to
// regular files. Per-entry errors are logged and skipped, never aborting the
// sweep.
func (j *Janitor) Sweep(now time.Time) int {
	defer func() { lastSweepTimestamp.Set(float64(now.Unix())) }()

	entries, err := os.ReadDir(j.dir)
	if err != nil {
		log.Warn().Err(err).Str("dir", j.dir).Msg("tmpjanitor: read dir failed")
		return 0
	}

	cutoff := now.Add(-j.maxAge)
	candidates := make([]candidate, 0, len(entries))

	for _, e := range entries {
		name := e.Name()

		// Reject path-traversal-shaped names defensively (ReadDir yields single
		// components, but /tmp holds attacker-influenced content).
		if strings.Contains(name, "/") || strings.Contains(name, "..") {
			continue
		}
		// Never touch a denylisted basename, even a same-prefix decoy.
		if _, deny := j.denylist[name]; deny {
			continue
		}
		// Skip symlinks entirely — never follow or delete them. Type() reads the
		// dirent type without an extra stat and does not follow the link.
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}

		if _, ok := j.matchRule(name, e.IsDir()); !ok {
			continue
		}

		// Age decision: the top-level entry's own mtime (Lstat-equivalent for a
		// ReadDir entry; does not follow symlinks). Never recurse — a nested
		// attacker-set mtime must not keep scratch alive or bias deletion.
		info, err := e.Info()
		if err != nil {
			// Entry vanished between ReadDir and Info, or is unreadable — skip.
			continue
		}
		if info.ModTime().After(cutoff) {
			continue // too fresh — could be an in-flight scan
		}

		candidates = append(candidates, candidate{
			name:  name,
			isDir: e.IsDir(),
			mtime: info.ModTime(),
		})
	}

	// Oldest-first: every candidate is already past maxAge and equally safe to
	// delete, but a deterministic order makes the cap testable and drains the
	// oldest backlog first. mtimes are already in hand, so the sort adds no I/O.
	sort.Slice(candidates, func(a, b int) bool {
		return candidates[a].mtime.Before(candidates[b].mtime)
	})

	deleted := 0
	var bytesReclaimed int64
	for _, c := range candidates {
		if deleted >= j.maxDelete {
			log.Info().
				Int("max_delete", j.maxDelete).
				Int("remaining", len(candidates)-deleted).
				Msg("tmpjanitor: per-sweep cap reached; backlog drains next cycle")
			break
		}

		full := filepath.Join(j.dir, c.name)
		size := entrySize(full, c.isDir)

		var derr error
		if c.isDir {
			derr = os.RemoveAll(full)
		} else {
			derr = os.Remove(full)
		}
		if derr != nil {
			skippedEntriesTotal.Inc()
			log.Warn().Err(derr).Str("entry", c.name).Msg("tmpjanitor: delete failed; skipping")
			continue
		}

		deleted++
		bytesReclaimed += size
		reclaimedEntriesTotal.Inc()
		reclaimedBytesTotal.Add(float64(size))
	}

	if deleted > 0 {
		log.Info().
			Int("deleted", deleted).
			Int64("bytes_reclaimed", bytesReclaimed).
			Int("candidates", len(candidates)).
			Msg("tmpjanitor: sweep reclaimed scratch")
	} else {
		log.Debug().Int("entries", len(entries)).Msg("tmpjanitor: sweep found nothing stale")
	}
	return deleted
}

// matchRule returns the first rule whose prefix matches name and whose
// kind-allowance permits this entry's type.
func (j *Janitor) matchRule(name string, isDir bool) (Rule, bool) {
	for _, r := range j.rules {
		if !strings.HasPrefix(name, r.Prefix) {
			continue
		}
		if isDir && r.AllowDirs {
			return r, true
		}
		if !isDir && r.AllowFiles {
			return r, true
		}
		// Prefix matched but kind not allowed (e.g. a directory under the
		// files-only shieldoo-gate- prefix) — do not fall through to a broader
		// rule; this entry is intentionally out of scope.
		return Rule{}, false
	}
	return Rule{}, false
}

// entrySize returns the disk footprint of an entry for observability. For a
// regular file it is the file size. For a directory it is a best-effort sum of
// the regular files within, walked without following symlinks (WalkDir does not
// descend into symlinks); errors are swallowed since this is metrics-only and
// the walk is bounded by the per-sweep deletion cap.
func entrySize(path string, isDir bool) int64 {
	if !isDir {
		if fi, err := os.Lstat(path); err == nil {
			return fi.Size()
		}
		return 0
	}
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
