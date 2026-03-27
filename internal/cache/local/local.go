package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ cache.CacheStore = (*LocalCacheStore)(nil)

// validNameRe matches safe artifact name components (no path traversal characters).
var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// LocalCacheStore stores cached artifacts on the local filesystem.
// Layout: {basePath}/{ecosystem}/{name}/{version}/{filename}
type LocalCacheStore struct {
	basePath  string
	maxSizeGB int64
}

// NewLocalCacheStore creates a new LocalCacheStore rooted at basePath.
// basePath is created if it does not already exist.
func NewLocalCacheStore(basePath string, maxSizeGB int64) (*LocalCacheStore, error) {
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return nil, fmt.Errorf("local cache: creating base directory %s: %w", basePath, err)
	}
	return &LocalCacheStore{basePath: basePath, maxSizeGB: maxSizeGB}, nil
}

// parseArtifactID splits "eco:name:version" into its three components.
func parseArtifactID(artifactID string) (eco, name, version string, err error) {
	parts := strings.SplitN(artifactID, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("local cache: invalid artifact ID %q: expected eco:name:version", artifactID)
	}
	return parts[0], parts[1], parts[2], nil
}

// validateName returns an error if a name component is unsafe.
func validateName(s string) error {
	if strings.Contains(s, "..") || strings.ContainsAny(s, "/\\") {
		return fmt.Errorf("local cache: invalid name component %q: contains path traversal", s)
	}
	if !validNameRe.MatchString(s) {
		return fmt.Errorf("local cache: invalid name component %q: does not match allowed characters", s)
	}
	return nil
}

// artifactPath returns the directory path for the given eco/name/version.
func (s *LocalCacheStore) artifactPath(eco, name, version string) string {
	return filepath.Join(s.basePath, eco, name, version)
}

// copyFile atomically copies src to dst via a temp file then rename.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("local cache: creating directory for %s: %w", dst, err)
	}

	srcF, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("local cache: opening source %s: %w", src, err)
	}
	defer srcF.Close()

	tmpF, err := os.CreateTemp(filepath.Dir(dst), ".tmp-")
	if err != nil {
		return fmt.Errorf("local cache: creating temp file: %w", err)
	}
	tmpPath := tmpF.Name()

	if _, err := io.Copy(tmpF, srcF); err != nil {
		tmpF.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("local cache: copying data to temp file: %w", err)
	}
	if err := tmpF.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local cache: closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local cache: renaming temp file to %s: %w", dst, err)
	}
	return nil
}

// Get returns the local filesystem path of a cached artifact.
// It returns cache.ErrNotFound if no file exists for the given artifactID.
func (s *LocalCacheStore) Get(_ context.Context, artifactID string) (string, error) {
	eco, name, version, err := parseArtifactID(artifactID)
	if err != nil {
		return "", err
	}

	dir := s.artifactPath(eco, name, version)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", cache.ErrNotFound
		}
		return "", fmt.Errorf("local cache: reading directory %s: %w", dir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", cache.ErrNotFound
}

// Put copies localPath into the cache at the appropriate layout path.
// All name components are validated to prevent path traversal attacks.
func (s *LocalCacheStore) Put(_ context.Context, artifact scanner.Artifact, localPath string) error {
	eco := string(artifact.Ecosystem)
	name := artifact.Name
	version := artifact.Version

	for _, component := range []string{eco, name, version} {
		if err := validateName(component); err != nil {
			return err
		}
	}

	dir := s.artifactPath(eco, name, version)
	filename := filepath.Base(localPath)
	if filename == "." || filename == "" {
		filename = name + "-" + version
	}

	dst := filepath.Join(dir, filename)
	return copyFile(localPath, dst)
}

// Delete removes the version directory and all its contents.
func (s *LocalCacheStore) Delete(_ context.Context, artifactID string) error {
	eco, name, version, err := parseArtifactID(artifactID)
	if err != nil {
		return err
	}
	dir := s.artifactPath(eco, name, version)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("local cache: removing %s: %w", dir, err)
	}
	return nil
}

// List returns artifactIDs matching the optional filter.
func (s *LocalCacheStore) List(_ context.Context, filter cache.CacheFilter) ([]string, error) {
	var ids []string

	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(s.basePath, path)
		if err != nil {
			return err
		}

		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 {
			return nil
		}
		eco, name, version := parts[0], parts[1], parts[2]

		if filter.Ecosystem != "" && filter.Ecosystem != eco {
			return nil
		}
		if filter.Name != "" && filter.Name != name {
			return nil
		}

		id := eco + ":" + name + ":" + version
		// Deduplicate: only add if not already present (multiple files in same version dir).
		for _, existing := range ids {
			if existing == id {
				return nil
			}
		}
		ids = append(ids, id)
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("local cache: listing: %w", err)
	}
	return ids, nil
}

// Stats walks the cache tree and returns aggregate statistics.
func (s *LocalCacheStore) Stats(_ context.Context) (cache.CacheStats, error) {
	stats := cache.CacheStats{
		ByEcosystem: make(map[string]int64),
	}

	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		stats.TotalItems++
		stats.TotalBytes += info.Size()

		rel, relErr := filepath.Rel(s.basePath, path)
		if relErr != nil {
			return relErr
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) >= 1 {
			stats.ByEcosystem[parts[0]] += info.Size()
		}
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return cache.CacheStats{}, fmt.Errorf("local cache: stats: %w", err)
	}
	return stats, nil
}
