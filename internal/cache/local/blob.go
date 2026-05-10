package local

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
)

// Compile-time interface check.
var _ cache.BlobStore = (*LocalCacheStore)(nil)

// sanitizeBlobPath rejects absolute paths, path-traversal segments, and empty
// values. It returns a cleaned relative path suitable for join with basePath.
func sanitizeBlobPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("local blob: empty path")
	}
	// Reject absolute paths.
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("local blob: absolute path not allowed: %q", p)
	}
	// Normalize and reject any ".." after cleaning.
	clean := filepath.Clean(p)
	if clean == "." || strings.HasPrefix(clean, "..") || strings.Contains(clean, string(filepath.Separator)+"..") {
		return "", fmt.Errorf("local blob: path contains traversal: %q", p)
	}
	return clean, nil
}

// PutBlob writes data atomically to basePath/path.
func (s *LocalCacheStore) PutBlob(_ context.Context, path string, data []byte) error {
	clean, err := sanitizeBlobPath(path)
	if err != nil {
		return err
	}
	dst := filepath.Join(s.basePath, clean)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("local blob: mkdir %s: %w", filepath.Dir(dst), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".blob-tmp-")
	if err != nil {
		return fmt.Errorf("local blob: temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("local blob: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local blob: close: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("local blob: rename to %s: %w", dst, err)
	}
	return nil
}

// GetBlob reads data from basePath/path.
func (s *LocalCacheStore) GetBlob(_ context.Context, path string) ([]byte, error) {
	clean, err := sanitizeBlobPath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(s.basePath, clean))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, cache.ErrBlobNotFound
		}
		return nil, fmt.Errorf("local blob: read %s: %w", clean, err)
	}
	return data, nil
}

// DeleteBlob removes basePath/path if present.
func (s *LocalCacheStore) DeleteBlob(_ context.Context, path string) error {
	clean, err := sanitizeBlobPath(path)
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(s.basePath, clean))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("local blob: delete %s: %w", clean, err)
	}
	return nil
}

// ListBlobs satisfies scheduler.BlobLister. It returns all blob paths under
// basePath/prefix as relative paths suitable for round-tripping through
// PutBlob/GetBlob/DeleteBlob. A non-existent prefix is treated as empty.
func (s *LocalCacheStore) ListBlobs(_ context.Context, prefix string) ([]string, error) {
	cleanPrefix, err := sanitizeBlobPath(prefix)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(s.basePath, cleanPrefix)
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("local blob: stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("local blob: list prefix is not a directory: %q", prefix)
	}
	var out []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		// Skip in-flight temp files written by PutBlob.
		if strings.HasPrefix(d.Name(), ".blob-tmp-") {
			return nil
		}
		rel, err := filepath.Rel(s.basePath, path)
		if err != nil {
			return fmt.Errorf("local blob: rel %s: %w", path, err)
		}
		// Always emit forward-slash paths so they round-trip cleanly with the
		// stored sbom_blob_path column even on Windows builds.
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local blob: walk %s: %w", root, err)
	}
	return out, nil
}
