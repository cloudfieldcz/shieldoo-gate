package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BlobStore manages local blob storage for pushed images.
type BlobStore struct {
	basePath string
}

// NewBlobStore creates a blob store at the given base directory.
func NewBlobStore(basePath string) *BlobStore {
	return &BlobStore{basePath: basePath}
}

// Put stores blob content keyed by digest.
func (bs *BlobStore) Put(digest string, data []byte) error {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(safePath), 0o755); err != nil {
		return fmt.Errorf("docker blob: creating directory: %w", err)
	}
	return os.WriteFile(safePath, data, 0o644)
}

// Get retrieves blob content by digest.
func (bs *BlobStore) Get(digest string) ([]byte, error) {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(safePath)
}

// Exists returns true if a blob with the given digest exists.
func (bs *BlobStore) Exists(digest string) bool {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(safePath)
	return err == nil
}

// GetSize returns the size in bytes of the blob with the given digest.
func (bs *BlobStore) GetSize(digest string) (int64, error) {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(safePath)
	if err != nil {
		return 0, fmt.Errorf("docker blob: stat %q: %w", digest, err)
	}
	return fi.Size(), nil
}

// digestPath computes a safe filesystem path for the given digest.
// Format: basePath/blobs/{algo}/{prefix}/{hex}
// Path traversal attempts are rejected.
func (bs *BlobStore) digestPath(digest string) (string, error) {
	// Reject path traversal and directory separators.
	if strings.Contains(digest, "..") || strings.ContainsAny(digest, "/\\") {
		return "", fmt.Errorf("docker blob: invalid digest %q", digest)
	}

	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("docker blob: invalid digest format %q", digest)
	}
	algo, hex := parts[0], parts[1]

	prefix := hex
	if len(hex) >= 2 {
		prefix = hex[:2]
	}
	return filepath.Join(bs.basePath, "blobs", algo, prefix, hex), nil
}
