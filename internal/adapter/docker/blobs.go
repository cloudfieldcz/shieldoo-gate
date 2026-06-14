package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
)

// BlobStore stores pushed image blobs and manifests in the durable
// cache.BlobStore backend under a fixed key namespace. Blobs are keyed by digest
// (content-addressed), so integrity is inherent: the key IS the content hash.
type BlobStore struct {
	backend   cache.BlobStore
	keyPrefix string // e.g. "docker-push"
}

// NewBlobStore wraps a durable backend with a digest-keyed namespace.
func NewBlobStore(backend cache.BlobStore, keyPrefix string) *BlobStore {
	return &BlobStore{backend: backend, keyPrefix: strings.Trim(keyPrefix, "/")}
}

// Put stores blob content keyed by digest.
func (bs *BlobStore) Put(ctx context.Context, digest string, data []byte) error {
	key, err := bs.digestKey(digest)
	if err != nil {
		return err
	}
	return bs.backend.PutBlob(ctx, key, data)
}

// Get retrieves blob content by digest (whole blob in memory — use for manifests).
func (bs *BlobStore) Get(ctx context.Context, digest string) ([]byte, error) {
	key, err := bs.digestKey(digest)
	if err != nil {
		return nil, err
	}
	return bs.backend.GetBlob(ctx, key)
}

// GetStream returns a streaming reader and size for a blob (use for layers).
func (bs *BlobStore) GetStream(ctx context.Context, digest string) (io.ReadCloser, int64, error) {
	key, err := bs.digestKey(digest)
	if err != nil {
		return nil, 0, err
	}
	return bs.backend.GetBlobStream(ctx, key)
}

// Exists reports whether a blob with the given digest is present.
func (bs *BlobStore) Exists(ctx context.Context, digest string) (bool, error) {
	if _, err := bs.Stat(ctx, digest); err != nil {
		if err == cache.ErrBlobNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Stat returns the size of the blob with the given digest.
func (bs *BlobStore) Stat(ctx context.Context, digest string) (int64, error) {
	key, err := bs.digestKey(digest)
	if err != nil {
		return 0, err
	}
	return bs.backend.StatBlob(ctx, key)
}

// digestKey maps a digest to a durable key: {prefix}/blobs/{algo}/{hex[:2]}/{hex}.
// Path traversal and separators are rejected (defence in depth — the backend also
// sanitizes).
func (bs *BlobStore) digestKey(digest string) (string, error) {
	if strings.Contains(digest, "..") || strings.ContainsAny(digest, "/\\") {
		return "", fmt.Errorf("docker blob: invalid digest %q", digest)
	}
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("docker blob: invalid digest format %q", digest)
	}
	algo, hexv := parts[0], parts[1]
	// Restrict the hex component to lowercase hex so a digest like "sha256:a;b"
	// cannot widen the key surface (defence in depth on top of backend sanitizing).
	for _, c := range hexv {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("docker blob: non-hex digest %q", digest)
		}
	}
	prefix := hexv
	if len(hexv) >= 2 {
		prefix = hexv[:2]
	}
	return fmt.Sprintf("%s/blobs/%s/%s/%s", bs.keyPrefix, algo, prefix, hexv), nil
}
