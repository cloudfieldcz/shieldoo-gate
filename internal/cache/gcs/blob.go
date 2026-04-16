package gcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	gcsstorage "cloud.google.com/go/storage"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
)

// Compile-time interface check.
var _ cache.BlobStore = (*GCSCacheStore)(nil)

func (s *GCSCacheStore) blobKey(path string) string {
	p := strings.TrimLeft(path, "/")
	if s.prefix != "" {
		return s.prefix + "/" + p
	}
	return p
}

// PutBlob uploads bytes to gs://bucket/{prefix}/{path}.
func (s *GCSCacheStore) PutBlob(ctx context.Context, path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("gcs blob: empty path")
	}
	key := s.blobKey(path)
	obj := s.client.Bucket(s.bucket).Object(key)
	w := obj.NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return fmt.Errorf("gcs blob: write %s: %w", key, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gcs blob: close %s: %w", key, err)
	}
	return nil
}

// GetBlob downloads bytes from gs://bucket/{prefix}/{path}.
func (s *GCSCacheStore) GetBlob(ctx context.Context, path string) ([]byte, error) {
	key := s.blobKey(path)
	obj := s.client.Bucket(s.bucket).Object(key)
	rc, err := obj.NewReader(ctx)
	if err != nil {
		if errors.Is(err, gcsstorage.ErrObjectNotExist) {
			return nil, cache.ErrBlobNotFound
		}
		return nil, fmt.Errorf("gcs blob: get %s: %w", key, err)
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rc); err != nil {
		return nil, fmt.Errorf("gcs blob: read %s: %w", key, err)
	}
	return buf.Bytes(), nil
}

// DeleteBlob removes gs://bucket/{prefix}/{path}.
func (s *GCSCacheStore) DeleteBlob(ctx context.Context, path string) error {
	key := s.blobKey(path)
	obj := s.client.Bucket(s.bucket).Object(key)
	if err := obj.Delete(ctx); err != nil {
		if errors.Is(err, gcsstorage.ErrObjectNotExist) {
			return nil
		}
		return fmt.Errorf("gcs blob: delete %s: %w", key, err)
	}
	return nil
}
