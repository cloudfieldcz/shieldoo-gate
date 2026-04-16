package cache

import (
	"context"
	"errors"
)

// BlobStore is a content-agnostic blob storage interface used for artifacts
// that are NOT scanner artifacts — primarily SBOMs and other generated
// metadata. Paths are treated as opaque keys; backend implementations may
// sanitize or namespace them as needed.
//
// All backends (local, s3, azure_blob, gcs) implement BlobStore alongside
// CacheStore. The Shieldoo Gate runtime selects the active backend at
// startup and uses the same instance for both artifact cache and blob
// storage so that deployments only configure one storage target.
type BlobStore interface {
	// PutBlob stores data at the given path, overwriting any existing blob.
	PutBlob(ctx context.Context, path string, data []byte) error

	// GetBlob retrieves the blob at path. Returns ErrBlobNotFound if absent.
	GetBlob(ctx context.Context, path string) ([]byte, error)

	// DeleteBlob removes the blob at path. It is NOT an error if the blob
	// does not exist — the post-condition is "not present".
	DeleteBlob(ctx context.Context, path string) error
}

// ErrBlobNotFound is returned by BlobStore.GetBlob when the requested path
// does not exist.
var ErrBlobNotFound = errors.New("blob not found")
