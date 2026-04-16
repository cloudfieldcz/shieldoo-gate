package azureblob

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
)

// Compile-time interface check.
var _ cache.BlobStore = (*AzureBlobStore)(nil)

func (s *AzureBlobStore) blobName(path string) string {
	p := strings.TrimLeft(path, "/")
	if s.prefix != "" {
		return s.prefix + "/" + p
	}
	return p
}

// PutBlob uploads bytes to {container}/{prefix}/{path}.
//
// Uses UploadBuffer (single-shot PUT) rather than UploadStream. UploadStream
// negotiates a newer block-blob API version which some older Azure-compatible
// stores (notably Azurite < 3.29) reject with HTTP 400 "API version not
// supported". SBOM blobs are small (kB–MB), so single-shot upload is fine and
// matches the API version used by the existing Put() path that already works
// against Azurite in the e2e test stack.
func (s *AzureBlobStore) PutBlob(ctx context.Context, path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("azure blob: empty path")
	}
	name := s.blobName(path)
	_, err := s.client.UploadBuffer(ctx, s.containerName, name, data, nil)
	if err != nil {
		return fmt.Errorf("azure blob: put %s: %w", name, err)
	}
	return nil
}

// GetBlob downloads bytes from {container}/{prefix}/{path}.
func (s *AzureBlobStore) GetBlob(ctx context.Context, path string) ([]byte, error) {
	name := s.blobName(path)
	resp, err := s.client.DownloadStream(ctx, s.containerName, name, nil)
	if err != nil {
		if bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil, cache.ErrBlobNotFound
		}
		return nil, fmt.Errorf("azure blob: get %s: %w", name, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// DeleteBlob removes {container}/{prefix}/{path}.
func (s *AzureBlobStore) DeleteBlob(ctx context.Context, path string) error {
	name := s.blobName(path)
	_, err := s.client.DeleteBlob(ctx, s.containerName, name, nil)
	if err != nil {
		if bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil
		}
		return fmt.Errorf("azure blob: delete %s: %w", name, err)
	}
	return nil
}
