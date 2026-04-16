package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
)

// Compile-time interface check.
var _ cache.BlobStore = (*S3CacheStore)(nil)

func (s *S3CacheStore) blobKey(path string) string {
	p := strings.TrimLeft(path, "/")
	if s.prefix != "" {
		return s.prefix + "/" + p
	}
	return p
}

// PutBlob uploads data to s3://bucket/{prefix}/{path}.
func (s *S3CacheStore) PutBlob(ctx context.Context, path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("s3 blob: empty path")
	}
	key := s.blobKey(path)
	_, err := s.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("s3 blob: put %s: %w", key, err)
	}
	return nil
}

// GetBlob downloads s3://bucket/{prefix}/{path}.
func (s *S3CacheStore) GetBlob(ctx context.Context, path string) ([]byte, error) {
	key := s.blobKey(path)
	out, err := s.client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *s3types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, cache.ErrBlobNotFound
		}
		return nil, fmt.Errorf("s3 blob: get %s: %w", key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

// DeleteBlob removes s3://bucket/{prefix}/{path}.
func (s *S3CacheStore) DeleteBlob(ctx context.Context, path string) error {
	key := s.blobKey(path)
	_, err := s.client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 blob: delete %s: %w", key, err)
	}
	return nil
}
