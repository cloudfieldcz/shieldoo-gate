package cache

import (
	"context"
	"errors"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

var ErrNotFound = errors.New("artifact not found in cache")

type CacheFilter struct {
	Ecosystem string
	Name      string
}

type CacheStats struct {
	TotalItems  int64
	TotalBytes  int64
	ByEcosystem map[string]int64
}

type CacheStore interface {
	Get(ctx context.Context, artifactID string) (localPath string, err error)
	Put(ctx context.Context, artifact scanner.Artifact, localPath string) error
	Delete(ctx context.Context, artifactID string) error
	List(ctx context.Context, filter CacheFilter) ([]string, error)
	Stats(ctx context.Context) (CacheStats, error)
}
