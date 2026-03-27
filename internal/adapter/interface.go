package adapter

import (
	"context"
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type Adapter interface {
	Ecosystem() scanner.Ecosystem
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	HealthCheck(ctx context.Context) error
}
