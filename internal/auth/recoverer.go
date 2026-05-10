package auth

import (
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// Recoverer is a chi-compatible middleware that recovers panics and routes the
// stack trace through zerolog *after* applying RedactBytes — closing the most likely
// path for an Authorization header to leak unredacted.
//
// Replace chi/middleware.Recoverer with this in main.go for the admin API.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				stack := debug.Stack()
				log.Error().
					Interface("panic", rv).
					Bytes("stack", RedactBytes(stack)).
					Str("path", r.URL.Path).
					Msg("panic recovered")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal_error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
