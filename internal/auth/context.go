// Package auth implements OIDC authentication middleware and login flow handlers
// for the Shieldoo Gate admin API.
package auth

import "context"

type contextKey int

const userContextKey contextKey = iota

// UserInfo holds the identity claims extracted from a verified OIDC token.
type UserInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// UserFromContext returns the authenticated user from the request context,
// or nil if no user is present (e.g. auth is disabled).
func UserFromContext(ctx context.Context) *UserInfo {
	u, _ := ctx.Value(userContextKey).(*UserInfo)
	return u
}

// ContextWithUser returns a new context carrying the given UserInfo.
func ContextWithUser(ctx context.Context, user *UserInfo) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
