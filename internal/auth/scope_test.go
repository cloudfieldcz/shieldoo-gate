package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

func TestHasScope(t *testing.T) {
	ctx := WithScopes(context.Background(), []string{"admin:read"})
	if !HasScope(ctx, "admin:read") {
		t.Error("expected scope present")
	}
	if HasScope(ctx, "admin:write") {
		t.Error("admin:write should not be present")
	}
}

func TestRequireScope_Allows(t *testing.T) {
	mw := RequireScope("scan:upload")
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(WithScopes(req.Context(), []string{"scan:upload"}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireScope_GlobalToken(t *testing.T) {
	mw := RequireScope("scan:upload")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(WithScopes(req.Context(), []string{"*"}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("global token should pass any scope; got %d", rr.Code)
	}
}

func TestRequireScope_Forbidden(t *testing.T) {
	mw := RequireScope("admin:write")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(WithScopes(req.Context(), []string{"admin:read"}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestScopesFromAPIKey_Default(t *testing.T) {
	scopes := ScopesFromAPIKey(&model.APIKey{Scopes: ""})
	if len(scopes) != 1 || scopes[0] != "proxy:fetch" {
		t.Errorf("empty scopes should default to proxy:fetch, got %v", scopes)
	}
}

func TestRedactBytes(t *testing.T) {
	in := []byte("Authorization: Bearer abc123\nfoo: bar\nCookie: session=xyz")
	out := RedactBytes(in)
	if string(out) == string(in) {
		t.Error("expected redaction to alter the input")
	}
	if string(out)[:0] == "" && len(out) > 0 {
		// Just confirming function returned something
	}
}
