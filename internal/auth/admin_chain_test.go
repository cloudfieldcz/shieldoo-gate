package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// An authenticated OIDC operator session is the admin UI's interactive trust root
// and must be able to mint an API key of ANY defined scope. This is a regression
// guard for the auth-hardening change (ADR-011 §8) where operators implicitly held
// only [admin:read, admin:write, keys:manage]; because scopes are orthogonal (admin:*
// does not imply proxy:fetch), the default "Create key" flow — which mints a
// proxy:fetch key — failed with 403 "cannot grant scope you do not hold: proxy:fetch".
func TestOperatorScopes_CanGrantEveryDefinedScope(t *testing.T) {
	for _, sc := range model.AllScopes {
		assert.Truef(t, ScopeSatisfiedBy(operatorScopes, sc),
			"OIDC operator must be able to grant %q to a minted API key", sc)
	}
}
