# ADR-011: Authentication surface hardening

**Status:** Accepted

## Context

A strict security review of the authentication surface (HTTP endpoints, OIDC/JWT,
sessions, API keys, PAT robustness) surfaced one critical and several high/medium
findings. The cryptographic fundamentals were sound (signature/issuer/audience/expiry
verification, PKCE S256, constant-time global-token comparison, 256-bit random tokens),
but the authorization wiring and session model were structurally weak. This ADR records
the remediation.

## Decisions

### 1. Admin auth chain fails closed (CRITICAL)

Previously, in "proxy-auth-only" mode (`proxy_auth.enabled=true`, `auth.enabled=false`)
the admin API was reachable with **no credentials**: the PAT middleware passed through
when no `Authorization` header was present, the OIDC fallback was nil, and scope
enforcement was disabled — so the request reached the handler unauthenticated. This
exposed `release`, `policy-mode`, artifact delete, project/override/docker management.

`AdminAuthChain` now fails closed by default: a request with no PAT/global token and no
OIDC fallback is rejected with 401. The genuine no-auth dev mode (neither `auth` nor
`proxy_auth` enabled) must opt in explicitly via `AllowUnauthenticated(true)`. Method-based
scope enforcement (`RequireScopeByMethod`) is enabled whenever **any** auth mechanism is
active (`auth` OR `proxy_auth`), not only for OIDC. In proxy-auth-only mode admins
authenticate with the global token as `Authorization: Bearer` (scope `*`).

### 2. Server-side sessions; ID tokens are no longer API bearers (HIGH)

The session cookie used to carry the raw OIDC ID token, which (a) could not be revoked
before its `exp` (logout only cleared the browser cookie) and (b) was accepted as an API
access bearer (token-type confusion).

A `sessions` table (migration 038) now backs an opaque, random (256-bit) session ID that
is what the cookie carries. `SessionStore` enforces expiry server-side, `Validate` purges
expired rows, logout deletes the row (immediate revocation), and refresh slides the
expiry server-side. The `OIDCMiddleware` validates only the session cookie — ID tokens
presented on `Authorization` are **no longer accepted**; API clients use PATs. A janitor
goroutine sweeps expired sessions.

### 3. Identity trust (HIGH) — single-tenant IdP

`email_verified` is now honored: a token whose email is explicitly unverified is rejected
(absent claim is tolerated, as some single-tenant IdPs omit it). The authorized-party
(`azp`) claim is validated when the token carries multiple audiences. A `nonce` is added
to the Authorization Code flow and checked on callback, binding the ID token to the auth
request.

### 4. Cookie hardening (HIGH)

Auth cookies are `Secure` by default. The previous heuristic (derive `Secure` from the
`redirect_url` scheme) is removed. `validateAuth` rejects a non-`https://` `redirect_url`
unless `auth.cookie_insecure=true` (explicit local-HTTP-dev opt-out).

### 5. CSRF protection on cookie-authenticated mutations (HIGH)

A CSRF guard runs on state-changing requests that authenticate via the session cookie. It
requires same-origin (`Origin`/`Referer` host equals the request `Host`, or an explicit
`auth.allowed_origins` match) or the custom `X-Shieldoo-CSRF` header that the SPA sets.
Token-authenticated requests (`Authorization` present) and safe methods are exempt — they
are not CSRF-prone.

### 6. Trusted-proxy client IP (HIGH)

`chi middleware.RealIP` (which trusted `X-Forwarded-For`/`X-Real-IP` unconditionally) is
replaced by `auth.TrustedProxyMiddleware`. Forwarding headers are honored only when the
immediate peer is within `server.trusted_proxies`; otherwise the real TCP peer is used.
This stops spoofing of the audit `ClientIP` (an integrity-sensitive field) and of the
rate-limit key.

### 7. Rate-limiter memory bound (HIGH)

The per-key bucket map is now bounded: a janitor evicts idle buckets and the map is
hard-capped (oldest-evicted backstop). The anonymous fallback key is normalized to the
bare IP (no ephemeral port), preventing per-port bucket inflation and rate-limit evasion.

### 8. API-key minting hardening (MEDIUM)

A dedicated `keys:manage` scope gates the `/api/v1/api-keys` endpoints, so a general
`admin:write` token cannot mint or revoke keys unless explicitly granted (OIDC operator
sessions are granted it). Key creation enforces **scope subset**: a caller cannot mint a
key with scopes it does not itself hold.

Because the subset rule binds the *minter's* held scopes, an OIDC operator session must
itself hold every scope it is expected to grant. Operator sessions therefore hold the
explicit set `auth.operatorScopes` (`admin:read`, `admin:write`, `keys:manage`,
`proxy:fetch`, `scan:upload`) — every currently defined scope — so an interactive admin
can mint any key from the UI, including the default `proxy:fetch` key for pip/npm/docker.
The set is an explicit literal rather than an auto-growing "all scopes" list or a `"*"`
wildcard: consistent with this ADR's least-privilege stance (`keys:manage` was split out
of `admin:write` for the same reason), introducing a new scope must be a deliberate
decision about whether operators should hold it, not a silent auto-grant.

### 9. Audit fail-closed for super-token use (MEDIUM)

Both auth paths previously ignored the `super_token_used` audit-write error. They now fail
**closed**: if the audit row cannot be written, the request is rejected (500) rather than
authenticating a privileged token with no trace (reinforces Security Invariant 6).

### 10. Log redactor (MEDIUM)

The unregistered, lossy `LogRedactorHook` (a zerolog hook cannot rewrite a message, only
discard it) was removed to avoid false assurance. The `RedactBytes`/`RedactString` helpers
remain and are applied at known leak points (panic-stack dumps).

## Consequences

- New config: `server.trusted_proxies`, `auth.session_ttl`, `auth.cookie_insecure`,
  `auth.allowed_origins`. `auth.redirect_url` must be `https://` in production.
- New DB table `sessions` (migration 038, SQLite + PostgreSQL).
- OIDC ID tokens are no longer accepted as API bearers — automation must use PATs.
- A general `admin:write` token can no longer manage API keys; grant `keys:manage`.
- The admin API is no longer silently open in proxy-auth-only mode; use the global token.
