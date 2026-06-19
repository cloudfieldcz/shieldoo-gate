# ADR-016: RP-initiated logout (OIDC end-session)

## Status
Accepted (2026-06-19)

## Context
`HandleLogout` previously cleared only the local server-side session and cookie. The IdP SSO
session stayed alive, so the next login silently re-authenticated the user without a
credential prompt — the user was not effectively logged out (GH #31). OIDC RP-Initiated
Logout terminates the IdP session via the provider's `end_session_endpoint`, optionally
passing `id_token_hint` (which suppresses the IdP's logout-confirmation prompt — required by
Keycloak 18+ when the hint is absent).

## Decision
- Persist the raw `id_token` on the server-side `sessions` row (`NOT NULL DEFAULT ''`,
  migration 039) so logout can supply `id_token_hint`. The token is read only by the logout
  path (`SessionStore.IDTokenFor`) and never returned by `Validate` — it does not reach
  request context.
- `NewAuthHandlers` reads `end_session_endpoint` from the discovery document.
- `HandleLogout` deletes the local session first, then — when an `end_session_endpoint` was
  discovered — returns `{"status":"logged_out","logout_url":"…"}`. The SPA navigates to
  `logout_url` (a 302 from a fetched POST is not a browser navigation, so the URL is returned
  in the body). The URL carries `client_id`, the operator-configured
  `post_logout_redirect_uri`, and `id_token_hint` (when present).

## Consequences
- **Fail-safe ordering:** local logout is authoritative and always succeeds regardless of IdP
  reachability; IdP termination is best-effort layered on top. Logout is a client-side
  browser navigation — there is **no server-side call to the end-session endpoint**, so no
  timeout/circuit-breaker is needed (a future maintainer should not add one).
- **Backwards compatible:** no advertised `end_session_endpoint` (or empty stored id_token)
  → unchanged local-only logout and `{"status":"logged_out"}` body.
- **Data exposure:** the stored `id_token` is a signed JWT carrying PII (email, name,
  subject) added to a `sessions` row that already stores email/name/subject in plaintext —
  no posture regression, but DB-at-rest protection remains the operator's responsibility. The
  token is short-lived (session TTL, default 15m) and cleared on logout via row delete.
- **Never-logged:** the `id_token_hint` rides in `logout_url`'s query string; `HandleLogout`
  must not log the URL or response body (enforced by
  `TestHandleLogout_MalformedEndSession_DegradesAndNeverLogsIDToken`). `log_redactor` scrubs
  header-shaped secrets, not URL query strings.
- **Open-redirect closed:** `post_logout_redirect_uri` is built solely from operator config,
  never request input (`TestHandleLogout_IgnoresRequestParams`); Keycloak also enforces its
  registered allow-list.
- **Accepted limitation — expired `id_token_hint`:** the session TTL slides on refresh and can
  outlive the id_token captured at login. Keycloak may reject an expired hint and fall back to
  its confirmation prompt. We accept this; parsing the JWT `exp` to drop a known-expired hint
  is deferred.
- **Out of scope:** the gate deletes only the single session bound to the request cookie. The
  IdP SSO termination may cascade to other relying parties at the IdP, but the gate does not
  enumerate a user's other gate sessions.

## References
- GH #31; OIDC RP-Initiated Logout 1.0; ADR-011 (server-side session rationale).
