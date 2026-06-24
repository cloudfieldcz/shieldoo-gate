# Local Keycloak (OIDC) dev environment

An opt-in Docker Compose overlay that runs [Keycloak](https://www.keycloak.org/) next to
Shieldoo Gate so the admin-UI OIDC login/logout flow can be exercised end-to-end on a
laptop. It is **not** part of the default dev stack or the E2E suite.

## One-time host setup (MANDATORY)

Your browser must resolve the Docker service hostname `keycloak` to localhost. Add this
single line to `/etc/hosts`:

```bash
echo "127.0.0.1 keycloak" | sudo tee -a /etc/hosts
```

Verify it:

```bash
getent hosts keycloak 2>/dev/null || ping -c1 keycloak
```

To remove it later, delete the `127.0.0.1 keycloak` line from `/etc/hosts`.

**Why this is needed:** the OIDC issuer URL (`http://keycloak:8081/realms/shieldoo`) shares the
host `keycloak:8081` between two
parties — the gate container resolves `keycloak` via Docker's internal DNS, while your host
browser needs this `/etc/hosts` entry. Using `localhost` instead would break the gate's
server-side token exchange; using `keycloak` without the hosts line would break the browser
redirect. The single shared hostname is what makes both work.

## Start / stop

```bash
make dev-keycloak-up     # build + start (prints the /etc/hosts preflight if missing)
make dev-keycloak-down   # stop and wipe volumes (so the realm re-seeds next start)
```

Then open **http://localhost:8080** and log in:

| Field    | Value       |
|----------|-------------|
| Username | `test`      |
| Password | `poklop123` |

Keycloak admin console: **http://keycloak:8081/admin** (`admin` / `admin`).

## What's configured

- Realm `shieldoo`, client `shieldoo-gate` (confidential, PKCE S256), user `test`.
- The gate is switched to OIDC auth via `SGW_*` env in the overlay — `config.yaml` is
  untouched. Auth stays off in the default `make` / E2E stacks.

## ⚠️ Dev-only — never use in a reachable environment

The fixed client secret (`local-dev-secret`), the `test` / `poklop123` user, and
`cookie_insecure=true` (drops the `Secure` cookie attribute for HTTP localhost) are
development fixtures. They live only in `docker/docker-compose.keycloak.yml` and
`docker/keycloak/realm-shieldoo.json`. Do not copy them into production config.

## Re-seeding the realm

Keycloak's `--import-realm` skips a realm that already exists. After editing
`docker/keycloak/realm-shieldoo.json`, run `make dev-keycloak-down` (which wipes the
volume) before `make dev-keycloak-up` to re-import.
