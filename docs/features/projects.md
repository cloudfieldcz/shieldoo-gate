# Project Registry

> Lightweight per-team / per-service segmentation of proxy usage, derived from the Basic-auth username.

**Status:** Implemented (v1.2)
**Analysis:** [2026-04-15-sbom-and-license-policy.md](../plans/2026-04-15-sbom-and-license-policy.md)

## Problem

Before v1.2, Shieldoo Gate treated every proxy request as global — there was no way to tell who or which project pulled which artifact, and no way to apply different policies to different projects. Multi-team deployments had to guess from audit timestamps and client IPs.

## Solution

A new `projects` table stores one row per logical project. The **Basic-auth username** presented by proxy clients (pip, npm, docker, etc.) is used as the project label. This requires zero client changes for deployments that already set a username; for new deployments we document how to configure pip/npm/docker to embed the label.

The admin UI + audit log expose `project_id` on every artifact request, and per-project license policy overrides (see [license-policy.md](./license-policy.md)) build on top of this.

## Quick answer: "what do I put in the username?"

Every proxy request authenticates via HTTP Basic Auth. The **password field** carries the PAT (or global token); the **username field** carries a **project label**.

| Case | What to use |
|------|-------------|
| You don't care about per-project segmentation | `default` (or leave the username empty — it falls back to `default`) |
| You want your team/service tracked separately | `backend-team`, `data-pipeline`, `ci-jenkins`, etc. (lowercase, `[a-z0-9][a-z0-9_-]{0,63}`) |
| You want strong separation (per-project license policy) | Run in **strict mode** and have an admin pre-create the project at `POST /api/v1/projects` |

### Why the username is reused as a project label

All supported proxy protocols (pip, npm, docker, NuGet, Maven, Go, gems) natively support HTTP Basic Auth but **none** support arbitrary custom headers. Reusing the username slot gives us project segmentation with **zero client-side changes**. The field was previously ignored — Shieldoo Gate authenticated on the password only. Starting in v1.2, the username is normalized (lowercased, regex-validated) and resolved to a `projects` row; the PAT still authenticates the caller.

### Silent fallback rules

- Empty username → `projects.default_label` (default: `default`).
- Mixed-case username → lowercased to a single canonical row (`MyTeam` and `myteam` collapse into one).
- Invalid username (non-matching regex, too long, traversal chars) → **400 `invalid_project_label`**, so you see immediately that something is wrong.

### Do I need to create the `default` project?

No. Migration `018_projects.sql` seeds it on first boot. Every deployment has a `default` row with `created_via='seed'` so old clients that never set a username (or forget to set one) are still routed correctly.

## Modes

### Lazy (default)

Any new username auto-creates a project row (`created_via = "lazy"`). This is the zero-friction default — pip/npm/docker don't need to know anything new and existing audit data is retroactively segmented.

**Guards:**

- `projects.max_count` hard cap (default 1000) — prevents unbounded table growth.
- `projects.lazy_create_rate` per-identity rate limit (default 10/hour/PAT) — prevents attackers from creating thousands of projects with random labels.
- Label validation: lowercased, regex `^[a-z0-9][a-z0-9_-]{0,63}$`.
- Empty Basic-auth username → `projects.default_label` (default `"default"`).
- Mixed-case labels collapse into a single lowercase row (`MyApp` → `myapp`).

### Strict

Labels must be pre-provisioned via `POST /api/v1/projects` **or** via `projects.bootstrap_labels` in `config.yaml` (see [Configuration](#configuration) below). Unknown labels are rejected with 403 at auth time. Use strict mode when:

- Per-project license policy overrides must be secure (see S-01 anti-spoofing in the analysis).
- You want deterministic billing / chargeback by project.
- You want to prevent ad-hoc labeling of proxy usage.

The reference [`docker/config.yaml`](../../docker/config.yaml) ships in **strict** mode with `bootstrap_labels` covering the `examples/` projects, the `shieldoo-gate` self-build identity, and `ci-bot`. This means the bundled smoke-test examples work immediately without any admin POST step.

## Configuration

```yaml
projects:
  mode: lazy                # lazy | strict
  default_label: default    # fallback for empty Basic-auth username
  label_regex: ""           # optional custom regex (default is the one above)
  max_count: 1000           # hard cap (0 = unlimited)
  lazy_create_rate: 10      # new projects per hour per identity (PAT hash)
  cache_size: 512           # LRU entries (hot-path optimization)
  cache_ttl: 5m             # LRU entry TTL
  usage_flush_period: 30s   # debounce interval for artifact_project_usage upserts
  bootstrap_labels:         # idempotent: ensure these projects exist on startup
    - default
    - shieldoo-gate
    - ci-bot
```

### `bootstrap_labels`

A list of project labels that are guaranteed to exist after every startup. The hook runs once during initialization, **after** migration 018 seeds `default` and **before** any HTTP listener accepts traffic:

1. For each label, `GetByLabel(label)` is called.
2. If the row exists, it is left untouched (display_name / description / enabled / created_via are not overwritten).
3. If it doesn't exist, `Create(label, "", "Bootstrapped from config.yaml projects.bootstrap_labels")` is called. The new row gets `created_via = 'api'`.
4. Failures are logged at WARN and execution continues — bootstrap is best-effort, never blocks startup.

**When you need it:**

- **Strict mode**: ad-hoc clients (CI runners, build pipelines, the `examples/` smoke-tests) cannot pre-provision themselves via `POST /api/v1/projects` because that endpoint requires admin OIDC. Bootstrap fills the gap so authentication works on first request.
- **Self-build dogfooding**: when Shieldoo Gate is built by another running Shieldoo Gate, the Dockerfile sends `SGW_USER=shieldoo-gate` as the Basic-auth username — bootstrap that label so the build doesn't 403.
- **Lazy mode**: not strictly required (labels auto-create on first use), but listing them makes the registry visible in the admin UI immediately, before any traffic.

Bootstrap is intentionally **idempotent and additive** — it never disables or deletes a label you already manage by hand.

## Architecture

```
Basic Auth: user=<label>, pass=<PAT>
    │
    ▼
APIKeyMiddleware
    1. Validate PAT (SHA-256 lookup)
    2. Extract username → label (NOT key.OwnerEmail!)
    3. projectSvc.Resolve(label, patHash):
        a. LRU cache hit → return
        b. SELECT by label → cache + return
        c. Lazy: rate-limit + cap check → INSERT OR IGNORE + SELECT
        d. Strict: 403 ErrProjectNotFound
    4. ctx = project.WithContext(ctx, p)
    │
    ▼
Adapter → Scanner → Policy
    • WriteAuditLogCtx stamps project_id
    • RecordUsage(projectID, artifactID) — debounced upsert
    • Policy engine reads project from context (license resolver, etc.)
```

## Performance Notes

- **LRU cache is mandatory**, not optional. Without it every proxy request would issue a SELECT on a hot table that also receives INSERTs for new projects → SQLite write-lock contention.
- **`artifact_project_usage` upserts are debounced** via an in-memory `sync.Map` + 30s flush loop (same pattern as `touchLastUsed` on `api_keys`). This collapses N identical `(artifact, project)` upserts into a single `use_count = use_count + N`.
- **Per-identity rate limiter** lives in memory. Server restart = reset (acceptable; the guard protects against sustained bursts, not single-request spikes).

## Schema

```sql
CREATE TABLE projects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT NOT NULL UNIQUE,
    display_name TEXT,
    description  TEXT,
    created_at   DATETIME NOT NULL,
    created_via  TEXT NOT NULL DEFAULT 'lazy',  -- 'lazy' | 'api' | 'seed'
    enabled      INTEGER NOT NULL DEFAULT 1     -- metadata flag in v1.2
);

CREATE TABLE artifact_project_usage (
    artifact_id   TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    first_used_at DATETIME NOT NULL,
    last_used_at  DATETIME NOT NULL,
    use_count     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (artifact_id, project_id)
);
```

`audit_log` gained a nullable `project_id` column (migration 019). The column is stamped by `WriteAuditLogCtx` when the request context carries a project.

## API

All endpoints require admin OIDC authentication.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/projects` | List projects |
| POST | `/api/v1/projects` | Explicit create (required for strict mode pre-provisioning) |
| GET | `/api/v1/projects/{id}` | Single project |
| PATCH | `/api/v1/projects/{id}` | Update `display_name`, `description`, `enabled` |
| DELETE | `/api/v1/projects/{id}` | Soft-disable (metadata-only in v1.2) |
| GET | `/api/v1/projects/{id}/artifacts` | Artifacts used by this project |
| GET | `/api/v1/projects/{id}/license-policy` | Effective license policy |
| PUT | `/api/v1/projects/{id}/license-policy` | Upsert override (requires strict mode) |

## Client Configuration Examples

The [`examples/`](../../examples/) directory ships ready-to-run smoke-test projects for every supported ecosystem. Each one picks a distinct project label so you can see per-project segmentation light up in the admin UI after a single `install`:

| Ecosystem | Example | Project label | Auth mechanism |
|-----------|---------|---------------|---------------|
| PyPI      | [python-requests](../../examples/python-requests/) | `python-demo`  | Basic-auth userinfo in `--index-url` |
| npm       | [npm-chalk](../../examples/npm-chalk/) | `npm-demo`     | `_auth` (base64) in `.npmrc` |
| NuGet     | [dotnet-json](../../examples/dotnet-json/) | `dotnet-demo`  | `<packageSourceCredentials>` in `nuget.config` |
| Maven     | [maven-example](../../examples/maven-example/) | `maven-demo`   | `<server>` in local `settings.xml` |
| RubyGems  | [rubygems-example](../../examples/rubygems-example/) | `rubygems-demo` | Basic-auth userinfo in `source` URL |
| Go        | [go-example](../../examples/go-example/) | `go-demo`      | Basic-auth userinfo in `GOPROXY` |

The reference [`docker/docker-compose.yml`](../../docker/docker-compose.yml) injects a well-known development token (`SGW_PROXY_TOKEN=test-token-123`) into the container via `environment:`, so these examples work right after `docker compose up -d` — no token bootstrapping required. See [examples/README.md](../../examples/README.md) for details, including the recipe for switching to `default` if you don't care about segmentation.

**Manual snippets** (for reference; prefer the ready-made examples above):

**pip / uv:**
```
uv pip install --index-url https://myproject:$PAT@proxy.example.com/pypi/simple ...
```

**npm:**
```
echo "//proxy.example.com/npm/:_auth=$(echo -n myproject:$PAT | base64)" > ~/.npmrc
npm install --registry https://proxy.example.com/npm/
```

**docker:**
```
echo $PAT | docker login proxy.example.com -u myproject --password-stdin
docker pull proxy.example.com/library/nginx
```

## Admin UI

The admin UI exposes the project registry at `/projects` (sidebar: **Projects**).

- **List view** (`/projects`) — shows every row with label, display name, source (`seed` / `lazy` / `api`), created_at, and enabled flag. Label links to the detail page.
- **New project** button opens a modal that validates the label against `[a-z0-9][a-z0-9_-]{0,63}` client-side and posts to `POST /api/v1/projects`. Use this to pre-provision projects for strict mode.
- **Detail view** (`/projects/:id`) has two tabs:
  - **Artifacts** — every artifact this project has pulled (from `artifact_project_usage`), ordered by `last_used_at`. The label in the left column deep-links to the artifact detail panel.
  - **License policy** — per-project override editor (see [License Policy › Admin UI](./license-policy.md#admin-ui)). In lazy mode the `override` radio is disabled with a tooltip that explains the strict-mode requirement.

Every proxy request is stamped with `project_id` in the audit log (visible in the **Audit Log** page once a project-filter column is wired).

## Limitations (v1.2)

- `enabled = 0` is metadata only. Blocking disabled projects at request time is deferred to a future release.
- No per-project rate limits or quotas yet — the `lazy_create_rate` is only for project *creation*, not request volume.
- No hierarchical projects or tags — a flat namespace of labels.
- PAT → project binding is not enforced. Any valid PAT can use any label (in lazy mode). This is the S-01 reason per-project license overrides are strict-mode-only.

## Files

- Service: [internal/project/service.go](../../internal/project/service.go)
- Context helpers: [internal/project/project.go](../../internal/project/project.go)
- Auth integration: [internal/auth/apikey.go](../../internal/auth/apikey.go)
- API: [internal/api/projects.go](../../internal/api/projects.go)
- Migrations: [018_projects.sql](../../internal/config/migrations/sqlite/018_projects.sql), [019_audit_project_id.sql](../../internal/config/migrations/sqlite/019_audit_project_id.sql), [020_artifact_project_usage.sql](../../internal/config/migrations/sqlite/020_artifact_project_usage.sql)
