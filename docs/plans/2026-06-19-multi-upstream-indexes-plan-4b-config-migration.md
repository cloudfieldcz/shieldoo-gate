# Multi-Upstream Indexes — Phase 4b: Config Migration & Consistency

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring every committed `config.yaml` in the repo into a consistent, intentional state for the multi-upstream-index feature, and add a regression guard that proves they all still load + validate. The Phase 1 back-compat decode hook means **no config is broken today** — this phase is about *consistency and discoverability*, plus locking in the production posture decided with the maintainer.

**Maintainer decisions (2026-06-19):**
1. **Every committed config is restructured to the `default:` form** — including production (`.deploy/config.yaml`) and the Helm chart (`values.yaml` + `configmap.yaml`). The `default:` shape is functionally identical to the bare string (it decodes to `UpstreamSet{Default: ...}` via the Phase 1 hook), so this is a **shape-only change with no behaviour change**.
2. **No production config gets real `extra_indexes`.** Prod remains a transparent pull-through proxy — `default:` only, no private/secondary indexes. (Adding a real private index to prod is a separate, future operational change — out of scope here.)
3. **Helm requires a template change too:** restructuring `values.yaml` to `default:` form means the `configmap.yaml` renderer must emit the structured `upstreams.<eco>.default` shape. Both are updated and verified with `helm template`.

**What other plans already cover (do NOT duplicate here):**
- `config.example.yaml` — full annotated multi-index block → **Phase 3 Task 4**.
- `tests/e2e-shell/config.e2e.yaml` — real unscoped + scoped indexes → **Phase 4 Task 3**.

**Tech Stack:** YAML config, Go 1.25 (`internal/config.Load` + `Validate`), `github.com/stretchr/testify`.

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

**Depends on:** Phase 1 (decode hook + `UpstreamSet` types + `validateUpstreamSet`). Best sequenced **after Phase 3** so `config.example.yaml` exists as the canonical annotated template the restructured configs mirror. It does not depend on Phase 2/4 code.

---

## File structure

- **Modify:** `docker/config.yaml` — restructure the six non-Docker upstreams to `default:` form.
- **Modify:** `examples/deploy/config.yaml` — restructure the six non-Docker upstreams to `default:` form.
- **Modify:** `.deploy/config.yaml` — restructure to `default:` form, **no `extra_indexes`** (prod = transparent proxy; no live deployment yet so no rollout risk; keep `.deploy/` 1:1 with the repo).
- **Modify:** `helm/shieldoo-gate/values.yaml` + `helm/shieldoo-gate/templates/configmap.yaml` — restructure values to `default:` form AND update the configmap renderer in lockstep; render-verify.
- **Create:** `internal/config/config_files_test.go` — regression test that every committed repo config `Load()`s + `Validate()`s cleanly.
- **Modify:** `docs/` (PyPI adapter / config page or ADR-017 stub) — document the structured-`default:` standard, that prod/helm ship no `extra_indexes`, and how to opt into a private index. (Coordinate with Phase 8 docs; if Phase 8 hasn't landed, add a short note now and let Phase 8 absorb it.)

---

## Task 1: Regression guard — every committed config loads + validates

**Rationale:** Restructuring YAML by hand is the easiest place to introduce a silent typo (wrong indent, `extra_index` vs `extra_indexes`). A table-driven test that loads every committed config and runs `Validate()` catches a broken restructure immediately and protects the configs forever. Write it **first** (TDD): it must pass against the *current* bare-string configs before any restructure, then keep passing after.

**Files:**
- Create: `internal/config/config_files_test.go`

- [ ] **Step 1: Write the test**

Create `internal/config/config_files_test.go`. The test resolves the repo root from the test's working directory (`internal/config` → two levels up) and loads each committed config that is meant to be a *complete* gate config (i.e. NOT Helm values, which are chart inputs, not a gate config; NOT the configmap template, which is Go-template text).

```go
package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoConfigFiles are committed, complete gate configs that MUST load + validate.
// Helm values.yaml and the configmap template are intentionally excluded — they
// are chart inputs / Go-template text, not standalone gate configs.
var repoConfigFiles = []string{
	"config.example.yaml",
	"docker/config.yaml",
	"examples/deploy/config.yaml",
	".deploy/config.yaml",
	"tests/e2e-shell/config.e2e.yaml",
}

func TestCommittedConfigs_LoadAndValidate(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	for _, rel := range repoConfigFiles {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(repoRoot, rel)
			cfg, err := Load(path)
			require.NoError(t, err, "Load(%s) must succeed", rel)
			require.NotNil(t, cfg)
			assert.NoError(t, cfg.Validate(), "Validate(%s) must succeed", rel)
		})
	}
}
```

> **Adapt to reality:** confirm `Load` returns `(*Config, error)` and `Validate` is a method on `*Config` with no args (it is, per Phase 1). If `Load` already calls `Validate` internally, the explicit `cfg.Validate()` is belt-and-suspenders — keep it. If any committed config legitimately requires an env var to validate (e.g. a required token), set it with `t.Setenv` inside that file's subtest. Report any such case.

- [ ] **Step 2: Run the test against current (bare-string) configs**

Run: `go test ./internal/config/ -run TestCommittedConfigs_LoadAndValidate -v`
Expected: PASS for all listed files **as they are today** (bare strings already decode via the Phase 1 hook). If any file fails NOW, that is a pre-existing config bug — report it before restructuring.

- [ ] **Step 3: Commit**

```bash
git add internal/config/config_files_test.go
git commit -m "test(config): regression guard — every committed config loads + validates"
```

---

## Task 2: Restructure `docker/config.yaml` to `default:` form

**Files:**
- Modify: `docker/config.yaml`

- [ ] **Step 1: Restructure the six non-Docker upstreams**

In `docker/config.yaml`, change the bare-string upstreams to the `default:` form. **Leave `maven_resolver`, `docker`, and every non-upstream section exactly as-is.** Result:

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
  npm:
    default: "https://registry.npmjs.org"
  nuget:
    default: "https://api.nuget.org"
  maven:
    default: "https://repo1.maven.org/maven2"
  maven_resolver:
    enabled: true                    # resolve licenses from parent POM chain (fail-open)
    cache_size: 4096                 # in-memory LRU entries for parent POMs
    cache_ttl: "24h"                 # parent POMs are immutable per release GAV
    max_depth: 5                     # max parent chain depth (hardcode ceiling: 10)
    fetch_timeout: "3s"              # per-POM HTTP timeout
    resolver_timeout: "5s"           # total timeout for entire parent chain walk
  rubygems:
    default: "https://rubygems.org"
  gomod:
    default: "https://proxy.golang.org"
  docker:
    # ... unchanged ...
```

> Preserve the exact default URL strings already present (read the file — do not assume). Preserve all comments and surrounding sections byte-for-byte except the six upstream entries.

- [ ] **Step 2: Verify it still loads + validates**

Run: `go test ./internal/config/ -run TestCommittedConfigs_LoadAndValidate/docker -v`
Expected: PASS (`docker/config.yaml` subtest green).

- [ ] **Step 3: Commit**

```bash
git add docker/config.yaml
git commit -m "config(docker): restructure upstreams to default: form (multi-index ready)"
```

---

## Task 3: Restructure `examples/deploy/config.yaml` to `default:` form

**Files:**
- Modify: `examples/deploy/config.yaml`

- [ ] **Step 1: Restructure the six non-Docker upstreams**

Same transformation as Task 2, applied to `examples/deploy/config.yaml` (this file has no `maven_resolver` block — leave whatever is actually there unchanged; only convert the six bare-string upstream entries). Result:

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
  npm:
    default: "https://registry.npmjs.org"
  nuget:
    default: "https://api.nuget.org"
  maven:
    default: "https://repo1.maven.org/maven2"
  rubygems:
    default: "https://rubygems.org"
  gomod:
    default: "https://proxy.golang.org"
  docker:
    # ... unchanged ...
```

- [ ] **Step 2: Verify**

Run: `go test ./internal/config/ -run TestCommittedConfigs_LoadAndValidate/examples -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add examples/deploy/config.yaml
git commit -m "config(examples): restructure deploy upstreams to default: form"
```

---

## Task 4: Restructure `.deploy/config.yaml` (production) to `default:` form

**Maintainer decision: restructure to `default:` form, NO `extra_indexes`.** Shape-only change — prod stays a transparent pull-through proxy. There is **no live prod deployment yet**, so there is no rollout risk; `.deploy/` must stay 1:1 with the repo.

**Files:**
- Modify: `.deploy/config.yaml`

- [ ] **Step 1: Restructure the six non-Docker upstreams**

In `.deploy/config.yaml`, convert the six bare-string upstreams to the `default:` form. Preserve `maven_resolver`, `docker`, and every non-upstream section. Do **not** add `extra_indexes`. Read the file first and preserve the exact default URL strings + comments:

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
  npm:
    default: "https://registry.npmjs.org"
  nuget:
    default: "https://api.nuget.org"
  maven:
    default: "https://repo1.maven.org/maven2"
  maven_resolver:
    enabled: true                    # (preserve whatever is actually present)
  rubygems:
    default: "https://rubygems.org"
  gomod:
    default: "https://proxy.golang.org"
  docker:
    # ... unchanged ...
```

Optionally add one pointer comment above the block so operators know the opt-in path:

```yaml
# Structured `default:` form (functionally identical to a bare string). To add a
# private/secondary index later, add `extra_indexes:` under an ecosystem — see
# config.example.yaml. Prod is a transparent pull-through proxy: no extra_indexes by default.
```

- [ ] **Step 2: Verify prod config loads + validates**

Run: `go test ./internal/config/ -run 'TestCommittedConfigs_LoadAndValidate/\.deploy' -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add .deploy/config.yaml
git commit -m "config(deploy): restructure prod upstreams to default: form (no behaviour change)"
```

---

## Task 5: Restructure the Helm chart (`values.yaml` + `configmap.yaml`) to `default:` form

**Maintainer decision: fully restructure Helm too — there is no prod deployment yet, so no migration risk.** Both the values defaults and the configmap renderer change so the chart emits the structured `upstreams.<eco>.default` shape. No `extra_indexes` by default.

**Files:**
- Modify: `helm/shieldoo-gate/values.yaml`
- Modify: `helm/shieldoo-gate/templates/configmap.yaml`

- [ ] **Step 1: Read both files first**

Read `helm/shieldoo-gate/values.yaml` (upstreams block ~line 64) and `helm/shieldoo-gate/templates/configmap.yaml` (how it renders `.Values.upstreams.*`). Determine whether the configmap currently renders each upstream as a scalar (`pypi: {{ .Values.upstreams.pypi }}`) or via a generic map walk. The renderer MUST change in lockstep with the values shape.

- [ ] **Step 2: Restructure `values.yaml`**

Convert the six non-Docker upstreams to nested `default:`:

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
  npm:
    default: "https://registry.npmjs.org"
  nuget:
    default: "https://api.nuget.org"
  maven:
    default: "https://repo1.maven.org/maven2"
  rubygems:
    default: "https://rubygems.org"
  gomod:
    default: "https://proxy.golang.org"
  docker:
    # ... unchanged (chart uses defaultRegistry/allowedRegistries/sync) ...
```

Add a comment noting `extra_indexes:` may be added under any ecosystem (see `config.example.yaml`) but is empty by default.

- [ ] **Step 3: Update `configmap.yaml` to render the structured shape**

Change the renderer so the generated gate `config.yaml` contains `upstreams.<eco>.default` (and is forward-compatible with `extra_indexes` if a values author adds them). Prefer a faithful YAML re-emit of the values subtree, e.g.:

```yaml
  upstreams:
    pypi:
      default: {{ .Values.upstreams.pypi.default | quote }}
    npm:
      default: {{ .Values.upstreams.npm.default | quote }}
    # ... nuget, maven, rubygems, gomod the same ...
```

> If the chart already used a generic `{{ toYaml .Values.upstreams | nindent N }}` dump, the restructure may need **no template change** (the nested map renders as-is) — verify by rendering. If it rendered scalars explicitly, update each line as above. To also support optional `extra_indexes` cleanly, a `toYaml` dump of the whole `upstreams` map is the most robust; choose it if the chart's existing style allows. **Report which approach you used and why.**

- [ ] **Step 4: Render-verify the chart**

Run (pin/локate helm as the repo expects; plain `helm template` is fine for verification):

```bash
helm template helm/shieldoo-gate > /tmp/helm-render.yaml 2>&1; tail -n 40 /tmp/helm-render.yaml
```

Confirm the rendered ConfigMap's gate `config.yaml` shows `upstreams.pypi.default: "https://pypi.org"` (structured), valid YAML, no template errors. If `helm` is unavailable in the environment, report that and fall back to a careful manual review + a note that render-verification is pending.

> **Strong recommendation:** extend the Task 1 regression test to also load the *rendered* config if feasible, OR at minimum assert the rendered YAML parses. If extracting the ConfigMap data in Go is too heavy for this phase, leave a `// TODO` and rely on `helm template` + manual review. Report your choice.

- [ ] **Step 5: Docs note**

Add a short note to the relevant `docs/` page (coordinate with Phase 8; if Phase 8 docs don't exist yet, add a stub under the PyPI adapter / config section):
- All configs (incl. prod + Helm) now use the structured `default:` form; bare strings remain supported (back-compat).
- Prod + Helm ship **no** `extra_indexes` (transparent proxy); how to opt a single ecosystem into `extra_indexes:` (link `config.example.yaml`).

- [ ] **Step 6: Full verification + commit**

Run: `make build && make test` (the Task 1 regression test runs under `./internal/config/`).
Expected: green.

```bash
git add helm/shieldoo-gate/values.yaml helm/shieldoo-gate/templates/configmap.yaml docs/
git commit -m "config(helm): restructure chart upstreams to default: form + render-verify"
```

---

## Phase 4b done-when

- [ ] `TestCommittedConfigs_LoadAndValidate` exists and passes for **all** committed gate configs.
- [ ] `docker/config.yaml`, `examples/deploy/config.yaml`, and `.deploy/config.yaml` all use the `default:` form; load + validate green; **no `extra_indexes` in prod**.
- [ ] Helm `values.yaml` restructured to `default:` form AND `configmap.yaml` renders the structured shape; `helm template` render-verified (or render-verification explicitly reported as pending if `helm` unavailable).
- [ ] No behaviour change anywhere (the `default:` form is functionally identical to the bare string); prod stays a transparent pull-through proxy.
- [ ] Standard (`default:` everywhere, `extra_indexes` opt-in) documented; `.deploy/` remains 1:1 with the repo.
- [ ] `make build && make test` green.
