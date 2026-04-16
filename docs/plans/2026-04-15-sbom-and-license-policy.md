# SBOM Generation + License Policy + Project Registry

> Technická analýza featury, která přidává: (1) evidenci projektů navázanou na Basic auth username, (2) generování CycloneDX SBOM pro každý scan, (3) vynucování licenční politiky per-projekt.

**Datum:** 2026-04-15
**Verze:** 1.1 (po cross-check reviews — BA / Dev / Security / Performance)
**Status:** Analýza — ready pro implementaci
**Cílové verze:** Shieldoo Gate v1.2 (Tier 2 features)
**Větev:** `feature/sbom-and-license-policy`

---

## Popis

Shieldoo Gate dnes proxyuje a skenuje artefakty, ale **nerozlišuje kdo si je táhne**. Všechny PAT a všechny scany jsou globální. Rozšíříme systém o:

1. **Project registry** — lehký evidenční model projektů (nová tabulka `projects`), identifikace přes Basic auth username (které se dnes ignoruje). `Lazy-create` mód: nový label = automaticky založený projekt.
2. **SBOM generation** — Trivy se pustí v `cyclonedx-json` módu (single-run s `--scanners vuln`), output se uloží **asynchronně** přes existující blob storage backendy. Expose přes `GET /api/v1/artifacts/{id}/sbom`.
3. **License Policy** — policy engine dostane nový vyhodnocovací krok (**po allowlist**, před aggregation), který čte licence ze SBOMu a blokuje/varuje podle globální + per-project konfigurace. **Per-project override je povolený pouze v `strict` módu** (ochrana proti label spoofing — viz S-01).

### Proč

- **Legal compliance** — GPL/AGPL v komerčních projektech tvoří právní riziko; některé organizace potřebují tvrdý gate.
- **EU CRA / EO 14028 / SOC2** — SBOM je stále častěji regulační požadavek, ne "nice to have".
- **Multi-team viditelnost** — admin UI dnes neví, které projekty si co tahají. Jednoduchý label v Basic auth username tuto mezeru zaplní bez friction.
- **Unlocks další feature** — Dependency Graph, Compliance Reporting, Per-project alerting postaveno nad tímto základem.

### Historie revizí

- **v1.0 (initial)** — první draft analýzy
- **v1.1 (po cross-check)** — zapracovány připomínky 4 reviewerů:
  - **CRITICAL fix**: per-project license policy override zakázán v lazy módu (S-01 security bypass)
  - **CRITICAL fix**: `artifact_id TEXT`, ne INTEGER (schéma parity)
  - **CRITICAL fix**: project propagován **přes context**, signature engine.Evaluate se nemění
  - **CRITICAL fix**: Trivy **single-run** (--format cyclonedx --scanners vuln), přepsaný parser
  - **HIGH fix**: hard cap projektů + rate-limit per PAT hash (ne per IP)
  - **HIGH fix**: `policy.licenses.on_sbom_error` konfigurovatelný (default `allow`)
  - **HIGH fix**: LRU cache + usage debounce **mandatory** (ne optional)
  - **HIGH fix**: SBOM blob write **async** post-response
  - **MEDIUM fix**: PolicyResult.Warnings, migration numbering, SBOM path sanitization, case normalization, Docker auth, dual-license AND/WITH rules

---

## Aktuální stav

### Autentikace (proxy)

- `APIKeyMiddleware` v [internal/auth/apikey.go:45-87](../../internal/auth/apikey.go#L45-L87) čte `Basic Auth`, ignoruje username, validuje password proti global tokenu nebo PAT hashem.
- V **global token** cestě (řádky 56-64) se username uloží do `UserInfo.Email`.
- V **PAT** cestě (řádky 80-83) se `UserInfo.Email` nastavuje na `key.OwnerEmail` — **Basic auth username se zahazuje**. Pro project identification si ho musíme v `Authenticate()` vytáhnout samostatně.

### Perzistence

- Artefakty a scan výsledky jsou **globální** — žádný `project_id`, `tenant_id`, `owner_email` filter.
- `api_keys` má `owner_email`, ale není to scope — PAT může autentizovat kohokoli.
- Policy overrides ([002_policy_overrides.sql](../../internal/config/migrations/sqlite/002_policy_overrides.sql)) jsou globální s `scope: version|package`.
- Audit log má `user_email`, ale ne projekt ([007_audit_user_email.sql](../../internal/config/migrations/sqlite/007_audit_user_email.sql)).
- **`artifacts.id` je `TEXT PRIMARY KEY`** (ne INTEGER) — viz [001_init.sql](../../internal/config/migrations/sqlite/001_init.sql). Všechny FK v systému (`scan_results.artifact_id`, `audit_log.artifact_id`, `docker_tags.artifact_id`) jsou `TEXT`. Nové migrace MUSÍ dodržet tento typ.
- Migrace jsou SQL soubory v `internal/config/migrations/sqlite/NNN_*.sql` a `internal/config/migrations/postgres/NNN_*.sql`. Aktuálně po `017_package_reputation.sql`.

### Skenery + SBOM

- Trivy je integrovaný ([internal/scanner/trivy/trivy.go](../../internal/scanner/trivy/trivy.go)) pouze pro vulnerability scanning (`--format json`). Žádný SBOM export, žádné license parsování.
- Scanner interface v [internal/scanner/interface.go](../../internal/scanner/interface.go) vrací `ScanResult{Verdict, Findings...}` — žádné místo pro SBOM blob.
- **Blob storage backendy** existují v [internal/cache/](../../internal/cache/): `local`, `s3`, `azure_blob`, `gcs`. ALE `CacheStore` interface je artifact-oriented (`Put(ctx, scanner.Artifact, localPath)`), **nemá** generic `PutRaw(ctx, path, data)` metodu. SBOM storage tedy **nemůže jen reusovat `CacheStore`** — potřebuje buď: (a) rozšíření interface o `PutRaw/GetRaw`, nebo (b) vlastní `sbom.Storage` s přímým napojením na backendy (SDK klienti).

### Policy engine

- [internal/policy/engine.go:161-200](../../internal/policy/engine.go#L161-L200) vyhodnocuje takto: DB override → static allowlist → aggregate findings → mode-based decision.
- Engine dostává `EngineConfig` ([engine.go:16-24](../../internal/policy/engine.go#L16-L24)) a signatura `Evaluate()` je `(ctx, artifact, scanResults)`.
- **Project se do engine dostane přes `ctx`** — v `Evaluate` voláme `project.FromContext(ctx)`. Tím se **nemění** signatura a **adaptery zůstávají beze změn**.
- `PolicyResult` dnes má jen `Action` a `Reason` — přidáme `Warnings []string` pro soft výstupy (license warn, SBOM chybí atd.).

### Scanner engine + concurrency

- [internal/scanner/engine.go:38-106](../../internal/scanner/engine.go#L38-L106) `ScanAll` drží **globální semafor** per scan call. Scanner `Scan()` běží uvnitř semaforu.
- To znamená: pokud Trivy wrapper uvnitř `Scan()` spustí **dva subprocesy sekvenčně/paralelně**, drží semafor celou dobu.
- Trivy navíc používá file lock na `--cache-dir`, takže dva paralelní Trivy subprocesy s týmž cache se stejně serializují.
- **Důsledek:** dual-run Trivy = scan throughput klesne ~50%. Musíme použít **single-run** `trivy --format cyclonedx --scanners vuln`.

### E2E testy

- Makefile target `test-e2e-containerized` spouští **3 běhy** (strict SQLite/local, balanced PostgreSQL/S3, permissive Azure Blob) — [Makefile](../../Makefile).
- Shell testy v `tests/e2e-shell/test_*.sh`, helpery v `helpers.sh`, docker-compose v `docker-compose.e2e.yml`.
- Struktura: každý ekosystém má vlastní skript, `run_all.sh` je agregátor.
- Playwright zatím **neexistuje** — UI features se netestují automaticky (pro tuto featuru UI testy **nejsou** požadované — validace přes API v shell testech).

### Srovnávací tabulka

| Aspekt | Současný stav | Navrhovaný stav |
|--------|---------------|-----------------|
| Projekty v DB | neexistuje | tabulka `projects`, lazy-create + hard cap + rate limit per PAT |
| Basic auth username | ignorováno | = `project.label` (+ fallback `default`, lowercase normalizace) |
| SBOM | negeneruje se | CycloneDX-JSON z Trivy single-run, blob storage **async**, pre-extracted licenses |
| License detection | žádné | ze SBOMu, inline SPDX normalizace + alias map |
| License policy | žádné | globální config (+ per-project override **jen v strict módu**) |
| API pro SBOM | žádné | `GET /api/v1/artifacts/{id}/sbom` (cyclonedx-json), `GET .../licenses` |
| Audit log | bez projektu | `ALTER TABLE ADD COLUMN project_id INTEGER NULL` (append-only invariant dodržen) |
| E2E test | bez license/SBOM scénářů | `test_projects.sh`, `test_sbom.sh`, `test_license_policy.sh` |
| fail-open behavior | — | `policy.licenses.on_sbom_error: allow|warn|block` (default `allow`) |

---

## Návrh řešení

### Architektura

```
                    ┌───────────────────────────────────────────┐
                    │  Proxy Request (pip/npm/docker/...)       │
                    │  Authorization: Basic base64(project:pat) │
                    └──────────────────┬────────────────────────┘
                                       │
                                       ▼
              ┌─────────────────────────────────────────────────┐
              │ APIKeyMiddleware                                │
              │ 1. validate PAT (SHA-256 lookup)                │
              │ 2. extract Basic auth username (not key.Owner!) │
              │ 3. lowercase + regex validate → label           │
              │ 4. rate-limit check per PAT hash (new projects) │
              │ 5. project.Service.Resolve(label)               │
              │    ├─ LRU cache hit → return                    │
              │    ├─ SELECT (read-only, no write lock)         │
              │    └─ INSERT OR IGNORE + SELECT (rare path)     │
              │ 6. ContextWithProject(ctx, project)             │
              └──────────────────┬──────────────────────────────┘
                                 │
                                 ▼
              ┌─────────────────────────────────────────────────┐
              │ Adapter (pypi/npm/docker/...)                   │
              │ - fetch artifact from upstream                  │
              │ - run scan pipeline (policy, SBOM gen inline)   │
              │ - usage upsert (debounced to sync.Map)          │
              │ - SBOM blob write → TriggerAsyncSBOMWrite(...)  │
              │ - serve                                         │
              └──────────────────┬──────────────────────────────┘
                                 │
                                 ▼
              ┌─────────────────────────────────────────────────┐
              │ Scanner Engine — ScanAll (semaphore-guarded)    │
              │ - Trivy single-run: --format cyclonedx          │
              │   --scanners vuln → ScanResult.SBOMPath         │
              │ - CycloneDX parser extracts:                    │
              │     · vulnerabilities → Findings                │
              │     · licenses → for pre-extraction             │
              └──────────────────┬──────────────────────────────┘
                                 │
                                 ▼
              ┌─────────────────────────────────────────────────┐
              │ Policy Engine — Evaluate(ctx, artifact, results)│
              │ project = project.FromContext(ctx)              │
              │ 1. DB override                                  │
              │ 2. Allowlist                                    │
              │ 3. ★ License rules (NEW)                        │
              │    LicenseEvaluator.Evaluate(project, licenses) │
              │    → block | warn | allow                       │
              │    (fail-open per config on_sbom_error)         │
              │ 4. Aggregate findings → verdict                 │
              │ 5. Mode-based decision                          │
              │ Result: {Action, Reason, Warnings[]}            │
              └──────────────────┬──────────────────────────────┘
                                 │
                                 ▼
              ┌─────────────────────────────────────────────────┐
              │ Audit Log (project_id, license events)          │
              │ Background: SBOM blob write, usage flush (30s)  │
              └─────────────────────────────────────────────────┘
```

### Databázové změny

> **Poznámka k numberingu:** migrace jsou očíslované podle **fáze**, v níž se merge-nou. Fáze 1: 018, 019, 020. Fáze 2: 021, 022. Fáze 3: 023.

#### Migrace `018_projects.sql` (Fáze 1)

| Sloupec | Typ | Popis |
|---------|-----|-------|
| `id` | INTEGER PK | autoincrement |
| `label` | TEXT UNIQUE NOT NULL | identifikátor z Basic auth username (lowercased, regex `^[a-z0-9][a-z0-9_-]{0,63}$`) |
| `display_name` | TEXT | volitelný human-readable název (default = label) |
| `description` | TEXT | volitelný popis |
| `created_at` | TIMESTAMP NOT NULL | |
| `created_via` | TEXT NOT NULL | `lazy` / `api` / `seed` (telemetrie) |
| `enabled` | INTEGER NOT NULL DEFAULT 1 | soft disable (future: blokace requestů; v1.2 = metadata-only) |

Index: `CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_label ON projects(label);`

Seed row: `INSERT INTO projects(label, display_name, created_via, created_at) VALUES ('default', 'Default Project', 'seed', CURRENT_TIMESTAMP);`

**Poznámka:** `enabled=0` v **v1.2 je pouze metadata** — neblokuje requesty. Endpoint `DELETE /api/v1/projects/{id}` je v API zdokumentovaný jako "soft-disable (metadata flag)" s poznámkou "runtime enforcement v1.3+".

#### Migrace `019_audit_project_id.sql` (Fáze 1)

```sql
-- MUSÍ použít pouze ALTER TABLE ADD COLUMN — NE table recreation (invariant #5 — audit log append-only).
ALTER TABLE audit_log ADD COLUMN project_id INTEGER REFERENCES projects(id);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, created_at);
```

Nullable sloupec → starší řádky fungují beze změny. Žádný backfill.

#### Migrace `020_artifact_project_usage.sql` (Fáze 1)

Evidujeme kdo si co tahal — denormalizace pro rychlé per-project reporty.

| Sloupec | Typ | Popis |
|---------|-----|-------|
| `artifact_id` | **TEXT** NOT NULL REFERENCES artifacts(id) | *(TEXT ne INTEGER — schéma parity)* |
| `project_id` | INTEGER NOT NULL REFERENCES projects(id) | |
| `first_used_at` | TIMESTAMP NOT NULL | |
| `last_used_at` | TIMESTAMP NOT NULL | |
| `use_count` | INTEGER NOT NULL DEFAULT 1 | |

PK: `(artifact_id, project_id)` composite.
Index: `(project_id, last_used_at DESC)` pro UI listing.

Upsert SQL (debounced batch flush každých 30s):
```sql
INSERT INTO artifact_project_usage(artifact_id, project_id, first_used_at, last_used_at, use_count)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(artifact_id, project_id)
DO UPDATE SET last_used_at = excluded.last_used_at,
              use_count = use_count + excluded.use_count;
```

#### Migrace `021_sbom_metadata.sql` (Fáze 2)

SBOM samotný je v blob storage, v DB pouze metadata.

| Sloupec | Typ | Popis |
|---------|-----|-------|
| `artifact_id` | **TEXT** PK REFERENCES artifacts(id) | 1:1 s artefaktem *(TEXT ne INTEGER)* |
| `format` | TEXT NOT NULL | `cyclonedx-1.5` |
| `blob_path` | TEXT NOT NULL | `sbom/{sha256_prefix}/{artifact_id}.cdx.json` v blob storage |
| `size_bytes` | INTEGER NOT NULL | |
| `component_count` | INTEGER NOT NULL | pro rychlý přehled |
| `licenses_json` | TEXT | pre-extracted JSON pole SPDX id (pro rychlé filtrování UI + license eval) |
| `generated_at` | TIMESTAMP NOT NULL | |
| `generator` | TEXT NOT NULL | `trivy-0.50.0` / atd. |

Separátní tabulka (ne sloupce na `artifacts`) — důvod: SBOM je volitelná feature (může být `sbom.enabled: false`), a `artifacts` tabulka se nemusí načítat s SBOM payloadem pro non-SBOM dotazy.

#### Migrace `022_project_license_policy.sql` (Fáze 3)

| Sloupec | Typ | Popis |
|---------|-----|-------|
| `id` | INTEGER PK | |
| `project_id` | INTEGER NOT NULL REFERENCES projects(id) UNIQUE | jeden policy záznam per projekt |
| `mode` | TEXT NOT NULL | `inherit` / `override` / `disabled` |
| `blocked_json` | TEXT | JSON pole SPDX id, NULL = inherit |
| `warned_json` | TEXT | JSON pole SPDX id, NULL = inherit |
| `allowed_json` | TEXT | JSON pole SPDX id, NULL = inherit (pokud set → whitelist mode) |
| `unknown_action` | TEXT | `block` / `warn` / `allow` / NULL = inherit |
| `updated_at` | TIMESTAMP NOT NULL | |
| `updated_by` | TEXT | email admina |

**Runtime enforcement:** `mode=override` se aplikuje **POUZE** pokud je `projects.mode: strict` v configu. V `lazy` módu engine ignoruje DB override a aplikuje jen globální policy (security fix S-01).

### Změny v servisní vrstvě

#### Nový balíček `internal/project/`

```go
// internal/project/service.go
type Service interface {
    // Resolve translates a Basic auth username into a Project. Implements LRU cache + read-before-write.
    Resolve(ctx context.Context, label string, patHash string) (*Project, error)

    // GetByID / GetByLabel / List — admin API
    GetByID(id int64) (*Project, error)
    GetByLabel(label string) (*Project, error)
    List() ([]*Project, error)

    // CreateExplicit — admin API (for strict mode pre-provisioning)
    CreateExplicit(label, displayName, description string, actor string) (*Project, error)

    // Update / Disable — admin API
    Update(id int64, patch ProjectPatch) error
    Disable(id int64) error

    // InvalidateCache is called after Update/Disable to clear LRU.
    InvalidateCache(label string)
}

type Project struct {
    ID          int64
    Label       string
    DisplayName string
    Description string
    Enabled     bool
    CreatedAt   time.Time
    CreatedVia  string
}
```

**Implementační detaily pro `Resolve` (hot path):**

1. **Lowercase + regex validace** — `MyApp` → `myapp`, ostatní → `labelInvalid` chyba (400).
2. **LRU cache check** — `lru.TwoQueueCache[string, *Project]` (hashicorp/golang-lru), size 512, TTL 5min. Cache hit → return.
3. **SELECT** (read-only) — lehký `SELECT * FROM projects WHERE label = ?`, žádný write lock. Existuje → cache it + return.
4. **Strict mode check** — pokud `config.Projects.Mode == "strict"` a SELECT vrátil 0 řádků → return `ErrProjectNotFound` (middleware zamítne 403).
5. **Lazy-create cesta** (jen v `lazy` módu):
   - Rate limit per `patHash` (`golang.org/x/time/rate`, bucket 10 nových projektů / hour / PAT)
   - Hard cap check: `SELECT COUNT(*) FROM projects` < `config.Projects.MaxCount` (default 1000)
   - `INSERT OR IGNORE` + následný `SELECT` (INSERT OR IGNORE je idempotentní, nezpůsobí error pokud už existuje — race-safe).
   - Cache + return.

**Thread safety:** `INSERT OR IGNORE` + `SELECT` je atomický díky UNIQUE constraintu. LRU cache je thread-safe (hashicorp lib).

**Rate limit storage:** `sync.Map[patHash]*rate.Limiter` — v paměti. Server restart = reset (akceptovatelné, nepřetrvávající riziko).

```go
// internal/project/context.go
type projectCtxKey struct{}

func ContextWithProject(ctx context.Context, p *Project) context.Context { ... }
func FromContext(ctx context.Context) *Project { /* returns nil if missing */ }
```

#### Úpravy `internal/auth/apikey.go`

- Přidat dependency `projectSvc project.Service` do `APIKeyMiddleware`.
- V `Authenticate` — **po** úspěšném PAT/global token checku:
  - Extrahovat **Basic auth username** (`user, _, _ := r.BasicAuth()`) — **NE** `key.OwnerEmail`.
  - Pokud prázdný → label = `config.Projects.DefaultLabel` (default `"default"`).
  - `project, err := projectSvc.Resolve(ctx, username, patHash)` → chyba → 400 (invalid label) nebo 403 (strict mode).
  - `ctx = project.ContextWithProject(ctx, project)`.
  - Pokračuj další middleware.
- **Rate limit key** = `patHash` pro PAT auth, `"global-token"` pro global token (sdílený bucket).

#### Rozšíření `internal/scanner/interface.go`

```go
type ScanResult struct {
    // ... existing fields
    SBOMPath   string // absolute path k dočasnému SBOM souboru (Trivy single-run output)
    SBOMFormat string // "cyclonedx-1.5" nebo prázdné
    Licenses   []string // pre-extracted canonical SPDX ids (duplicity už removed)
}
```

Struct extension — non-breaking change. Ostatní scannery (GuardDog, OSV, reputation) nechávají pole prázdná.

#### Úpravy `internal/scanner/trivy/trivy.go`

- Přidat flag `generateSBOM bool` do `TrivyScanner` (config driven, default `true`).
- `Scan()` spustí Trivy **jednou** s:
  - `trivy fs|image --format cyclonedx --scanners vuln,license --output {tmpfile} --cache-dir {cache} --quiet`
  - `--scanners vuln,license` zajistí že CycloneDX obsahuje i vulnerability data i license info.
- **Přepsat parser** — nový `parseCycloneDX(data []byte) (ScanResult, error)`:
  - Extrahuje vulnerabilities ze sekce `vulnerabilities[]` → `Findings`.
  - Extrahuje licence z `components[].licenses[].license.{id,name,expression}` → `Licenses` (přes `spdx.Normalize`).
  - Starý `parseOutput` smazat (cleanup commit před strukturálními změnami, viz verifikační disciplína v CLAUDE.md).
- Pokud `generateSBOM=false` → použít starý Trivy native JSON format (fallback pro disabled SBOM).

#### Nový balíček `internal/sbom/`

```go
// internal/sbom/storage.go
type Storage interface {
    // Write ukládá blob + metadata. Volán ASYNCHRONNĚ z adapteru (nevolá se v request path).
    Write(ctx context.Context, artifactID string, sbom []byte, format string, licenses []string) error

    // Read — pro API /sbom endpoint
    Read(ctx context.Context, artifactID string) ([]byte, string, error)

    // Delete — pro rescan / TTL purge
    Delete(ctx context.Context, artifactID string) error

    // Metadata-only (pro license evaluator — fast path, bez blob load)
    GetMetadata(artifactID string) (*Metadata, error)
}

type Metadata struct {
    ArtifactID    string
    Format        string
    BlobPath      string
    SizeBytes     int64
    Components    int
    Licenses      []string // pre-extracted SPDX ids
    GeneratedAt   time.Time
    Generator     string
}
```

**Storage backend wiring** (oprava Dev reviewu — NENÍ "cache bez změn"):

Možnost A (preferována): **Rozšířit `cache.CacheStore` o generic blob metody:**
```go
type BlobStore interface {  // nový sub-interface
    PutBlob(ctx context.Context, path string, data []byte) error
    GetBlob(ctx context.Context, path string) ([]byte, error)
    DeleteBlob(ctx context.Context, path string) error
}

// Každý backend (local, s3, azure_blob, gcs) implementuje BlobStore i CacheStore.
```

Možnost B (fallback): **Vlastní blob wrapper v `sbom/storage_backend.go`** — pokud rozšíření CacheStore způsobí příliš mnoho změn.

**POC rozhodnutí:** Začít s A. Pokud implementace ukáže že CacheStore interface je příliš "artifact-shaped" → fallback na B.

**Path sanitization:** Před `Write` projít SBOM JSON a nahradit absolute cache paths relativními:
- Před: `/var/cache/shieldoo-gate/pypi/requests-2.31.0.whl`
- Po: `pypi/requests-2.31.0.whl`

Implementováno jako `sanitizeCycloneDX(raw []byte, cachePrefix string) []byte` — string replace `cachePrefix` → `""`.

**Async write wiring:** V adapteru — po úspěšném policy pass + response flush, spustit `go sbomStorage.Write(...)` (podobně jako existující `TriggerAsyncScan`). Error logovat, nezasahovat do request.

#### Nový balíček `internal/license/`

```go
// internal/license/evaluator.go
type Evaluator interface {
    Evaluate(ctx context.Context, project *project.Project, licenses []string) Decision
}

type Decision struct {
    Action         string // "allow" | "warn" | "block"
    Reason         string
    MatchedLicense string
    Rule           string // "blocked" | "not-in-allowlist" | "unknown" | "inherit-global"
}

// internal/license/resolver.go — resolve policy
// 1. If config.Projects.Mode == "lazy" → vždy použít globální policy (S-01 fix)
// 2. If config.Projects.Mode == "strict":
//    - Load project_license_policy for project.ID
//    - If mode=override → use per-project, else global
```

**Resolve order v `strict` módu:**
1. Per-project `override` (pokud set) > inherit > globální config
2. Per-project `inherit` → fallback na globální
3. Per-project `disabled` → skip license check pro tento projekt

**SPDX normalizace (`internal/license/spdx.go`):**
- Statická mapa aliasů (rozšířený seznam oproti v1.0 — zapracování S-07):
  - `GPL-3.0` → `GPL-3.0-only` (deprecated SPDX id → current)
  - `Apache 2`, `Apache License 2.0`, `Apache-2` → `Apache-2.0`
  - `MIT License` → `MIT`
  - `GNU General Public License v3` → `GPL-3.0-only`
  - ~50 dalších nejčastějších non-standard stringů (ze SPDX license-list-data JSON)
- Compile-time generated z downloaded SPDX list (`go generate`), kontrolováno do repa.

**Dual-license handling (`internal/license/expression.go`):**
- Parser pro SPDX License Expressions ([spec](https://spdx.dev/learn/handling-license-info/)):
  - `OR`: default = `any_allowed` (aspoň jedna licence v OR musí projít). Configurable: `all_allowed` (každá musí projít).
  - `AND`: všechny musí být individually allowed — jinak block (konjunkce = musím splnit obě).
  - `WITH`: exception modifier (`Apache-2.0 WITH LLVM-exception`) — **pro v1.2**: ignorujeme exception, vyhodnocujeme jen base license. Dokumentováno jako known limitation.
  - Závorky: `(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)` — rekurzivní parser.
- Pokud expression nelze parsovat → `unknown_action`.

**Config:**
```yaml
policy:
  licenses:
    enabled: true
    blocked: []
    warned: []
    allowed: []
    unknown_action: allow    # allow | warn | block
    on_sbom_error: allow     # allow | warn | block — co dělat pokud SBOM chybí
    or_semantics: any_allowed  # any_allowed | all_allowed
```

#### Integrace do `internal/policy/engine.go`

- **Signatura `Evaluate()` se NEMĚNÍ** — project se extrahuje z `ctx` uvnitř engine.
- Nový `EngineOption`: `WithLicenseEvaluator(le license.Evaluator, sbomStore sbom.Storage)`.
- `PolicyResult` dostane nové pole: `Warnings []string` (neblocking upozornění).
- V `Evaluate()` (řádek 161-200) **mezi** allowlist check (řádek 173) a findings aggregation (řádek 180):
  1. `proj := project.FromContext(ctx)` — pokud nil → skip license check, log warning.
  2. `meta, err := sbomStore.GetMetadata(artifact.ID)` — rychlý DB hit na `sbom_metadata` (bez blob load).
  3. Pokud `meta == nil` (SBOM neexistuje) nebo `err != nil`:
     - `on_sbom_error: allow` → skip + `Warnings = append("license: SBOM unavailable")`
     - `on_sbom_error: warn` → totéž, ale audit event `LICENSE_CHECK_SKIPPED`
     - `on_sbom_error: block` → `PolicyResult{Action: Block, Reason: "license: SBOM required but unavailable"}`
  4. `decision := licenseEval.Evaluate(ctx, proj, meta.Licenses)`:
     - `block` → return `PolicyResult{Block, Reason: "license: {license} blocked by {global|project-X}"}`, audit `LICENSE_BLOCKED`
     - `warn` → `Warnings = append(...)`, audit `LICENSE_WARNED`, continue
     - `allow` → continue
- **License evaluation je AFTER allowlist** (oprava BA contradiction) — allowlisted packages skip license check.

**Cache hit vs. re-evaluation:** License check probíhá **při scanu** (tedy při cache miss). Pro cached artifact se policy re-evaluate **neprovádí** (existující behavior). Retroaktivní vynucení nové policy → admin musí spustit rescan přes rescan scheduler. **Dokumentováno** jako known limitation v `docs/features/license-policy.md`.

### Změny v UI

- **Nová stránka `/projects`** — list projektů (label, display_name, created_via, last activity, počet artefaktů přes JOIN na `artifact_project_usage`).
- **Detail projektu** — per-project artifact list, license policy editor (enabled pouze v strict módu, v lazy módu UI zobrazí "Per-project override requires strict mode").
- **License policy editor** — UI pro `blocked / warned / allowed / unknown_action` s autocomplete SPDX ID.
- **Artifact detail** — nová sekce "SBOM": komponenty, licence, download link (`cyclonedx-json`).

### Konfigurace

Přidat do `config.example.yaml`:

```yaml
projects:
  mode: lazy              # lazy | strict
  default_label: default  # fallback pro prázdný username
  label_regex: "^[a-z0-9][a-z0-9_-]{0,63}$"
  max_count: 1000         # hard cap (0 = unlimited)
  lazy_create_rate: 10    # nové projekty / hour / PAT
  cache_size: 512         # LRU cache size
  cache_ttl: 5m

sbom:
  enabled: true
  format: cyclonedx-json
  async_write: true       # nebloku request na blob storage write
  ttl: 30d                # retence (mazáno s artefaktem nebo standalone cleanup)

policy:
  licenses:
    enabled: true
    blocked: []           # příklad: ["GPL-3.0-only", "AGPL-3.0-only"]
    warned: []
    allowed: []           # pokud neprázdné → whitelist mode
    unknown_action: allow # allow | warn | block
    on_sbom_error: allow  # allow | warn | block
    or_semantics: any_allowed  # any_allowed | all_allowed
```

### API endpointy

Všechny project/SBOM/license endpointy vyžadují OIDC auth (admin API, ne proxy Basic auth).

| Metoda | Cesta | Popis |
|--------|-------|-------|
| GET | `/api/v1/projects` | list projektů |
| POST | `/api/v1/projects` | explicitní create (pro strict mode) |
| GET | `/api/v1/projects/{id}` | detail + statistiky |
| PATCH | `/api/v1/projects/{id}` | update display_name, description, enabled |
| DELETE | `/api/v1/projects/{id}` | soft-disable (metadata only v1.2) |
| GET | `/api/v1/projects/{id}/license-policy` | efektivní policy (inherit + override) |
| PUT | `/api/v1/projects/{id}/license-policy` | upsert override (**403 pokud `projects.mode != strict`**) |
| GET | `/api/v1/projects/{id}/artifacts` | artefakty použité projektem (přes `artifact_project_usage`) |
| GET | `/api/v1/artifacts/{id}/sbom` | SBOM blob (content-type `application/vnd.cyclonedx+json`) |
| GET | `/api/v1/artifacts/{id}/licenses` | pre-extracted JSON pole SPDX id |

### Proxy error responses

**Pro license-blocked (403) response:**
```json
{
  "error": "license_blocked",
  "message": "Package my-pkg (1.0.0) contains license 'GPL-3.0-only' which is blocked by global policy. Contact your admin.",
  "license": "GPL-3.0-only",
  "project": "webapp",
  "policy_source": "global"
}
```
+ header `X-Shieldoo-Reason: license:GPL-3.0-only blocked by global policy`.

Pip zobrazí `message` ve stderr, Docker / npm mají odlišné chování — header je fallback.

### Docker registry auth compatibility

Docker registry v2 má vlastní token flow přes `/v2/token`. Musíme ověřit ve Fázi 1 POC že:
1. Docker klient v prvním requestu na `/v2/` pošle `Authorization: Basic base64(project:pat)`.
2. Middleware ten username extrahuje → project label.
3. Následné token-exchange requesty (pokud adaptér má vlastní token flow) musí ten project label zachovat.

**Akceptanční kritérium Fáze 1:** E2E test `test_docker.sh` funguje s Basic auth username → projekt se objeví v DB.

---

## Dotčené soubory

### Nové soubory

- `internal/config/migrations/sqlite/018_projects.sql`
- `internal/config/migrations/sqlite/019_audit_project_id.sql`
- `internal/config/migrations/sqlite/020_artifact_project_usage.sql`
- `internal/config/migrations/sqlite/021_sbom_metadata.sql`
- `internal/config/migrations/sqlite/022_project_license_policy.sql`
- `internal/config/migrations/postgres/018_*.sql` — `022_*.sql` — mirror (ANSI SQL)
- `internal/project/service.go` + `service_test.go`
- `internal/project/context.go`
- `internal/project/cache.go` (LRU + rate-limit wrapper)
- `internal/sbom/storage.go` + `storage_test.go`
- `internal/sbom/parser.go` (CycloneDX → ScanResult.Findings/Licenses)
- `internal/sbom/sanitize.go` + test
- `internal/cache/blob.go` (nový `BlobStore` sub-interface + wiring do existujících backendů)
- `internal/license/evaluator.go` + `evaluator_test.go`
- `internal/license/expression.go` + test (SPDX expression parser s OR/AND/WITH)
- `internal/license/spdx.go` + `spdx_data.go` (go-generated alias map)
- `internal/api/projects.go` (REST handlery)
- `internal/api/sbom.go`
- `internal/api/licenses.go` (per-artifact licenses endpoint)
- `ui/src/views/Projects.tsx`, `ui/src/views/ProjectDetail.tsx`, `ui/src/views/LicensePolicyEditor.tsx`
- `tests/e2e-shell/test_projects.sh` (lazy create + strict mode + hard cap + rate limit)
- `tests/e2e-shell/test_sbom.sh` (download + validace CycloneDX + path sanitization)
- `tests/e2e-shell/test_license_policy.sh` (block/warn/allow scénáře, per-project override jen v strict)
- `tests/e2e-shell/fixtures/packages/` — fixture PyPI balíček s GPL licencí pro deterministický test
- `docs/features/projects.md`
- `docs/adr/ADR-018-project-identification-via-basic-auth.md`
- `docs/adr/ADR-019-sbom-storage-backend-wiring.md`

### Upravené soubory

- [internal/auth/apikey.go:20-87](../../internal/auth/apikey.go#L20-L87) — inject `project.Service`, extrakce Basic auth username → Resolve → Context
- [internal/scanner/interface.go](../../internal/scanner/interface.go) — přidat `SBOMPath`, `SBOMFormat`, `Licenses` do `ScanResult`
- [internal/scanner/trivy/trivy.go:33-82](../../internal/scanner/trivy/trivy.go#L33-L82) — single-run `--format cyclonedx --scanners vuln,license`, nový parser
- [internal/scanner/trivy/trivy.go:96-147](../../internal/scanner/trivy/trivy.go#L96-L147) — smazat `parseOutput` native JSON parser, nahradit `parseCycloneDX`
- [internal/policy/engine.go:161-200](../../internal/policy/engine.go#L161-L200) — nový krok license evaluation mezi allowlist a aggregation
- [internal/policy/engine.go:71-84](../../internal/policy/engine.go#L71-L84) — nové `EngineOption` pro license evaluator + sbom store
- [internal/policy/rules.go](../../internal/policy/rules.go) — přidat `Warnings []string` do `PolicyResult`
- [internal/config/config.go:13-28](../../internal/config/config.go#L13-L28) — rozšířit o `Projects`, `SBOM`, `Policy.Licenses`
- [config.example.yaml](../../config.example.yaml) — dokumentovat nové sekce
- [internal/api/](../../internal/api/) — router: registrace nových endpointů
- [internal/cache/interface.go](../../internal/cache/interface.go) — přidat `BlobStore` sub-interface
- [internal/cache/local/local.go](../../internal/cache/local/local.go), `s3/`, `azure_blob/`, `gcs/` — implementovat `BlobStore` na každém backendu
- [docs/api/openapi.yaml](../../docs/api/openapi.yaml) — Project, LicensePolicy, SBOM schémata
- [docs/features/index.md:80-87](../../docs/features/index.md#L80-L87) — status SBOM + License Policy → **Implemented**
- [docs/features/sbom-generation.md](../../docs/features/sbom-generation.md), [docs/features/license-policy.md](../../docs/features/license-policy.md) — status + implementační detaily
- [docs/index.md](../../docs/index.md) — link na `features/projects.md`
- [Makefile](../../Makefile) — `test-e2e-containerized` automaticky zahrne nové testy (via `run_all.sh`)
- [tests/e2e-shell/run_all.sh](../../tests/e2e-shell/run_all.sh) — přidat `test_projects.sh`, `test_sbom.sh`, `test_license_policy.sh`
- [tests/e2e-shell/config.e2e.yaml](../../tests/e2e-shell/config.e2e.yaml) — `sbom.enabled: true`, `policy.licenses.enabled: true`
- [tests/e2e-shell/helpers.sh](../../tests/e2e-shell/helpers.sh) — nové helpery `create_project`, `set_license_policy`, `fetch_sbom`, `assert_audit_event_type`

### Soubory BEZ změn (důležité)

- [internal/adapter/](../../internal/adapter/) — adaptery jsou project-unaware; project se extrahuje v middleware a projde contextem. `Evaluate()` signatura se nemění.
- [internal/auth/handlers.go](../../internal/auth/handlers.go) — OIDC flow se netýká; projects souvisí jen s proxy Basic auth
- [scanner-bridge/](../../scanner-bridge/) — GuardDog nevrací licence, zůstává beze změn
- [internal/threatfeed/](../../internal/threatfeed/) — nesouvisí
- [internal/scanner/guarddog/](../../internal/scanner/guarddog/), [osv/](../../internal/scanner/osv/), [reputation/](../../internal/scanner/reputation/), [versiondiff/](../../internal/scanner/versiondiff/) — žádný z nich negeneruje SBOM, beze změn
- [internal/scanner/engine.go](../../internal/scanner/engine.go) — semafor + parallelism nezměněn (single-run Trivy nepřidá čas na semaforu)

---

## Implementační fáze

### Fáze 1: Project Registry + Auth integrace

**Cíl:** Projekty v DB, Basic auth username → project v contextu, API pro management, hard cap + rate limit.

**Rozsah:**
- Migrace `018_projects.sql`, `019_audit_project_id.sql`, `020_artifact_project_usage.sql` (SQLite + PostgreSQL mirror)
- Balíček `internal/project/` — Service + LRU cache + rate limiter
- `APIKeyMiddleware` injekce project.Service + extrakce Basic auth username (NE OwnerEmail)
- Audit log — zapisovat `project_id` pokud je v contextu
- `artifact_project_usage` upsert s **mandatory debounce** (sync.Map + 30s flush, podobně jako `touchLastUsed`)
- REST API: `/api/v1/projects` CRUD (OIDC-only auth)
- UI: stránka `/projects` s listem + detailem (bez License Policy editoru — ten přijde ve Fázi 3)
- Config `projects.mode: lazy | strict`, `max_count`, `lazy_create_rate`, `cache_size`, `cache_ttl`
- Docker adapter auth POC — ověřit že Basic auth username propadne do projektu (acceptance: `test_docker.sh` funguje + projekt se objeví v DB)
- E2E testy:
  - `test_projects.sh` — lazy create flow, strict 403, hard cap 429, rate limit per PAT, audit log check
- Docs: `docs/features/projects.md`, `ADR-018`

**Závislosti:** žádné.

Checklist:
- [ ] Migrace SQLite (018, 019, 020)
- [ ] Migrace PostgreSQL mirror
- [ ] `internal/project/service.go` + LRU cache + rate limiter + testy (concurrent safety test!)
- [ ] `internal/project/context.go`
- [ ] APIKeyMiddleware integrace + test
- [ ] `/api/v1/projects` handlery + OpenAPI
- [ ] `artifact_project_usage` upsert debounce helper
- [ ] Audit log — zapsat project_id
- [ ] UI stránka Projects
- [ ] Config rozšíření (viper + validation)
- [ ] Docker auth POC + `test_docker.sh` nezměněn
- [ ] E2E test `test_projects.sh`
- [ ] Docs: `docs/features/projects.md`, `ADR-018`
- [ ] `make test-e2e-containerized` zelený

### Fáze 2: SBOM Generation

**Cíl:** Trivy single-run generuje CycloneDX SBOM, async write do blob storage, dostupné přes API.

**Rozsah:**
- Migrace `021_sbom_metadata.sql`
- `internal/cache/blob.go` — nový `BlobStore` sub-interface, implementace na `local`, `s3`, `azure_blob`, `gcs`
- Balíček `internal/sbom/` — storage + CycloneDX parser + path sanitization
- `ScanResult` rozšíření (`SBOMPath`, `SBOMFormat`, `Licenses`)
- `TrivyScanner` — single-run `--format cyclonedx --scanners vuln,license`, nový parser, smazaný native JSON parser (cleanup commit napřed — viz CLAUDE.md "Cleanup first")
- Pipeline hook v adapteru: po scan + policy pass → spustit `go sbomStorage.Write(...)` (async, non-blocking)
- API `GET /api/v1/artifacts/{id}/sbom` + `GET /api/v1/artifacts/{id}/licenses`
- UI: sekce SBOM v Artifact Detail (komponenty, licence, download)
- Config `sbom.enabled`, `sbom.format`, `sbom.async_write`, `sbom.ttl`
- E2E test `test_sbom.sh`:
  - Pull PyPI + npm package přes proxy → fetch SBOM → validace CycloneDX schema
  - Assert pre-extracted licenses
  - Path sanitization — grep že SBOM neobsahuje `/var/cache/shieldoo-gate/`
- Docs: `docs/features/sbom-generation.md` update, `ADR-019`

**Závislosti:** žádné (paralelizovatelné s Fází 1, ale Fáze 3 vyžaduje Fázi 2).

Checklist:
- [ ] Migrace `021_sbom_metadata.sql` (SQLite + PG)
- [ ] `internal/cache/blob.go` interface + 4 backend implementace
- [ ] `internal/sbom/parser.go` + testy
- [ ] `internal/sbom/sanitize.go` + testy
- [ ] `internal/sbom/storage.go` + testy
- [ ] Scanner interface rozšíření
- [ ] TrivyScanner single-run cutover (cleanup commit před)
- [ ] Async write hook v adapterech (pypi, npm, docker, nuget, maven, rubygems, gomod)
- [ ] API endpointy + OpenAPI
- [ ] UI: Artifact Detail SBOM section
- [ ] E2E test `test_sbom.sh`
- [ ] Docs update
- [ ] `make test-e2e-containerized` zelený

### Fáze 3: License Policy

**Cíl:** Licenční politika (globální + per-project **jen v strict módu**) blokuje/varuje podle SPDX id ze SBOMu.

**Rozsah:**
- Migrace `022_project_license_policy.sql`
- Balíček `internal/license/` — evaluator + SPDX expression parser + normalizace
- Static SPDX alias data (`go generate` z SPDX license-list-data)
- Policy engine — nový krok `evaluateLicenses` mezi allowlist a aggregation
- `PolicyResult.Warnings` field
- API `/api/v1/projects/{id}/license-policy` GET/PUT (**PUT vrací 403 v lazy módu**)
- UI: License Policy Editor v Project Detail (disabled v lazy módu s tooltipem)
- Config `policy.licenses.*` kompletní
- Audit event typy `LICENSE_BLOCKED`, `LICENSE_WARNED`, `LICENSE_CHECK_SKIPPED`
- E2E test `test_license_policy.sh`:
  - **Lazy mode:**
    - GPL-3.0 package + global blocked → 403, audit `LICENSE_BLOCKED`
    - LGPL-2.1 package + global warned → 200 + warning header + audit `LICENSE_WARNED`
    - MIT package + global allowed whitelist → 200
    - Unknown license + `unknown_action: block` → 403
    - Dual-license `"MIT OR Apache-2.0"` + MIT allowed → 200
    - PUT `/api/v1/projects/X/license-policy` v lazy módu → 403
  - **Strict mode:**
    - Per-project override: project `oss-playground` s allowlist=["GPL-3.0-only"] → GPL projde i když global blocks
    - Unknown project label → 401/403 (už z Fáze 1, ale double-check)
  - **SBOM chybí:**
    - `on_sbom_error: allow` → 200 + warning
    - `on_sbom_error: block` → 403

**Závislosti:** **vyžaduje Fázi 1** (projects + context) + **Fázi 2** (sbom metadata).

Checklist:
- [ ] Migrace `022_project_license_policy.sql`
- [ ] `internal/license/spdx.go` + `spdx_data.go` (go generate)
- [ ] `internal/license/expression.go` (OR/AND/WITH parser) + test
- [ ] `internal/license/evaluator.go` + testy (všechny dual-license scénáře)
- [ ] `PolicyResult.Warnings` v rules.go
- [ ] Policy engine integrace (license step AFTER allowlist)
- [ ] API `/api/v1/projects/{id}/license-policy` (PUT 403 v lazy módu)
- [ ] UI License Policy Editor (disabled v lazy módu)
- [ ] Audit log event typy
- [ ] E2E test `test_license_policy.sh` (všechny scénáře výše)
- [ ] Docs update (license-policy.md, index.md, openapi.yaml)
- [ ] `make test-e2e-containerized` zelený

---

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| **Project label spoofing** (S-01) — útočník použije label permissivního projektu | License policy bypass | ~~Střední~~ **Vysoká** | Per-project override **zakázán v lazy módu** (PUT vrací 403). Globální policy platí pro všechny. Ve strict módu labely vytváří admin, takže spoofing se omezí na existující projekty. v1.3: PAT-to-project binding. |
| Lazy-create DoS (S-02) | Rozrůstání `projects` tabulky | Nízká–Střední | `projects.max_count` hard cap (default 1000) + rate-limit per PAT hash (`lazy_create_rate: 10/hour`). Regex validace labelu. CLI `shieldoo-gate projects prune --no-activity-since=90d`. |
| License fail-open bypass (S-03) | Obejití license policy vypuzením Trivy timeout | Nízká–Střední | Configurable `on_sbom_error: allow|warn|block` (default `allow` pro bezpečné defaults, org může zpřísnit). Audit event `LICENSE_CHECK_SKIPPED`. |
| SBOM single-run nesplní parity s native JSON (P1) | Chybí vulnerability data | Střední | POC ve Fázi 2 — spustit oba formáty proti stejnému fixture, diff findings. Acceptance: všechny existující E2E testy (test_typosquat, test_version_diff, ...) projdou beze změn. Fallback: SBOM async post-scan (mimo semafor). |
| `GetOrCreate` SQLite write-lock contention (P2) | Throughput collapse při concurrent requests | Vysoká (bez mitigace) | **MANDATORY** LRU cache + **SELECT before INSERT OR IGNORE** — write lock jen při prvním výskytu labelu. Test: concurrent 100 req/s s stejným labelem, 0 write lock contention. |
| `artifact_project_usage` upsert hotness (P3) | Write amplifikace na SQLite | Střední | **MANDATORY** debounce přes sync.Map + 30s flush (pattern z `touchLastUsed`). |
| SBOM blob write blocks request (P4) | +50-200ms na cache-miss path | Střední | **MANDATORY** async write v goroutine (pattern `TriggerAsyncScan`). Response serve → blob write v pozadí. Error log-only. |
| SBOM blob bloat (cache narůstá) | Diskové místo | Nízká–Střední | TTL 30d konfigurovatelné. Prometheus metric `sbom_storage_bytes_total`. Dokumentace. |
| SBOM internal path leak (S-04) | Info disclosure o interní infrastruktuře | Nízká | `sanitizeCycloneDX()` před `Write` — strip cache prefix. E2E test assertuje že SBOM neobsahuje `/var/cache/shieldoo-gate/`. |
| Audit log invariant porušen (S-05) | Ztráta audit trail | Nízká | Migrace 019 **MUSÍ** použít `ALTER TABLE ADD COLUMN` — pattern z 007 (table recreation) je zakázán pro tuto migraci. PR template dokumentuje. |
| Dual-license false positives (BA Q2) | Legální balíčky blokovány | Nízká–Střední | Explicit parser s testy pro OR/AND/WITH. Configurable `or_semantics`. `WITH` modifier ignorován (dokumentováno). |
| SPDX static list zastará (S-07) | Nové licence jako `unknown` | Nízká | `go generate` z SPDX license-list-data při každém release. ~50 aliasů pro non-standard stringy. |
| License check pomalý (extra DB query) (P6) | Latence cache-miss | Nízká | LRU cache per-project policy (5min TTL), invalidate na PUT. `licenses_json` pre-extracted — 1 DB hit, ne blob load. |
| Migrace na produkci | Rozbitý deploy | Nízká | Všechny nové sloupce nullable, žádný backfill, žádné DROP. Testováno v `make test-e2e-containerized` (3× strict/balanced/permissive). |
| Trivy CycloneDX schema change mezi verzemi | Parser rozbitý po Trivy upgrade | Nízká | Trivy verze pinned (viz CLAUDE.md version pinning). Parser má fallback na `unknown_action`. Integration test s fixture CycloneDX JSON. |

---

## Testování

### Unit testy

**`internal/project/`:**
- `TestService_Resolve_NewLabel_CreatesRow_LazyMode`
- `TestService_Resolve_ExistingLabel_ReturnsRowFromCache`
- `TestService_Resolve_InvalidLabel_Returns400`
- `TestService_Resolve_MixedCase_LowercasedBeforeRegex` (`MyApp` → `myapp`)
- `TestService_Resolve_Concurrent_NoDuplicate` (100 goroutin stejný nový label)
- `TestService_Resolve_StrictMode_UnknownLabel_ReturnsErrNotFound`
- `TestService_Resolve_HardCapReached_Returns429`
- `TestService_Resolve_RateLimitExceeded_PerPATHash_Returns429`
- `TestService_Resolve_CacheInvalidation_AfterUpdate`

**`internal/sbom/`:**
- `TestStorage_Write_StoresBlobAndMetadata`
- `TestStorage_Read_Roundtrip`
- `TestStorage_GetMetadata_NoBlobLoad`
- `TestParser_CycloneDX_ExtractsLicenses`
- `TestParser_CycloneDX_ExtractsVulnerabilities`
- `TestParser_EmptyComponents_ReturnsEmptyLicenses`
- `TestSanitize_ReplacesCachePrefix`

**`internal/license/`:**
- `TestEvaluator_BlockedLicense_ReturnsBlock`
- `TestEvaluator_Whitelist_OnlyAllowedPassed`
- `TestEvaluator_UnknownLicense_AppliesUnknownAction`
- `TestEvaluator_LazyMode_ProjectOverride_Ignored` (S-01 fix)
- `TestEvaluator_StrictMode_ProjectOverride_BeatsGlobal`
- `TestEvaluator_InheritMode_FallsBackToGlobal`
- `TestExpression_SimpleLicense_Parsed`
- `TestExpression_OR_AnyAllowed`
- `TestExpression_OR_AllAllowed_Configurable`
- `TestExpression_AND_AllRequired`
- `TestExpression_WITH_IgnoresException` (v1.2 limitation)
- `TestExpression_Parens_Recursive`
- `TestExpression_Malformed_FallsBackToUnknown`
- `TestSPDX_Normalize_CommonAliases` (~20 případů)

**`internal/policy/`:**
- `TestEngine_Evaluate_LicenseBlock_ReturnsBlock`
- `TestEngine_Evaluate_NoSBOM_OnSBOMErrorAllow_Skips`
- `TestEngine_Evaluate_NoSBOM_OnSBOMErrorBlock_Blocks`
- `TestEngine_Evaluate_LicenseWarn_AddedToWarnings`
- `TestEngine_Evaluate_AllowlistedPackage_SkipsLicenseCheck`
- `TestEngine_Evaluate_ProjectFromContext_UsedForPolicy`

**`internal/auth/`:**
- `TestAPIKeyMiddleware_BasicAuthUsername_BecomesProjectLabel`
- `TestAPIKeyMiddleware_EmptyUsername_UsesDefaultProject`
- `TestAPIKeyMiddleware_UsernameIsNotOwnerEmail` (regression)
- `TestAPIKeyMiddleware_StrictMode_UnknownLabel_Returns403`
- `TestAPIKeyMiddleware_LazyMode_RateLimitPerPAT`

**`internal/cache/`:**
- `TestBlobStore_Local_PutGetDelete`
- `TestBlobStore_S3_PutGetDelete` (s mock S3)
- `TestBlobStore_Paths_Sanitized`

### Integrační testy

- SQLite: migrations up/down clean (all 5 new)
- PostgreSQL: migrations parity
- Policy engine s real SQLite DB — vytvoř project, policy, SBOM metadata, Evaluate

### E2E testy (shell, v `tests/e2e-shell/`)

**`test_projects.sh`:**
```bash
# Lazy create happy path
curl -u myapp:$PAT https://proxy/pypi/simple/requests/
assert_sqlite_exists "SELECT 1 FROM projects WHERE label='myapp'"
assert_audit_event_type="ARTIFACT_SERVED" project="myapp"

# Case normalization
curl -u MyApp:$PAT https://proxy/pypi/simple/requests/
assert_sqlite_exists "SELECT 1 FROM projects WHERE label='myapp'"  # nedostaneme druhý row

# Empty username → default
curl -u :$PAT https://proxy/pypi/simple/requests/
assert_audit_event project="default"

# Invalid label (uppercase, regex fail po lowercase je OK, ale speciální znaky ne)
curl -u 'my@app:$PAT' https://proxy/pypi/simple/requests/
assert_http 400

# Strict mode
set_config projects.mode=strict
curl -u unknownproject:$PAT https://proxy/pypi/simple/requests/
assert_http 403
assert_audit_event_type="PROJECT_NOT_FOUND"

# Hard cap
set_config projects.max_count=3
# (create 3 projects via lazy)
curl -u proj4:$PAT https://proxy/pypi/simple/requests/
assert_http 429

# Rate limit per PAT
set_config projects.lazy_create_rate=2
curl -u a:$PAT  # OK
curl -u b:$PAT  # OK
curl -u c:$PAT  # 429 (rate limit)

# API: explicit create
curl -X POST -H "Cookie: $SESSION" /api/v1/projects -d '{"label":"payments"}'
assert_sqlite_exists "SELECT 1 FROM projects WHERE label='payments' AND created_via='api'"
```

**`test_sbom.sh`:**
```bash
# Pull PyPI package přes proxy
uv pip install --index-url https://myproj:$PAT@proxy/pypi/simple requests==2.31.0

# Fetch SBOM
ARTIFACT_ID=$(sqlite_query "SELECT id FROM artifacts WHERE name='requests' AND version='2.31.0'")
curl -H "Cookie: $SESSION" https://proxy/api/v1/artifacts/$ARTIFACT_ID/sbom > sbom.json

# Validate CycloneDX
jq '.bomFormat' sbom.json | grep -q CycloneDX
jq '.specVersion' sbom.json | grep -qE '^"1\.[0-9]+"$'
assert_gt "$(jq '.components | length' sbom.json)" 0

# Path sanitization
! grep -q "/var/cache/shieldoo-gate" sbom.json

# Pre-extracted licenses
curl .../$ARTIFACT_ID/licenses | jq '.' | grep -q "Apache-2.0"
```

**`test_license_policy.sh`:**
```bash
# LAZY MODE — global policy only
set_config projects.mode=lazy policy.licenses.blocked='["GPL-3.0-only"]'

# GPL package → blocked
curl -u webapp:$PAT https://proxy/pypi/simple/some-gpl-pkg/
assert_http 403
assert_response_json ".error" == "license_blocked"
assert_response_json ".license" == "GPL-3.0-only"
assert_audit_event_type="LICENSE_BLOCKED" project="webapp"

# MIT package → allowed
curl -u webapp:$PAT https://proxy/pypi/simple/some-mit-pkg/
assert_http 200

# Per-project override PUT v lazy módu → 403
curl -X PUT /api/v1/projects/$WEBAPP_ID/license-policy -d '{"mode":"override","blocked":[]}'
assert_http 403

# STRICT MODE — per-project override funguje
set_config projects.mode=strict
create_project_via_api oss-playground
set_license_policy oss-playground mode=override blocked='[]'

# GPL package + override → allowed
curl -u oss-playground:$PAT https://proxy/pypi/simple/some-gpl-pkg/
assert_http 200

# WHITELIST MODE (allowed jen explicitní)
set_config policy.licenses.allowed='["MIT","Apache-2.0"]'
curl -u webapp:$PAT https://proxy/pypi/simple/some-bsd-pkg/
assert_http 403  # BSD není v allowed

# DUAL LICENSE
curl -u webapp:$PAT https://proxy/pypi/simple/dual-mit-apache-pkg/
assert_http 200  # MIT v allowed → OR = any_allowed → pass

# UNKNOWN LICENSE
set_config policy.licenses.unknown_action=block
curl -u webapp:$PAT https://proxy/pypi/simple/unknown-license-pkg/
assert_http 403

# SBOM ERROR → on_sbom_error behavior
# (simulate by delete row from sbom_metadata before request or use artifact without SBOM)
set_config policy.licenses.on_sbom_error=block
# manually DELETE FROM sbom_metadata WHERE artifact_id=X
curl -u webapp:$PAT .../already-cached-no-sbom-artifact
assert_http 403
```

### Verifikace před claim "done"

```bash
make build
make lint
make test                    # unit + integration
make test-e2e-containerized  # strict + balanced + permissive scénáře (3 runs)
```

Následně ruční check:
- `grep -rn "TODO\|FIXME\|XXX" internal/project internal/sbom internal/license` — žádné nedodělky
- `grep -rn "fmt.Println\|log.Println" internal/...` — žádné debug printy
- `grep -rn "/var/cache/shieldoo-gate" tests/e2e-shell/fixtures/` — fixture SBOMy jsou sanitized
- OpenAPI validní
- Docs up-to-date: `docs/features/projects.md`, `sbom-generation.md`, `license-policy.md`, `index.md` aktualizovaný status

---

## Poznámky

### Idempotence

- `Resolve` používá LRU cache → `SELECT` → `INSERT OR IGNORE` + `SELECT` — race-safe na SQLite i PostgreSQL.
- `artifact_project_usage` upsert: `ON CONFLICT ... DO UPDATE` je idempotentní; debounced flush sjednotí N volání do 1 batch.
- SBOM storage je content-addressed přes `artifact_id` → re-run generování je idempotentní (přepíše blob + metadata).
- License evaluator je pure function (bez side effects) → bezpečná concurrency.

### Edge cases

- **Empty username v Basic auth** — dnes povolené, mapujeme na `default` projekt.
- **Non-UTF-8 / non-ASCII username** — regex fail po lowercase → 400.
- **Extrémně dlouhý username** — regex limit 64 znaků → 400.
- **MixedCase username** — `MyApp` → lowercase → `myapp` (silent normalization, dokumentováno).
- **Artefakt z před SBOM funkce** — `sbom_metadata` pro něj neexistuje; license check aplikuje `on_sbom_error`.
- **Trivy timeout** — SBOM se nevygeneruje, artefakt projde scan → `on_sbom_error` policy.
- **Anon request (auth disabled)** — ProxyAuth musí být `enabled` pro projekt tracking. Pokud disabled → middleware se přeskočí → `default` projekt (fallback v adapteru).
- **Cached artifact + policy change** — license policy se neaplikuje retroaktivně; admin spustí rescan přes rescan scheduler. Dokumentováno jako known limitation.
- **Disabled project + in-flight request** — eventual consistency: projekt disable neruší běžící requesty; usage upsert proběhne. Metadata-only chování v v1.2.

### Výkonnostní úvahy

- **`Resolve` hot path:**
  - Cache hit: ~1μs (map lookup)
  - Cache miss (existing): `SELECT` via `idx_projects_label` ~100μs na SQLite
  - Cache miss (new): `INSERT OR IGNORE` + `SELECT` + LRU insert ~500μs
  - **Bez cache** (baseline): každý request by byl 500μs+ → throughput collapse. Cache je mandatory.
- **`artifact_project_usage` upsert:** debounced — flush 1× za 30s, batch size = počet unique `(artifact, project)` v intervalu. Kontrast: bez debounce = 1 write per request.
- **License eval:** `GetMetadata` je DB hit na PK `sbom_metadata.artifact_id` (~50μs). LRU cache `project_license_policy` eliminuje druhý DB hit pro strict mode override.
- **SBOM write async:** response latence +0ms (goroutine). Disk I/O na pozadí.
- **Single-run Trivy:** +0ms oproti current (one subprocess, jeden parser switch).

### Zpětná kompatibilita

- **Všechny nové sloupce jsou nullable** → starší řádky (audit_log, artifacts) fungují beze změny.
- **Existující PATs fungují beze změny** — pokud klient neposílá username, mapuje se na `default` projekt.
- **Config defaults:** `sbom.enabled: true`, `policy.licenses.enabled: true` ale `blocked: []` → žádné blokování, jen evidence. `projects.mode: lazy` → žádné 403 pro neznámé labely.
- **Existující policy overrides** (DB tabulka) fungují beze změny — license step je **po** allowlist, ne před.
- **Staré artefakty bez SBOM** — `on_sbom_error: allow` (default) → license check se přeskočí, artifakt projde.

### Budoucí extension points

- **PAT vázaný na project_id** (v1.3) — při vytváření PAT explicit `project_id`. Middleware odmítne username který nesedí. Řeší S-01 spoofing úplně.
- **SPDX auto-update** — periodický refresh SPDX license listu z GitHub mirror.
- **SBOM SPDX export** — CycloneDX → SPDX convertor (dnes 406).
- **Project-level alerting** — per-project webhook URLs v `projects` tabulce.
- **Project-level rate limits** — per-project request quotas.
- **`enabled=0` runtime enforcement** — v1.3: disabled projekt vrátí 403 při proxy requestu.

---

## Reference

- [SPDX License List](https://spdx.org/licenses/)
- [SPDX License Expressions spec](https://spdx.dev/learn/handling-license-info/)
- [CycloneDX 1.5 JSON spec](https://cyclonedx.org/docs/1.5/json/)
- [Trivy SBOM docs](https://aquasecurity.github.io/trivy/latest/docs/supply-chain/sbom/)
- [Trivy `--scanners` flag](https://aquasecurity.github.io/trivy/latest/docs/target/rootfs/)
- Existující podobné vzory v codebase:
  - [internal/scanner/trivy/trivy.go](../../internal/scanner/trivy/trivy.go) — wrapper Trivy binárky
  - [internal/auth/apikey.go:96-124](../../internal/auth/apikey.go#L96-L124) — debounce pattern (`touchLastUsed`, flush loop)
  - [internal/policy/engine.go](../../internal/policy/engine.go) — EngineOption pattern
  - [internal/config/migrations/sqlite/014_triage_cache.sql](../../internal/config/migrations/sqlite/014_triage_cache.sql) — tabulka s JSON sloupcem
  - [internal/config/migrations/sqlite/007_audit_user_email.sql](../../internal/config/migrations/sqlite/007_audit_user_email.sql) — **NEGATIVNÍ příklad**: table recreation pattern, kterému se v migraci 019 vyhneme (invariant #5)
