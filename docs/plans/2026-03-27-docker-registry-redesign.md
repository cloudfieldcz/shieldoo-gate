# Docker Registry Redesign — Proxy Registry s Multi-Upstream

## Popis

Přestavba Docker adaptéru z transparentního proxy na plnohodnotnou proxy registry (Harbor-like). Systém bude fungovat jako interní Docker registry, která:
- Stahuje images z více upstream registries (dockerhub, ghcr.io, quay.io, ...)
- Skenuje images před zpřístupněním klientům (blocking scan)
- Umožňuje push interních images (ne do upstream proxy repozitářů)
- Automaticky re-pulluje a re-skenuje images, které už má
- Poskytuje API + UI pro manuální tagging

### Proč

- Transparentní proxy nestačí pro produkční use case — organizace potřebuje kontrolu nad tím, co se dostane do clusteru
- Podpora více upstream registries je nutnost (dockerhub, ghcr.io, quay.io, interní registry třetích stran)
- Automatický re-scan chrání proti nově objeveným CVE v již stažených images
- Push interních images umožňuje používat shieldoo-gate jako single point of access pro všechny container images

## Aktuální stav

### Docker Adapter

Aktuální implementace je transparentní proxy s scan-on-pull:

- **Router**: `internal/adapter/docker/docker.go:92-105` — chi routes pro OCI Distribution Spec v2
- **Single upstream**: `docker.go:41` — `upstreamURL string`, jeden upstream per instance
- **Artifact ID**: `docker.go:193-196` — formát `docker:{safeName}:{ref}`, lomítka nahrazena podtržítky
- **Scan pipeline**: `docker.go:190-421` — blocking request, klient čeká na scan
- **Blob proxy**: `docker.go:548-577` — přímý pass-through bez skenu
- **Manifest fetch**: `docker.go:425-457` — stahuje z jednoho upstream URL
- **Image pull**: `docker.go:461-494` — crane pull do OCI tarballu, scan tarballu

### Konfigurace

- `internal/config/config.go:34-39` — `UpstreamsConfig.Docker` je jeden string
- `cmd/shieldoo-gate/main.go:157` — fallback na `https://registry-1.docker.io`

### Databáze

- `internal/config/migrations/001_init.sql:1-12` — `artifacts` tabulka, `upstream_url` je TEXT
- `001_init.sql:26-34` — `artifact_status` tabulka se statusem CLEAN/QUARANTINED/SUSPICIOUS/PENDING_SCAN

### Cache

- `internal/cache/local/local.go:124-143` — Put metoda, path = `{basePath}/{ecosystem}/{name}/{version}/`
- `local.go:58-61` — `artifactPath()` = `filepath.Join(basePath, eco, name, version)`

| Aspekt | Současný stav | Navrhovaný stav |
|--------|--------------|-----------------|
| Upstream | Jeden (dockerhub) | Více (dockerhub + allowlist) |
| Naming | `docker:library_nginx:v1.0` | `docker:ghcr.io/user_app:v1.0` nebo `docker:library_nginx:v1.0` |
| Push | Nepodporován | Push interních images |
| Re-scan | Nepodporován | Automatický scheduled re-pull + re-scan |
| Tagging | Nepodporován | API + UI pro manuální tagging |
| Upstream routing | N/A | Dot-in-first-segment = registry hostname |
| Registry discovery | N/A | Allowlist v configu |

## Návrh řešení

### Architektura

#### Multi-Upstream Routing

Routování na základě prvního segmentu cesty za `/v2/`:

```
GET /v2/ghcr.io/cloudfieldcz/cf-powers/manifests/v1.0
         ^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^ ^^^^
         registry  image path           OCI route  ref

GET /v2/library/nginx/manifests/latest
        ^^^^^^^^^^^^^ ^^^^^^^^^^ ^^^^^^
        image path    OCI route  ref
        (default → dockerhub)
```

**Pravidla:**
- Obsahuje-li první segment tečku (`.`) nebo dvojtečku (`:`) → je to registry hostname
- Hostnames s portem (např. `myregistry.corp:5000`) jsou podporovány — port je součást hostname pro routing i allowlist
- Jinak → default (dockerhub)
- Registry hostname musí být v `allowed_registries`, jinak → **403 Forbidden** + structured error + audit log BLOCKED
- Bare image names bez namespace (např. `nginx`) se automaticky expandují na `library/nginx` pro Docker Hub

#### Image Lifecycle

```
Pull request → Parse upstream → Allowlist check (403 pokud nepovolená)
  → Cache check → HIT + CLEAN: serve
                → HIT + QUARANTINED: 403
                → MISS: fetch from upstream → scan (blocking) → cache + serve/reject
```

Synchronní blocking model — klient čeká na scan. Žádný PENDING_SCAN stav.

#### Push Flow (jen interní images)

```
Push request → Ověř že první segment NENÍ v allowed_registries ani default registry hostname
  → 403 pokud je → "Cannot push to upstream proxy namespace"
  → Přijmi layers + manifest (OCI monolithic upload: POST + PUT)
  → Scan image PŘED odesláním success response (Security Invariant #2)
  → Scan OK → 201 Created, cache + uložit metadata
  → Scan FAIL → quarantine, 403
```

**OCI Push subset (v1 — monolithic upload only):**
1. `POST /v2/{name}/blobs/uploads/` → 202 + `Location` header s upload UUID
2. `PUT /v2/{name}/blobs/uploads/{uuid}?digest=sha256:...` → celý blob v body, 201 Created
3. `HEAD /v2/{name}/blobs/{digest}` → check existence (skip upload)
4. `PUT /v2/{name}/manifests/{ref}` → push manifest, trigger scan

Chunked upload (PATCH) je future work.

**Požadované response headers:**
- `Docker-Upload-UUID` v upload responses
- `Location` header v POST upload initiation
- `Docker-Content-Digest` v manifest PUT response
- `201 Created` pro úspěšný manifest push

#### Scheduled Sync

```
Cron job → Pro každý cached image s upstream_registry != "" a sync_enabled = true
  → Re-pull z upstreamu → Re-scan → Aktualizuj status
  → Pokud nový scan najde problém → quarantine
```

**Sync error handling:**

| Scénář | Chování | Změna statusu |
|--------|---------|---------------|
| Upstream nedostupný | Retry s exponential backoff, log warning | Beze změny |
| Upstream 404 (image smazán) | Nastavit `sync_enabled = false`, log error | Beze změny (servírovat cached) |
| Upstream 429 (rate limited) | Respektovat `Retry-After` header, back off | Beze změny |
| Re-scan selže | Fail open (zachovat aktuální status), log error | Beze změny |
| Re-scan najde nové CVE | Quarantine | CLEAN → QUARANTINED |

**Concurrency:** Max 3 souběžné sync operace (konfigurovatelné). Priorita: naposledy pullnuté images first. Jitter: random 0-30s delay mezi starty.

**Change detection:** Změna = upstream manifest digest se liší od lokálního `docker_tags.manifest_digest`. Pokud beze změny, re-scan pouze po uplynutí `rescan_interval` od `last_synced_at`.

### Databázové změny

#### Nová tabulka: `docker_repositories`

| Sloupec | Typ | Popis |
|---------|-----|-------|
| id | INTEGER PRIMARY KEY | Auto-increment |
| registry | TEXT NOT NULL | Upstream registry hostname (`docker.io` pro Hub, prázdný = interní) |
| name | TEXT NOT NULL | Image name (e.g. `cloudfieldcz/cf-powers`) |
| is_internal | BOOLEAN NOT NULL DEFAULT 0 | True = pushed, ne proxied |
| created_at | DATETIME NOT NULL | Kdy byl repo poprvé zaregistrován |
| last_synced_at | DATETIME | Poslední sync z upstreamu |
| sync_enabled | BOOLEAN NOT NULL DEFAULT 1 | Povolit auto-sync |

UNIQUE index na `(registry, name)`.

**Lifecycle:** Řádek se vytváří automaticky při prvním úspěšném pull (pro proxied images) nebo při prvním push initiation (pro interní images). Lze také pre-vytvořit přes admin API.

#### Nová tabulka: `docker_tags`

| Sloupec | Typ | Popis |
|---------|-----|-------|
| id | INTEGER PRIMARY KEY | Auto-increment |
| repo_id | INTEGER NOT NULL FK → docker_repositories.id | Repozitář |
| tag | TEXT NOT NULL | Tag name (e.g. `v1.0`, `latest`) |
| manifest_digest | TEXT NOT NULL | SHA256 manifest digest |
| artifact_id | TEXT FK → artifacts.id | Odkaz na artifact |
| created_at | DATETIME NOT NULL | Kdy byl tag vytvořen |
| updated_at | DATETIME NOT NULL | Poslední update tagu |

UNIQUE index na `(repo_id, tag)`.
Index na `manifest_digest` pro lookup by digest.

**Tag semantics:** Tagy jsou mutable — přesun tagu na jiný digest spustí re-scan cílového digestu. Předchozí asociace tag→digest se zachová v audit logu. Smazání tagu neodstraňuje underlying artifact (zůstává dostupný přes digest).

#### Změny v existujících tabulkách

`artifacts` — přidat sloupec:
- `registry TEXT NOT NULL DEFAULT 'docker.io'` — upstream registry hostname (`docker.io` pro Hub, `_internal` pro pushed images)

#### Migrace existujících dat

**Strategie: clean break.** Nové artifact IDs pro nové pully. Existující artifacts zůstávají jak jsou — starý formát `docker:library_nginx:v1.0` bude stále fungovat pro čtení. Nové pully vytvoří nový záznam s novým formátem. Audit log se NEMĚNÍ (append-only invariant).

#### Cache naming

Cache layer **zachovává `_` encoding** pro lomítka v cestách — je to interní implementační detail. Artifact ID v DB může mít plné jméno, ale cache path je derivovaný přes safe encoding (`/` → `_`, `.` → `_`). Žádná změna v `validateName()`.

#### Migration runner

Přidat `schema_migrations` tracking tabulku pro idempotentní ALTER TABLE. Každá migrace se spustí pouze jednou.

### Změny v servisní vrstvě

#### Docker Adapter refaktor

- `DockerAdapter` struct: `upstreamURL string` → `defaultUpstream string` + `allowedRegistries map[string]RegistryConfig`
- Nová metoda `resolveUpstream(name string) (registry, imagePath, upstreamURL string)`
- `handleManifest` — volá `resolveUpstream`, konstruuje artifact ID s registry prefixem
- Nové OCI push handlery: `handleBlobUploadInit`, `handleBlobUploadComplete`, `handleBlobHead`, `handleManifestPut`
- Nový `handleV2Wildcard` — rozšířit o PUT/POST/HEAD routes
- `/v2/` endpoint odpovídá lokálně s `Docker-Distribution-API-Version: registry/2.0`, NEPROXUJE na upstream
- Auth challenges se řeší per-upstream při actual pull/push operacích

#### Nový service: `internal/adapter/docker/sync.go`

- `SyncService` struct s metodami `SyncAll(ctx)`, `SyncRepository(ctx, repo)`
- Spouštěn cronem z main.go s context cancellation při shutdown
- Re-pull + re-scan logika
- `maxConcurrentSyncs` semaphore
- Temp disk space check před sync operací

#### Nový service: `internal/adapter/docker/tags.go`

- CRUD operace nad `docker_tags` tabulkou
- Metody: `ListTags`, `CreateTag`, `DeleteTag`, `GetTagByDigest`
- Tag movement → trigger re-scan

### API změny

Nové REST endpointy v `internal/api/`:

```
GET    /api/v1/docker/repositories              — seznam repozitářů
GET    /api/v1/docker/repositories/{id}/tags     — tagy repozitáře
POST   /api/v1/docker/repositories/{id}/tags     — vytvořit/přesunout tag (triggers re-scan)
DELETE /api/v1/docker/repositories/{id}/tags/{tag} — smazat tag (artifact zůstává)
POST   /api/v1/docker/sync/{id}                 — vynutit sync
GET    /api/v1/docker/registries                 — seznam povolených registries
```

### Změny v UI

Nová sekce v admin UI:
- Docker Repositories list s filtrováním dle registry
- Tag management per repository
- Sync status a manuální trigger
- Registry allowlist management

### Konfigurace

```yaml
upstreams:
  docker:
    default_registry: "https://registry-1.docker.io"
    allowed_registries:
      - host: "ghcr.io"
        url: "https://ghcr.io"
        auth:
          type: "bearer"           # nebo "basic"
          token_env: "SGW_GHCR_TOKEN"  # reference na env var, nikdy plaintext
      - host: "quay.io"
        url: "https://quay.io"
    sync:
      enabled: true
      interval: "6h"              # jak často re-pullovat
      rescan_interval: "24h"      # jak často re-skenovat i bez změny
      max_concurrent: 3           # max souběžných sync operací
    push:
      enabled: true
      # namespace pro interní images (volitelné omezení)
      # allowed_namespaces: ["internal", "myteam"]
```

Credentials per registry se NIKDY nelogují (Security Invariant #3).

## Dotčené soubory

### Nové soubory
- `internal/adapter/docker/registry.go` — multi-upstream routing logika
- `internal/adapter/docker/push.go` — OCI push handlery (monolithic upload)
- `internal/adapter/docker/sync.go` — scheduled sync service
- `internal/adapter/docker/tags.go` — tag management service
- `internal/config/migrations/003_docker_registry.sql` — nové tabulky + schema_migrations
- `internal/api/docker_handlers.go` — REST API pro Docker management
- UI komponenty pro Docker repository/tag management

### Upravené soubory
- `internal/adapter/docker/docker.go:36-105` — struct refaktor, router rozšíření, multi-upstream, `/v2/` lokální response
- `internal/config/config.go:34-39` — `UpstreamsConfig.Docker` z string na struct
- `cmd/shieldoo-gate/main.go:157-163` — nová inicializace Docker adaptéru, sync scheduler s context cancellation
- `internal/config/db.go` — schema_migrations tracking tabulka

### Soubory BEZ změn (důležité)
- `internal/cache/local/local.go` — cache layer zůstává beze změn, `_` encoding se zachovává
- `internal/scanner/` — scanner pipeline zůstává beze změn
- `internal/policy/` — policy engine zůstává beze změn
- `internal/adapter/pypi/`, `npm/`, `nuget/` — ostatní adaptéry se nemění
- `internal/adapter/interface.go` — adapter interface zůstává (Docker adapter je stále `http.Handler`)
- `internal/adapter/base.go` — sdílené utility zůstávají

## Implementační fáze

### Fáze 1: Multi-Upstream Routing + Allowlist
- Refaktor `DockerAdapter` pro podporu více upstream registries
- Dot-in-first-segment routing logika + `library/` prefix pro bare names
- Config změna z `string` na struct s allowlist + per-registry credentials
- Databázová migrace: `docker_repositories` tabulka, `schema_migrations` tracking
- Artifact ID: zachovat `_` encoding v cache, nový formát s registry prefixem v DB
- `/v2/` endpoint lokální response (ne proxy)
- 403 + audit log pro nepovolené registry
- Testy pro routing, allowlist, credentials forwarding
- **Závislosti:** žádné
- **Výsledek:** `docker pull shieldoo:5002/ghcr.io/user/app:v1.0` funguje

### Fáze 2: Push Support pro interní images
- OCI monolithic push handlery (POST init + PUT complete + HEAD check + manifest PUT)
- Response headers: `Docker-Upload-UUID`, `Location`, `Docker-Content-Digest`
- Validace: push namespace nesmí být upstream registry → 403
- Scan PŘED success response (Security Invariant #2)
- `docker_tags` tabulka + blob storage
- Testy pro push flow, namespace validation, scan-before-response
- **Závislosti:** Fáze 1
- **Výsledek:** `docker push shieldoo:5002/internal/myapp:v1.0` funguje

### Fáze 3: Scheduled Sync
- `SyncService` s cron schedulingem + context cancellation při shutdown
- Re-pull + re-scan logika s change detection (manifest digest comparison)
- Error handling tabulka (unreachable, 404, 429, scan fail)
- Auto-quarantine při novém nálezu
- Concurrency control: `maxConcurrentSyncs` semaphore, jitter, priority
- Temp disk space check
- Config pro intervaly
- Testy pro sync flow, error handling, concurrency
- **Závislosti:** Fáze 1
- **Výsledek:** images se automaticky aktualizují a re-skenují

### Fáze 4a: Tag Management API
- REST endpointy pro CRUD nad tagy
- REST endpointy pro repository listing
- Tag movement → re-scan trigger
- Tag deletion neodstraňuje artifact
- Manuální sync trigger endpoint
- **Závislosti:** Fáze 1-2
- **Výsledek:** kompletní API management

### Fáze 4b: Tag Management UI
- UI komponenty pro repository listing, tag management
- Sync status dashboard + manuální trigger
- **Závislosti:** Fáze 3, 4a
- **Výsledek:** kompletní UI management

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| Dot-routing kolize s dockerhub namespace | Špatný upstream routing | Nízká | Dockerhub namespaces neobsahují tečky; `host:port` format podporován |
| OCI push spec komplexnost | Delší implementace fáze 2 | Vysoká | Monolithic upload only v v1; zvážit `go-containerregistry/pkg/registry` jako referenci; chunked jako future |
| Sync storm při mnoha images | Přetížení upstream + local resources | Střední | Max 3 concurrent syncs, jitter, priority, temp disk check |
| Cache invalidace při re-sync | Stale data servírována klientům | Nízká | Atomický swap manifest + tag update |
| Artifact ID format change | Existující data | Střední | Clean break: nové pully = nový formát, staré zůstávají, audit log se nemění |
| Auth challenge rewriting pro push | Push flow nefunguje | Střední | `/v2/` odpovídá lokálně, auth per-upstream jen při actual operations |
| Sync disk exhaustion | Re-pull vytváří temp tarbally | Střední | Disk space check před sync, `maxConcurrentSyncs` limit |

## Testování

### Unit testy
- `resolveUpstream()` — routing: s tečkou, bez tečky, s portem, nepovolená registry, bare names → `library/`
- Push namespace validace — interní vs upstream
- Tag CRUD operace + tag movement re-scan
- Sync scheduling, change detection, error handling
- Schema migrations idempotence

### Integrační testy
- Pull z různých upstream registries (mock HTTP)
- Push monolithic upload flow + scan-before-response
- Sync re-pull + re-scan flow + error scenarios
- API endpointy pro tag management
- Credentials forwarding (bearer, basic)
- Databázové migrace

### E2E testy
- `docker pull/push` s reálným Docker klientem
- Multi-upstream pull
- Sync cyklus
- Tag management přes API

### Verifikace
- `make test` — všechny testy projdou
- `make lint` — žádné nové warningy
- `docker compose up` — systém startuje s novou konfigurací

## Poznámky

- **Zpětná kompatibilita**: Existující `docker pull shieldoo:5002/library/nginx:latest` musí fungovat beze změn (default upstream = dockerhub)
- **Blob storage**: V první fázi se blobs stále proxují z upstreamu. Lokální blob storage přijde s push supportem (fáze 2)
- **Auth**: Autentizace na upstream registries (bearer token flow) — credentials per registry v configu, reference přes env var
- **Rate limits**: Dockerhub má rate limity pro anonymous pulls. Konfigurovatelné credentials per registry to řeší
- **Digest stability**: Manifest digest se nesmí měnit mezi upstream a shieldoo-gate — klienti na něj spoléhají pro content-addressability
- **Timeout budget**: Max scan duration konfigurovatelná (default z `scanners.timeout`). Při překročení → 504 Gateway Timeout, artefakt se NEcachuje. Při client disconnect → context cancellation zastaví scan.
- **Observability**: Nové Prometheus metriky — sync duration, upstream errors, push counts, scan-on-push duration. Nové log fieldy pro registry hostname.

## Reference

- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)
- [Harbor Proxy Cache](https://goharbor.io/docs/2.0.0/administration/configure-proxy-cache/)
- [go-containerregistry/pkg/registry](https://pkg.go.dev/github.com/google/go-containerregistry/pkg/registry) — referenční in-memory registry
- Aktuální Docker adapter: `internal/adapter/docker/docker.go`
- Aktuální konfigurace: `internal/config/config.go`
- Aktuální migrace: `internal/config/migrations/001_init.sql`
