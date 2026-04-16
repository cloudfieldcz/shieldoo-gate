# Maven effective-pom resolver + AI license detection — pokrytí mezery v license enforcement

## Popis

Současná license enforcement v Shieldoo Gate funguje deterministicky pro PyPI (`*.dist-info/METADATA`), npm (`package.json`), NuGet (`*.nuspec`) a — částečně — Maven (pouze JARy, které mají inline `<licenses>` blok ve svém embedded `META-INF/maven/.../pom.xml`). V e2e testech (E2E v7, 2026-04-16) prošlo Maven enforcement pouze pro `org.apache.logging.log4j:log4j-core:2.23.1`, který tento blok obsahuje. Většina běžně používaných JARů (Apache Commons rodina, Hibernate, slf4j, lombok, junit, mysql-connector-j, iText) license **dědí z parent pomu** a embedded pom uvnitř JARu má pouze `<parent>` referenci — náš per-artifact extractor tak vrátí prázdný seznam.

Tento dokument navrhuje **dvě komplementární řešení** zavedená ve dvou nezávislých fázích:

- **Fáze A — Effective POM Resolver** (Maven only, deterministický, zdarma): proxy si stáhne standalone `.pom` z upstream Maven Central a rekurzivně projde `<parent>` chain, dokud nenajde explicitní `<licenses>` nebo nedosáhne hranice pre-konfigurovaných whitelistovaných parent repository.
- **Fáze B — AI License Detection** (cross-ekosystém, drahý fallback): nový scanner `ai-license-detector` v scanner-bridge dostane extracted artifact dir + ekosystém a vrátí seznam SPDX IDs. Spustí se **jen když strukturní extractor vrátí 0 licencí AND `policy.licenses.enabled`** — minimalizuje LLM cost a latenci. Výsledky cachuje v DB.

Fáze B je nadřazená nad A — pokrývá i ekosystémy, kde Effective POM nemá smysl (RubyGems `.gem` nested archives, Docker images bez Trivy detekce, exotické formáty). A je rychlejší a deterministická pro Maven, kde dnes máme největší mezeru.

### Proč

- **Reálný impact**: dnes je Maven license enforcement no-op pro odhadem 80–95% běžných enterprise JARů — falešný pocit bezpečí. Audit "blocked GPL artifact" by v praxi vůbec nikdy nevystřelil pro `mysql-connector-j`, `itext-core`, `jpcap`, atd.
- **Compliance**: zákazníci v regulovaných odvětvích (fintech, health, gov) potřebují důkaz, že proxy skutečně blokuje GPL/AGPL napříč všemi formáty, ne jen u 5% JARů s historickou inline deklarací.
- **AI scanner už existuje** — `internal/scanner/ai/scanner.go` má kompletní gRPC pipeline do scanner-bridge, prompt templates v `scanner-bridge/prompts/`, cache infrastrukturu (`triage_cache` migration). License detection je téměř zadarmo z architektonického pohledu.
- **Trivy 0.50 limitace nejde obejít**: Trivy `fs <dir>` analyzátor vyžaduje lockfile-style projekt root (requirements.txt, package-lock.json), ne single-package metadata. Upgrade na novější Trivy by mohl pomoct s některými ekosystémy, ale ne s parent-pom inheritance — to není problém Trivy, je to problém Maven dependency modelu.
- **Technický dluh**: současný workaround v `tests/e2e-shell/test_license_policy.sh:336-381` používá `log4j-core` jako blocked test artifact a explicitní komentář "the same code path applies to any JAR that includes GPL/AGPL/etc. inline" — tento komentář maskuje skutečnost, že 95% JARů v praxi inline license nemá.

## Aktuální stav

### Co dnes funguje

| Ekosystém | Co extrahujeme | Funguje deterministicky? |
|-----------|----------------|--------------------------|
| PyPI `.whl` | `*.dist-info/METADATA` (RFC-822 `License-Expression`, `License:`, classifiers) | ✅ Ano |
| PyPI `.tar.gz` | `PKG-INFO` (stejný formát) | ✅ Ano |
| npm `.tgz` | `package/package.json` `.license` (oba formáty) | ✅ Ano |
| NuGet `.nupkg` | `*.nuspec` `<license type="expression">` nebo `<licenseUrl>` | ✅ Ano |
| Maven `.jar` (inline `<licenses>`) | `META-INF/maven/{group}/{artifact}/pom.xml` | ⚠️ Pouze ~5% běžných JARů |
| Maven `.jar` (parent inheritance) | — (nedetekováno) | ❌ **Tato analýza** |
| RubyGems `.gem` | YAML gemspec uvnitř `metadata.gz` | ⚠️ Best-effort, často mine |
| Go `.zip` modul | `go.mod` (bez license metadata) | ❌ N/A — Go moduly license neexponují |
| Docker OCI | Trivy `image --input` (vlastní detekce) | ✅ Ano |

### Code paths

Hlavní integrace per-artifact license extrakce:

- **Trivy scanner volá extraktor** v `internal/scanner/trivy/trivy.go:108-128` — po extrakci archivu (`prepareScanPath`) zavolá `extractLicensesFromDir(scanPath)`, normalizuje výsledek přes `sbom.NameAliasToID()` a merguje do `result.Licenses`.
- **Per-ekosystém parsery** v `internal/scanner/trivy/license_extractor.go:48-98` — `parsePyPIMetadata`, `parseNPMPackageJSON`, `parseNuSpec`, `parseMavenPOM`. Maven parser čte `<licenses><license><name>` z prvního pomu nalezeného v `META-INF/maven/`.
- **Policy engine** v `internal/policy/engine.go:340-396` — collectuje `result.Licenses` ze všech scannerů, fallbacks na `sbom_metadata.licenses_json`, pak `unknown_action`/`on_sbom_error`.
- **Maven adapter scan path** v `internal/adapter/maven/maven.go:384-440` — download → `scanEngine.ScanAll` → `policyEngine.Evaluate` → cache/serve/quarantine. Žádný post-download license enrichment.
- **AI scanner reference** v `internal/scanner/ai/scanner.go:33-80` — gRPC client, DialContext na `unix://${bridge_socket}`, posílá `AIScanRequest{artifact_id, ecosystem, name, version, local_path, original_filename}`, dostává `AIScanResponse{verdict, confidence, findings, explanation, model_used, tokens_used}`. **Dnes pouze pro malware analýzu**.
- **Scanner-bridge gRPC schema** v `scanner-bridge/proto/scanner.proto:1-65` — service `ScannerBridge` má rpc `ScanArtifact`, `ScanArtifactAI`, `TriageFindings`, `HealthCheck`. **Žádná license RPC**.
- **Triage cache pattern** (vzor pro AI license cache) v `internal/policy/engine.go` + migrace `014_triage_cache.sql` — sha256(artifact_id+content) → cached LLM výsledek + TTL.

### Aktuální mezera

| Aspekt | Současný stav | Navrhovaný stav |
|--------|--------------|-----------------|
| Maven license detection coverage | ~5% běžných JARů | **A:** ~95% (vše s funkčním parent chainem) + **B:** ~99% (LLM si poradí s edge cases) |
| Cross-ekosystém fallback | žádný | **B:** AI scanner běží, když strukturní vrátí prázdný seznam |
| Determinism | 100% (ale úzký záběr) | A: 100% pro Maven, B: pravděpodobnostní s cache |
| LLM cost | $0 | **A:** $0, **B:** ~1 LLM call per uncached artifact (cache TTL 30 dní) |
| Latence sync scan path | nedotčená | A: +1–3 HTTP fetches per Maven JAR (parent chain, cached), B: +0.5–2s per uncached artifact |
| Auditability | Trivy/extractor jako jediný zdroj | A: standalone `.pom` (forensicky uložitelné), B: LLM explanation v audit logu |
| Vendor lock-in | žádný | B: vyžaduje Azure OpenAI nebo OpenAI-kompatibilní endpoint (stejná závislost jako stávající ai-scanner) |

## Návrh řešení

### Architektura

Obě fáze přidávají *novou cestu doplnění `ScanResult.Licenses`* přes per-adapter enrichment + scanner merge. Klíčový pre-requisit: **přidat `scanner.EcosystemMaven` do `TrivyScanner.SupportedEcosystems()`** — dnes Trivy vrací pouze Docker, PyPI, npm, NuGet (`internal/scanner/trivy/trivy.go:59-65`), takže scanner engine pro Maven Trivy vůbec nevolá a veškerá license extrakce pro JARy je mrtvý kód. Tento fix je triviální (1 řádek) ale bez něj celá Fáze A nefunguje.

#### Merge semantics (cross-check F-01)

Všechny zdroje licencí (Trivy CycloneDX, `extractLicensesFromDir`, `Artifact.ExtraLicenses`, případně AI fallback) se slučují do **union** — policy engine evaluuje celou sadu. Pokud inline pom řekne Apache-2.0 a parent chain řekne GPL-2.0, OBĚ licence se zobrazí a OBĚ se evaluují proti blocked listu. Toto je **conservative (compliance-safe)** — falešně pozitivní (blokuje víc) je přijatelnější než falešně negativní (propustí GPL). Admin explicitně vidí obě licence v UI a může vytvořit override na `Artifact.ID` level pokud je to false positive (existující mechanismus `internal/api/overrides.go`).

```
┌─────────────────────────────────────────────────────────────────┐
│ adapter (maven/pypi/npm/...)                                    │
│   1. download artifact → tmpPath                                │
│   2. ★ FÁZE A (Maven only):                                     │
│        effectivepom.Resolve(group, artifact, version)           │
│        → Artifact.ExtraLicenses = [...SPDX...]                  │
│   3. scanEngine.ScanAll(artifact)                               │
│        (pre-requisit: Maven přidán do Trivy SupportedEcosystems)│
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ scanner.Trivy.Scan                                              │
│   1. prepareScanPath (extract archive)                          │
│   2. trivy fs ... → SBOMContent + Licenses                      │
│   3. extractLicensesFromDir → merge to Licenses                 │
│   4. merge Artifact.ExtraLicenses (UNION, dedup by normalizeID) │
│   5. ★ FÁZE B (cross-eco, ASYNC post-serve):                    │
│        IF len(Licenses) == 0 AND policy.licenses.enabled:       │
│          aiLicense.DetectAsync(artifact, scanPath) → cache      │
│          (applied on NEXT request, not this one)                │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
                  policy.Evaluate(...)
```

### Fáze A — Effective POM Resolver

#### Bezpečnostní požadavky (cross-check S-01, S-04)

POM soubory stahované z upstream jsou **nedůvěryhodný XML vstup**. Resolver MUSÍ:

- Parsovat přes `xml.NewDecoder` s body-size cap **1 MB** (legitimní POM < 100 KB) — chrání proti XML bomb / Billion Laughs.
- Stripovat DTD deklarace před parsing NEBO validovat, že Go `encoding/xml` v použité verzi neprovádí interní entity expansion. Přidat unit test `TestParser_XMLBomb_DoesNotOOM`.
- Omezit celkovou dobu resolution na **`resolver_timeout: 5s`** (cap na celý parent chain walk), nezávisle na per-POM `fetch_timeout: 3s`.
- Hardcode ceiling `max_depth: 10` který config nemůže překročit (i když admin nastaví vyšší).
- Track `seenCoords map[Coords]bool` pro cycle detection (A→B→A loop).

#### Princip

Maven Central serves každý artifact na URL ve tvaru `<base>/<group-path>/<artifact>/<version>/<artifact>-<version>.{jar,pom,...}`. Standalone `.pom` existuje vedle `.jar` a obsahuje plný projekt deskriptor včetně `<parent>` reference. Resolver:

1. Z artifact koordinátů sestrojí URL standalone `.pom` (nahradí `.jar` → `.pom`).
2. Stáhne pom (sdílí stejný `httpClient` jako adapter, respektuje `PipelineTimeout`).
3. Parsuje `<licenses>` blok. Pokud non-prázdný → vrať a hotovo.
4. Pokud prázdný a má `<parent>` → sestrojí URL parent pomu (`<groupId>/<artifactId>/<version>/<artifactId>-<version>.pom`), goto 2.
5. Cap recursion **5 levels** (typický Maven dependency strom má max 3–4 levels).
6. **In-memory LRU cache** parent pomů (TTL 24h, parent poms jsou immutable per GAV, ale verze přidávané v upstream se časem mění).

#### Architektura

```
internal/maven/effectivepom/
├── resolver.go       # Resolver type + Resolve(...) → []string
├── parser.go         # parsePOM(bytes) → (licenses []string, parent *coords)
├── cache.go          # LRU<coords, *cachedPOM>, TTL, sync.RWMutex
└── resolver_test.go
```

#### Změny v servisní vrstvě

Nový balíček `internal/maven/effectivepom`:

- `type Resolver struct` — drží upstream URL, http client, LRU cache, max depth.
- `type Coords struct { GroupID, ArtifactID, Version string }`
- `func NewResolver(upstreamURL string, client *http.Client, cacheSize int, cacheTTL time.Duration) *Resolver` — **`client` je sdílený `*http.Client` z Maven adapteru** (`adapter.NewProxyHTTPClient`), takže resolver automaticky dědí proxy TLS settings i případné transport-level auth (Basic auth injected přes custom `RoundTripper` pokud enterprise repo vyžaduje). Resolver NIKDY nekonstruuje vlastní HTTP client — vždy dostává hotový z adapteru.
- `func (r *Resolver) Resolve(ctx context.Context, c Coords) ([]string, error)` — vrátí seznam SPDX-ish license stringů (před normalizací). Empty na cycle/depth-limit/network error.
- Resolver musí implementovat **`CheckRedirect`** handling na přijatém clientu: pokud upstream vrátí 3xx redirect na jiný host, resolver ODMÍTNE follow (prevence credential theft přes open redirect). Pokud custom RoundTripper na clientu není, resolver pracuje bez auth (public Maven Central — nejčastější případ).

Změna v existujícím balíčku `internal/scanner`:

- `internal/scanner/interface.go:38-48` — přidat pole `ExtraLicenses []string` do `Artifact` struct. Naplněno před `ScanAll`. Trivy scanner ho po své vlastní extrakci zmerguje do `ScanResult.Licenses` (stejný dedup pattern jako pro `extractLicensesFromDir`).

Změna v Maven adapteru:

- `internal/adapter/maven/maven.go:384-417` — mezi `downloadToTemp` a `scanEngine.ScanAll`:
  - Pokud `parsed.Ext == "jar"`, zavolat `effectivepom.Resolve(ctx, Coords{...})`
  - Naplnit `scanArtifact.ExtraLicenses = licenses`
  - Network failures **fail-open** — log warn a pokračovat, NIKDY neblokovat scan kvůli upstream pom resolution timeoutu.

Změna v `cmd/shieldoo-gate/main.go`:

- Po inicializaci Maven adapter (kolem řádky 240) konstruovat `effectivepom.Resolver` z konfigu a předat do adapter konstruktoru.

#### Konfigurace

Nové pole `MavenConfig.EffectivePOM`:

```yaml
upstreams:
  maven_resolver:
    enabled: true                # default true — fail-open je bezpečné
    cache_size: 4096             # in-memory LRU entries (cross-check P3: enterprise repos mají 500-1000 GAVs × 2-3 parent levels)
    cache_ttl: "24h"             # parent poms jsou immutable per release GAV (SNAPSHOTs: 1h)
    max_depth: 5                 # ochrana proti maliciously deep parent chain (hardcode ceiling: 10)
    fetch_timeout: "3s"          # per-pom HTTP timeout (cross-check P2: Maven Central P50 ~100ms, 3s je generous)
    resolver_timeout: "5s"       # total timeout pro celý parent chain walk (cross-check P2: caps worst-case na 5s, ne 50s)
```

**Latence expectations (cross-check P2):**
- P50: ~150ms (1–2 cache hits, 0–1 network fetch)
- P95: ~500ms (2–3 network fetches, all fast)
- P99: ~3s (fetch_timeout hit na jednom level → fail-open)
- Max: 5s (resolver_timeout hard cap, pak fail-open s warn log)

#### Databázové změny

N/A — vše in-memory cache, žádná persistence (parent poms jsou cheap to re-fetch po restart).

### Fáze B — AI License Detection Fallback

#### Princip

Existující AI scanner (`internal/scanner/ai/scanner.go`) přidá nové RPC `DetectLicenses(LicenseRequest) → LicenseResponse` do `scanner-bridge`. LLM dostane:

- Ekosystém (pypi/npm/maven/...)
- Cestu k extrahovanému archive dir
- Seznam relevantních souborů (LICENSE, LICENSE.txt, NOTICE, COPYING, README, MANIFEST.MF, prvních pár řádků hlavních zdrojových souborů)

Vrátí seznam normalizovaných SPDX IDs s confidence skóre.

Spustí se **jen tehdy**, když:
- `policy.licenses.enabled = true`
- `scanResult.Licenses == []` (strukturní extractor i Effective POM resolver vrátily prázdno)
- AI scanner je healthy
- Cache miss

#### Execution model (cross-check P1: ASYNC by default)

**Phase B běží ASYNC post-serve** — stejný pattern jako sandbox scanner (`internal/adapter/base.go:150-173`). První request pro artifact bez detekované licence se servuje s `unknown_action` (allow/warn/block dle globální/per-project policy). AI license scanner běží v background goroutine. Výsledek se uloží do `ai_license_cache`. **Druhý a každý další request** pro stejný artifact vidí cache hit → licence se vyhodnotí synchronně v policy engine.

Důvod (Performance review P1): sync LLM call na scan path přidá 0.5–35s tail latency per artifact. Pro developer `mvn install` s 50 deps to znamená minuty navíc. Async-post-serve eliminuje tuto latenci za cenu "first request passes through unblocked".

**Opt-in sync mode**: `scanners.ai_license.sync_mode: true` zapne synchronní LLM volání v scan path. Dokumentovat prominentně: "Přidává 0.5–2s na první fetch každého uncached artifactu. Použijte jen pokud vaše compliance vyžaduje zero-first-request-pass-through."

#### Architektura

```
internal/scanner/ailicense/
├── scanner.go              # implementuje scanner.Scanner interface (per existing ai-scanner pattern)
├── scanner_test.go
├── cache.go                # DB-backed cache: SELECT/INSERT into ai_license_cache
└── prompt_builder.go       # vybere relevantní soubory z dir, sestaví LLM input

scanner-bridge/
├── ai_license.py           # nová Python funkce DetectLicenses
├── prompts/
│   └── license_detection.txt   # system prompt + few-shot examples
└── main.py:XX              # gRPC handler dispatch

scanner-bridge/proto/scanner.proto:NN  # nový rpc + messages
```

#### gRPC schema

```protobuf
service ScannerBridge {
    rpc ScanArtifact(ScanRequest) returns (ScanResponse);
    rpc ScanArtifactAI(AIScanRequest) returns (AIScanResponse);
    rpc TriageFindings(TriageRequest) returns (TriageResponse);
    rpc DetectLicenses(LicenseRequest) returns (LicenseResponse);   // NEW
    rpc HealthCheck(HealthRequest) returns (HealthResponse);
}

message LicenseRequest {
    string artifact_id          = 1;
    string ecosystem            = 2;
    string extracted_root_path  = 3;   // path to dir kde žije extracted artifact
    int32  max_files_to_inspect = 4;   // default 25
}

message LicenseResponse {
    repeated string spdx_ids    = 1;   // canonical IDs (alias-normalized server-side)
    float  confidence           = 2;   // 0.0–1.0
    string explanation          = 3;   // krátký lidský popis (audit log)
    string model_used           = 4;
    int32  tokens_used          = 5;
}
```

#### Změny v servisní vrstvě

Nový balíček `internal/scanner/ailicense`:

- `type Scanner struct` — implementuje `scanner.Scanner` interface.
- `func NewScanner(cfg AILicenseConfig, db *config.GateDB) (*Scanner, error)` — dial gRPC, lookup cache.
- `func (s *Scanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error)` — vrátí `ScanResult` s populovaným `Licenses` polem.

Změna v existujícím Trivy scanneru:

- `internal/scanner/trivy/trivy.go:108-128` — po existujícím merge license logic, IF `len(result.Licenses) == 0` a AI license je enabled:
  - Volání do `aiLicense.Detect(ctx, artifact, scanPath)`
  - Merge výsledku s normalizací přes `sbom.NameAliasToID()`

Alternativa: nezavolat z Trivy scanneru, ale jako samostatný `Scanner` v engine. **Preferuju druhou variantu** — zachovává Single Responsibility a umožňuje admin disabling AI license bez vypnutí Trivy.

Změna v scanner engine:

- `internal/scanner/engine.go` — řazení scannerů: Trivy běží jako sync, AI license běží jako sync ale conditionally (založeno na předchozích výsledcích). Engine umožňuje "follow-up scanner" pattern? Pokud ne, AI license bude prostě další scanner v listu, ale uvnitř svého `Scan` provede no-op když policy už má licenses ze sbom_metadata. Toto rozhodnutí dořešit v plan fázi.

#### Databázové změny

Nová tabulka `ai_license_cache` (migrace 024):

| Sloupec | Typ | Popis |
|---------|-----|-------|
| `artifact_id` | TEXT PRIMARY KEY | `ecosystem:name:version[:filename]` |
| `spdx_ids_json` | TEXT | JSON pole canonical SPDX IDs |
| `confidence` | REAL | 0.0–1.0 |
| `explanation` | TEXT | LLM explanation (audit) |
| `model_used` | TEXT | model identifier |
| `tokens_used` | INTEGER | for cost monitoring |
| `created_at` | DATETIME | NOT NULL |
| `expires_at` | DATETIME | NOT NULL — TTL evaluated on read |

DDL (SQLite, identical for Postgres modulo type names):

```sql
CREATE TABLE IF NOT EXISTS ai_license_cache (
    artifact_id   TEXT PRIMARY KEY,
    spdx_ids_json TEXT NOT NULL,
    confidence    REAL NOT NULL,
    explanation   TEXT,
    model_used    TEXT,
    tokens_used   INTEGER,
    created_at    DATETIME NOT NULL,
    expires_at    DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_license_cache_expires ON ai_license_cache(expires_at);
```

Postgres mirror: stejná struktura, `REAL` → `DOUBLE PRECISION`, `DATETIME` → `TIMESTAMPTZ`.

Cleanup: periodický `DELETE FROM ai_license_cache WHERE expires_at < NOW()` v rescan scheduleru. **POZOR (cross-check P4):** rescan scheduler dnes žádný cleanup neprovádí — `internal/rescan/scheduler.go` zpracovává pouze `PENDING_SCAN` artefakty. Existující `triage_cache` tabulka spoléhá na read-time TTL check a expirované řádky se nikdy nemažou. Fáze B MUSÍ implementovat `CleanupExpiredCaches()` metodu spouštěnou na každém rescan cyklu, která čistí jak `ai_license_cache` tak retroaktivně `triage_cache`.

#### Konfigurace

Nová sekce `scanners.ai_license`:

```yaml
scanners:
  ai_license:
    enabled: false                       # opt-in
    bridge_socket: "/tmp/shieldoo-bridge.sock"   # sdílí s ai-scanner
    timeout: "30s"
    cache_ttl: "720h"                    # 30 days
    rate_limit: 5                        # LLM calls per second
    circuit_breaker_threshold: 3
    circuit_breaker_cooldown: "60s"
    max_files_per_artifact: 25           # cap input pro LLM
    max_input_tokens: 16000              # menší než triage (license soubory jsou krátké)
    confidence_threshold: 0.7           # výsledky pod tímto thresholdem se zahazují (cross-check BA F-06)
    sync_mode: false                    # default ASYNC post-serve (cross-check P1); true = sync na scan path
    api_key_env: "AI_SCANNER_API_KEY"   # sdílí s ai-scanner
    azure_endpoint: ""                   # sdílí s ai-scanner
    azure_deployment: "gpt-54-mini"     # sdílí s ai-scanner
```

#### Změny v UI

- `ui/src/components/ArtifactDetailPanel.tsx:267-296` — sekce "Licenses" už zobrazuje `licenses[]`. Přidat:
  - Drobný badge `(detected by AI)` vedle license, pokud `source == "ai_license"`.
  - Tooltip s `explanation` z `ai_license_cache.explanation`.
  - Vyžaduje rozšíření `GET /api/v1/artifacts/{id}/licenses` o `source` field.
- Žádné nové stránky.

### Fázová strategie

Důvod proč to jsou dvě fáze a ne jedna:

1. **A je dramaticky levnější** — pure Go, žádný scanner-bridge change, žádná DB migrace, deterministické. Měl by jít deploynout do v1.3 v rámci jednoho týdne.
2. **B je drahá v engineering čase i runtime** — gRPC schema change, Python prompt iterace, Azure OpenAI cost monitoring, cache plumbing. Sprintový závazek na 2 týdny.
3. **A pokrývá hlavní use case** (Maven enterprise JARs s parent inheritance), který je dnes zlomený. B je doplňkový pro edge cases.
4. **Independent deployment** — A může jet bez B v produkci dlouho. B se přidá až bude business case (zákazník chce 99%+ coverage napříč ekosystémy).

## Dotčené soubory

### Nové soubory — Fáze A

- `internal/maven/effectivepom/resolver.go` — `Resolver`, `Coords`, `NewResolver`, `Resolve`
- `internal/maven/effectivepom/parser.go` — `parsePOM`
- `internal/maven/effectivepom/cache.go` — LRU + TTL wrapper
- `internal/maven/effectivepom/resolver_test.go` — unit testy
- `internal/maven/effectivepom/testdata/` — fixture pomy (s `<licenses>`, bez, s `<parent>`, cyclic, deep)

### Nové soubory — Fáze B

- `internal/scanner/ailicense/scanner.go` — implementuje `scanner.Scanner`
- `internal/scanner/ailicense/cache.go` — DB-backed cache
- `internal/scanner/ailicense/scanner_test.go`
- `internal/config/migrations/sqlite/024_ai_license_cache.sql`
- `internal/config/migrations/postgres/024_ai_license_cache.sql`
- `scanner-bridge/ai_license.py` — Python LLM client
- `scanner-bridge/prompts/license_detection.txt` — system prompt + few-shot examples

### Upravené soubory — Fáze A

- `internal/scanner/interface.go:38-48` — přidat `ExtraLicenses []string` do `Artifact` struct
- `internal/scanner/trivy/trivy.go:108-128` — po existujícím merge přidat merge `artifact.ExtraLicenses` (s normalizací přes `sbom.NameAliasToID`)
- `internal/adapter/maven/maven.go:65-82` — konstruktor přijme `*effectivepom.Resolver`
- `internal/adapter/maven/maven.go:384-417` — invoke resolver před `ScanAll`
- `cmd/shieldoo-gate/main.go:230-250` — vytvoření resolveru z `cfg.Upstreams.Maven`, předání do adapter konstruktoru
- `internal/config/config.go` — nové pole `MavenResolverConfig` v `UpstreamsConfig`
- `config.example.yaml` — nová sekce `upstreams.maven_resolver`
- `docker/config.yaml` — povolit (default true)
- `docs/features/sbom-generation.md` — update kompatibilní matice (Maven přejde z ⚠️ na ✅ pro JARy s parent chainem)

### Upravené soubory — Fáze B

- `scanner-bridge/proto/scanner.proto:1-65` — nová `DetectLicenses` rpc + messages
- `Makefile:proto` — regenerate (existující target)
- `internal/scanner/trivy/trivy.go:108-128` — fallback IF `len(result.Licenses) == 0` AND `aiLicense != nil` → invoke
   - **Alternativa:** zaregistrovat ai-license jako separátní scanner v `scanner.Engine`, přeskočit Trivy modifikaci. Rozhodnutí v plan fázi.
- `internal/scanner/engine.go` — registrace nového scanneru (per-config)
- `cmd/shieldoo-gate/main.go` — instantiation podle `cfg.Scanners.AILicense.Enabled`
- `internal/config/config.go` — `AILicenseConfig` v `ScannersConfig`
- `internal/api/sbom.go:48-90` — `handleGetArtifactLicenses` přidá `source` field do response
- `ui/src/api/types.ts:189` — `ArtifactLicenses` type rozšířit o `source?: 'sbom' | 'ai_license'` a `confidence?: number`
- `ui/src/components/ArtifactDetailPanel.tsx:267-296` — drobný badge "(AI)" + tooltip s explanation
- `internal/rescan/scheduler.go` — periodický DELETE expirovaných řádek z `ai_license_cache`
- `docs/features/license-policy.md` — nová sekce "AI license detection"
- `docs/features/sbom-generation.md` — update kompatibilní matice (cross-ekosystém fallback)

### Soubory BEZ změn (důležité)

- `internal/scanner/trivy/license_extractor.go` — beze změny, parsery zůstávají primary path
- `internal/scanner/trivy/license_extractor_test.go` — beze změny
- `internal/sbom/parser.go:191-225` — alias map roste organicky podle potřeby, ale tato analýza nepřidává nové aliasy
- `internal/policy/engine.go:340-396` — `evaluateLicenses` má `result.Licenses` jako primary input, beze změny
- `internal/license/evaluator.go` — beze změny, normalizace už v scanner layer
- `internal/license/resolver.go` — beze změny
- `internal/api/license_policy.go` — beze změny
- `internal/sbom/storage.go` — beze změny (sbom_metadata write path)
- `internal/scanner/ai/scanner.go` — beze změny (ai-license je separátní scanner; sdílí pouze gRPC client + bridge socket)
- `tests/e2e-shell/test_license_policy.sh:336-381` — Maven test sekce zůstane (log4j-core), pouze přibude druhá assertion s `mysql-connector-j` po Fázi A

## Implementační fáze

### Fáze A: Maven Effective POM Resolver

- **Co je zahrnuto:** přidat Maven do Trivy `SupportedEcosystems` (1 řádek), nový balíček `internal/maven/effectivepom`, integrace do Maven adapteru, `Artifact.ExtraLicenses` field, Trivy merge, konfigurace, dokumentace, testy.
- **Očekávaný výsledek:** Maven JARy mají detekovanou license skrze parent chain. e2e Maven test mění log4j-core na mysql-connector-j jako primary blocked artifact.
- **Závislosti:** žádné (může jít první).

#### Acceptance criteria (cross-check F-04) — Phase A is DONE when:

1. **`com.mysql:mysql-connector-j:8.4.0`** → resolver vrátí `GPL-2.0-only` (parent chain: `mysql-connector-j` → `oss-parent`). E2E `test_license_maven` s blocked=`[GPL-2.0-only]` vrátí HTTP 403.
2. **`org.apache.commons:commons-lang3:3.14.0`** → resolver vrátí `Apache-2.0` (parent chain: `commons-lang3` → `commons-parent` → `apache`). Ověřeno unit testem.
3. **`org.slf4j:slf4j-api:1.7.36`** → resolver vrátí `MIT` (parent chain: `slf4j-api` → `slf4j-parent`). Ověřeno unit testem.
4. **`org.apache.logging.log4j:log4j-core:2.23.1`** → inline `<licenses>` detekováno přímo z embedded pom (Trivy + extractor path), resolver se nevyvolá (inline má přednost). Ověřeno e2e.
5. **`max_depth` exceeded** → resolver vrátí prázdný seznam + warn log. Unit test.
6. **Network failure** → resolver vrátí prázdný seznam (fail-open), request prochází bez license check delay. Unit test.
7. **XML bomb** (billion-laughs POM) → resolver odmítne POM > 1MB, vrátí prázdný seznam. Unit test `TestParser_XMLBomb_DoesNotOOM`.

- [ ] Pre-requisit: přidat `scanner.EcosystemMaven` do `TrivyScanner.SupportedEcosystems()` (`internal/scanner/trivy/trivy.go:59-65`)
- [ ] Návrh resolveru a parseru (s XXE protection, body size cap, CheckRedirect)
- [ ] Implementace LRU cache s TTL
- [ ] Integrace do Maven adapteru a main.go
- [ ] Konfigurační schema + viper bindings
- [ ] Unit testy (parsery + cycle detection + depth limit + cache miss/hit)
- [ ] Update e2e: druhá assertion s `mysql-connector-j` v `test_license_maven`
- [ ] Doc update: `sbom-generation.md` matice + `license-policy.md` Maven coverage
- [ ] Smoke test proti veřejnému Maven Central z lokálního stacku

### Fáze B: AI License Detection Fallback

- **Co je zahrnuto:** nový scanner `internal/scanner/ailicense`, gRPC schema rozšíření, Python LLM client v scanner-bridge, prompt template, DB cache (migrace 024), konfigurace, UI badge.
- **Očekávaný výsledek:** pro každý artifact bez detekované licence (po Trivy + extractor + Effective POM) se spustí AI detekce. Cache hit ratio v ustáleném stavu >90% (artefakty se opakují). Cross-ekosystém pokrytí pro RubyGems `.gem`, exotické JARy, Docker images bez Trivy detekce.
- **Závislosti:** Fáze A by měla být deployed first — sníží počet AI invokací → nižší LLM cost.
- [ ] Návrh prompt template + few-shot examples
- [ ] gRPC schema design + regenerate proto
- [ ] Python `ai_license.py` implementace + retries + circuit breaker (sdílí s ai-scanner)
- [ ] Go `ailicense` scanner + DB cache + dedup logic
- [ ] Migrace 024 (SQLite + Postgres)
- [ ] Engine integration + scanner ordering decision
- [ ] Cleanup hook v rescan scheduleru
- [ ] UI badge + API field rozšíření
- [ ] Konfigurační schema + Helm chart values
- [ ] Manuální e2e: 5 artifactů ze známých ekosystémů, ověřit detekci a confidence
- [ ] Cost monitoring dashboard (existující Prometheus metrics infrastructure — `tokens_used` jako counter)
- [ ] Doc updates (sbom-generation, license-policy, configuration, alerts)

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| **A: Upstream Maven Central rate-limits** parent pom requests | sync scan path se zpomalí, fail-open umožňuje proxy stále serve, ale audit ukáže "license: no parent pom resolved" | Nízká — Maven Central nemá per-IP rate limits pro běžný traffic | LRU cache TTL 24h dramaticky redukuje volume; on persistent failure circuit-breaker auto-disable resolveru po N neúspěších v M sekundách |
| **A: Maliciously deep parent chain** (DoS) | Resolver se zacyklí a vyčerpá goroutine + paměť | Velmi nízká — Maven Central artefakty jsou kurátované, ale interní enterprise repo by mohlo | Hard cap `max_depth: 5` + cycle detection (sledovat `seenCoords map[Coords]bool` během rekurze) |
| **A: Parent pom obsahuje nestandardní license string** | Match selže → false negative (artifact prochází blocked policy) | Střední — některé enterprise pomy mají kreativní license textu | `sbom.NameAliasToID()` alias map se rozšiřuje organicky; admin může přidat aliases bez deployment skrze YAML rules (future); v krátkodobém horizontu loguje `license: ${unknown_string}` do auditu, admin dohledá manuálně |
| **A: Privátní enterprise repo** s autentizovanými pomy | Resolver dostane 401/403, vrátí prázdný seznam | Vysoká pro enterprise zákazníky | Resolver respektuje `upstreams.maven` auth config (Basic auth pass-through), reuse stejných credentials |
| **B: LLM halucinace** — model vrátí license, která tam není | False negative i false positive (audit ukáže blocked, ale skutečně nebyl) | Střední — modely jsou fallible, krátké license soubory většinou OK | Confidence threshold v policy engine (default 0.7); cache umožňuje admin manual override; explanation field v audit logu pro forensic review |
| **B: LLM cost runaway** — vysoký traffic s unique artifacty | Měsíční Azure OpenAI bill exploduje | Nízká — cache TTL 30 dní + popular packages se opakují | Rate limiter (default 5 calls/s), circuit breaker, cost dashboard, kill-switch via `scanners.ai_license.enabled: false` (live config reload) |
| **B: Latence v sync path** — LLM call přidá 1–2s na první scan | Pomalý developer experience pro nové artefakty | Střední | Async option: AI license běží jako async post-serve, blokuje až další request (stejný pattern jako sandbox scanner). Zvážit v plan fázi. |
| **B: Privacy leakage** — license soubory jdou do third-party LLM | Compliance issue (GDPR, IP) — některé kódy obsahují copyright headers s PII | Nízká pro license soubory specificky, ale stojí za ošetření | Document explicitly which files are sent (LICENSE, NOTICE, README, MANIFEST.MF — public files); never source code; admin opt-in; on-prem LLM deployment option pro regulované zákazníky |
| **B: Bridge socket congestion** — ai-license + ai-scanner + guarddog sdílí jeden Unix socket | Throughput hit při high concurrent scans | Střední | Bridge má per-RPC concurrency limits; pokud bottleneck → dedicated socket per scanner type |
| **A+B: Backwards compat** — staré verze klientů parsují `Artifact` struct přímo? | Build break | Nízká — `Artifact` je interní, nejen API | Add field at end of struct, backward-compatible. API responses jsou JSON s `source?` jako optional field. |
| **A+B: Test_license_maven dependency on real Maven Central** v e2e | Flaky tests pokud Maven Central down | Nízká | Existující testy už závisí na Maven Central; fixture-based test pro effectivepom resolver pokrývá edge cases bez network |

## Testování

### Unit testy — Fáze A

- `TestParser_NoLicenses` — pom bez `<licenses>` vrátí `(nil, nil)` plus `<parent>` koords.
- `TestParser_InlineLicenses` — pom s explicitním blokem vrátí `["Apache-2.0"]`.
- `TestParser_ParentReference` — pom s `<parent>` ale bez `<licenses>` vrátí `(nil, &parent)`.
- `TestResolver_DepthLimit` — uměle nastavený `max_depth: 2`, pom hierarchie hloubky 5 → resolver vrátí prázdno + audit warn.
- `TestResolver_CycleDetection` — A→B→A loop → resolver detekuje cycle, vrátí prázdno bez crashe.
- `TestResolver_CacheHit` — dvě volání pro stejný GAV → druhé volání nezpůsobí HTTP request.
- `TestResolver_CacheTTL` — record expires po `cache_ttl`, refetch.
- `TestResolver_NetworkFailure_FailsOpen` — http client vrací error → resolver vrátí `(nil, nil)` (ne error), Maven adapter pokračuje s prázdným ExtraLicenses.
- `TestResolver_RealMavenCentral_MysqlConnectorJ` (`-tags integration`) — proti reálnému Maven Central, ověří GPL-2.0 detekce přes parent chain `com.mysql:mysql-connector-j → oss-parent`.

### Unit testy — Fáze B

- `TestAILicense_CacheHit` — dva sequential scany stejného artifactu → druhý nedělá gRPC call.
- `TestAILicense_CacheMiss` — fresh artifact → gRPC call + cache write.
- `TestAILicense_CacheExpired` — record po TTL → re-fetch.
- `TestAILicense_RateLimitExceeded` — rate limiter triggernutý → empty result + audit warn (fail-open).
- `TestAILicense_CircuitBreakerOpen` — N failures → circuit breaker open → další volání skip bez gRPC.
- `TestAILicense_BridgeUnreachable` — gRPC dial fail → fail-open, scanner reportuje empty.
- `TestAILicense_LowConfidenceFiltered` — LLM vrátí license s confidence < threshold → ignorováno.
- `TestPromptBuilder_FileSelection` — adresář s 100 soubory → builder vybere max 25 dle priority (LICENSE > NOTICE > MANIFEST > README > zdrojové headers).

### Integrační / manuální testy — Fáze A

- E2E test `test_license_maven` upravený: druhá assertion s `mysql-connector-j:8.4.0` (po fázi A musí být 403); `slf4j-api:1.7.36` (přes parent přes parent dorazí na MIT) dle policy buď allow nebo block.
- Manual test: `curl -u "lic-test:test-token-123" http://localhost:8085/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.jar` vrátí 403 s reason obsahujícím "GPL-2.0".

### Integrační / manuální testy — Fáze B

- E2E `test_license_rubygems` přejde z `log_skip` na `log_pass` po fázi B (AI fallback detekuje Apache-2.0 z `aws-sdk-core`).
- Manual: vypnout extractor (mock), zapnout AI scanner, fetchnout `requests` (Apache-2.0) → audit ukáže `LICENSE_BLOCKED` s `source: "ai_license"` a non-zero `tokens_used`.
- Cost smoke test: fetchnout 100 unique artifactů → ověřit token spend < $0.50 (gpt-4o-mini ceník 2026-04).

### Verifikace

```bash
# Build + lint po každé fázi
go build ./...
go vet ./...
go test ./internal/maven/effectivepom/... -v
go test ./internal/scanner/ailicense/... -v

# Plné e2e
make test-e2e-containerized

# Grep kontrola — žádné pozůstatky log4j workaround komentářů
grep -rn "Maven license-enforcement caveat" tests/ docs/

# Migrace check (Phase B)
grep -E "024_ai_license_cache" internal/config/migrations/{sqlite,postgres}/

# Dokumentace cross-ref
grep -E "Effective POM|AI license" docs/features/sbom-generation.md docs/features/license-policy.md
```

## Poznámky

- **Idempotence:** Effective POM resolver je čistý GET — bezpečně retryable. AI license detection má cache, ale samotné LLM volání není idempotentní (model vrátí trochu jiný text při dvojím volání) — `spdx_ids` ale po normalizaci budou identické.
- **Edge cases (Fáze A):**
  - Maven `pom-only` artifacts (žádný JAR, jen pom): typicky aggregator/BOM poms — license většinou není relevant; resolver i tak funguje.
  - SNAPSHOT versioning: `1.0.0-SNAPSHOT` poms se mohou měnit v čase; cache TTL 24h je rozumný kompromis (releases jsou immutable, snapshots tolerují krátkou inconsistency).
  - Klasifikátory (`mysql-connector-j-8.4.0-sources.jar`, `-javadoc.jar`): mají vlastní pomy? Ano — typicky stejný pom jako main artifact. Resolver bere main pom (bez classifieru), reuses cache.
- **Edge cases (Fáze B):**
  - Multi-license artifacts (`MIT OR Apache-2.0`): LLM by měl vracet expression nebo array. `spdx_ids: ["MIT", "Apache-2.0"]` + downstream evaluator zachází jako s expression dle `or_semantics` config.
  - Empty artifact: directory s 0 soubory → builder skip, return empty bez gRPC volání (avoid wasted token).
  - Encrypted/binary-only artifacts: LLM vrátí "no license found" s nízkou confidence → unknown_action handle.
- **Performance:** A přidá max +30s na první scan Maven JARu (cap parent chain × fetch_timeout) ale typicky <500ms (cache hit dominates). B přidá +0.5–2s per uncached artifact, 0ms na cache hit.
- **Backwards compatibility:** Žádná. `Artifact.ExtraLicenses` je nové pole (zero value je nil — stejné chování jako dnes). `ai_license_cache` je nová tabulka. Žádné existující řádky se nemění.
- **Rollback strategy:** A: `upstreams.maven_resolver.enabled: false` v configu → resolver se neinstanciuje, `Artifact.ExtraLicenses` zůstane nil, vše funguje jako dnes. B: `scanners.ai_license.enabled: false` → scanner se neinstanciuje, žádná cache lookup, žádné LLM volání.
- **Self-build dogfood (CLAUDE.md):** Effective POM resolver poběží i pro vlastní Shieldoo Gate go modules build path? Ne — Go moduly nejdou přes Maven proxy. Žádný self-impact.
- **Security invariants (CLAUDE.md "NEVER Violate"):**
  - Audit log zůstává append-only — nové AI license records nepřidávají UPDATE/DELETE na audit_log, pouze na `ai_license_cache`.
  - Quarantined artifact se NIKDY neslouží — no change, license check je orthogonal k quarantine status.
  - Authorization headers se v AI license payload NESMÍ logovat — prompt builder explicitly excludes credentials.
  - Pinned scanner deps — Python `ai_license.py` přidá závislosti (openai SDK už pinned via `requirements.txt`), žádná unpinned.

## Reference

- Existující implementace AI scanneru (vzor pro Fázi B): `internal/scanner/ai/scanner.go`, `scanner-bridge/ai_scanner.py`, `scanner-bridge/prompts/` (gitignored adresář pro citlivé prompts? Ne — prompts jsou v repu)
- Triage cache pattern (vzor pro `ai_license_cache`): `internal/policy/engine.go` `triageCache` + migrace `014_triage_cache.sql`
- Maven Central Repository [URL conventions](https://maven.apache.org/repository/layout.html)
- [Maven POM Reference — Inheritance](https://maven.apache.org/pom.html#inheritance) — chování `<parent>` rozlišení
- Aktuální license matice: [docs/features/sbom-generation.md](../features/sbom-generation.md#ecosystem-coverage)
- Aktuální license policy doc: [docs/features/license-policy.md](../features/license-policy.md)
- Pivot rationale (log4j-core workaround) v této session: e2e v6/v7 byla 502 → 200 → fix
- ADR-002 *(SBOM Storage via BlobStore Sub-Interface)*: [docs/adr/ADR-002-sbom-storage-via-blobstore-subinterface.md](../adr/ADR-002-sbom-storage-via-blobstore-subinterface.md) — precedent pro decoupling scanner z storage
