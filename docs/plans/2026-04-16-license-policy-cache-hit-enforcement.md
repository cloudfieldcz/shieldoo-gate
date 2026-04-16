# License Policy Enforcement na Cache-Hit Path — Odstranění policy bypass

## Popis

Při servírování cached artefaktů se **nikdy neprovádí kontrola license policy**. Artefakty
s blokovanou licencí jsou klientům servírovány bez omezení, pokud byly poprvé staženy před
změnou policy.

### Proč

- **Security/compliance gap**: Změna license policy (např. blokování MIT) se nepromítne do
  cached artefaktů. Klienti je stahují dál bez jakéhokoliv upozornění.
- **Legal riziko**: Organizace nemůže garantovat, že blokovaná licence se nedostane do produkce.
- **Porušení principu "license policy je nadřazená"**: I manuálně uvolněný artefakt z karantény
  musí být blokován, pokud má blokovanou licenci.

## Aktuální stav

### Cache-hit serve flow (identický ve všech 7 adapterech)

```
Request → cache.Get() → hit?
  → GetArtifactStatus() → QUARANTINED? → block
  → VerifyCacheIntegrity() → SHA256 OK?
  → [NO LICENSE CHECK]
  → http.ServeFile() ← SERVÍRUJE SE BEZ KONTROLY LICENCE
```

Dotčené soubory a řádky (cache-hit serve body):

| Adapter   | Soubor                              | 1. cache-hit | 2. cache-hit (post-lock) |
|-----------|-------------------------------------|-------------|--------------------------|
| PyPI      | `internal/adapter/pypi/pypi.go`     | :189-231    | :282-308                 |
| npm       | `internal/adapter/npm/npm.go`       | :233-268    | :296-321                 |
| NuGet     | `internal/adapter/nuget/nuget.go`   | :263-298    | :321-346                 |
| Maven     | `internal/adapter/maven/maven.go`   | :295-331    | :354-379                 |
| RubyGems  | `internal/adapter/rubygems/rubygems.go` | :284-320 | :343-368                |
| Go Mod    | `internal/adapter/gomod/gomod.go`   | :296-334    | :357-383                 |
| Docker    | `internal/adapter/docker/docker.go` | :586-633    | :656-689                 |

### Fresh-scan flow (licence SE kontroluje)

```
Request → cache miss → download → ScanAll() → policyEngine.Evaluate()
  → evaluateLicenses() → licenseResolver.ResolveForProject() → licenseEval.Evaluate()
  → ActionBlock? → 403
```

`policy/engine.go:352-424` — `evaluateLicenses()` se volá **pouze** z `Evaluate()`,
které se volá pouze na fresh-scan path a při manuálním rescanu.

### Při změně policy (nic se neděje)

```
PUT /api/v1/policy/licenses → SetGlobal(newPol) → cache.Purge()
  → [NO RE-EVALUATION OF CACHED ARTIFACTS]
  → next fresh-scan request uses new policy ← ale cache-hity NE
```

| Aspekt | Současný stav | Navrhovaný stav |
|--------|---------------|-----------------|
| Cache-hit license check | Žádný | Lightweight check proti aktuální policy |
| Policy change reaction | Žádná | Async re-evaluation všech artefaktů |
| License vs. scanner priority | License jen na fresh scan | License vždy nadřazená |
| Audit trail při policy change | Žádný | LICENSE_BLOCKED/LICENSE_WARNED eventy |

## Návrh řešení

### Architektura

Dva nezávislé mechanismy (defense-in-depth):

**Fix A — Cache-hit license gate (synchronní, na serve path):**
Nová funkce v `adapter/base.go` volaná ze všech adapterů před `http.ServeFile()`.
Načte SBOM metadata z DB, vyhodnotí licence proti aktuální policy přes existující
`policyEngine`. Pokud ActionBlock → 403, pokud ActionWarn → X-Shieldoo-Warning header.

**Fix B — Policy-change re-evaluation (async, na API path):**
Při `PUT /api/v1/policy/licenses` (globální i per-project) se po uložení policy
spustí async goroutina, která projde všechny CLEAN artefakty s SBOM metadaty,
vyhodnotí licence proti nové policy, a quarantinuje/uvolní dle výsledku.

### Databázové změny

N/A — žádné schéma změny. Využíváme existující `sbom_metadata.licenses_json` a
`artifact_status`.

### Změny v servisní vrstvě

#### Fix A — `adapter/base.go`: nová funkce

```go
// CheckLicensePolicy performs a lightweight license policy check for
// cached artifacts. Returns (block bool, warnings []string).
// Uses sbom_metadata.licenses_json — no rescan needed.
func CheckLicensePolicy(ctx context.Context, policyEngine *policy.Engine, artifactID string) (block bool, reason string, warnings []string)
```

Interně volá novou metodu na policy engine:

```go
// Engine.EvaluateLicensesOnly checks stored SBOM licenses against the
// current policy without requiring scan results. For cache-hit path.
func (e *Engine) EvaluateLicensesOnly(ctx context.Context, artifactID string) PolicyResult
```

Tato metoda reusuje `evaluateLicenses()` s prázdným `scanResults` — existující
fallback na `sbom_metadata.licenses_json` (engine.go:384-391) se automaticky aktivuje.

#### Fix B — `api/global_license_policy.go` + `license_policy.go`: async re-evaluation

```go
// triggerLicenseReEvaluation re-evaluates all CLEAN artifacts against
// the current license policy and quarantines/releases as needed.
func (s *Server) triggerLicenseReEvaluation(ctx context.Context, reason string)
```

Pattern podle existujícího rescan scheduleru (`scheduler/rescan.go:276-304`):
- SELECT all CLEAN artifacts s neprázdným `sbom_metadata.licenses_json`
- Pro každý: `policyEngine.EvaluateLicensesOnly()` → UPDATE artifact_status + audit log

### Konfigurace

N/A — žádná nová konfigurace. License policy enforcement je implicitně zapnuté,
pokud je `policy.licenses.enabled: true` (což je defaultní stav).

## Dotčené soubory

### Nové soubory

Žádné — vše jde do existujících souborů.

### Upravené soubory

- `internal/policy/engine.go:352-424` — nová public metoda `EvaluateLicensesOnly()` reusující `evaluateLicenses()`
- `internal/adapter/base.go` — nová funkce `CheckLicensePolicy()` volaná z adapterů
- `internal/adapter/pypi/pypi.go:228-231, :305-308` — vložení license check před ServeFile
- `internal/adapter/npm/npm.go:265-268, :319-321` — dtto
- `internal/adapter/nuget/nuget.go:295-298, :344-346` — dtto
- `internal/adapter/maven/maven.go:328-331, :377-379` — dtto
- `internal/adapter/rubygems/rubygems.go:317-320, :366-368` — dtto
- `internal/adapter/gomod/gomod.go:331-334, :381-383` — dtto
- `internal/adapter/docker/docker.go:630-633, :687-689` — dtto
- `internal/api/global_license_policy.go:183-191` — trigger async re-evaluation po SetGlobal
- `internal/api/license_policy.go:175-177, :197-199` — trigger async re-evaluation po InvalidateProject
- `internal/api/server.go` — (bez změn, pole `policyEngine` a `sbomStore` již existují)
- `docs/features/sbom-generation.md` — aktualizace "Known Limitations"

### Soubory BEZ změn

- `internal/sbom/storage.go` — metadata query `GetMetadata()` již existuje, stačí volat
- `internal/license/evaluator.go` — evaluátor se nemění, reuse přes engine
- `internal/license/resolver.go` — resolver se nemění, `SetGlobal`/`InvalidateProject` již fungují
- `internal/scanner/` — scannery se nevytahují, licence se berou z DB
- `ui/` — UI nepotřebuje změny

## Implementační fáze

### Fáze 1: Cache-hit license gate (Fix A)

- Nová metoda `EvaluateLicensesOnly()` na policy engine
- Nová helper `CheckLicensePolicy()` v `adapter/base.go`
- Integrace do VŠECH 7 adapterů (14 insertion points)
- Unit testy pro engine + adapter helper
- Integrační test: block MIT → cache-hit request → 403

**Závislosti:** žádné
**Výsledek:** Cache-hity okamžitě respektují aktuální license policy

### Fáze 2: Policy-change re-evaluation (Fix B)

- Nová metoda `triggerLicenseReEvaluation()` na API serveru
- Volání z PUT/DELETE global policy + PUT/DELETE project policy
- Audit log eventy pro každý quarantinovaný/uvolněný artefakt
- Unit testy pro re-evaluation logiku
- Integrační test: artifact CLEAN → block MIT → API call → artifact QUARANTINED

**Závislosti:** Fáze 1 (reuse `EvaluateLicensesOnly()`)
**Výsledek:** Změna policy proaktivně quarantinuje/uvolní artefakty

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|--------|-------|-----------------|----------|
| Latence na cache-hit path | Přidání DB query (~1ms) na každý serve | Nízký dopad | `GetMetadata()` je single-row PK lookup; negligible vs. network I/O |
| Race condition: policy change vs. concurrent serve | Artefakt se servíruje se starou policy | Nízký | Defense-in-depth: Fix A blokuje na dalším requestu, Fix B quarantinuje async |
| Re-evaluation na velké DB | Tisíce artefaktů s SBOM metadata | Střední | Async goroutina, batch processing, rate limiting |
| False positive quarantine | Admin změní policy omylem, artefakty se quarantinují | Střední | Audit trail umožňuje rychlé release; policy je pod admin kontrolou |

## Testování

### Unit testy

- `TestEvaluateLicensesOnly_BlockedLicense_ReturnsBlock`
- `TestEvaluateLicensesOnly_AllowedLicense_ReturnsAllow`
- `TestEvaluateLicensesOnly_NoSBOM_RespectsOnSBOMError`
- `TestEvaluateLicensesOnly_DisabledPolicy_ReturnsAllow`
- `TestCheckLicensePolicy_BlockedLicense_ReturnsTrue`
- `TestCheckLicensePolicy_NoSBOMMetadata_Allows`
- `TestTriggerLicenseReEvaluation_BlocksMIT_QuarantinesArtifact`
- `TestTriggerLicenseReEvaluation_UnblocksMIT_ReleasesArtifact`

### Integrační / manuální testy

1. Install `chalk@5.4.1` (MIT) → cache-hit → serve OK
2. Block MIT v policy → stáhni chalk znovu → **403 LICENSE_BLOCKED**
3. Verify audit log obsahuje LICENSE_BLOCKED event
4. Unblock MIT → stáhni chalk → **200 OK**
5. Block MIT → verify artifact_status přešel na QUARANTINED (Fix B)
6. Unblock MIT → verify artifact_status přešel zpět na CLEAN (Fix B)

### Verifikace

```bash
make build && make test
# Playwright test
cd ui && npx playwright test e2e/licenses.spec.ts
```

## Poznámky

- **License policy je nadřazená scanner policy**: I artefakt manuálně uvolněný z
  karantény musí být blokován, pokud má blokovanou licenci. Fix A to zajišťuje —
  kontroluje se na serve path nezávisle na artifact_status.
- **Idempotence Fix B**: Re-evaluation je idempotentní — pokud artefakt už je QUARANTINED
  z jiného důvodu (scanner), neměníme quarantine_reason. Pokud je QUARANTINED kvůli licenci
  a licence je teď povolená, uvolníme ho zpět na CLEAN.
- **Zpětná kompatibilita**: Žádné breaking changes. Artefakty bez SBOM metadata (pre-v1.2)
  se chovají podle `on_sbom_error` policy (default: allow).

## Reference

- `internal/policy/engine.go:352-424` — existující `evaluateLicenses()`
- `internal/scheduler/rescan.go:255-351` — pattern pro re-evaluation + status update
- `docs/features/sbom-generation.md` — SBOM architecture
- `docs/features/license-policy.md` — license policy docs
