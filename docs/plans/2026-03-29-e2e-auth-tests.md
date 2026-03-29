# E2E testy s proxy autentizací — Druhý běh s povoleným auth

## Popis

Přidat do E2E test suite druhý běh, kde je `proxy_auth.enabled=true`. Všechny existující testy (PyPI, npm, NuGet, Docker, Maven, RubyGems, GoMod) musí projít i s povolenou autentizací. `make test-e2e-containerized` spustí obě sady sekvenčně.

### Proč

- Proxy auth je klíčová bezpečnostní funkce, ale dosud se testovala izolovaně (jen `test_proxy_auth.sh`)
- Potřebujeme ověřit, že celý ekosystém (všechny package managery) funguje s auth
- Regresní ochrana — při změnách auth middleware se nerozbijí reálné instalační flows

## Aktuální stav

### Jak testy fungují dnes

1. **Makefile** (`Makefile:17-20`): `test-e2e-containerized` spustí compose jednou, test-runner provede všechny testy, compose down
2. **helpers.sh** (`tests/e2e-shell/helpers.sh:38-46`): URL proměnné pro každý ekosystém (`E2E_PYPI_URL`, `E2E_NPM_URL`, ...)
3. **assert_http_status** (`helpers.sh:124-131`): curl bez jakýchkoli auth hlaviček
4. **run_all.sh**: spouští test funkce sekvenčně, na konci `print_summary`
5. **test_proxy_auth.sh**: samostatný test, skip pokud `SGW_PROXY_AUTH_ENABLED != true`

### Kde se v testech volá curl/package managery

| Test soubor | Přímé curl volání | Package manager | Konfigurace URL |
|---|---|---|---|
| `test_pypi.sh` | `curl -sf "${E2E_PYPI_URL}/simple/"` | `uv pip install --index-url` | URL v argumentu |
| `test_npm.sh` | `curl -sf "${E2E_NPM_URL}/is-odd"` | `npm install --registry` + `.npmrc` | URL v argumentu + soubor |
| `test_nuget.sh` | `curl -sf "${E2E_NUGET_URL}/v3/index.json"` | `dotnet restore --configfile nuget.config` | XML config soubor |
| `test_docker_registry.sh` | mnoho curl volání na `${E2E_DOCKER_URL}` | `crane manifest/copy --insecure` | `E2E_DOCKER_REGISTRY_HOST` |
| `test_maven.sh` | `curl -sf "${E2E_MAVEN_URL}/..."` | žádný (jen curl) | URL přímo |
| `test_rubygems.sh` | `curl -sf "${E2E_RUBYGEMS_URL}/..."` | žádný (jen curl) | URL přímo |
| `test_gomod.sh` | `curl -sf "${E2E_GOMOD_URL}/..."` | žádný (jen curl) | URL přímo |

### Compose env vars (`docker-compose.e2e.yml`)

Gate i test-runner dostávají:
```yaml
SGW_PROXY_AUTH_ENABLED: "${SGW_PROXY_AUTH_ENABLED:-false}"
SGW_PROXY_TOKEN: "${SGW_PROXY_TOKEN:-}"
```

### Gate config (`config.e2e.yaml:91-94`)

```yaml
proxy_auth:
  enabled: false
  global_token_env: "SGW_PROXY_TOKEN"
```

Gate podporuje override konfigurace přes env vars (viper: `SGW_PROXY_AUTH_ENABLED` → `proxy_auth.enabled`).

| Aspekt | Současný stav | Navrhovaný stav |
|---|---|---|
| E2E run count | 1 | 2 (no-auth + auth) |
| Auth v test helperech | Žádná | Podmíněná Basic Auth hlavička |
| Package manager auth | Jen v `test_proxy_auth.sh` | Ve všech test souborech |
| Compose run | 1× bez auth | 1× bez auth, pak 1× s auth |

## Návrh řešení

### Architektura

**Přístup:** Dvě sekvenční spuštění stejného docker-compose s různými env vars.

```
make test-e2e-containerized
  ├─ Run 1: SGW_PROXY_AUTH_ENABLED=false (jako dnes)
  │   └─ test_proxy_auth() → SKIP (auth disabled)
  │
  ├─ docker compose down -v (čistý stav)
  │
  └─ Run 2: SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=e2e-test-token-xxx
      ├─ Všechny testy projdou s auth hlavičkami
      └─ test_proxy_auth() → runs (auth enabled)
```

**Proč ne druhý compose soubor:** Zbytečná duplikace. Stačí env var override — gate podporuje viper env override `SGW_PROXY_AUTH_ENABLED=true`.

### Změny v helpers.sh

Přidat globální proměnné pro auth a wrapper funkce:

```bash
# Auth configuration (set when SGW_PROXY_AUTH_ENABLED=true)
E2E_AUTH_HEADER=""
E2E_AUTH_USERINFO=""  # user:pass@ prefix pro URL
if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ] && [ -n "${SGW_PROXY_TOKEN:-}" ]; then
    E2E_AUTH_HEADER="-u ci-bot:${SGW_PROXY_TOKEN}"
    E2E_AUTH_USERINFO="ci-bot:${SGW_PROXY_TOKEN}@"
fi
```

Modifikovat `assert_http_status`:
```bash
assert_http_status() {
    local desc="$1" expected_status="$2" url="$3"
    local actual_status
    # shellcheck disable=SC2086
    actual_status=$(curl -s -o /dev/null -w "%{http_code}" $E2E_AUTH_HEADER "$url")
    assert_eq "$desc" "$expected_status" "$actual_status"
}
```

Přidat helper pro auth URL (pro package managery):
```bash
# auth_url "http://host:port" → "http://ci-bot:token@host:port"
auth_url() {
    local url="$1"
    if [ -n "$E2E_AUTH_USERINFO" ]; then
        echo "${url//:\/\//:\/\/${E2E_AUTH_USERINFO}}"
    else
        echo "$url"
    fi
}
```

### Změny v jednotlivých testech

Každý test musí přidat auth do přímých curl volání a package manager konfigurací:

**test_pypi.sh:**
- `curl -sf $E2E_AUTH_HEADER "${E2E_PYPI_URL}/simple/"` (přímé curl)
- `uv pip install --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/"` (uv)

**test_npm.sh:**
- `curl -sf $E2E_AUTH_HEADER "${E2E_NPM_URL}/is-odd"` (přímé curl)
- `.npmrc`: přidat `_auth=base64(ci-bot:token)` když auth enabled
- `npm install --registry "$(auth_url "${E2E_NPM_URL}")"` (npm)

**test_nuget.sh:**
- `curl -sf $E2E_AUTH_HEADER "${E2E_NUGET_URL}/v3/index.json"` (přímé curl)
- `nuget.config`: přidat `<add key="ClearTextPassword" value="token" />` dynamicky

**test_docker_registry.sh:**
- `curl -s $E2E_AUTH_HEADER -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/"` (curl)
- `crane`: env var `CRANE_INSECURE=true` + basic auth via `.docker/config.json` nebo `--username/--password`

**test_maven.sh, test_rubygems.sh, test_gomod.sh:**
- Pouze curl volání → přidat `$E2E_AUTH_HEADER` ke každému

### Změny v Makefile

```makefile
test-e2e-containerized:
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml build
	@echo "=== E2E Run 1: No authentication ==="
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
		--abort-on-container-exit --exit-code-from test-runner
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v
	@echo "=== E2E Run 2: Proxy authentication enabled ==="
	SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=e2e-test-token-shieldoo \
		docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
		--abort-on-container-exit --exit-code-from test-runner
	SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=e2e-test-token-shieldoo \
		docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v
```

### Konfigurace

Žádná nová config hodnota. Vše řízené env vars:
- `SGW_PROXY_AUTH_ENABLED=true` — viper override → `proxy_auth.enabled=true`
- `SGW_PROXY_TOKEN=e2e-test-token-shieldoo` — globální token pro testy

## Dotčené soubory

### Upravené soubory
- `Makefile:17-20` — druhý compose run s auth env vars
- `tests/e2e-shell/helpers.sh:38-46,124-131` — auth proměnné, `assert_http_status` s auth, `auth_url` helper
- `tests/e2e-shell/test_pypi.sh:19,45-50` — auth do curl a uv pip install
- `tests/e2e-shell/test_npm.sh:19,34-44` — auth do curl, .npmrc s auth, npm install
- `tests/e2e-shell/test_nuget.sh` — auth do curl, nuget.config s credentials
- `tests/e2e-shell/test_docker_registry.sh:88-117,134,165,177,182,198` — auth do curl a crane
- `tests/e2e-shell/test_maven.sh` — auth do curl volání
- `tests/e2e-shell/test_rubygems.sh` — auth do curl volání
- `tests/e2e-shell/test_gomod.sh` — auth do curl volání

### Soubory BEZ změn
- `internal/auth/apikey.go` — middleware je hotový, funguje
- `internal/config/config.go` — ProxyAuthConfig existuje
- `tests/e2e-shell/test_proxy_auth.sh` — existující testy zůstanou, jen se poprvé reálně spustí
- `tests/e2e-shell/test_api.sh` — admin API nemá auth (jiný port/listener)
- `tests/e2e-shell/config.e2e.yaml` — `proxy_auth.enabled: false` v souboru, override přes env var
- `tests/e2e-shell/docker-compose.e2e.yml` — env vars propagace již existuje

## Implementační fáze

### Fáze 1: Auth helpers a Makefile

Úprava helpers.sh (auth proměnné, `assert_http_status`, `auth_url` helper) a Makefile (druhý run).

- Očekávaný výsledek: infrastruktura pro auth testy připravená
- Závislosti: žádné
- [ ] Přidat E2E_AUTH_HEADER a E2E_AUTH_USERINFO do helpers.sh
- [ ] Přidat `auth_url()` helper funkci
- [ ] Upravit `assert_http_status()` na použití auth
- [ ] Upravit Makefile — dvě sekvenční spuštění

### Fáze 2: Úprava všech test souborů

Přidat auth do přímých curl volání a package manager konfigurací v každém testu.

- Očekávaný výsledek: všech 8 test souborů funguje s i bez auth
- Závislosti: Fáze 1
- [ ] test_pypi.sh — curl + uv pip install s auth
- [ ] test_npm.sh — curl + .npmrc + npm install s auth
- [ ] test_nuget.sh — curl + nuget.config s auth
- [ ] test_docker_registry.sh — curl + crane s auth
- [ ] test_maven.sh — curl s auth
- [ ] test_rubygems.sh — curl s auth
- [ ] test_gomod.sh — curl s auth

### Fáze 3: Spuštění a ověření

- [ ] `make test-e2e-containerized` — oba běhy projdou
- [ ] Ověřit, že Run 1 (bez auth) prochází beze změn
- [ ] Ověřit, že Run 2 (s auth) prochází se všemi testy

## Rizika a mitigace

| Riziko | Dopad | Pravděpodobnost | Mitigace |
|---|---|---|---|
| Druhý run zdvojnásobí dobu E2E testů | Střední | Vysoká | Akceptovatelné — auth je kritická funkce. Trivy cache přežije (volume se smaže, ale Docker layer cache ne). Druhý run bude rychlejší. |
| npm auth konfigurace je komplikovaná | Nízký | Střední | npm podporuje `_auth` v `.npmrc` — ověřený pattern z `test_proxy_auth.sh` |
| crane auth pro Docker | Nízký | Střední | crane podporuje `--username` + `--password` flags |
| NuGet auth v nuget.config | Nízký | Nízká | dotnet CLI podporuje `ClearTextPassword` v package source credentials |
| Docker Hub rate limit při druhém runu | Střední | Střední | Druhý run využije cached images (pokud se neudělá `down -v` předčasně). Alternativně: skip Docker Hub pulls pokud cache existuje. |

## Testování

### Unit testy
- N/A — jedná se čistě o E2E test infrastrukturu

### Integrační / manuální testy
- `make test-e2e-containerized` — kompletní suite
- Run 1 (bez auth): všechny existující testy projdou beze změny chování
- Run 2 (s auth): všechny testy projdou s Basic Auth credentials
- `test_proxy_auth` se reálně spustí v Run 2 (dnes skip)

### Verifikace
```bash
make test-e2e-containerized
# Očekáváno: oba runy exit 0
```

## Poznámky

- **Zpětná kompatibilita:** Run 1 (bez auth) je identický s dnešním chováním. Žádná breaking change.
- **Idempotence:** `$E2E_AUTH_HEADER` je prázdný string když auth disabled → curl ho ignoruje (shellcheck: `# shellcheck disable=SC2086` pro word splitting).
- **Admin API nepotřebuje auth:** Admin API běží na jiném portu (8080) a je chráněn OIDC, ne proxy auth. V E2E s `auth.enabled=false` je otevřený.
- **Token v env var:** `e2e-test-token-shieldoo` je test-only token, nikdy se nepoužije v produkci.

## Reference

- `tests/e2e-shell/test_proxy_auth.sh` — existující auth testy (vzor pro auth URL)
- `internal/auth/apikey.go` — proxy auth middleware implementace
- `tests/e2e-shell/helpers.sh` — test infrastructure
