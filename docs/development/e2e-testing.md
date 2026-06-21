# End-to-End (E2E) Testing

This page is the **complete reference** for the `tests/e2e-shell/` harness — what
it covers, how the stack is wired, how each ecosystem and scanner surface is
exercised, and (in depth) **how the multi-upstream-index behaviour is tested**.
It is the source of truth for the shell E2E suite.

> **Why a separate test tier?** Unit and `httptest` integration tests prove the
> logic in isolation. The E2E tier proves the **full stack** behaves correctly
> against *real* package-manager clients (`pip`/`uv`, `npm`, `dotnet`, `crane`,
> `mvn`, `gem`, `go`) and *real* upstreams over *real* TLS. Several classes of bug
> — a metadata URL rewrite that doubles a path, a CA-trust misconfiguration, a
> scan **bypass** — only surface here. See the
> [Phase 4 outcome](../plans/2026-06-19-multi-upstream-indexes-plan-index.md#phase-4-outcome-e2e-executed--release-gate-proven)
> for a real bug this tier caught that unit tests could not.

---

## 1. How to run

### 1.1 Containerized (canonical)

The suite runs **inside a `test-runner` container** that has every client
pre-installed. This is the canonical mode — it is what CI runs and what the
182/0 release-gate numbers come from.

```bash
# single strict pass (fastest; the build is cached after the first run)
SGW_POLICY_MODE=strict docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
  --abort-on-container-exit --exit-code-from test-runner > /tmp/e2e.log 2>&1
docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v --remove-orphans
tail -n 120 /tmp/e2e.log
```

> **Logfile convention (repo standard):** always redirect E2E output to a temp log
> file and `tail` it — the output is long and interleaved across containers. Run
> the suite **once at a time**: two concurrent `up` invocations collide on the
> compose project name (`shieldoo-e2e`) and SIGKILL each other.

`--exit-code-from test-runner` makes the whole `up` exit with the test-runner's
status, so a single non-zero assertion fails the command. `down -v` removes the
named volumes so the next run starts from a clean DB/cache.

### 1.2 The three containerized passes (`make test-e2e-containerized`)

`make test-e2e-containerized` runs the **same suite three times** against
different infrastructure to prove backend-independence. Each pass tears the stack
down with `down -v` (fresh volumes) before the next:

| Pass | Policy mode | DB | Cache | Proxy auth | Extra |
|---|---|---|---|---|---|
| 1 | `strict` | SQLite | local FS | off | baseline |
| 2 | `balanced` | PostgreSQL | S3 (MinIO) | on (PAT) | strict projects + license enforcement + AI triage (`docker-compose.e2e.auth.yml`) |
| 3 | `permissive` | PostgreSQL | Azure Blob (Azurite) | on | `docker-compose.e2e.azurite.yml` |

The multi-index tests run in **every** pass. Many auxiliary suites self-skip in
pass 1 because they require proxy auth or PostgreSQL (see §6 on skips).

### 1.3 Host mode (`run.sh`) — a lighter subset

`./tests/e2e-shell/run.sh` brings the stack up with `docker compose` and runs a
**subset** of the tests **from your host** using locally installed clients. It is
a developer convenience, **not** the canonical suite — see §3.3 for exactly how it
differs from the containerized runner and why.

```bash
./tests/e2e-shell/run.sh            # build + run + teardown
./tests/e2e-shell/run.sh --no-build # reuse already-built images
./tests/e2e-shell/run.sh --keep     # leave the stack up for debugging
```

Host mode needs `docker`, `curl`, `jq`, `uv`, `node`/`npm`, and `crane` on
`PATH` (`dotnet` optional — NuGet self-skips without it).

### 1.4 Go-based E2E (`make test-e2e`)

A separate, smaller Go E2E suite lives under `tests/e2e/` and is run with
`make test-e2e`. It is out of scope for this page, which documents the shell
suite.

---

## 2. Stack architecture

The stack is defined in `tests/e2e-shell/docker-compose.e2e.yml` (compose project
`shieldoo-e2e`). Passes 2 and 3 layer in `docker-compose.e2e.auth.yml` /
`docker-compose.e2e.azurite.yml`.

### 2.1 Services

| Service | Role | Notes |
|---|---|---|
| `shieldoo-gate` | **The system under test.** | Built from `docker/Dockerfile`; trusts the test CA via `SSL_CERT_FILE`; healthchecked on `/api/v1/health`; mounts `config.e2e.yaml`. |
| `scanner-bridge` | Python GuardDog/AI sidecar | gRPC over a shared Unix-socket volume (`e2e-bridge-socket`). Also mounts the gate cache **read-only** so the version-diff scanner can open the previous cached artifact. |
| `private-index` | **HTTPS private upstream** (Caddy `2.8.4`) | Serves **all six** ecosystems' private fixtures from one `www/` tree at `https://private-index:8443`. The heart of multi-index testing — see §5. |
| `ca-init` | CA bundler | Concatenates the gate image's system roots **+** the test CA into the shared `e2e-ca` volume, then **stays alive** (`tail -f`) — see §2.3. |
| `push-registry` | Local `registry:2.8.3` | Only the Docker **push** target — *not* an upstream. |
| `docker-dind` | Docker-in-Docker (privileged, test-only) | Backs the `docker`/`crane` registry tests. Never used in production. |
| `test-runner` | Runs the suite (containerized mode) | Built from `Dockerfile.test-runner`; all clients pre-installed; entrypoint `CMD ["./run_all.sh"]`; exits non-zero on any failure. |

> **There is no `trivy` service.** Trivy is a CLI **inside the gate image**, run as
> a subprocess by the gate. Its vulnerability DB is cached in the `e2e-trivy-cache`
> volume (the `scanners.timeout` is bumped to `120s` so the first-run DB download
> fits). Likewise OSV is reached over HTTPS from the gate; neither is a compose
> service.

### 2.2 Networks & volumes

Two bridge networks isolate client traffic from upstream traffic:

- **`proxy-net`** — client ↔ gate (the `test-runner`/host hits the gate here).
- **`internal-net`** — gate ↔ upstreams (`private-index`, `push-registry`) + gate
  ↔ `scanner-bridge` + `ca-init`. The `private-index` and `scanner-bridge` are
  **only** on `internal-net`, so they are not reachable from the client side.

Named volumes: `e2e-bridge-socket` (gRPC socket), `e2e-gate-data` (SQLite DB),
`e2e-gate-cache` (artifact cache; also mounted RO into the bridge), `e2e-trivy-cache`,
`e2e-gate-logs` (the gate log, mounted RO into the test-runner so in-container
tests can grep it), and `e2e-ca` (the CA bundle).

Host port mappings live in `helpers.sh` (`15xxx`/`18xxx` range) so the E2E stack
never collides with a local dev stack: PyPI `15010`, npm `14873`, NuGet `15001`,
Docker `15002`, push-registry `15003`, Maven `18085`, RubyGems `18086`, Go modules
`18087`, Admin `18080`. In containerized mode, `helpers.sh` instead reads the
`SGW_*_URL` env vars the compose file sets to **service-name** URLs
(`http://shieldoo-gate:5000`, …).

### 2.3 The test CA and the https-only invariant

Production Shieldoo Gate **only** talks to upstreams over HTTPS — there is no
insecure-HTTP escape hatch and no `InsecureSkipVerify` anywhere in product code.
To test private indexes without weakening that invariant, the harness:

1. ships a committed **test-only** self-signed CA + a server cert for SAN
   `private-index` (`fixtures/private-index/{test-ca.pem,test-ca-key.pem,server.pem,server-key.pem}`,
   regenerate with `gen-certs.sh`);
2. `ca-init` builds `cabundle.pem = <gate image system roots> + <test CA>` into the
   shared `e2e-ca` volume;
3. the gate is pointed at it with `SSL_CERT_FILE=/shared/cabundle.pem` (Go's crypto/tls
   honours this env var).

Result: `pypi.org` (default upstream) still validates against the **public** roots
**and** `https://private-index:8443` validates against the **test CA** — with
**zero product-code change**. An untrusted cert would fail the handshake, which is
exactly the production behaviour we want to preserve. The HTTPS leg is therefore
proven implicitly by every multi-index fan-out: if CA trust were broken, every
private-index fetch (and thus every release-gate assertion) would fail.

> **Why `ca-init` stays alive.** The run uses `up --abort-on-container-exit`, which
> tears the whole stack down (SIGKILL) the moment **any** container exits. A
> one-shot `ca-init` that exits 0 would abort the run and kill the bridge/dind/
> registry early — breaking every bridge-backed scan. So `ca-init` writes the
> bundle then `tail -f /dev/null`, and dependents gate on `service_healthy` (bundle
> file present) rather than `service_completed_successfully`.

---

## 3. The test harness

### 3.1 Structure

Each `test_*.sh` file is **sourced** (not executed) and defines a single
`test_<name>()` function. It does **not** `set -e` (one failing assertion must not
abort the suite) and uses the shared helpers from `helpers.sh`. The orchestrators
(`run_all.sh`, `run.sh`) source the helpers + the test files, wait for the gate's
`/api/v1/health`, call each `test_<name>()` in order, and print a counted summary;
`print_summary` returns non-zero if any assertion failed.

### 3.2 Assertion & API helpers (`helpers.sh`)

| Helper | Purpose |
|---|---|
| `log_pass` / `log_fail` / `log_skip` / `log_info` / `log_section` | Structured, counted output. A `log_fail` flips the suite exit code. |
| `assert_eq` / `assert_contains` / `assert_gte` | Value assertions (`assert_gte` is integer ≥). |
| `assert_http_status "<desc>" <expected> <url>` | The workhorse — `curl`s a URL (with proxy auth if enabled) and checks the status code. |
| `api_get <path>` / `api_jq <path> <jq-filter>` | Query the gate **admin API** and parse JSON with `jq`. This is how a test proves an artifact was *scanned + cached* — an authoritative **server-side** check, not a client-side guess. |
| `admin_curl` / `E2E_ADMIN_CURL_AUTH[]` | Admin-API curl that presents the global super-token as `Authorization: Bearer` when proxy auth is on (the admin chain fails closed in auth passes). |
| `E2E_CURL_AUTH[]` / `auth_url` | Proxy-auth flags (`-u ci-bot:$TOKEN`) / URL userinfo prefix — empty when proxy auth is off, populated in passes 2/3. Splice into every `curl`: `curl "${E2E_CURL_AUTH[@]}" …`. |
| `db_exec` / `db_available` | Direct SQL — **PostgreSQL passes only** (returns 1 under SQLite); used by the integrity tests. |

### 3.3 Two runners, deliberately different (audit note)

`run_all.sh` (the container entrypoint) and `run.sh` (host) are **not** identical,
and the difference is intentional:

- **`run_all.sh` is canonical.** It sources and calls every suite, including the
  ones that require the container environment (proxy-auth, PostgreSQL, license
  enforcement, the full `vuln_scan_*` set). Auth/Postgres-gated suites self-skip
  in pass 1 rather than fail.
- **`run.sh` is a lighter host subset.** It omits the auth/Postgres-gated suites
  and the `vuln_scan_*` family because those are meaningful only in the layered
  passes.
- **`test_ai_scanner` runs in `run.sh` only.** It is inherently a *host* test: its
  malicious-`.pth` checks shell into the `scanner-bridge` container with
  `docker compose ps` / `docker exec` / `docker cp`, which need a Docker CLI and
  `COMPOSE_FILE` — neither exists inside the `test-runner` container (where
  `docker_logs` is even stubbed to read the shared log file instead). So it cannot
  run in containerized mode and is excluded from `run_all.sh` by design.

**Consequence for the AI-scanner surface in CI:** the dedicated `test_ai_scanner`
does **not** run in the canonical containerized suite. The AI/LLM surfaces that
*do* run there are `test_version_diff` (wiring exercised even when the LLM is off)
and `test_vuln_scan_ai_ssrf` (self-skips when AI is off). See §7.

> When you add a suite, decide which runner(s) it belongs in by what it needs (see
> §8) — do **not** assume "both". The multi-index suites belong in **both** and are
> in both.

---

## 4. Test inventory

Each suite drives a real client and/or the admin API through the gate. Suites
marked **(both)** run in `run_all.sh` and `run.sh`; **(container)** run only in
`run_all.sh`; **(host)** only in `run.sh`.

| Suite (`test_*.sh`) | Runner | Validates |
|---|---|---|
| `pypi` | both | `uv pip install` through the proxy; scan pipeline. |
| **`pypi_multi_index`** | both | **Multi-upstream PyPI (issue #32) — see §5.** |
| `npm` | both | npm packument/tarball through the proxy (real `npm install` in auth pass). |
| **`npm_multi_index`** | both | **Multi-upstream npm — see §5.** |
| `nuget` | both | `dotnet restore` through the proxy (self-skips without `dotnet`). |
| **`nuget_multi_index`** | both | **Multi-upstream NuGet — see §5.** |
| `docker` / `docker_registry` | both | OCI pull/push via `crane`, multi-registry, allowlist 403s, tag API, sync, scan pipeline. |
| `docker_push_durable` | container | Push durability + quarantine-gating (needs a durable backend pass). |
| `maven` | both | `mvn`/coordinate fetch through the proxy. |
| **`maven_multi_index`** | both | **Multi-upstream Maven — see §5.** |
| `rubygems` | both | `gem`/metadata through the proxy. |
| **`rubygems_multi_index`** | both | **Multi-upstream RubyGems — see §5.** |
| `gomod` | both | `go`/GOPROXY metadata + `.zip` through the proxy. |
| **`gomod_multi_index`** | both | **Multi-upstream Go modules — see §5.** |
| `api` | both | Admin API: stats, audit log after traffic. |
| `version_diff` | both | AI-driven cross-version diff scanner wiring (LLM step gated on creds). |
| `ai_scanner` | host | Dedicated AI-scanner surface (health gating + malicious `.pth`); host-only — see §3.3. |
| `vuln_scan_negative` / `vuln_scan_lifecycle` | both | Push-from-CI SBOM endpoint guards + lifecycle (self-skip without proxy auth). |
| `proxy_auth` / `admin_auth` / `policy_tiers` / `typosquat` / `reputation` / `integrity` / `projects` / `sbom` / `license_*` | container | Their respective features (most self-skip without auth/Postgres/strict-projects). |
| `vuln_scan_pypi` / `_npm` / `_docker` / `_log_redaction` / `_super_token_audit` / `_ai_ssrf` / `_shdg` | container | Vuln-scan ecosystem + redaction + super-token audit + SSRF + `shdg` CLI paths. |

---

## 5. Multi-upstream-index testing (issue #32) — in depth

This is the part to read carefully. Multi-upstream support lets one ecosystem
endpoint front a **default public** registry **plus** one or more **extra
indexes** (private/vendor registries), with ordered fallback and optional
per-index `packages` glob scoping. The E2E tier proves the whole chain
end-to-end, over real TLS, against real clients. The design is recorded in
[ADR-017](../adr/ADR-017-multi-upstream-indexes.md).

### 5.1 The single shared private upstream

All six ecosystems share **one** Caddy server (`private-index`) at
`https://private-index:8443`, serving committed fixtures from one `www/` tree. Its
`Caddyfile` routes by path so one host can serve every protocol (the one special
case is the npm packument, which collides path-wise with the tarball directory and
so is matched by a `path_regexp` and mapped to `www/npm/<pkg>.json`):

```
www/simple/<pkg>/index.html                            # PyPI PEP 503 simple pages
www/packages/<pkg>-<ver>.tar.gz                        # PyPI sdists
www/npm/<pkg>.json                                     # npm packument (Caddy maps GET /mycompany-npm-* → here)
www/<pkg>/-/<pkg>-<ver>.tgz                            # npm tarball
www/v3/registration/<id>/index.json                    # NuGet V3 registration
www/v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg       # NuGet .nupkg
www/api/v1/gems/<name>.json  +  www/info/<name>        # RubyGems metadata (+ compact index)
www/gems/<name>-<ver>.gem                              # RubyGems .gem artifact
www/github.com/<org>/<repo>/@v/{list,<ver>.info,<ver>.mod,<ver>.zip}  # Go module GOPROXY layout
www/maven/<group/path>/<ver>/<artifact>-<ver>.{pom,jar,jar.sha1}  +  .../maven-metadata.xml
```

Fixtures are generated once and committed by the `gen-*.sh` scripts:
`gen-package.sh` (PyPI), `gen-npm-nuget.sh` (npm + NuGet), `gen-rubygems-gomod.sh`
(RubyGems + Go), and `gen-maven.sh` (Maven). The generators build tiny real
artifacts and compute correct integrity hashes (npm `shasum`/`integrity`, gem
`sha`, Maven `.sha1`).

> **Key fixture design rule:** every download URL embedded in the fixtures'
> metadata points at `https://private-index:8443` **with no path prefix** (PyPI
> simple pages use *relative* hrefs), so that *after the gate rewrites it to the
> gate's own origin* the URL routes back to the gate's own scanned download route
> (`/ext-packages/<index>/…`, `/<pkg>/-/<tgz>`, `/v3-flatcontainer/…`, `/gems/…`).
> The `*-evil` fixtures deliberately embed a **foreign** host
> (`https://evil.example.net/…`) — that is what the fail-closed negatives refuse.

### 5.2 Config wiring (`config.e2e.yaml`)

The same private host is registered under each ecosystem. PyPI carries **two**
extra indexes (an unscoped `private` fallback **and** a scoped `corp`); the
flat-coordinate ecosystems carry a single **scoped** `private` index (they have no
unscoped support — §5.6):

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
    extra_indexes:
      - name: "private"                 # unscoped fallback (mycompany-lib)
        url: "https://private-index:8443"
      - name: "corp"                    # scoped namespace
        url: "https://private-index:8443"
        packages: ["acme-*"]
  npm:      { default: "https://registry.npmjs.org",   extra_indexes: [{ name: private, url: "https://private-index:8443", packages: ["mycompany-*"] }] }
  nuget:    { default: "https://api.nuget.org",        extra_indexes: [{ name: private, url: "https://private-index:8443", packages: ["mycompany.*"] }] }
  maven:    { default: "https://repo1.maven.org/maven2", extra_indexes: [{ name: private, url: "https://private-index:8443/maven", packages: ["com.mycompany:*"] }] }
  rubygems: { default: "https://rubygems.org",         extra_indexes: [{ name: private, url: "https://private-index:8443", packages: ["mycompany-*"] }] }
  gomod:    { default: "https://proxy.golang.org",     extra_indexes: [{ name: private, url: "https://private-index:8443", packages: ["github.com/mycompany/*"] }] }
```

> **The `url` contract:** an index `url` is the registry **base** — the gate appends
> the ecosystem's metadata path itself (PyPI `/simple/<pkg>/`, etc.). Do **not**
> include `/simple/` or it gets doubled. A base **may** include a mount path (Maven's
> `…:8443/maven`) — the gate appends only the ecosystem's own sub-path to it. This
> contract was settled after the E2E caught exactly the doubling bug (see the plan
> index).

### 5.3 The non-negotiable release gate

> **A secondary-index artifact MUST be scanned + cached, not bypassed.**

A metadata-rewrite miss is a *silent full scan bypass* — the worst failure this
product can have (an artifact reaches the client without being scanned). So the
**authoritative** assertion in every multi-index suite is not "did the client get
a 200" but a server-side check that a **namespaced artifact row exists**:

```bash
api_jq "/api/v1/artifacts?ecosystem=<eco>__private" '[.data[] | select(...)] | length'  # ≥ 1
```

Artifacts served from an extra index are stored under a **namespaced ecosystem**
`eco__<index>` (`pypi__private`, `npm__private`, `nuget__private`,
`rubygems__private`, `go__private`, `maven__private`); the default index keeps the
bare `eco`. The gate persists the artifact row **synchronously, after the scan,
before serving** — so once the artifact-fetch step returns 200 the row must
already exist. **An artifact row under `eco__<index>` therefore proves the
download→scan→policy→cache pipeline ran** (it is not a timing race). If that row is
missing, the artifact was served without being scanned and the phase is **not
done**. (The PyPI suite additionally emits a bypass diagnostic that distinguishes
"a `SERVED` audit row exists but no artifact row" — an outright bypass — from "no
`SERVED` row either" — never reached the pipeline.)

> **Audit note — strength of the gate.** The assertion checks **existence** of the
> row, not `status == CLEAN`. That is sufficient here because the row is written
> only by `persistArtifact` *after* the scan pipeline completes, and the fixtures
> are clean (so a CLEAN verdict + cache write is the only path that produces a row +
> a 200). A future hardening could additionally assert the scan verdict via
> `/api/v1/artifacts/{id}/scans`.

### 5.4 Scenario matrix

Each ecosystem's multi-index suite runs the same shaped checks. `eco` ∈ {pypi,
npm, nuget, rubygems, go, maven}.

| Scenario | What it proves | Assertion |
|---|---|---|
| **back-compat** (S1 / N1 / G1 / R1 / M1 / MV1) | Default upstream still works through the gate. | Public package metadata → **200**. |
| **scanned + cached** (S2 / N2 / G2 / R2 / M2 / MV2) | **Release gate.** Private package served via the gate, fetched back, scanned, cached. | metadata download URL rewritten to the gate origin where applicable (private host **gone**); artifact fetch → **200**; **artifact row under `eco__private`** (the hard gate). RubyGems R2b additionally drives a real `gem install` (best-effort); Maven MV2a fetches the POM (fan-out hit) then the `.jar`. |
| **scoped-miss** (S4 / N3 / G3 / R3 / M3 / MV3) | Dependency-confusion guard: a name *claimed* by a scoped index but absent there is a hard 404, never a public fallback. | claimed-but-absent name → **404** **and** a `BLOCKED` audit row under `eco__private:<name>` (or `pypi__corp:<name>`). |
| **fail-closed** (N4 / G4 / R4) | A rewrite the gate cannot make safe is refused, never served verbatim. | a fixture whose download URL host is **foreign** → **502**, and **no** artifact row. |

> **Why the `BLOCKED` audit row — not the 404 — is the real scoped-miss proof.** A
> claimed-but-absent name 404s *anyway* (it's absent everywhere, including the
> public default). The status code alone could pass for the wrong reason. The
> assertion that makes it meaningful is the **`BLOCKED` audit row under the
> namespaced ecosystem** (`pypi__corp:acme-ghost`, `npm__private:mycompany-ghost`,
> …): it proves the gate treated the name as a *scoped* miss for **that index** and
> did **not** fall through to the public default. If the resolver wrongly fell back,
> the audit would be under a different ecosystem (or absent) and the test fails.

PyPI-only extras (PyPI is the reference adapter with the richest surface):

| Scenario | What it proves | Assertion |
|---|---|---|
| **S3 scoped serve** | A scoped package is served from its *claiming* index, not the unscoped fallback. | `acme-widget` (matches `corp`'s `acme-*` **and** the unscoped `private`) → simple page + tarball under **`/ext-packages/corp/`**, proving scoped claim wins over unscoped fallback. |
| **S5 SSRF fail-closed** | A forged extra-index name is rejected at the download route. | `GET /ext-packages/ghost/x` → **404** (the index name is validated before any upstream URL is built). |

#### Why Go modules and Maven have no fail-closed case

Their metadata carries **no download URLs**: the `go` client builds
`…/@v/{ver}.zip` and `mvn`/Gradle build the artifact URL from the
`groupId:artifactId:version` coordinate — both against the gate itself. So
`maven-metadata.xml`/`.pom`/checksums and the GOPROXY `@v/*` metadata are relayed
**verbatim** (size-capped) — there is no metadata-rewrite scan-bypass surface to
fail closed on. The unconditional download route (`.zip`, `.jar`/`.war`/`.aar`) is
the scan chokepoint. RubyGems sits in between: `/info/{name}` + version metadata
relay verbatim and only the optional `gem_uri` field is a rewrite surface — hence
RubyGems has a fail-closed case (R4) but Maven and Go do not.

### 5.5 The fail-closed negative fixtures

The `*-evil` fixtures exist purely to prove the gate refuses an unsafe rewrite —
each embeds a **foreign** download host so the 502 is for the *right* reason:

- `mycompany-npm-evil` — packument `dist.tarball` → `https://evil.example.net/…` → **502**.
- `mycompany.nuget.evil` — registration `packageContent` → foreign host → **502**.
- `mycompany-evil` — gem JSON `gem_uri` → foreign host → **502**.

The corresponding implementation guarantees (per-ecosystem metadata is a
scan-bypass surface): fail closed on a foreign download host, fail closed on
non-parseable/unexpected content, and use a **real parser** (HTML tokenizer for
PyPI, `encoding/json` for npm/NuGet/RubyGems) — never a verbatim relay of a
rewritable document. See [`adapters.md`](../adapters.md#multi-upstream-indexes) for
the per-adapter rules.

### 5.6 Why the flat-coordinate ecosystems must be `packages`-scoped

PyPI carries the index identity on the download leg through its dedicated
`/ext-packages/<index>/…` route, so an **unscoped** PyPI extra index works (ordered
fallback). npm/NuGet/RubyGems/Go/Maven have **no** such route — their download
handler recovers the serving index by **re-resolving the package name/coordinate**.
That re-resolution is only deterministic if the name is *claimed* by exactly one
scoped index; an unscoped extra index that served a package only because the
default 404'd cannot be re-identified on the download leg. Hence the
flat-coordinate ecosystems require `packages` scoping, and `config.e2e.yaml`
reflects that (only PyPI has an unscoped extra index).

### 5.7 How a single multi-index request flows (npm example)

```
npm  ──GET /mycompany-npm-lib──▶ gate
                                  │  resolver: "mycompany-*" claimed by index "private"
                                  │  fan-out: GET https://private-index:8443/mycompany-npm-lib
                                  │  rewrite dist.tarball  https://private-index:8443/…  ──▶  http://gate/…
                                  │  (fail closed 502 if a tarball host is foreign / body not JSON)
        ◀──packument (rewritten)──┘
npm  ──GET /mycompany-npm-lib/-/…tgz──▶ gate
                                  │  re-resolve "mycompany-npm-lib" → index "private" (recover serving index + auth)
                                  │  download from private-index, scan, policy, cache
                                  │  store artifact under ecosystem  npm__private
        ◀──tarball (200, scanned)─┘
```

PyPI differs only in that the rewritten download routes through an explicit
`/ext-packages/<index>/…` route (the simple page has no package id to re-resolve
from); npm/NuGet/RubyGems/Maven/Go recover the serving index by **re-resolving the
package name / coordinate** on the download leg.

---

## 6. Reading the results

`print_summary` prints `Total / Passed / Failed / Skipped`. The single strict pass
currently produces **182 passed, 0 failed, 27 skipped**. The 27 skips in pass 1
are all expected — they fall into:

- **proxy-auth-gated** (pypi/npm/nuget/maven/rubygems back-compat with auth,
  proxy_auth, admin_auth, projects, license_*, the `vuln_scan_*` lifecycle/upload
  tests, `shdg`) — run in passes 2/3;
- **PostgreSQL-gated** (`integrity`, `docker_push_durable`) — run in passes 2/3;
- **credential-gated** (`vuln_scan_ai_ssrf` when AI off);
- **client/host-gated** (`R2b` real `gem install`, `shdg --image` / `log_redaction`
  needing docker.sock in the runner).

A genuine regression shows up as `Failed > 0`; grep the log for `[FAIL]`.

---

## 7. How each scanner surface is tested

`config.e2e.yaml` sets a per-scanner `criticality` map (keyed by each scanner's
`Name()`); unlisted scanners default to `best_effort`.

| Scanner (`Name()`) | Criticality in E2E | Enabled by default | How it's exercised |
|---|---|---|---|
| `guarddog` (+ typosquat) | required | yes | Every PyPI/npm install routes through the GuardDog bridge. `test_typosquat` (container) drives the typosquat heuristic directly. |
| `trivy` | best_effort | yes | Runs as a subprocess in the gate on Docker/artifact scans; DB cached in `e2e-trivy-cache`. Exercised by the docker suites; failures fail **open** (best-effort) so a flaky DB download never reds the suite. |
| `osv` | best_effort | yes | Queried over HTTPS during scans; best-effort. (The push-from-CI vuln-scan OSV backend is separately **disabled** in `vuln_scan.scanners.osv` — CI-unreliable — so `vuln_scan_*` stays isolated from OSV.dev.) |
| `builtin-reputation` | required | yes | `test_reputation` (container) asserts upstream-metadata risk scoring; thresholds raised in E2E (`suspicious 0.8`, `malicious 0.95`) to avoid pagination-inflated false positives. |
| `version-diff` | required | yes (`mode: shadow`) | `test_version_diff` (both). The LLM diff step only fires when the bridge has `AI_SCANNER_ENABLED=true` (pass 4 / `.env`); otherwise it falls back to `UNKNOWN`→fail-open and only the **wiring** is exercised. `shadow` mode means the verdict never escalates to policy. |
| `ai-scanner` | required | **no** (opt-in) | Off by default (`SGW_SCANNERS_AI_ENABLED`/`AI_SCANNER_ENABLED`). The dedicated `test_ai_scanner` is **host-only** (§3.3) and self-skips its integration checks unless AI is enabled; `test_vuln_scan_ai_ssrf` (container) self-skips when AI is off. So in the canonical CI run the AI-scanner is present in config but its LLM path is not exercised — enable it via `tests/e2e-shell/.env` to run the malicious-`.pth` detection. |
| `builtin-threat-feed` | required | **no** (`threat_feed.enabled: false`) | Disabled in E2E to avoid flaky TLS to the feed host; the feature's logic is unit/integration-tested. |

Best-effort scanner failures are logged + counted and never escalate to
`MALICIOUS`; required scanner failures fail closed per `policy.on_scan_error`. AI
and version-diff surfaces are credential-gated and **skip cleanly** when creds are
absent — they never red a credential-less run.

---

## 8. Adding a new multi-index scenario (worked example: a new ecosystem/index)

Using **Maven** as the worked example (it's the simplest shape — verbatim metadata
relay, no rewrite surface):

1. **Add the fixture** under `fixtures/private-index/www/` and (re)generate via the
   matching `gen-*.sh` so hashes are correct, then **commit the output**. For Maven:
   `gen-maven.sh` writes `www/maven/<group/path>/<ver>/<artifact>-<ver>.{pom,jar,jar.sha1}`
   and `…/maven-metadata.xml`. Every embedded download URL (none, for Maven) must
   point at `https://private-index:8443` with no path prefix; a `*-evil` fixture (for
   ecosystems with a rewrite surface) must point at `https://evil.example.net/…`.
2. **Extend the `Caddyfile`** only if a new route *shape* is needed (Maven needs
   none — `file_server` serves the `www/maven/**` tree directly; the only special
   route so far is the npm packument `path_regexp`).
3. **Scope the index in `config.e2e.yaml`** under `upstreams.<eco>.extra_indexes`
   with a `packages` glob (required for every ecosystem except PyPI, which also
   supports an unscoped fallback). Match the fixture's coordinate
   (`packages: ["com.mycompany:*"]`).
4. **Write `test_<eco>_multi_index.sh`** defining `test_<eco>_multi_index()` (sourced,
   no `set -e`, helpers only). Mirror the scenario matrix (§5.4): back-compat 200,
   the **release-gate** `api_jq "…?ecosystem=<eco>__private"` ≥ 1, the scoped-miss
   404 **plus** the `BLOCKED`-audit-under-`<eco>__private` assertion, and a
   fail-closed 502 **iff** the ecosystem has a metadata rewrite surface.
5. **Wire it into the runner(s).** Add `source` + the call to **`run_all.sh`**
   (canonical), and to **`run.sh`** as well if it is host-runnable (the multi-index
   suites are — they use only `curl`/`jq`/`uv`/`gem`). Keep the order consistent
   with the existing entries. Do **not** add a suite that shells into containers
   (`docker exec`) to `run_all.sh` — see §3.3.
6. **Prove server-side evidence** with `api_jq` (artifact row / audit row), not just
   a client status code — that is the difference between proving "scanned + cached"
   and merely "the client got bytes".
7. **Run via the logfile convention** (§1.1) and confirm green.

---

## 9. Debugging a failure

```bash
# leave the stack up after a host run
./tests/e2e-shell/run.sh --keep

# inspect gate logs (or the mounted e2e-gate-logs volume)
docker compose -f tests/e2e-shell/docker-compose.e2e.yml logs shieldoo-gate | tail -100

# hit the private upstream directly from the gate's network (proves CA trust + fixture path)
docker compose -f tests/e2e-shell/docker-compose.e2e.yml exec -T shieldoo-gate \
  wget -q -O- https://private-index:8443/simple/mycompany-lib/

# tear down when done
docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v --remove-orphans
```

For a multi-index failure, the first question is always **"is there an artifact
row under `eco__<index>`?"** — its absence means a scan bypass; its presence with a
client error means a rewrite/serve bug downstream of the scan.

---

## 10. Known limitations & deferred follow-ups

Two cross-adapter MEDIUM hardening items are tracked as follow-ups (documented, not
yet fixed — see [ADR-017 §Consequences](../adr/ADR-017-multi-upstream-indexes.md#consequences)
and the [Phase 6](../plans/2026-06-19-multi-upstream-indexes-plan-6-rubygems-gomod.md)/[Phase 7](../plans/2026-06-19-multi-upstream-indexes-plan-7-maven.md)
plans):

1. **Breaker-open claimed-name download fallback.** If a scoped index's circuit
   breaker is open during an outage, the download leg can fall back to the default
   (still scanned, but could fetch a public package of the same name). The
   *metadata* leg already fails closed; this is a download-leg gap.
2. **Unscoped extra index is WARNed, not rejected.** An authenticated extra index
   with no `packages` scope gets a startup WARN + metric rather than a hard config
   error (an unscoped extra index cannot be recovered on the flat-coordinate
   download leg).

These are not exercised by the suite; adding a breaker-open scenario fixture would
require simulating an upstream outage and is left for the follow-up work.

---

## See also

- [Protocol Adapters](../adapters.md) — the per-adapter **Multi-Upstream Indexes**
  sections (PyPI, npm, NuGet, Maven, RubyGems, Go modules) carry the
  rewrite/scoping/fail-closed rules.
- [ADR-017 — Multi-Upstream Indexes](../adr/ADR-017-multi-upstream-indexes.md) — the design decision.
- [Configuration](../configuration.md) — the `upstreams.<eco>.{default,extra_indexes}` schema.
- [Multi-Upstream Indexes plan index](../plans/2026-06-19-multi-upstream-indexes-plan-index.md) — design, decisions, and execution-time security findings.
