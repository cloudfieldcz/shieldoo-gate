# Multi-Upstream Indexes — Phase 4: E2E Scenarios (multi-index)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run E2E redirected to a log file, then tail it (per the repo's E2E-via-logfile convention).

**Goal:** A dedicated, docker-compose-based E2E phase that drives **real `pip`** against the gate and proves the Phase 1/2/3 behaviour end-to-end — most importantly the **non-negotiable release gate: a secondary-index artifact is actually scanned + cached, not bypassed.** This phase also builds the reusable multi-index E2E harness that later ecosystem phases (5–7) extend.

**Architecture (maintainer decision):** A local **HTTPS** private index (`private-index`, a Caddy static server with a committed self-signed cert) serves a PEP 503 tree. A one-shot `ca-init` service concatenates the gate image's system CA bundle with the committed test CA into a shared volume; the gate trusts it via `SSL_CERT_FILE` — so the production **https-only upstream invariant is preserved** (no insecure-http escape hatch, no product-code change). `config.e2e.yaml` wires `upstreams.pypi` to a set with an unscoped `private` index and a scoped `corp` index.

**Tech Stack:** docker-compose (e2e), Caddy (pinned, TLS + static file_server), OpenSSL (committed cert fixtures), `pip`, bash (`helpers.sh` log_pass/log_fail/log_skip), the gate admin API + mounted gate logs for assertions.

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## Scenario matrix (what each phase's behaviour is validated by)

| # | Scenario | Validates | Assertion |
|---|----------|-----------|-----------|
| S1 | Default package via default upstream still works | Phase 1 back-compat (default-only) | `pip download requests` via gate succeeds |
| S2 | Unscoped private package served + **scanned + cached** | Phase 2 fallback + Phase 3 fan-out/rewrite/download | served via `/ext-packages/private/…`; artifact row under `pypi__private` with a scan verdict |
| S3 | Scoped private package served from claiming index only | Phase 2 scoping | `acme-widget` served from `corp`, never public |
| S4 | Scoped-miss → 404, no public fallback, audited | Phase 2 claimed + Phase 3 scoped-miss | `acme-ghost` → 404; audit row under `pypi__corp` |
| S5 | Forged extra-index name → 404 pre-upstream | Phase 3 SSRF control | `GET /ext-packages/ghost/x` → 404 |
| S6 | HTTPS private index reachable only via trusted CA | maintainer decision (https-only preserved) | gate fetches `https://private-index:8443` successfully; an untrusted cert would fail |

---

## Task 1: Test fixtures — self-signed cert + minimal private package

**Files:**
- Create: `tests/e2e-shell/fixtures/private-index/gen-certs.sh` (+ committed outputs `test-ca.pem`, `test-ca-key.pem`, `server.pem`, `server-key.pem`)
- Create: `tests/e2e-shell/fixtures/private-index/gen-package.sh` (+ committed PEP 503 tree under `tests/e2e-shell/fixtures/private-index/www/`)
- Create: `tests/e2e-shell/fixtures/private-index/Caddyfile`

- [ ] **Step 1: Cert generation script**

Create `tests/e2e-shell/fixtures/private-index/gen-certs.sh` (run once, commit the PEMs; the cert is long-lived and **test-only**):

```bash
#!/usr/bin/env bash
# gen-certs.sh — regenerate the E2E private-index TLS material. Run once; commit outputs.
# TEST-ONLY self-signed CA + server cert for CN/SAN "private-index". NOT for production.
set -euo pipefail
cd "$(dirname "$0")"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout test-ca-key.pem -out test-ca.pem \
  -subj "/CN=shieldoo-e2e-private-index-CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=private-index" \
  -addext "subjectAltName=DNS:private-index"

openssl x509 -req -in server.csr -CA test-ca.pem -CAkey test-ca-key.pem \
  -CAcreateserial -days 3650 \
  -extfile <(printf "subjectAltName=DNS:private-index") \
  -out server.pem
rm -f server.csr test-ca.srl
echo "Generated test-ca.pem, server.pem, server-key.pem"
```

Run it once and commit `test-ca.pem`, `server.pem`, `server-key.pem` (do **not** commit `test-ca-key.pem` if you prefer; it is only needed to regenerate — committing it is acceptable since this is a throwaway test CA).

- [ ] **Step 2: Minimal private package (PEP 503 tree)**

Create `tests/e2e-shell/fixtures/private-index/gen-package.sh` to build two tiny sdists and the simple pages (run once, commit `www/`):

```bash
#!/usr/bin/env bash
# gen-package.sh — build minimal sdists + PEP 503 simple pages for the E2E private index.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p www/packages www/simple

build_sdist() { # name version
  local name="$1" ver="$2" dir
  dir="$(mktemp -d)"
  mkdir -p "$dir/$name"
  printf 'def hello(): return "hi from %s"\n' "$name" > "$dir/$name/__init__.py"
  cat > "$dir/pyproject.toml" <<EOF
[project]
name = "$name"
version = "$ver"
EOF
  ( cd "$dir" && tar czf "$name-$ver.tar.gz" --transform "s,^,$name-$ver/," pyproject.toml "$name" )
  cp "$dir/$name-$ver.tar.gz" "www/packages/"
  rm -rf "$dir"
}

simple_page() { # name version
  local name="$1" ver="$2"
  mkdir -p "www/simple/$name"
  cat > "www/simple/$name/index.html" <<EOF
<!DOCTYPE html><html><body>
<a href="../../packages/$name-$ver.tar.gz">$name-$ver.tar.gz</a>
</body></html>
EOF
}

build_sdist mycompany-lib 1.0    # unscoped private package (served by 'private' index)
build_sdist acme-widget   2.0    # scoped package (served by 'corp' index)
simple_page mycompany-lib 1.0
simple_page acme-widget   2.0
echo "Built www/ tree"
```

Run once; commit the `www/` tree (small text + tiny tarballs).

- [ ] **Step 3: Caddyfile (TLS + static, both `private` and `corp` indexes share this server)**

Create `tests/e2e-shell/fixtures/private-index/Caddyfile`:

```
{
	auto_https off
}
private-index:8443 {
	tls /certs/server.pem /certs/server-key.pem
	root * /srv/www
	file_server browse
}
```

> Both config indexes (`private` and `corp`) point at the same `https://private-index:8443` host but differ by `packages` scope and `name`; serving the same tree is fine for the scenarios (S2 uses `mycompany-lib`, S3/S4 use `acme-*`).

- [ ] **Step 4: Commit fixtures**

```bash
chmod +x tests/e2e-shell/fixtures/private-index/*.sh
git add tests/e2e-shell/fixtures/private-index/
git commit -m "test(e2e): private-index fixtures (self-signed cert, minimal sdists, Caddyfile)"
```

---

## Task 2: Compose services — CA-init + HTTPS private index, gate trusts the CA

**Files:**
- Modify: `tests/e2e-shell/docker-compose.e2e.yml`

- [ ] **Step 1: Add `ca-init` (one-shot) + `private-index` services**

In `tests/e2e-shell/docker-compose.e2e.yml`, add to `services:` (Caddy pinned per CLAUDE.md):

```yaml
  # Builds a CA bundle = gate image's system roots + the test CA, into a shared
  # volume. The gate trusts it via SSL_CERT_FILE, so the HTTPS private index is
  # reachable WITHOUT relaxing the production https-only upstream invariant.
  ca-init:
    image: caddy:2.8.4-alpine
    volumes:
      - ./fixtures/private-index/test-ca.pem:/test-ca.pem:ro
      - e2e-ca:/shared
    command:
      - sh
      - -c
      - "cat /etc/ssl/certs/ca-certificates.crt /test-ca.pem > /shared/cabundle.pem && echo ca-bundle-ready"
    networks:
      - internal-net
    restart: "no"

  private-index:
    image: caddy:2.8.4-alpine
    container_name: shieldoo-e2e-private-index
    depends_on:
      ca-init:
        condition: service_completed_successfully
    volumes:
      - ./fixtures/private-index/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./fixtures/private-index/www:/srv/www:ro
      - ./fixtures/private-index/server.pem:/certs/server.pem:ro
      - ./fixtures/private-index/server-key.pem:/certs/server-key.pem:ro
    networks:
      - internal-net
    restart: "no"
```

Add the `e2e-ca` volume under `volumes:`:

```yaml
  e2e-ca:
```

- [ ] **Step 2: Make the gate trust the bundle + depend on the index**

In the `shieldoo-gate` service, add the CA volume + `SSL_CERT_FILE`, and depend on `private-index`:

```yaml
    depends_on:
      scanner-bridge:
        condition: service_started
      ca-init:
        condition: service_completed_successfully
      private-index:
        condition: service_started
    volumes:
      # ... existing volumes ...
      - e2e-ca:/shared:ro
    environment:
      # ... existing env ...
      SSL_CERT_FILE: /shared/cabundle.pem   # system roots + test CA (Go honours this)
```

> `SSL_CERT_FILE` replaces Go's default root set with this single file; because the bundle is
> `system-roots + test-CA`, pypi.org (the default upstream) keeps validating AND the private index's
> self-signed chain is trusted. This is why `ca-init` concatenates rather than supplying only the test CA.

- [ ] **Step 3: Verify the index is reachable over HTTPS from the gate network**

Run (build + bring up just the dependencies, redirect to log):
```bash
( cd tests/e2e-shell && docker compose -f docker-compose.e2e.yml up -d ca-init private-index shieldoo-gate scanner-bridge ) > /tmp/e2e-up.log 2>&1
( cd tests/e2e-shell && docker compose -f docker-compose.e2e.yml exec -T shieldoo-gate wget -q -O- https://private-index:8443/simple/mycompany-lib/ ) > /tmp/e2e-probe.log 2>&1
tail -n 20 /tmp/e2e-probe.log
```
Expected: the simple-page HTML for `mycompany-lib` (proves S6 — HTTPS + trusted CA works). If TLS fails, the CA bundle wiring is wrong.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/docker-compose.e2e.yml
git commit -m "test(e2e): https private-index service + CA-trust wiring (https-only invariant preserved)"
```

---

## Task 3: Wire the multi-index config into `config.e2e.yaml`

**Files:**
- Modify: `tests/e2e-shell/config.e2e.yaml` (`upstreams.pypi`, line 22)

- [ ] **Step 1: Replace the bare `pypi:` string with a set**

Change `tests/e2e-shell/config.e2e.yaml` line 22 (`pypi: "https://pypi.org"`) to:

```yaml
  pypi:
    default: "https://pypi.org"
    extra_indexes:
      - name: "private"                                  # unscoped fallback
        url: "https://private-index:8443/simple/"
      - name: "corp"                                     # scoped namespace
        url: "https://private-index:8443/simple/"
        packages: ["acme-*"]
```

> Leave `npm`/`nuget`/`maven`/`rubygems`/`gomod` as bare strings (they migrate in Phases 5–7). No
> `auth` here — auth is unit-tested in Phase 3; the e2e proves transport + scan+cache + scoping. The
> `private` index is unscoped so `mycompany-lib` (absent from pypi.org) falls through to it (S2);
> `corp` claims `acme-*` (S3/S4).

- [ ] **Step 2: Commit**

```bash
git add tests/e2e-shell/config.e2e.yaml
git commit -m "test(e2e): wire pypi multi-index (unscoped private + scoped corp) into e2e config"
```

---

## Task 4: The E2E test script

**Files:**
- Create: `tests/e2e-shell/test_pypi_multi_index.sh`

- [ ] **Step 1: Write the scenario test**

Create `tests/e2e-shell/test_pypi_multi_index.sh` — sourced by `run.sh`, defines `test_pypi_multi_index()`, does NOT `set -e`, uses `helpers.sh` (`log_pass`/`log_fail`/`log_skip`, `SGW_PYPI_URL`, `SGW_ADMIN_URL`). Mirror the structure of `test_pypi.sh`. Concrete scenarios:

```bash
#!/usr/bin/env bash
# test_pypi_multi_index.sh — multi-upstream-index E2E (issue #32). Sourced by run.sh.
# Validates: default back-compat (S1), unscoped private served+scanned+cached (S2),
# scoped serve (S3), scoped-miss 404 (S4), forged ext-index 404 (S5).

test_pypi_multi_index() {
  local pypi="$SGW_PYPI_URL" admin="$SGW_ADMIN_URL" tmp
  tmp="$(mktemp -d)"

  # S1 — default upstream back-compat
  if pip download --no-deps --disable-pip-version-check -i "$pypi/simple/" -d "$tmp" requests >/dev/null 2>&1; then
    log_pass "S1 default upstream (pypi.org) still serves via gate"
  else
    log_skip "S1 default upstream download failed (network?)"
  fi

  # S2 — unscoped private package served + scanned + cached (THE release gate)
  local simple
  simple="$(curl -fsS "$pypi/simple/mycompany-lib/" 2>/dev/null || true)"
  if grep -q "/ext-packages/private/" <<<"$simple"; then
    log_pass "S2a simple page rewritten to /ext-packages/private/"
  else
    log_fail "S2a private simple page NOT rewritten through proxy: $simple"
  fi
  if pip download --no-deps --disable-pip-version-check -i "$pypi/simple/" -d "$tmp" mycompany-lib >/dev/null 2>&1; then
    log_pass "S2b mycompany-lib downloaded through gate from private index"
  else
    log_fail "S2b mycompany-lib download via gate failed"
  fi
  # Proof of scan+cache (not bypass): artifact row under the namespaced ecosystem.
  if curl -fsS "$admin/api/v1/artifacts?ecosystem=pypi__private" 2>/dev/null | grep -q "mycompany-lib"; then
    log_pass "S2c artifact cached+scanned under pypi__private (NOT bypassed)"
  else
    # Fallback: audit log evidence (served/scanned event for the namespaced artifact).
    if curl -fsS "$admin/api/v1/audit?artifact=pypi__private:mycompany-lib" 2>/dev/null | grep -qi "served\|scanned\|clean"; then
      log_pass "S2c artifact scanned (audit evidence) under pypi__private"
    else
      log_fail "S2c NO scan/cache evidence for private-index artifact — possible scan BYPASS"
    fi
  fi

  # S3 — scoped package served from claiming index
  if pip download --no-deps --disable-pip-version-check -i "$pypi/simple/" -d "$tmp" acme-widget >/dev/null 2>&1; then
    log_pass "S3 scoped acme-widget served from corp index"
  else
    log_fail "S3 scoped acme-widget download via gate failed"
  fi

  # S4 — scoped miss → 404, no public fallback, audited
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "$pypi/simple/acme-ghost/")"
  if [ "$code" = "404" ]; then
    log_pass "S4 scoped-miss acme-ghost → 404 (no public fallback)"
  else
    log_fail "S4 scoped-miss expected 404, got $code"
  fi
  if curl -fsS "$admin/api/v1/audit?artifact=pypi__corp:acme-ghost" 2>/dev/null | grep -qi "scoped\|not found"; then
    log_pass "S4b scoped-miss audited under pypi__corp"
  else
    log_skip "S4b scoped-miss audit row not found via API (verify audit endpoint shape)"
  fi

  # S5 — forged extra-index name → 404 before any upstream request (SSRF)
  code="$(curl -s -o /dev/null -w '%{http_code}' "$pypi/ext-packages/ghost/whatever-1.0.tar.gz")"
  if [ "$code" = "404" ]; then
    log_pass "S5 forged /ext-packages/ghost → 404 (SSRF fail-closed)"
  else
    log_fail "S5 forged ext-index expected 404, got $code"
  fi

  rm -rf "$tmp"
}
```

> **Verify the admin endpoint shapes** before finalising S2c/S4b: `grep -rn "api/v1/artifacts\|api/v1/audit" internal/api/` to confirm the exact query params. Adjust the asserts to the real endpoints; keep the *intent* (positive scan/cache evidence under the namespaced eco) intact — that is the release gate.

- [ ] **Step 2: Commit**

```bash
git add tests/e2e-shell/test_pypi_multi_index.sh
git commit -m "test(e2e): multi-index pypi scenarios (S1-S5: back-compat, scanned+cached, scoped, SSRF)"
```

---

## Task 5: Register + run the E2E (logfile convention)

**Files:**
- Modify: `tests/e2e-shell/run_all.sh`

- [ ] **Step 1: Register the test**

In `tests/e2e-shell/run_all.sh`, add `test_pypi_multi_index` to the run sequence (mirror how `test_pypi` is invoked; `grep -n "test_pypi" run_all.sh run.sh` to find the registration pattern).

- [ ] **Step 2: Run via log file, then tail**

```bash
make build && \
  ( cd tests/e2e-shell && ./run.sh pypi_multi_index ) > /tmp/e2e-pypi-multi.log 2>&1; \
  tail -n 80 /tmp/e2e-pypi-multi.log
```
Expected: S1–S5 PASS. **S2c is the hard gate** — if it fails, a private-index artifact was served without scanning (a full scan bypass) and the phase is NOT done.

- [ ] **Step 3: Run the full suite once to confirm no regression**

```bash
( cd tests/e2e-shell && ./run_all.sh ) > /tmp/e2e-all.log 2>&1; tail -n 40 /tmp/e2e-all.log
```
Expected: the existing PyPI test (`test_pypi`) still passes (back-compat) alongside the new one.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/run_all.sh
git commit -m "test(e2e): register pypi multi-index e2e in run_all"
```

---

## Task 6: Example project (moved from Phase 3)

**Files:**
- Create: `examples/python-private-index/README.md`, `examples/python-private-index/pip.conf.example`

- [ ] **Step 1: Write the example**

Create `examples/python-private-index/README.md` documenting the real-world setup: configure `upstreams.pypi.extra_indexes` with a Hexaly-style unscoped public vendor index and a scoped private index (with env-var `auth`), point pip's `index-url` at the gate, and `pip install` the private package **through** the gate (scanned + cached, not bypassed). Reference the e2e (`tests/e2e-shell/test_pypi_multi_index.sh`) as the executable spec. Include `pip.conf.example`:

```ini
[global]
index-url = http://localhost:5000/simple/
```

Add the example to `examples/README.md`'s index.

- [ ] **Step 2: Commit**

```bash
git add examples/python-private-index/ examples/README.md
git commit -m "docs(examples): python private-index example (multi-upstream-index)"
```

---

## Phase 4 done-when

- [ ] HTTPS private index is reachable from the gate via the trusted test CA (S6); the production https-only upstream invariant is unchanged (no insecure-http path added).
- [ ] S1 back-compat: default upstream still serves through the gate.
- [ ] **S2 release gate: an unscoped private-index artifact is served via `/ext-packages/private/…` AND has scan+cache evidence under `pypi__private` (NOT bypassed).**
- [ ] S3 scoped package served from the claiming index; S4 scoped-miss → 404 (no public fallback) + audit; S5 forged extra-index → 404.
- [ ] `test_pypi_multi_index` registered in `run_all.sh`; full suite green (no regression to `test_pypi`).
- [ ] Example project added. (Full `docs/` + ADR-017 remain Phase 8.)
