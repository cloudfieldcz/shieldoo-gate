# scanner-bridge/Dockerfile
#
# Multi-stage build. The builder stage carries the C toolchain and -dev headers
# needed to install Python packages with native extensions; the runtime stage is
# a clean python:slim that ships ONLY the installed packages and app code. This
# keeps build-time packages (gcc -> linux-libc-dev kernel headers, libgit2-dev ->
# libssh2/mbedtls headers, libffi-dev, pkg-config) out of the released image,
# removing the bulk of base-image CVE noise. The pinned wheels bundle their own
# native libs (pygit2 bundles libgit2; cryptography bundles openssl), so no -dev
# runtime libs are required; the import check in the runtime stage fails the build
# if any native extension lost a shared lib it needs.
#
# Dependencies are installed into a virtualenv at /opt/venv rather than into the
# interpreter's own site-packages. That path carries no Python version number, so
# bumping the base image is a one-line `FROM` change — with a `--system` install
# the runtime stage had to name /usr/local/lib/python3.13/site-packages verbatim,
# and every base-image bump (e.g. dependabot's 3.13 -> 3.14 PR) failed with
# `"/usr/local/lib/python3.13/site-packages": not found`. Both stages share the
# same pinned base image, so the venv's interpreter symlinks resolve in runtime.

# ---- Builder: toolchain + dependency install ----
FROM python:3.13.15-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS builder

ARG SGW_TOKEN=""
# Basic-auth username = project label on a self-hosted Shieldoo Gate. We use
# "shieldoo-gate" so the whole project (core + bridge) shows up under one
# label in the admin UI when the proxy is self-hosting.
ARG SGW_USER=shieldoo-gate

# System dependencies for building cffi and pygit2 native extensions.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libgit2-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.7.12@sha256:4faec156e35a5f345d57804d8858c6ba1cf6352ce5f4bffc11b7fdebdef46a38 /uv /usr/local/bin/uv

WORKDIR /app

# Self-contained venv at a version-independent path. VIRTUAL_ENV makes the
# subsequent `uv pip install` (and `python`, via PATH) target it without naming
# the interpreter version anywhere.
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN uv venv "$VIRTUAL_ENV"

COPY requirements.txt .
RUN if [ -n "$SGW_TOKEN" ]; then \
      uv pip install --no-cache --require-hashes \
        --index-url "https://${SGW_USER}:${SGW_TOKEN}@pypi.shieldoo-gate.cloudfield.cz/simple/" \
        -r requirements.txt; \
    else \
      uv pip install --no-cache --require-hashes -r requirements.txt; \
    fi

# Compile the gRPC stubs here (grpc_tools is only needed at build time).
COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

# ---- Runtime: clean image, no build toolchain or -dev headers ----
FROM python:3.13.15-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS runtime

# Pull Debian-security patches for base-image OS packages on top of the pinned
# base tag, then strip perl. The tag (python:3.13.14-slim) is pinned for
# reproducibility; `apt-get upgrade` adds whatever fixed package versions
# Debian-security has published at build time (e.g. openssl 3.5.6-1~deb13u2 for
# CVE-2026-45447). `perl-base` is a Debian "essential" package shipped by the
# base image but used NOWHERE in the bridge (a glibc Python gRPC service —
# guarddog is Python, pygit2 bundles libgit2; nothing invokes the Perl
# interpreter). It is the source of the only two CRITICAL
# findings (CVE-2026-42496, CVE-2026-8376) plus the perl-base highs/mediums,
# none of which have an upstream fix. Force-purging it deletes the interpreter
# and its files so the scanner no longer sees the package; apt/dpkg are never
# run at runtime, so the resulting dpkg "essential removed" state is inert. The
# final `! command -v perl` fails the build if perl somehow survives. See ADR-010.
RUN apt-get update \
 && apt-get upgrade -y \
 && dpkg --purge --force-remove-essential --force-depends perl-base \
 && rm -rf /var/lib/apt/lists/* \
 && ! command -v perl

WORKDIR /app

# Installed third-party packages (venv, incl. its console scripts) and the
# generated gRPC stubs. Copying the venv instead of the interpreter's own
# site-packages also keeps the builder's /usr/local/bin — and with it the `uv`
# binary — out of the runtime image.
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/proto/ proto/
ENV PATH="/opt/venv/bin:$PATH"

# Fail the build now (not at runtime in prod) if a native extension is missing a
# shared lib it depends on after dropping the -dev packages. `guarddog` is
# imported too (main.py uses it as a library, never as a CLI) so that a base-image
# Python bump fails here rather than on the first scan in production.
RUN python -c "import _cffi_backend; import pygit2; import grpc; import guarddog"

# Upgrade the base-image pip to a patched release. pip is shipped by the base
# image (not a runtime dependency of the bridge, which only runs `python
# main.py`), so it is flagged by the scanner but not covered by requirements.txt.
# Hash-pinned via pip-bootstrap.txt, not just version-pinned: an exact version
# alone still trusts the index to serve the same bytes under that version.
# Addressed by absolute path because the pip being patched is the base image's,
# not the venv's (the venv has no pip).
COPY pip-bootstrap.txt .
RUN /usr/local/bin/python -m pip install --no-cache-dir --require-hashes -r pip-bootstrap.txt

COPY extractors/ extractors/
COPY extractors_diff/ extractors_diff/
COPY prompts/ prompts/
COPY ai_scanner.py .
COPY ai_triage.py .
COPY diff_scanner.py .
COPY scratch_janitor.py .
# main.py imports this lazily inside DraftIgnoreReason's `except Exception`, so
# omitting it did not crash — it silently degraded every ignore-reason draft to
# an empty string.
COPY vuln_drafter.py .
COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

# Run as a non-root user that MATCHES the gate's sgw (uid 100/gid 101). Two
# reasons (issue #24):
#   1. Defence in depth — the bridge runs guarddog over *untrusted* package
#      content; it must not do so as root.
#   2. Shared-/tmp scratch ownership — /tmp is the shared `bridge-socket` volume,
#      mounted into both containers and sticky (1777). guarddog unpacks package
#      scratch there that can escape the TMPDIR redirect; only the file's *owner*
#      may unlink it under the sticky bit. With the bridge as the same uid as the
#      gate, that scratch is sgw-owned and the gate's tmpjanitor (sgw) can reclaim
#      it.
# uid 100 / gid 101 are unused in the python:slim base. HOME must exist and be
# writable: guarddog writes per-user cache/config under $HOME at runtime.
#
# The glob below is deliberate: it keeps the Python version out of the path. If
# it ever fails to match, the shell passes the pattern through literally and
# `chown` fails the build — a missing chown must not degrade silently into a
# read-only resources dir that only breaks on the first scan.
RUN groupadd -g 101 sgw \
 && useradd -u 100 -g 101 -m -d /home/sgw -s /usr/sbin/nologin sgw \
 && chown -R sgw:sgw /opt/venv/lib/python*/site-packages/guarddog/analyzer/metadata/resources
ENV HOME=/home/sgw
USER sgw

CMD ["python", "main.py"]
