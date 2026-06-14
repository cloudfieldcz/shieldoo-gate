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

# ---- Builder: toolchain + dependency install ----
FROM python:3.13.13-slim AS builder

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
COPY --from=ghcr.io/astral-sh/uv:0.7.12 /uv /usr/local/bin/uv

WORKDIR /app

COPY requirements.txt .
RUN if [ -n "$SGW_TOKEN" ]; then \
      uv pip install --system --no-cache --require-hashes \
        --index-url "https://${SGW_USER}:${SGW_TOKEN}@pypi.shieldoo-gate.cloudfield.cz/simple/" \
        -r requirements.txt; \
    else \
      uv pip install --system --no-cache --require-hashes -r requirements.txt; \
    fi

# Compile the gRPC stubs here (grpc_tools is only needed at build time).
COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

# ---- Runtime: clean image, no build toolchain or -dev headers ----
FROM python:3.13.13-slim AS runtime

WORKDIR /app

# Installed third-party packages + console scripts, and the generated gRPC stubs.
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app/proto/ proto/

# Fail the build now (not at runtime in prod) if a native extension is missing a
# shared lib it depends on after dropping the -dev packages.
RUN python -c "import _cffi_backend; import pygit2; import grpc"

COPY extractors/ extractors/
COPY extractors_diff/ extractors_diff/
COPY prompts/ prompts/
COPY ai_scanner.py .
COPY ai_triage.py .
COPY diff_scanner.py .
COPY scratch_janitor.py .
COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

CMD ["python", "main.py"]
