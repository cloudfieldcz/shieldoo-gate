# scanner-bridge/Dockerfile
FROM python:3.12.11-slim

ARG SGW_TOKEN=""
ARG SGW_USER=docker-build

# System dependencies for cffi and pygit2
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
# Verify native extensions are present (catches wrong-platform wheel)
RUN python -c "import _cffi_backend; import pygit2"

COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

COPY extractors/ extractors/
COPY prompts/ prompts/
COPY ai_scanner.py .
COPY ai_triage.py .
COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

CMD ["python", "main.py"]
