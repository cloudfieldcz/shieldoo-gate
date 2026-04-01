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
        --python-platform manylinux_2_17_x86_64 \
        --index-url "https://${SGW_USER}:${SGW_TOKEN}@pypi.shieldoo-gate.cloudfield.cz/simple/" \
        -r requirements.txt; \
    else \
      uv pip install --system --no-cache --require-hashes \
        --python-platform manylinux_2_17_x86_64 \
        -r requirements.txt; \
    fi
# Verify cffi native extension is present (catches wrong-platform wheel from cache)
RUN python -c "import _cffi_backend"

COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

CMD ["python", "main.py"]
