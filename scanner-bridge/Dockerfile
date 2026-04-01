# scanner-bridge/Dockerfile
FROM python:3.12.11-slim

ARG SGW_TOKEN=""
ARG SGW_USER=docker-build

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

COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

CMD ["python", "main.py"]
