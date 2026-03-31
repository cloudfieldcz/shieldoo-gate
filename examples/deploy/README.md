# Shieldoo Gate — Example Production Deployment

Example Docker Compose deployment with Traefik reverse proxy, PostgreSQL, and TLS via Let's Encrypt.

## Architecture

```
Internet
  │
  ▼ (443/HTTPS)
┌─────────┐     ┌────────────────┐     ┌─────────────────┐
│ Traefik │────▶│ Shieldoo Gate  │────▶│ Scanner Bridge   │
│ (TLS)   │     │ (Go proxy)     │     │ (GuardDog/gRPC)  │
└─────────┘     └───────┬────────┘     └─────────────────┘
                        │
                  ┌─────▼─────┐
                  │ PostgreSQL │
                  └───────────┘
```

## Subdomains

| Subdomain                          | Service          |
|------------------------------------|------------------|
| `shieldoo-gate.example.com`        | Admin UI + API   |
| `pypi.shieldoo-gate.example.com`   | PyPI proxy       |
| `npm.shieldoo-gate.example.com`    | npm proxy        |
| `nuget.shieldoo-gate.example.com`  | NuGet proxy      |
| `cr.shieldoo-gate.example.com`     | Docker registry  |
| `maven.shieldoo-gate.example.com`  | Maven proxy      |
| `gems.shieldoo-gate.example.com`   | RubyGems proxy   |
| `go.shieldoo-gate.example.com`     | Go module proxy  |

## Quick Start

1. **Set up DNS** — point `shieldoo-gate.example.com` and `*.shieldoo-gate.example.com` to your server IP.

2. **Copy and configure environment:**

   ```bash
   cp .env.example .env
   # Edit .env — set real passwords, domain, email
   ```

3. **Start:**

   ```bash
   docker compose up -d
   ```

4. **Verify:**

   ```bash
   curl https://shieldoo-gate.example.com/api/v1/health
   ```

## Client Configuration

Once running, configure your package managers:

```bash
# pip
pip install --index-url https://pypi.shieldoo-gate.example.com/simple/ requests

# npm
npm config set registry https://npm.shieldoo-gate.example.com/

# NuGet
dotnet nuget add source https://nuget.shieldoo-gate.example.com/v3/index.json -n shieldoo

# Docker
docker pull cr.shieldoo-gate.example.com/library/nginx:latest

# Maven (settings.xml)
# <mirror><url>https://maven.shieldoo-gate.example.com/</url></mirror>

# Go
GOPROXY=https://go.shieldoo-gate.example.com,direct go get github.com/rs/zerolog
```

## Files

| File              | Description                                     |
|-------------------|-------------------------------------------------|
| `compose.yaml`    | Docker Compose with Traefik + PG + Gate          |
| `config.yaml`     | Shieldoo Gate configuration (PostgreSQL backend) |
| `.env.example`    | Environment variables template                   |
