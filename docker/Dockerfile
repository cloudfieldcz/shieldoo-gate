# Stage 1: Build React UI
FROM node:25.2.1-alpine3.21@sha256:32509199057d74a987fdd88cde00fdfd48ef52469adbd6bd11969fc701477761 AS ui-builder

ARG APP_VERSION=dev
ARG SGW_TOKEN=""
# SGW_USER is used as the Basic-auth username when fetching dependencies via
# a self-hosted Shieldoo Gate — the username is interpreted as the project
# label. We label the Shieldoo Gate build as project "shieldoo-gate" so its
# own proxy traffic is visible as such in the admin UI.
ARG SGW_USER=shieldoo-gate
ENV VITE_APP_VERSION=${APP_VERSION}

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN if [ -n "$SGW_TOKEN" ]; then \
      npm config set registry https://npm.shieldoo-gate.cloudfield.cz/ && \
      npm config set //npm.shieldoo-gate.cloudfield.cz/:_auth "$(printf '%s:%s' "${SGW_USER}" "${SGW_TOKEN}" | base64 | tr -d '\n')"; \
    fi && \
    npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Build Go binary
# Go 1.27.0 ships the fixes for GO-2026-6218 (net/url), GO-2026-6091
# (html/template), GO-2026-6090 (crypto/tls), GO-2026-6089 (net/http),
# GO-2026-6088 (encoding/xml), GO-2026-5972 (encoding/asn1) and GO-2026-5026
# (net/http) — all fixed in go1.26.6, taken here via the 1.27.0 minor bump.
# Keep in lockstep with go.mod's `go` directive, the CI GO_VERSION in
# .github/workflows/{ci,codeql,release}.yml, and — easy to miss —
# tests/e2e-shell/Dockerfile.test-runner's own `FROM golang:...` stage AND
# its separate ARG GO_VERSION/GO_SHA256 tarball install, so all build paths
# embed the same patched stdlib. See ADR-010 for the full seven-location
# list.
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS go-builder

ARG SGW_TOKEN=""
# Same rationale as stage 1 — identify as project "shieldoo-gate" when
# pulling Go modules through a self-hosted proxy.
ARG SGW_USER=shieldoo-gate
ARG APP_VERSION=dev

# git is required for `go mod download` to fall back to direct VCS clones
# (GOPROXY=...,direct) when an upstream module proxy 404/410s — common during
# self-hosted GOPROXY hiccups.
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /src
COPY go.mod go.sum ./
RUN if [ -n "$SGW_TOKEN" ]; then \
      export GOPROXY="https://${SGW_USER}:${SGW_TOKEN}@go.shieldoo-gate.cloudfield.cz,direct"; \
    fi && \
    go mod download

COPY . .
# Copy built UI assets into the source tree so they are embedded if needed
COPY --from=ui-builder /ui/dist ./ui/dist

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-X main.Version=${APP_VERSION}" \
    -o /shieldoo-gate ./cmd/shieldoo-gate

# Trivy binary — pinned to match shdg CLI's bundled Trivy (cmd/shdg/trivy.go).
# Trivy < 0.66 cannot decode CycloneDX 1.6 SBOMs; shdg generates 1.6 by default,
# so the gate must run a Trivy that supports it or every push-from-CI scan will
# silently fall back to OSV-only and miss CVSS-derived severities.
FROM aquasec/trivy:0.73.0@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c AS trivy

# Stage 3: Runtime image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

RUN apk add --no-cache ca-certificates sqlite-libs

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY --from=go-builder /shieldoo-gate /usr/local/bin/shieldoo-gate
COPY --from=ui-builder /ui/dist /var/www/shieldoo-gate/ui

RUN addgroup -S sgw && adduser -S sgw -G sgw \
 && mkdir -p /var/lib/shieldoo-gate /var/cache/shieldoo-gate /var/cache/trivy /var/log/shieldoo-gate \
 && chown sgw:sgw /var/lib/shieldoo-gate /var/cache/shieldoo-gate /var/cache/trivy /var/log/shieldoo-gate
USER sgw

EXPOSE 5000 4873 5001 5002 8080 8085 8086 8087

ENTRYPOINT ["/usr/local/bin/shieldoo-gate"]
CMD ["--config", "/etc/shieldoo-gate/config.yaml"]
