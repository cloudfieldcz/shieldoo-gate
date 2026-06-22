# Stage 1: Build React UI
FROM node:20.19.0-alpine3.21@sha256:8bda036ddd59ea51a23bc1a1035d3b5c614e72c01366d989f4120e8adca196d4 AS ui-builder

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
# Go 1.26.4 ships the fix for CVE-2026-42504 (mime/WordDecoder.DecodeHeader
# quadratic complexity), CVE-2026-42507 (net/textproto) and CVE-2026-27145
# (crypto/x509). Keep in lockstep with go.mod's `go` directive and the CI
# GO_VERSION in .github/workflows/release.yml so all build paths embed the
# same patched stdlib.
FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS go-builder

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
FROM aquasec/trivy:0.71.2@sha256:f5d0e600ecda7449e2a9b272805aef698631d3bb3f3a739a750de2c6819acdc9 AS trivy

# Stage 3: Runtime image
FROM alpine:3.20.10@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS runtime

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
