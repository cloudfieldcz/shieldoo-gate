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
# embed the same patched stdlib. On both `FROM golang:<tag>@sha256:<digest>`
# lines the tag and the @sha256 digest must move together — Docker resolves
# such a reference by digest, so editing only the tag silently keeps building
# the old, unpatched image with a green build and no checksum failure. See
# ADR-010 for the authoritative seven-location list.
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS go-builder

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

# Trivy binary — pinned to match shdg CLI's bundled Trivy (cmd/shdg/trivy.go's
# trivyVersion). KEEP IN LOCKSTEP: the two pins have no shared automation, so
# a Dependabot bump here alone silently drifts unless cmd/shdg/trivy.go moves
# too. CI's "Trivy version parity" step (.github/workflows/ci.yml) greps both
# and fails the build on mismatch — see docs/development/ci.md.
# Trivy < 0.66 cannot decode CycloneDX 1.6 SBOMs; shdg's `trivy fs --format
# cyclonedx` (no explicit spec version requested) emits CycloneDX 1.7 on both
# 0.72.0 and this 0.74.0 pin (verified directly against real output — Trivy
# picks the spec version, shdg does not request one), so the gate must run a
# Trivy that can decode at least 1.6+ or every push-from-CI scan will
# silently fall back to OSV-only and miss CVSS-derived severities.
FROM aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy

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
