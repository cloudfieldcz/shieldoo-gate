# Stage 1: Build React UI
FROM node:20.19.0-alpine3.21 AS ui-builder

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
FROM golang:1.25.7-alpine AS go-builder

ARG SGW_TOKEN=""
# Same rationale as stage 1 — identify as project "shieldoo-gate" when
# pulling Go modules through a self-hosted proxy.
ARG SGW_USER=shieldoo-gate

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

RUN CGO_ENABLED=1 GOOS=linux go build -o /shieldoo-gate ./cmd/shieldoo-gate

# Trivy binary
FROM aquasec/trivy:0.50.0 AS trivy

# Stage 3: Runtime image
FROM alpine:3.20.6 AS runtime

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
