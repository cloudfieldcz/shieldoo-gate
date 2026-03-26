# Stage 1: Build React UI
FROM node:20.19.0-alpine3.21 AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.25-alpine AS go-builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

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
 && mkdir -p /var/lib/shieldoo-gate /var/cache/shieldoo-gate /var/cache/trivy \
 && chown sgw:sgw /var/lib/shieldoo-gate /var/cache/shieldoo-gate /var/cache/trivy
USER sgw

EXPOSE 5000 4873 5001 5002 8080

ENTRYPOINT ["/usr/local/bin/shieldoo-gate"]
CMD ["--config", "/etc/shieldoo-gate/config.yaml"]
