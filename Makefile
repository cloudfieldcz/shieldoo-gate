# Makefile — Shieldoo Gate

.PHONY: build test test-e2e test-e2e-containerized lint clean proto

BINARY := shieldoo-gate
CMD_DIR := ./cmd/shieldoo-gate

# Dogfooding: pull Go deps through Shieldoo Gate when SGW_TOKEN is set
ifdef SGW_TOKEN
  SGW_USER ?= $(shell whoami)
  export GOPROXY := https://$(SGW_USER):$(SGW_TOKEN)@go.shieldoo-gate.cloudfield.cz,direct
endif

build:
	go build -o bin/$(BINARY) $(CMD_DIR)

test:
	go test -tags '!e2e' ./... -v -race

test-e2e:
	go test -tags e2e ./tests/e2e/... -v -count=1

test-e2e-containerized:
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml build
	@echo "=== E2E Run 1: strict mode + SQLite + local cache + no auth ==="
	SGW_POLICY_MODE=strict \
		docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
		--abort-on-container-exit --exit-code-from test-runner
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v --remove-orphans
	@echo "=== E2E Run 2: balanced + Auth + PostgreSQL + MinIO (S3) + STRICT projects + license enforcement ==="
	SGW_POLICY_MODE=balanced SGW_POLICY_AI_TRIAGE_ENABLED=true \
		SGW_PROJECTS_MODE=strict \
		SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=$$(openssl rand -hex 16) \
		docker compose \
		-f tests/e2e-shell/docker-compose.e2e.yml \
		-f tests/e2e-shell/docker-compose.e2e.auth.yml \
		up --abort-on-container-exit --exit-code-from test-runner
	docker compose \
		-f tests/e2e-shell/docker-compose.e2e.yml \
		-f tests/e2e-shell/docker-compose.e2e.auth.yml \
		down -v --remove-orphans
	@echo "=== E2E Run 3: permissive mode + Auth + PostgreSQL + Azurite (Azure Blob) ==="
	SGW_POLICY_MODE=permissive \
		SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=$$(openssl rand -hex 16) \
		docker compose \
		-f tests/e2e-shell/docker-compose.e2e.yml \
		-f tests/e2e-shell/docker-compose.e2e.azurite.yml \
		up --abort-on-container-exit --exit-code-from test-runner
	docker compose \
		-f tests/e2e-shell/docker-compose.e2e.yml \
		-f tests/e2e-shell/docker-compose.e2e.azurite.yml \
		down -v --remove-orphans

lint:
	go vet ./...

clean:
	rm -rf bin/

proto:
	protoc --go_out=internal/scanner/guarddog/proto \
		--go_opt=paths=source_relative \
		--go-grpc_out=internal/scanner/guarddog/proto \
		--go-grpc_opt=paths=source_relative \
		-I scanner-bridge/proto \
		scanner-bridge/proto/scanner.proto
