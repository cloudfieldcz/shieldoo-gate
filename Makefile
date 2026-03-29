# Makefile — Shieldoo Gate

.PHONY: build test test-e2e test-e2e-containerized lint clean proto

BINARY := shieldoo-gate
CMD_DIR := ./cmd/shieldoo-gate

build:
	go build -o bin/$(BINARY) $(CMD_DIR)

test:
	go test -tags '!e2e' ./... -v -race

test-e2e:
	go test -tags e2e ./tests/e2e/... -v -count=1

test-e2e-containerized:
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml build
	@echo "=== E2E Run 1: No authentication ==="
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
		--abort-on-container-exit --exit-code-from test-runner
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml down
	@echo "=== E2E Run 2: Proxy authentication enabled ==="
	SGW_PROXY_AUTH_ENABLED=true SGW_PROXY_TOKEN=$$(openssl rand -hex 16) \
		docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
		--abort-on-container-exit --exit-code-from test-runner
	docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v

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
