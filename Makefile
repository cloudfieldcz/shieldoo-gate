# Makefile — Shieldoo Gate

.PHONY: build test test-e2e lint clean proto

BINARY := shieldoo-gate
CMD_DIR := ./cmd/shieldoo-gate

build:
	go build -o bin/$(BINARY) $(CMD_DIR)

test:
	go test -tags '!e2e' ./... -v -race

test-e2e:
	go test -tags e2e ./tests/e2e/... -v -count=1

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
