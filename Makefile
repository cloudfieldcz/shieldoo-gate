# Makefile — Shieldoo Gate

.PHONY: build test lint clean

BINARY := shieldoo-gate
CMD_DIR := ./cmd/shieldoo-gate

build:
	go build -o bin/$(BINARY) $(CMD_DIR)

test:
	go test ./... -v -race

lint:
	go vet ./...

clean:
	rm -rf bin/
