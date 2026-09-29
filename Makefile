# Argus — developer entrypoints (POSIX: WSL, Linux, CI).
# Windows PowerShell users: use scripts/dev.ps1 (same targets).
#
# Local toolchain lives in .tools/ (gitignored); scripts/env.sh prepends it to PATH.

GO      ?= go
COMPOSE ?= docker compose
COMPOSE_FILE ?= deployments/compose/docker-compose.dev.yml
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X github.com/argus-platform/argus/internal/platform/buildinfo.Version=$(VERSION) \
  -X github.com/argus-platform/argus/internal/platform/buildinfo.Commit=$(COMMIT) \
  -X github.com/argus-platform/argus/internal/platform/buildinfo.Date=$(DATE)

.PHONY: help build build-server build-collector test test-race vet fmt fmt-check lint proto tidy \
        dev up down reset logs ps check versions doctor

help:
	@echo "Argus dev targets:"
	@echo "  make dev          - build and start the local stack (db, server, collector)"
	@echo "  make down|reset   - stop stack / stop and delete volumes"
	@echo "  make logs         - follow stack logs"
	@echo "  make build        - compile server + collector to bin/"
	@echo "  make test         - go test ./..."
	@echo "  make check        - fmt-check + vet + test"
	@echo "  make lint         - golangci-lint (installed in .tools/bin)"
	@echo "  make proto        - buf generate (requires protoc plugins in .tools/bin)"
	@echo "  make versions     - print toolchain versions in use"

build: build-server build-collector

build-server:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/argus-server ./cmd/argus-server

build-collector:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/argus-collector ./cmd/argus-collector

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@out=$$(gofmt -l cmd internal); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	.tools/bin/golangci-lint run

proto:
	.tools/bin/buf lint
	.tools/bin/buf generate

tidy:
	$(GO) mod tidy

check: fmt-check vet test

dev: up

up:
	$(COMPOSE) -f $(COMPOSE_FILE) up --build --wait

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down

reset:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v --remove-orphans

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=100

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

versions:
	@echo "go:      $$($(GO) version)"
	@echo "node:    $$(node --version 2>/dev/null || echo 'not installed')"
	@echo "docker:  $$($(COMPOSE) version 2>/dev/null || echo 'not installed')"

doctor:
	./scripts/doctor.sh
