# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  Ludovic Ramos
# Licensed under the GNU AGPLv3. See LICENSE for details.

BINARY      := arenet
CMD_PKG     := ./cmd/arenet
BUILD_DIR   := bin
DATA_DIR    := ./data
FRONTEND    := web/frontend

GOFLAGS     ?=
LDFLAGS     ?=

.PHONY: all build frontend run dev-frontend test clean fmt vet help

all: build

## frontend: Build the SvelteKit static bundle into web/frontend/build/
frontend:
	cd $(FRONTEND) && npm install && npm run build

## build: Build frontend then the arenet binary into $(BUILD_DIR)/
build: frontend
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD_PKG)

## run: Build and run arenet in dev mode (does NOT start Vite)
run: build
	@mkdir -p $(DATA_DIR)
	$(BUILD_DIR)/$(BINARY) --dev --data-dir $(DATA_DIR)

## dev-frontend: Start Vite dev server on :5173 (run alongside `make run`)
dev-frontend:
	cd $(FRONTEND) && npm run dev

## test: Run all unit tests with race detector
test:
	go test -race -count=1 ./...

## clean: Remove Go and frontend build artifacts (keeps build/.gitkeep)
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(FRONTEND)/.svelte-kit
	find $(FRONTEND)/build -mindepth 1 -not -name '.gitkeep' -delete 2>/dev/null || true
	go clean -cache -testcache

## fmt: Format all Go source files
fmt:
	gofmt -s -w .

## vet: Run go vet on all Go packages
vet:
	go vet ./...

## help: Print this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //'
