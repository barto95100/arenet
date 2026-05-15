# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  Ludovic Ramos
# Licensed under the GNU AGPLv3. See LICENSE for details.

BINARY      := arenet
CMD_PKG     := ./cmd/arenet
BUILD_DIR   := bin
DATA_DIR    := ./data

GOFLAGS     ?=
LDFLAGS     ?=

.PHONY: all build run test clean fmt vet help

all: build

## build: Compile the arenet binary into $(BUILD_DIR)/
build:
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD_PKG)

## run: Build and run arenet in dev mode
run: build
	@mkdir -p $(DATA_DIR)
	$(BUILD_DIR)/$(BINARY) --dev --data-dir $(DATA_DIR)

## test: Run all unit tests with race detector
test:
	go test -race -count=1 ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean -cache -testcache

## fmt: Format all Go source files
fmt:
	gofmt -s -w .

## vet: Run go vet on all packages
vet:
	go vet ./...

## help: Print this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //'
