SHELL := /bin/sh

.DEFAULT_GOAL := help

BINARY := bouncer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN_DIR := $(CURDIR)/bin
export PATH := $(BIN_DIR):$(PATH)
LINT_TOOLCHAIN ?= go1.23.4

IMAGE ?= $(notdir $(CURDIR))
TAG ?= latest
FULL_IMAGE := $(IMAGE):$(TAG)
REGISTRY ?= ghcr.io
GHCR_OWNER ?= $(shell whoami)
GHCR_IMAGE := $(REGISTRY)/$(GHCR_OWNER)/$(IMAGE):$(TAG)

.PHONY: help
help: ## Show targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*?##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-18s %s\n", $$1, $$2}'

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Build the Go binary
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

.PHONY: run
run: build ## Run the server locally
	./$(BINARY) --config bouncer.json --onboarding --listen :8443

# =============================================================================
# Docker
# =============================================================================

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t $(FULL_IMAGE) .

.PHONY: dual-tag
dual-tag: docker-build ## Tag image as ghcr.io/<user>/<image>:<tag>
	docker tag $(FULL_IMAGE) $(GHCR_IMAGE)

.PHONY: tag-ghcr
tag-ghcr: dual-tag ## Convenience alias for dual-tag

# =============================================================================
# Dependencies
# =============================================================================

.PHONY: deps
deps: ## Download Go module dependencies
	go mod download

.PHONY: install
install: deps ## Install project dependencies

.PHONY: install-dev
install-dev: ## Install dev tools (golangci-lint, gosec)
	@mkdir -p $(BIN_DIR)
	@set -e; \
	OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then ARCH=amd64; fi; \
	if [ "$$ARCH" = "aarch64" ]; then ARCH=arm64; fi; \
	if ! command -v golangci-lint >/dev/null 2>&1; then \
		URL="https://github.com/golangci/golangci-lint/releases/download/v1.62.2/golangci-lint-1.62.2-$${OS}-$${ARCH}.tar.gz"; \
		TMP=$$(mktemp -d); \
		curl -sSL $$URL | tar -xz -C $$TMP; \
		mv $$TMP/golangci-lint-1.62.2-$${OS}-$${ARCH}/golangci-lint $(BIN_DIR)/; \
		rm -rf $$TMP; \
	fi; \
	if ! command -v gosec >/dev/null 2>&1; then \
		URL="https://github.com/securego/gosec/releases/download/v2.21.2/gosec_2.21.2_$${OS}_$${ARCH}.tar.gz"; \
		TMP=$$(mktemp -d); \
		curl -sSL $$URL | tar -xz -C $$TMP; \
		mv $$TMP/gosec $(BIN_DIR)/; \
		rm -rf $$TMP; \
	fi

# =============================================================================
# Quality
# =============================================================================

.PHONY: lint
lint: ## Run linters
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		GOTOOLCHAIN=$(LINT_TOOLCHAIN) golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; run make install-dev"; \
		exit 1; \
	fi
	@if command -v gosec >/dev/null 2>&1; then \
		GOTOOLCHAIN=$(LINT_TOOLCHAIN) gosec ./...; \
	else \
		echo "gosec not installed; run make install-dev"; \
		exit 1; \
	fi

.PHONY: format
format: ## Format code
	gofmt -s -w .

.PHONY: test
test: ## Run tests
	go test ./...

.PHONY: coverage
coverage: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: check
check: ## Run standard validation pipeline
	@$(MAKE) lint
	@$(MAKE) build

.PHONY: tidy
tidy: ## Tidy modules
	go mod tidy

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: clean
clean: ## Remove local build/test artifacts
	rm -f $(BINARY) coverage.out
