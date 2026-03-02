SHELL := /bin/sh

.DEFAULT_GOAL := help

BINARY := bouncer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBIN ?= $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)
LINT_TOOLCHAIN ?= go1.26.0

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
	@command -v golangci-lint >/dev/null 2>&1 || GOTOOLCHAIN=$(LINT_TOOLCHAIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
	@command -v gosec >/dev/null 2>&1 || GOTOOLCHAIN=$(LINT_TOOLCHAIN) go install github.com/securego/gosec/v2/cmd/gosec@v2.24.6

# =============================================================================
# Quality
# =============================================================================

.PHONY: lint
lint: ## Run linters
	@$(MAKE) install-dev
	go vet ./...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) golangci-lint run ./...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) gosec ./...

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
