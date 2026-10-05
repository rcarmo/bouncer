SHELL := /bin/sh

.DEFAULT_GOAL := help

BINARY := bouncer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBIN ?= $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)
LINT_TOOLCHAIN ?= go1.26.0

# Every test execution records allocations; no cached/unprofiled test recipes.
PROFILE_ROOT ?= artifacts/allocations
TEST_PACKAGES ?= ./...
TEST_FLAGS ?=
export PROFILE_ROOT TEST_PACKAGES TEST_FLAGS
PROFILE_TEST = bash scripts/test-profile.sh

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
	@command -v golangci-lint >/dev/null 2>&1 || GOTOOLCHAIN=$(LINT_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
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
test: ## Run tests with per-package allocation profiles
	$(PROFILE_TEST) test

.PHONY: coverage
coverage: ## Run coverage plus allocation profiling
	$(PROFILE_TEST) coverage

.PHONY: check
check: ## Run standard validation pipeline
	@$(MAKE) lint
	@$(MAKE) workflow-check
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

.PHONY: test-race
test-race: ## Run race tests with allocation profiles
	$(PROFILE_TEST) race

.PHONY: test-integration
test-integration: ## Profile authenticated SSE/WebSockets and reload in a real process
	$(PROFILE_TEST) integration

.PHONY: test-browser
test-browser: ## Profile Bouncer during Chromium passkey/SSE/WS smoke tests
	$(PROFILE_TEST) browser

.PHONY: workflow-check
workflow-check: ## Validate GitHub Actions workflows
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

.PHONY: vuln
vuln: ## Check reachable Go vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

.PHONY: test-browser-tls
test-browser-tls: ## Profile local-TLS Chromium and HTTP trust onboarding tests
	$(PROFILE_TEST) browser-tls

.PHONY: test-integration-race
test-integration-race: ## Profile race-instrumented process reload/stream tests
	$(PROFILE_TEST) integration-race

.PHONY: bench
bench: ## Run benchmarks with B/op, allocs/op and allocation profiles
	$(PROFILE_TEST) bench

.PHONY: clean-profiles
clean-profiles: ## Explicitly delete retained local allocation evidence
	rm -rf -- "$(PROFILE_ROOT)"

.PHONY: clean-build-cache
clean-build-cache: ## Remove rebuildable Go compilation cache, preserving test evidence
	go clean -cache

CONTAINER_ENGINE ?= docker
CONTAINER_IMAGE ?= bouncer:security-local
.PHONY: test-container
# Test-only image: production Docker builds leave GO_BUILD_TAGS empty.
test-container: ## Profile non-root container startup, low ports and writable state
	CONTAINER_ENGINE="$(CONTAINER_ENGINE)" CONTAINER_IMAGE="$(CONTAINER_IMAGE)" PROFILE_ROOT="$(PROFILE_ROOT)" bash scripts/container-smoke.sh
