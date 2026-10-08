SHELL := /bin/sh

.DEFAULT_GOAL := help

GO ?= go
BINARY := bouncer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

# Select a disposable base before redirecting TMPDIR. Preserve the original
# environment through recursive Make invocations so bouncer is appended once.
ifeq ($(origin BOUNCER_INHERITED_TMPDIR),undefined)
BOUNCER_INHERITED_TMPDIR := $(TMPDIR)
endif
export BOUNCER_INHERITED_TMPDIR
WORKSPACE_LOCAL_TMP_BASE ?= /workspace/tmp
WORKSPACE_SELECTED_TMP_BASE := $(shell \
	if [ -n "$(WORKSPACE_TMP_BASE)" ]; then printf '%s' "$(WORKSPACE_TMP_BASE)"; \
	elif [ -n "$(CI)" ] && [ "$(CI)" != 0 ] && [ "$(CI)" != false ]; then \
		printf '%s' "$(or $(RUNNER_TEMP),$(BOUNCER_INHERITED_TMPDIR),/tmp)"; \
	elif [ -d "$(WORKSPACE_LOCAL_TMP_BASE)" ] && [ -w "$(WORKSPACE_LOCAL_TMP_BASE)" ] && [ -x "$(WORKSPACE_LOCAL_TMP_BASE)" ]; then \
		printf '%s' "$(WORKSPACE_LOCAL_TMP_BASE)"; \
	else printf '%s' "$(or $(BOUNCER_INHERITED_TMPDIR),/tmp)"; fi)
WORKSPACE_PROJECT_TMP := $(abspath $(WORKSPACE_SELECTED_TMP_BASE))/bouncer
WORKSPACE_CACHE_DIR := $(WORKSPACE_PROJECT_TMP)/cache
WORKSPACE_BUILD_DIR := $(WORKSPACE_PROJECT_TMP)/build
WORKSPACE_TEST_DIR := $(WORKSPACE_PROJECT_TMP)/tests
WORKSPACE_LOG_DIR := $(WORKSPACE_PROJECT_TMP)/logs
WORKSPACE_RUN_DIR := $(WORKSPACE_PROJECT_TMP)/runs
export TMPDIR := $(WORKSPACE_RUN_DIR)/tmp
export GOTMPDIR := $(WORKSPACE_BUILD_DIR)/tmp
export GOCACHE := $(WORKSPACE_CACHE_DIR)/go-build
export GOMODCACHE := $(WORKSPACE_CACHE_DIR)/go-mod
export GOLANGCI_LINT_CACHE := $(WORKSPACE_CACHE_DIR)/golangci-lint
export BUN_INSTALL_CACHE_DIR := $(WORKSPACE_CACHE_DIR)/bun
export XDG_CACHE_HOME := $(WORKSPACE_CACHE_DIR)/xdg
# Preserve existing output contracts; allocate new profile runs outside source.
PROFILE_ROOT ?= $(WORKSPACE_TEST_DIR)/allocations

GOBIN ?= $(shell GOTOOLCHAIN=local go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)
LINT_TOOLCHAIN ?= go1.26.6

# Routine tests are uncached and unprofiled; profile is an explicit pre-release target.
TEST_PACKAGES ?= ./...
TEST_FLAGS ?=
export PROFILE_ROOT TEST_PACKAGES TEST_FLAGS WORKSPACE_TEST_DIR
PROFILE_MODE ?= test
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
	./$(BINARY) --config bouncer.json --onboarding

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

.PHONY: deps ingress-deps
ingress-deps: | workspace-prepare
	go get tailscale.com/tsnet@v1.102.5

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
test: ## Run unit tests
	$(GO) test -count=1 -timeout=5m $(TEST_FLAGS) $(TEST_PACKAGES)

.PHONY: coverage
coverage: ## Run coverage
	$(GO) test -count=1 -timeout=5m -coverprofile=$(WORKSPACE_TEST_DIR)/coverage.out $(TEST_FLAGS) $(TEST_PACKAGES)

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
test-race: ## Run race tests
	$(GO) test -count=1 -timeout=5m -race $(TEST_FLAGS) $(TEST_PACKAGES)

.PHONY: test-integration
test-integration: build ## Test authenticated streams and reload in a real process
	BOUNCER_TEST_BINARY=$(CURDIR)/$(BINARY) $(GO) test -count=1 -timeout=5m -tags=integration -run '^TestProcessStreams$$' $(TEST_FLAGS) .

.PHONY: test-browser
test-browser: build ## Test Chromium passkeys and streaming
	BOUNCER_TEST_BINARY=$(CURDIR)/$(BINARY) bun scripts/browser-smoke.ts

.PHONY: workflow-check
workflow-check: ## Validate GitHub Actions workflows
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

.PHONY: vuln
vuln: ## Check reachable Go vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

.PHONY: test-browser-tls
test-browser-tls: build ## Test Chromium with local TLS
	BOUNCER_TEST_BINARY=$(CURDIR)/$(BINARY) BOUNCER_TEST_TLS=1 bun scripts/browser-smoke.ts

.PHONY: test-integration-race
test-integration-race: ## Test process streaming and reload with race detection
	$(GO) build -race -o $(WORKSPACE_BUILD_DIR)/bouncer-race .
	BOUNCER_TEST_BINARY=$(WORKSPACE_BUILD_DIR)/bouncer-race $(GO) test -race -count=1 -timeout=5m -tags=integration -run '^TestProcessStreams$$' $(TEST_FLAGS) .

.PHONY: bench
bench: ## Run benchmarks
	$(GO) test -count=1 -timeout=5m -run '^$$' -bench . -benchmem $(TEST_FLAGS) $(TEST_PACKAGES)

.PHONY: clean-profiles
clean-profiles: ## Explicitly delete retained local allocation evidence
	rm -rf -- "$(PROFILE_ROOT)"

.PHONY: clean-build-cache
clean-build-cache: ## Remove rebuildable Go compilation cache, preserving test evidence
	go clean -cache

CONTAINER_ENGINE ?= docker
CONTAINER_IMAGE ?= bouncer:security-local
.PHONY: test-container
# Explicit optional profiling uses BOUNCER_PROFILE_CONTAINER=1.
test-container: ## Test non-root container startup, low ports and writable state
	CONTAINER_ENGINE="$(CONTAINER_ENGINE)" CONTAINER_IMAGE="$(CONTAINER_IMAGE)" PROFILE_ROOT="$(PROFILE_ROOT)" bash scripts/container-smoke.sh

# Do not move/delete old caches or retained evidence when adopting this layout.
.PHONY: workspace-prepare workspace-paths
workspace-prepare: ## Create project-scoped disposable directories
	@mkdir -p "$(WORKSPACE_CACHE_DIR)" "$(WORKSPACE_BUILD_DIR)" "$(WORKSPACE_TEST_DIR)" "$(WORKSPACE_LOG_DIR)" "$(WORKSPACE_RUN_DIR)" "$(TMPDIR)" "$(GOTMPDIR)" "$(GOCACHE)" "$(GOMODCACHE)" "$(GOLANGCI_LINT_CACHE)" "$(BUN_INSTALL_CACHE_DIR)" "$(XDG_CACHE_HOME)"

workspace-paths: ## Print selected disposable paths and profile output
	@printf '%s\n' "$(WORKSPACE_PROJECT_TMP)" "$(WORKSPACE_CACHE_DIR)" "$(WORKSPACE_BUILD_DIR)" "$(WORKSPACE_TEST_DIR)" "$(WORKSPACE_LOG_DIR)" "$(WORKSPACE_RUN_DIR)" "$(PROFILE_ROOT)"

# Order-only prerequisites keep directory setup out of source/timestamp tracking.
build deps install-dev lint tidy workflow-check vuln test coverage test-race test-integration test-integration-race test-browser test-browser-tls bench test-container clean-build-cache: | workspace-prepare

.PHONY: profile
profile: workspace-prepare ## Capture explicit pre-release profiles (PROFILE_MODE=test)
	$(PROFILE_TEST) $(PROFILE_MODE)

.PHONY: profile-diff
profile-diff: workspace-prepare ## Compare equivalent captures (PROFILE_BASE, PROFILE_CURRENT, PROFILE_BINARY)
	@test -n "$(PROFILE_BASE)" -a -n "$(PROFILE_CURRENT)" -a -n "$(PROFILE_BINARY)"
	$(GO) tool pprof -top -sample_index=alloc_space -base "$(PROFILE_BASE)" "$(PROFILE_BINARY)" "$(PROFILE_CURRENT)"
	$(GO) tool pprof -top -sample_index=alloc_objects -base "$(PROFILE_BASE)" "$(PROFILE_BINARY)" "$(PROFILE_CURRENT)"
