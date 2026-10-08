---
name: go-makefile
description: Go dependency, lint and test workflow through this repository's Makefile.
---

# Go workflow

Use the existing Make targets and follow [AGENTS.md](../../../AGENTS.md). Do not assume generic `vet` or `security` targets exist.

- `make deps`: download module dependencies.
- `make install-dev`: install missing golangci-lint and gosec.
- `make check`: vet, golangci-lint, gosec, actionlint and build.
- `make test`, `make test-race`, `make coverage`: uncached unit verification, without profiling.
- `make test-integration` / `make test-integration-race`: real-process streaming and reload regressions.
- `make test-browser` / `make test-browser-tls`: Chromium passkey, stream and persistence tests; requires Bun/Playwright.
- `make vuln`: reachable/imported-package vulnerability scan.
- `make bench TEST_PACKAGES='./internal/session ./internal/site'`: per-operation allocation benchmarks.
- `make profile PROFILE_MODE=integration`: explicit pre-release allocation capture; inspect both space/object summaries before removing raw captures.

Go 1.26.6 is the module/container minimum. Respect the Makefile's portable project-scoped cache paths and retain only concise profiling findings after analysis. CI runs Make targets; source publication and deployment are separate actions.
