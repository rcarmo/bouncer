# Bouncer development instructions

## Validation and allocation profiling

- Use Make targets for builds, lint, tests and benchmarks. Ordinary development targets must run without profiling; use explicit profiling targets during pre-release testing.
- Profile and tune representative workloads during pre-release testing. Do not collect allocation profiles on every unit, race, coverage, integration, browser, regression or benchmark run. Disable test caching for deliberate profiling runs so captures represent executed workloads.
- Use `make test`, `make test-race`, `make coverage`, `make test-integration`, `make test-integration-race`, `make test-browser`, `make test-browser-tls`, or `make bench`. For focused runs, pass `TEST_PACKAGES='./internal/session' TEST_FLAGS='-run TestName'`.
- Use `make profile PROFILE_MODE=test` (or `race`, `coverage`, `bench`, `integration`, `integration-race`, `browser`, `browser-tls`) for explicit pre-release profiling. `scripts/test-profile.sh` collects heap/allocation pprof data and matching binaries under the selected disposable project root. Inspect `alloc_space` and `alloc_objects` summaries; delete raw captures and matching analysis binaries after analysis, including older analysed captures in `artifacts/allocations/`. Keep concise findings and measured results. Routine integration and browser runs must not enable server profiling. Production builds contain no profiling endpoint or environment-controlled profiling code.
- Inspect allocation summaries during pre-release analysis and retain concise findings. Use `make profile-diff PROFILE_BASE=OLD.pprof PROFILE_CURRENT=NEW.pprof PROFILE_BINARY=MATCHING.test` to inspect space/object differences. For container captures use `make test-container BOUNCER_PROFILE_CONTAINER=1`; routine container checks remain unprofiled. Compare equivalent workloads using the same toolchain, profiling rate and race setting before attempting reductions. Use `go tool pprof -alloc_space -base OLD.pprof NEW.pprof` and the analogous `-alloc_objects` comparison; use benchmark `B/op` and `allocs/op` for stable per-operation measurements.
- Treat lower allocations as a goal, not permission to weaken authentication, persistence, locking, streaming, or test coverage. During pre-release tuning, re-profile affected workloads after an optimisation. Report measured changes and remaining hotspots; do not infer an improvement from code shape alone.
- Profiles can include paths and application identifiers. Keep them out of Git and Docker contexts. Use `make clean-profiles` after analysis to delete raw profiling data and disposable analysis binaries; retain concise findings, not indefinite raw captures.
- A forced kill, panic or abrupt `os.Exit` can prevent the server's final profile from being written. The runner must fail if an expected profile is absent. Never describe that run as successfully profiled.

## Repository conventions

- Read relevant code and existing tests before editing; prefer small changes and regression tests.
- Run `make check`, `make vuln` and applicable regression tests before declaring a fix complete. Profiling and tuning belong to pre-release validation, not every development fix.
- Keep SSE flushing and bidirectional WebSocket upgrades working across SIGHUP reloads. Test long-lived connections, not just status codes.
- Preserve runtime configuration, credentials, CA keys and session data. Never commit generated secrets or live state.
- Browser smoke tests require Bun and Playwright Chromium. On Redshirt use `PLAYWRIGHT_BROWSERS_PATH=/workspace/bin/pw-browsers`.

## Project cache and temporary-file policy (5 October 2026)

- Reproducible caches and temporary files use a selected base with the stable `bouncer` slug appended. Selection order: explicit `WORKSPACE_TMP_BASE` > in CI, `RUNNER_TEMP`, inherited `TMPDIR`, then `/tmp` > outside CI, writable/searchable `/workspace/tmp` > inherited `TMPDIR`, then `/tmp`. Treat unset, empty, `0` and `false` CI flags as local mode. An absent workspace must not break CI or a local checkout. NEVER create ad-hoc paths, loose base-directory files or project-local caches.
- `WORKSPACE_TMP_BASE` overrides the base, not the project directory: `/some/base` produces `/some/base/bouncer`. `WORKSPACE_LOCAL_TMP_BASE` defaults to `/workspace/tmp` and permits selection probes. `BOUNCER_INHERITED_TMPDIR` snapshots the original TMPDIR before redirection and is exported to recursive Make to avoid repeated slug nesting.
- Use `cache/`, `build/`, `tests/`, `logs/` and `runs/` beneath the selected project root. Unique run folders belong inside these directories. `make workspace-paths` prints the selection; `make workspace-prepare` creates directories. Build/test/tool targets depend on preparation.
- Make exports TMPDIR=`runs/tmp`, GOTMPDIR=`build/tmp`, GOCACHE=`cache/go-build`, GOMODCACHE=`cache/go-mod`, GOLANGCI_LINT_CACHE=`cache/golangci-lint`, BUN_INSTALL_CACHE_DIR=`cache/bun` and XDG_CACHE_HOME=`cache/xdg`. Paths are relative to the selected project root. New profiled runs default to `tests/allocations`; profiling scripts require Make's `PROFILE_ROOT`. CI artifact uploads use the matching runner-temp path. Installed tools and durable output contracts are not disposable caches.
- This rule supersedes older scratch/cache examples in these instructions. Preserve published output contracts until their consumers are updated and verified. Keep source, curated checkpoints, credentials, persistent service data and durable deliverables outside disposable storage.
- Do not delete or move existing artifacts during adoption, especially while a process or another worktree uses them. Cleanup must be restricted to this project's disposable paths.

## Profiling and tuning policy

- Profile and tune during pre-release testing, using representative workloads. Routine development tests run without profiling; do not attach CPU, heap, allocation or trace capture to every test run.
- During pre-release analysis, compare equivalent workloads, fix measured bottlenecks, and re-measure without weakening correctness or test coverage.
- After analysis, retain concise findings, commands, source/toolchain identities and measured before/after results. Delete raw profiling captures and their disposable analysis binaries once analysis is complete; do not retain raw captures indefinitely or treat them as permanent checkpoints.
- Keep profiling data in the project's documented disposable workspace paths, with the existing portable CI/absent-workspace fallback. Restrict cleanup to owned files and wait for processes using them to finish. Preserve source, user data and non-profiling evidence.
- This policy supersedes older instructions requiring profiling on every development test or indefinite retention of raw profiling data. If existing Make targets or harnesses still force profiling for ordinary tests, correct that tooling before using those paths for routine development; this documentation change alone does not change runtime behaviour.
