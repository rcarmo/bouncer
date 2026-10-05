# Bouncer development instructions

## Validation and allocation profiling

- Use Make targets for every build, lint, test and benchmark run. Do not run bare `go test` or invoke the browser smoke script directly: those paths bypass the allocation evidence required below.
- **Every test run must capture allocation profiles.** This includes unit tests, race tests, coverage, process integration tests, browser tests, targeted regressions and benchmarks. Disable test caching so each profile represents an executed workload.
- Use `make test`, `make test-race`, `make coverage`, `make test-integration`, `make test-integration-race`, `make test-browser`, `make test-browser-tls`, or `make bench`. For focused runs, pass `TEST_PACKAGES='./internal/session' TEST_FLAGS='-run TestName'`.
- The Makefile runs `scripts/test-profile.sh`. It records Go heap/allocation pprof data with `memprofilerate=1`, saves the matching test binaries, and generates both `alloc_space` and `alloc_objects` summaries under a unique `artifacts/allocations/` run directory. Integration and browser runs also profile the Bouncer server process; each restart gets a separate profile. Production builds contain no profiling endpoint or environment-controlled profiling code.
- Retain and inspect allocation summaries after tests. Compare equivalent workloads using the same toolchain, profiling rate and race setting before attempting reductions. Use `go tool pprof -alloc_space -base OLD.pprof NEW.pprof` and the analogous `-alloc_objects` comparison; use benchmark `B/op` and `allocs/op` for stable per-operation measurements.
- Treat lower allocations as a goal, not permission to weaken authentication, persistence, locking, streaming, or test coverage. Rerun the profiled regression tests after every optimisation. Report measured changes and remaining hotspots; do not infer an improvement from code shape alone.
- Profiles can include paths and application identifiers. Keep them out of Git and Docker contexts. Use `make clean-profiles` only when the evidence is no longer needed; ordinary `make clean` preserves profiles.
- A forced kill, panic or abrupt `os.Exit` can prevent the server's final profile from being written. The runner must fail if an expected profile is absent. Never describe that run as successfully profiled.

## Repository conventions

- Read relevant code and existing tests before editing; prefer small changes and regression tests.
- Run `make check` and `make vuln` alongside the applicable profiled tests before declaring a fix complete.
- Keep SSE flushing and bidirectional WebSocket upgrades working across SIGHUP reloads. Test long-lived connections, not just status codes.
- Preserve runtime configuration, credentials, CA keys and session data. Never commit generated secrets or live state.
- Browser smoke tests require Bun and Playwright Chromium. On Redshirt use `PLAYWRIGHT_BROWSERS_PATH=/workspace/bin/pw-browsers`.
