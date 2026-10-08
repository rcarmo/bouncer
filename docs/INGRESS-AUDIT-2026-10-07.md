# Ingress audit — 7 October 2026

The local audit fixes are implemented and verified. No production configuration, credentials, CA or tsnet identity was changed. Source publication does not change deployment or live-verification status.

## Fixes

- CA/server-certificate and enrollment-token preparation no longer persists a reload candidate. Persistence follows successful listener preparation. A failed bind regression confirms the prepared token expiry stays off disk and existing SSE/WebSocket streams continue.
- Authentication is blocked only for the reload snapshot and commit, not while nodes/listeners are staged. A changed file during staging rejects the candidate so concurrent authentication writes cannot be overwritten.
- Requests select ingress trust and routing from the same active generation. Staged HTTP servers do not accept connections or perform TLS handshakes until commit.
- Commit/rollback callbacks are idempotent and mutually exclusive. Rollback wakes staged serving goroutines; retired endpoints close tracked and hijacked connections.
- Equivalent and overlapping local socket declarations are rejected. Bootstrap requires a local-CA owner and an HTTPS public origin.
- Unchanged discovery records are reused during backend-only reloads.
- tsnet close is serialised. The readiness close watcher ends before ServeConfig mutation, so exposure rollback can use the local API before closing the node.
- Dead CLI override and listener-comparison code was removed. Current ingress documentation supersedes historical restart-only proposals.
- Routine Make tests, browser tests and container checks no longer force profiling. Explicit captures use `make profile PROFILE_MODE=...` or `BOUNCER_PROFILE_CONTAINER=1`. Integration targets include their required build tag; TLS browser tests set the actual script flag.

## Verification

On the final code tree:

- `make test-race`: all 14 packages passed, uncached and unprofiled.
- `make test-integration-race`: passed, including failed-bind rollback, listener addition/removal and unchanged authenticated streams beyond the 15-second read timeout.
- `make check`: passed vet, golangci-lint, gosec (zero issues), actionlint and build.
- `make vuln`: zero reachable or imported-package vulnerabilities; five required-module advisories are not called by this code.
- `make test-browser` and `make test-browser-tls`: passed passkey enrollment/login/logout, SSE/WebSocket and restart persistence after the reload/lifecycle fixes. TLS browser verification also passed after the final bootstrap validation change.
- `git diff --check` and shell syntax checks passed.

Logs: `/workspace/tmp/bouncer/logs/audit-final-*.log`.

The revised unprofiled `make test-container CONTAINER_ENGINE='podman --cgroup-manager=cgroupfs'` could not complete: Podman failed committing the build layer with `no space left on device`. Earlier container success predates these audit changes; it is not a final-tree pass. No unrelated storage was pruned.

## Earlier allocation evidence

The already-completed race capture `20261007T230718Z-race-W8sM0C` used Go 1.27.1 (as recorded in run metadata), race detection and `memprofilerate=1`; all 14 space/object summaries were inspected. The root package total was 1466.27 kB / 7546 objects. The largest package total was `internal/notify`, 28099.67 kB, including cache-bound regression workloads. These are whole-test totals, not per-request benchmarks. No before/after allocation improvement is claimed. Raw captures and matching analysis binaries from this inspected run were removed after checking that no process used them (303 MB reduced to 372 KB of summaries/logs). Other historical evidence was preserved.

## Limits

Real tailnet enrollment, Funnel certificates, public client attribution and exposure teardown need explicit approval and an approved key. Upstream tsnet forbids Close concurrent with Start; the 60-second readiness timeout begins after synchronous Start. Real startup and ListenFunnel cancellation still need live verification. The file recheck detects changes during staging; external writers must still follow the documented single-writer rule.
