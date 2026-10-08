# Allocation profiling pass — 7–8 October 2026

Measured allocation reductions are implemented in the ingress source tree. No production state or public Funnel was used.

## Workloads and method

Full uncached unit suite (14 packages), real-process streaming/reload integration, HTTP Chromium and TLS Chromium passkey/stream/restart workloads were captured before and after optimisation with `make profile PROFILE_MODE=...`. Each capture used `memprofilerate=1`, without race instrumentation. Both baseline and final metadata identify **Go 1.27.1 linux/amd64**, Intel N100; go.mod requires Go 1.26.6. Linters use the configured Go 1.26.6 toolchain. Do not label these profiles Go 1.26.6 measurements.

All space/object summaries were inspected, including intermediate runs and the failed intermediate session-test compile. Equivalent initial server captures were compared with `make profile-diff` in both allocation dimensions. Ordinary uncached benchmarks ran without profiling; final benchmarks ran three times. Raw profiles include cold-start/runtime metadata and the browser workload includes two server lifetimes. Whole-workload totals are not per-request measurements.

## Changes and stable benchmark results

| Operation | Baseline B/op, allocs/op | Final B/op, allocs/op | Byte reduction |
|---|---:|---:|---:|
| Hostname resolution | 208, 6 | 0, 0 | 100% |
| Session lookup | 120, 2 | 96, 1 | 20% |
| Proxy response copy path | 34,808, 29 | 2,041–2,043, 28 | 94.1% |
| Credential check: copied snapshot versus locked membership | 224, 3 | 0, 0 | 100% |

- Host resolution avoids constructing SplitHostPort errors for plain DNS names, parsing DNS labels as numeric IP addresses, and parsing peers when no proxy trust exists. IPv4/IPv6 canonicalisation and trusted forwarded-host rules remain intact.
- Session lookup reuses the RFC3339 LastSeen string within its second-precision interval. Returned sessions remain independent snapshots; expiry, persistence cadence and locking are unchanged.
- ReverseProxy uses a shared sync.Pool of 32 KiB response arrays. Buffers remain held for the entire response, including long-lived streams. GC can discard them, so cold or GC-heavy workloads still allocate buffers; the pool has no fixed memory ceiling or guaranteed hit rate.
- Ordinary session authorisation uses a read-locked credential membership check, avoiding copies of public keys, credentials and transports. WebAuthn paths retain independent credential snapshots. Revocation and site/user scoping are preserved.

Final three-run time ranges: credential membership 25.27–25.85 ns/op; snapshot 160.6–178.4 ns/op; proxy 3,155–3,609 ns/op; session lookup 467.0–506.3 ns/op; hostname resolution 301.6–587.2 ns/op. Timing varies; allocation counts are the primary evidence. Create/delete retains 35 allocations and roughly 3,036–3,043 B/op; synchronous atomic persistence dominates its latency and was preserved.

## Equivalent server profiles

| Workload / server lifetime | Before alloc_space / objects | After alloc_space / objects |
|---|---:|---:|
| Streaming and reload integration | 872.99 kB / 4,036 | 843.91 kB / 3,956 |
| HTTP browser, initial process | 822.21 kB / 4,031 | 753.95 kB / 3,898 |
| HTTP browser, restarted process | 530.28 kB / 2,706 | 524.84 kB / 2,631 |
| TLS browser, initial process | 1,386.52 kB / 8,265 | 1,309.84 kB / 8,100 |
| TLS browser, restarted process | 813.93 kB / 4,983 | 788.56 kB / 4,901 |

Initial-process byte reductions: integration 3.3%, HTTP browser 8.3%, TLS browser 5.5%. Profile diffs attribute removal of 128 KiB integration / 96 KiB browser direct proxy-copy allocations, offset partly by pool initialisation. FindUserByID, hostname normalisation and IP parsing also decrease. TLS crypto, network buffers, JSON/reflection cold-start metadata and persistence remain visible costs. These were not weakened for lower totals.

Full unit-test totals are diagnostic rather than equivalent performance comparisons: regressions were added during tuning. The root package reports 1,209.21 to 1,194.81 kB and 6,310 to 6,150 objects; no suite-wide improvement claim relies on those totals.

## Verification and limits

Final `make test-race` passed all 14 packages; `make test-integration-race` passed streaming/reload and failed-bind rollback. Full profiling, integration profiling, both browser profiling modes, `make check` (zero gosec findings), `make vuln`, whitespace and shell syntax checks passed. The vulnerability scanner found zero reachable/imported-package vulnerabilities and five unused required-module advisories.

Container profiling was not repeated: the preceding container build failed committing a layer with `no space left on device`. Live tsnet/Funnel profiling requires an approved key and explicit public-exposure authorisation. No CPU, heap-retention or real tailnet throughput improvement is claimed.

Logs, benchmark measurements, diffs, toolchain/build IDs and textual summaries live beneath `/workspace/tmp/bouncer/logs/` and `/workspace/tmp/bouncer/tests/allocations/`. Baselines: `20261007T234736Z-test-6jQknS`, `234852Z-integration-YcbLwH`, `234934Z-browser-IWmGhT`, `234954Z-browser-tls-VX4uUy`. Final runs: `235745Z-test-eX10Bb`, `235852Z-integration-xt4oKa`, `235921Z-browser-SDiN6R`, `235942Z-browser-tls-zwm6mc` (all prefixed `20261007T`). Raw captures and matching analysis binaries from this pass are removed after analysis; textual evidence is retained. Earlier unrelated captures and persistent state are preserved.
