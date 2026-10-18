# Pre-release allocation check — 18 October 2026

Session and proxy benchmark profiles passed for the v0.2.1 release patch. No allocation optimisations were made in this fixes-only release.

## Workload and identity

- Source: v0.2.1 changes on base `aed109098e35e368ba2e9a753fa3d3d0e166b8ea`; capture preceded the release commit. Runtime source was unchanged after capture.
- Go 1.27.2, Linux ARM64, CIX P1 CD8160, `GOMAXPROCS=2`, without race instrumentation.
- Uncached benchmark execution, `-benchtime=100ms`, `memprofilerate=1`.
- Matching binary build IDs: session `82fd44e07086f1f4797cb46a64b48363567e02c4`; proxy `80082faacd4fa1fe21b7cb660859073c02974dfb`.

```sh
GOFLAGS=-p=1 GOMAXPROCS=2 GOMEMLIMIT=768MiB \
make profile PROFILE_MODE=bench \
  TEST_PACKAGES='./internal/session ./internal/proxy' \
  TEST_FLAGS='-benchtime=100ms'
```

## Measurements

| Benchmark | B/op | allocs/op |
|---|---:|---:|
| SessionGet | 96 | 1 |
| SessionCreateDelete | 2,901 | 36 |
| ProxyResponse | 2,100 | 28 |

Full sampling distorts timings, so no latency claim is made. These measurements include the benchmark fixtures and do not establish a before/after performance change.

Both `alloc_space` and `alloc_objects` summaries were inspected for both profiles:

- Session process: 6,025.73 KiB and 63,406 allocated objects. The independent session copy in `Store.Get` accounted for 94.69% of allocated bytes and 95.99% of objects. The one-copy return preserves isolation of authentication state. Durable create/delete also allocates for JSON, path handling and atomic-file persistence.
- Proxy process: 2,452.15 KiB and 32,804 allocated objects. Header setting, request/context cloning, URL cloning and response-copy flushing dominate. Benchmark transport/body fixtures contribute too. Pooled response buffers accounted for 64 KiB in the whole process; this is not a per-request buffer cost.

No correctness, persistence, authentication or streaming checks were weakened to reduce allocations. Earlier AMD64/Go 1.27.1 results are not an equivalent comparison. These two workloads do not profile WebAuthn ceremonies, certificate generation, notifications or live tsnet/Funnel traffic.

Raw profiles and their matching disposable analysis binaries were removed after inspection. Concise findings, commands and identities are retained here; routine tests remain unprofiled.
