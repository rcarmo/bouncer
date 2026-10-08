# Bouncer v0.2.0

Adds explicit local and embedded tsnet ingress management, human-editable YAML configuration and Go 1.27.1.

## Changes

- Manage up to 32 ingress entries through `ingresses[]`: local HTTP/TLS, local mDNS discovery and multiple embedded Funnel nodes with separate persistent identities.
- Stage SIGHUP additions transactionally; failed preparation preserves active routing and streams without persisting candidate certificates/token expiry. Reuse unchanged sockets/discovery and explicitly close removed WebSocket connections.
- Isolate listener trust: tsnet never trusts forwarded headers or grants LAN enrollment bypass; enforce site, authority, port and SNI bindings with shared authentication/enrollment budgets.
- Default configuration to `bouncer.yaml`, with strict fields, duplicate-key rejection, one document, two-space indentation and multiline PEM blocks. Sessions remain JSON.
- Align module/container/tooling to Go 1.27.1; update golangci-lint to 2.14.0 and gosec to 2.29.0.
- Reduce measured hostname-resolution allocations to zero, session lookup from 120 to 96 B/op, proxy response-copy benchmark from 34,808 to about 2,042 B/op, and credential membership checks to zero allocations.
- Separate routine unprofiled tests from explicit profiling. Add current specification, ingress migration, architecture and operations documentation.

## Migration

Back up current configuration, sessions, CA and node identity with the single writer stopped. Existing files must explicitly declare `ingresses[]`; legacy server/site listener settings do not create sockets. Remove listener/backend/hostname/IP/Cloudflare CLI overrides from launch commands.

Existing JSON content is readable as YAML, but the next save writes YAML and does not preserve comments or original formatting. Update the launch path to `bouncer.yaml` and do not leave an old command pointing at a stale JSON copy. YAML-only content cannot be read by old JSON-only binaries; rollback requires deliberate offline conversion preserving current security state. Quote numeric-looking codes/identifiers.

Preserve stable site IDs, public origins, RP IDs, users and CA keys. A new Funnel hostname needs its own credential scope; existing passkeys are not relabelled. Container state remains owned by UID/GID 10001. Session settings require restart; conflicting socket/node changes require remove/add across two reloads.

See [ingress migration](INGRESSES.md#yaml-persistence-and-migration) and [operations manual](OPERATIONS.md).

## Verification and limits

Local Go 1.27.1 unit/race, real-process streaming/reload/failed-bind, HTTP/TLS Chromium passkey/restart, vet, lint, gosec, actionlint and build checks passed. The vulnerability scan found zero reachable/imported-package vulnerabilities and five advisories in unused required-module functionality. YAML round-trip regressions preserve credentials, token state and multiline keys.

Equivalent pre-YAML allocation workloads showed initial-process byte reductions of 3.3% for streaming/reload, 8.3% for HTTP browser flows and 5.5% for TLS browser flows. These are workload-specific results; YAML persistence has not received a separate before/after profiling comparison.

The local final container recheck was blocked by disk space; tag CI validates container startup before publishing native amd64/arm64 images. Real tailnet enrollment, public certificates/client attribution, multi-node overhead and exposure teardown are not live-verified. Synchronous upstream Start and ListenFunnel have no verified whole-operation timeout. Public acceptance requires explicit approval and a test key.

Source/image publication does not deploy or migrate any production state. No physical device trust installation was performed.
