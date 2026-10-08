# Bouncer architecture

Bouncer uses one shared authentication/session pipeline behind a collection of local and embedded tsnet ingress endpoints. Sites define routing and credential scope; ingresses define network access, TLS, trust and lifecycle.

## Source layout

| Surface | Responsibility |
|---|---|
| `main.go` | Startup, generation publication, SIGHUP and shutdown |
| `ingresses.go` | Listener adapters, local-only SAN selection, mDNS reuse |
| `router.go`, `bootstrap.go` | Authenticated routing and separate trust bootstrap |
| `internal/ingress` | Validation, endpoint manager, request policy, tsnet/Funnel lifecycle |
| `internal/config` | Configuration, credential snapshots/membership and durable enrollment state |
| `internal/authn` | Site-specific WebAuthn, challenges, shared rate limits and enrollment |
| `internal/site` | Host/host:port registry and ingress site restrictions |
| `internal/session` | Persistent, credential-bound sessions and expiry |
| `internal/proxy` | ReverseProxy, sanitised forwarding and pooled response buffers |
| `internal/ca` | Local certificates and Apple trust profile |
| `internal/mdns` | Local DNS-SD service announcements |
| `internal/localip`, `internal/token` | Client attribution and cryptographic enrollment codes |
| `internal/notify` | Pushover, GeoIP providers, bounded caches and DB-IP updates |
| `internal/atomicfile` | Same-directory atomic persistence |
| `web/` | Embedded Preact/HTM UI, handlers and vendored assets |
| `scripts/`, `Makefile` | Build/test/browser/container flows and explicit profiling |

The production binary embeds its client assets. There is no frontend build server or runtime Node dependency. Bun and Playwright are development test dependencies.

## Request path

```text
local TLS / local upstream proxy / tsnet Funnel TLS
                       |
       ingress identity + effective trust + site allowlist
                       |
         one active routing/configuration generation
                       |
         security headers + site/origin validation
                       |
             passkey/session authorisation
                       |
            site's ReverseProxy -> backend
```

Each endpoint carries an atomic ingress policy. TLS connections remain intact so net/http supplies Request.TLS; the underlying Funnel connection supplies authenticated public-source metadata. Incoming HTTP headers cannot supply internal policy.

The dispatcher selects the active policy and router together under a short state lock. WebAuthn/logout requests also take an authentication read lock to serialise durable credential/token mutations with generation snapshot and commit. No generation lock remains held while proxying long-lived responses.

Local proxy trust is explicit per ingress. tsnet has no proxy trust and never grants local enrollment bypass. The site registry enforces allowlists; tsnet additionally checks exact authority, port and TLS SNI. See [INGRESSES.md](INGRESSES.md) for validation rules and state-directory ownership.

## Authentication and session state

One authentication handler per generation serves every listener, sharing challenge capacity, rate limits and enrollment budgets. WebAuthn instances are keyed by site and validate the site's RP ID/public origin. Registration consumes its accepted one-time enrollment code at the options step; challenges expire and are single-use.

Users and credentials remain site-bound. Sessions include the exact credential ID; ordinary authorisation performs a read-locked membership check without copying credential records. WebAuthn operations use independent snapshots because they need the full credential data. Revoked credentials cannot authorise new requests; existing streams retain their selected backend until disconnection.

`internal/session` protects its map with a mutex and returns independent session copies. LastSeen has RFC3339 second precision and reuses its string within that second. Session creation/deletion persists immediately; activity writes are batched. TTL is measured from creation, not activity.

Enrollment state stores expiry, per-generation attempts and a cross-generation failure budget. Neither startup nor reload resets lockout. Code issuance and durable consumption are serialised. Optional bounded notification work uses GeoIP/Pushover without exposing codes in routine logs or API responses.

## Endpoint lifecycle and reload

The manager owns each listener, HTTP server, tracked connection set and provider cleanup function by stable ingress ID. Prepare reuses compatible endpoints and stages additions. Staged servers wait before Accept, so they cannot perform a handshake against an unpublished local certificate. Commit and rollback are mutually exclusive and idempotent.

SIGHUP performs these steps:

1. Snapshot/load the candidate while auth writes are blocked briefly.
2. Validate sites/ingresses; prepare CA material, token expiry, auth handler, proxies, discovery and listeners without persisting the candidate.
3. Reacquire the auth lock and check that the file did not change during staging. A changed file rejects the candidate.
4. Persist prepared state, publish routing/certificates/policies, activate additions and retire removals.
5. Close old auth/discovery resources; unchanged discovery is reused.

Failed preparation closes additions and leaves the active generation running. Socket/node conflicts require remove/add across two reloads; session settings require restart. Existing SSE/WebSocket connections on reused endpoints survive. Removal explicitly closes tracked connections, including hijacked WebSockets, then closes the HTTP server and provider resources. There is no promise to drain removed streams gracefully.

Each tsnet ingress owns a separate persistent node and Funnel listener. Initial enrollment uses a per-ingress environment secret reference. Process-wide login overrides are rejected. Bouncer checks certificate-domain and Funnel permissions, tracks newly enabled exposure and removes its owned changes during cleanup without erasing pre-existing exposure. Close is serialised; the readiness close watcher ends before ServeConfig changes.

Upstream forbids Close concurrent with Start. Bouncer completes synchronous Start first, then bounds readiness to 60 seconds. Whole-startup/ListenFunnel cancellation, public certificates and teardown require live verification; local readiness does not prove external reachability.

## TLS and discovery

Only sites attached to local-CA ingresses contribute local SANs. The CA/server keys live in protected configuration, survive restart and are never disposable caches. Trust bootstrap uses a TLS-off local ingress with no proxy trust and an HTTPS local-CA owner. It serves trust instructions/downloads without authentication or passkey registration.

mDNS is optional on local ingresses. Advertisements use the ingress port and public site metadata, never backend credentials. Unchanged records are retained during backend reloads. DNS-SD does not guarantee browser DNS aliases. Funnel hosts should use separate sites excluded from LAN certificate/discovery bindings.

External Cloudflare remains a separate connector forwarding to a restricted local ingress. `server.cloudflare` controls certificate-step presentation and certificate-route registration in the main router; it does not create sockets, enable proxy trust or disable ingress TLS.

## Persistence and allocation management

`bouncer.yaml` stores configuration, CA material, users and enrollment state; a separate configured session file stores sessions. Atomic writes use temp file, sync and rename with mode 0600. Paths relative to configuration are resolved consistently. Use one writer per config/session pair and preserve current state when editing files.

Proxy responses use pooled 32 KiB buffers, held for the response lifetime. GC can discard pool entries, and concurrent streams each need a buffer. Hostname resolution avoids unnecessary IP parsing and malformed host:port error allocations. See [allocation measurements](ALLOCATION-PASS-2026-10-08.md) for workload-specific results and limitations.

Go 1.27.1 is the module/container minimum; allocation measurements used Go 1.27.1. Native amd64/arm64 packaging uses a non-root UID/GID 10001 with writable persistent `/data`. [AGENTS.md](../AGENTS.md) defines portable project-scoped cache/temp selection. Durable credentials, identities and deliverables stay outside that storage.

## Verification

Use `make check`, `make vuln`, uncached unit/race tests, real-process integration, HTTP/TLS Chromium and non-root container checks. Tests cover origin/host spoofing, trust isolation, credential revocation, failed-bind rollback, stream survival and persistent restart. Routine tests are unprofiled; `make profile` captures deliberate pre-release workloads and `make profile-diff` compares equivalent runs.

[Ingress audit](INGRESS-AUDIT-2026-10-07.md) and [allocation pass](ALLOCATION-PASS-2026-10-08.md) record results and blockers. The latest container recheck failed for lack of disk space. Real tailnet/public Funnel acceptance requires explicit approval and an approved key; it is not part of routine CI.
