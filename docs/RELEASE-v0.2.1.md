# Bouncer v0.2.1

Fixes explicit DB-IP refreshes and TLS certificate validation, and updates dependencies. No new application features or persistence-format changes.

## Fixes

- An explicit `--dbip-update` now refreshes the database even within its normal update interval. Automatic startup updates continue to honour that interval.
- Verify existing server certificates for TLS server-authentication usage and unsupported critical extensions before reuse. Unsuitable leaves follow the existing renewal path.
- Reject unsuitable existing CA roots without silently replacing the trust anchor or its key.
- Keep prerelease container tags off `latest`; stable patch releases still update it.
- Make container checks independent of live GeoIP downloads and remove their own disposable anonymous volumes after testing.
- Reject IP-address WebAuthn public origins/RP IDs during configuration validation, matching the upgraded authentication library. Integration tests use a DNS-based `localhost` relying party while retaining real loopback sockets.

## Dependencies and toolchain

- Go 1.27.2 for the module, lint tools and Docker builder.
- WebAuthn 0.18.2, Tailscale 1.104.1, SQLite 1.60.1 and x/net 0.61.0, plus refreshed transitive dependencies within their existing module major versions.
- Keep gVisor at the generated-Go revision required by Tailscale 1.104.1 (`a6f909f08a72`). Raw upstream gVisor master is not a buildable replacement for that dependency.
- Playwright 1.64.1 for browser tests; golangci-lint 2.15.0, actionlint 1.7.12 and govulncheck 1.9.0 for development/release checks.
- Pin gosec to upstream revision `707f2271f665` (2.29.1 development), whose updated Go importer supports Go 1.27 export data. Stable gosec 2.29.0 cannot analyse this toolchain; security scanning remains mandatory.

## Upgrade

The v0.2.0 YAML configuration, credential records and session format are unchanged. Back up the configuration and session files, preserve CA keys and node identities, and keep one writer per configuration/session pair.

WebAuthn public origins and RP IDs must use DNS hostnames. IP addresses remain supported as listener addresses, host aliases and TLS SANs, but an IP address cannot be a WebAuthn relying-party identity. Replace any IP-based canonical origin/RP ID with a DNS name before upgrading. The configuration check now rejects this unsupported setup instead of passing validation and failing during authentication startup.

Existing valid CA roots remain unchanged. If an imported root has a client-auth-only restriction or an unsupported critical extension, startup now reports the validation error instead of serving an unusable certificate. Fix the configured trust material through the normal operator-managed process; do not discard existing CA keys or trust state.

Live tailnet/Funnel enrollment, public certificate issuance, source attribution and teardown still require separately authorised acceptance testing. Local tests do not establish public Funnel reachability. External Pushover/GeoIP services were not exercised during this release validation.

## Verification

Validated locally with Go 1.27.2 on Linux ARM64:

- Uncached unit and race suites; `make check` including vet, golangci-lint, gosec, actionlint and build.
- Real-process race integration covering long-lived SSE/WebSocket streams across SIGHUP, failed-bind rollback, ingress addition/removal and credential revocation.
- HTTP and TLS Chromium passkey enrollment, logout, discoverable login, streaming and persistence across restart using Playwright 1.64.1. Ubuntu 26.04 ARM64 used Playwright's explicit Ubuntu 24.04 ARM64 fallback build.
- Non-root container UID 10001, writable state, HTTP port 80/TLS port 443 and graceful shutdown, without live GeoIP downloads.
- govulncheck 1.9.0: zero reachable advisories and zero advisories in imported packages. The required x/crypto module retains GO-2026-5932 for its unused, unmaintained OpenPGP package; Bouncer does not import it.
- Go module checksums verified and Bun's frozen lockfile verified.
- Explicit pre-release session/proxy allocation capture; both space/object summaries inspected. Raw profiles and matching analysis binaries were removed. See [measurements and limits](ALLOCATION-PASS-2026-10-18.md).
