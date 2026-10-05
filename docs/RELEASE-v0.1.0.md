# Bouncer v0.1.0

First tagged release. There were no earlier release tags.

## Changes

- Fix enrollment client-IP attribution, expiring one-time tokens and persisted guess limits.
- Fix config/session persistence races, user revocation on new requests, and passkey backup-flag persistence.
- Require discoverable passkeys; reject counter replay/regression and authenticator clone warnings.
- Preserve trusted forwarding headers, strip Bouncer's session cookie, and leave backend CSP/permissions policy intact.
- Keep SSE and bidirectional WebSockets alive across backend reloads; use one routing generation per request.
- Fix TLS renewal/validation, IPv6 and port routing, unknown-host rejection, HTTP-to-HTTPS onboarding, and CLI WebAuthn origins.
- Stop retired GeoIP workers and close database pools on reload; bound shutdown.
- Add mandatory allocation profiles to every test target, with retained binaries, allocation summaries and CI evidence uploads.
- Patch the reachable JWT vulnerability. Validate before publishing multi-architecture images and retain historical tags/releases and referenced image digests.

## Verification

All final checks passed: profiled unit and race suites, race-enabled process streaming/reload tests, Chromium HTTP and TLS passkey/SSE/WebSocket tests, vet, golangci-lint, gosec, build and reachable-vulnerability scan. See [AUDIT-2026-10.md](AUDIT-2026-10.md) for allocation baseline and limitations.

In GitHub Actions on the release commit, `make check`, `make test`, `make test-race`, `make test-integration-race` and `make vuln` passed, and allocation profiles were uploaded as workflow artefacts. Browser tests ran locally only. Physical device trust/passkey installation, Bonjour and a live Cloudflare Tunnel have not been tested.

## Upgrade notes

- Back up configuration, CA keys, credentials and sessions before upgrading.
- Existing synced passkeys may need re-enrollment because earlier records omitted backup flags.
- Trusted proxies must sanitise forwarding headers; disable LAN enrollment bypass on untrusted networks.
- Active SSE/WebSocket connections survive reload and user removal. Restart for immediate termination.
- Older state restores can revive tokens or sessions. Do not overwrite current security state casually during rollback.

## Images

The tag workflow repeats validation, builds native `linux/amd64` and `linux/arm64` images, and publishes `ghcr.io/rcarmo/bouncer:v0.1.0` and `latest` as a multi-architecture manifest. Older tags, releases and image digests are not deleted automatically.
