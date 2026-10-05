# Bouncer v0.1.0 — release candidate notes

First proposed tagged release. No prior release tags were present on 5 October 2026. Publication is blocked because the available GitHub bot has no push permission on `rcarmo/bouncer`.

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

## Verified locally

All final checks passed: profiled unit and race suites, race-enabled process streaming/reload tests, Chromium HTTP and TLS passkey/SSE/WebSocket tests, vet, golangci-lint, gosec, build and reachable-vulnerability scan. See [AUDIT-2026-10.md](AUDIT-2026-10.md) for allocation baseline and limitations.

Remote CI and Docker publishing have not run. Physical device trust/passkey installation, Bonjour and a live Cloudflare Tunnel have not been tested.

## Upgrade notes

- Back up configuration, CA keys, credentials and sessions before upgrading.
- Existing synced passkeys may need re-enrollment because earlier records omitted backup flags.
- Trusted proxies must sanitise forwarding headers; disable LAN enrollment bypass on untrusted networks.
- Active SSE/WebSocket connections survive reload and user removal. Restart for immediate termination.
- Older state restores can revive tokens or sessions. Do not overwrite current security state casually during rollback.

## Publication steps once write access is granted

1. Push the audited commit to `main` and verify CI, including uploaded allocation evidence.
2. Create an annotated `v0.1.0` tag on that verified commit; push the tag without force.
3. Wait for the publish workflow's validation, native amd64/arm64 builds and manifest inspection.
4. Confirm both platform digests and publish a GitHub release using the final notes, removing the candidate/blocker text.

Do not move an already published release tag. Tag creation intentionally remains unperformed while publication is blocked.
