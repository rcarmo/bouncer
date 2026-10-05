# Bouncer v0.1.1

Security fixes for the second audit of v0.1.0.

## Changes

- Generate 12-digit enrollment codes. Persist lockout after 10 wrong guesses per code and a 100-failure budget across automatic generations. Reusable codes also expire. Automatic issuance and restart cannot unlock enrollment; a trusted operator can use `--reset-enrollment` while the service is stopped.
- Rate-limit missing client attribution by the parsed peer address. Bound global authentication traffic, rate keys, challenges and concurrent notification work.
- Bind sessions to the exact passkey credential and require matching browser Origin on WebSocket upgrades.
- Expose a read-only CA SHA256 command, startup fingerprint and verification instructions. Warn that HTTP trust bootstrap is unauthenticated and an unsigned root profile grants broad TLS authority.
- Serve external UI scripts with a self-only script policy.
- Bound external JSON, HTML, compressed/expanded DB-IP data, CSV records and rows. Cap the GeoIP cache and evict expired entries.
- Pin workflow actions to commit SHAs, disable checkout credential persistence and restrict package writes to publishing jobs.
- Run the container as UID/GID 10001 in owned `/data`, retaining low-port bind capability.
- Remove backend URLs from mDNS and enrollment codes from normal logs/stdout. Codes remain available through optional Pushover and the explicit trusted reset command.

## Migration

Back up config, credentials, CA keys and sessions. Legacy sessions require a new login; stored credentials and the CA remain unchanged. Removing a credential denies new requests from its sessions; restart to terminate existing streams. Set bind-mount ownership to UID/GID 10001 before upgrading. Stop the single writer before using the reset command, then restart. See the [README migration section](../README.md#v011-security-migration).

## Verification

Local profiled unit, race, coverage (52.8%), real-process reload/streaming, Chromium HTTP/TLS passkey/SSE/WebSocket and non-root container tests passed. Allocation profiles, matching binaries and summaries were retained. Vet, lint, gosec, workflow validation and the reachable-vulnerability scan passed.

Physical authenticator/OS trust installation and ARM64 runtime were not tested locally. Fingerprint comparison requires an independent trusted channel; the HTTP acknowledgement cannot prevent an attacker replacing the page.
