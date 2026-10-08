# Bouncer

![Bouncer](docs/icon-256.png)

Bouncer protects HTTP backends with [WebAuthn](https://webauthn.guide/) passkeys and persistent sessions. One Go process serves local HTTPS, trusted external proxies and multiple embedded Tailscale Funnels through an explicit ingress collection. Local HTTPS includes a built-in CA and iOS/macOS trust onboarding.

## Features

- **WebAuthn/Passkey authentication** — no passwords, no TOTP codes
- **Built-in CA** — generates root CA + server certs automatically (no mkcert needed)
- **iOS/macOS onboarding** — serves `.mobileconfig` profiles for trust installation
- **Uniform ingresses** — local sockets, optional mDNS and multiple embedded tsnet/Funnel nodes
- **Single YAML config** — config + user DB in one file; sessions in a separate file
- **One-time enrollment token** — 12 digits, issued on demand, optional Pushover; persisted lockout; local-IP bypass supported
- **Enrollment alerts** — optional Pushover notifications with IP/UA/geo info
- **Transparent reverse proxy** — authenticated users are forwarded to the backend, including long-lived SSE streams and WebSocket upgrades
- **Static binary** — single Go binary, Docker-ready
- **Multi-site support** — host-based routing to multiple backends in one instance
- **Hot-reloadable routing config** — send `SIGHUP` to reload hostnames/sites/backends without restarting unchanged listeners
- **LAN discovery and port routing** — optional mDNS/Bonjour announcements and explicit local ingress ports

## Quick start

Requires Go 1.27.1 or newer. Live tsnet/Funnel enrollment, certificates and teardown have not yet been verified with a tailnet account; local security, lifecycle and browser tests have passed. See [live acceptance](docs/TSNET-PLAN.md#authorised-live-acceptance).

Configure `sites[]` and `ingresses[]`, then validate and run:

```sh
make build
./bouncer --config bouncer.yaml --check-config
./bouncer --config bouncer.yaml --onboarding
# After editing:
kill -HUP <pid>
```

See [uniform ingress configuration](docs/INGRESSES.md) for local/mDNS, external Cloudflare and multiple embedded Funnel endpoints. Existing files must explicitly declare ingresses. Listener/backend/hostname CLI overrides are rejected.

## CLI

- `--config <path>`: YAML configuration path.
- `--check-config`: validate sites/ingresses without starting listeners or resolving secrets.
- `--onboarding`: enable enrollment.
- `--fingerprint-CA`: print existing trust root SHA256.
- `--reset-enrollment`: reset lockout and print a code through a trusted console while stopped.
- `--dbip-update`: update configured geolocation data.
- `--log-level`: debug, info, warn or error.

## How It Works

1. **Normal mode**: users must authenticate with a passkey to access the backend.
2. **Onboarding mode** (`--onboarding`): new users can register a passkey using a one-time 12-digit token (issued on demand and optionally sent via Pushover). Local network users can bypass the token. Optional Pushover alerts can be sent with IP/UA + basic geolocation.
3. **External Cloudflare**: a local HTTP ingress with explicit proxy trust receives the connector traffic.

Sessions expire after 7 days (configurable) and are persisted across restarts.

## Security Notes

- WebAuthn endpoints enforce **same-origin** requests.
- Sessions are **bound to the resolved site and exact passkey credential** in multi-site mode.
- Session cookies are marked **Secure** when requests are HTTPS (or forwarded HTTPS via trusted proxies).
- HSTS is emitted for HTTPS responses.
- WebAuthn responses are **no-store** and servers use **read-header/read timeouts** plus max header size to mitigate slowloris attacks.
- Write timeouts are intentionally disabled because proxied apps such as Piclaw use long-lived SSE streams and WebSocket upgrades.

## Configuration

[docs/INGRESSES.md](docs/INGRESSES.md) defines the authoritative ingress list, defaults, secret references and live reload behaviour. Sites hold app origins/RP IDs/backends; ingresses hold transports, site allowlists and discovery.

### Onboarding notifications (optional)

```yaml
onboarding:
  enabled: true
  oneTimeToken: true
  rotateTokenOnStart: false
  localBypass: true
  pushover:
    enabled: true
    apiToken: pushover-app-token
    userKey: pushover-user-key
    device: iphone
    sound: pushover
  geoip:
    enabled: true
    timeoutSeconds: 2
    cacheTtlSeconds: 3600
    preferCloudflareHeaders: true
    dbip:
      enabled: true
      databasePath: dbip-city-lite.sqlite
      autoUpdate: true
      updateIntervalHours: 24
      updatePageUrl: https://db-ip.com/db/download/ip-to-city-lite
```

Notes:
- One-time codes are issued on demand and consumed by an accepted registration-options request. All codes expire and share persisted failure limits; startup does not reset them. `rotateTokenOnStart` is retained metadata with no rotation effect.
- When `preferCloudflareHeaders` is `true`, Cloudflare geolocation headers are used first (from explicitly trusted local-ingress proxies; never tsnet), falling back to local DB-IP Lite or an optional external geoip URL if configured.
- DB-IP Lite requires attribution to db-ip.com on any page that displays or uses the data.

## YAML configuration

Configuration defaults to `bouncer.yaml`; sessions remain `sessions.json`. Unknown fields, duplicate YAML keys and multiple documents are rejected. Saves use two-space indentation and multiline PEM blocks, but do not preserve comments or original formatting. Quote numeric-looking codes/IDs. Existing JSON content is readable; the next successful save writes YAML. Stop the writer, back up current state and update the launch path when migrating. See [YAML migration](docs/INGRESSES.md#yaml-persistence-and-migration).

## Documentation

- [Operations manual](docs/OPERATIONS.md): deployment, provisioning, reloads, backups, recovery and troubleshooting.

- [Specification](SPEC.md): authentication, persistence and request contracts.
- [Ingress configuration](docs/INGRESSES.md): migration, examples, secrets and reload rules.
- [Architecture](docs/ARCHITECTURE.md): ownership, lifecycle and request path.
- [tsnet decisions and live acceptance](docs/TSNET-PLAN.md): prerequisites and unverified checks.
- [Ingress audit](docs/INGRESS-AUDIT-2026-10-07.md) and [allocation pass](docs/ALLOCATION-PASS-2026-10-08.md): verification and measurements.
- [Development instructions](AGENTS.md): Make targets, portable caches and profiling.

## License

[MIT](LICENSE) © 2026 Rui Carmo

## Validation and allocation profiling

See [the ingress audit](docs/INGRESS-AUDIT-2026-10-07.md), [allocation measurements](docs/ALLOCATION-PASS-2026-10-08.md) and [development instructions](AGENTS.md). The [5 October audit](docs/AUDIT-2026-10.md) records earlier release evidence.

Routine test targets disable caching and run without profiling. Use `make profile PROFILE_MODE=race` (or `test`, `coverage`, `bench`, `integration`, `integration-race`, `browser`, `browser-tls`) for explicit pre-release captures. These runs store profiles, matching binaries and `alloc_space`/`alloc_objects` summaries under the selected project's `tests/allocations/` directory. Inspect summaries, retain concise findings, then remove raw captures and analysis binaries. Production builds exclude profiling endpoints.

```sh
make test
make test-race
make coverage
make test-integration-race
make check
make vuln
make bench TEST_PACKAGES='./internal/session ./internal/site'
# Focused regression:
make test TEST_PACKAGES=./internal/session TEST_FLAGS='-run TestSessionPersistenceFailure'
# Requires Bun and Playwright Chromium:
bun install
make test-browser
make test-browser-tls
```

Use `make profile-diff PROFILE_BASE=OLD.pprof PROFILE_CURRENT=NEW.pprof PROFILE_BINARY=MATCHING.test` for space/object comparisons and benchmark B/op / allocs/op for per-operation measurements. Compare the same workload, toolchain, profiling rate and race setting. Keep concise findings before `make clean-profiles` removes the selected profile directory; normal `make clean` preserves it.

## Proxy deployment requirements

Trusted proxies must overwrite `X-Forwarded-Host`/`X-Forwarded-Proto` and append the observed client address to `X-Forwarded-For`. Bouncer walks XFF right-to-left across trusted hops. Alternative client-IP headers do not authorise enrollment. Missing/malformed attribution never grants local bypass. Disable `onboarding.localBypass` when LAN membership must not permit enrollment.

All enrollment codes expire after 10 minutes and lock after 10 incorrect guesses across all client IPs. A persisted budget of 100 failures spans expired code generations. Automatic issuance, reload and restart cannot clear lockout. Only an operator reset clears it. Successful registration options consume a one-time code; reusable codes retain the same expiry and guess limits.

Existing SSE/WebSocket connections retain their backend across SIGHUP; new requests use the new configuration. Removing a user blocks subsequent requests but does not terminate established streams. Session settings require restart. Ingress additions/removals reload transactionally; conflicting sockets or node identities require removal and addition across two reloads.

For local TLS, an explicit `local` ingress with `tls: "off"` and `bootstrap: true` provides trust downloads. HTTP onboarding links to the canonical HTTPS origin. Shared-host port aliases are ambiguous on the HTTP bootstrap listener; use their explicit HTTPS URLs.

Existing synced passkeys created before backup flags were stored may need re-enrollment. Disable onboarding after provisioning and run only one Bouncer writer per config/session pair.

## v0.1.1 security migration

- Existing sessions remain stored but sessions without `credentialId` require a new passkey login. Removing that credential invalidates subsequent requests even when the account has other credentials. Established streams continue until disconnected; restart for immediate revocation.
- New enrollment codes contain 12 digits. Legacy short codes keep their stored value with bounded lifetime/guesses; reset before provisioning new devices. For operator recovery, stop Bouncer, run `./bouncer --config bouncer.yaml --reset-enrollment` through a trusted console, and restart. Do not run a second writer against live state. Only this explicit reset clears the persisted lockout and global failure budget.
- Root trust requires independent fingerprint verification. Run `./bouncer --config bouncer.yaml --fingerprint-CA` through a trusted server console. Compare the downloaded certificate with `openssl x509 -inform DER -in bouncer-ca.cer -noout -fingerprint -sha256` before installation. The HTTP page, its fingerprint and the unsigned profile can all be replaced on the network. A checkbox is guidance, not cryptographic verification.
- WebSocket upgrades require one exact site `Origin`, including the configured port. Non-browser clients must send it. Bouncer UI uses external scripts under `script-src 'self'`; backend applications retain their own policy.
- Images run as UID/GID `10001:10001` with `/data` as their writable working directory. Named volumes initialise with the image's ownership. Back up existing bind mounts, then grant this UID/GID ownership; no startup chown or root wrapper runs. A file capability permits ports 80/443; runtimes that strip capabilities need explicit bind capability or unprivileged listeners.
- Gateway authentication has a 500-request/minute global ceiling, 4096 rate keys, 1024 pending challenges and 32 concurrent notification jobs per routing generation. Excess requests fail closed and excess notifications are dropped.
- External GeoIP uses a 4096-entry FIFO cache with expiry eviction and 256-byte text fields. JSON is capped at 1 MiB and discovery HTML at 2 MiB. DB-IP caps are 512 MiB compressed, 4 GiB expanded, 64 KiB per logical CSV record and 20 million records. Failed imports keep the old database.

Run the container check with `make test-container` or `make test-container CONTAINER_ENGINE='podman --cgroup-manager=cgroupfs'`. Routine checks use the production build without profiling and retain logs beneath the selected project's `tests/container/` directory. Set `BOUNCER_PROFILE_CONTAINER=1` for an explicit pre-release capture; successful profiled runs remove temporary CA/config state after extracting profiles.
