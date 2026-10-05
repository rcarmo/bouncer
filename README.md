# Bouncer

![Bouncer](docs/icon-256.png)

A Go-based reverse proxy that protects backend HTTP services with [WebAuthn](https://webauthn.guide/) (passkeys). Zero-config TLS with a built-in CA, file-backed sessions, and a simple onboarding flow for iOS/macOS devices.

## Features

- **WebAuthn/Passkey authentication** — no passwords, no TOTP codes
- **Built-in CA** — generates root CA + server certs automatically (no mkcert needed)
- **iOS/macOS onboarding** — serves `.mobileconfig` profiles for trust installation
- **Cloudflare Tunnel mode** — skip local TLS entirely, use Cloudflare for HTTPS
- **Single JSON config** — config + user DB in one file; sessions in a separate file
- **One-time enrollment token** — 12 digits, issued on demand, optional Pushover; persisted lockout; local-IP bypass supported
- **Enrollment alerts** — optional Pushover notifications with IP/UA/geo info
- **Transparent reverse proxy** — authenticated users are forwarded to the backend seamlessly, including long-lived SSE streams and WebSocket upgrades
- **Static binary** — single Go binary, Docker-ready
- **Multi-site support** — host-based routing to multiple backends in one instance
- **Hot-reloadable routing config** — send `SIGHUP` to reload hostnames/sites/backends without restarting
- **LAN discovery and aliases** — optional mDNS/Bonjour announcements and per-site listener ports

## Quick Start

### Cloudflare Tunnel mode (simplest)

```bash
# Build
make build

# Run with onboarding enabled
./bouncer --cloudflare --onboarding --hostname bouncer.example.com --backend http://localhost:3000

# Visit your Cloudflare hostname → /onboarding
# Start registration to trigger a one-time token (sent via Pushover; otherwise use the trusted reset command)
```

### Local TLS mode

```bash
# Run — generates CA + certs on first start
./bouncer --onboarding --hostname myhost.local --ip 192.168.1.50 --backend http://localhost:3000

# Independently obtain the CA SHA256: ./bouncer --fingerprint-CA
# Visit http://myhost.local/onboarding, verify the downloaded certificate
# against the trusted fingerprint, then install the trust profile
# Then visit https://myhost.local/onboarding to create a passkey
```

### Docker

```bash
make docker-build
docker volume create bouncer-data
docker run -p 443:443 -p 80:80 -v bouncer-data:/data bouncer \
  --config /data/bouncer.json --onboarding --backend http://host.docker.internal:3000
```

## CLI

```
Usage: bouncer [flags]

Flags:
  --config <path>         Path to JSON config (default: ./bouncer.json)
  --listen <addr>         Listen address (default: :443 for TLS, :8080 for HTTP)
  --backend <url>         Backend HTTP URL (e.g., http://localhost:3000)
  --hostname <host>       DNS name for TLS SANs (may be repeated)
  --ip <addr>             IP for TLS SANs (may be repeated)
  --onboarding            Enable onboarding mode (allow registration)
  --cloudflare            Cloudflare Tunnel mode (no local TLS)
  --dbip-update           Download/update DB-IP Lite database and exit
  --fingerprint-CA        Print existing CA certificate SHA256 through a trusted console
  --reset-enrollment      Reset enrollment lockout, print a fresh code and exit
  --log-level <level>     debug|info|warn|error
```

## How It Works

1. **Normal mode**: users must authenticate with a passkey to access the backend.
2. **Onboarding mode** (`--onboarding`): new users can register a passkey using a one-time 12-digit token (issued on demand and optionally sent via Pushover). Local network users can bypass the token. Optional Pushover alerts can be sent with IP/UA + basic geolocation.
3. **Cloudflare mode** (`--cloudflare`): Cloudflare provides HTTPS; Bouncer skips TLS and certificate onboarding.

Sessions expire after 7 days (configurable) and are persisted across restarts.

## Security Notes

- WebAuthn endpoints enforce **same-origin** requests.
- Sessions are **bound to the resolved site and exact passkey credential** in multi-site mode.
- Session cookies are marked **Secure** when requests are HTTPS (or forwarded HTTPS via trusted proxies).
- HSTS is emitted for HTTPS responses.
- WebAuthn responses are **no-store** and servers use **read-header/read timeouts** plus max header size to mitigate slowloris attacks.
- Write timeouts are intentionally disabled because proxied apps such as Piclaw use long-lived SSE streams and WebSocket upgrades.

## Configuration

### Single-site (default)

```json
{
  "server": {
    "listen": ":443",
    "publicOrigin": "https://bouncer.example.com",
    "rpID": "bouncer.example.com",
    "backend": "http://127.0.0.1:3000",
    "hostnames": ["bouncer.example.com"],
    "ipAddresses": ["192.168.1.50"]
  }
}
```

### Multi-site (host-based routing)

```json
{
  "server": {
    "listen": ":443",
    "cloudflare": false,
    "trustedProxies": []
  },
  "sites": [
    {
      "id": "app-a",
      "publicOrigin": "https://a.example.com",
      "rpID": "a.example.com",
      "backend": "http://127.0.0.1:3001",
      "hostnames": ["a.example.com"],
      "ipAddresses": ["192.168.1.10"]
    },
    {
      "id": "app-b",
      "publicOrigin": "https://b.example.com",
      "rpID": "b.example.com",
      "backend": "http://127.0.0.1:3002",
      "hostnames": ["b.example.com"],
      "ipAddresses": ["192.168.1.11"]
    }
  ]
}
```

Notes:
- If `sites` is present, **CLI overrides** for `--backend`, `--hostname`, and `--ip` are ignored.
- In local TLS mode, Bouncer **aggregates SANs** from all sites when generating the server certificate.
- In Cloudflare mode, set `publicOrigin`/`rpID` per site to the Cloudflare hostname.

### LAN port aliases and mDNS

For environments where you cannot control LAN DNS/DHCP, each site can bind an extra listener port and Bouncer can advertise Bonjour/mDNS service records:

```json
{
  "server": {
    "listen": ":443",
    "mdns": { "enabled": true, "service": "_https._tcp", "domain": "local." }
  },
  "sites": [
    {
      "id": "smith-lan",
      "publicOrigin": "https://192.168.1.50:8441",
      "rpID": "192.168.1.50",
      "backend": "http://127.0.0.1:8081",
      "hostnames": ["192.168.1.50"],
      "ipAddresses": ["192.168.1.50"],
      "listen": ":8441"
    },
    {
      "id": "jones-lan",
      "publicOrigin": "https://192.168.1.50:8442",
      "rpID": "192.168.1.50",
      "backend": "http://127.0.0.1:8082",
      "hostnames": ["192.168.1.50"],
      "ipAddresses": ["192.168.1.50"],
      "listen": ":8442"
    }
  ]
}
```

This gives no-DNS LAN URLs such as `https://192.168.1.50:8441` and `https://192.168.1.50:8442`. mDNS advertises discoverable services for Bonjour-aware clients, but ordinary browsers still need a URL/bookmark; mDNS service discovery is not the same as wildcard DNS aliases.

### Hot reload

Bouncer reloads routing/auth/proxy configuration on `SIGHUP`:

```bash
kill -HUP $(pidof bouncer)
```

Reloadable without restart:

- `sites[]` additions/removals/hostname changes
- site `backend` URLs
- `trustedProxies`
- onboarding flags and token settings
- local TLS SANs/certificate material for new hostnames

Not reloadable without restart:

- listen address (`server.listen`)
- Cloudflare-vs-local-TLS mode (`server.cloudflare`)

This is intended for adding more hostnames/backends while keeping existing SSE and WebSocket sessions alive.

See [SPEC.md](SPEC.md) for the full JSON schema and configuration reference.

### Onboarding notifications (optional)

```json
{
  "onboarding": {
    "enabled": true,
    "oneTimeToken": true,
    "rotateTokenOnStart": true,
    "localBypass": true,
    "pushover": {
      "enabled": true,
      "apiToken": "pushover-app-token",
      "userKey": "pushover-user-key",
      "device": "iphone",
      "sound": "pushover"
    },
    "geoip": {
      "enabled": true,
      "timeoutSeconds": 2,
      "cacheTtlSeconds": 3600,
      "preferCloudflareHeaders": true,
      "dbip": {
        "enabled": true,
        "databasePath": "dbip-city-lite.sqlite",
        "autoUpdate": true,
        "updateIntervalHours": 24,
        "updatePageUrl": "https://db-ip.com/db/download/ip-to-city-lite"
      }
    }
  }
}
```

Notes:
- When `oneTimeToken` is `true`, tokens are issued on demand and consumed after use. All codes expire and share persisted failure limits; startup does not reset them.
- When `preferCloudflareHeaders` is `true`, Cloudflare geolocation headers are used first (from trusted proxies), falling back to local DB-IP Lite or an optional external geoip URL if configured.
- DB-IP Lite requires attribution to db-ip.com on any page that displays or uses the data.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the package layout and design.

## License

[MIT](LICENSE) © 2026 Rui Carmo

## Validation and allocation profiling

See [the October 2026 audit](docs/AUDIT-2026-10.md) and [development instructions](AGENTS.md).

Every test target records allocation profiles, matching binaries and `alloc_space`/`alloc_objects` summaries in a unique `artifacts/allocations/` directory. Integration/browser tests also profile each Bouncer server process. No profiling endpoint is included in production builds.

```sh
make test
make test-race
make coverage
make test-integration-race
make check
make vuln
make bench TEST_PACKAGES='./internal/session ./internal/site'
# Focused regression, still fully profiled:
make test TEST_PACKAGES=./internal/session TEST_FLAGS='-run TestSessionPersistenceFailure'
# Requires Bun and Playwright Chromium:
bun install
make test-browser
make test-browser-tls
```

Use `make clean-profiles` to remove allocation evidence explicitly. Normal `make clean` preserves it. Compare equivalent workloads using `go tool pprof -alloc_space -base OLD.pprof NEW.pprof` (also `-alloc_objects`) and benchmark B/op / allocs/op.

## Proxy deployment requirements

Trusted proxies must overwrite `X-Forwarded-Host`/`X-Forwarded-Proto` and append the observed client address to `X-Forwarded-For`. Bouncer walks XFF right-to-left across trusted hops. Alternative client-IP headers do not authorise enrollment. Missing/malformed attribution never grants local bypass. Disable `onboarding.localBypass` when LAN membership must not permit enrollment.

All enrollment codes expire after 10 minutes and lock after 10 incorrect guesses across all client IPs. A persisted budget of 100 failures spans expired code generations. Automatic issuance, reload and restart cannot clear lockout. Only an operator reset clears it. Successful registration options consume a one-time code; reusable codes retain the same expiry and guess limits.

Existing SSE/WebSocket connections retain their backend across SIGHUP; new requests use the new configuration. Removing a user blocks subsequent requests but does not terminate established streams. Session settings and listener addresses require restart.

For local TLS, optional `server.httpListen` overrides the separate trust/download listener (default `:80`, or `:8080` with a nonstandard TLS port). HTTP onboarding links to the canonical HTTPS origin. Shared-host port aliases are ambiguous on the HTTP bootstrap listener; use their explicit HTTPS URLs.

Existing synced passkeys created before backup flags were stored may need re-enrollment. Disable onboarding after provisioning and run only one Bouncer writer per config/session pair.

## v0.1.1 security migration

- Existing sessions remain stored but sessions without `credentialId` require a new passkey login. Removing that credential invalidates subsequent requests even when the account has other credentials. Established streams continue until disconnected; restart for immediate revocation.
- New enrollment codes contain 12 digits. Legacy short codes keep their stored value with bounded lifetime/guesses; reset before provisioning new devices. For operator recovery, stop Bouncer, run `./bouncer --config bouncer.json --reset-enrollment` through a trusted console, and restart. Do not run a second writer against live state. Only this explicit reset clears the persisted lockout and global failure budget.
- Root trust requires independent fingerprint verification. Run `./bouncer --config bouncer.json --fingerprint-CA` through a trusted server console. Compare the downloaded certificate with `openssl x509 -inform DER -in bouncer-ca.cer -noout -fingerprint -sha256` before installation. The HTTP page, its fingerprint and the unsigned profile can all be replaced on the network. A checkbox is guidance, not cryptographic verification.
- WebSocket upgrades require one exact site `Origin`, including the configured port. Non-browser clients must send it. Bouncer UI uses external scripts under `script-src 'self'`; backend applications retain their own policy.
- Images run as UID/GID `10001:10001` with `/data` as their writable working directory. Named volumes initialise with the image's ownership. Back up existing bind mounts, then grant this UID/GID ownership; no startup chown or root wrapper runs. A file capability permits ports 80/443; runtimes that strip capabilities need explicit bind capability or unprivileged listeners.
- Gateway authentication has a 500-request/minute global ceiling, 4096 rate keys, 1024 pending challenges and 32 concurrent notification jobs per routing generation. Excess requests fail closed and excess notifications are dropped.
- External GeoIP uses a 4096-entry FIFO cache with expiry eviction. JSON is capped at 1 MiB and discovery HTML at 2 MiB. DB-IP caps are 512 MiB compressed, 4 GiB expanded, 64 KiB per logical CSV record and 20 million records. Failed imports keep the old database.

Run the profiled container check with `make test-container` or `make test-container CONTAINER_ENGINE='podman --cgroup-manager=cgroupfs'`. Its image enables the test-only `allocprofile` tag; normal Docker builds leave that tag empty. Test state stays under gitignored allocation evidence; the successful runner removes temporary CA/config state after retaining profiles.
