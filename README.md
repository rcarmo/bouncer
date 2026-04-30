# Bouncer

![Bouncer](docs/icon-256.png)

A Go-based reverse proxy that protects backend HTTP services with [WebAuthn](https://webauthn.guide/) (passkeys). Zero-config TLS with a built-in CA, file-backed sessions, and a simple onboarding flow for iOS/macOS devices.

## Features

- **WebAuthn/Passkey authentication** — no passwords, no TOTP codes
- **Built-in CA** — generates root CA + server certs automatically (no mkcert needed)
- **iOS/macOS onboarding** — serves `.mobileconfig` profiles for trust installation
- **Cloudflare Tunnel mode** — skip local TLS entirely, use Cloudflare for HTTPS
- **Single JSON config** — config + user DB in one file; sessions in a separate file
- **One-time enrollment token** — 6 digits, issued on demand, logged + optional Pushover; local-IP bypass supported
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
./bouncer --cloudflare --onboarding --backend http://localhost:3000

# Visit your Cloudflare hostname → /onboarding
# Start registration to trigger a one-time token (printed to logs and sent via Pushover)
```

### Local TLS mode

```bash
# Run — generates CA + certs on first start
./bouncer --onboarding --hostname myhost.local --ip 192.168.1.50 --backend http://localhost:3000

# Visit http://myhost.local/onboarding to install the trust profile
# Then visit https://myhost.local/onboarding to create a passkey
```

### Docker

```bash
make docker
docker run -p 443:443 -p 80:80 -v $(pwd)/data:/data bouncer \
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
  --log-level <level>     debug|info|warn|error
```

## How It Works

1. **Normal mode**: users must authenticate with a passkey to access the backend.
2. **Onboarding mode** (`--onboarding`): new users can register a passkey using a one-time 6-digit token (issued on demand and logged). Local network users can bypass the token. Optional Pushover alerts can be sent with IP/UA + basic geolocation.
3. **Cloudflare mode** (`--cloudflare`): Cloudflare provides HTTPS; Bouncer skips TLS and certificate onboarding.

Sessions expire after 7 days (configurable) and are persisted across restarts.

## Security Notes

- WebAuthn endpoints enforce **same-origin** requests.
- Sessions are **bound to the resolved site** in multi-site mode.
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
- When `oneTimeToken` is `true`, tokens are issued on the first registration attempt and consumed after use. `rotateTokenOnStart` is ignored.
- When `preferCloudflareHeaders` is `true`, Cloudflare geolocation headers are used first (from trusted proxies), falling back to local DB-IP Lite or an optional external geoip URL if configured.
- DB-IP Lite requires attribution to db-ip.com on any page that displays or uses the data.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the package layout and design.

## License

[MIT](LICENSE) © 2026 Rui Carmo
