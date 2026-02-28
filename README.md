# Bouncer

A Go-based reverse proxy that protects backend HTTP services with [WebAuthn](https://webauthn.guide/) (passkeys). Zero-config TLS with a built-in CA, file-backed sessions, and a simple onboarding flow for iOS/macOS devices.

## Features

- **WebAuthn/Passkey authentication** — no passwords, no TOTP codes
- **Built-in CA** — generates root CA + server certs automatically (no mkcert needed)
- **iOS/macOS onboarding** — serves `.mobileconfig` profiles for trust installation
- **Cloudflare Tunnel mode** — skip local TLS entirely, use Cloudflare for HTTPS
- **Single JSON config** — config + user DB in one file; sessions in a separate file
- **6-digit enrollment token** — printed to stdout, with local-IP bypass
- **Transparent reverse proxy** — authenticated users are forwarded to the backend seamlessly
- **Static binary** — single Go binary, Docker-ready

## Quick Start

### Cloudflare Tunnel mode (simplest)

```bash
# Build
make build

# Run with onboarding enabled
./bouncer --cloudflare --onboarding --backend http://localhost:3000

# Note the 6-digit token printed to stdout
# Visit your Cloudflare hostname → /onboarding
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
  --log-level <level>     debug|info|warn|error
```

## How It Works

1. **Normal mode**: users must authenticate with a passkey to access the backend.
2. **Onboarding mode** (`--onboarding`): new users can register a passkey using a 6-digit token (printed to logs). Local network users can bypass the token.
3. **Cloudflare mode** (`--cloudflare`): Cloudflare provides HTTPS; Bouncer skips TLS and certificate onboarding.

Sessions expire after 7 days (configurable) and are persisted across restarts.

## Configuration

See [SPEC.md](SPEC.md) for the full JSON schema and configuration reference.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the package layout and design.

## License

[MIT](LICENSE) © 2026 Rui Carmo
