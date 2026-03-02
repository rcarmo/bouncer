# Bouncer Spec

## Overview
Bouncer is a Go-based reverse proxy that protects backend HTTP services using WebAuthn (passkeys). It supports **single-site** and **multi-site** (host-based) routing, with an **onboarding mode** to help users install trust (via iOS/macOS profiles) and register passkeys, then transparently forwards authenticated users to the backend service.

Configuration and user data live in a **single JSON file**. Sessions are persisted in a **separate JSON file** with a configurable TTL. A CLI switch enables onboarding mode.

## Goals
- Simple, self-contained reverse proxy with WebAuthn authentication.
- Onboarding flow for iOS/macOS trust + passkey registration.
- Transparent pass-through once authenticated (no app changes required).
- Single JSON file for config + user DB.
- **Multi-site host-based routing** (one instance, multiple public origins/backends).
- Optional **simplified mode** via Cloudflare Tunnel (no local TLS or profiles).

## Non‑Goals
- Multi-tenant or multi‑backend routing.
- External DB dependencies.
- Enterprise IAM features (SAML/OIDC, RBAC, SCIM).

---

## Architecture

```
Client Browser
   | HTTPS
   v
Bouncer (TLS + WebAuthn + Session)
   | HTTP
   v
Backend Service (existing app)
```

Key components:
- **HTTP(S) reverse proxy** (Go `net/http`, `httputil.ReverseProxy`).
- **WebAuthn server** (Go library: `github.com/go-webauthn/webauthn`).
- **Session manager** (secure httpOnly cookie, persisted to a separate `sessions.json` file with TTL).
- **Static onboarding UI** served by Bouncer (vendored Preact/HTM, embedded via `embed.FS`).
- **Config + user DB** stored in `bouncer.json`; sessions in `sessions.json`.

---

## Modes

### 1) Normal Mode (default)
- Passkey **registration disabled**.
- Only authenticated users (valid session cookie) can access the backend.
- Unauthenticated users see a **login page** (passkey assertion).

### 2) Onboarding Mode (`--onboarding`)
- Registration enabled.
- Enrollment requires a **six‑digit token**; local IP ranges (RFC1918 + loopback) bypass the token when `onboarding.localBypass` is `true` (default).
- Token is **randomly generated on startup** and **printed to stdout/proxy logs**.
- Optional **Pushover alerts** can be sent on enrollment attempts (IP, UA, basic geo lookup).
- Users without a valid session see **onboarding UI**:
  - If TLS is not trusted (local CA use‑case): prompt to install the profile.
  - Then prompt to **enter the 6‑digit token** and **create a passkey**.
- After passkey creation, user is redirected to the backend.

### 3) Cloudflare Tunnel Mode (`--cloudflare`)
- Bouncer listens on **local HTTP only** (no TLS termination).
- Cloudflare Tunnel provides the public HTTPS hostname + certs.
- `rpID` and `publicOrigin` must be set to the **Cloudflare hostname** (not the local address).
- Onboarding UI **skips certificate/profile installation** and goes directly to passkey registration/login.
- Bouncer trusts `X-Forwarded-Proto` only from IPs listed in `server.trustedProxies` (loopback is auto-trusted in Cloudflare mode).

---

## CLI

```
Usage: bouncer [flags]

Flags:
  --config <path>         Path to JSON config (default: ./bouncer.json)
  --listen <addr>         Listen address (default: :443 for TLS, :8080 for HTTP)
  --backend <url>         Backend HTTP URL (e.g., http://localhost:3000)
  --hostname <host>       Override DNS name for TLS/WebAuthn (may be repeated)
  --ip <addr>             Override IP SAN for TLS/WebAuthn (may be repeated)
  --onboarding            Enable onboarding mode (allow registration)
  --cloudflare            Enable Cloudflare Tunnel mode (no local TLS/profile flow)
  --log-level <level>     info|debug|warn|error

Note: CLI overrides for `--backend`, `--hostname`, and `--ip` apply only in single-site mode. When `sites` is configured, these flags are ignored.
```

---

## Config JSON (Single File)

**File:** `bouncer.json`

```json
{
  "server": {
    "listen": ":443",
    "publicOrigin": "https://bouncer.local",
    "rpID": "bouncer.local",
    "backend": "http://127.0.0.1:3000",
    "hostnames": ["bouncer.local"],
    "ipAddresses": ["192.168.1.50"],
    "trustedProxies": [],
    "tls": {
      "ca": {
        "certPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "keyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      },
      "serverCert": {
        "certPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "keyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      }
    },
    "cloudflare": false
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
  ],
  "session": {
    "ttlDays": 7,
    "cookieName": "bouncer_session",
    "file": "sessions.json"
  },
  "onboarding": {
    "enabled": false,
    "token": "",
    "rotateTokenOnStart": true,
    "localBypass": true,
    "profileUrl": "/certs/rootCA.mobileconfig",
    "macCertUrl": "/certs/rootCA.cer",
    "instructions": {
      "ios": [
        "Install the profile",
        "Enable full trust in Certificate Trust Settings"
      ]
    },
    "pushover": {
      "enabled": false,
      "apiToken": "",
      "userKey": "",
      "device": "",
      "sound": "",
      "timeoutSeconds": 3
    },
    "geoip": {
      "enabled": true,
      "url": "https://ipapi.co/%s/json/",
      "timeoutSeconds": 2,
      "cacheTtlSeconds": 3600
    }
  },
  "users": [
    {
      "id": "user-1",
      "site": "app-a",
      "displayName": "Alice",
      "name": "alice@example.com",
      "credentials": [
        {
          "id": "base64url-credential-id",
          "publicKey": "base64url-public-key",
          "signCount": 12,
          "transports": ["internal"],
          "createdAt": "2026-02-28T15:00:00Z"
        }
      ]
    }
  ]
}
```

### Notes
- `publicOrigin` must match the hostname used by browsers.
- `rpID` should be the eTLD+1 or host portion of `publicOrigin`. In Cloudflare mode, this is the **Cloudflare hostname**, not the local address.
- `hostnames`/`ipAddresses` define TLS SANs; they can be set in config or overridden via CLI.
- `trustedProxies`: CIDR list. `X-Forwarded-*` headers are only trusted from these IPs. Empty = trust nothing (direct mode). In Cloudflare mode, loopback is auto-trusted; add Cloudflare ranges if you terminate upstream.
- In Cloudflare mode, `tls` may be omitted.
- If `sites` is set, each site defines its own `publicOrigin`, `rpID`, and `backend`. CLI overrides for `--backend`, `--hostname`, and `--ip` are ignored in multi-site mode.
- `session.ttlDays`: sessions expire after this many days (default 7); user must re‑authenticate with passkey.
- `session.file`: path to the sessions JSON file (default `sessions.json`, relative to config dir).
- `onboarding.rotateTokenOnStart`: if `true`, a new 6‑digit token is generated on each startup (old token discarded).
- `onboarding.localBypass`: if `true`, requests from RFC1918 + loopback IPs skip the token requirement.
- `users` holds registered WebAuthn credentials. In multi-site mode, each user is tagged with `site` (defaults to `default` for legacy entries).

---

## WebAuthn Flow

### Registration (Onboarding Mode only)
1. User visits `/onboarding`.
2. If required, user installs the trust profile/cert.
3. User enters **six‑digit enrollment token**.
   - If `onboarding.localBypass` is `true` and request is from RFC1918/loopback, token is not required.
4. Client calls `POST /webauthn/register/options` (token included).
5. Server returns `PublicKeyCredentialCreationOptions`.
6. Client creates credential (`navigator.credentials.create`).
7. Client sends result to `POST /webauthn/register/verify`.
8. Server verifies and stores credential under the user.
9. Server issues session cookie and redirects to backend.

### Login (Normal + Onboarding)
1. Client calls `POST /webauthn/login/options`.
2. Server returns `PublicKeyCredentialRequestOptions`.
3. Client uses `navigator.credentials.get`.
4. Client sends result to `POST /webauthn/login/verify`.
5. Server verifies and issues session cookie.

### Session
- Cookie: `bouncer_session` (httpOnly, secure, SameSite=Lax).
- **Persisted** in a separate `sessions.json` file (configurable path).
- Each session record stores: session ID, site ID, user ID, creation time, last‑seen time.
- **TTL**: sessions expire after `session.ttlDays` (default **7 days**) from creation. Expired sessions require a fresh passkey login.
- Cleanup: expired sessions are pruned on startup and periodically (e.g., hourly).
- Atomic writes: write to temp file, fsync, rename (same strategy as `bouncer.json`).

---

## HTTP Routes

### UI
- `GET /login` → login page (passkey sign-in)
- `GET /onboarding` → onboarding page (profile + passkey creation)

### WebAuthn API
- `POST /webauthn/register/options`
- `POST /webauthn/register/verify`
- `POST /webauthn/login/options`
- `POST /webauthn/login/verify`
- `POST /logout`

### Cert/Profiles (local TLS mode only)
- `GET /certs/rootCA.mobileconfig` — served over **HTTP or HTTPS** (profile must be downloadable before trust is established).
- `GET /certs/rootCA.cer` — served over **HTTP or HTTPS**.

### Proxy
- All other paths → forwarded to backend **only if authenticated**.
- Unauthenticated requests → redirect to `/login` or `/onboarding`.

---

## Reverse Proxy Behavior
- Preserve method, headers, body, query string.
- Add standard proxy headers:
  - `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`.
- In multi-site mode, route by `Host` (or `X-Forwarded-Host` from trusted proxies).
- Optional allowlist of headers to strip (e.g., `Authorization`).

---

## TLS + Certificates

### Local TLS Mode (Built‑in CA, no mkcert)
- On first run (or when `tls.ca` is empty), Bouncer generates a **root CA** and persists it in the JSON config.
- Bouncer mints a **server certificate** signed by that CA using `hostnames` + `ipAddresses` as SANs.
- TLS uses the generated server cert/key (stored in JSON or regenerated on startup).
- Bouncer serves the CA as `.cer` and a **mobileconfig profile** for iOS/macOS.
- **Profile signing is not required** (unsigned profile is acceptable, with extra warnings).

### Cloudflare Tunnel Mode (Simplified)
- Cloudflare handles TLS and public origin.
- Bouncer runs HTTP locally; trusts `X-Forwarded-Proto` **only from `trustedProxies`** IPs.
- Onboarding UI skips profile/cert steps and focuses on passkey setup.
- `rpID` and `publicOrigin` must be the Cloudflare hostname.

---

## Built‑in CA Details (Go)
- **Key type**: ECDSA P‑256 (or RSA‑2048 if you prefer broader legacy support).
- **Root CA cert**:
  - `IsCA = true`, `BasicConstraintsValid = true`
  - `KeyUsage`: `CertSign | CRLSign | DigitalSignature`
  - Validity: e.g., 5–10 years
- **Server cert**:
  - `KeyUsage`: `DigitalSignature | KeyEncipherment`
  - `ExtKeyUsage`: `ServerAuth`
  - SANs: `hostnames` + `ipAddresses`
  - Validity: e.g., 1 year
- **Serials**: 128‑bit random.
- **Persistence**: store CA PEM in JSON; re‑issue server cert if SANs change.

### iOS/macOS Profile (unsigned)
- Serve a `.mobileconfig` with `PayloadType = "Configuration"` containing a **root CA payload**:
  - Root CA payload `PayloadType`: `com.apple.security.root`
  - `PayloadContent`: DER‑encoded certificate bytes (base64)
- Also serve `rootCA.cer` (DER) for macOS import.
- Unsigned profiles show extra warnings but are acceptable for local onboarding.

#### Example `.mobileconfig` (minimal, unsigned)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>local.bouncer.rootca</string>
  <key>PayloadUUID</key>
  <string>REPLACE-WITH-UUID</string>
  <key>PayloadDisplayName</key>
  <string>Bouncer Local CA</string>
  <key>PayloadDescription</key>
  <string>Installs the Bouncer local root CA so your device trusts the local HTTPS server.</string>
  <key>PayloadOrganization</key>
  <string>Bouncer</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>local.bouncer.rootca.payload</string>
      <key>PayloadUUID</key>
      <string>REPLACE-WITH-UUID</string>
      <key>PayloadDisplayName</key>
      <string>Bouncer Root CA</string>
      <key>PayloadContent</key>
      <data>
      BASE64_DER_CERT_HERE
      </data>
    </dict>
  </array>
</dict>
</plist>
```

---

## Onboarding UX Requirements
- Detect if browser is iOS/macOS and show trust instructions.
- Provide clear buttons/inputs:
  - “Install iOS/macOS profile”
  - “Download macOS cert (optional)”
  - **Enrollment token input (6 digits)**
  - “Create passkey”
  - “Sign in with passkey”
- If `onboarding.localBypass` is `true` and request is from a local IP, token input is hidden.
- After passkey success, redirect to original requested URL.

---

## Security Considerations
- Enforce HTTPS for all routes except `/certs/*` in local TLS mode (profile must be downloadable before trust is established).
- Require same-origin for WebAuthn endpoints.
- Validate `Origin` and `RP ID` strictly; in Cloudflare mode these must match the tunnel hostname.
- Rate limit WebAuthn attempts (basic IP-based throttling).
- Sessions are bound to the resolved `site` to prevent cross-site reuse.
- Session cookies are marked `Secure` when the request is HTTPS or when a trusted proxy reports `X-Forwarded-Proto: https`.
- HSTS is emitted on HTTPS responses.
- WebAuthn responses use `Cache-Control: no-store`.
- HTTP servers enforce sane timeouts and max header size to mitigate slowloris-style attacks.
- Protect `bouncer.json` and `sessions.json` with restrictive file permissions (0600).
- Enrollment token is **6 digits**, generated via `crypto/rand`.
- Token is **printed to stdout/proxy logs** when onboarding is active; never exposed via API.
- `onboarding.localBypass`: when enabled, only RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) + loopback (`127.0.0.0/8`, `::1`) skip the token.
- `trustedProxies`: `X-Forwarded-*` headers are stripped unless `RemoteAddr` matches a trusted proxy CIDR. Prevents origin/proto spoofing.

---

## Persistence Strategy
- **`bouncer.json`**: config + user DB. Loaded at startup; written back on credential changes. Atomic writes (temp + fsync + rename).
- **`sessions.json`**: session records. Separate file so session churn doesn't rewrite the config. Atomic writes. Pruned of expired entries on startup and periodically.
- CA key/cert PEM persisted in `bouncer.json` so trust survives restarts.
- Enrollment token persisted in `bouncer.json`; rotated on startup when `rotateTokenOnStart` is `true`.

---

## Implementation Notes (Go)
- HTTP server with `net/http`.
- Reverse proxy with `httputil.NewSingleHostReverseProxy`.
- WebAuthn using `github.com/go-webauthn/webauthn`.
- Static UI (vanilla JS) embedded via `embed.FS`.
- JSON persistence using `encoding/json` + atomic file writes.
- CA/cert generation using `crypto/x509`, `crypto/ecdsa`, `crypto/rand`, and `encoding/pem`.
- Token generation: 6‑digit via `crypto/rand` (uniform 000000–999999).
- Mobileconfig generation: minimal XML template with UUIDs generated via `crypto/rand`.
- Local IP detection: parse `RemoteAddr` (or `CF-Connecting-IP`/`True-Client-IP`/`X-Forwarded-For` when sender is trusted) and match against RFC1918/loopback CIDRs.
- Session file: loaded into in-memory map on startup; flushed to disk on changes + periodic sync.
- Token validation: checked in `POST /webauthn/register/options` before issuing a challenge.

---

## Future Enhancements
- Admin UI for user management.
- Enrollment tokens for adding users in normal mode.
- Audit log to file.
- mTLS for backend.
- Optional OIDC upstream integration.
