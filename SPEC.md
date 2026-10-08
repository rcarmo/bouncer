# Bouncer specification

Bouncer protects HTTP backends with WebAuthn passkeys and persistent, site- and credential-bound sessions. It routes by hostname or host:port without rewriting application paths.

## Configuration and ingress

`bouncer.yaml` contains configuration, TLS material and user credentials. `sessions.json` stores sessions separately. [INGRESSES.md](docs/INGRESSES.md) defines the ingress schema, defaults, validation and migration requirements.

- `sites[]` defines stable IDs, public origins, RP IDs, backend URLs and host/IP aliases. Origins must be absolute HTTP(S) URLs without credentials, query or fragment; backend URLs must be absolute HTTP(S) URLs.
- `ingresses[]` is required in existing configuration files and owns listeners, TLS, proxy trust and discovery. There is no legacy listener normalisation. Up to 32 entries are accepted; at least one must be enabled.
- `local` supports `local-ca` or `off` TLS, explicit trusted proxy CIDRs and optional mDNS. A socket may allow several sites.
- `tsnet` provides embedded Funnel TLS with one persistent node and one site per ingress. Ports are 443, 8443 or 10000. Identity directories must be separate, protected and persistent. Enrollment keys are referenced through environment-variable names.
- mDNS is discovery attached to a local listener. It does not create browser DNS aliases.
- New files use the built-in defaults: site `default`, local HTTPS on `:443`, HTTP trust bootstrap on `:80`, origin `https://bouncer.local` and backend `http://127.0.0.1:3000`. When `sites[]` is absent, server-level origin/backend fields supply the single default site; they do not define listeners.

External Cloudflare Tunnel remains a separate connector. Configure its restricted local origin as a `local` ingress with TLS off and explicit proxy trust. No embedded cloudflared connector or implicit loopback trust is provided. The retained `server.cloudflare` field controls certificate-step presentation and certificate-route registration in the main router; listener security comes from the ingress.

## Authentication and enrollment

Normal operation disables registration. Onboarding can be enabled in configuration or with `--onboarding`.

- Passkey registration and login use site-specific RP IDs and exact public origins. Challenges are bounded, expiring, single-use and separated by flow.
- Enrollment uses a cryptographically random 12-digit code issued on demand. Codes expire after 10 minutes and lock after 10 incorrect guesses per generation, including empty submissions. A persisted 100-failure budget spans expired generations.
- One-time codes are consumed by an accepted registration-options request. Reusable codes retain the same expiry and failure limits. Startup and reload do not clear lockout or replace live codes; `rotateTokenOnStart` is retained metadata only.
- A trusted operator can run `--reset-enrollment` while the service is stopped to reset lockout and print a fresh code. API responses and routine logs do not expose codes. Optional Pushover notifications can deliver them.
- When enabled, local bypass uses verified client attribution and RFC1918, loopback or IPv6 ULA membership. It is always disabled on tsnet, including local-looking tailnet peers.
- Rate and enrollment budgets are shared across listeners. Tailnet membership does not replace passkey authentication.

## Sessions and persistence

Sessions store ID, site ID, user ID, credential ID, creation time and last-seen time. Default TTL is seven days from creation. Each authenticated request verifies that the exact credential still exists for that user and site.

Cookies are HttpOnly, SameSite=Lax and Secure when actual TLS or a trusted proxy establishes HTTPS. Removing a credential blocks subsequent requests; established streams continue until disconnected. Sessions without a credential ID require fresh login.

Configuration and session files use same-directory atomic writes with restrictive `0600` permissions. Session creation/deletion persists immediately; last-seen writes are batched. Startup and hourly cleanup prune expired sessions. CA material and tsnet identity survive restart. Use one writer per configuration/session pair; external edits must preserve current credentials and enrollment state.

## Request and trust boundaries

- Sites resolve from Host/host:port, or `X-Forwarded-Host` only from explicitly trusted local-ingress proxies. Unknown or disallowed sites return 404.
- tsnet rejects mismatched Host, port and conflicting TLS SNI. It never trusts forwarded client, host or scheme headers. Public client attribution comes from upstream `ipn.FunnelConn` metadata.
- Forwarded client chains are evaluated right-to-left through trusted hops. Missing or malformed attribution cannot grant local bypass.
- WebAuthn POST requests and WebSocket upgrades require the configured origin. Bouncer's session cookie is stripped before proxying; unrelated backend cookies remain.
- HTTPS responses include HSTS. UI/auth responses use security headers and no-store caching. Header, body, challenge and rate-state limits constrain untrusted input.

## HTTP surfaces

| Route | Behaviour |
|---|---|
| `/login` | Passkey sign-in UI |
| `/onboarding` | Trust/enrollment UI |
| `/static/*` | Embedded client assets |
| `POST /webauthn/register/options`, `/verify` | Onboarding-only registration |
| `POST /webauthn/login/options`, `/verify` | Passkey authentication |
| `POST /logout` | Remove session and clear cookie |
| `/certs/rootCA.cer`, `/certs/rootCA.mobileconfig` | Local-CA trust downloads |
| Other paths, including `/` | Authenticated backend proxy; unauthenticated requests redirect to login/onboarding |

A local HTTP bootstrap ingress serves trust downloads and instructions only. It cannot register passkeys or authenticate. It requires an HTTPS public origin owned by a local-CA ingress and redirects other paths to that origin. Verify the CA SHA256 independently with `--fingerprint-CA` before installing trust.

## TLS, proxying and discovery

Local certificates use ECDSA P-256. The CA lasts 10 years; server certificates last up to one year, capped at CA expiry. Valid matching server certificates are reused until within 30 days of expiry. SANs include only local-CA sites. tsnet uses Tailscale-managed TLS without Bouncer CA wrapping.

The standard reverse proxy preserves methods, bodies, queries and application paths; it supplies sanitised forwarding headers. SSE flushes and bidirectional WebSockets are supported. Servers use 5-second header, 15-second read and 60-second idle timeouts, a 1 MiB header limit and no write timeout. Response copy buffers are pooled for the lifetime of each response.

mDNS publishes DNS-SD records from enabled local discovery settings, using the actual ingress port. Unchanged records are reused across backend-only reloads. Discovery is not proof of browser hostname resolution or public reachability.

## Lifecycle and reload

Startup validates the collection and stages all enabled endpoints before activation. Failure closes staged resources. SIGHUP prepares a candidate before publishing routing and policies; new listeners do not accept HTTP connections or perform TLS handshakes until commit. Failed reloads do not persist prepared certificates or token expiry.

Authentication remains available during staging. A changed configuration file during preparation rejects the candidate; retry SIGHUP. Each request selects routing and trust from one generation. Unchanged listeners and streams survive reload; removed ingresses close their HTTP and hijacked connections and provider resources.

Session storage/settings require restart. Changes conflicting with an active socket or node identity require removal and addition across two reloads. Persistent identity is not deleted on removal. tsnet readiness is bounded to 60 seconds after synchronous upstream Start; Start and ListenFunnel do not have a verified whole-operation timeout. Live Funnel acceptance requires separate authorised testing.

## Commands and verification

```sh
./bouncer --config /data/bouncer.yaml --check-config
./bouncer --config /data/bouncer.yaml --onboarding
./bouncer --config /data/bouncer.yaml --fingerprint-CA
# Service stopped; deliberate enrollment reset:
./bouncer --config /data/bouncer.yaml --reset-enrollment
# DB-IP enabled in configuration:
./bouncer --config /data/bouncer.yaml --dbip-update
kill -HUP <pid>
```

`--log-level` accepts debug, info, warn or error. Listener/backend/hostname/IP/Cloudflare CLI overrides are rejected; edit sites/ingresses instead. `--check-config` starts no listeners/nodes and resolves no secret values; filesystem checks resolve identity-path aliases.

Use Make targets from [AGENTS.md](AGENTS.md) for builds, lint, uncached tests and benchmarks. Routine tests are unprofiled; explicit pre-release captures use `make profile`. See [architecture](docs/ARCHITECTURE.md), [ingress audit](docs/INGRESS-AUDIT-2026-10-07.md) and [allocation measurements](docs/ALLOCATION-PASS-2026-10-08.md) for implementation and verification evidence. No external IAM, path-prefix rewriting, private-only tsnet transport or embedded Cloudflare connector is implemented.
