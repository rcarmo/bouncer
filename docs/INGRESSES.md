# Uniform ingress configuration

Bouncer uses `ingresses[]` as the authoritative listener list. Sites describe app hostnames, WebAuthn RP IDs and backends; ingress entries bind those sites to local sockets or embedded Tailscale Funnel nodes. mDNS advertises a local listener and is configured on that entry.

Implementation is locally tested for routing, policy and live local-listener reload. Real Funnel connectivity/enrollment has not been verified with a tailnet account. No production configuration has been changed.

## Migrating existing configuration

Back up configuration, sessions and CA/identity state before editing. Add explicit `ingresses[]` for every required listener. Move listener TLS, trusted proxies and mDNS settings into each local ingress; retained server/site `listen` and server `httpListen` fields do not create sockets. Preserve stable site IDs, RP IDs, public origins and user credentials. Remove rejected listener/backend/hostname/IP/Cloudflare flags from launch commands, validate with `--check-config`, then reload or restart as required. Never copy production secrets into examples.

When using explicit `sites[]`, reference those IDs from each ingress. The built-in `default` site exists only when no explicit sites are declared. Retained server-level origin/backend fields supply that default site's routing, not listener configuration. There is no automatic legacy listener migration.

## Two apps and a LAN listener

```json
{
  "sites": [
    {"id":"notes-lan","publicOrigin":"https://notes.local","rpID":"notes.local","backend":"http://notes:3000"},
    {"id":"notes-public","publicOrigin":"https://notes.example.ts.net","rpID":"notes.example.ts.net","backend":"http://notes:3000"},
    {"id":"photos-public","publicOrigin":"https://photos.example.ts.net","rpID":"photos.example.ts.net","backend":"http://photos:3000"}
  ],
  "ingresses": [
    {"id":"lan","type":"local","siteIds":["notes-lan"],"local":{"listen":":443","mdns":{"enabled":true}}},
    {"id":"notes","type":"tsnet","siteIds":["notes-public"],"tsnet":{"hostname":"notes","authKeyEnv":"TS_AUTHKEY_NOTES"}},
    {"id":"photos","type":"tsnet","siteIds":["photos-public"],"tsnet":{"hostname":"photos","authKeyEnv":"TS_AUTHKEY_PHOTOS"}}
  ]
}
```

Replace the tailnet suffix and backends with your own. The examples contain secret variable names, never keys. Each hostname has its own passkey/session scope; LAN and public origins do not share registrations automatically.

## Fields and defaults

| Field | Behaviour |
|---|---|
| `id` | Stable unique identifier, letters/digits/hyphens/underscores, at most 63 characters. Used in errors and state defaults. |
| `type` | `local` or `tsnet`. |
| `enabled` | Defaults to true; false skips resource creation and secret lookup. |
| `siteIds` | Explicit nonempty site allowlist; tsnet currently requires exactly one site. |
| `local.listen` | Required IP:port or :port. |
| `local.tls` | Defaults to `local-ca`; `off` for an HTTP origin behind an explicitly trusted HTTPS proxy. |
| `local.trustedProxies` | Optional CIDR list; no proxy trust by default. Applies only to this ingress. |
| `local.mdns` | Optional existing mDNS settings: enabled, service, domain, instancePrefix. Service defaults to `_https._tcp`; explicitly use `_http._tcp` for HTTP discovery. |
| `local.bootstrap` | Defaults false. With TLS off, serves only trust downloads/instructions and HTTPS redirects. No registration/login API. |
| `tsnet.hostname` | Required unique node DNS label. Must match the site's ts.net origin name. |
| `tsnet.port` | Defaults 443; supported ports: 443, 8443, 10000. Non-default port must match the site's origin. |
| `tsnet.funnelOnly` | Defaults false; accepts tailnet and public connections. True restricts listener to public Funnel connections. |
| `tsnet.stateDir` | Defaults to `tsnet/<id>` beside the configuration. Protected persistent node identity, never a build cache. |
| `tsnet.authKeyEnv` | Environment variable containing the first-enrollment key. Optional only when valid persisted identity exists. |

At most 32 enabled/disabled entries may be declared. At least one enabled ingress is required. Duplicate local sockets, node names, ingress IDs, site references and overlapping/aliased state directories are rejected. Empty/missing lists fail validation. Newly generated default configuration contains LAN HTTPS and HTTP trust-bootstrap entries.

All tsnet entries use Funnel. Each node owns its virtual port 443 independently of other nodes and LAN port 443. Multiple nodes need separate state directories; they may use separate enrollment keys or a permitted reusable key. A single-use key cannot enroll several fresh nodes. Removing an auth key does not revoke an enrolled device; manage device permissions/revocation in Tailscale.

MagicDNS, HTTPS and Funnel permission must be enabled in the tailnet. State must be writable by the running UID (container UID/GID 10001). Bootstrap uses only each entry's explicit auth-key reference. Process-wide client-secret/WIF/force-login overrides are rejected to avoid cross-node enrollment. Raw upstream logs/errors are suppressed to avoid secret disclosure.

## Local trust installation

Declare an HTTP bootstrap ingress alongside local HTTPS:

```json
{"id":"trust","type":"local","siteIds":["notes-lan"],"local":{"listen":":80","tls":"off","bootstrap":true}}
```

Visit HTTP `/onboarding` to download the root certificate/profile. Compare `--fingerprint-CA` output through an independent trusted channel before installation. Bootstrap requires TLS off and no trusted proxies. Its allowlist must refer to a site with an HTTPS `publicOrigin` served by a local-CA ingress.

Only sites attached to local-CA ingresses contribute certificate SANs. Only local entries with mDNS enabled are advertised. Use separate Funnel sites and omit them from local bindings to keep their hostnames out of LAN certificates/discovery. mDNS DNS-SD advertisements do not guarantee OS resolution of arbitrary `.local` aliases.

## External Cloudflare

Keep cloudflared external and configure its origin socket explicitly:

```json
{"id":"cloudflare-origin","type":"local","siteIds":["public-app"],"local":{"listen":"127.0.0.1:8080","tls":"off","trustedProxies":["127.0.0.1/32"]}}
```

No automatic loopback trust is added. Restrict the socket and require the proxy to overwrite forwarded host/scheme and append observed-client attribution. The retained `server.cloudflare` field controls certificate-step presentation and certificate-route registration in the main router; it does not create listeners or set trust. The old listener/hostname/backend CLI override flags are rejected; edit the JSON instead.

## Validation and live reload

```sh
make build
./bouncer --config /data/bouncer.json --check-config
./bouncer --config /data/bouncer.json --onboarding
# After editing and checking the file:
kill -HUP <pid>
```

`--check-config` checks configuration without starting nodes/listeners or resolving secret values. Use the same configuration path as the running service so relative state paths resolve identically.

SIGHUP validates the entire proposed collection and prepares new listeners/nodes without accepting HTTP connections or performing TLS handshakes. Publication activates the listeners. Each request selects routing and trust policy from one active generation. A failed preparation closes staged resources without persisting prepared CA material or token expiry. Authentication stays available during staging; a configuration change during preparation rejects the candidate and requires another SIGHUP. Startup uses all-or-nothing endpoint creation. Existing listeners and authenticated SSE/WebSocket connections remain intact when unrelated entries or backends change.

Removing/disabling an ingress closes that endpoint's connections, including WebSockets, and closes its node. Persistent identity is retained. Changes to local site allowlists, trusted proxies, discovery settings and backend routing reuse the socket where possible.

A changed address can be staged beside the old socket. In-place changes that reuse a live socket with a different TLS mode, or a live tsnet identity/hostname with changed node/endpoint settings, are rejected with an instruction to remove and then add across two reloads. This intentionally causes downtime only for the changed endpoint; unrelated endpoints stay running. Site origin/RP changes likewise require retiring that node binding first. Session storage settings still require restart.

The node readiness phase is bounded to 60 seconds after synchronous upstream `Start`; upstream forbids concurrent `Close` and `Start`. Safe cancellation of real startup/listener operations needs live verification. Funnel exposure owned by the attempt is undone during cleanup; pre-existing exposure is not erased. A listener-ready log is not proof of public reachability or successful certificate issuance.

## Security and verification

- Funnel requests never qualify for LAN enrollment bypass, including ULA/IPv6 peers.
- Forwarded client/host/scheme headers are untrusted on tsnet. Original public client attribution comes from upstream `FunnelConn` metadata.
- Each tsnet listener rejects other site hostnames, wrong ports and conflicting TLS SNI. All ingresses enforce site allowlists.
- Authentication, lockout and global request budgets are shared across listeners. Passkeys/sessions remain site- and credential-bound.
- Removed endpoints close hijacked streams explicitly. Unchanged streams survive reload.

Local verification passed full race tests, process SIGHUP/stream/add-remove/failed-bind tests and HTTP/TLS Chromium passkey/restart tests. Build/lint/actionlint/gosec and vulnerability scanning passed; the scan reported zero reachable/imported-package vulnerabilities and five unused required-module advisories. The final container recheck failed committing a layer with `no space left on device`; earlier container success predates the final audit. Routine tests are uncached and unprofiled. Explicit profiling was completed for equivalent unit/integration/browser workloads; summaries remain after raw captures were removed. See [the audit](INGRESS-AUDIT-2026-10-07.md) and [allocation measurements](ALLOCATION-PASS-2026-10-08.md).

Real multi-node Funnel startup, enrollment keys, external certificates/client attribution and teardown still require an explicitly authorised live test. Do not deploy based solely on the local listener tests.
