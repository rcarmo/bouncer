# Embedded tsnet decisions and remaining live tests

Bouncer implements supplemental embedded Funnel listeners through the uniform `ingresses[]` collection. [INGRESSES.md](INGRESSES.md) defines current configuration; [ARCHITECTURE.md](ARCHITECTURE.md) describes lifecycle ownership.

## Decisions

Rui selected multiple supplemental Funnel hostnames and a uniform local/mDNS/tsnet configuration on 7 October 2026.

- One embedded `tsnet` node per hostname, each bound to exactly one site and a separate durable identity directory.
- Sites retain backend URLs, public origins, RP IDs and credential scope. Adding a hostname does not migrate passkeys or sessions.
- `local` owns sockets, TLS, explicit upstream proxy trust and optional mDNS. mDNS is discovery, not a third transport.
- `tsnet` owns public Funnel TLS. Default port is 443; 8443 and 10000 are also allowed. `funnelOnly` can exclude direct tailnet connections. Both public and tailnet clients require Bouncer authentication.
- No legacy listener normalisation or global transport selector. Existing configs must explicitly declare `ingresses[]`. There is no separate `funnel` flag: every tsnet ingress uses Funnel.
- Startup is all-or-nothing. SIGHUP stages additions, publishes routing and retires removals; failed preparation retains the active generation. Conflicting socket/node changes require remove/add across two reloads.
- Each node uses an environment-variable secret reference for initial enrollment. Persisted identity survives removal and restart. Bouncer does not change account permissions or start unattended interactive login.
- Shared authentication/session budgets; ingress-specific trust and site restrictions. tsnet ignores forwarding headers and cannot grant LAN bypass, including to IPv6 ULA peers.
- Local certificates/discovery include only their local bindings. Use separate sites for Funnel hostnames to keep them out of LAN SANs/mDNS.

Earlier proposals for one node, `server.tailscale.ingresses`, restart-only changes, legacy normalisation, `internal/tailscale`, optional per-endpoint startup failure isolation and profile-every-test were superseded. The implementation resides in `internal/ingress`; ordinary tests are unprofiled.

## Upstream API and dependency

Source review used Tailscale `v1.102.5`. The dependency is pinned and builds locally; its Go requirement is 1.26.6; Bouncer now targets Go 1.27.1 for the module, lint tools and container.

- `Server.Listen` returns tailnet TCP; `ListenTLS` returns tailnet TLS.
- `ListenFunnel` returns TLS for Funnel and, unless restricted, tailnet traffic. MagicDNS, HTTPS and node/port Funnel permissions are account prerequisites.
- `Server.Dir` stores identity. `Up(ctx)` reports readiness; certificate-domain checks bind the configured public origin to the actual node.
- `ipn.FunnelConn.Src` supplies public client metadata. Bouncer retains the underlying connection while preserving Request.TLS.
- `WhoIs`-based login, private-only transport, subnet routing and custom-domain certificates are outside this change.

References: [tsnet README](https://github.com/tailscale/tailscale/blob/v1.102.5/tsnet/README.md), [lifecycle/listener implementation](https://github.com/tailscale/tailscale/blob/v1.102.5/tsnet/tsnet.go), [module requirements](https://github.com/tailscale/tailscale/blob/v1.102.5/go.mod).

## Lifecycle limits

Upstream prohibits Close before or concurrent with Start. Bouncer finishes synchronous Start, then bounds readiness to 60 seconds. The close watcher ends before ServeConfig mutation so rollback can access the local API. Newly enabled exposure is tracked and removed on cleanup; pre-existing exposure is preserved.

Start and ListenFunnel are not covered by a verified whole-operation timeout. Closing a removed endpoint ends streams rather than draining them. Persistent state is never deleted automatically. A locally returned listener proves neither public reachability nor successful first certificate acquisition.

## Local evidence

The full race suite, spoofing/trust regressions, real-process SIGHUP/failed-bind streaming tests, HTTP/TLS Chromium authentication and restart flows, static checks and vulnerability scan passed. The allocation pass compared equivalent local workloads and retained measured findings. See [ingress audit](INGRESS-AUDIT-2026-10-07.md) and [profiling report](ALLOCATION-PASS-2026-10-08.md).

The final container recheck failed committing a build layer with `no space left on device`; earlier container success predates the final audit. Native release builds for the new ingress tree have not been published. No production identity/configuration has changed.

## Authorised live acceptance

Real tailnet enrollment, public certificates, source attribution, exposure rollback and multi-node overhead remain unverified. An approved key and explicit public-exposure/cleanup scope are required before testing.

Use separate protected test identity/configuration and verify:

1. Actual public and tailnet TLS against the expected hostname; Funnel-only rejection where configured.
2. Passkey enrollment/login, exact RP scope, secure cookies/HSTS and original public-source attribution.
3. Forged Host/SNI/forwarding headers, cross-site cookies and IPv4/IPv6 LAN-bypass attempts fail closed.
4. SSE/WebSockets survive unrelated reloads; failed additions retain the active generation.
5. Restart retains identity, credentials and sessions; removal closes only the chosen endpoint.
6. Owned exposure is removed on failed setup/shutdown without erasing pre-existing Serve configuration.
7. Two or more nodes route concurrently; record binary size, startup, idle memory and equivalent workload allocations without claiming local tests prove upstream behaviour.
8. Startup/listener cancellation ends owned work within observed limits; document any upstream blocking phase.

Live testing must not run in routine CI. Do not report Funnel support as live-verified until these checks pass. Publishing source, issuing a release and deploying are separate actions.

## Cloudflare connector

The official [Cloudflare Go SDK](https://github.com/cloudflare/cloudflare-go) manages the control-plane API. The supported connector is `cloudflared`; its maintainer [stated there were no expectations of an SDK](https://github.com/cloudflare/cloudflared/issues/196#issuecomment-2688015792). Third-party wrappers couple Bouncer to connector internals. Keep cloudflared external, forwarding to a restricted, explicitly trusted local origin.
