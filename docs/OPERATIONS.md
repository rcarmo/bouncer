# Bouncer operations manual

Operate one Bouncer writer per configuration/session pair. Preserve configuration, credentials, CA keys and tsnet identity across restarts and upgrades.

This manual applies to the YAML/Go 1.27.1 source tree following ingress commit `dc082f0`, not the published v0.1.1 configuration format. The source has passed local race, reload, browser and allocation tests. Final container verification failed for lack of build storage; real Funnel enrollment, public certificates, attribution and teardown require separately authorised testing. See [verification evidence](INGRESS-AUDIT-2026-10-07.md) and [live acceptance](TSNET-PLAN.md#authorised-live-acceptance).

## Files and permissions

| State | Requirement |
|---|---|
| `bouncer.yaml` | Config, users, credential records, enrollment state and local CA/private keys. Mode 0600. |
| Configured session file | Default `sessions.json`, relative to configuration. Mode 0600; preserve or deliberately invalidate. |
| `tsnet/<ingress-id>/` | Default node identity path beside configuration. Mode 0700; separate directory for each node. |
| DB-IP database | Default `dbip-city-lite.sqlite` beside configuration; preserve if needed, or rebuild through the updater. |
| Backup archive | Treat as credentials: restricted access, encrypted storage and controlled retention. |

The process must be able to write the parent directory, not just existing files: persistence replaces files atomically. Relative state paths resolve from the configuration directory. Container runtime UID/GID is 10001:10001. Do not recursively change ownership of unrelated bind mounts.

Do not store durable state in build/test caches. Do not use a backup configuration as a live editor buffer: replacing current enrollment or credential state can revive revoked access.

## Build and select an artifact

For a source deployment, use Go 1.27.1 or newer:

```sh
make build
```

Record the commit and binary checksum. The local allocation pass used Go 1.27.1; it is not evidence of identical performance on every supported toolchain.

Use an explicitly selected release digest or a tested source-built image for containers. Do not assume `latest` contains the new ingress schema. The examples below use `IMAGE` for the artifact selected by the operator. They are deployment templates, not executed production changes.

## First local configuration

Create a protected state directory owned by the service user. Save this example as `bouncer.yaml` there, replacing hostname, IP and backend:

```yaml
sites:
  - id: app-lan
    publicOrigin: https://app.local
    rpID: app.local
    hostnames:
      - app.local
    ipAddresses:
      - 192.168.1.50
    backend: http://127.0.0.1:3000
ingresses:
  - id: lan
    type: local
    siteIds:
      - app-lan
    local:
      listen: ":443"
      tls: local-ca
      mdns:
        enabled: true
  - id: trust
    type: local
    siteIds:
      - app-lan
    local:
      listen: ":80"
      tls: "off"
      bootstrap: true
onboarding:
  enabled: false
  localBypass: false
session:
  ttlDays: 7
  cookieName: bouncer_session
  file: sessions.json
users:
  []
```

Missing non-ingress settings use defaults, including enabled GeoIP/DB-IP update settings. Review these before startup if outbound requests are restricted. Configure local DNS or hosts entries; mDNS DNS-SD does not guarantee browser resolution of arbitrary `.local` aliases.

Validate using the same configuration path and user as the running service:

```sh
./bouncer --config /srv/bouncer/bouncer.yaml --check-config
```

Validation opens no listeners/nodes and resolves no secret values. It cannot prove backend availability, permissions, Funnel account access or certificate issuance. If the path is missing, configuration loading creates a default file; check that you selected the intended file first.

Start with normal registration-disabled operation. Enable onboarding deliberately for provisioning. Startup generates missing local CA/server material; never replace a working CA just to clear a browser warning.

## Host service template

Install the tested binary at `/usr/local/bin/bouncer`, create a dedicated `bouncer` account, and give it ownership of `/srv/bouncer`. Adapt this systemd unit to the host:

```ini
[Unit]
Description=Bouncer passkey reverse proxy
Wants=network-online.target
After=network-online.target

[Service]
User=bouncer
Group=bouncer
WorkingDirectory=/srv/bouncer
ExecStart=/usr/local/bin/bouncer --config /srv/bouncer/bouncer.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Save as `/etc/systemd/system/bouncer.service`, reload systemd, then start it. The network capability permits local ports 80/443; it is unnecessary when all local listeners use high ports. tsnet's virtual Funnel ports do not require host port publication. This unit has no whole-startup timeout guarantee: upstream synchronous Start/ListenFunnel cancellation still needs live verification.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bouncer
sudo systemctl status bouncer
sudo journalctl -u bouncer -n 100 --no-pager
```

Never put `--onboarding` permanently in ExecStart if you intend to disable onboarding through configuration: the flag is reapplied on reload.

## Container template

Create a dedicated bind directory before first run:

```sh
sudo install -d -m 0700 -o 10001 -g 10001 /srv/bouncer
# Copy the reviewed configuration into this directory, then:
sudo chown 10001:10001 /srv/bouncer/bouncer.yaml
sudo chmod 0600 /srv/bouncer/bouncer.yaml
docker run --rm --mount type=bind,src=/srv/bouncer,dst=/data \
  "$IMAGE" --config /data/bouncer.yaml --check-config
docker run -d --name bouncer --restart unless-stopped \
  --mount type=bind,src=/srv/bouncer,dst=/data \
  -p 80:80 -p 443:443 \
  "$IMAGE" --config /data/bouncer.yaml
```

Publish only required **local** ports; Funnel connections use embedded tsnet. `EXPOSE` does not publish ports. In a container, `127.0.0.1` backends refer to that container, not the host; use a reachable host/container address or a shared application network. Maintain firewall restrictions and validate mount ownership before replacing an existing container. Container startup requires the binary's low-port bind capability for 80/443.

## External HTTPS proxy / Cloudflare

Keep cloudflared external. Create a site with the public HTTPS origin and RP ID, then a restricted local origin ingress:

```yaml
id: edge-origin
type: local
siteIds:
  - public-app
local:
  listen: 127.0.0.1:8080
  tls: "off"
  trustedProxies:
    - 127.0.0.1/32
```

Configure the connector to reach that socket. Loopback works only in the same network namespace; separate containers need an appropriately restricted network/address and explicit proxy CIDR. Do not expose this origin to untrusted clients.

The proxy must overwrite forwarded host/scheme and append observed client attribution. Trust is per ingress; there is no automatic loopback trust. The retained `server.cloudflare` setting controls certificate-step presentation and main-router certificate routes, not listeners or trust. Local enrollment bypass should normally be off for public provisioning.

## Adding a tsnet Funnel

Obtain explicit approval for enrollment and public exposure first. Enable required MagicDNS, HTTPS and Funnel permissions in the tailnet. Use the actual expected node hostname and `.ts.net` suffix; Bouncer rejects mismatched origin/RP/node/port combinations.

1. Add a **separate site** for the Funnel origin, even if the backend is shared with a LAN site. Preserve existing site IDs and passkeys.
2. Add a `tsnet` ingress allowing that one site. Use separate protected node state per ingress and `authKeyEnv` naming an approved secret supplied to the process.
3. Supply the variable through a protected service credential/environment mechanism. Do not put the key in configuration, command arguments, logs, Git or this manual.
4. Validate locally, then use the authorised live acceptance procedure before relying on public availability.

Defaults: port 443, `funnelOnly: false`, state `tsnet/<id>` beside config. Other supported ports are 8443/10000 and must match the origin. Default listeners admit both public and tailnet connections; both require passkey authentication. A single-use enrollment key cannot initialise multiple nodes. Persisted identity normally needs no fresh key. Process-wide OAuth/WIF/force-login overrides are rejected.

Do not add Funnel sites to local-CA/mDNS bindings. LAN/public registrations do not transfer automatically. An `ingresses ready` log establishes local readiness only; test public TLS, exact hostname, cookies, attribution, authentication and stream behaviour independently.

## Trust and provisioning

1. Deliberately set `onboarding.enabled: true` and reload, or use temporary startup `--onboarding`.
2. For local TLS, obtain `--fingerprint-CA` through a trusted console. Compare it independently before installing HTTP-delivered trust material; HTTP can be substituted by an attacker.
3. Visit bootstrap HTTP `/onboarding` for the profile/certificate; return to the configured HTTPS origin for passkey registration. Bootstrap cannot authenticate or register.
4. With the writer stopped, use `--reset-enrollment` if an operator-delivered code is needed or lockout requires recovery. Restart and deliver the printed code securely; its ten-minute lifetime starts at reset.
5. Test logout and discoverable passkey login. Disable onboarding and reload after provisioning.

Codes are 12 digits, expire after ten minutes, lock after ten wrong guesses per generation and share a persisted 100-failure budget. One-time codes are consumed at accepted registration-options, so failed/cancelled browser registration may require another code. Startup/reload cannot clear lockout. Optional Pushover delivers codes; routine logs/API responses do not. tsnet never grants LAN bypass.

## Changing configuration and reloading

Bouncer writes configuration for credentials, enrollment and certificates. To avoid overwriting those changes, stop the writer for sensitive manual edits and work from a fresh copy. A backend/ingress live edit is possible during a controlled change window, but stale editor contents can still discard recent state; the staging file check is not an external-writer lock.

After an edit, run `--check-config`, signal the specific service process, then inspect logs and externally test new requests:

```sh
sudo systemctl reload bouncer
sudo journalctl -u bouncer -n 50 --no-pager
# Container equivalent:
docker kill --signal=HUP bouncer
docker logs --tail 50 bouncer
```

A successful reload logs `configuration reloaded`. `config reload failed` means the active generation continues; inspect the reason and retry after correction. Prepared state is not persisted on failed listener setup, but the operator's already-written invalid file is **not** automatically restored. Restore a reviewed current configuration before restart.

Unchanged listeners and existing SSE/WebSockets retain their connections/backend. Removed/disabled ingresses close their own connections, including WebSockets. Local site/trust/backend changes reuse compatible sockets. Session settings require restart. Changes conflicting with a live socket/TLS mode or tsnet identity require removal and addition across two reloads; keep another enabled ingress and expect downtime on the removed endpoint. Identity files remain.

## Health checks and logs

There is no dedicated health/status API. A known-site `/login` response checks listener/router availability; it does not prove backend availability or passkey authentication. Use trusted TLS, for example:

```sh
curl --cacert /path/to/verified-root-ca.pem \
  --resolve app.local:443:192.168.1.50 https://app.local/login
```

For public TLS, use normal CA verification. Avoid `curl -k` as acceptance evidence. Test an authenticated application request plus SSE/WebSocket separately. Check logs for startup version, `ingresses ready`, reload failures and `ingress stopped`; no log alone proves public Funnel exposure.

## Backup, upgrade and recovery

Stop the writer for a consistent backup. Archive the entire dedicated state directory, including config, sessions, CA, every tsnet identity and any SQLite sidecars. Use restricted archive permissions and encrypted backup storage. A stopped-directory copy avoids inconsistent credential/session/enrollment or database snapshots.

Before upgrade, record artifact digest/checksum and retain the previous binary/image. Validate a candidate configuration against the candidate artifact using protected non-production copies; configuration checking can resolve identity-path aliases but does not verify runtime access. Existing configs need explicit ingress migration; see [INGRESSES.md](INGRESSES.md#migrating-existing-ingress-configuration).

Replace the artifact without resetting state, start one writer, inspect logs and verify TLS/login/application/streams. A source rollback across the ingress schema boundary may need reviewed configuration changes. Prefer preserving current security state; restoring an old full backup can revive revoked credentials, tokens or sessions. Do not restore CA/node keys selectively without an identity/trust plan.

For an emergency access revocation, stop the service to terminate established streams. With the writer stopped, remove the chosen credential/user from current configuration and deliberately clear sessions if required. Restart and verify denial. There is no administration API; removing credentials denies new requests but does not terminate already-established streams by itself.

Removing/disabling a Funnel ingress closes that node/listener but does not revoke its device or enrollment key. Manage device/key revocation in Tailscale and verify external exposure after removal. Do not delete identity state unless deliberate decommissioning is approved.

## Troubleshooting

| Symptom | Checks/action |
|---|---|
| Missing/empty ingress error | Migrate to explicit `ingresses[]`; preserve site IDs and current security state. |
| Unknown host / 404 | Check public origin, actual Host/port, site allowlist, DNS and trusted forwarded-host policy. |
| Bind conflict | Inspect host sockets and wildcard overlap; conflicting live changes need remove/add or restart. |
| Config/session permission failure | Check running UID, mode, parent-directory write access and mount ownership. Do not delete state. |
| TLS warning | Independently verify CA, hostname/SAN and clock; do not regenerate the CA to suppress a warning. |
| Passkey fails on new hostname | RP scope differs; provision for that site. Do not relabel existing credentials. |
| Enrollment locked/expired | Stop writer, deliberate trusted reset, restart and deliver the fresh code securely. |
| Reload rejected during preparation | Credentials/file changed during staging; take a fresh config snapshot and retry. |
| Funnel bootstrap/permission/domain failure | Check approved env reference, identity state, actual node domain, HTTPS/Funnel permissions and allowed port. Never print secrets. |
| Streams stop after reload | Determine whether the ingress was removed; removal intentionally closes streams. Check backend/proxy idle limits for unchanged listeners. |
| Build/container layer out of space | Inspect owned project/engine storage. Do not prune unrelated volumes, identity or backup state; raw analysed profiles are disposable. |

Routine development checks use `make check`, `make vuln`, unit/race, process and browser targets. Explicit pre-release profiling uses `make profile`; retain findings and remove analysed raw captures. Performance evidence and exact commands are in [ALLOCATION-PASS-2026-10-08.md](ALLOCATION-PASS-2026-10-08.md).
