# Security fixes — second October 2026 audit

The v0.1.0 follow-up findings are addressed in v0.1.1. No deployed production configuration was changed.

| Finding | Control and regression evidence |
|---|---|
| Code guessing across rotations / reusable codes | 12-digit generation; 10-minute expiry in both modes; persisted per-code lock and 100-failure cross-generation budget; explicit operator reset. Config tests cover restart, rotations, reuse, expiry and lockout. |
| Missing-address limiter bypass / unbounded work | Peer fallback or rejection, global request ceiling, bounded keys/challenges/notification slots; tests exercise fallback, map capacity and excess jobs. Race tests caught and verified correction of a metadata closure race. |
| WebSocket origin | One exact site origin required; sibling, missing, opaque and path-bearing origins denied. Browser/process tests verify valid bidirectional sockets across reload. |
| HTTP CA substitution | SHA256 from certificate DER printed on trusted console and by read-only command; verification instructions and acknowledgement in HTTP/TLS UI. HTTP itself is unauthenticated; operator comparison remains required. |
| Unlimited external bodies / decompression / CSV | Streaming byte budgets and raw logical CSV record/row budget before parser allocation. Tests cover chunked responses, trailing JSON, boundary overflow, gzip expansion, quoted newlines and blank records. |
| GeoIP cache growth | FIFO cap of 4096 and expired-entry eviction on access/insertion; expiry/cap regression. |
| CI token/action trust | SHA-pinned actions; no persisted checkout credentials; only build/merge jobs have package-write permission. Actionlint passed. |
| Root container | UID/GID 10001, owned /data, file bind capability; profiled Podman smoke verifies default HTTP/TLS ports and durable writable config. |
| mDNS topology leak | Public ID/origin TXT only; test rejects backend metadata. |
| Enrollment codes in logs | Normal logger/stdout omit secrets; explicit operator reset prints a code by request. Optional Pushover intentionally delivers codes. Logging regression verifies omission. |
| Credential removal leaves sessions | Session credential ID persisted and admission requires that exact credential. Legacy state retained but unauthorised; tests cover restart, specific credential removal and another credential remaining. |
| Inline script allowance | External embedded modules, fixed script allowlist, self-only script policy. Source tests reject inline scripts/handlers; Chromium HTTP/TLS validates flows. |

## Limits

Existing streams survive configuration reload and revocation; disconnect or restart to terminate them. LAN enrollment bypass is still an explicit trust policy; disable it for untrusted networks. Automatic lockout intentionally permits enrollment denial of service until trusted recovery. Legacy short codes should be reset before new provisioning. Profiles can contain identifiers; keep allocation evidence private. No physical device or OS trust installation was performed.

The earlier brute-force timing estimate assumed 20 requests every five minutes; requests after lockout reset also consume rate windows. It was an illustrative distributed-threat estimate, not a measured throughput result. The persisted lockout and longer code remove the unbounded regeneration mechanism.
