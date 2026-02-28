# Bouncer Audit Report

**Audited by:** GPT-5.2-Codex  
**Date:** 2026-02-28  
**Scope:** Full codebase review — security, correctness, robustness, style

---

## Executive Summary

The project is well-structured, compiles cleanly, and has solid test coverage on core packages. The overall architecture is sound. I found **4 security issues** (2 high, 2 medium), **6 correctness bugs**, and **8 robustness/quality improvements**. None are show-stoppers, but several should be fixed before any real-world use.

---

## 🔴 Security Issues

### S1. Credential ID and PublicKey stored as raw `string` — binary corruption risk (HIGH)

**File:** `internal/authn/authn.go` lines ~82, ~215–220; `internal/config/config.go` `Credential` type

WebAuthn credential IDs and public keys are **arbitrary binary data**. The code stores them via `string(credential.ID)` and `string(credential.PublicKey)`. When these are serialized to JSON, any non-UTF-8 bytes will be corrupted or cause marshaling errors.

The `WebAuthnCredentials()` adapter reads them back via `[]byte(c.ID)` — but if JSON round-tripped through invalid UTF-8, the bytes will be wrong and login will silently fail.

**Fix:** Base64url-encode credential IDs and public keys before storing, and decode on read. The `Credential` struct fields should remain strings, but the conversion in `authn.go` must use `base64.RawURLEncoding`.

### S2. Session cookie set with `Secure: true` in Cloudflare HTTP mode (HIGH)

**File:** `internal/authn/authn.go` `setSessionCookie()`

`Secure: true` is hardcoded. In Cloudflare Tunnel mode, Bouncer listens on plain HTTP. Browsers will refuse to send `Secure` cookies over `http://` connections on the loopback/LAN. If Cloudflare sets `X-Forwarded-Proto: https`, the browser sees HTTPS and it works — but only if the public origin actually uses HTTPS.

This is *probably* fine in practice (Cloudflare always terminates HTTPS), but the code should be explicit: pass a `secure bool` parameter based on whether the server is in Cloudflare mode or local TLS mode, so it's clear and testable.

### S3. No rate limiting on WebAuthn endpoints (MEDIUM)

**File:** `main.go` route setup; `internal/authn/authn.go`

The spec mentions "rate limit WebAuthn attempts (basic IP-based throttling)" but there's no implementation. A brute-force of the 6-digit token (1M combinations) is feasible with automated requests. At minimum, add a per-IP counter with exponential backoff on `/webauthn/register/options`.

### S4. Challenge cleanup goroutines leak on high traffic (MEDIUM)

**File:** `internal/authn/authn.go` `RegisterOptions()`, `LoginOptions()`

Each challenge spawns a goroutine that sleeps for 5 minutes. Under load (or attack), thousands of goroutines accumulate. Replace with a single background ticker that sweeps a map of `challengeID → expiry`, similar to the session cleanup approach.

---

## 🟡 Correctness Bugs

### C1. `AddUser` panics if user has zero credentials

**File:** `internal/config/config.go` `AddUser()`

```go
u.Credentials[0].CreatedAt = time.Now().UTC().Format(time.RFC3339)
```

If `u.Credentials` is empty, this panics with an index-out-of-range. Guard with `len(u.Credentials) > 0`.

### C2. `FindUserByID` / `FindUserByCredentialID` return pointers to slice elements — data race

**File:** `internal/config/config.go`

These methods return `*User` (pointer into the `cfg.Users` slice) while holding only an `RLock`. The caller (in `authn.go`) then reads/modifies the user *after* the lock is released. If another goroutine appends to `Users` (triggering a slice reallocation), the pointer becomes dangling. Return a copy instead, or hold the lock longer.

### C3. `LoginVerify` returns 200 even when user is nil after credential lookup

**File:** `internal/authn/authn.go` `LoginVerify()` ~line 338

```go
user, _ := h.cfg.FindUserByCredentialID(string(credential.ID))
if user != nil {
    // set session...
}
// falls through to 200 OK with no session set
```

If the user lookup fails (shouldn't happen, but defensive coding), the response is `{"status":"ok"}` with no session cookie. The client thinks login succeeded but has no session. Return an error instead.

### C4. `proxy.New` panics when `clientIP` is nil (untrusted path)

**File:** `internal/proxy/proxy.go` Rewrite function

```go
r.Out.Header.Set("X-Forwarded-For", clientIP.String())
```

If `localip.ExtractIP` returns nil (malformed RemoteAddr), this is a nil pointer dereference. Add a nil check.

### C5. HTTP redirect to HTTPS uses `cfg.Server.PublicOrigin` which may be empty

**File:** `main.go` HTTP catch-all in local TLS mode (~line 290)

```go
target := cfg.Server.PublicOrigin + r.URL.RequestURI()
```

If `PublicOrigin` is empty or not configured, this produces a relative redirect like `/foo` → `/foo`, causing a redirect loop. Default or validate `PublicOrigin` on startup.

### C6. `session.Get()` updates `LastSeen` but never persists it

**File:** `internal/session/session.go` `Get()`

`LastSeen` is updated in memory on every `Get()` call, but `save()` is never called. The updated timestamp is lost on restart. Either call `save()` (throttled, e.g., at most once per minute) or accept that `LastSeen` is best-effort.

---

## 🟢 Robustness & Quality

### R1. `go.mod` says `go 1.23` but Go 1.26 is installed

The `Rewrite`-based proxy API requires Go 1.20+, so this works, but the `go.mod` should match the minimum actually needed. Go 1.22 introduced the `"METHOD /path"` routing patterns used in `main.go` (`mux.HandleFunc("POST /webauthn/...")`). Set `go 1.22` as the minimum.

### R2. Dockerfile uses `golang:1.23-alpine` — version mismatch

**File:** `Dockerfile`

Should match the `go.mod` minimum or the version actually used. Update to `golang:1.23-alpine` or later.

### R3. `session.Save()` takes `RLock` but should take `Lock`

**File:** `internal/config/config.go` `Save()`

`Save()` serializes the entire config. It takes `RLock`, which is correct for read-only access to the data. However, this means concurrent `AddUser` calls (which take `Lock`, mutate, then call `Save` which takes `RLock`) create a lock ordering issue: `Lock` → `RLock` is fine on `sync.RWMutex`, but it's fragile and confusing. Consider refactoring `Save` to be called with the lock already held (private `saveLocked()` method).

### R4. SPEC says "vendored Preact/HTM" but UI uses vanilla JS

The HTML files use plain `<script type="module">` with vanilla JavaScript. The spec and README mention "vendored Preact/HTM" but this was never implemented. Update docs to match reality, or add Preact if desired.

### R5. `onboarding.html` Cloudflare detection is fragile

**File:** `main.go` onboarding handler

```go
html = strings.Replace(html, "window.location.search", "'?cloudflare=1'", 1)
```

This string replacement in HTML source is brittle — if the JS changes, it silently breaks. Better to inject a `<meta>` tag (like local-bypass) or a `<script>` variable.

### R6. Error responses mix plain text and JSON

WebAuthn handlers return `http.Error()` (plain text) for errors but `json.NewEncoder` for success. Clients must handle both content types. Consider returning JSON error bodies consistently: `{"error": "message"}`.

### R7. No graceful shutdown

**File:** `main.go`

The server uses `http.ListenAndServe` / `server.Serve` with no signal handling. On SIGTERM (e.g., Docker stop), in-flight requests are dropped and sessions may not be flushed. Add `signal.NotifyContext` + `server.Shutdown(ctx)`.

### R8. Missing `Content-Security-Policy` and other security headers

The HTML pages have no CSP, X-Frame-Options, or X-Content-Type-Options headers. Add a middleware that sets:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
```

---

## Summary Table

| ID | Severity | Category | Description |
|----|----------|----------|-------------|
| S1 | 🔴 High | Security | Binary credential data stored as raw string — JSON corruption |
| S2 | 🔴 High | Security | `Secure` cookie flag hardcoded in HTTP mode |
| S3 | 🟡 Medium | Security | No rate limiting on token/WebAuthn endpoints |
| S4 | 🟡 Medium | Security | Per-challenge goroutine leak under load |
| C1 | 🟡 Medium | Correctness | `AddUser` panics on empty credentials slice |
| C2 | 🟡 Medium | Correctness | Pointer-to-slice-element data race in user lookup |
| C3 | 🟡 Medium | Correctness | `LoginVerify` returns 200 OK when user not found |
| C4 | 🟡 Medium | Correctness | Nil pointer dereference in proxy when RemoteAddr is malformed |
| C5 | 🟢 Low | Correctness | Empty `PublicOrigin` causes redirect loop |
| C6 | 🟢 Low | Correctness | `LastSeen` update never persisted |
| R1 | 🟢 Low | Quality | `go.mod` version should be 1.22+ |
| R2 | 🟢 Low | Quality | Dockerfile Go version mismatch |
| R3 | 🟢 Low | Quality | `Save()` lock ordering fragility |
| R4 | 🟢 Low | Quality | Docs say Preact/HTM but UI is vanilla JS |
| R5 | 🟢 Low | Quality | Brittle string replacement for Cloudflare detection |
| R6 | 🟢 Low | Quality | Inconsistent error response format |
| R7 | 🟢 Low | Quality | No graceful shutdown |
| R8 | 🟢 Low | Quality | Missing security headers on HTML pages |

---

## Positive Notes

- Clean package boundaries with minimal cross-dependencies
- Atomic file writes are a nice touch for crash safety
- WebAuthn discoverable login flow is correctly implemented
- SAN change detection for cert regeneration works well
- Good test coverage on core packages (localip 94%, session 90%)
- CLI flag design is sensible and well-documented
