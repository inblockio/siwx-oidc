# Root Cause Analysis: Third-Party Matrix Clients Blocked by CORS

**Date:** 2026-05-19
**Reporter:** Tim Bansemer
**Affected:** All third-party Matrix clients (Cinny, FluffyChat, Beeper, nheko, etc.)
**Severity:** Blocks federation-compatible client access entirely

## Reproduction

1. Go to https://app.cinny.in/login
2. Set homeserver to `matrix.inblock.io`
3. Result: "Failed to get authentication flow information"

## Observed Errors (browser console)

```
Access to fetch at 'https://matrix.inblock.io/_matrix/client/v3/login'
from origin 'https://app.cinny.in' has been blocked by CORS policy:
The 'Access-Control-Allow-Origin' header has a value
'https://element.inblock.io' that is not equal to the supplied origin.
```

Additional errors (secondary, caused by the CORS block):

- `matrix.inblock.io/_matrix/client/v3/login` -- `ERR_FAILED`
- `matrix.inblock.io/_matrix/client/v3/register` -- 403
- `Uncaught (in promise) Error: Missing auth flow!`

## Root Cause

The production Caddyfile (deployed via `deploy.sh` lines 128-164) has **no CORS
headers** on the four browser-facing endpoints that proxy to siwx-oidc:

| Endpoint | CORS headers | Result |
|---|---|---|
| `/.well-known/matrix/client` | `Access-Control-Allow-Origin: *` | Works for all clients |
| `/_matrix/client/v3/login` | **None** | Blocked for non-Element origins |
| `/_matrix/client/v3/logout` | **None** | Blocked for non-Element origins |
| `/_matrix/client/v3/refresh` | **None** | Blocked for non-Element origins |
| `siwx-oidc.inblock.io/*` | **None** | Blocked for non-Element origins |

Without explicit CORS headers from Caddy, the response falls through to whatever
the upstream (Synapse or siwx-oidc) emits. Synapse's built-in CORS sends
`Access-Control-Allow-Origin: *` for Matrix API paths, but the login/logout/refresh
paths are proxied to siwx-oidc, not Synapse. siwx-oidc has no CorsLayer configured
in the current codebase (the `tower-http` cors feature is declared in Cargo.toml
but unused in code). This means **no CORS headers are sent at all** for these
endpoints.

The browser error message mentioning `https://element.inblock.io` suggests an
earlier deployment may have had a hardcoded CORS origin, or the browser is
conflating a cached response. Regardless, the current deploy.sh Caddyfile
emits no CORS headers on the affected paths.

### Why it works for Element Web

Element Web is served from `element.inblock.io` on the same Caddy instance and
Docker network. When Element makes requests to `matrix.inblock.io`, those
requests cross origins. However, Element may also be benefiting from:

1. The `/.well-known/matrix/client` response having `Access-Control-Allow-Origin: *`
   (discovery works for all clients)
2. Synapse's own CORS headers on standard Matrix API paths (non-login paths)
3. Potentially cached CORS responses from earlier configurations

The core issue remains: the MSC3861 login/logout/refresh paths routed to siwx-oidc
lack CORS headers entirely.

## Affected Architecture Layer

```
Browser (app.cinny.in)
  |
  | Cross-origin request to matrix.inblock.io/_matrix/client/v3/login
  v
Caddy (portal-caddy-1)          <-- CORS headers must be set HERE
  |
  | reverse_proxy siwx-oidc:8081
  v
siwx-oidc                       <-- No CorsLayer in current code
  |
  v
(response with no CORS headers) --> Browser rejects
```

## Contrast with Local Development

The local Caddyfile (`Caddyfile.local`) already solves this correctly:

1. **Strips upstream CORS** via `(strip_upstream_cors)` snippet (prevents header
   duplication if siwx-oidc ever adds its own CorsLayer)
2. **Echoes the request Origin** via `(siwx_cors_local)` snippet with an allowlist
3. **Handles OPTIONS preflight** with a 204 response
4. **Adds Vary: Origin** so caches don't pin one origin for all clients

The production Caddyfile was never updated to include equivalent CORS handling.

## Fix Options

### Option A: Dynamic Origin Echo (recommended)

Add a Caddy snippet to the production Caddyfile that echoes the request Origin
back if it matches an allowlist. This is what `Caddyfile.local` already does.

```caddyfile
(siwx_cors) {
    @cors_origin header Origin https://element.inblock.io https://app.cinny.in
    @cors_preflight {
        method OPTIONS
        header Origin https://element.inblock.io https://app.cinny.in
    }
    header @cors_origin Access-Control-Allow-Origin "{http.request.header.Origin}"
    header @cors_origin Vary Origin
    header @cors_origin Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    header @cors_origin Access-Control-Allow-Headers "Authorization, Content-Type, X-Requested-With"
    header @cors_origin Access-Control-Allow-Credentials "true"
    header @cors_origin Access-Control-Max-Age "600"
    respond @cors_preflight 204
}
```

Apply to all four siwx-oidc-proxied handlers plus the `siwx-oidc.inblock.io` site block.

**Pros:** Explicit allowlist, credentials-compatible, cache-safe via Vary.
**Cons:** Must update the allowlist for each new client origin.

### Option B: Wildcard CORS (`Access-Control-Allow-Origin: *`)

Set `Access-Control-Allow-Origin: *` on all endpoints, matching what Synapse does
natively for Matrix API paths.

**Pros:** Zero maintenance, works for all clients.
**Cons:** Cannot combine `*` with `Access-Control-Allow-Credentials: true` (the
browser ignores credentials headers with wildcard origin). If any endpoint needs
credentialed requests, this breaks. Also a weaker security posture.

### Option C: CorsLayer in siwx-oidc (application-level)

Add `tower-http`'s `CorsLayer` to siwx-oidc's axum router (the dependency is
already declared). This puts CORS handling inside the application.

**Pros:** Works regardless of proxy configuration.
**Cons:** Duplicates CORS headers if the proxy also sets them (browsers reject
duplicate `Access-Control-Allow-Origin` values). Requires the `strip_upstream_cors`
Caddy snippet to stay safe. Harder to manage the allowlist (requires code changes
and redeployment instead of a Caddyfile edit).

### Recommendation

**Option A** is the correct fix. CORS policy should live in the reverse proxy
(single authority), not in the application. The local Caddyfile already demonstrates
the pattern. The production Caddyfile needs the same treatment.

For maximum openness (matching Synapse's own behavior and the Matrix spec's
expectation that homeservers are CORS-permissive), Option B is also defensible.
The Matrix Client-Server spec explicitly states that homeservers should set
permissive CORS to allow web-based clients.

## Required Changes

1. **`deploy.sh`** (lines 128-164): Add the `(siwx_cors)` snippet and `import` it
   into the four `handle` blocks for login/logout/refresh and the siwx-oidc site block.

2. **Live Caddyfile on server**: The Caddyfile is only written once (the `if grep`
   guard on line 125 skips if entries exist). To apply the fix:
   - SSH to `agentic.inblock.io`
   - Edit `/home/portal/portal/Caddyfile` to add the snippet
   - `docker exec portal-caddy-1 caddy reload --config /etc/caddy/Caddyfile`

3. **Optional, siwx-oidc code**: Consider adding CorsLayer as a defense-in-depth
   measure (with the proxy stripping upstream CORS to prevent duplication). Not
   strictly necessary if the proxy handles it.

## Matrix Spec Context

The Matrix Client-Server API specification (section on CORS) states:

> Homeservers should ensure that CORS is set up to allow requests from web
> browsers. All responses to requests should include a valid
> Access-Control-Allow-Origin header with a value of * to allow requests from
> all domains.

This means Option B (wildcard) is spec-compliant and expected. Many Matrix
homeservers (including stock Synapse) use `Access-Control-Allow-Origin: *` on
all client API endpoints.

## Secondary Issues

### DNS typo in error logs

The browser logs show requests to `matrix.inblockio` (missing the dot). This is
likely Cinny's homeserver input parser stripping the dot, or a copy-paste artifact
in the error report. The real requests go to `matrix.inblock.io`.

### 403 on `/register`

The 403 on `/_matrix/client/v3/register` is expected behavior: Synapse has
registration disabled (only OIDC login is supported). This is not a bug.
