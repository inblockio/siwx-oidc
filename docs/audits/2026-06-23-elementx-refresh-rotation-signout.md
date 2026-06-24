# Element-X mobile sign-out: refresh-token rotation has zero replay tolerance

**Date:** 2026-06-23
**Component:** `siwx-oidc` (OAuth2/OIDC provider for `matrix.inblock.io` via MSC3861)
**Deployed build at time of investigation:** image `ghcr.io/inblockio/siwx-oidc:sha-db79e75` (PR #13), up ~4 days
**Severity:** High (recurring unexpected sign-out of mobile users; ~1 to 2 incidents/day across the deployment)
**Status:** Root cause confirmed. Fix (refresh-token grace window) implemented on branch `fix/refresh-token-grace`.

---

## One-line root cause

`siwx-oidc` rotates refresh tokens by **hard-deleting the old token the instant a refresh
succeeds, with no grace window**. On mobile, the rotation HTTP response is regularly lost
in flight (radio handoff, app suspension, cross-process refresh), so the phone keeps
presenting a refresh token the server already deleted. The next refresh returns
`invalid_grant`, which matrix-rust-sdk treats as terminal, and Element-X signs the session
out.

---

## The causal chain (verified against deployed code + live prod logs)

```
Inputs:   ACCESS_TOKEN_TTL = 300s  (src/db/mod.rs)  -> every active client refreshes every ~5 min
          Refresh handlers hard-delete the old refresh token on success, no grace:
            - src/oidc.rs   token_refresh()  (OAuth /token, grant_type=refresh_token)  delete_token(&rt)
            - src/compat.rs refresh()         (POST /_matrix/client/v3/refresh)          delete_token(&body.refresh_token)
          No grace / successor / replay tolerance anywhere (grep-confirmed: the only
          "consumed" guard in the codebase is for authorization codes, not refresh tokens).
   |
Activity: Element-X (matrix-rust-sdk OAuth) POSTs grant_type=refresh_token to /token every ~5 min.
          Server stores new access+refresh, returns the new pair, then DELETEs the old refresh token.
   |
Trigger:  The HTTP response is lost or not persisted client-side:
            - mobile radio transition (WiFi <-> cellular, dead zone, tunnel)
            - iOS/Android suspends or kills the backgrounded app mid-request
            - cross-process double refresh (iOS notification-service extension + main app)
   |
Output:   The phone still holds the OLD refresh token. The server already deleted it.
   |
Outcome:  Next refresh -> get_token() = None -> invalid_grant "Unknown or expired refresh token."
   |
Impact:   matrix-rust-sdk treats invalid_grant on the refresh grant as unrecoverable
          -> Element-X signs the session out.
```

---

## Evidence

### Prod-log signature (the smoking gun)

Over ~4 days the deployed `siwx-oidc` logged **7 `invalid_grant` events** and **4
`/oauth2/revoke` calls**. The `invalid_grant` events arrive in **tight pairs**, each pair
**immediately followed by a `POST /oauth2/revoke`**:

```
2026-06-22T04:32:31.477  WARN bad_request_token error=invalid_grant "Unknown or expired refresh token."   <- stale RT, attempt 1
2026-06-22T04:32:32.034  WARN bad_request_token error=invalid_grant "Unknown or expired refresh token."   <- retry, attempt 2
2026-06-22T04:32:32.467  INFO request method=POST path=/oauth2/revoke                                      <- client gives up, tears down the session
```

Same shape at `2026-06-21 11:28`, `2026-06-22 13:36`, and `2026-06-23 07:31`. This is the
exact sequence of a client that (1) refreshes with a dead token, (2) retries once, then
(3) revokes and logs out. The cadence (spread across day and night, ~1 to 2/day) matches a
phone, not a server-side bot.

### The error string pins it to rotation-delete, not expiry

The error is always **"Unknown or expired refresh token"** (the `get_token() == None`
branch), never **"Refresh token has expired"** (the explicit `exp <= now` branch). So the
tokens are being **deleted by rotation**, not aging out their TTL. This is what
distinguishes the rotation race from a TTL or clock-skew problem.

### Two independent buggy sites, same defect

| Path | Function | Hard delete | Used by |
|------|----------|-------------|---------|
| OAuth `POST /token` (`grant_type=refresh_token`) | `src/oidc.rs::token_refresh` | `let _ = db_client.delete_token(&rt).await;` | Element-X (matrix-rust-sdk OAuth), the source of the prod `invalid_grant` lines |
| `POST /_matrix/client/v3/refresh` | `src/compat.rs::refresh` | `let _ = state.redis_client.delete_token(&body.refresh_token).await;` | legacy CS-API refresh path |

Both rotate (mint new access+refresh) and then unconditionally delete the presented refresh
token, with no record of what it rotated to. A replay is therefore indistinguishable from an
unknown token.

### Why mobile and not Element Web

Web desktop holds a stable connection and is never suspended mid-request, so it almost
always receives and persists the rotated token. Mobile loses in-flight responses constantly
(radio transitions, Doze/App-Nap, the OS killing a backgrounded app, and the iOS NSE
refreshing in parallel with the main app). The short 5-minute access-token TTL multiplies
the number of rotations, and therefore the number of chances to hit the lost-response window.

---

## Falsified hypotheses (what it is NOT)

| Hypothesis | Verdict | Disproof |
|---|---|---|
| Redis evicting / ephemeral token store | **Falsified** | `appendonly=yes`, `maxmemory-policy=noeviction`, `maxmemory=0`, 16-day uptime. Tokens are durable and never evicted. |
| 90-day refresh TTL expiry | **Falsified** | Live Redis `avg_ttl` ~= 33.7 days (mix of 90d refresh + 300s access) confirms the deployed `REFRESH_TOKEN_TTL = 7_776_000` (90d). Events are scattered hourly, not on 90-day boundaries, and the error string is "unknown," not "expired." |
| 24h refresh TTL (per a stale CLAUDE.md table) | **Falsified** | Deployed constant at `db79e75` is `REFRESH_TOKEN_TTL = 7_776_000` (90d); the doc table was out of date. The live `avg_ttl` independently confirms ~90d. |
| Device-deletion races (H3/H6/H9) / account erase / logout-all | **Falsified** | No `device_delete` / `revoke_device_tokens` / erase / deactivate lines correlate with the events. The 2026-06-14/15 race fixes touch a different path and are not implicated. |
| Clock skew on the siwx-oidc container | **Falsified** | Skew would surface as "Refresh token has expired" (the `exp` check), which never appears. |
| OIDC-discovery / cross-signing bootstrap regression (the 2026-05-25 class) | **Not implicated** | That failure mode breaks login/bootstrap, not a steady-state sign-out hours into a working session. |

---

## Fix: a bounded refresh-token grace window

The canonical mitigation (what MAS implements and `siwx-oidc` omits): on rotation, instead
of deleting the old token outright, record a short-lived pointer from the old refresh token
to its **already-minted successor** (`RotatedToken { access_token, refresh_token, access_exp }`)
with a small TTL (`REFRESH_GRACE_TTL = 60s`, comfortably under `ACCESS_TOKEN_TTL` so the
replayed access token is still valid). If a client presents an already-rotated refresh token
within that window, return the same successor pair idempotently instead of `invalid_grant`.

Properties:
- **Bounded:** the grace pointer expires via Redis TTL (60s). It does not weaken rotation;
  the old token still becomes unusable for *new* rotations, and a genuinely unknown or truly
  expired token is still rejected.
- **Idempotent:** a replay (or a duplicate refresh) returns the same successor the first call
  minted, so the client converges on one refresh chain.
- **Covers both paths:** the OAuth `/token` path (Element-X) and the `/_matrix/client/v3/refresh`
  compat path share one store-layer mechanism.
- **No schema migration:** the grace record lives under a new key namespace
  (`token_rotated/{old_refresh}`); `TokenMetadata` is unchanged, so no Redis flush on deploy.
- **Race-safe ordering:** the grace pointer is written only on the committed success path,
  after the existing H3/H6 check-mint-recheck rollback, so it never points to rolled-back
  (revoked) tokens.

Raising `ACCESS_TOKEN_TTL` from 300s would reduce the *frequency* of the race but does not
fix it; the grace window is the real fix.

### Residual / known limits

- The grace window addresses the dominant **sequential lost-response** case. For two *truly
  concurrent* refreshes presenting the same old token, behavior is unchanged from today (both
  may mint, both new tokens are the user's own and valid); matrix-rust-sdk serializes refreshes,
  so this is rare. The tiny window between deleting the old token and writing the grace pointer
  is only reachable by true concurrency, not by the sequential retry.

---

## Verification

See the reproducer `refresh_grace_window_tolerates_replay` (and the compat sibling) in
`tests/e2e_race_teardown.rs`: RED against the current deployed code (replay -> `invalid_grant`
/ `M_UNKNOWN_TOKEN`), GREEN after the fix (replay -> 200 with an active successor access
token). A negative assertion confirms a never-issued refresh token is still rejected, so the
grace path does not blanket-accept.

## Deployment note

Code-only change. No Redis flush, no Synapse change, no Caddy change. Deploy is the standard
manual step on `agentic.inblock.io`:
`cd /home/deploy/matrix/stack && docker compose pull siwx-oidc && docker compose up -d siwx-oidc`.
Deploy is deliberately gated on owner approval and is NOT part of this change.
