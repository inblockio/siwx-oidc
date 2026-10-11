# Guest mode: operator guide

Guest mode lets a person with a single-use link join a Matrix video call as a short-lived,
restricted account, without an account, wallet or passkey. This page is for the operator of a
siwx-oidc deployment that turns it on. It is written so that a fresh operator can reach the
acceptance criteria A1 to A8 below from this page alone. The exact keys are in
[configuration.md](configuration.md#guest-mode), the routes in [api/openapi.yaml](api/openapi.yaml).

Guest mode is **off by default**. With it off every `/guest` path answers `503 guest_unavailable`
and nothing else changes.

## 1. What a guest is

- **The identity is a `did:key` made in the guest's own browser.** The page generates the key,
  keeps the private half in that browser, and proves possession of it by signing a challenge
  (CAIP-122 message over a five-minute nonce) at redeem and again at the hand-off. **The server
  never holds, derives or receives private key material.** There is no server-side key secret,
  no key reference and no custodial key to configure, back up or rotate; the operator cannot
  derive a guest's key.
- The guest's Synapse account is created at the hand-off, typed `io.inblock.guest`, with the
  display name `"First Second (Guest)"` (`guest_name_suffix`). It carries `io.inblock.guest: true`
  in the ID token and userinfo (the claim is absent, never `false`, for everyone else).
- The session ends at a deadline (`guest_session_max_secs`, default 7200 s, an invite may ask for
  600 to 14400 s). A reaper then erases the account. A guest who **claims** keeps the account
  (same DID, same MXID) with a passkey, and stays restricted until an operator promotes it.

### Lifecycle

| Step | Route | What happens |
|---|---|---|
| Invite | `POST /guest/invites` (host Bearer token) | A host in `guest_hosts` creates links for a room that passes the room template. The secret (`gi_` + 32 characters) is shown once; only its SHA-256 is stored. |
| Peek | `POST /guest/peek` | The join page asks what the link allows. Reads only, burns nothing. An unknown id, a wrong secret and an unparsable body all answer the same `404 invalid_link`. |
| Redeem | `POST /guest/redeem` | The browser sends its `did:key`, names and consent plus the proof. The server mints a guest record in one Redis script and sets the cookie. **No Synapse write.** The deadline is Redis `TIME` plus the invite's `session_secs`. A second redemption of a single-use link is refused (`410`). |
| Hand-off | `GET /authorize` with scope `urn:io.inblock:guest`, then `GET/POST /guest/continue` | The Meet client starts a normal authorization-code flow; the hand-off page signs with the stored key, the `sign_in` guest branch creates the Synapse account and device. At most `guest_max_devices` devices, `guest_handoff_per_minute` hand-offs per minute. |
| In the call | Synapse, policy module, lk-jwt | The guest is confined by the Synapse policy module (P4) and lk-jwt membership enforcement (P1), not by siwx-oidc. |
| End | deadline, `POST /guest/end`, host end routes, kill switch | The record's deadline moves to now. |
| Reap | reaper, every `guest_reaper_interval_secs` | Revoke every grant and device, write `erased:user/<localpart>` and the DID tombstone `erased:did/<sha256(DID)>`, delete the Synapse user with erase, drop the record. Idempotent and crash-safe. |
| Claim (optional) | `POST /guest/claim/start`, `/finish`, `GET /guest/claim` | With `guest_claim_enabled`. Registers a passkey against the guest's own DID, then one compare-and-set moves the record to `claimed`; pre-claim devices are revoked. |
| After | `GET /guest/ended`, `GET /guest/resume` | `/guest/ended` is the static end screen; `/guest/resume` is the JSON session probe the pages read, which answers `ended` (or `claimed`) once the guest is gone. On either signal the page forgets this browser's key. |

## 2. Prerequisites (P1 to P9)

siwx-oidc does not read the Synapse configuration, so most of these are asserted by you and
checked by hand or by the Synapse-side deployment of
[siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server). Describe them in
your own runbook; do not enable guests until each line is true.

| # | Condition | How to check |
|---|---|---|
| P1 | lk-jwt enforces room membership before it hands out an SFU token: `LIVEKIT_REQUIRE_MEMBERSHIP` on lk-jwt and Synapse `msc4502_enabled` (the lk-jwt appservice registration). Hard dependency before any guest exists, dev included. | A non-member's token request is refused; see the lk-jwt tests of the matrix-server repository. |
| P2 | SFU eviction and a short SFU token lifetime. Before production only; dev accepts the one-hour token tail. | The token lifetime of your lk-jwt/LiveKit build. |
| P3 | Synapse 1.162.0 or later; **federation off**; `auto_join_rooms` empty; no published rooms or `enable_room_list_search: false`; `allow_public_rooms_without_auth` off; `element_call.guest_spa_url` **unset** in every Element Web config. | `GET /_matrix/federation/v1/version` is unreachable from outside; `homeserver.yaml`. |
| P4 | The guest policy module (`synapse-guest-policy`) is loaded, and Synapse has `user_types: extra_user_types: [io.inblock.guest]`. Without the module a guest is an ordinary account that may do anything. | `homeserver.yaml`; the module's own tests; A2. |
| P5 | Redis for guests is persistent (AOF or equivalent), `maxmemory-policy noeviction`, version 5 or later, a single node. | `redis-cli CONFIG GET appendonly maxmemory-policy`; `INFO server`. |
| P6 | The reverse proxy rate-limits the guest routes and `POST /register`, caps bodies, adds HSTS, and neither caches `/guest` nor adds CORS to it. | `scripts/check-guest-proxy.sh` (section 7). |
| P7 | (superseded) No profile-field denylist entry exists; the marker is the Synapse `user_type`. | none |
| P8 | `block_non_admin_invites` stays off. | `homeserver.yaml`. |
| P9 | Element Web has `feature_ask_to_join` enabled for hosts. | Element Web config. |

## 3. Enabling guest mode

Set at least these (environment variables, or the same keys in the config file; see
[configuration.md](configuration.md#guest-mode) for all of them):

```
SIWXOIDC_GUEST_ENABLED=true
SIWXOIDC_GUEST_CLIENT_URL=https://meet.example.org/            # fixed Meet start URL
SIWXOIDC_GUEST_CLIENT_ID=meet-guest                            # the only client allowed the guest scope
SIWXOIDC_GUEST_CLIENT_REDIRECT_URIS='["https://meet.example.org/callback"]'
SIWXOIDC_GUEST_HOSTS='["alice","did:key:z6Mk..."]'             # who may create invitations
SIWXOIDC_GUEST_CLIENT_TOPOLOGY=same-site                       # or cross-site (see residual risks)
# already required for the Synapse admin path:
SIWXOIDC_MAS_SHARED_SECRET=...  SIWXOIDC_SYNAPSE_ENDPOINT=http://synapse:8008  SIWXOIDC_MATRIX_SERVER_NAME=example.org
# optional:
SIWXOIDC_GUEST_EMAIL_POLICY=off|optional|required   SIWXOIDC_GUEST_CLAIM_ENABLED=true
SIWXOIDC_GUEST_ALLOW_OPEN_LINKS=false               SIWXOIDC_GUEST_SESSION_MAX_SECS=7200
```

Start-up validates the whole block and refuses to start, naming each key, when a required key
is missing or empty, a URL is not `https` (localhost may use `http`), `supported_did_methods`
lacks `key`, the topology is not `same-site`/`cross-site`, or a quota is zero. There is deliberately
no key for a guest secret. The quotas (`guest_max_guests`, `guest_host_*`, `guest_global_max_active`,
`guest_daily_mint_max`, `guest_max_claimed`, the brake and the alert thresholds) all have defaults;
review them before the first meeting.

Steps, in order:

1. Meet P1 to P9. Put the reverse proxy in front (section 7). Deploy with guests still **off**.
2. `scripts/check-guest-posture.sh https://id.example.org off` : the 503 shell and its headers.
3. Set the keys above, restart. Start-up must succeed.
4. `scripts/dev-stack-guest-smoke.sh https://id.example.org` : posture, proxy and a bogus peek.
5. Walk A1 to A8 on the dev stack. Only then think about production.

## 4. Acceptance A1 to A8

Each criterion says how to verify it. "Audit" means a log line with `target=guest_audit` (section 5).

| # | Criterion | Verify |
|---|---|---|
| A1 | A guest joins an end-to-end encrypted call from a single-use link, typing two names and ticking consent, with no account, wallet or passkey. A second redemption of the same link is refused. | Host creates one link: `curl -sS -X POST $ISSUER/guest/invites -H "Authorization: Bearer $HOST_TOKEN" -H 'Content-Type: application/json' -d '{"room_id":"!room:example.org"}'` (the token stays in your shell; the response holds the link). Open it in a browser, join. Open it again: the page says the link is used (`410 exhausted` from peek). Audit: `guest_minted`, `guest_signin`. Check that no passkey or wallet prompt appeared. |
| A2 | The guest sees and reaches nothing else: room creation, direct messages, invites, directory search, a knock on a foreign room, a message, a rename, an upload, an invite mint and a foreign-client token are each refused. | Enforced by the Synapse policy module, lk-jwt and this repository's `/authorize` and host routes, not by siwx-oidc alone. Run the module's and matrix-server's confinement tests on the dev stack. From this repository: `POST /guest/invites` with a guest token answers `403 guest_token`; `/authorize` with the guest scope from any client but `guest_client_id` is refused. |
| A3 | After the call no live state remains: no guest record, handle, token, device or joined room; the Synapse account is erased; only the `erased:*` markers remain. The stale `m.call.member` entry is the accepted residue. | After the deadline plus one reaper tick: audit `guest_reap` with `outcome=erased`; `redis-cli EXISTS guest:acct/<localpart>` is `0`; `redis-cli ZCARD guest:due` is back to its earlier value; `redis-cli EXISTS erased:user/<localpart>` is `1`; Synapse admin `GET /_synapse/admin/v2/users/@<localpart>:example.org` shows the account erased/deactivated. |
| A4 | A guest who claims keeps the account (same DID, same MXID), signs in with the passkey on a fresh device, and stays restricted: room creation still refused, the pre-claim refresh token refused. | Needs `guest_claim_enabled`. Claim in the browser; audit `guest_claimed`; sign in with the passkey elsewhere; the pre-claim refresh token is refused (the claim revokes the pre-claim devices); the account still has `user_type` `io.inblock.guest`. |
| A5 | The kill-switch drill and the written rollback have been run and recorded. | Section 5.1 : engage, check each refusal, clear. Rollback: redeploy the previous image; the `guest:*` keys stay in Redis, inert, and new config keys default off. |
| A6 | The abuse tests pass with nothing skipped. The abuse tests are the repository's test suites, not a script against a live issuer: `cargo test --workspace` with `SIWX_TEST_REQUIRE_REDIS=1`, and the e2e suites with `E2E_STRICT_SKIPS=1` (a skipped test does not count). `scripts/dev-stack-guest-smoke.sh $ISSUER` is only a posture smoke on the deployed stack (posture, proxy, a bogus peek); it runs no abuse test. |
| A7 | The three e-mail policies behave as configured. `off` collects no address, `optional` accepts a join without one, `required` refuses a join without a syntactically valid one. The address lives only in the guest record and is gone after the reap and (unless the claimant chose to keep it) after a claim. | Set `guest_email_policy`, restart, redeem with and without an address; `GET /guest/invites` shows `email` only when given; after the reap no record remains. |
| A8 | **The server never holds private key material; the DID is tombstoned (`erased:did`) after the reap; every signature path except the guest hand-off refuses a guest DID.** | (a) No key setting exists in the config, and no log line or Redis value holds key material: the record holds the public DID only. (b) After a reap, `redis-cli GET erased:did/<sha256-hex of the canonical DID>` returns a value starting `guest `; redeeming that DID again answers `409 did_in_use`. (c) Try to sign in with a guest DID through the ordinary paths (SIWx sign-in, account re-auth, device approval, link): each answers `403 guest_identity`; only `/guest/continue` for a live record accepts it. A **claimed** DID is not tombstoned: it is the account's permanent identity and signs in with its passkey, and the guest hand-off refuses it from then on. |

A9 of the design (Element X parity for registered users) is a Meet-client property and is
outside this repository.

## 5. Operations

### 5.1 Kill switch and banned hosts

There is no HTTP admin endpoint, no config key and no restart: the operator writes Redis.
The reaper reads it every tick; a change is logged once per instance as `guest_control_changed`.

```
HSET guest:control disabled 1            # engage (1 or true); HDEL guest:control disabled to clear
HSET guest:control reap_before <epoch>   # every unclaimed guest minted at or before it is due now; HDEL to clear
SADD guest:banned_hosts <host>           # the host's identity as in guest_hosts; SREM to clear
```

| Setting | Effect |
|---|---|
| `disabled` | `POST /guest/invites` and the other host routes: `403 disabled`. Peek, redeem: `503 disabled`. The hand-off (`/authorize` marker, `/guest/continue`) is refused. `/guest/resume` answers `no_session`. The guest refresh grant: `400 invalid_grant`. Live guests are **not** ended; use `reap_before`. |
| `reap_before` | The refresh guard refuses a matching guest at once and each reaper tick moves the deadline of every matching live record to now; the normal reap follows, even with Synapse down. A claimed account is never touched. |
| `guest:banned_hosts` | The host cannot mint (`403 host_banned`), its invites read as `revoked`, and each tick makes its live guests due now. |

A value that does not parse, or a `guest:control` of another type, is an error: the refresh guard
answers 5xx and the hand-off is refused; the reaper logs it and keeps reaping.
Drill: engage `disabled`, check that `scripts/check-guest-posture.sh` reports the kill switch
(peek answers `503 disabled`), `HDEL`, check peek is `404 invalid_link` again.

### 5.2 The reaper and `guest_reap outcome=deferred`

Every instance runs a reaper (also with guests turned off, so guests are erased after you turn the
feature off). It tears down at most 16 due guests per tick. A failed teardown is retried with a
backoff of 15 s doubling to 15 min. **A reap that meets a live hand-off lease waits 10 s and is tried
again; it is not a failure.** It appears as audit `guest_reap` with `outcome=deferred`, the failure
count is not raised, and a `deferred` event is not a reap. Several instances may share one Redis
(one 120 s lease per guest).

### 5.3 Audit events and alerts

Events are `tracing` lines with `target=guest_audit` and an `event` field (`SIWXOIDC_LOG_FORMAT=json`
makes them one object per line). None carries a name, e-mail, secret or token.

| `event` | When | Fields |
|---|---|---|
| `guest_invite_created` | `POST /guest/invites` | `count` |
| `guest_minted` | redeem succeeded | |
| `guest_signin` | the hand-off issued a code | |
| `guest_refused` | a refused guest request | `route` (`invites`, `peek`, `redeem`, `authorize`, `refresh`, `continue`, `claim_start`, `claim_finish`), `reason`; counted for `refusal_burst` |
| `guest_reap` | per teardown attempt | `reason`, `outcome` (`erased`, `already_gone`, `claimed`, `deferred`, `failed`), `attempts` |
| `guest_control_changed` | `guest:control` or `guest:banned_hosts` differ from the last tick | `disabled`, `reap_before`, `banned_hosts` |
| `guest_claimed` | claim committed | `localpart`, `invite_id`, `credential` (fingerprint) |
| `guest_orphan`, `guest_orphan_scan` | the orphan scan | `localpart`; `scanned`, `guests`, `orphans` |

Alerts are `error` lines on the same target with an `alert` field, at most one per condition per
tick: `reaping_stuck` (a record in `reaping` longer than `guest_alert_reaping_secs`, default 900 s),
`live_guests_high`, `daily_mints_high`, `refusal_burst`. Wire your log pipeline to page on
`alert=` and to count `outcome=failed`.

### 5.4 Orphan scan

Every `guest_orphan_report_secs` (default 7 days; `0` is off) one instance asks Synapse for accounts
of `user_type` `io.inblock.guest` that have no guest record (after a Redis loss, for example) and logs
one `guest_orphan` per localpart. **It only reports; it never erases or writes.** Handle each orphan
yourself with the Synapse admin API. The scan runs with guests off only while a guest is still scheduled.

### 5.5 What to watch on Synapse: `application_services_txns`

The lk-jwt appservice registration has `url: null`: Synapse has nowhere to push transactions, so
transactions for it should not pile up. A growing count means events are being queued for an appservice
that never acknowledges them. Read-only, run against the Synapse database (table name as in the Synapse
schema; confirm on your version):

```sql
SELECT as_id, count(*) AS pending_txns FROM application_services_txns GROUP BY as_id ORDER BY pending_txns DESC;
```

Record the baseline at A1; alert when the lk-jwt row grows steadily across days.

### 5.6 Runbook headlines

- **Guests cannot join:** check in this order: the flag (`check-guest-posture.sh`), the kill switch
  (`HGETALL guest:control`), `guest_refused` reasons and `quota_exceeded` (`quota` says which), the
  minting brake (`guest_brake_reaping_count` reaps in `guest_brake_reaping_secs` pauses minting),
  Synapse reachability, Redis.
- **Reaping backlog:** `ZCARD guest:due`, `guest_reap outcome=failed`, `alert=reaping_stuck`; usually
  Synapse admin access. The reap is idempotent, so fix Synapse and wait.
- **Suspected stolen host token:** `SADD guest:banned_hosts <host>`; its live guests become due and its
  invites read as revoked.
- **Abuse through an open link:** end the invite (`POST /guest/invites/{id}/end`) or ban the host;
  open links exist only with `guest_allow_open_links`.
- **Redis loss or restore:** guests with no record are orphans on Synapse; read the next orphan scan
  (or lower `guest_orphan_report_secs` temporarily). Rotate backups within 7 days (section 6).
- **A data-subject request:** a claimed account erases itself through `/account`; an unclaimed guest is
  gone at the reap. See the retention table.

## 6. Retention and residues

| Data | Kept until |
|---|---|
| Guest record (names, optional e-mail, public DID) | The reap: at most `session_secs` (ceiling 4 hours) plus retry backoff. A record stuck in `reaping` holds its personal fields until Synapse confirms the erase (alert at 15 minutes). A claimed record lives as long as the account. |
| Consent log | Not kept. |
| Proxy access logs on `/guest/*` | At most 7 days; drop or truncate the address. |
| siwx-oidc application logs | At most 14 days. |
| Synapse `user_ips` | Set `user_ips_max_age` to at most 7 days where guests exist (it applies to every user of the homeserver, so you decide). |
| Redis persistence and backups | Rotate so that a reaped record leaves them within 7 days. |

Checklist lines (answer each, with an owner and a date): proxy log retention set; application log
retention set; `user_ips_max_age` set; Redis backup rotation set.

**Residues to state to guests and to your data-protection owner.** Never claim full erasure.

- **The private key lives only in the guest's browser; the server holds the public DID.** The operator
  cannot derive a guest's key. After the reap the DID is tombstoned and can never sign in again. The
  server cannot prove that a browser that never returns forgot its key; a stale key in an abandoned
  browser is useless against the server (the tombstone refuses the DID) but is not "deleted".
- Guests send no messages, so none remain; other participants may have seen or recorded the call.
- A stale `m.call.member` state event of the deactivated guest stays in the room (cosmetic).
- The SFU token and a connected participant survive removal for up to the token lifetime (noise in an
  end-to-end encrypted room).
- Backups, Synapse `user_ips` and logs hold personal data until their retention runs out.
- Uploaded media (none expected) is bounded by a low `max_upload_size` and a sweep of files without a
  database row; a refused upload can leave a file until the sweep.
- A guest's display name and optional e-mail are unverified; the host sees "Name (Guest)" and decides.

**Recording agents.** An agent that records or transcribes a guest room is a separate processing with
its own notice. The invite can carry `recording_expected`. This repository cannot police agent presence
(it is a room membership the host controls): the agent must announce itself in the room in a way a
guest sees, and delete or hand over its output on its own schedule. The operator's checklist line:
"a recording agent announces itself in the room".

## 7. Scripts

All three need only `bash`, `curl`, `grep`, `sed` and `tr`, read no secret and change no state.
They print `PASS:` / `FAIL:` / `SKIP:` lines and a count, and exit 1 on any `FAIL`.

| Script | Use |
|---|---|
| `scripts/check-guest-posture.sh <issuer-url> [on\|off]` | The app's own posture: flag state (with it off, the checks that need guests on are `SKIP`), GP-SEC-39 headers, the 403/415/413 gates, CORS (none on the cookie routes; `*` without credentials on the Bearer routes), the helper pages (`/guest/continue`, join, ended, claim) served from the issuer origin with a CSP that has no `'unsafe-inline'` for scripts and no inline `<script>`, on* handler or `javascript:` URL, anonymous callers refused, discovery issuer. |
| `scripts/check-guest-proxy.sh <public-url> [<direct-upstream-url>]` | The reverse proxy: the public origin equals `base_url`, headers and `Cache-Control: no-store` survive, no `Access-Control-Allow-Origin` on the cookie routes and exactly one `*` on the Bearer routes, HSTS and the http redirect, the body caps are not raised or lowered, status and headers match the direct upstream. Optional: `GUEST_SET_COOKIE='<Set-Cookie value>'` checks the cookie attributes without printing the value (only a real redeem produces one); `CHECK_RATE_LIMIT=1` sends 25 bogus redeems and expects a 429 (off by default: it trips the limiter for real users behind the address). |
| `scripts/dev-stack-guest-smoke.sh <issuer-url> [<direct-upstream-url>]` | The two above plus a bogus peek that must answer `404 invalid_link`. It does not run the live-Synapse suites (policy module, lk-jwt, LiveKit); those need the operations stack. |

Caddy note: in the `reverse_proxy` block strip any upstream `Access-Control-Allow-Origin`
(`header_down -Access-Control-Allow-Origin`) and set CORS once at the proxy where you need it; the
Bearer routes (`/guest/invites`, `/guest/invites/*/end`, `/guest/meetings/end`, `/guest/context`,
`/guest/end`) need `Access-Control-Allow-Origin: *` without credentials for the host tool and Meet
client. The cookie routes must have none. Proxy limits per the design: join/peek 60 per minute per
address, redeem 10 per 10 minutes, hand-off and `/guest/resume`, `/guest/ended` 20 per minute, claim
routes 10 per 10 minutes, host routes 10 per minute, `GET /guest/invites` 30 per minute,
`GET /guest/context` 20 per minute, `POST /register` 5 per minute, Synapse media upload 10 per minute.
The app's body caps (4 KiB; 16 KiB on `claim/finish`) are fixed; do not set a proxy cap below them.

## 8. Residual risks

Reviewable entries, with owner and review trigger, are in
[`security/EXCEPTIONS.md`](../security/EXCEPTIONS.md#guest-mode-residual-risks). In short: the operator
can read guest data and act as a guest session; a token stolen from a guest browser is usable until the
deadline (at most 4 hours); a guest left logged in on a shared machine can be continued or claimed by the
next user within the deadline; the server cannot prove a browser forgot its key; `cross-site` topology
permits silent hand-offs from a third-party page; login CSRF can put a victim into an attacker's meeting;
accounts are open to any valid proof, so guest confinement is not a perimeter; the design depends on
experimental Synapse and lk-jwt behaviour that must be re-checked at each upgrade.
