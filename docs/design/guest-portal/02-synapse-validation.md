# Guest portal 02: Synapse validation

Status: DRAFT for review. Scope: validate the guest architecture (invite link, custodial restricted account, knock
into a call room, E2EE call through lk-jwt-service and LiveKit, server-side teardown, optional claim) against the
Synapse source and the open upstream topics. Design only, nothing in this document has been run against a
deployment.

Evidence base, stated once:

| Source | Version | Read |
|---|---|---|
| Synapse | tag v1.161.0 (commit `a33b01f330850d2a968581f8e150204d7aea3b22`); paths `synapse/...` are relative to it | 2026-09-30 |
| siwx-oidc | origin/main at commit `3547bd2`; paths `src/...` are relative to it | 2026-09-30 |
| Element Call | tag v0.26.1 (commit `9f7c35c`) | 2026-09-30 |
| Element Web | tag v1.12.30 (commit `f19cfd9`); paths `apps/web/src/...` are relative to it | 2026-09-30 |
| matrix-js-sdk | tag v43.0.0 (commit `5723f58`), the version Element Web 1.12.30 and the thin client pin (03 GP-CLI-11). Every js-sdk line reference in this set is against it. Element Call's own lockfile pins an older develop commit (`24929be`, 50 commits before v43.0.0), which no reference here uses | 2026-09-30 |
| lk-jwt-service | tag v0.7.0 (Rust rewrite, `src/handler.rs`, `src/helper.rs`) | 2026-09-30 |
| Upstream issues, PRs, MSCs | GitHub state fetched 2026-09-30 | 2026-09-30 |

Synapse v1.162.0 was released on 2026-09-29, after the v1.161.0 base. Its relevant deltas are listed in
[section 1](#1-result-in-one-page) and were read from its changelog only, not from source.

Status words used in tables: **V** verified (read in source or fetched), **I** inferred (reasoned from source),
**U** unverified (could not be checked).

The marker `(revised, see D<n>)` on a requirement points to decision `n` of the
[decisions log in the overview](00-overview.md#7-decisions-log). Those decisions settle contradictions between the documents
of this set, and each stays open for the maintainers.

## 1. Result in one page

The flow is buildable on Synapse with delegated authentication, one small Synapse module, and a short list of global
settings. No Synapse core patch is needed for the guest path. This document was validated against Synapse 1.161.0. Four
prerequisites lie outside this repository ([1.3](#13-prerequisites-outside-this-repository-hard-gates)): the lk-jwt-service
membership gap (P1, [section 7](#7-lk-jwt-service-prerequisite)) must be closed before any guest account exists, on dev too,
and Synapse 1.162.0 or later is required before the module goes live (P3).

### 1.1 Behaviours that differ from what a reader might expect

These are places where Synapse or the code behaves differently from what a configuration name, a comment or a first reading suggests. The design relies on each of them.

| # | Plausible expectation | What the source says | Evidence | Status |
|---|---|---|---|---|
| C1 | "Erase leaves the user in rooms" | Deactivation, with or without erase, makes the user LEAVE and FORGET every room through a background loop. Pending invites and knocks are rejected first. The guest's `m.call.member` state event stays behind and can no longer be cleared by the guest. | `synapse/handlers/deactivate_account.py:162,186,280-331` | V |
| C2 | "A pending delayed leave cleans up the call entry" | Nothing cancels or fires delayed events on deactivation or device deletion. A delayed leave that fires after the guest was parted fails event auth and is only logged. | `synapse/handlers/delayed_events.py:583-646`, no reference to deactivation in the delayed-event storage | V (mechanism), I (outcome) |
| C3 | "Synapse keeps trusting a token up to 2 min past its expiry" (comment in `src/admin_token.rs:57-63`) | Expiry is enforced per request from `retrieved_at_ms + expires_in`, even for a cached introspection. The 2 min cache delays only revocation of an unexpired token. Deleting the device is immediate. The comment in siwx-oidc is wrong on expiry and should be corrected; the rule "never infer validity from Synapse" stays right for revocation. | `synapse/api/auth/mas.py:90-101,332,399-406` | V |
| C4 | "`limit_profile_requests_to_users_who_share_rooms` restricts profile reads" | Inert on its own. It only applies when `require_auth_for_profile_requests` is also true, because an unauthenticated request carries no requester. | `synapse/rest/client/profile.py:76-85`, `synapse/handlers/profile.py:1007-1011` | V |
| C5 | "`block_non_admin_invites` stops guests inviting" | It blocks every non-admin invite, so a host who accepts a knock (accept is an invite) is blocked too. Use a module callback instead. | `synapse/handlers/room_member.py:906-912` | V |
| C6 | "`experimental_features.msc3266_enabled` and `msc4140_enabled` exist" | Neither key exists in 1.161. The room summary endpoint is always on. Delayed events are on when top-level `max_event_delay_duration` is set and `experimental_features.msc4140_max_delayed_events_per_user` is non-zero (default 100). | `synapse/rest/client/room.py:1696-1735`, `synapse/config/server.py:969-999` | V |
| C7 | "Element's restricted-guests module can be loaded as is" | It creates accounts through the MAS admin API, which siwx-oidc (the IdP) does not offer, and identifies guests by a localpart prefix. See [3.2](#32-the-restricted-guests-module). | element-modules `guest_module.py:82-92`, `mas_admin_client.py:37,64,93` | V |
| C8 | "Account validity and MAU limits cap guests" | Neither is enforced for delegated auth. request authentication checks `is_user_expired` only in internal auth, `check_auth_blocking` is skipped for admin registration and never called in `mas.py`. | `synapse/api/auth/internal.py:171`, `synapse/handlers/register.py:305`, `synapse/api/auth/mas.py` (no call) | V |
| C9 | "`provision_user` on a deactivated localpart revives it" | It returns 200 and changes nothing about the deactivation. The localpart is consumed for ever. | `synapse/rest/synapse/mas/users.py:155-220` | V |
| C10 | "`enable_set_displayname: false` and `enable_set_avatar_url: false` stop a guest from renaming or changing its avatar" | Both are global, and each binds only when a value already exists: a user with no avatar can still set one. Admin writes always pass. Per-room profiles are stripped only by the separate global `allow_per_room_profiles: false`. | `synapse/handlers/profile.py:247-256,372-381`, `synapse/config/registration.py:148-149`, `synapse/handlers/room_member.py:804-811`, `synapse/config/server.py:741` | V |
| C11 | "A module can veto a profile change" | No hook runs before the write. `on_profile_update` fires after it, for display name, avatar and custom fields, and carries `by_admin` and `deactivation`. The Module API can set a display name but has no avatar setter. | `synapse/handlers/profile.py:281-296,417-419,736-738`, `synapse/module_api/callbacks/third_party_event_rules_callbacks.py:487-505`, `synapse/module_api/__init__.py:2018-2064` | V |
| C12 | "`user_may_invite` confines invites for every inviter" | It does not run when the inviter is a server admin: `block_non_admin_invites` and the spam-checker call both sit inside `if not is_requester_admin`. `check_event_allowed` has no admin bypass and sees the invite event together with the room state. Invite confinement and the admission re-audit therefore run there, with `user_may_invite` as a second layer (GP-SYN-04, GP-SYN-19) | `synapse/handlers/room_member.py:904-916`, `synapse/handlers/message.py:1437-1441` | V |
| C13 | "A near-zero per-user upload limit bounds storage abuse" | The body is stored before the per-user limit is checked, and the `UserLimitExceededError` path deletes nothing and writes no database row. Each refused upload leaves an untracked file of up to `max_upload_size` (default 50 MiB), which `delete_user` and the admin media APIs do not see. The module callback `is_user_allowed_to_upload_media_of_size` runs before the body is stored (GP-SYN-13) | `synapse/media/media_repository.py:349-353,413-418`, `synapse/rest/media/upload_resource.py:67-78`, `synapse/config/repository.py:199` | V |
| C14 | "Rewriting `displayname` and `avatar_url` confines a marked user's member events" | The rest of the content stays the guest's. The state PUT of the guest's own member event hands the whole content dict to `update_membership`, and a knock carries a free-text `reason`, for which Element Web offers the host a "view message" link. GP-SYN-08 therefore keeps an allow-list of content keys | `synapse/rest/client/room.py:364-376`, `synapse/rest/client/knock.py:62-66`, `apps/web/src/components/views/rooms/RoomKnocksBar.tsx:108-117` | V |

### 1.2 Version deltas to plan for

| Change | Where | Consequence for this design |
|---|---|---|
| Admin API user creation is refused when MAS delegation is on. Merged 2026-09-28 on `develop`, NOT in v1.162.0 (its changelog entry is absent), so it ships with the next release. Modifying an existing user stays allowed, the PR's own test asserts that. | https://github.com/element-hq/synapse/pull/20241 (fetched 2026-09-30) | Never create the guest through `PUT /_synapse/admin/v2/users/{id}`. Create with `provision_user`, then modify with the admin API ([3.3](#33-the-guest-marker)). |
| The default room version is "11" on 1.161 (`synapse/config/server.py:179`, read at `:612`). v1.162.0 raises it to "12" (changelog). `check_event_allowed` crashed on room version 12 creation events until PR 19768 (merged 2026-09-15, in 1.162.0), so the crash hits rooms created as v12, which is what 1.162 makes the default. | https://github.com/element-hq/synapse/pull/19768 | Our module relies on `check_event_allowed`. Run 1.162.0 or later before the module goes live (P3) and test the module on v12 rooms first. On 1.161 keep the default "11", for dev experiments only. Room version 12 also changes how power and room ids work, see the row "Room versions" of [section 4](#4-room-model). |
| v1.162.0 adds `rc_profile` (profile lookup rate limit) | v1.162.0 changelog | Optional help against profile probing, not needed by the design. |

### 1.3 Prerequisites outside this repository (hard gates)

| Gate | Prerequisite | Addressed in |
|---|---|---|
| P1 | lk-jwt membership enforcement (Synapse `msc4502_enabled` plus a small lk-jwt patch that calls the existing membership check on the routes Element Call actually uses). Hard dependency before any guest exists, on dev too. | GP-SYN-01, [section 7](#7-lk-jwt-service-prerequisite) |
| P2 | SFU eviction and a short SFU token lifetime before production (lk-jwt kick PR or equivalent). The OpenID token lifetime is a Synapse constant (`synapse/rest/client/openid.py:72`) and is not configurable; P1 covers confidentiality for that half. | residual gap in [section 7](#7-lk-jwt-service-prerequisite), open decision 6 |
| P3 | Synapse 1.162.0 or later before the module goes live, then re-read 02 against that version. Federation off for a guest deployment (a remote knock reaches no hook). | [1.2](#12-version-deltas-to-plan-for), GP-SYN-12, open decision 8 |
| P4 | the guest policy module (separate repository, licence path decided by the maintainers with counsel). | GP-SYN-02, [3.2](#32-the-restricted-guests-module), open decision 4 |

### 1.4 Hard dependencies inside the deployment

| ID | Dependency | Owner | Section |
|---|---|---|---|
| GP-SYN-01 (revised, see D11) | lk-jwt-service membership check on every route that mints a publish token or creates an SFU room (P1), bound to the configured homeserver name | outside this repository | [7](#7-lk-jwt-service-prerequisite) |
| GP-SYN-02 (revised, see D1) | A guest policy Synapse module (marker-keyed confinement, directory, media, names) (P4) | small new component in its own repository | [3](#3-restrictions) |
| GP-SYN-03 | `auto_join_rooms` empty on a homeserver that provisions guests | deployment check | [3.5](#35-global-synapse-configuration) |

## 2. Flow validation, step by step

Columns: what Synapse does, what it enforces, what it does NOT enforce, and the gap the design must close.

| Step | Synapse behaviour (evidence) | Enforces | Does NOT enforce | Gap and countermeasure |
|---|---|---|---|---|
| 1, 2. Invite link, name, e-mail | Synapse is not involved. | nothing | The invite token, the name and the e-mail are invisible to Synapse. | All admission control, rate limiting and input validation live in siwx-oidc. Synapse does not validate display name length or content on this path (I), so siwx-oidc must sanitise. |
| 3a. `provision_user` creates the account | `synapse/rest/synapse/mas/users.py:144-240` calls `register_user(localpart, default_display_name, bind_emails, by_admin=True)`. Returns 201. siwx-oidc client: `src/synapse_client.rs:468`. | Shared secret (`_base.py`), localpart charset, length, case-insensitive uniqueness (`register.py:159-219,308-309`). Fires the `check_registration_for_spam` callback with the localpart (`register.py:281-302`; a deny is answered to the caller as 429) and `on_user_registration` (`register.py:768`). | No rate limit (`check_registration_ratelimit` is a no-op without an address, `register.py:706-721`), no MAU or auth blocking (`register.py:305`), no cap on user count, no `user_type`, no guest concept. E-mail is stored as a validated 3pid without verification (`register.py:~415`). | Account minting is bounded only by siwx-oidc. The marker must be added right after creation ([3.3](#33-the-guest-marker)). Treat the e-mail as unverified PII. |
| 3a'. `auto_join_rooms` | Fires inside `register_user` for a NEW user, synchronously, before any device exists (`register.py:378-396`). A `knock` room counts as "requires invite" and is entered through `auto_join_mxid_localpart`, bypassing the knock (`register.py:560-576`). | only what is configured | Anything about who the user is. | Keep `auto_join_rooms` empty (GP-SYN-03). Otherwise every guest lands in those rooms and can list their members. |
| 3b. Marker write | `PUT /_synapse/admin/v2/users/{id}` modify branch sets `user_type` (`synapse/rest/admin/users.py:470-471`); value must be in `user_types.extra_user_types` (`users.py:308-310`, `synapse/config/user_types.py:30,34`); the store invalidates the `get_user_by_id` cache (`synapse/storage/databases/main/registration.py:760-762`). Registered under delegated auth (`synapse/rest/admin/__init__.py:306`). | admin scope (`urn:synapse:admin:*`, `synapse/api/auth/mas.py:274-275`) | Nothing links the call to the invite. | siwx-oidc writes the marker between `provision_user` and `upsert_device`, so before any device row and before any token exists. If the write fails the mint fails closed: no token, the guest record stays `provisioning`, and the reaper erases the half-created account once the lease of 01 GP-FLOW-26 has lapsed (GP-SYN-07, revised, see D1). |
| 3b'. Canonical name write | A second admin request. Inside one modify request the profile is written before `user_type` (`users.py:372-379` against `:470-471`), so the name needs its own request once the marker exists. Admin writes reach `on_profile_update` with `by_admin=True` (`synapse/handlers/profile.py:294-296`); so does `provision_user` for an existing user (`synapse/rest/synapse/mas/users.py:173-180`). | the same admin scope | A guest's own profile writes carry `by_admin=False`. | The module records the admin-made name of a marked user as canonical (GP-SYN-08, spike SY-1). |
| 3c. `upsert_device` | `synapse/rest/synapse/mas/devices.py:37-77`. 201 if inserted, 200 if it existed, 404 if no user row. siwx-oidc client: `src/synapse_client.rs:502`. | user exists | Does not check `is_deactivated`, no device count limit. | A token is only valid while its device row exists (step 4). Create the device with the first token. |
| 4. Token introspection | `synapse/api/auth/mas.py:193-414`. Consumes `active`, `scope`, `username`, `device_id`, `expires_in`. Requires the Matrix API scope, an existing users row, and an existing device row. Cache: 2 min, keyed by token (`mas.py:136-147`). Siwx-oidc side: `src/introspect.rs:142-159`. | activity and expiry on every request (`mas.py:90-101,332`), device existence on every request (`mas.py:399-406`) | `is_deactivated`, `locked`, `suspended`, `sub`, issuer. A deactivated user with a live device is served. | Teardown must delete the device ([6](#6-erase-deactivate-call-cleanup-and-claim)). Keep `expires_in` at or below the 300 s access TTL. A token revoked only in siwx-oidc stays usable for up to 2 min. |
| 5a. Knock | `POST /_matrix/client/v3/knock/{roomIdOrAlias}` (`synapse/rest/client/knock.py:44-95`). Event auth: room version 7 or later, `join_rule` knock or knock_restricted, sender equals target, not joined, not invited, not banned (`synapse/event_auth.py:801-819`). | the event auth rules; `rc_message` per user (`synapse/handlers/message.py:1983-1994`) | No spam-checker callback (the KNOCK branch at `room_member.py:1196-1222` calls none), no `rc_joins`/`rc_invites`, no per-room cap. Remote knocks (`do_knock`, `synapse/handlers/federation.py:880`) reach no module hook at all. `check_event_allowed` sees local knocks (`message.py:1437`). | A guest who knows any knock room id can knock on it. Confine with `check_event_allowed` (GP-SYN-05) and keep guest deployments unfederated (GP-SYN-12). |
| 5a'. Host notification | The knock is a normal `m.room.member` event. The default push rule `.m.rule.member_event` has EMPTY actions, only `invite_for_me` notifies (`rust/src/push/base_rules.rs:100-132`). | | Any push notification of a knock. | The host is not alerted by Matrix itself, so a host-visible notice is part of the design, by the mechanism named in GP-SYN-20 (revised, see D7). Element Web renders a knock bar in the room header behind `feature_ask_to_join`, which is off by default, and has a popup text for a knock (`apps/web/src/components/views/rooms/RoomHeader/RoomHeader.tsx:425,517`, `apps/web/src/settings/Settings.tsx:737-744`, `apps/web/src/Notifier.test.ts:446-475`). Whether the default push rule lets that popup fire, and whether a per-room override rule outranks it, was not established (U): GP-SYN-20 makes both a requirement on spike SP-3 of the plan. |
| 5b. Host accepts | There is no accept API. Accept is `POST /rooms/{id}/invite` by a member with invite power (`room_member.py:914`, `rc_invites` at `:379-394`). After an invite a repeat knock is refused (`event_auth.py:815-816`). | `rc_invites.*` limits; `user_may_invite` and `block_non_admin_invites` only when the inviter is not a server admin (`room_member.py:906-916`) | | See C5 and C12. Guests must never be able to invite, and a marked invitee is admitted only into an audited room. Both rules run in `check_event_allowed` on the invite event, which has no admin bypass, with `user_may_invite` as a second layer (GP-SYN-04, GP-SYN-19). |
| 5c. Guest joins | `POST /join` needs an invite for a knock room (`event_auth.py:757-768`). `user_may_join_room(user, room, is_invited)` fires (`room_member.py:1075`), skipped for server admins and for a room the user just created. `rc_joins.local` and `rc_joins_per_room` apply (`room_member.py:637-651`). | invite, callback, rate limits | The invite link is invisible to Synapse. | The host's invite is the only Synapse-side proof of admission. |
| 6a. Call membership | `m.call.member` is an ordinary state event, sendable if the guest holds the power level for that type. A state key that starts with `@` and differs from the sender is refused in every room version (`synapse/event_auth.py:894-921`, 403 "You are not allowed to set others state"). Only the owner rule for a key that continues after the user id with `_` is gated, and only by the unstable room versions (`msc3757_enabled`, `event_auth.py:899-920`). MatrixRTC keys begin with an underscore: `_<MXID>_<device id>_m.call` (js-sdk `src/matrixrtc/MembershipManager.ts:979-994`, the underscore form outside the unstable room versions), so in every stable room version any member with the power level can overwrite another member's entry. | power level | ownership of an underscore key | `check_event_allowed` rule: a guest may only write the one call-member key built from its own MXID and a device id, compared exactly and never by substring (GP-SYN-06). |
| 6b. Delayed leave | Needs `max_event_delay_duration` (off by default). Rows are bound to `user_localpart` and `device_id`, survive restarts and are re-sent on start (`synapse/handlers/delayed_events.py:91-130,583-646`). In 1.161 the management calls `cancel`, `restart` and `send` take no access token: an unauthenticated call is rate limited by client address, and the delay id (`syd_` plus 20 random characters) is the only capability (`synapse/handlers/delayed_events.py:427-495`, `synapse/rest/client/delayed_events.py:83-133`, `synapse/storage/databases/main/delayed_events.py:703`). | per-user count 100, `rc_delayed_event_mgmt` 1/s burst 5 (`synapse/config/ratelimiting.py:238`) | cancellation on deactivation or device deletion | Not a reliable cleanup path (C2). Keep it enabled for ordinary disconnects only. |
| 6c. Media keys | See [section 5](#5-e2ee-for-a-brand-new-guest-device). | | | |
| 7a. Revoke | `active:false` is seen after at most 2 min. Device deletion is seen at once, but only for a token that names a device: the device row is read only `if device_id is not None`, and `is_deactivated` is never read (`mas.py:385-406`). | | | Delete each device of the guest, do not rely on introspection alone, and never issue a guest token without a device scope (GP-SYN-09, revised, see D2). |
| 7b. `delete_user` with erase | `synapse/rest/synapse/mas/users.py:271-310` runs `deactivate_account(erase_data=erase)` with `by_admin=False` (upstream issue 19721, open). siwx-oidc client: `src/synapse_client.rs:1116-1151`. | see [section 6](#6-erase-deactivate-call-cleanup-and-claim) | Message redaction. | Residues table in section 6. |
| 7c. Claim | siwx-oidc links a passkey to the same DID. The claim writes nothing to Synapse: the account must still be alive, and the marker stays (GP-SYN-10, revised, see D3). | | | A claim must complete before teardown (GP-SYN-10). |

## 3. Restrictions

### 3.1 What the module API can enforce per user

| Hook | Fired at | Usable for | Blind spots |
|---|---|---|---|
| `check_registration_for_spam` | `synapse/handlers/register.py:281` (runs for MAS-provisioned users) | Global creation backstop, deny is answered as 429 | Sees the localpart only, not the invite |
| `on_user_registration` (account validity API) | `register.py:768` | Post-creation hook | Same |
| `user_may_create_room` | `synapse/handlers/room.py:707,1233` | Deny guests | none |
| `user_may_create_room_alias`, `user_may_publish_room` | `synapse/handlers/directory.py:160,453` | Deny guests | none |
| `user_may_invite` | `room_member.py:914` | Second layer of the invite rules of GP-SYN-04 and GP-SYN-19 (the first layer is `check_event_allowed`) | Skipped when the inviter is a server admin: it and `block_non_admin_invites` sit inside `if not is_requester_admin` (`room_member.py:906-916`). Runs after `block_non_admin_invites` |
| `user_may_join_room` | `room_member.py:1075` | Allow guest joins only into guest rooms | JOIN only, NOT knock; skipped for admins |
| `check_event_allowed` (third-party rules) | `synapse/handlers/message.py:1437`, every locally created event incl. knock, invite, leave and call state, with no admin bypass. Receives the room state before the event as a map of (type, state key) to event (`third_party_event_rules_callbacks.py:280-289`). May return a replacement event. | Knock confinement, the re-knock cap of GP-SYN-21, invite confinement and the admission re-audit of GP-SYN-19, state-write limits, denial of non-state events, the content allow-list and the name rewrite of member events | Not reached by a remote knock (`federation.py:880`); must never deny a guest's `leave`. A replacement may change content but not type, state key or room (`message.py:2458-2474`) |
| `check_event_for_spam` | `message.py:1197` | Message content checks | Non-member events only |
| `user_may_send_state_event` | `synapse/rest/client/room.py:322` | State PUT checks | REST state PUT only, not membership, not delayed events |
| `check_username_for_spam` (2-argument form) | `synapse/handlers/user_directory.py:177` | Hide guests from every search and give guests an empty directory | needs Synapse 1.122 or later |
| `get_media_upload_limits_for_user` | `synapse/media/media_repository.py:364-372` | Per-user upload quota | Checked AFTER the body is stored, so it refuses the request but bounds no storage (C13) |
| `is_user_allowed_to_upload_media_of_size` | `synapse/rest/media/upload_resource.py:67-78` (called by the POST upload and the async PUT upload), `synapse/module_api/callbacks/media_repository_callbacks.py:100-110` | Refuse a marked user's upload by declared `Content-Length` before the body is stored (GP-SYN-13) | Judges the declared length only; the HTTP layer has already buffered the body, so bandwidth and transient disk are spent |
| `check_media_file_for_spam` | media repository | | `FileInfo` carries no uploader (`synapse/media/_base.py:526-541`), so it cannot target guests |
| `get_ratelimit_override_for_user` | `synapse/api/ratelimiting.py:183-195` | Tighten invite limits | Only `rc_invites.*` call it (`room_member.py:169-187`); experimental. The admin `override_ratelimit` can only disable limits (`ratelimiting.py:173-180`) |
| `is_user_expired` (account validity) | `synapse/api/auth/internal.py:171` only | | Not enforced under delegated auth (C8) |
| `check_can_deactivate_user`, `on_user_deactivation_status_changed` | `synapse/handlers/deactivate_account.py:97,229,360` | Observe or veto teardown | `by_admin` is always false for `delete_user` |
| `on_profile_update(user_id, new_profile, by_admin, deactivation)` | third-party rules; `synapse/handlers/profile.py:294,417,736,823` | Record the admin-made canonical name of a marked user, revert the marked user's own global name change | Fires AFTER the write, so it cannot veto. Fires for display name, avatar and custom fields. Erase fires it with empty values and `deactivation=True` (`profile.py:464-469`): never revert then. Exceptions are logged and swallowed (`third_party_event_rules_callbacks.py:497-505`) |
| `user_may_invite` with `ModuleApi.get_room_state` | `room_member.py:914`; `synapse/module_api/__init__.py:1644` | Second layer of the admission re-audit (GP-SYN-19), for a non-admin inviter | The callback receives no room state; the module reads it. Skipped for server admins |

Failure behaviour, which decides what a module bug costs. An exception inside a spam-checker callback such as
`user_may_invite` or `user_may_join_room` is not caught by the dispatcher, so the request fails and the action does not
happen (`synapse/module_api/callbacks/spamchecker_callbacks.py:495-503`, `:452-458`). An exception inside
`check_event_allowed` becomes a `ModuleFailedException` and the event is not created
(`third_party_event_rules_callbacks.py:303-306`). An exception inside `on_profile_update` is logged and ignored
(`:497-505`). The enforcing rules therefore fail closed, and the profile revert is a repair step that can fail open for the
global profile while the room-visible name stays enforced by `check_event_allowed`.

### 3.2 The restricted-guests module

Source: https://github.com/element-hq/element-modules/tree/main/modules/restricted-guests (fetched 2026-09-30; last commit
touching it 2026-09-02; requires Synapse 1.122 or later).

| Aspect | What it does | Fit with this design |
|---|---|---|
| How a guest is identified | `_is_module_guest`: local user whose localpart starts with `user_id_prefix` (default `guest-`). No flag, no account data (`guest_module.py:82-92`). | Poor. Our localparts are derived from the DID (`src/mxid.rs`) and never change, and policy must never key on identifier structure. The marker is a server-side field instead ([3.3](#33-the-guest-marker)). |
| How accounts are created | Its own unauthenticated `POST /_synapse/client/register_guest` servlet mints a random `guest-` localpart and, under MAS, calls the MAS admin API (`/api/admin/v1/users`, `/personal-sessions`) (`mas_admin_client.py:37,64`). | Not usable. siwx-oidc is the IdP and has no MAS admin API, and an account minting endpoint inside Synapse would bypass the invite gate. |
| Expiry | A reaper deactivates users older than `user_expiration_seconds` (default 24 h) using its own table `guest_module_mas_users` and the MAS admin API (`guest_user_reaper.py:108-149`). | Not needed. siwx-oidc owns lifetime and teardown. |
| Restrictions | No room creation, guests cannot invite, nobody may invite a guest into a room in `rooms_forbidden_to_guests`, a guest may join only `knock` rooms or when invited, guests hidden from the user directory and given an empty one, display-name suffix ` (Guest)` restored on profile update (`guest_module.py:278-364`). | This half is what we need, with two gaps: no callback fires for a knock, so a guest can knock on ANY knock room on the server; and `user_may_invite` lets any non-guest invite a guest into ANY room. |
| Optional room-list monkey patch | `hide_room_directory_from_guests` patches Synapse internals (`room_list_patch.py`), off by default. | Skip. |
| `rooms_forbidden_to_guests` | A deny list of room IDs, module-only (Synapse has no such key, `grep` of `synapse/` and `docs/` finds nothing). | Replace by a positive rule: guests act only in rooms carrying a guest-room flag (GP-SYN-05). A deny list fails open for every room added later. |

Decision: write the small equivalent, do not load the upstream module.

| Option | Verdict | Reason |
|---|---|---|
| Adopt unmodified | No | Registration path and identification both assume MAS and a prefix. |
| Adapt (fork the restriction half) | Only if the maintainers accept the licence consequence below | About 100 lines of logic, but any copied expression carries the upstream licence. |
| Write the small equivalent against the public module API | Yes | The rules in [3.4](#34-rules-of-the-guest-policy-module) are simple predicates over documented callback signatures, and we add the two missing rules. |

Licence consequences, stated neutrally. This is not legal advice and the maintainers decide.

- The upstream module is offered under `AGPL-3.0-only` or a paid Element commercial licence (SPDX header of
  `guest_module.py`; README of the module). Its file header states that the code was originally licensed under
  Apache-2.0. Which revisions carry which licence was not checked.
- Synapse itself is `AGPL-3.0-or-later` or an Element commercial licence (`pyproject.toml:10`). A module loaded into a
  Synapse process therefore runs inside an AGPL process whichever choice the operator made.
- siwx-oidc is Apache-2.0 (`LICENSE`). Copying upstream module code into this repository would make those files AGPL
  or require the commercial licence. A module written independently would keep its own licence, and if it is kept in a
  separate repository the question does not reach this one.
- This document describes behaviour. It contains no upstream code. An implementer who wants a clean separation should
  write from the Synapse module documentation (`docs/modules/*.md`), not from the upstream module source.

### 3.3 The guest marker

A guest must be recognisable to the module through a server-side fact that the guest cannot write and that is not
derived from the localpart or the DID method. The marker means "confined identity". It does not mean "unclaimed": a
claim does not clear it (D3), so a claimed guest stays confined until an operator promotes the account.

| Candidate | Why not, or why |
|---|---|
| Localpart prefix (upstream) | Immutable, conflicts with DID-derived localparts, and keys policy on identifier structure. |
| Custom profile field | Dropped (D1). Stock Synapse lets any user write any custom profile field (`docs/matrix-integration.md`, patch registry section); the denylist patch is open upstream (synapse#19980, open, updated 2026-09-11). A second, advisory marker that can disagree with the enforcing one is a defect. |
| Account data | User-writable through the client API (I). |
| `locked` flag | Hides the user from the directory but is not enforced by Synapse under delegated auth (`mas.py:277-414`), and the meaning collides with real locks. |
| Module-owned table | Needs a write channel into Synapse: a new endpoint, a new secret, a new attack surface. |
| Redis read by the module | Couples Synapse to siwx-oidc's store and forces a fail-open or fail-closed choice per request. |
| `user_types.default_user_type` | Global: it marks every account `provision_user` creates, because that route passes no per-call type (`synapse/handlers/register.py:323-324`, `synapse/rest/synapse/mas/users.py:158-163`). |
| **`users.user_type`** | Native column, admin-only writes, read through the cached `get_userinfo_by_id` (`synapse/module_api/__init__.py:738-748`, cache at `registration.py:380`), custom values allowed with `user_types.extra_user_types`, no built-in behaviour attached to a custom value (only `support` and `bot` are special-cased, `registration.py:848,1128`). |

**GP-SYN-07 (revised, see D1 and D3)** The marker is `user_type = io.inblock.guest`, and it is the only guest marker on the
homeserver. siwx-oidc writes it with `PUT /_synapse/admin/v2/users/{id}` `{"user_type": "io.inblock.guest"}` after a
successful `provision_user` and before `upsert_device`, on every guest sign-in (the write is idempotent), so no device row
and no token exists before it. A claim never clears it. Promotion to an ordinary account is an operator action or an
attested claim that writes `{"user_type": null}` through the admin API (`users.py:470-471` sets the column whenever the key
is present), never a side effect of the passkey claim and never based on key structure. If `provision_user` or the marker
write fails, the mint fails closed: no token is issued and the guest record stays `provisioning` (01 GP-FLOW-26: the sign-in
moved it there by compare-and-set before `provision_user`, because the account may exist), so the next sign-in retries every
step. A record that is never completed is torn down at the deadline by the reaper of 01, which reads `provisioning` as "the
account may exist": it moves the record to `reaping` only once it holds the lease (`guest:lease/<localpart>`, held by an
in-flight sign-in for 120 s), so it leaves the due entry for the next tick, waits at most one lease after the last fence and never
erases under a sign-in that is making progress, and then always erases, with no `query_user` shortcut. A sign-in that hangs past
the lease is fenced out by its refused state move and erases what it made itself. The half-created account holds no device and no room membership (GP-SYN-03). The marker write must never create the user itself: on an absent
user the admin `PUT` takes the creation branch (`users.py:371,481`), which is refused after PR 20241 (section 1.2). An
unmarked account can exist only as that failed-mint residue, and it cannot act because every request needs a token.

Orphans are findable by an operator audit: the admin user list returns `user_type` for every row and sorts by it
(`synapse/rest/admin/users.py:144-157`, `synapse/storage/databases/main/__init__.py:99-114,319-322`). It has a
`not_user_type` filter and no positive one.

Creation through the admin API would make the marker atomic with the account, but that path is refused in the next Synapse
release (section 1.2), so it must not be used. If upstream ever refuses modification too, the fallback is a module-owned
table with a small write endpoint authenticated by the MAS shared secret. A custom type counts as a real user for MAU.

### 3.4 Rules of the guest policy module

| ID | Rule | Hook |
|---|---|---|
| GP-SYN-04 | A guest may not create rooms or aliases, publish to the directory, or invite anyone. Nobody may invite a marked user into a room that is not a flagged guest room, whoever the inviter is, server admins included (04 GP-SEC-29). The invite rules run in `check_event_allowed` on every `m.room.member` invite event whose sender or target is a marked user, because that hook has no admin bypass. `user_may_invite` repeats them as a second layer and is skipped when the inviter is a server admin (C12). | `user_may_create_room`, `user_may_create_room_alias`, `user_may_publish_room`, `check_event_allowed` (first layer), `user_may_invite` (second layer) |
| GP-SYN-05 | Confinement. A guest may knock, be invited, join and send events only in a room whose state carries `io.inblock.guest_room` (state key empty). A guest's `leave` is always allowed, because the deactivation loop uses it (`deactivate_account.py:306-331`) and swallows failures. | `user_may_join_room`, `check_event_allowed` |
| GP-SYN-06 | State writes. In a guest room a guest may write only its own `m.room.member` event and its own call-member events (`m.call.member` and the unstable names). A call-member state key is accepted only if it equals `_` plus the guest's own MXID plus `_` plus a device id plus `_m.call`, where the device id contains neither `@` nor `:`. The match is exact and anchored at both ends, never a substring or prefix test, and a key without the leading underscore is refused (outside the unstable room versions the js-sdk always writes the underscore form, and Synapse refuses an `@` key that is not the sender's own, `event_auth.py:894-921`). Why: MatrixRTC keys are `_<MXID>_<device id>_<app><slot>` (js-sdk `MembershipManager.ts:979-994`), and a rule that only required the guest's MXID to appear somewhere in the key would pass a key that embeds another user's id. Spike SY-2 fixes which event types and keys Element Call 0.26.1 really writes, and the same key rule applies to each type it writes. | `check_event_allowed` |
| GP-SYN-08 (revised, see D8) | Name, profile and content confinement. Every `m.room.member` event whose state key is a marked user (knock, invite, join, leave, the user's own edits, whoever sends it) is replaced by a copy whose content holds only an allow-list of keys: `membership` and the canonical `displayname`. `reason`, `avatar_url` and every unknown key are dropped, because the rest of the content is otherwise the guest's (C14): a knock carries a free-text `reason` that Element Web offers the host, and the state PUT of the own member event stores the whole content dict. A `leave` keeps `membership` only and reads no module storage (GP-SYN-17). The module rewrites through the replacement return value and does not reject. The allow-list does not depend on spike SY-1 and stays in force under every fallback below: only the source of the `displayname` value changes. The marked user's own global name change is reverted. The canonical name is fixed by an admin write at mint, as described in [the mechanism below](#canonical-name-and-profile-confinement-gp-syn-08). The operator suffix of 04 is part of the canonical string, so the module enforces equality and needs no suffix logic. | `check_event_allowed`, `on_profile_update` |
| GP-SYN-11 | Directory. Guests are hidden from every search and get an empty directory. | `check_username_for_spam` |
| GP-SYN-13 | Media. A marked user's upload is refused before the body is stored, by the declared `Content-Length`, and `get_media_upload_limits_for_user` returns a quota of zero bytes as a second check. Neither bounds storage on its own, because the per-user limit is checked after the body is stored and a refused upload leaves its file on disk with no database row (C13). The real controls are a low global `max_upload_size` on the guest deployment, a proxy rate limit (10 per minute per address, 04 section 3.1) and a body cap equal to `max_upload_size` on the media upload routes (`/_matrix/media/*/upload` and `/_matrix/media/*/create`), and a periodic sweep of media files with no database row. The residual is recorded in [3.6](#36-isolation-gaps-that-remain). | `is_user_allowed_to_upload_media_of_size`, `get_media_upload_limits_for_user`, proxy, deployment |
| GP-SYN-14 (revised, see D5) | Who may set the flag. Only users on a configured host list may send `io.inblock.guest_room`; the room's power levels set it to 100. The module list must contain every entry of the siwx-oidc `guest_hosts` list (04 GP-SEC-28 has the mint-time audit check that the flag's sender is in `guest_hosts`, so one list governs both sides and the module list may only be broader). This is the one rule that restricts an unmarked user, and it covers one event type only. | `check_event_allowed` |
| GP-SYN-15 | Optional backstop on account creation: deny when more than N accounts were created in a window. | `check_registration_for_spam` |
| GP-SYN-17 (D1) | Scope of the module: deny by default for marked users, no effect on unmarked ones. Every callback first reads `user_type` of the acting user, and of the target for invites. If neither carries the marker it returns at once, so ordinary accounts are never restricted and pay one cached read. For a marked user every action that no rule above allows is refused. A `leave` is always allowed and never depends on module storage. | all callbacks |
| GP-SYN-18 | Denial of non-state events. A marked user sends no event except its own `m.room.member` events and its own call-member state (GP-SYN-06): `m.room.message`, `m.room.encrypted`, `m.reaction` and `m.room.redaction` are refused, and the member events themselves carry no free text (the allow-list of GP-SYN-08 leaves no place for `reason` or a custom key). The operator may widen the list (04 GP-SEC-27, `guest_allowed_event_types`). Whether Element Call needs any room event from a participant is untested (spike SY-2). | `check_event_allowed` |
| GP-SYN-19 | Re-audit at admission. `check_event_allowed` refuses an `m.room.member` invite event whose target is a marked user when the room is not a flagged guest room, and when it is flagged but its current state violates the template of [section 4](#4-room-model), whoever the inviter is: a server admin included, because the hook has no admin bypass (C12, 04 GP-SEC-29). It reads the state map it receives (the room state before the event), so no extra read is needed. Power is computed with the room-version rule (a creator and every `additional_creators` entry is maximal, read from `m.room.create` and never from the `users` map, row "Room versions" of section 4). `user_may_invite` repeats the predicate as a second layer for a non-admin inviter and reads the room state through `ModuleApi.get_room_state` because that callback receives none (04 GP-SEC-29). | `check_event_allowed` (first layer), `user_may_invite` (second layer) |
| GP-SYN-20 (revised, see D7) | Host notice. A knock raises no push notification (row 5a'), so each knock on a flagged room produces a host-visible notice. The mechanism is the one of 01 GP-FLOW-29, 04 GP-SEC-68 and the host screens of 06: a waiting-guest notice in the host tool that created the invites, fed by the host list of `GET /guest/invites`, and in addition one per-room override push rule for knock events that the tool installs when it creates the room. The Element Web knock bar (`feature_ask_to_join`) is an additional aid and a bot message is an operator option outside v1. Requirement on spike SP-3 of the plan: it must establish, on the target Synapse and Element Web builds, whether a per-room override rule that matches `m.room.member` events with `content.membership` of `knock` outranks the default override rule `.m.rule.member_event` (empty actions, `rust/src/push/base_rules.rs:118-132`) for both evaluators, Synapse's own (pushers, mobile) and the js-sdk push processor (Element Web popups), and whether the default rule lets the knock-bar popup fire at all. Until SP-3 passes, only the host tool notice is relied on. Constraints from Synapse for a bot variant: a bot message must not be `m.notice`, which the default rule `.m.rule.suppress_notices` silences (`rust/src/push/base_rules.rs:86-98`); with `events_default` 50 the sender needs power level 50 or more; in an encrypted room such a message is plaintext to the server; siwx-oidc cannot send it, because it never sees Matrix events. | plan: host tool, installed push rule; bot only as an operator option |
| GP-SYN-21 | Re-knock cap. A marked user may knock on one room at most 3 times in any 10 minutes (01 GP-FLOW-33; a knock after a deny, a kick or a cancel counts like the first). `check_event_allowed` refuses the `m.room.member` knock event of a marked user once 3 knocks that the module allowed for that user and room lie within the last 10 minutes. Refused knocks are not counted, so the window frees itself. The counter is module-private state (user id, room id and a timestamp, through `ModuleApi.run_db_interaction`, the pattern of the canonical name row of the mechanism below), read and written in one transaction so that two concurrent knocks cannot both pass. An unreadable counter refuses the knock: an exception in the callback stops the event (`third_party_event_rules_callbacks.py:303-306`). Rows older than the window are pruned on each write, and a user's rows are deleted in `on_user_deactivation_status_changed` (they name the guest's MXID). A `leave` never reads the counter (GP-SYN-17). A banned guest is refused by event authorisation, not by this rule (`synapse/event_auth.py:801-819`). The module answers with a plain refusal (`M_FORBIDDEN`), so the wait line of the lobby is computed by the client from the knocks it sent. Why: Synapse limits a knock only by `rc_message` (section 4, row "knock"), so a denied guest could otherwise knock as fast as that limiter allows; the client mirrors the cap, and a modified client skips a cap that lives only there. | `check_event_allowed` |

Each rule is a predicate over arguments the callback already receives, plus one cached `get_userinfo_by_id` read
and, for the flag and the admission re-audit, the room state that `check_event_allowed` passes in.

#### Canonical name and profile confinement (GP-SYN-08)

Why a canonical source is needed. No hook vetoes a profile change (C11). `enable_set_displayname` is global and binds only
when a name already exists (C10). A rename through the client API before the first knock creates no event, because the
guest is in no room, so `check_event_allowed` never sees it, yet the knock event carries the new name
(`synapse/handlers/room_member.py:113-118,849-866`). Without a canonical source every name rule applied at redeem is bypassed.

Mechanism M1 (to be proven by spike SY-1):

1. siwx-oidc writes the marker (GP-SYN-07), then writes the canonical name in a separate admin request, `PUT
   /_synapse/admin/v2/users/{id}` `{"displayname": "<canonical>"}` (`by_admin=True`, `users.py:372-379`) or `provision_user`
   with `set_displayname` for the now existing user (`by_admin=True`, `mas/users.py:173-180`). Two requests, because inside
   one admin request the profile is written before `user_type` (`users.py:372-379` against `:470-471`).
2. The module's `on_profile_update` stores `new_profile.display_name` as canonical when the user is marked, `by_admin` is
   true and `deactivation` is false. Storage is a module-private table through `ModuleApi.run_db_interaction`
   (`synapse/module_api/__init__.py:1052-1076`). No write channel into Synapse is added: the admin API is the channel and
   only admins reach it.
3. For a marked user with `by_admin=False` whose new name differs from the canonical one, the module reverts the global
   name with `ModuleApi.set_displayname` (`module_api/__init__.py:2018-2064`). That call writes as admin, so the callback
   fires again with the canonical value, which the module treats as a no-op. An operator's later admin write redefines the
   canonical name, by design.
4. `check_event_allowed` rewrites every member event of a marked user to the allow-listed content of GP-SYN-08 (`membership`
   and the canonical name, no avatar, no `reason`), so the room never shows another name, including during the moment between
   a rename and its revert (`message.py:1437-1451`).
5. A marked user with no canonical row is refused every event except `leave` until an admin write restores it. siwx-oidc
   repeats marker and canonical-name writes at every guest sign-in, so a lost row heals.
6. Guards. Never revert when `deactivation` is true: erase calls `on_profile_update` with empty values and
   `deactivation=True` (`synapse/handlers/profile.py:464-469`), and a revert would write a name back onto an erased account.
   Delete the canonical row in `on_user_deactivation_status_changed` (`synapse/handlers/deactivate_account.py:229`),
   because the row holds the guest's name. Never require the row to allow a `leave`.
7. Limits. The Module API has a display name setter and no avatar setter (`module_api/__init__.py:2018`; the only other
   `avatar_url` in that file is the `create_room` docstring, `:1966`). A marked user's global avatar change therefore
   cannot be reverted. The module removes `avatar_url` from every member event instead, so the room never shows it and
   only a profile lookup by MXID can.

Fallbacks if SY-1 fails, in order, chosen by deployment:

- F-0, if the revert of step 3 proves unreliable but the canonical row and the rewrite of steps 1, 2 and 4 work: the
  room-visible name and avatar stay forced by replacement events, the global profile may diverge until it is repaired, and
  the module logs each divergence for the operator (04 GP-SEC-20).
- F-a, for a homeserver that serves the guest portal alone: set `enable_set_displayname: false`,
  `allow_per_room_profiles: false` and `enable_set_avatar_url: false`, and seed a neutral non-empty avatar at mint because
  the avatar guard binds only when one exists. Admin writes still pass (`handlers/profile.py:247,372`). The knobs are
  global and stop every ordinary user from changing a profile, so they do not fit a shared homeserver. The module then
  needs no canonical row.
- F-b, for a shared homeserver: no name enforcement after mint. The Matrix-visible seed is neutral (`Guest` plus a short
  code shown to both sides) and the typed name reaches the host only through the host API of 01. Containment is human
  admission: the host compares the knocker's Matrix display name and code with what the IdP lists for that invite. The
  residual is a guest showing a name other than the seed, inside the waiting room, until the host decides. If not even
  the room-visible value can be forced, name confinement is unenforceable and v1 must not claim it; the deployment
  documentation must say so.

### 3.5 Global Synapse configuration

| Key | Value | Why | Source |
|---|---|---|---|
| `matrix_authentication_service` | as in `docs/matrix-integration.md` | delegated auth | existing |
| `user_types.extra_user_types` | `["io.inblock.guest"]` | allowed marker value | `synapse/config/user_types.py:30,34` |
| `modules` | the guest policy module (P4) | GP-SYN-04 to 06, 08, 11, 13, 14, 17 to 19, 21 | [3.4](#34-rules-of-the-guest-policy-module) |
| `auto_join_rooms` | empty (default) | GP-SYN-03. A provisioned user is joined at creation, before the marker exists, and a knock room is entered through an invite | `register.py:378-396,560-576` |
| `max_event_delay_duration` | set, at least as large as the delay Element Call asks for | without it the delayed leave returns 403 | `synapse/config/server.py:969-999` |
| `rc_joins_per_room` | raise above 1/s burst 10 for event-sized calls | a burst of joins into ONE room hits this limiter | `ratelimiting.py:170-174` (I for the counter update site) |
| `federation_domain_whitelist` | `[]` or own domain only, and call rooms created with `m.federate: false` | a remote knock reaches no module hook (GP-SYN-12, P3) | `synapse/config/federation.py:36` |
| `allow_profile_lookup_over_federation` | `false` | smaller lookup surface | `synapse/config/federation.py:57` |
| `user_directory.search_all_users` | `false` (default) | directory shows only users who share a room | `synapse/config/user_directory.py:38-39` |
| `experimental_features.msc4263_limit_key_queries_to_users_who_share_rooms` | `true`, on dev first | stops a guest probing device keys of any MXID (existence oracle) | `synapse/handlers/e2e_keys.py:165-190`, `synapse/config/experimental.py:275`; MSC4263 is open, updated 2025-02-21 |
| `max_upload_size` | as low as the deployment allows | the one global bound on the body that a refused upload leaves on disk (C13, GP-SYN-13) | `synapse/config/repository.py:199`, `synapse/rest/media/upload_resource.py:67-72` |
| reverse proxy on `/_matrix/media/*/upload` and `/_matrix/media/*/create` | a rate limit (10 per minute per address, 04 section 3.1) and a body cap equal to `max_upload_size` | Synapse rate limits `/create` per user (`rc_media_create`, `synapse/rest/media/create_resource.py:55-62`) and applies no rate limit to the upload routes (`synapse/rest/media/upload_resource.py` has no limiter) (GP-SYN-13) | deployment, not a Synapse key |
| `media_upload_limits` | optional per-user quota for ordinary users | a row count checked after the body is stored: it does not bound storage (C13) and is not the guest control | `synapse/config/repository.py:130-170`, `synapse/media/media_repository.py:364-420` |
| `default_room_version` | leave the default: "11" on 1.161, "12" on 1.162.0 and later. Never set "12" on 1.161 | the module and the audit must handle every room version the audit accepts, including 11 and 12 ([section 4](#4-room-model), row "Room versions"), and a v12 room crashes `check_event_allowed` on 1.161 (section 1.2) | `synapse/config/server.py:179,612` |
| `block_non_admin_invites` | do NOT set | breaks knock accept (C5) | `room_member.py:906-912` |
| `enable_set_displayname`, `allow_per_room_profiles`, `enable_set_avatar_url` | leave at their defaults, except under fallback F-a of [3.4](#canonical-name-and-profile-confinement-gp-syn-08) | global, they hit every user; the module mechanism M1 makes them unnecessary | `synapse/config/registration.py:148-149`, `synapse/config/server.py:741` |
| `require_auth_for_profile_requests` and `limit_profile_requests_to_users_who_share_rooms` | leave both unset | only effective as a pair (C4); the shipped verifier and any unauthenticated reader of the public `io.inblock.did` field would break; guest localparts are opaque 16-character strings | `synapse/rest/client/profile.py:76-85`; `siwx-oidc-auth/src/did_assertion.rs:50-53`, `src/resolve.rs` header |
| `enable_room_list_search`, `room_list_publication_rules` | operator choice | a published room is public by definition; the module denies guests publishing | `synapse/config/room_directory.py:35` |

### 3.6 Isolation gaps that remain

| Gap | Evidence | Severity | Mitigation or acceptance |
|---|---|---|---|
| A guest can send to-device messages to any local user, including verification requests | `synapse/handlers/devicemessage.py:224-345`: no shared-room check, only `m.room_key_request` is rate limited | Low: MXIDs are opaque, but a guest can learn one from the call room | Accept, document. No module hook exists. |
| `/keys/query` answers for any MXID | `e2e_keys.py:165-190` | Low to medium (user existence and device names) | MSC4263 flag above |
| Remote knock has no hook | `synapse/handlers/federation.py:880` onward | Low: nuisance from the homeserver's name | No federation for guest deployments (GP-SYN-12) |
| Room summary is open to unauthenticated callers for every knock room: name, topic, avatar, alias, member count | `synapse/handlers/room_summary.py:646-661`, `synapse/rest/client/room.py:1719-1725` | Medium for the "room id is the secret" assumption | Neutral room name, no topic, no avatar (GP-SYN-16). The member count tells whether the host has joined. |
| The knocker receives stripped state: join rules, alias, avatar, encryption, name, create, topic | `synapse/config/api.py:91-101`, `message.py:2103-2112` | Same | Same |
| Display-name impersonation | the guest chooses the name, and can rename through the client API before its first knock (C10, C11) | Medium | canonical name (GP-SYN-08, spike SY-1, fallbacks F-0, F-a and F-b) and Element's own disambiguation |
| A marked user's global avatar change cannot be reverted | the Module API has no avatar setter (C11) | Low: only a profile lookup by MXID shows it, the room never does (GP-SYN-08 rewrites member events) | accept, or fallback F-a |
| Guests can register pushers | `synapse/push/httppusher.py:163` uses the blocklisted client | Low | depends on `ip_range_blacklist` staying set |
| Guests can write custom profile fields | stock Synapse | Low | storage abuse only; erase deletes them (`synapse/handlers/profile.py:425-470`, called from `deactivate_account.py:175`) |
| A guest can upload cross-signing keys once without interactive auth | first-time setup is allowed, a replacement needs the IdP to mark the master key replaceable (`synapse/rest/client/keys.py:529-548`) | Low | the thin client never starts cross-signing (03 GP-CLI-09); no `/account` path is offered to guests |
| A guest cannot add or delete a 3PID, change a password or deactivate itself | the legacy 3PID add answers 404 and the add, delete, password and deactivate servlets are not registered under delegated auth; the 3PID list is still served (`synapse/rest/client/account.py:610-623,914-935`) | None | verified by reading, not run |
| Underscore call-member keys are not owner-checked (a key that starts with `@` is, in every room version) | row 6a | Medium inside a call | GP-SYN-06 (exact key rule) covers guest writes, other participants are trusted |
| A refused media upload leaves an untracked file of up to `max_upload_size`, invisible to `delete_user` and to the admin media APIs | `synapse/media/media_repository.py:349-353,413-418` (C13) | Medium: a confined guest can repeat it at request speed | GP-SYN-13: pre-store refusal by the module, a low global `max_upload_size`, a proxy rate limit (10 per minute per address) and a body cap equal to `max_upload_size` on the upload routes, a periodic sweep of media files with no database row. Residual: the refused body is still received and buffered, and a module that is absent or fails leaves every refused file on disk |
| Writes the module cannot see or veto: typing, read receipts, presence, account data, event reports, server-side key backup versions | none of the callbacks of [3.1](#31-what-the-module-api-can-enforce-per-user) fires for them (I). Presence carries a free-text `status_msg` (`synapse/rest/client/presence.py:112-115`) | Low to medium: the presence text is the one free-text channel left to a guest, and it reaches users who share a room with it | Accept for v1, or set `presence.enabled: false` (`synapse/config/server.py:506-510`) where the deployment does not need presence. Erase removes account data and key backups (`synapse/handlers/deactivate_account.py:196-202`) |
| Account minting is unbounded at Synapse | C8 | High if siwx-oidc has no gate | siwx-oidc rate limit and invite gate, GP-SYN-15 as backstop |

## 4. Room model

| Question | Answer |
|---|---|
| Who creates the call room, and the template (revised, see D7) | A host account, or a host-side service account, through the ordinary client API. siwx-oidc never creates rooms: it audits the room at mint (01 section 4.3; 04 GP-SEC-28) and the module re-audits it at admission (GP-SYN-19). Required: `join_rules: knock` (Synapse accepts a knock from room version 7, `synapse/event_auth.py:801-819`; the stricter room version minimum of the audit is our policy, stated once in 01 section 4.3); `m.room.encryption` present (mandatory, next row); `history_visibility: joined`, never `world_readable`; `guest_access: forbidden`; `creation_content: {"m.federate": false}`; the `io.inblock.guest_room` state event; power levels with `state_default` 50, a restrictive `events_default` (50), `users_default` 0, `invite`, `kick`, `ban` and `redact` at 50 or more, the call-member event types at 0 and `io.inblock.guest_room` at 100 (in room version 12 the creators are not listed in `users`, see the next row); a neutral name, no topic, no avatar (GP-SYN-16). No guest holds the power to write a join rule or any state event beyond its own membership and call-member keys (GP-SYN-06). (Element's own call rooms set the call-member power level, `apps/web/src/createRoom.ts:182-205` in element-web develop.) |
| Room versions | The default room version is 11 on 1.161 and 12 on 1.162.0 and later (section 1.2), so the audit and the module see both. In room version 12 the creator and every `additional_creators` entry of `m.room.create` hold unlimited power (`CREATOR_POWER_LEVEL`, 2**53, `synapse/event_auth.py:1133-1135`, `synapse/events/__init__.py:167-181`), and a power-levels event that lists any of them in `users` is rejected (`synapse/event_auth.py:982-1005`), so the `users` map of a v12 room never shows the host's power. Room ids in v12 are `!` plus a hash with no server part (`msc4291_room_ids_as_hashes`, `rust/src/room_versions.rs:300-308`; Synapse's own comment at `synapse/handlers/room_member.py:1198-1199`). Three consequences, stated once here and used by GP-SYN-19 and by the audit of 01 section 4.3. (1) Power is computed with the room-version rule: a creator and every `additional_creators` entry is maximal, read from `m.room.create`, and never read from `users`. (2) `additional_creators` is empty or a subset of `guest_hosts`: a creator cannot be demoted, so an extra creator would be a permanent co-owner of the call room. (3) A room id is checked by the grammar of 04 GP-SEC-07 (`!` plus opaque characters, an optional `:server` part, a length cap, a character set), never by a pattern that requires a server part, which would refuse every v12 room. The audit and the module are each tested against a v10, a v11 and a v12 room. |
| Why `events_default` is part of the template | Synapse takes the send level of a state event from `events` or else `state_default`, and of a non-state event from `events` or else `events_default` (`synapse/event_auth.py:866-877`). Membership events skip that check (`event_auth.py:415-419`), so a restrictive `events_default` never blocks a knock, join or leave. Element Call's own `createRoom` sets `state_default: 0` and `events_default: 0` (Element Call v0.26.1 `src/utils/matrix.ts:227-260`), which lets any joined guest rewrite the join rule and send messages; the audit refuses such a room. Element Call's call-member type must then be listed in `events` at 0, or a guest cannot join the call. |
| Why the room is encrypted (D7) | lk-jwt checks no membership until P1 lands, and a removed guest keeps an SFU token until P2 lands (section 7). Confidentiality of the call must not rest on SFU admission. With `m.room.encryption` present Element Call uses per-participant media keys and rotates them when someone leaves ([section 5](#5-e2ee-for-a-brand-new-guest-device)); without it the call has no media E2EE. The knocker sees the encryption event in its stripped state (`synapse/config/api.py:91-101`), so the guest client can refuse an unencrypted room (03 GP-CLI-12). GP-E2EE-04. |
| Join rule: knock, invite or public | Knock adds a human gate and is the only control against a leaked link. Invite-only plus a direct invite on link redemption removes the wait and works with no Synapse change, but then a leaked link admits anyone. Public is rejected: the room id leaks through the room summary. Recommendation: knock. |
| What MSC3266 is needed for | Nothing in the API: `/knock` and `/sync` do not call it. It only feeds the preview screen in Element. The endpoint is stable (`/_matrix/client/v1/room_summary/`), always registered, and open to unauthenticated callers for knock rooms (C6, section 3.6). |
| How a just-provisioned user knocks | With its access token, `POST /knock/{roomIdOrAlias}`. It needs no state from Synapse except the room id (and `via` for a remote room, not used). The client gets `rooms.knock.<room>.knock_state` in `/sync` (`synapse/rest/client/sync.py:485-535`). |
| How the host accepts | Invite by a member with invite power. There is no accept shortcut. After the invite the guest joins with `/join`; upstream issue 16307 (auto-join when a knock is accepted, open) means the client must do that itself. The host gets no push for a knock (row 5a' in section 2), so a host-visible notice is part of the design (GP-SYN-20). Element Web's knock bar exists behind `feature_ask_to_join` (row 5a'); upstream tracks knock UX in element-web issues 35197 and 35199 (closed) and 28097 (open, stuck knock requests). |
| `auto_join_rooms` | Keep empty (GP-SYN-03). Auto-join bypasses the knock. |
| `rooms_forbidden_to_guests` | Not a Synapse key. Replaced by confinement (GP-SYN-05). |
| Rate limits that bite | See the table below. |
| History visibility | `joined`, never `world_readable`. A knocker later kicked could read earlier events under `shared` (synapse#13968, open). |

| Limiter | Default per second, burst | Key | Bites for guests |
|---|---|---|---|
| `rc_message` | 0.2, 10 | per user | Every event incl. knock and invite. A host bot inviting more than about 10 guests in a burst drops to one per 5 s. |
| `rc_joins.local` | 0.1, 10 | per user, JOIN only | No, each guest joins once |
| `rc_joins_per_room` | 1, 10 | per room | Yes for event-sized calls: more than about 10 joins into one room in a short window |
| `rc_invites.per_room` | 0.3, 10 | per room | Yes for a host inviting many guests to one room |
| `rc_invites.per_user` | 0.003, 5 | per invitee | Only when the same guest is re-invited more than 5 times |
| `rc_invites.per_issuer` | 0.3, 10 | per inviter | Yes for one bot inviting across rooms |
| knock | none of `rc_joins*` or `rc_invites*` | n/a | A guest can knock repeatedly at `rc_message` pace. Bound it with one knock target per invite (GP-SYN-05) and the re-knock cap of GP-SYN-21 (3 per room in 10 minutes). |
| `rc_registration`, `rc_login.*` | | | Not applicable under delegated auth |

Defaults: `synapse/config/ratelimiting.py:84-215`. Applicability: `room_member.py:637-654`.

## 5. E2EE for a brand-new guest device

Full trace and citations: Element Call v0.26.1 and matrix-js-sdk v43.0.0 (evidence table at the top).

| Question | Answer | Evidence | Status |
|---|---|---|---|
| How call media keys travel | Olm-encrypted to-device `m.call.encryption_keys`, one 16 byte key per sender. The in-room key transport is gone from the pinned SDK. The alternative is the shared key in the URL fragment (`password`), which Element Web never passes. | Element Call `src/e2ee/sharedKeyManagement.ts:106-112`; js-sdk `src/matrixrtc/MatrixRTCSession.ts:626-627`, `src/matrixrtc/RTCEncryptionManager.ts:482-506`; element-web `apps/web/src/models/Call.ts:895-930,973-975` | V |
| New joiner and rotation | A joiner gets the sender's current key only if it is under 10 s old, otherwise a fresh key is rotated to everyone. Keys rotate when someone leaves, unless rotation is suppressed by `keyRotationParticipantLimit`, whose default is unset, meaning never suppressed. | js-sdk `src/matrixrtc/RTCEncryptionManager.ts:36-47,99-105,418-446` | V |
| Are keys sent to unverified devices | Yes. `encryptToDeviceMessages` does no trust filtering. `blacklistUnverifiedDevices` and the isolation modes affect only room (Megolm) keys, and both default to off in Element Web. | js-sdk `src/rust-crypto/rust-crypto.ts:1544-1588`, `src/rust-crypto/RoomEncryptor.ts:273-289`; element-web `apps/web/src/settings/Settings.tsx:1139-1149` | V |
| Guest without cross-signing | Treated as an ordinary unverified user. No shield, no banner, no block. A fresh user cannot cause an identity-changed warning. | element-web `apps/web/src/utils/ShieldUtils.ts:33-80` | V (shield logic), I (UI) |
| Call without Olm | Only the shared link key. Rejected for this design: the link becomes a bearer media secret, no rotation, a host in Element Web cannot join it, no revocation of one guest. | Element Call `src/state/CallViewModel/CallViewModel.ts:1944-1948` | V |
| Silent key loss | Synapse omits devices without uploaded keys from `/keys/query`. The SDK skips an unknown device with a warning, swallows the error, records the joiner as served, and does not retry on a device-list change. A guest who publishes membership before its keys are uploaded stays deaf until the next rotation. | Synapse `synapse/storage/databases/main/end_to_end_keys.py:333-346`; js-sdk `rust-crypto.ts:1581`, `src/matrixrtc/ToDeviceKeyTransport.ts:102-116`, `RTCEncryptionManager.ts:459` | V (code), I (window is small) |
| History for the guest | A new device receives no earlier Megolm sessions. MSC4268 history sharing is not called by Element Web. | js-sdk `rust-crypto.ts:1635-1660` | V (SDK), U (Element X) |
| Element X as host | Encrypted to-device through its widget driver on current builds | not read | U |

| ID | Requirement | Enforcement | Test |
|---|---|---|---|
| GP-E2EE-01 | The guest client completes `initRustCrypto` and the first `/keys/upload` (device keys, one-time keys, fallback key) before it publishes `m.call.member` | guest client | host joined first, guest joins, both directions decrypt within 10 s |
| GP-E2EE-02 | The client uses the device id from the token scope, never its own | siwx-oidc and client | `/keys/query` for the guest returns the id that appears in `m.call.member` |
| GP-E2EE-03 | Recovery: if the host does not see media from the guest, the guest leaves and rejoins (a membership change forces a new rotation) | guest shell | drop the first key message in a harness and assert recovery |
| GP-E2EE-04 (D7) | The call room is encrypted: `m.room.encryption` is present at the mint-time audit and again at admission (GP-SYN-19). An unencrypted room is refused, and the guest client refuses to join one (03 GP-CLI-12). Why: media confidentiality must not rest on SFU admission while P1 and P2 are open | siwx-oidc audit (04 GP-SEC-28), module, guest client | mint into a room without the event: refused; invite a marked user into a flagged room that lacks the event: refused |

Guest client: a real matrix-js-sdk client with rust crypto. The client document recommends a thin client that mounts the
Element Call component, gated by its spike S1 (D10). Standalone Element Call cannot sign in under delegated auth
(03 section 1). A client without crypto cannot obtain per-participant keys. Pin host and guest Element Call to one version
and to `compatibility` mode.

## 6. Erase, deactivate, call cleanup and claim

Entry: `delete_user` runs `deactivate_account(user_id, erase_data=erase)` (`synapse/rest/synapse/mas/users.py:271-310`).

| Item | erase false | erase true | Evidence | Status |
|---|---|---|---|---|
| Messages | not redacted | not redacted. The user is added to `erased_users`: later viewers who were not joined see pruned events, viewers who were joined still see content. The user's own membership events are censored before the leave. | `deactivate_account.py:175-182,310-316`, `synapse/visibility.py:453-477` | V |
| Profile | kept | deleted, including every custom profile field; old names stay in historical state | `deactivate_account.py:172-183`, `synapse/handlers/profile.py:425-470` | V |
| Devices, tokens, device keys, one-time and fallback keys | deleted | deleted | `deactivate_account.py:148-151`, `synapse/storage/databases/main/devices.py:418-451` | V |
| Room memberships | parted and forgotten by a background loop, one room at a time, failures logged and skipped. Invites and knocks rejected first. | same | `deactivate_account.py:162,186,280-331` | V |
| `m.call.member` state | stays, nothing references it | same | grep of `call.member` in `synapse/` finds nothing | V |
| To-device inbox | queued messages for deleted devices removed by a background task | same | `synapse/handlers/device.py:336-354` | V |
| Account data, push rules, pushers, 3pids, key backup | removed | removed | `deactivate_account.py:126-146,158,196,202` | V |
| User directory | removed | removed | `synapse/handlers/user_directory.py:216-220` | V |
| Cross-signing keys, read receipts, uploaded media | not referenced by the handler | same | | I |
| Client IP and user agent (`user_ips`) | written for every authenticated request, pruned after `user_ips_max_age` (default 28 days); the handler does not reference the table | same | `synapse/api/auth/base.py:396-416`, `synapse/config/server.py:683-685` | V (write, default), I (not removed at deactivation) |
| Guest policy module state | the canonical-name row and the knock counters (GP-SYN-21) are module-private and Synapse does not know them | the module deletes them at deactivation | GP-SYN-08 item 6, GP-SYN-21, `deactivate_account.py:229` | V (callback), U (module not written) |
| Localpart | consumed for ever | same | `mas/users.py:155-165` | V |
| Reactivate | restores flags and an EMPTY profile only; no devices, memberships, keys, account data | same | `deactivate_account.py:335-368` | V |

### 6.1 Teardown order and call state (revised, see D2)

Order at Synapse, with the siwx-oidc steps around it owned by 01:

1. siwx-oidc marks the guest record ended under compare-and-set. A record in `provisioning` moves only once the reaper holds
   `guest:lease/<localpart>` (01 GP-FLOW-26): until then the reaper leaves the due entry for the next tick, so it waits at most one
   lease (120 s) after the last fence for a sign-in in flight.
2. siwx-oidc revokes the guest's access and refresh tokens. Introspection then answers `active:false`, which Synapse may
   still serve from its cache for up to 2 minutes (C3).
3. siwx-oidc deletes each Synapse device in the guest record (`POST /_synapse/mas/delete_device`,
   `synapse/rest/synapse/mas/devices.py:80-118`). The next request with any token of that device fails at once, because
   Synapse checks the device row on every request and drops the cached introspection entry
   (`synapse/api/auth/mas.py:397-406`).
4. siwx-oidc calls `delete_user` with erase. That deletes any remaining device, parts and forgets every room, and clears the
   profile (`deactivate_account.py:148-151,172-183,280-331`). For a record that was `provisioning` the call is never skipped: the
   account may exist, so there is no `query_user` shortcut (01 GP-FLOW-18).
5. siwx-oidc destroys the custodial key material and the personal fields of the guest record.

The parting loop creates the `leave` events as the user, so the module sees them: it must allow them (GP-SYN-05) and must
not need its own storage for them (GP-SYN-17).

Call state in v1: there is no active cleanup. The residue is a stale `m.call.member` entry of a deactivated user, which
nothing can clear afterwards (C1). Why it is cosmetic: the js-sdk drops a call membership whose user is not joined to the room
(`isValidMembership` ignores it, logging "Ignoring membership of user ... who is not in the room",
`src/matrixrtc/MatrixRTCSession.ts:1020,1052-1074`), and Element Call builds its participant list from that session's
membership list (Element Call v0.26.1 `src/state/SessionBehaviors.ts:88`, `src/state/CallViewModel/CallViewModel.ts:553`). A guest
removed by a kick or by the parting loop of deactivation is no longer joined; the session recomputes its list on every room
member update (`MatrixRTCSession.ts:546,871`), so the entry leaves the list, the leaver is detected (`anyLeft`) and the remaining clients rotate their media key (`src/matrixrtc/RTCEncryptionManager.ts:399-431`), unless
rotation is suppressed by `keyRotationParticipantLimit`, which is unset by default. The stale entry stays in room state, but it
neither shows a participant nor blocks the rotation. The rotation follows the parting, which is asynchronous
(`deactivate_account.py:280-331`); until it happens the guest still counts as joined, and the order of GP-SYN-09 (device
deleted first) already stops the guest from receiving any new key message. This is cosmetic, it is accepted for v1, and the
mitigation named in the plan is host-side: the host view shows a guest as left as soon as the IdP record is ended. The claim
rests on reading the SDK, so spike SY-3 tests it (host kicks a guest mid-call, and deactivation mid-call: the remaining client
rotates its key).

| Option | Verdict |
|---|---|
| Rely on delayed events | Unreliable (C2). Keep for ordinary disconnects. |
| Active cleanup as the guest before `delete_user`: mint a short-lived token for the guest's device, `PUT` an empty call-member event at the guest's own key, `leave` | Not in v1 (D2). It makes the reaper act as a chosen user, a new privileged primitive, for a cosmetic gain. A recorded v1.1 option. If added: only device ids in the guest record, token lifetime at most 60 s, only in state `reaping`, one audit event, never blocking the erase. |
| A host or bot overwrites the guest's key afterwards | Works in room versions with no owner rule, needs a member with power. A v1.1 sweeper option. |
| Synapse admin API writes state as the guest | None found (U). |

**GP-SYN-09 (revised, see D2)** Teardown order at Synapse: revoke the siwx-oidc tokens, delete each device of the guest,
then `delete_user` with erase. The deleted device, not introspection alone, is the revocation point, and only for a token that
names a device: Synapse reads the device row only `if device_id is not None` and never reads `is_deactivated`
(`synapse/api/auth/mas.py:385-406`), so a deviceless token survives device deletion until introspection turns inactive.
siwx-oidc therefore asserts at mint, at the code exchange and at every refresh of a guest record, that the token carries the
`urn:matrix:client:device:<id>` scope of a device in the guest record, and issues no token otherwise. No call-state cleanup
in v1. After teardown on dev, assert that every old token is refused at once, the account has no device and no joined
room (upstream issue 19603 reports rejoining after erase through the admin API, open, not reproduced by us).

### 6.2 What a claim must not undo

**GP-SYN-10 (revised, see D3)** A claim completes before teardown, and the teardown decision reads a durable claimed flag
immediately before `delete_user`. The claim writes nothing to Synapse, and the marker stays: a claimed guest is a permanent
but confined identity that loses its deadline and its eligibility for the reaper (05 GP-CLM-08).

| Dependency | Why |
|---|---|
| Account not deactivated or erased at claim time | Reactivation restores almost nothing (table above) |
| Claimed flag set atomically with the link | A failed claim must not lead to erase |
| Marker kept (`user_type` unchanged) | Confinement is a property of the identity, not of its age. Promotion is a separate operator act, never inferred from key type |
| `locked` never touched | This design never sets it, so there is nothing to undo; a claimed guest stays hidden from the directory (GP-SYN-11) |
| Localpart, MXID, DID unchanged | No rename exists; consistent with the binding rule |
| Display name and canonical-name row kept | `unset_displayname` would wipe what the host knows, and the module keeps enforcing the canonical name |
| E-mail | Re-bind with `set_emails` only after verification |
| Devices kept at Synapse | Never call `sync_devices` with a reduced set. Tokens of the pre-claim devices are handled per device by siwx-oidc (04 GP-SEC-36, 05), never with `revoke_all_user_tokens`: it plants the 900 s user tombstone that the refresh path reads as "deactivated" (`src/db/redis.rs:281-285,306-309`, `src/oidc.rs:976-988`) and would lock the claimant out |
| Room membership | A claimed guest stays in the call room unless an operator parts them, and stays confined to flagged rooms |

## 7. lk-jwt-service prerequisite

| Route (v0.7.0) | Membership check | Publish grant | Creates SFU room | Evidence |
|---|---|---|---|---|
| `POST /get_token` and legacy `POST /sfu/get` | none | yes for homeservers in `LIVEKIT_FULL_ACCESS_HOMESERVERS` | yes | `src/handler.rs:831,852,870,905,928,946` |
| `POST /delegate_delayed_leave` | none | none | no | `handler.rs:1180-1185` |
| appservice-only C-S `get_token` and S-S route | yes (`is_user_joined`) | yes (C-S), never (S-S) | yes | `handler.rs:1014-1052,1107-1158` |

Facts: `is_user_joined` is called in exactly two places (`handler.rs:1016,1121`), and the two OpenID routes stay registered
in appservice mode without a check (`:1268-1280`). The LiveKit room name is a hash of the Matrix room id and a slot, not
secret (`helper.rs:209-222`). Join tokens live one hour (`handler.rs:70`). Element Call v0.26.1 calls `/get_token` and
falls back to `/sfu/get` (`src/livekit/openIDSFU.ts:214,297`) and never the checked route.

| Fallback | Closes the gap | Verdict |
|---|---|---|
| Small lk-jwt patch that calls `is_user_joined` inside the three OpenID handlers (`handler.rs:827,901,1176`), together with the binding rule of GP-SYN-01 | yes | Recommended. Needs appservice config and the Synapse scope, not MSC4512. Without the binding rule the check can be bypassed. |
| Edge rule | no: the decision needs the JSON body and the OpenID `sub` | Path policy only |
| LiveKit `room.auto_create: false` | no: lk-jwt creates rooms itself with its own grant (`helper.rs:388`) | Mandatory hygiene, not the control |
| Restrict `LIVEKIT_FULL_ACCESS_HOMESERVERS` | no: matched per server name, guests and hosts share it | Hygiene: exactly our server name, never `*` |
| Appservice mode alone | no for Element Call v0.26.1 | Prerequisite of the patch |

**GP-SYN-01 (hard dependency, P1; revised, see D11).** Before any guest account exists, on dev too, every lk-jwt route that can mint a publish token or
create an SFU room for a local user verifies that the caller is currently joined to the requested room. Concretely:

1. Synapse: `experimental_features.msc4502_enabled: true` (`synapse/config/experimental.py:207`) and an appservice
   registration with `io.element.msc4502.scopes: ["urn:matrix:client:io.element.msc4502:rooms:is_joined"]`
   (`synapse/config/appservice.py:225-230`, `synapse/appservice/__init__.py:66-71`). The lk-jwt README example uses other key
   names that 1.161 does not read, so test the registration on dev.
2. lk-jwt: `LIVEKIT_AS_TOKEN`, `LIVEKIT_HS_TOKEN`, `LIVEKIT_HS_SERVER_NAME` (or the registration file).
3. Either the patch above, or an Element Call build that requests tokens through the client-server route together with
   an edge block of `/get_token` and `/sfu/get`.
4. Hygiene: `room.auto_create: false`, LiveKit API and Twirp endpoints not public.
5. Binding rule (part of the patch, not optional). With the membership check on, the patched handlers refuse a request unless
   the request's `openid_token.matrix_server_name` equals the configured homeserver name (`LIVEKIT_HS_SERVER_NAME`) and the
   `sub` that the userinfo call returns is a Matrix user id whose server part (after the first colon) equals that name. The
   name is checked before any outbound request. Why: lk-jwt takes the subject from whichever server the request names.
   `exchange_openid_userinfo` resolves `token.matrix_server_name` and returns `user_info.sub` (`src/helper.rs:610-642`),
   `verify_openid_token` compares that `sub` only with the caller's own claimed user id (`src/handler.rs:674-698`), and
   `is_full_access_user` reads the same request-supplied name (`src/handler.rs:661-672`). A caller who names a server it
   controls can answer `{"sub":"@<a joined host>:<our name>"}`, pass the membership check for that host and receive a token
   (subscribe-only, because the named server is not full-access, so this is not a content loss while the room is encrypted)
   under the host's LiveKit identity, which can displace the real participant (LiveKit side: Unverified). The same request
   also makes lk-jwt send a server-side request, with the caller's access token in the query string, to any server name the
   caller supplies: a server-side request forgery. Both defects exist in stock v0.7.0 independent of guests, so report them
   upstream through the project's private security reporting route (open decision 16). The rule also refuses federated
   participants, which a guest deployment does not have (P3).
   Test, with a fake userinfo server that the test names in `matrix_server_name`: it answers with a joined host's user id and
   must receive no request at all, and the call is refused; a request that names the configured homeserver but whose `sub`
   carries another server part is refused; a joined member of the configured homeserver still receives a token.

Maturity: MSC4502 and MSC4512 are both open, `needs-implementation`, not in FCP, last activity 2026-09-18
(https://github.com/matrix-org/matrix-spec-proposals/pull/4502, `.../4512`). Synapse has them only behind
`experimental_features`. `is_joined` tests current `join` membership only, so knock then accept then join is correctly
gated. Risk under delegated auth: appservice tokens still authenticate through the normal path (`mas.py`), but no
deployment evidence for this combination was found (U). Pin Synapse, lk-jwt and Element Call versions, and retest on each
upgrade.

Residual gap after the dependency is met, which the design must state: the check gates token issue only. A deactivated guest
stays on the SFU until it disconnects and can reconnect with the old token for up to one hour, because v0.7.0 never kicks
anyone when membership ends and OSS LiveKit has no revocation. See lk-jwt PR 235 and LiveKit PR 4344 below. The window is
accepted on dev. P2 (SFU eviction and a short SFU token lifetime) closes it before production. Teardown does not
try to close it (D2), and the OpenID token issued by Synapse stays valid for its own hour after `delete_user`
(`synapse/rest/client/openid.py:72`, `synapse/storage/databases/main/openid.py:41-56`).

## 8. Open upstream topics

Impact: BLOCKER (cannot ship without it), RISK (design must mitigate), WATCH (could change the design), NONE.

| Link | Title | Status | Last activity | Impact | Workaround |
|---|---|---|---|---|---|
| this document, section 7 | lk-jwt OpenID routes mint publish tokens with no membership check | n/a (v0.7.0 source) | 2026-09-30 | BLOCKER | patch plus appservice mode |
| [spec PR 4502](https://github.com/matrix-org/matrix-spec-proposals/pull/4502) | MSC4502 targeted room member queries | open, needs-implementation | 2026-09-18 | BLOCKER (the dependency is experimental and may change shape) | pin versions, unstable names, retest |
| [spec PR 4512](https://github.com/matrix-org/matrix-spec-proposals/pull/4512) | MSC4512 delegating C-S and S-S parts to appservices | open, needs-implementation | 2026-09-18 | RISK (needed only for the client-server token route) | skip it if the lk-jwt patch is taken |
| [Synapse PR 20241](https://github.com/element-hq/synapse/pull/20241) | Reject user creation via the admin API when delegating to MAS | merged 2026-09-28, not in 1.162.0 | 2026-09-28 | RISK for any admin-API creation, NONE for `provision_user` | create with `provision_user`, modify with the admin API |
| [Synapse issue 19721](https://github.com/element-hq/synapse/issues/19721) | `delete_user` always deactivates as a self-deactivation | open | 2026-09-03 | RISK | the module must not branch on `by_admin` in deactivation callbacks. `on_profile_update` (GP-SYN-08) reads `by_admin` only for profile writes, where admin writes carry true, and skips `deactivation=True` |
| [Synapse issue 19603](https://github.com/element-hq/synapse/issues/19603) | Deactivation with erase through the admin API rejoins rooms afterwards | open | 2026-04-02 | RISK (reported on 1.149.1, same handler) | assert no joined rooms after teardown on dev |
| [Synapse PR 19980](https://github.com/element-hq/synapse/pull/19980) | Add allow- and deny-list of custom profile fields | open | 2026-09-11 | NONE (the profile-field marker was dropped, D1) | `user_type` is the marker |
| [Synapse issue 20014](https://github.com/element-hq/synapse/issues/20014) | Retention for deactivated users | open | 2026-07-30 | WATCH (erased accounts and localparts persist) | plan for accumulation |
| [Synapse issue 13968](https://github.com/element-hq/synapse/issues/13968) | Kicked knocker can read earlier events under `shared` history | open | 2025-01-17 | RISK | `history_visibility: joined` |
| [Synapse issue 16307](https://github.com/element-hq/synapse/issues/16307) | Auto-join when a knock is accepted | open | 2025-01-17 | WATCH | client joins after the invite |
| this document, section 2 | Knock is not covered by `rc_joins`, `rc_invites` or any module callback | n/a | 2026-09-30 | RISK | invite gate in siwx-oidc, GP-SYN-05 |
| [Synapse issue 16002](https://github.com/element-hq/synapse/issues/16002) | `rc_joins` rate limits do not function | open | 2023-12-22 | WATCH (2023 report, not reproduced) | not the only abuse control |
| [Synapse issue 8309](https://github.com/element-hq/synapse/issues/8309) | Empty room created because of the join ratelimit | open | 2026-04-16 | WATCH | generous `rc_joins` on the call path |
| [Synapse issue 17801](https://github.com/element-hq/synapse/issues/17801) | Ignore `users_in_public_rooms` in directory search | open | 2026-02-27 | WATCH | guest in no public room, module hides guests |
| [Synapse issue 20254](https://github.com/element-hq/synapse/issues/20254) | Epic: MSC4140 cancellable delayed events | open | 2026-09-25 | WATCH | needs `max_event_delay_duration` |
| [Synapse issue 18021](https://github.com/element-hq/synapse/issues/18021) | Delayed-event rate-limit failures drop the event | open | 2025-11-21 | RISK (a dropped leave leaves a ghost participant) | lk-jwt delegated leave and SFU webhook as a second path |
| [Synapse PR 20257](https://github.com/element-hq/synapse/pull/20257) | MSC4140: authenticate delayed-event management endpoints | open | 2026-09-24 | RISK (in 1.161 `cancel`, `restart` and `send` take no access token, the delay id is the only capability, row 6b of section 2; lk-jwt's unauthenticated restart and send will fail once they are authenticated) | appservice mode, needed anyway |
| [lk-jwt PR 240](https://github.com/element-hq/lk-jwt-service/pull/240) | Authenticate delegated delayed leave calls | open | 2026-09-24 | RISK | same |
| [lk-jwt PR 235](https://github.com/element-hq/lk-jwt-service/pull/235) | Periodic membership check and kick from the SFU | open | 2026-09-16 | WATCH (closes the teardown gap) | one-hour token expiry |
| [lk-jwt PR 241](https://github.com/element-hq/lk-jwt-service/pull/241) | Use `member_id` on C-S and S-S endpoints | merged | 2026-09-30 | WATCH (API moving after v0.7.0) | pin a release or commit |
| [lk-jwt issue 112](https://github.com/element-hq/lk-jwt-service/issues/112) | Make `CreateRoomRequest` configurable | open | 2025-07-28 | RISK (room size unlimited, `helper.rs:669`) | invite gate, small membership |
| [lk-jwt issue 238](https://github.com/element-hq/lk-jwt-service/issues/238) | Federated user cannot unmute outside the full-access list | closed | 2026-09-18 | NONE (confirms restricted means subscribe only) | |
| [LiveKit PR 4344](https://github.com/livekit/livekit/pull/4344) | Token revocation list | open | 2026-09-30 | WATCH (immediate revocation at teardown) | one-hour token |
| [spec PR 4195](https://github.com/matrix-org/matrix-spec-proposals/pull/4195) | MSC4195 LiveKit transport | open, FCP proposed, unresolved concerns | 2026-09-30 | WATCH (route names unstable; text requires a joined check and short tokens) | |
| [spec PR 4143](https://github.com/matrix-org/matrix-spec-proposals/pull/4143) | MSC4143 MatrixRTC | open, FCP proposed | 2026-09-30 | WATCH | |
| [spec PR 4354](https://github.com/matrix-org/matrix-spec-proposals/pull/4354) | MSC4354 sticky events | open, FCP proposed | 2026-09-29 | WATCH (changes how call membership persists) | re-evaluate teardown |
| [spec PR 4263](https://github.com/matrix-org/matrix-spec-proposals/pull/4263) | MSC4263 preventing MXID enumeration via key queries | open, needs-implementation | 2025-02-21 | WATCH (Synapse flag is experimental) | dev first |
| [spec PR 4268](https://github.com/matrix-org/matrix-spec-proposals/pull/4268) | MSC4268 sharing room keys for past messages | merged | 2026-06-24 | WATCH (a host client that shares history could expose earlier messages) | dedicated call room |
| [spec PR 3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861) | MSC3861 delegated auth | merged | 2026-05-19 | NONE (Synapse 1.157 removed `experimental_features.msc3861`) | stable `matrix_authentication_service` block |
| [MAS issue 1445](https://github.com/element-hq/matrix-authentication-service/issues/1445) | Guest access mode | open | 2026-08-06 | WATCH (no upstream guest mode, no commitment) | restricted normal accounts |
| [MAS PR 6003](https://github.com/element-hq/matrix-authentication-service/pull/6003) | Invite guests via e-mail | open, draft | 2026-09-28 | WATCH (MAS only) | concept only |
| [MAS PR 5971](https://github.com/element-hq/matrix-authentication-service/pull/5971) | Very experimental invite links | open, draft | 2026-09-25 | WATCH (MAS only) | concept only |
| [Element Call issue 4055](https://github.com/element-hq/element-call/issues/4055) | Invite guest to a call | open | 2026-06-29 | WATCH | this design |
| [Element Call issue 940](https://github.com/element-hq/element-call/issues/940) | Invite guests with registration disabled | open | 2025-10-25 | WATCH | this design |
| [Element Call issue 4220](https://github.com/element-hq/element-call/issues/4220) | Waiting room | open | 2026-09-21 | WATCH (overlaps knock) | knock on the Matrix room |
| [Element Call PR 3471](https://github.com/element-hq/element-call/pull/3471) | OAuth login for the Element Call SPA | closed, not merged | 2026-08-04 | RISK (standalone Element Call has no OIDC login upstream) | Element Web or a thin client as the guest surface |
| [Element Call issue 4127](https://github.com/element-hq/element-call/issues/4127) | Media undecryptable, "No targets found for sending key" | open | 2026-09-11 | WATCH (related to silent key loss, cause unverified) | GP-E2EE-01 to 03 |
| [Element Web issue 35200](https://github.com/element-hq/element-web/issues/35200) | E-mail invitation for guest (and 35201, settings for guests) | open | 2026-09-28 | WATCH (upstream guest UX, refers to the restricted-guests module) | track |
| [Element Web issues 35197, 35199](https://github.com/element-hq/element-web/issues/35197) | Knock screen and room-list UX for knockable rooms | closed | 2026-09-30 | WATCH | track |
| [Element Web PR 34729](https://github.com/element-hq/element-web/pull/34729) | Note that restricted guests requires knocking | open | 2026-08-19 | WATCH (the module assumes knock admission, as we do) | |
| [Element Web issue 28097](https://github.com/element-hq/element-web/issues/28097) | Incorrect room state, stuck knock requests | open | 2024-09-30 | RISK (title only read) | verify on dev |
| [element-modules restricted-guests](https://github.com/element-hq/element-modules/tree/main/modules/restricted-guests) | module v1.0.3, active | released | 2026-09-02 | WATCH | see 3.2 |

"Element Meet": searched 2026-09-30 in GitHub repositories (direct lookups of `element-hq/element-meet` and
`element-hq/meet` returned 404), code and issue search across `element-hq`, the element.io home page and two web
searches. No product, repository or document of that name was found (absence in these sources only). What exists upstream
to reuse: Element Web (knock UI), Element Call embedded and standalone, lk-jwt-service, LiveKit, the restricted-guests
module. Whether an unreleased product of that name exists: U.

### 8.1 Upstream watchlist: what would let us delete a piece

| Upstream change | What it removes or relaxes |
|---|---|
| Element Call requests tokens through the client-server route (the js-sdk method exists, Element Call v0.26.1 does not call it) | the lk-jwt patch |
| MSC4502 and MSC4512 stabilise | unstable key names and experimental flags |
| lk-jwt PR 235 merged and deployed | the "guest stays on the SFU after teardown" gap, down to one poll interval |
| LiveKit PR 4344 adopted by lk-jwt | the one-hour wait after teardown |
| Synapse issue 19721 fixed | the rule that the module must not branch on `by_admin` in deactivation callbacks |
| A Synapse callback for knock | the knock confinement through `check_event_allowed` and the no-federation rule |
| Synapse enforces `locked` and deactivation in `mas.py` | the dependence on device deletion as the revocation point |
| MAS guest mode (issue 1445) | nothing while siwx-oidc is the IdP; concept only |
| Element Web guest UX issues 35197 to 35201 shipped | part of the thin client we would build |
| MSC4354 sticky events in Synapse | the stale call-member handling and the teardown order |

## 9. Requirements register

The full text of each rule is stated once, in the place named in the second column. The register adds the rationale, the
enforcement point and the test, and it is the only place where the test of a rule is written. GP-SYN-12 and GP-SYN-16 have
no other home: their rule text is stated here.

| ID | Rule (title, and where its text is) | Rationale | Enforcement point | Test |
|---|---|---|---|---|
| GP-SYN-01 (revised, see D11) | lk-jwt membership check, bound to the configured homeserver name, before any guest exists, on dev too (P1). Text: [section 7](#7-lk-jwt-service-prerequisite) | any local account can publish into any room it knows; without the binding rule the check can be bypassed through a caller-named server | lk-jwt patch plus appservice mode | non-member `/get_token` returns 403; member returns a token; a fake userinfo server named in `matrix_server_name` receives no request and the call is refused; a `sub` with another server part is refused |
| GP-SYN-02 (revised, see D1) | A guest policy module is loaded (P4), keyed on the marker. Text: [1.4](#14-hard-dependencies-inside-the-deployment) | Synapse has no per-user restriction | Synapse `modules` | create room, invite, knock elsewhere all refused for a marked user; an unmarked user is unaffected |
| GP-SYN-03 | `auto_join_rooms` empty. Text: [1.4](#14-hard-dependencies-inside-the-deployment) | auto-join fires at creation, before the marker, and bypasses knock | deployment check | not a siwx-oidc test, because siwx-oidc never reads the Synapse configuration: the deployment check of M10 (04 GP-SEC-30, the posture script) against the target homeserver, and the dev-stack smoke run |
| GP-SYN-04 | Guests cannot create rooms, aliases, publications or invites; a guest is invited only into a guest room, enforced in `check_event_allowed` first. Text: [3.4](#34-rules-of-the-guest-policy-module) | minimal capability; `user_may_invite` is skipped for server admins, so it cannot be the only layer | module (`check_event_allowed`, `user_may_invite`) | refusal codes on each call; an invite of a marked user by a server admin into an unflagged room is refused |
| GP-SYN-05 | Confinement to rooms with `io.inblock.guest_room`; `leave` always allowed. Text: [3.4](#34-rules-of-the-guest-policy-module) | knock has no other hook; deactivation needs `leave` | module (`check_event_allowed`, `user_may_join_room`) | knock on a knock room without the flag is refused; leave is allowed |
| GP-SYN-06 | Guest state writes limited to its own member event and the one call-member key built from its own MXID and a device id, compared exactly. Text: [3.4](#34-rules-of-the-guest-policy-module) | no key-ownership check for underscore keys in stable room versions; a substring rule passes a key that embeds another user's id | module | guest overwrites another participant's call-member key: refused. Negative vectors: a foreign key `_@host:example.org_DEV_m.call`, a key that embeds a second user id after the own prefix, a key without the leading underscore, a key with a suffix after `_m.call`: all refused. The own key: accepted |
| GP-SYN-07 (revised, see D1, D3) | Marker `user_type = io.inblock.guest`, the only marker, written between `provision_user` and `upsert_device`, never cleared by a claim, mint fails closed. Text: [3.3](#33-the-guest-marker) | server-side, not user-writable, one marker that cannot disagree with another | siwx-oidc (writes), module (reads) | guest token cannot change it; a claim leaves it; a failed write leaves no token and no device |
| GP-SYN-08 (revised, see D8) | Name, profile and content confinement: canonical name fixed by an admin write at mint; every member event of a marked user keeps only `membership` and the canonical `displayname`; own global changes reverted. Text: [3.4](#34-rules-of-the-guest-policy-module) | impersonation, bypass of the redeem-time name rules, free text through `reason` and custom keys | module, siwx-oidc (writes) | rename before the first knock, after admission and per room, copy the host's avatar: room-visible values stay canonical; erase is not undone. A knock with a `reason` and extra keys (one large), a state PUT of the own member event with extra keys, a host invite with a `reason`: the stored event holds none of them. A `leave` stores `membership` only |
| GP-SYN-09 (revised, see D2) | Teardown at Synapse: revoke tokens, delete each guest device, `delete_user` with erase; every guest token carries a device scope; no call-state cleanup in v1. Text: [6.1](#61-teardown-order-and-call-state-revised-see-d2) | delayed leave and introspection are unreliable; active cleanup is a privileged primitive for a cosmetic gain; the device row is checked only for a token that names a device | siwx-oidc | after teardown no joined rooms, no device, every old token refused at once; a guest token without a device scope is not issued at the code exchange or at a refresh; spike SY-3 variants for a deviceless token and for a forced removal mid-call |
| GP-SYN-10 (revised, see D3) | Claim completes before teardown; durable claimed flag read before `delete_user`; the claim writes nothing to Synapse and the marker stays. Text: [6.2](#62-what-a-claim-must-not-undo) | reactivation restores almost nothing; confinement is not age | siwx-oidc | failed claim does not erase; after a claim the module still refuses room creation |
| GP-SYN-11 | Guests hidden from and given an empty user directory. Text: [3.4](#34-rules-of-the-guest-policy-module) | enumeration | module | directory search as a guest and as a host |
| GP-SYN-12 (revised, see D11) | No federation for guest deployments, call rooms created with `m.federate: false` (P3). Stated here only | a remote knock reaches no hook | Synapse config, room creation | knock on a remote room fails |
| GP-SYN-13 | A marked user's upload is refused before the body is stored; the storage controls are deployment controls (low global `max_upload_size`, proxy rate limit of 10 per minute per address and body cap, sweep of files with no row). Text: [3.4](#34-rules-of-the-guest-policy-module) | a per-user limit is checked after the body is stored and bounds no storage | module, proxy, deployment | guest upload refused and no new file appears in the media store; with the module removed, a refused upload leaves a file, the sweep finds it, and the proxy cap and rate limit hold |
| GP-SYN-14 (revised, see D5) | Only listed hosts may set `io.inblock.guest_room`; the module list contains `guest_hosts`. Text: [3.4](#34-rules-of-the-guest-policy-module) | any room admin could open any room to guests | module | non-listed admin attempt refused |
| GP-SYN-15 | Account creation bounded in siwx-oidc, optional Synapse backstop. Text: [3.4](#34-rules-of-the-guest-policy-module) | Synapse has no limit on provisioning | siwx-oidc, module | burst of redemptions stops at the limit |
| GP-SYN-16 | Call room has a neutral name, no topic, no avatar. Stated here only | unauthenticated room summary and knock state leak them | room creation | summary call without a token shows nothing revealing |
| GP-SYN-17 (D1) | Module scope: deny by default for marked users, no effect on unmarked ones; `leave` always allowed and never dependent on module storage. Text: [3.4](#34-rules-of-the-guest-policy-module) | a marker cannot be missing except after a failed mint; normal accounts must not pay for guests | module, every callback | unmarked user: every callback returns allow; marked user: an unlisted action is refused |
| GP-SYN-18 | Marked users send no non-state events except own membership and own call-member state, and their member events carry no free text. Text: [3.4](#34-rules-of-the-guest-policy-module) | no message residue, no chat abuse, no spam inside the call | module (`check_event_allowed`) | message, encrypted event, reaction and redaction refused; a member event with a `reason` is stored without it; a full call still connects |
| GP-SYN-19 | Invites of marked users are re-audited against the room template in `check_event_allowed`, with no admin bypass. Text: [3.4](#34-rules-of-the-guest-policy-module) | the mint-time audit can be stale at admission, and the likeliest hosts are server admins | module (`check_event_allowed`, then `user_may_invite`) | weaken the room after mint, admit a knocker: the invite is refused, also when the inviter is a server admin; the same check against a v10, a v11 and a v12 room |
| GP-SYN-20 (revised, see D7) | A host-visible notice exists for each knock. Text: [3.4](#34-rules-of-the-guest-policy-module) | Matrix sends no push for a knock | plan: host tool, installed push rule; bot only as an operator option | knock while the host is away from the room: the host tool notice is produced; spike SP-3 records whether the override rule outranks the default rule for Synapse pushers and for the Element Web push processor |
| GP-SYN-21 | A marked user may knock on one room at most 3 times in any 10 minutes, counted in module-private state. Text: [3.4](#34-rules-of-the-guest-policy-module) | Synapse limits a knock only by `rc_message`, and a client cap is advisory | module (`check_event_allowed`) | a modified client knocks 4 times in 10 minutes: the fourth is refused and the count of the first three is unchanged; after the window a knock passes; a `leave` passes while over the cap; the counter rows are gone after deactivation; with the counter made unreadable the knock is refused |
| GP-E2EE-01 to 04 | Text: [section 5](#5-e2ee-for-a-brand-new-guest-device) | silent key loss; unencrypted rooms | guest client, audit, module | see section 5 |

## 10. What we deleted or simplified

| Deleted or simplified | Because |
|---|---|
| Upstream registration servlet, MAS admin client, reaper and its table | siwx-oidc is the registrar and owns lifetime |
| `rooms_forbidden_to_guests` deny list | a positive allow rule fails closed |
| `user_may_invite` as the only layer for invite confinement and the admission re-audit | it is skipped for server admins, who are the likeliest hosts; `check_event_allowed` has no admin bypass and receives the room state |
| The near-zero per-user upload limit as the storage control | it is checked after the body is stored; a pre-store refusal and deployment controls replace it |
| Global `block_non_admin_invites`, `enable_set_displayname`, `enable_set_avatar_url`, `allow_per_room_profiles` | they hit every user, a module rule hits only guests; they survive only as fallback F-a |
| Account validity and MAU as guest limits | not enforced under delegated auth |
| `locked` as a guest marker | collides with real locks, not enforced |
| A profile-field marker next to `user_type` (D1) | two markers that can disagree are a defect; stock Synapse lets any user write a custom profile field |
| Clearing the marker at claim (D3) | confinement is a property of the identity; promotion is an operator act, so no invite link becomes an open registration path |
| Active call-state cleanup as the guest (D2) | a privileged primitive for a cosmetic residue; recorded as a v1.1 option |
| Suffix-only name rule (D8) | replaced by one canonical string that contains the suffix, so the module needs no suffix logic |
| Shared-key call mode | bearer media secret, no rotation, hosts in Element Web cannot join |
| Unencrypted call rooms (D7) | confidentiality would rest on SFU admission while P1 and P2 are open |
| Edge rule for membership | cannot see the body |
| Admin-API creation of the guest | refused in the next Synapse release |
| Room-list monkey patch | no public rooms are involved |

## 11. Dev spikes before the module goes live

Each spike has a pass condition and names what fails. Spikes SY-1 to SY-4 run on a dev Synapse 1.162.0 or later (P3). They
are separate from the client spikes S1 to S8 of 03.

| Spike | Setup | Pass | Fail means |
|---|---|---|---|
| SY-1 canonical name (D8) | Mint a marked user (marker, then canonical name by admin write). As that user: rename globally before any knock, rename per room, knock, rename after admission, set an avatar, copy the host's avatar. Then erase | Every member event shows the canonical name and no avatar; the global name returns to canonical; the module records its own revert as a no-op; erase leaves no name and no canonical row | Use the first working fallback of F-0, F-a and F-b in [3.4](#canonical-name-and-profile-confinement-gp-syn-08) and record which |
| SY-2 call under confinement | Host in Element Web, guest in the thin client, room per the template of section 4 with `events_default` 50 and call-member types at 0, module denying every non-state event | Join, leave, delayed leave and a two-way call work for host and guest; no event other than membership and call-member state is refused in the module log; the log lists every event type and state key the guest wrote, and GP-SYN-06 and the content allow-list of GP-SYN-08 accept each of them; a fourth knock of one marked user on one room within 10 minutes is refused (GP-SYN-21) | A needed event type is listed in `guest_allowed_event_types`, the key rule of GP-SYN-06 is changed to the observed key shape, or the template changes |
| SY-3 teardown order | Revoke tokens, delete the device, then `delete_user` with erase, while a call is connected. Variants: (a) a token with `device_id` null, issued for a marked test user by the test stack; (b) the host kicks the guest mid-call, with no teardown; (c) deactivation mid-call | The old access token is refused on the next request, the module lets the `leave` through without a canonical row, no joined room and no device remain. (a) The deviceless token stays valid until introspection turns inactive and is refused within 2 minutes after the token revoke of step 2 of 6.1, which is why GP-SYN-09 forbids issuing one. (b) and (c) The remaining client rotates its outbound media key once the guest has left the room, the guest's last key no longer decrypts the media that follows, and the stale `m.call.member` entry does not appear in the participant list | Keep an explicit leave step, or fix the module. For (b) and (c): the cosmetic-residue rule of D2 and the rotation argument of D7 fail, and active cleanup must be reconsidered |
| SY-4 marker fail-closed | Make the marker write fail (admin token refused) after a successful `provision_user`, then retry the sign-in | No token is issued and the record stays `provisioning`; the orphan is found by the admin user list and, once the lease of 01 GP-FLOW-26 has lapsed, erased by the reaper with no `query_user` shortcut; the retry marks the account before any device exists | Mint order or reaper coverage is wrong |

Requirement on spike SP-3 of the plan (host-side, not one of the SY spikes): it must include the push-rule ordering check of
GP-SYN-20, in words. On the target Synapse and Element Web builds, install a per-room override rule that matches knock events and
notifies, have a guest knock while the host is away from the room, and record, for Synapse's own evaluation (pushers, mobile)
and for the js-sdk push processor (Element Web popups) separately, whether the rule outranks the default
`.m.rule.member_event`, and whether the default rule alone lets the knock-bar popup fire. A pass makes the installed rule a
relied-on part of the host notice; a fail leaves the host tool notice as the only mechanism.

## Validation status

| Claim | Evidence | Status |
|---|---|---|
| `provision_user` creates with `by_admin=True`, fires registration spam check and `on_user_registration`, no rate limit, no auth blocking | `synapse/rest/synapse/mas/users.py:144-240`, `register.py:281,305,706-721,768` | Verified |
| `auto_join_rooms` fires at creation and treats a knock room as invite-required | `register.py:378-396,560-576` | Verified |
| Deactivation parts and forgets all rooms | `deactivate_account.py:280-331` | Verified |
| Erase does not redact messages | `deactivate_account.py:175-182`, `visibility.py:453-477` | Verified |
| siwx-oidc comment on introspection lag past expiry | `src/admin_token.rs:57-63` versus `mas.py:90-101` | Contradicted |
| Device deletion revokes a token at once, introspection alone after at most 2 min. Only a token that names a device is covered: the device row is read only `if device_id is not None`, and `is_deactivated` is never read | `mas.py:136-147,385-406` | Verified |
| Knock has no spam hook and no dedicated limiter | `room_member.py:637-654,1196-1222` | Verified |
| `check_event_allowed` sees local knocks, not remote knocks | `message.py:1437`, `federation.py:880` onward | Verified (local), Inferred (remote absence) |
| Room summary is open to unauthenticated callers for knock rooms | `room_summary.py:646-661`, `room.py:1719-1725` | Verified |
| `limit_profile_requests_to_users_who_share_rooms` inert alone | `profile.py:76-85`, `handlers/profile.py:1007-1011` | Verified |
| `block_non_admin_invites` blocks host invites | `room_member.py:906-912` | Verified |
| Account validity and MAU not enforced under delegated auth | `internal.py:171`, `register.py:305`, `mas.py` | Verified |
| `user_type` modifiable through the admin API under delegated auth | `rest/admin/__init__.py:306`, `users.py:470-471`, PR 20241 test text | Verified |
| Admin API creation will be refused in the next release | PR 20241 merged 2026-09-28, absent from the 1.162.0 changelog | Verified |
| The per-user media limit is checked after the body is stored, and a refused upload deletes nothing and writes no database row | `media_repository.py:349-353,364-420` | Verified |
| `is_user_allowed_to_upload_media_of_size` runs in both upload servlets before the body is stored; `check_media_file_for_spam` cannot target a user | `rest/media/upload_resource.py:67-78,117-126,167-180`, `module_api/callbacks/media_repository_callbacks.py:100-110`, `media/_base.py:526-541` | Verified (source), Unverified (run) |
| A state key that starts with `@` and differs from the sender is refused in every room version; the owner rule for underscore keys exists only in unstable room versions | `event_auth.py:894-921`, `rust/src/room_versions.rs:146,185,268-286` | Verified |
| MatrixRTC writes the state key `_<MXID>_<device id>_m.call` outside the unstable room versions | js-sdk `src/matrixrtc/MembershipManager.ts:979-994` | Verified (code), Unverified (run: the exact event types and keys, spike SY-2) |
| Delayed events are not cancelled on deactivation | `delayed_events.py`, storage, grep | Verified (mechanism), Inferred (outcome) |
| Restricted-guests identifies by prefix and registers through the MAS admin API | `guest_module.py:82-92`, `mas_admin_client.py:37,64` | Verified |
| Restricted-guests licence | SPDX header and README | Verified |
| lk-jwt v0.7.0 checks membership only on appservice routes; Element Call uses the others | `handler.rs:1016,1121,1268-1280`, `openIDSFU.ts:214,297` | Verified |
| MSC4502 and MSC4512 are open and experimental in Synapse | GitHub fetch 2026-09-30, `experimental.py:207,317` | Verified |
| lk-jwt README appservice example matches Synapse 1.161 key names | `README.md:148-164` versus `config/appservice.py:225-246` | Contradicted (Inferred, not run) |
| Call keys go to unverified devices and a guest without cross-signing is not blocked | SDK `rust-crypto.ts:1544-1588`, Element Web `ShieldUtils.ts:33-80` | Verified |
| Silent key loss for a late-uploading guest device | SDK `ToDeviceKeyTransport.ts:102-116`, `RTCEncryptionManager.ts:459` | Verified (code), Inferred (window) |
| Element Web shows a knock-request UI to the host, behind `feature_ask_to_join` (default off) | `apps/web/src/components/views/rooms/RoomHeader/RoomHeader.tsx:425,517`, `apps/web/src/settings/Settings.tsx:737-744` | Verified (source), Unverified (run) |
| Element X supports encrypted to-device through its widget driver | not read | Unverified |
| MSC4502 `is_joined` with delegated auth plus appservice token works in practice | not run | Unverified |
| An unreleased upstream product named "Element Meet" exists | searches found none | Unverified |
| Cross-signing keys, read receipts, media, `user_ips` survive deactivation | absence of references in the handler | Inferred |
| `user_ips` rows are written per authenticated request and pruned after 28 days by default | `synapse/api/auth/base.py:396-416`, `synapse/config/server.py:683-685` | Verified |
| The admin user list returns `user_type` per row and sorts by it, with a `not_user_type` filter and no positive filter | `synapse/rest/admin/users.py:144-157`, `synapse/storage/databases/main/__init__.py:99-114,319-322` | Verified |
| `user_types.default_user_type` is global and `provision_user` passes no per-call type | `synapse/handlers/register.py:323-324`, `synapse/rest/synapse/mas/users.py:158-163` | Verified |
| On an absent user the admin `PUT` takes the creation branch, which passes `user_type` | `synapse/rest/admin/users.py:371,481-500` | Verified |
| Inside one admin modify request the display name is written before `user_type`; admin writes and `provision_user` on an existing user set the name with `by_admin=True` | `synapse/rest/admin/users.py:372-379,470-471`, `synapse/rest/synapse/mas/users.py:173-180` | Verified |
| `on_profile_update` fires after the write, for display name, avatar and custom fields, with `by_admin` and `deactivation`; erase fires it with empty values and `deactivation=True` | `synapse/handlers/profile.py:281-296,417-419,464-469,736-738,823-825`, `third_party_event_rules_callbacks.py:487-505` | Verified |
| No hook vetoes a profile change; the Module API can set a display name (as admin) and has no avatar setter | `synapse/module_api/__init__.py:2018-2064`, search of the file for avatar setters | Verified (by reading; absence by search) |
| `enable_set_displayname` and `enable_set_avatar_url` bind only when a value exists, and never against an admin write | `synapse/handlers/profile.py:247-256,372-381` | Verified |
| Per-room profile content is stripped only by `allow_per_room_profiles: false`; knock and join events carry the global profile | `synapse/handlers/room_member.py:113-118,804-811,849-866` | Verified |
| A `check_event_allowed` replacement may change content but not type, state key or room | `synapse/handlers/message.py:1437-1451,2439-2474` | Verified |
| Spam-checker callback exceptions propagate, `check_event_allowed` exceptions fail the event, `on_profile_update` exceptions are swallowed | `spamchecker_callbacks.py:452-458,495-503`, `third_party_event_rules_callbacks.py:303-306,497-505` | Verified |
| Membership events skip the power-level send check; `events_default` applies to non-state events, `state_default` to state events | `synapse/event_auth.py:415-419,866-877` | Verified |
| Element Call's own `createRoom` sets `state_default: 0` and `events_default: 0` | Element Call v0.26.1 `src/utils/matrix.ts:227-260` | Verified |
| A module can read room state for an admission re-audit | `synapse/module_api/__init__.py:1644` | Verified |
| The deactivation loop parts the user as that user, so the module sees the `leave` | `synapse/handlers/deactivate_account.py:300-331` | Verified |
| `delete_device` removes the device and every later request with its token fails at once | `synapse/rest/synapse/mas/devices.py:80-118`, `synapse/api/auth/mas.py:397-406` | Verified (by reading, not run) |
| Default push rules give a member event no action and silence `m.notice` | `rust/src/push/base_rules.rs:86-98,121-132` | Verified |
| Under delegated auth a guest cannot add or delete a 3PID, change a password or deactivate itself; the first cross-signing upload needs no interactive auth | `synapse/rest/client/account.py:610-623,914-935`, `synapse/rest/client/keys.py:529-548` | Verified (by reading, not run) |
| `user_may_invite` and `block_non_admin_invites` are skipped for a server admin inviter; `check_event_allowed` has no admin bypass | `room_member.py:904-916`, `message.py:1437-1441` | Verified |
| The state PUT of a user's own member event passes the whole content dict to `update_membership`; a knock carries a free-text `reason`, and Element Web offers it to the host | `rest/client/room.py:364-376`, `rest/client/knock.py:62-66`, `apps/web/src/components/views/rooms/RoomKnocksBar.tsx:108-117` | Verified |
| The default room version is 11 on 1.161 (read at `config/server.py:612`) and 1.162.0 raises it to 12 | `config/server.py:179,612`, v1.162.0 changelog | Verified (1.161 source); the 1.162 default is read from its changelog only |
| Room version 12: creators hold unlimited power and may not appear in `users`; `additional_creators` are creators; room ids carry no server part | `event_auth.py:982-1005,1133-1135`, `events/__init__.py:167-181`, `rust/src/room_versions.rs:300-308`, `handlers/room_member.py:1198-1199` | Verified |
| lk-jwt takes the subject from the server named in the request and sends a server-side request to that name | `lk-jwt/src/helper.rs:610-642`, `src/handler.rs:661-698,901-930` | Verified (source), Unverified (displacement of a LiveKit participant with the same identity) |
| A call membership of a user who is not joined to the room is dropped from the session list, which is recomputed on every room member update, and Element Call reads that list; key rotation follows a leaver unless `keyRotationParticipantLimit` suppresses it (unset by default) | js-sdk `MatrixRTCSession.ts:546,871,1020,1052-1074`, `RTCEncryptionManager.ts:36-47,399-431`; Element Call `src/state/SessionBehaviors.ts:88`, `src/state/CallViewModel/CallViewModel.ts:553` | Verified (code), Unverified (run, spike SY-3) |
| Delayed-event `cancel`, `restart` and `send` take no access token in 1.161 | `synapse/handlers/delayed_events.py:427-495`, `synapse/rest/client/delayed_events.py:83-133` | Verified |
| No module callback fires for typing, read receipts, presence, account data, event reports or key backup uploads; presence carries a free-text `status_msg`; erase removes account data and key backups | `synapse/rest/client/presence.py:112-115`, `synapse/handlers/deactivate_account.py:196-202` | Inferred (absence of a hook), Verified (the rest) |
| Element Call falls back to no media E2EE when the room is unknown or has no encryption state event | Element Call `src/e2ee/sharedKeyManagement.ts:100-113`, `src/state/CallViewModel/CallViewModel.ts:1937-1939` | Verified |
| Mechanism M1 (module-private canonical name recorded from the admin write, reverted on user writes) works in practice | not run | Unverified (spike SY-1) |
| A module that denies every non-state event still lets an Element Call join and leave succeed | not run | Unverified (spike SY-2) |
| A module can count knocks per marked user and room in module-private storage and refuse the fourth within 10 minutes; the dispatcher honours a plain `False` from `check_event_allowed` | `synapse/module_api/callbacks/third_party_event_rules_callbacks.py:255-310` (a `False` answers `M_FORBIDDEN`); the counter itself is not written | Verified (the hook), Unverified (the counter, spike SY-2) |
| The default push rules let the Element Web knock popup fire for a host | not established | Unverified (requirement on spike SP-3, GP-SYN-20) |
| A per-room override rule outranks the default `.m.rule.member_event` for Synapse pushers and for the Element Web push processor | not established | Unverified (requirement on spike SP-3, GP-SYN-20) |
| This document holds unchanged on Synapse 1.162.0 | changelog only | Unverified (P3 requires the re-read before the module goes live) |

## Open decisions

1. **Knock or direct invite on link redemption.** Recommendation adopted (D7): knock, because a leaked link would otherwise
   admit anyone; add a host-visible notice (GP-SYN-20), since Matrix sends no push for a knock.
2. **Who may set `io.inblock.guest_room`.** Recommendation: a configured host list in the module (GP-SYN-14) that contains
   `guest_hosts`, not every room admin. Hosting itself is deny by default (D5).
3. **Marker write path.** Recommendation adopted (D1): `provision_user`, then the admin `PUT` of `user_type` before
   `upsert_device` (GP-SYN-07), mint fails closed, no profile-field marker. Fallback if upstream ever refuses modification
   too: module-owned table with a shared-secret write endpoint.
4. **Licence path for the guest policy module (P4).** Recommendation: a separate repository written against the Synapse
   module documentation; the maintainers decide the licence and confirm with counsel.
5. **lk-jwt fix (P1).** Recommendation: patch now and carry it as a small fork or upstream PR, delete it when Element Call
   uses the client-server token route. Dev first, production only with a written rollback.
6. **Residual SFU access of one hour after teardown (P2).** Recommendation: accept on dev, make lk-jwt PR 235 or an
   equivalent kick, and a short SFU token lifetime, a precondition for production.
7. **Federation posture for guest deployments (P3).** Recommendation: none, because a remote knock reaches no hook.
8. **Synapse version (P3).** Recommendation adopted (D11): move to 1.162.0 or later before the module goes live, because 1.162
   fixes the `check_event_allowed` crash on rooms created as version 12, which it makes the default (on 1.161 the default stays
   "11"), and re-read this document against that version.
9. **Profile lockdown pair.** Recommendation: leave unset, accept that a guest can read the public profile of a user whose
   MXID it learned from the call room.
10. **Guest shell.** Recommendation adopted (D10): the thin client of the client document, gated by its spike S1; a client
    without crypto is excluded.
11. **What a claim does to confinement.** Recommendation adopted (D3): the marker stays, so a claimed guest is permanent but
    confined, and promotion is an operator action or an attested claim. The maintainers decide whether an operator
    promotion tool is needed in v1 (05 recommends none).
12. **Teardown without call-state cleanup.** Recommendation adopted (D2): no active cleanup in v1, the stale `m.call.member`
    entry is a cosmetic residue with a host-side mitigation; the confined cleanup of [6.1](#61-teardown-order-and-call-state-revised-see-d2)
    is a v1.1 option.
13. **Name confinement mechanism and fallback.** Recommendation (D8): run spike SY-1 before anything depends on M1. If it
    fails, use F-0 when only the revert is unreliable, F-a where the homeserver serves guests alone, and F-b elsewhere. The
    maintainers decide whether F-b's residual (a guest can show another name in the waiting room, and v1 claims no name
    confinement) is acceptable on a shared homeserver.
14. **Host notice mechanism.** Recommendation: the mechanism of 01 GP-FLOW-29 and 04 GP-SEC-68, a waiting-guest notice in the host
    tool plus one per-room override push rule, with the Element Web knock bar (`feature_ask_to_join`) as an additional aid and a
    bot message only where operators ask. Spike SP-3 must settle the rule ordering (GP-SYN-20).
15. **Encrypted call room.** Recommendation adopted (D7): mandatory, refused at audit and at admission (GP-E2EE-04).
16. **Report the lk-jwt request-binding defect upstream.** Recommendation: yes, through the project's private security reporting
    route, because taking the subject from the server that the request names, and sending a server-side request to that name,
    exist in stock v0.7.0 regardless of guests (GP-SYN-01, item 5). Carry the binding rule in our patch meanwhile.
17. **Presence for guest deployments.** Recommendation: leave presence as it is in v1 and accept the free-text `status_msg` as
    the one text channel left to a guest (3.6); turn presence off only on a homeserver dedicated to the guest portal. The
    maintainers decide.
