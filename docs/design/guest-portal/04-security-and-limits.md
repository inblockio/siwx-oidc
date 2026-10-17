# Guest portal 04: security considerations and enforced limits

**Status:** DRAFT design document. Nothing here is implemented, and nothing in this document changes code.
**Scope:** attack the flow of [01-flow-model.md](01-flow-model.md) and the Synapse validation of
[02-synapse-validation.md](02-synapse-validation.md), and turn the result into enforceable requirements
(`GP-SEC-nn`). Those two documents are the contracts. [03-element-meet-client.md](03-element-meet-client.md) was read for
context only. Requirement IDs of the other documents (`GP-FLOW-nn`, `GP-SYN-nn`, `GP-E2EE-nn`, `GP-CLI-nn`) are
referenced, never restated.
**Baseline:** siwx-oidc `origin/main` at `3547bd2` (2026-09-30), Synapse v1.161.0 (`a33b01f`). Every `path:line` is
against those; paths prefixed `synapse/`, `lk-jwt/` are upstream. The claim ceremony itself is specified in
[05-claim-flow.md](05-claim-flow.md) (`GP-CLM-nn`); this document owns the confinement and token rules around it, and the
two documents state them identically (section 8).

Status words: **Verified** (read in source or fetched), **Unverified** (reasoned, taken from another document, or needs a run or a browser), **Contradicted**.
Enforcement points: **S** siwx-oidc, **M** Synapse policy module, **C** Synapse configuration, **E** reverse proxy,
**L** lk-jwt or LiveKit, **K** guest client, **O** operator process.

Decision references: `D<n>` names a decision of the [decisions log in the overview](00-overview.md#7-decisions-log).
Each stays listed there as an open decision for the maintainers, so every requirement that follows one is marked
`(revised, see D<n>)` and keeps its ID.
Vocabulary: the **marker** is the Synapse `user_type` value `io.inblock.guest` (section 3.3); the **tag** is the visible
` (Guest)` suffix of the display name; a **claim** is the passkey-link ceremony and nothing else.

## 0. Result in one page

The flow is defensible if a short list of limits is enforced in code rather than left to deployment. The limits that
matter most are not the obvious ones (rate limits, captcha). They are the places where the two contracts leave a gap.

| # | Issue | Consequence | Where handled |
|---|---|---|---|
| F1 | siwx-oidc opens an account to any valid proof: wallet and headless sign-ins create the account directly, the passkey login needs one click ([passkeys.md:164-182](../../passkeys.md)). Guest confinement therefore bounds the holder of a link, it is **not a perimeter** for the homeserver. The real gates are who may host, quotas, and human admission. | "Any non-guest account with invite power may host" would mean anyone. Hosting is deny by default: the allow-list is the primary control and has no opt-out (D5, D17). | GP-SEC-01, 02, 03 |
| F2 | Claim is the escalation path. A claim turns a deadline-capped session into a permanent account: a leaked link could become a permanent unrestricted account, and a refresh token stolen from a guest browser a permanent credential. | Claim is gated on admission, revokes every pre-claim token device by device, and does not lift confinement: the marker stays and promotion is an operator act (D3). | GP-SEC-35 to 38 |
| F3 | The custodial key signs nothing in the standard flow (01 HK-3) and nothing in the recommended claim. Storing it is pure liability. | Derive, never store; sign nothing in v1; refuse guest DIDs on every signature path; destroy the per-guest value at reap and at the claim commit (D9). | GP-SEC-52 to 59 |
| F4 | The module confines joins and state writes. It does not by itself stop a guest from posting messages, renaming itself, or copying the host's avatar, and Element Call's own room defaults let a joined guest write state and events. | The room template carries a restrictive `events_default` (D7); the module denies message events and profile changes by marked users (D8). | GP-SEC-20, 27, 28 |
| F5 | The lk-jwt membership gap (P1) is **already live for every local account today**, not a new risk. Guests enlarge the population that holds an account from "people who signed up" to "anyone who receives a link". Even with P1, a removed guest keeps an SFU token for up to an hour. | P1 plus mandatory E2EE plus key rotation on leave; P2 (SFU eviction and a short SFU token lifetime) before production (D11). | GP-SEC-31 |
| F6 | Teardown order and call state. Clearing call membership as the guest would make the reaper mint a token as a chosen user and act as them: a new privileged primitive for a cosmetic gain. | Order of section 5.4; v1 performs no active call-state cleanup, and the stale `m.call.member` entry is an accepted residue (D2). | Section 5.4, GP-SEC-32, RR-15 |
| F7 | Erase is not erasure of everything: Synapse keeps client IPs and user agents for 28 days by default, backups keep the record, historical member events persist. | State the residue to the guest and the operator; guests post no messages, which removes the largest residue class. | GP-SEC-27, 62, 63 |
| F8 | Smaller but load-bearing: the reaper must outlive the feature flag, deadlines must use Redis `TIME`, the device count needs an in-process cap, siwx-oidc sets no security headers at all. | Orphaned live accounts after a config change; clickjacking of the ceremony pages. | GP-SEC-05, 08, 39, 49 |

Three statements about what this document does **not** claim. It does not make the guest identity trustworthy (section 4
says why it is low assurance). It does not protect a guest from the operator (section 4.4 is the honest trust statement).
It does not replace an account-admission policy for the homeserver (F1).

### 0.1 Prerequisites outside this repository (hard gates)

Every requirement below assumes these four. The server cannot verify them, so enabling guest mode asserts them and the
deployment check of GP-SEC-30 reads what it can. The same four statements appear in every document of the set (D11). The operator
assertions P5 to P9 (P7 is superseded) are authoritative in 01 section 2 (07 repeats some of them for planning).

| Id | Prerequisite | Note |
|---|---|---|
| P1 | lk-jwt membership enforcement (Synapse `msc4502_enabled` plus a small lk-jwt patch that calls the existing membership check on the routes Element Call actually uses). Hard dependency before any guest exists, on dev too. | Both routes take any local account today. |
| P2 | SFU eviction and a short SFU token lifetime before production (lk-jwt kick PR or equivalent). The OpenID token lifetime is a Synapse constant (`synapse/rest/client/openid.py:72`) and is not configurable; P1 covers confidentiality for that half. | Does not shorten the Synapse OpenID token, a 1 h Synapse constant that P1 makes harmless (GP-SEC-31). |
| P3 | Synapse 1.162.0 or later before the module goes live, then re-read 02 against that version. Federation off for a guest deployment (a remote knock reaches no hook). | 1.162 makes room version 12 the default (1.161: 11) and fixes `check_event_allowed` for rooms created as v12. |
| P4 | the guest policy module (separate repository, licence path decided by the maintainers with counsel). | Before any guest exists: without it a guest is an unconfined account. |

## 1. Assets, adversaries and trust boundaries

### 1.1 Assets

| Id | Asset | Why it matters |
|---|---|---|
| A1 | Guest personal data: names, optional e-mail, IP, device, media, transcripts if an agent is present | Privacy and compliance exposure (section 5) |
| A2 | The meeting: who is in it, what is said, the room it runs in | Confidentiality and integrity for the host and the guests |
| A3 | Homeserver capacity: Synapse `users` rows (one per guest, forever), devices, Redis memory, SFU rooms and participants | A cheap mint loop becomes a permanent cost |
| A4 | The identity namespace: DIDs, MXIDs and the provider-signed `io.inblock.did` binding | A guest binding must not be mistaken for an assured identity |
| A5 | Provider secrets: MAS shared secret, ES256 signing key, the new guest key secret (section 4) | siwx-oidc can mint any token and any admin credential (`src/admin_token.rs` module doc) |
| A6 | The operator's reputation and mail reputation | Abuse relayed through our forms or our domain |
| A7 | Logs and audit trail | Evidence for abuse handling, and a personal-data store in their own right |

### 1.2 Adversaries

| Id | Adversary | Capability | Goal | In scope |
|---|---|---|---|---|
| ADV-1 | Anonymous abuser or bot | Internet access, no link | Mint accounts, exhaust resources, probe endpoints | Yes |
| ADV-2 | Malicious guest | Valid link, a real guest session | Reach other rooms, harass, impersonate, keep the account, escalate | Yes |
| ADV-3 | Mistaken or malicious host | Valid host token, controls the room | Mint guests at scale, phish guests, admit strangers by mistake, weaken the room | Yes |
| ADV-4 | Link leaker or forwarder | Has a copy of a link | Enter a meeting not meant for them, burn the link | Yes |
| ADV-5 | Link-preview bot or mail scanner | Fetches URLs, may execute scripts, cannot type | Burn a single-use link unintentionally | Yes |
| ADV-6 | Curious or compromised operator | Reads Redis, logs, can mint tokens | Read guest data, act as a guest | Partly: stated, not prevented (section 4.4) |
| ADV-7 | Network attacker | Passive or active on the path | Read links, tokens, media | Yes, TLS and E2EE, not a hostile operator |
| ADV-8 | Compromised guest browser or XSS in the client | Script in the Meet origin | Steal tokens, abuse the session, claim the account | Yes |
| ADV-9 | Another guest in the same call | A second guest session in the same room | Harass, spy on the list, inject media | Yes |

### 1.3 Trust boundaries and what must be checked where

The diagram of 01 section 3 is the reference. This table lists the checks that make each boundary hold.

| Boundary | Crosses | Check that must hold | Requirement |
|---|---|---|---|
| Internet to issuer origin | join page, redeem, hand-off, claim, cookie-authorised end | uniform answers, limits, headers, JSON only, `Origin` and `Sec-Fetch-Site` check, `__Host-` Lax cookie | GP-SEC-04, 12, 13, 39, 40, 41 |
| Meet origin to issuer | authorize, token, context, end | exact redirect allow-list, PKCE, `prompt=none` completes only for the guest client (and, in the default same-site topology, refuses a cross-site navigation), Bearer for context and end, no Bearer authority over claim | GP-SEC-34, 38, 42, 67 |
| Host to issuer | invite create, list, end | host allow-list, creator-only access, room audit, no confused deputy | GP-SEC-01, 06, 07 |
| Issuer to Redis | all state | persistent, PII confined to the guest record, hashed handles | GP-SEC-41, 60 |
| Issuer to Synapse | provision, marker, erase, audit reads | two credentials, fail closed on the marker, retry on erase | GP-SEC-66, GP-FLOW-15, GP-SYN-07 |
| Synapse to module | every local event | marked users are confined and a fixed allow-list of event types applies; unmarked users are not touched | GP-SEC-19, 20, 27, 29, 66 |
| Client to lk-jwt to SFU | OpenID token, SFU token | membership check (P1), E2EE, SFU eviction and a short SFU token lifetime (P2) | GP-SEC-31 |
| Guest to host | knock | human admission, visible "(Guest)" tag, recipient-bound links, host-visible knock notice, re-knock cap (02 GP-SYN-21) | GP-SEC-10, 19, 68 |
| Operator to everyone | everything | documented, not prevented | section 4.4 |

## 2. Abuse cases and attack trees

Leaves name the control that closes them. "Residual" is what remains after the controls of section 3.

### AC-01 Mass account minting and resource exhaustion

```
Goal: fill Synapse, Redis or the SFU, or starve real guests
+-- obtain many redeemable secrets
|   +-- become a host ........................................ GP-SEC-01 (host allow-list), GP-SEC-06
|   +-- steal one host token and mint in bulk ................ GP-SEC-02 (per-host quotas)
|   +-- one open link handed to a crowd ...................... GP-SEC-10 (single use default; open is an opt-in with a hard use cap), GP-SEC-02
+-- redeem without a secret
|   +-- guess id or secret ................................... GP-SEC-09 (96 bit id, 190 bit secret)
|   +-- flood garbage to burn CPU and Redis .................. GP-SEC-04 (proxy), body cap
+-- multiply inside one guest
|   +-- loop authorize, hand-off, sign_in for devices ........ GP-SEC-05 (device cap), GP-SEC-67 (rate per guest record), GP-SEC-04
+-- make cleanup fail so accounts pile up
|   +-- break erase so guests stay in reaping ................ GP-SEC-03 (mint brake), GP-FLOW-18
+-- grow permanent cost
|   +-- sustained mint under the burst limits ................ GP-SEC-02 (daily ceiling)
|   +-- many claims to keep accounts forever ................. GP-SEC-35 (claim cap, admission gate)
+-- crowd one SFU room ....................................... GP-SEC-02 (max_guests), host kick
Residual: a valid host can spend the daily ceiling. The ceiling is the damage bound, and it alerts (GP-SEC-46).
```

The baseline matters here: a stranger can already create ordinary accounts through the headless or passkey path (F1). This tree
is about not adding a cheaper, unmetered route, and about keeping the permanent cost (one Synapse row per guest) bounded.

### AC-02 Link theft and replay

```
Goal: enter a meeting with a link not meant for you, or burn the intended guest's link
+-- obtain the link
|   +-- forwarded by the recipient or posted by the host .... GP-SEC-10 (recipient-bound single links), admission
|   +-- mail scanner or chat unfurler copies it ............. GP-SEC-12 (GET never mutates), residual
|   +-- browser history or sync holds it ..................... burned after use; unused links expire (GP-SEC-11)
|   +-- logs or Referer ...................................... fragment transport, GP-SEC-39, GP-SEC-44
+-- replay
|   +-- redeem twice, or race two redeems .................... GP-FLOW-02 (atomic), single burns at redeem
|   +-- redeem after expiry or revoke ........................ GP-FLOW-11, GP-SEC-14
|   +-- reuse a stolen guest_session cookie .................. GP-SEC-41, 32 (deadline), residual on shared PCs
+-- burn it as a preview bot
|   +-- script-executing scanner loads the page .............. GP-SEC-12 (mutation needs typed names and consent)
Residual: a scanner that stores the full URL keeps a copy of the secret. The first successful redeemer still wins.
```

### AC-03 Impersonation through the alias

```
Goal: appear to the host or the other guests as someone else
+-- choose the name
|   +-- host, employee or executive name ..................... GP-SEC-18 (reserved and host lookalike), admission
|   +-- homoglyphs and mixed scripts ......................... GP-SEC-17
|   +-- zero width, bidi, control characters ................. GP-SEC-16
|   +-- fake role or fake tag: "Support", "(Guest)" .......... GP-SEC-16 (no parentheses), GP-SEC-18, GP-SEC-19
|   +-- identifier shapes: did:, @x:y ........................ GP-SEC-16 (colon and at sign not in the charset)
+-- change it after admission
|   +-- rename globally or per room ......................... GP-SEC-20 (canonical name, changes by marked users denied), GP-SYN-08
|   +-- copy the host's avatar ............................... GP-SEC-20
+-- spoof the tag
|   +-- drop or double the suffix ............................ GP-SEC-19 (module rewrite), GP-SYN-08
Residual: a guest can still pick a common real name that is not reserved. The host sees "Name (Guest)" and decides.
```

### AC-04 Harvesting the directory and room membership

```
Goal: learn who else exists on the server or in the meeting
+-- user directory search ................................... GP-SYN-11 (hidden, empty), C: search_all_users false
+-- public room directory ................................... GP-SEC-30 (no published rooms or list disabled)
+-- room summary and knock state of a knock room ............. GP-SEC-28 (neutral name, no topic, no avatar), GP-SYN-16
+-- profile and key queries for guessed MXIDs ............... opaque localparts (2^80); legacy did-pkh localparts
|                                                             are guessable from a public wallet address, GP-SEC-30 (MSC4263 flag)
+-- member list of the meeting room .......................... inherent; one room only (GP-SYN-05)
+-- resolve a known DID ...................................... existing public /resolve, four fields (AGENTS invariant)
Residual: other participants of the same call are visible to each guest. Legacy wallet-derived MXIDs stay probeable.
```

### AC-05 Reaching rooms or calls other than the meeting

```
Goal: act in a room or SFU room the guest was not admitted to
+-- Matrix side
|   +-- knock on another knock room ......................... GP-SYN-05 (confinement), GP-SEC-29
|   +-- join a public room by id or alias .................... GP-SYN-05 (user_may_join_room)
|   +-- be invited into a foreign room ....................... GP-SYN-04 (guest rooms only)
|   +-- remote knock ......................................... GP-SYN-12 (no federation)
+-- Media side
|   +-- /get_token or /sfu/get for any room id ................ GP-SYN-01 (membership check), GP-SEC-31
|   +-- keep an SFU token after removal (up to 1 h) .......... GP-SEC-31 (E2EE, key rotation, P2: eviction and short TTL), residual
|   +-- create SFU rooms with random ids ..................... closed by the same membership check
|   +-- learn a room id from the public directory ............ GP-SEC-30
Residual: the one hour token tail. In an E2EE room it yields noise, not content.
```

### AC-06 Spam and harassment inside the call

```
Goal: disrupt the meeting
+-- text and media
|   +-- chat, links, files by reference, reactions .......... GP-SEC-27 (no non-state events), GP-SEC-28
|   +-- knock, leave, knock again ............................ re-knock cap of 3 per room in 10 minutes (02 GP-SYN-21, 01 GP-FLOW-33), host ban; single-use links bound the population
+-- call
|   +-- noise, video, screen share as an admitted guest ...... residual; host kick and ban, E2EE key rotation on leave
|   +-- overwrite another participant's call membership ...... GP-SYN-06
+-- out of band
|   +-- to-device and verification-request spam to the host .. 02 section 3.6, accepted
Residual: an admitted guest is a full media participant. The remedy is removal by the host.
```

### AC-07 Using the guest account as a foothold

```
Goal: turn the guest account into something more than a call seat
+-- Matrix
|   +-- DM, room creation, invites ........................... GP-SYN-04
|   +-- media upload ......................................... GP-SYN-13 (bounded, not blocked: low global limit, proxy cap, orphan sweep), GP-SEC-04
|   +-- profile fields, avatar, display name ................. GP-SEC-20; custom fields are storage abuse only
|   +-- 3PID, password, self deactivation ..................... not registered under delegated auth (synapse/rest/client/account.py:914-935)
|   +-- pushers (outbound HTTP) ............................... 02 section 3.6 (ip_range_blacklist), accepted
|   +-- presence, typing, receipts ............................ harmless, accepted
|   +-- keys, cross-signing, backup ........................... stock; first setup is open, a replacement needs the IdP under MAS (synapse/rest/client/keys.py:529-548)
+-- siwx-oidc
|   +-- admin credential or admin API ......................... scope fixed at issuance (src/oidc.rs:1464-1475)
|   +-- account actions and device approval ................... need a signature or passkey the guest lacks, GP-SEC-56
|   +-- tokens for other clients .............................. GP-SEC-34
|   +-- mint invites .......................................... GP-SEC-06
+-- become permanent .......................................... GP-SEC-35 to 37
Residual: storage abuse through custom profile fields and account data, bounded by the deadline, and files that a refused upload
leaves on disk until the sweep removes them (02 GP-SYN-13).
```

### AC-08 Account claim takeover

```
Goal: end up owning someone else's claimed account, or a permanent account from a link
+-- hijack the claim
|   +-- XSS in the Meet client steals tokens, then claims ..... GP-SEC-38 (claim authority is the cookie, never a Bearer token)
|   +-- XSS in the Meet client drives the claim page .......... claim routes are same-origin JSON only (GP-SEC-40); the Meet origin cannot
|   |                                                            script the issuer origin; WebAuthn needs the user on the issuer page
|   +-- shared computer, next person claims ................... deadline, End session clears cookie, residual
|   +-- CSRF or clickjack the claim page ....................... GP-SEC-39, 40, 41, 43; WebAuthn origin binding
|   +-- cross-site navigation carrying the Lax cookie ........... GET claim routes change no state and return nothing a script can read
+-- keep a foot in the door after claim
|   +-- pre-claim refresh token survives ....................... GP-SEC-36 (revoked per device, crash-safe)
|   +-- token minted by a hand-off that raced the claim ........ GP-SEC-36, GP-CLM-23 (device append only while `active`)
|   +-- operator-held key signs in as the claimed account ..... GP-SEC-56, 57 (value destroyed; signature paths refuse the DID for ever)
+-- abuse claim itself
|   +-- claim without ever being admitted ..................... GP-SEC-35 (joined to the room, re-read at finish)
|   +-- claim to lift restrictions ............................. GP-SEC-37 (marker and confinement stay, promotion is an operator act)
|   +-- claim and reap race ................................... GP-FLOW-16, GP-SYN-10
|   +-- repeated finish, or a forged credential id that exists .. GP-CLM-06, GP-CLM-02 (single-flight lock, compensation only of a
|   |                                                              credential this call verified and wrote, existing id refused)
Residual: a guest on an unattended shared machine can be claimed by the next user within the deadline. The result is a permanent but
confined account, not a full one.
```

### AC-09 Teardown bypass

```
Goal: a guest that never expires, or acts after its deadline
+-- refresh after the deadline ............................... GP-FLOW-13, GP-SEC-32
+-- code minted before teardown exchanged after ............... GP-FLOW-14 (exchange probes both tombstones with the code's device
|                                                               id, rechecks after the mint and rolls back, as refresh does; logout_all
|                                                               plants the user tombstone, so a timestamp refusing only codes issued
|                                                               before it is preferred)
+-- first sign-in racing the reaper ........................... GP-FLOW-26 (provisioning fence: a refused state move after provision_user
|                                                               makes sign_in erase the account itself)
+-- deadline extension ....................................... GP-SEC-33 (monotone), GP-SEC-08 (Redis TIME)
+-- reaper down, stuck, or disabled by config ................ GP-SEC-32 (guard), GP-SEC-49 (runs regardless of flag)
+-- Redis flushed, guest record lost, Synapse account lives .. GP-FLOW-23 (persistence), GP-SEC-50 (orphan report); the account stays
|                                                               confined because the marker lives in Synapse (GP-SEC-66)
+-- Synapse down at teardown ................................. GP-FLOW-15, 18 (steps 1 and 2 of section 5.4 need only Redis, retry the rest)
+-- host end not reaching guests ............................. GP-FLOW-11 (by_invite set)
+-- OpenID token and SFU token tail ........................... GP-SEC-31, residual
+-- stale call membership ..................................... accepted cosmetic residue in v1 (D2, GP-SEC-63, RR-15)
Residual: media tail (one hour), orphan after a Redis loss until the operator runs the report, stale call tile.
```

### AC-10 E-mail abuse

```
Goal: use the form to reach arbitrary people, or to learn who is known
+-- make us send mail to an arbitrary address ................. no mailer in v1 (GP-SEC-24); v2 gate rules
+-- smuggle headers or list separators in the address ......... GP-SEC-22 (strict syntax)
+-- enumerate known addresses ................................. GP-SEC-25 (no uniqueness, no oracle)
+-- pose as someone else through a typed address .............. GP-SEC-23 (labelled unverified everywhere)
+-- read other guests' addresses ................................ GP-SEC-26 (creator host only, API authorisation)
+-- harvest from logs or Synapse 3PIDs ......................... GP-SEC-44, 23
Residual: a host sees an unverified address and may trust it. The label is the only defence.
```

### AC-11 Attacks on the ceremony itself

```
Goal: act with a victim's cookies, or fixate a session
+-- cross-site form or fetch POST (claim, cookie end) ........ Lax withholds the cookie; JSON only and Origin / Sec-Fetch-Site check (GP-SEC-40, 41)
+-- same-site sibling origin credentialed request ............ Lax and Strict both travel same-site, so the defence is JSON only (forces a
|                                                               preflight), Origin equal to the issuer origin, Sec-Fetch-Site same-origin (GP-SEC-40)
+-- cookie tossing from a sibling subdomain .................. __Host- prefix (GP-SEC-41)
+-- cross-site top-level GET navigation carries the cookie .... every GET route is state-free and data-free (GP-SEC-40); the hand-off sends
|                                                               the code only to the exact redirect URI, with PKCE (GP-SEC-34)
+-- a third-party page triggers silent hand-offs ............. default same-site topology: the marker branch of /authorize refuses a navigation
|                                                               whose Sec-Fetch-Site is cross-site (GP-SEC-34, D19), so nothing is burned.
|                                                               Cross-site topology only: it burns devices, bounded by GP-SEC-05 and the
|                                                               per-record rate of GP-SEC-67; it denies the guest's own resume at worst and grants nothing
+-- login CSRF: plant an attacker's guest session ............ needs the attacker's own link; victim joins the attacker's meeting,
|                                                               accepted as in 03, GP-SEC-42 (no open redirect)
+-- framing the join or claim page ............................ GP-SEC-39, 43
+-- open redirect through the hand-off or sign_in ............. GP-FLOW-06, GP-SEC-42
+-- stored XSS into the host's list through a name ............ GP-SEC-16, 15
Residual: login CSRF can put a victim into an attacker's meeting. The victim still has to grant camera and microphone access and wait for admission.
```

### AC-12 Operator or insider, and a stolen secret

```
Goal: read or act as guests beyond what the flow shows
+-- read Redis or backups ..................................... names and e-mail are in clear in the record; section 5
+-- mint tokens as a guest .................................... inherent to an IdP; stated in 4.4
+-- derive guest keys from the master secret ................... GP-SEC-53, 56 (keys sign nothing; signature paths refuse guest DIDs)
+-- add a device to a guest account and receive call keys ..... inherent; 4.4
+-- read Synapse with the admin credential .................... inherent; not a guest issue
Residual: accepted and documented. A hostile operator is out of scope.
```

## 3. Controls catalogue

Every row is a requirement: rule with rationale, enforcement point, default, whether it is configurable, and the
abuse test in words. Tests are located in section 6.3. Configuration key names are proposals in the style of 01 section 10.

### 3.1 Admission, quotas, minting

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-01 | **Hosting is deny by default, with no opt-out (revised, see D5, D17).** `guest_hosts` is the primary control and must be non-empty when `guest_enabled` is true; startup refuses otherwise. An entry names an account by DID (byte exact) or by localpart, and an attested host claim may be added to the same check once the identity-claims work provides one (not in v1). There is never a rule over DID method or key structure, and no setting lets any account host (the rejected opt-out is recorded in section 7, D17). The existing room-invite-power check at mint (GP-FLOW-10) is the second condition. Why: any valid proof creates an account (F1), so "any account with invite power" is "anyone", and a closed deployment can list its few hosts. | S | empty list refuses startup | config | Start with guest mode on and no hosts: exit non-zero. A token of an unlisted account on `POST /guest/invites`: 403. A listed account without invite power in the room: refused at audit. |
| GP-SEC-02 | **Quotas are counted in process, inside the same Redis script as the state change.** Numbers in the table below, including the use cap and the expiry ceiling of an open link (D6). Why: they are invariants (a permanent row per guest), not a DoS shield, so they are not the proxy's job. | S | see table | config | Mint up to each ceiling in a loop; the next call is refused and nothing is written; concurrent calls never pass the ceiling. |
| GP-SEC-03 | **Cleanup backlog brakes minting.** Redeem answers 503 while `guest_brake_reaping_count` records or more are stuck (default 2 x `guest_host_max_live_guests`, which is 50), or the oldest stuck record has been stuck for over `guest_brake_reaping_secs` (900 s). A record is stuck when its last teardown attempt failed or it has sat in `reaping` for more than one reaper tick (15 s). Why: a broken erase must not let the mint loop accumulate live accounts, and a healthy teardown must never trip the brake: ending a full meeting sets up to `guest_max_guests` records to `reaping` at once, they clear within a tick plus the erase time and are not counted, and one host cannot reach the default count inside its live-guest quota. | S | 50 stuck records, 900 s | config | Synapse mock refusing `delete_user`: after 50 reaps stuck, redeem refuses; recovery clears the brake. Ending a meeting of `guest_max_guests` guests against a healthy mock never trips it. |
| GP-SEC-04 | **Proxy limits and a body cap** (table below). The application also caps request bodies on guest routes at 4 KiB, except `POST /guest/claim/finish`, which has its own cap of 16 KiB. Why: per-IP shaping is the proxy's job by repository convention (AGENTS.md), and the application cannot verify it, so a deployment check proves it. The claim finish body carries a WebAuthn attestation response (attestation object, client data, a credential id of up to 1023 bytes, extensions): usually 1 to 2 KiB under `none` attestation, but a packed or TPM statement or a long credential id needs margin, and the existing `/link/webauthn/finish` has no cap at all. | E, S | table | config at the proxy, caps fixed | Deployment check sends 15 redeems from one address and expects 429 after the burst; a 5 KiB body on a guest route gets 413. A claim finish with a worst-case credential id (1023 bytes) and a packed attestation statement is accepted; a 17 KiB body gets 413. |
| GP-SEC-05 | **Devices per guest are capped** (`guest_max_devices`, default 8, counted on the guest record where a device id is appended, before any Synapse device is created). Why: every resume creates a fresh device (no recycling invariant) and the deadline bounds time, not count; the silent hand-off can also be triggered from another site (GP-SEC-67), so the cap is the last bound. | S | 8 | config | Nine resumes of one guest: the ninth is refused before any Synapse device is created. |
| GP-SEC-06 | **Minting authority is narrow (revised, see D3).** `POST /guest/invites` refuses minted admin tokens, tokens of any account that has a guest record in any state (`claimed` included) unless the record carries `promoted_at`, tokens without a live entry in `guest_hosts`, and any token when the kill switch is on. Why: guests, claimed-restricted accounts and the service user must never mint. | S | fixed | fixed | Guest Bearer, claimed-restricted Bearer, admin token, unlisted host, killed system: each 403, nothing written. A promoted host that is listed: accepted. |
| GP-SEC-07 | **The invite endpoint is not a confused deputy.** It uses the minted admin token for two read-only Synapse calls. `room_id` must match the room id grammar below, defined here once, and is sent as one percent-encoded path segment; answers to the host are fixed reason codes, never a Synapse body; list, end and revoke check that the caller created the invite; invite ids are random. Why: a normal user steers an admin credential. | S | fixed | fixed | `room_id` values with `/`, `..`, `?`, `%2f`, newline: rejected before any upstream call. The grammar vectors below. Host B lists, ends or revokes host A's invite: 404. |
| GP-SEC-08 | **Deadlines use Redis `TIME`.** Deadline arithmetic and comparison happen in the Redis scripts, not from instance clocks. Why: skew between instances must not extend or shorten a session. | S | fixed | fixed | Two instances with a skewed clock: the same deadline, enforced at the same instant. |

Room id grammar (GP-SEC-07, the single definition). A room id is `!` followed by an opaque part and, optionally, `:` and a
server name. The opaque part is one or more ASCII letters, digits, `-`, `_` or `.`, and nothing else (no `/`, `%`, `?`, `#`,
backslash, whitespace, control or non-ASCII character). The whole id is at most 255 bytes, the Matrix identifier limit. A server
part, when present, must equal `matrix_server_name` byte for byte, because guest rooms are local and do not federate. Room versions
before 12 give `!<opaque>:<server>`, and room version 12 gives `!<hash>` with no server part (MSC4291), so the grammar never
requires a server part: a rule copied from `!opaque:server` would refuse every v12 room, and Synapse 1.162 makes v12 the default.
Vectors: `!abcdefghijklmnopqr:example.org` and `!` plus a 43 character base64url hash with no server part are accepted;
`!a:other.example`, `!a/b`, `!a%2fb`, `!a b`, `a:example.org` (no sigil), `!` alone and a 256 byte id are refused.

Quota numbers (GP-SEC-02). They suit a deployment measured in tens of guests a day. Raising one is an explicit operator act.

| Key | Default | Why this number |
|---|---|---|
| `guest_max_guests` (per invite; also the ceiling of `count` for a batch of single links) | 10 | One external meeting. Bounds SFU room size, which lk-jwt does not (lk-jwt issue 112). |
| `guest_allow_open_links` | false | A reusable link exists only behind this flag (GP-SEC-10). |
| `guest_open_link_max_uses` | 10 | Hard use cap of one reusable link. The invite's `max_guests` for `kind: open` may not exceed it. |
| `guest_open_link_max_ttl_secs` | 86400 | Expiry ceiling of a reusable link. |
| `guest_host_max_open_invites` (active per host) | 1 | A reusable link is the one place a crowd can enter; one per host bounds it. |
| `guest_host_max_invites` (active per host) | 5 | A host runs a few meetings at once; more is bulk abuse or a stolen token. |
| `guest_host_max_live_guests` | 25 | Live means `minted`, `provisioning`, `active` or `reaping`. Above this one host is larger than any meeting the design targets. |
| `guest_host_invites_per_hour` | 20 | Bulk create counts once per link. |
| `guest_global_max_active` | 50 | Each live guest costs a Synapse user, devices, Redis keys and up to one SFU participant. Size it against measured SFU capacity. |
| `guest_daily_mint_max` | 500 | Each mint costs one Synapse row for ever (the localpart is consumed). The ceiling bounds the permanent damage of a stolen host token. |
| `guest_max_claimed` (permanent accounts from links) | 200 | A claim creates a permanent, confined account; see GP-SEC-35. |
| `guest_max_devices` | 8 | GP-SEC-05. |
| `guest_handoff_per_minute` (per guest record) | 3 | GP-SEC-67. A reload, a retry and one spare; more is automation or a hostile page. |
| `guest_brake_reaping_count`, `guest_brake_reaping_secs` | 2 x `guest_host_max_live_guests` (50), 900 | GP-SEC-03. Counts only stuck records (a failed last teardown attempt, or more than one reaper tick in `reaping`), so ordinary use never trips it. |

Proxy limits (GP-SEC-04). The redeem burst equals the default `max_guests` so one meeting behind one office NAT passes.

| Route | Per address | Per /24 (IPv4) or /56 (IPv6) | Why |
|---|---|---|---|
| `GET /guest/join/*` and `POST /guest/peek` (one shared bucket) | 60 per minute, burst 30 | 300 per minute | Static shell and the secret-checked, non-burning lookup behind it (one Redis read, no state change); stops scanning of ids |
| `POST /guest/redeem` | 10 per 10 minutes, burst 10 | 30 per 10 minutes | Mint path |
| Hand-off (`GET /authorize` from the Meet client, any `/guest/continue` step), `GET /guest/resume` | 20 per minute | 100 per minute | Each completion creates a device; the per-record bound is GP-SEC-67 |
| `GET /guest/ended` (static issuer page of the end screens; its script calls `GET /guest/resume`, so the two share this bucket) | 20 per minute, shared with the row above | 100 per minute, shared with the row above | Static shell, changes no state; one page load costs one `resume` read |
| claim routes (`GET /guest/claim`, `POST /guest/claim/start`, `POST /guest/claim/finish`) | 10 per 10 minutes | 30 per 10 minutes | WebAuthn registration; `claim/finish` has its own 16 KiB body cap (GP-SEC-04) |
| `POST /guest/invites`, `POST /guest/end` (Bearer or cookie) | 10 per minute | none | Authenticated |
| `GET /guest/invites` | 30 per minute | none | Authenticated host list, polled by the host screen; reads only the caller's own invites |
| `POST /guest/invites/{invite_id}/end`, `POST /guest/meetings/end` | 10 per minute | none | Authenticated host end routes, a few a meeting |
| `GET /guest/context` | 20 per minute | 100 per minute | Guest Bearer, read once after the code exchange and after a reload; changes no state |
| `POST /register` | 5 per minute | 20 per minute | Open dynamic registration is a pre-existing Redis growth path (03 section 3.2) |
| Synapse media upload routes (`/_matrix/media/*/upload` and `/create`, a Synapse route behind the same proxy) | 10 per minute | none | Body cap equal to the low global `max_upload_size`; a refused upload still leaves its file on disk (02 GP-SYN-13) |

### 3.2 Invite links

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-09 | **Invite construction.** Public id: 96 random bits (not sequential, not derivable). Secret: `gi_` plus 32 base62 characters (about 190 bits, 01). Only the SHA-256 of the secret is stored; compare the hashes in constant time. The redeem path always hashes and always does one lookup, known id or not. The secret travels only in the URL fragment (GP-FLOW-01) and is removed from the address bar after redeem (GP-CLI-10); it is never placed in a path, query, cookie or log. Why: ids must not be enumerable, and a stored secret would be a bearer credential at rest. | S, K | fixed | fixed | Unknown id and wrong secret return byte-identical responses; Redis dump contains no secret; ids of a thousand mints show no pattern. |
| GP-SEC-10 | **Links are single-use and recipient-bound by default; a reusable link is an explicit, capped opt-in (revised, see D6).** Default: `kind: single`, one redemption per link. A host needing N guests creates N links in one call (`count`, at most `guest_max_guests`) and labels each with the intended recipient (host-chosen, at most 40 characters, shown only to the creating host). `kind: open` exists only when `guest_allow_open_links = true` (default false) and then always carries a hard use cap (`max_guests`, at most `guest_open_link_max_uses`), an expiry of at most `guest_open_link_max_ttl_secs` (24 hours), and the knock admission of the room: siwx-oidc has no admit path and no auto-admit option, so the host admits every guest. Whether v1 ships the reusable variant at all is the maintainers' call; the recommendation is single-use first. Why: link-preview bots and forwarding burn or spread a bearer link; per-recipient links give attribution and per-person revocation; a reusable link lets every holder mint a permanent Synapse row, so it is capped, short and never unattended. | S | single only | config | With the default: a request for `kind: open` is refused. Flag on: the use cap, the expiry clamp and the one-open-link-per-host quota hold; every guest of an open link appears as a pending knock the host must admit. Host lists links: label next to the redeemed name. Forwarded single link: second redeemer refused. |
| GP-SEC-11 | **Expiry.** Default 24 hours, ceiling 72 hours, as in 01 section 10 (`guest_invite_ttl_secs` 86400, ceiling 259200). Why: a bearer link that can sit valid for a week in mailboxes and scanner caches is a long attack window; a far-off meeting can re-issue. | S | 24 h, 72 h | config | Request 96 hours: clamped or refused; redeem after expiry refused. |
| GP-SEC-12 | **A link scanner cannot burn or mint.** `GET /guest/join/*` never changes state. Redeem needs a JSON `POST` carrying typed names, the consent flag and the secret; no script path submits it without user input. Why: scanners that execute JavaScript see the fragment but cannot type. | S, K | fixed | fixed | Headless browser loads the full URL with fragment and waits: `guest_count` unchanged, no record. |
| GP-SEC-13 | **No oracle.** Extends GP-FLOW-24: unknown id, wrong secret and malformed body share one status and body, and follow the same code path (hash, lookup, compare). State-specific answers only after the secret verified. Why: an id alone must not reveal whether an invite exists or what state it is in. | S | fixed | fixed | Compare responses for unknown id, known id with wrong secret, expired, revoked: identical until the secret is right. |
| GP-SEC-14 | **Revocation.** The creating host can revoke one link and end the whole meeting (GP-FLOW-11); the operator kill switch (GP-SEC-48) revokes everything. A revoked link stays refusable for its whole physical TTL. Why: a leaked link needs a one-step kill. | S | fixed | fixed | Revoke one of three links: that one refused, the others work, its guest (if any) reaped. |
| GP-SEC-15 | **No host-controlled or URL-controlled text before redeem (revised, see D21).** The join and consent pages render only operator text, and the answer of `POST /guest/peek` carries only state and non-text parameters (e-mail policy, session length, consent version, recording flag): no host name, meeting name, room name or label, and the invite record holds no host display text at all (D21). After redeem, names, labels and room names from the host are inserted as text, never as HTML (the client gets the meeting name from `GET /guest/context`). Why: the page is on the issuer origin, where a phishing string from a stolen host token would carry the operator's name, and a guest who holds only a link needs none of it to decide. | S, K | fixed | fixed | Invite label and room name containing markup appear escaped after redeem; the pre-redeem shell is byte-identical for any id and the `peek` answer of an invite with a hostile name and label contains neither string. |

### 3.3 Names, the tag and the marker

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-16 | **Character policy** (supersedes the character rules of GP-FLOW-09). Each part: NFC normalised, trimmed, inner whitespace collapsed to one space, 1 to 40 scalar values. Allowed: letters, combining marks (at most two in a row), space, hyphen-minus, apostrophe (U+0027, U+2019), and a period only after a single letter (an initial). Everything else is refused: digits, symbols, emoji, parentheses, brackets, `@`, `:`, `#`, `/`, control, bidirectional and format characters (which include zero width), surrogates, private use. Why: the charset alone removes markup, DID and MXID shapes, fake markers and invisible tricks. | S | fixed | fixed | Vectors: `<b>x</b>`, `did:key:z6Mk`, `@a:b`, `Jane (Host)`, a name with U+200B inside it, a name with U+202E, `R2D2`, `Mary  Jane` (collapses), a 41-character part: each outcome as listed. |
| GP-SEC-17 | **Script policy.** Each part must be single-script under UAX 39 "Highly Restrictive" (Latin, Cyrillic, Greek, Han with Kana, Hangul, Arabic, Hebrew, Devanagari, Thai and the other listed scripts), with no mixing between letters of different scripts inside a part. Why: the classic homoglyph is a Cyrillic letter inside a Latin word. | S | fixed | fixed | A Latin word with Cyrillic U+0430 in place of `a`: refused. A Latin name with a diacritic (`Zo` plus U+00EB), a wholly Cyrillic name, a wholly Han name: accepted. |
| GP-SEC-18 | **Reserved and lookalike names.** Compute the UAX 39 skeleton of each part and of the full name. Refuse if it equals or contains a reserved word from the built-in list (admin, administrator, moderator, support, helpdesk, system, security, staff, official, host, organiser, organizer, owner, bot, guest) or the operator list (`guest_reserved_names`, for example employee names), or if it equals the skeleton of the inviting host's current display name (read at redeem through `read_profile`, best effort: a failed read skips this one check and never the others; the name is compared only, never stored and never shown to the guest, D21). Why: the cheap impersonations are the ones the host and other guests will actually see. | S | built-in list | config (list) | `admin` with a fullwidth first letter (U+FF21), `host` with Greek Eta (U+0397), `Sup port`, the host's own name with one homoglyph: each refused. |
| GP-SEC-19 | **The tag is the IdP's and the module's, never the guest's.** siwx-oidc seeds the displayname at first provision as `First Second` plus the suffix (default ` (Guest)`, operator-configurable, never empty). The module enforces the canonical string, which contains the suffix exactly once (GP-SYN-08), and rewrites every member event of a marked user to an allow-list of content keys (`membership` and the canonical `displayname`), dropping `reason`, `avatar_url` and unknown keys, so a dropped or doubled suffix never reaches the room. Why: seeding without the suffix opens a window between provision and the module's first rewrite. | S, M | ` (Guest)` | config (text) | Profile read right after first sign-in carries the suffix; a rename attempt keeps it once; a member event with a `reason` and an unknown key is stored without them. |
| GP-SEC-20 | **The name and the avatar are frozen, from a source the guest cannot write (revised, see D8, D1).** The canonical values are the name siwx-oidc seeds and no avatar. A canonical name is fixed by admin write at mint, and the module denies profile changes by marked users. Mint order in the guest branch of `sign_in`: the marker (GP-SEC-66), then the canonical name in a second admin `PUT` (`user_type` is applied last within one request, `synapse/rest/admin/users.py:470-471`, so a single request cannot show the module a marked user at the time of the profile write), then the first token. The module records an admin-made profile write on a marked user as canonical, rewrites every own member event to a replacement that keeps only an allow-list of content keys, `membership` and the canonical `displayname`, and drops `reason`, `avatar_url` and every unknown key (`check_event_allowed` may return a replacement event), and reverts global display name changes (`ModuleApi.set_displayname`, `synapse/module_api/__init__.py:2018`). No avatar setter was found in the module API, so a changed global avatar stays readable on profile lookups and only the room-visible value is forced. **Mechanism and fallback, stated up front:** the mechanism is M1 of 02 section 3.4 (the module stores the admin write as canonical, reverts global name changes and rewrites member events), and it is proven by the dev spike SY-1 before anything else depends on it. If SY-1 fails the deployment chooses a fallback (02): F-a, for a homeserver that serves the guest portal alone, turns the global profile knobs off and seeds a neutral avatar at mint; F-b, for a shared homeserver, enforces no name after mint and contains the risk by human admission, where the host compares the knocker's Matrix display name with the name the IdP lists for that invite, a residual the deployment documentation must state. Why: no module hook vetoes a profile change (`on_profile_update` fires after the fact, `synapse/handlers/profile.py:294`) and `enable_set_displayname` is global (`:247`). Without a canonical source every name rule of GP-SEC-16 to 18 is bypassed by a rename through the Matrix API before the first knock, and GP-SYN-08 guarantees only the suffix. | M, S | fixed | fixed | A guest renames before knocking, after admission and per room, and copies the host's avatar: the room-visible values stay canonical. A knock with a free-text `reason` and extra custom content keys: the stored event carries neither. The admin-write mechanism (seen as `by_admin` on a marked user) is Unverified: spike on dev. |
| GP-SEC-66 | **The enforcing marker is written fail closed and only by the mint path (D1).** The marker is the Synapse `user_type` value `io.inblock.guest`. siwx-oidc writes it with an admin `PUT` right after `provision_user` and before the first token is issued. If the write fails the mint fails closed: the request answers 503 with no device and no code, the record stays `provisioning` (01 section 6.2), the next hand-off retries every step, and an account that is never completed is erased by the reaper (GP-SEC-49), which always erases a `provisioning` record and never takes the `query_user` shortcut for it. The marker means "confined identity", not "unclaimed": a claim never clears it (GP-SEC-37) and only an operator promotion does. There is no second marker: no `io.inblock.guest` profile field exists, so two markers cannot disagree. The module confines every marked user and leaves unmarked users alone; since the mint path is the only writer, a guest without the marker exists only as a failed mint that holds no token. Why: a marker that can be best-effort is a marker that can be missing, and a missing marker is an unconfined account. Orphans stay confined and stay findable (GP-SEC-50). | S, M | fixed | fixed | Mock Synapse refusing the marker write: no device and no code, the next hand-off retries, an abandoned account is reaped. A guest token cannot change `user_type` (no admin scope). After a claim the marker is unchanged. A profile read of a guest shows no marker field. |

### 3.4 E-mail

These rules govern a **guest's** address. The registered e-mail accounts of R11 use the address as an authenticator by design, under their own rules ([09](09-registered-users.md) GP-REG-07 to GP-REG-11). Neither set loosens the other: a guest's address stays unverified and never authenticates, whatever R11 adds.

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-21 | **Policy is frozen on the invite and enforced in the server.** `optional`, `required` or `off` as in 01. `required` with no address: 422. `off`: a submitted address is refused, not silently dropped. Why: enforcement cannot live in the form. | S | `optional` | config (operator) | Post `required` without the field, post `off` with the field: 422 both. |
| GP-SEC-22 | **Syntax only.** One `@`, at most 254 characters, local part at most 64, domain with a dot, ASCII or IDNA punycode, lowercase domain. No whitespace, control characters, commas, semicolons, angle brackets, quotes or display-name form. No DNS, MX or SMTP lookup at redeem. Why: list injection and header injection need those characters; a lookup is an outbound request with attacker-chosen names and a timing oracle. | S | fixed | fixed | `a@b.c, d@e.f`, `"x"@y.z`, `a@b` (no dot), a header-injection string, 255 characters: each refused. No DNS query in the mock network log. |
| GP-SEC-23 | **The e-mail is unverified everywhere and never an authenticator or an identity.** It is never put in a token, ID token, userinfo, profile, Synapse 3PID (`provision_user` sends only localpart and displayname, `src/synapse_client.rs:468-480`; it must never send `set_emails`), account data or log line, and never used for claim authentication or recovery. Every consumer labels it "typed by the guest, not verified". Why: a self-asserted address is an impersonation vector. | S, K | fixed | fixed | After a full flow with a sentinel address: absent from tokens, userinfo, profile, the mock Synapse request bodies, and stdout. |
| GP-SEC-24 | **No outbound mail in v1.** A mailer is a new security review with these gates: mail only after a same-session double opt-in; one mail per guest record, 3 per address per day, 20 per address-range per hour, 200 per day overall; a fixed template with no attacker-controlled text (no name, no label); identical response whether or not anything was sent. Why: a form that mails a typed address is a spam relay with our reputation. | S | no mailer | fixed in v1 | Grep of dependencies and config for an SMTP client: none. |
| GP-SEC-25 | **No enumeration, no uniqueness.** The same address may appear on any number of guests; redeem never says whether an address was seen. Why: an address is not an identity. | S | fixed | fixed | Two redeems with one address both succeed and answer identically. |
| GP-SEC-26 | **Retention and visibility (revised, see D13).** The address lives in the guest record only, is readable by the creating host through the host API and by the operator, and is deleted at reap (`guest_email_retention_secs`, default 0, which governs the unclaimed case only). At claim the guest is asked once (05 CL-02): keep the address on the account for notices, or remove it. The default is remove, and no answer, abandonment or reap means deletion: the claim commit deletes it unless `keep_email` is true (GP-CLM-05). A kept address is unverified, is never a login or recovery factor (GP-SEC-23), and is reachable by no host once the claim removed the invite membership. Why: v1 has no purpose for the address beyond host contact (section 7), so a permanent account carries an unverified address only when its owner chose that. | S | remove | config (operator) for the unclaimed case; the guest's choice at claim | After reap, and after a claim without the keep choice, the field is gone; after a claim with it, exactly that address remains and no host list returns it; another host's list never returns it. |

### 3.5 Capability confinement

| Capability of a guest | Allowed | Enforced by | Test |
|---|---|---|---|
| Knock on the meeting room, be admitted, join | Yes | client API, host admission | end to end |
| Knock again after a deny, a kick or a cancel | At most 3 knocks per room in 10 minutes | 02 GP-SYN-21 (01 GP-FLOW-33) | a fourth knock from a modified client: refused by the module |
| Knock on, join or be invited into any other room | No | GP-SYN-04, 05, GP-SEC-29 | foreign knock refused (module test) |
| Create rooms or aliases, publish to a directory | No | GP-SYN-04 | refusal codes |
| Invite anyone | No | GP-SYN-04 | refusal |
| Start a DM | No | room creation denied, inbound invites only into guest rooms | refusal |
| Search the user directory | Empty results | GP-SYN-11 | directory search as a guest |
| List public rooms | No rooms to list | GP-SEC-30 | deployment check |
| Read the meeting room members | Yes, that room only | inherent | none |
| Read history before joining | No | `history_visibility: joined` | room audit |
| Send messages, files, reactions, other events | No | **GP-SEC-27** | post a message, a reaction, a redaction: refused |
| Write state | Only own membership and call-member keys | GP-SYN-06 | overwrite another key: refused |
| Change display name or avatar | No | **GP-SEC-20** | see above |
| Upload media | Bounded, not blocked: a low global `max_upload_size`, a proxy rate limit and body cap on the media upload routes, and a periodic sweep of media files that have no database row (a refused upload still leaves its file on disk, so a per-user quota alone bounds nothing) | GP-SYN-13, GP-SEC-04 | upload above the limit refused; sweep removes the leftover file; residual recorded in 02 |
| Add a 3PID, set a password, deactivate self | Not available | not registered under delegated auth (`synapse/rest/client/account.py:914-935`) | endpoints answer 404 (Verified by reading) |
| Cross-signing: first setup allowed, replacement only with IdP approval | As described | `synapse/rest/client/keys.py:529-548` | no `/account` path for guests |
| Register a pusher, write account data, set presence | Yes, accepted | residual (02 section 3.6) | none |
| Reach `/_synapse/admin/*` or `/_synapse/mas/*` | No | scope fixed at issuance (`src/oidc.rs:1464-1475`), shared secret | admin call with a guest token: 401 |
| Mint invites, act as host | No | GP-SEC-06 | 403 |
| Obtain tokens for any client but the guest client | No | GP-SEC-34 | authorize for a foreign client with a guest cookie: no code |
| Publish to the SFU | Only in the meeting room, after P1 | GP-SYN-01 | non-member `get_token`: 403 |

The table holds for every marked account, before and after a claim. What a claim changes is stated once, in the same words as
[05 section 5.5](05-claim-flow.md#55-what-a-claimed-account-may-do-and-who-decides): *After a claim the account keeps the marker, the
module confinement and its mint-time policy (room confinement, event allow-list, frozen name and avatar). It loses the deadline and
reaper eligibility and gains a passkey. It can still sign in with the passkey, use `/account` (devices, deactivate, erase), take part
in calls in flagged guest rooms it is in or is invited into, and be invited into further flagged guest rooms by a host. It cannot
create rooms, start direct messages, invite, search the directory, publish, send non-state events, mint invites or host, or add a
second passkey. Promotion to an ordinary account is an operator action (or, later, an attested claim), never a side effect of
claiming and never based on key structure; there is no configuration that promotes at claim.* (GP-SEC-37)

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-27 | **Guests send no non-state events by default, claimed accounts included.** The module denies every event a marked user sends except its own `m.room.member` and its own call-member state (GP-SYN-06), including `m.room.message`, `m.room.encrypted`, `m.reaction` and `m.room.redaction`. Operators may widen it with `guest_allowed_event_types`. Why: the client exposes no composer (GP-CLI-08), but a guest holds a real token; 02 confines state writes and joins and leaves messages open. Without chat there is no message residue after erase (section 5). Whether Element Call needs any room event from a participant beyond call state is **Unverified** (spike S1 of 03). | M | deny all | config (list) | A guest token posts a message, an encrypted event, a reaction and a redaction: each refused. A full call still connects. |
| GP-SEC-28 | **The room template is the union of 01 section 4.3 with 02 section 4, plus `events_default` and mandatory encryption (revised, see D7).** The call room is created by the host's own client, never by siwx-oidc, and audited at mint. Required: `knock` and the room version minimum of the audit (stated once in 01 section 4.3; it is our audit policy, not a Synapse constraint), `history_visibility: joined` (stricter than "not world readable": under `shared` a knocker who is later removed could read earlier events), `guest_access: forbidden`, `m.federate: false`, the `io.inblock.guest_room` flag set by a sender that is in `guest_hosts`, power levels `state_default` 50 with no per-type override below 50 except the call-member types (so no join rule, encryption, power level or other state event is guest-writable), `events_default` 50, `users_default` 0, `invite`, `kick`, `ban`, `redact` at 50 or more, call-member types at 0, a neutral name, no topic, no avatar, and **`m.room.encryption` present (enforced, not merely allowed)**. Power is evaluated with the room-version rule stated once in 01 section 4.3 (in room version 12 the creator and the `additional_creators` of `m.room.create` hold unlimited power and never appear in `users`; `additional_creators` must be empty or a subset of `guest_hosts`), never by reading the `users` map alone. Why: Element Call's own rooms set `state_default: 0` and `events_default: 0` (`ec/src/utils/matrix.ts:227-260`), which lets a joined guest rewrite join rules; the summary of a knock room is readable without authentication (GP-SYN-16); lk-jwt checks no membership without P1, so confidentiality rests on E2EE, which is also what makes the SFU token tail survivable (GP-SEC-31). | S | `enforce` | config (`warn` for tests only) | Mint into a room missing each item in turn: refused with the reason class. The same vectors on room versions 10, 11 and 12, including a v12 room whose creator is the host with an empty `users` map (accepted) and one with a foreign `additional_creators` entry (refused). |
| GP-SEC-29 | **The room is re-audited at admission, for every inviter.** The module's `check_event_allowed` refuses an `m.room.member` invite event whose target is a marked user and whose room is flagged but whose current state violates the template, and refuses an invite of a marked user into a room that is not a flagged guest room, whoever the inviter is: server admins included, because Synapse skips `user_may_invite` for an admin inviter (`synapse/handlers/room_member.py:895-925`) and hosts and support staff are often admins. `user_may_invite` stays as a second layer. Why: the audit at mint can be stale by the time the host admits (01 section 9, "Room rules changed after mint"); admission is the moment that matters, and only the event hook sees every inviter. | M | fixed | fixed | Weaken `join_rules` after mint, then admit a knocker as an ordinary host and as a server admin: the invite is refused both times. An invite of a marked user into an unflagged room by an admin: refused. |
| GP-SEC-30 | **Deployment posture.** The operator asserts, and a deployment check verifies where it can: `auto_join_rooms` empty (GP-SYN-03); no federation (GP-SYN-12, P3); Synapse 1.162.0 or later (P3); no published rooms, or `enable_room_list_search: false`; `element_call.guest_spa_url` **unset** in every Element Web config (the secretless guest link of 01 C8); `allow_public_rooms_without_auth` off (default); `experimental_features.msc4263_limit_key_queries_to_users_who_share_rooms` on dev first (02 section 3.5); no public-directory room that a call runs in. Why: each is a way around the module that no code in this repository can close. | O | checklist | n/a | `scripts/` deployment check reads what it can (configuration endpoints, room list as a guest) and prints a pass or fail per line. |
| GP-SEC-31 | **The media tail (revised, see D2, D11).** P1 (GP-SYN-01) is a hard dependency before any guest exists. In addition: the call room is encrypted (GP-SEC-28) so a removed guest, who is denied the next key rotation, can only send noise; before production P2 holds: SFU eviction of a connected participant (lk-jwt kick PR or equivalent) and a short SFU token lifetime. The LiveKit token lifetime is fixed at one hour today (`lk-jwt/src/handler.rs:70`) and the same lk-jwt change makes it configurable, set by the operator to 10 minutes. The OpenID token lifetime is a Synapse constant of one hour (`synapse/rest/client/openid.py:72`) that nothing in this design can shorten; with P1 an old OpenID token mints no SFU token once the account has left the room. LiveKit `room.auto_create: false`; LiveKit API and Twirp endpoints not public. Residue in v1, documented: for up to one hour after teardown a connected participant or an already minted token can linger, and a stale `m.call.member` entry can remain (section 5.4). Why: deactivation cannot remove a connected participant and OSS LiveKit has no revocation (02 section 7). | L, O | 1 h today | config after patch | After host removal the ex-guest cannot decrypt new media; a fresh `get_token` with the old OpenID token is refused (P1); after P2 the participant is evicted. |
| GP-SEC-68 | **A pending knock is visible to the host, without the guest's e-mail (D7).** Matrix sends no push for a knock (the default `.m.rule.member_event` has empty actions), so a host-visible notice is part of the design: a client notice in the host's own client or a bot message in the call room, naming the guest by the canonical `Name (Guest)` only. The notice never carries the e-mail, the invite secret or a link label. siwx-oidc posts nothing to rooms and needs no room credential for it. Why: admission is the control that makes a leaked link survivable, and an unseen knock is an unattended door; a notice that leaked the address would undo GP-SEC-26. | host, O | recommended | n/a | Knock as a guest: the host sees the pending knock with the canonical name and nothing else. |

### 3.6 Tokens, sessions and claim

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-32 | **The deadline is enforced in four independent layers**: the refresh guard (GP-FLOW-13), the reaper, the kill-switch epoch (GP-SEC-48), and Synapse-side device deletion at teardown (step 3 of the order in section 5.4). A read error in the refresh guard answers 5xx, so the client retries and is not signed out, and never passes: the post-mint probe of the existing refresh paths fails open on `Indeterminate` (`src/oidc.rs:1029-1047`), and the guard must not copy that shape. Why: no single layer may be the only thing between a guest and "never expires". | S | fixed | fixed | Stop the reaper: refresh after the deadline is refused. Delete the due entry by hand: the epoch or the refresh guard still ends the session. Make the guard's Redis read fail: the refresh answers 5xx and mints nothing. |
| GP-SEC-33 | **Lifetimes.** `session_secs` minimum 600, default 7200, ceiling 14400. The deadline is monotone: it can only move earlier. Access tokens stay 300 s (fixed, `src/db/mod.rs:90`). Why: short enough that a forgotten session is cheap, long enough for a meeting. | S | 7200 | config within bounds | Request 600, 14400, 14401, 599: accepted, accepted, clamped or refused, refused. A second write with a later deadline is a no-op. |
| GP-SEC-34 | **A guest session yields tokens only for the guest client (revised, see D4, D19).** The hand-off (the guest-marker branch of `/authorize` with `prompt=none`, the `/guest/continue` ceremony and `sign_in`; the routing scope marker only selects the path and is no authority) requires `client_id` equal to the configured `guest_client_id` (01 section 10), a `redirect_uri` that matches `guest_client_redirect_uris` exactly (GP-FLOW-06) and PKCE S256. The guest client must be a static entry that never expires (03, GP-CLI-02). The client id check is what stops a dynamically registered client from driving the hand-off: `POST /register` accepts any redirect URI without a fragment (`src/oidc.rs:2775-2780`), so such a client can share the Meet client's exact redirect URI and use its own PKCE challenge. Guest mode refuses to start when `did:key` is not in `supported_did_methods`, because the derived guest DID needs it. Under the default `guest_client_topology = same-site` (client and issuer share a registrable domain, for example `meet.example.org` and `id.example.org`) the marker branch of `/authorize` also refuses a navigation whose `Sec-Fetch-Site` is `cross-site` when the header is present (D19); `cross-site` is the value for a deployment that cannot share a domain, and it relies on the exact redirect and the per-record bound of GP-SEC-67 alone. The `__Host-guest_session` cookie is read only by the hand-off, `GET /guest/resume`, `POST /guest/end` and the claim routes. A code goes only to the exact redirect URI, so a page that triggers a completion cross-site cannot receive it. Why: the guest session must never become a second login for other relying parties. | S | fixed | config (allow-list, client id, topology) | Authorize with a guest cookie for an attacker-registered client or a foreign redirect: no code, nothing written. A dynamic client registered with the Meet client's exact redirect URI and a different client id: no code. A cross-site navigation to `/authorize` with a valid cookie: refused under `same-site`; under `cross-site` the code reaches only the allow-listed redirect URI, which holds no matching `state` or verifier. Start with `did:key` missing from `supported_did_methods`: exit non-zero. |
| GP-SEC-35 | **Claim is gated (revised, see D3).** A claim is accepted only while the record is `active` and `now < deadline` by Redis `TIME`; only if the account is **currently joined to its invite's room** (one admin read at start and again at finish before the credential is written, fail closed); only if the Synapse account exists and is active (`reject_if_new_identity`, then `reject_if_deactivated`); and only while fewer than `guest_max_claimed` records are in state `claimed` (counted inside the script). The state change is the single compare-and-set of GP-FLOW-16. Why: a claim turns a two-hour account into a permanent one, so it is bounded to people a host actually admitted. | S | fixed | cap configurable | Claim before admission: refused. Claim after the host removed the guest: refused. Claim at the cap: refused. Concurrent claim and reap: exactly one wins. |
| GP-SEC-36 | **Claim revokes every pre-claim token, device by device, and survives a crash (revised, see D3).** The compare-and-set keeps the record's device ids, deletes the guest-session handle and adds the localpart to a pending set (`guest:claim_revoke`). The claim handler then revokes the tokens of each device id held in the record (`revoke_device_tokens`, `src/db/redis.rs:212`) and removes the pending entry; the reaper tick finishes any entry a crash left behind, and the revocation is idempotent. The claim keeps `revoke_device_tokens` as it is, including its keyspace scan: the token index is advisory (`set_token` does `SET`, `SADD` and `EXPIRE` as separate commands, `src/db/redis.rs:934-953`), so an index-only revoke would miss a token whose `SADD` had not run, which is exactly the window of a refresh rotation racing the claim. The scan costs at most `guest_max_devices` passes per claim and each guest claims once (cap `guest_max_claimed`). Only the reaper uses the index-only variant, because it has a second net that the claim does not have: the user tombstone and the deletion of the Synapse devices. The append of a device id is conditional on state `active` in the same script (GP-CLM-23), so a hand-off that loses the race to the compare-and-set mints nothing that outlives the revocation. The claim must **not** call `revoke_all_user_tokens`: that plants the 900 s user tombstone (`src/db/redis.rs:281-309`), which the refresh path reads as "deactivated" (`src/oidc.rs:980`) and which GP-FLOW-14 would extend to code exchange, so the claimant would be locked out of the session they just earned for up to 15 minutes. `revoke_device_tokens` plants a tombstone for the revoked device ids only, so a passkey sign-in on a fresh device id is unaffected. An authorization code minted before the claim cannot be exchanged after it: code exchange probes both tombstones with the code's device id (GP-FLOW-14), and the device tombstone (900 s) outlives the code (300 s). The record keeps the revoked ids as `pre_claim_devices` and `sign_in` refuses a proposed device id in that list (05 GP-CLM-26), because the tombstone lasts only 900 s and `resolve_device_id` accepts any id the client proposes (`src/oidc.rs:2058-2063`); the guest client also proposes a fresh id. Synapse device rows are left alone (no `sync_devices` with a reduced set). Why: otherwise a refresh token taken from the guest browser before the claim survives into a permanent account and refreshes for up to 90 days. The claim is offered on the end screen, on the join-page resume screen and, with a warning that the call session ends, from the in-call chip (GP-CLM-19), so continuity of the live call is not preserved. | S | fixed | fixed | Keep a refresh token from before the claim: its refresh is refused, also after a simulated crash between the compare-and-set and the revocation. A passkey sign-in straight after the claim succeeds and its first refresh (300 s later) succeeds. A code minted for a pre-claim device and exchanged after the claim: refused. A passkey login that proposes a pre-claim device id, also after 900 s: refused. |
| GP-SEC-37 | **Claim does not lift confinement (revised, see D3, D1).** After a claim the account keeps the marker, the module confinement and its mint-time policy (room confinement, event allow-list, frozen name and avatar). It loses the deadline and reaper eligibility and gains a passkey. It can still sign in with the passkey, use `/account` (devices, deactivate, erase), take part in calls in flagged guest rooms it is in or is invited into, and be invited into further flagged guest rooms by a host. It cannot create rooms, start direct messages, invite, search the directory, publish, send non-state events, mint invites or host, or add a second passkey. Promotion to an ordinary account is an operator action (or, later, an attested claim), never a side effect of claiming and never based on key structure; there is no configuration that promotes at claim. The operator promotes by clearing `user_type` with the Synapse admin API and then setting `promoted_at` on the guest record, which promotion never deletes (so GP-SEC-56 keeps holding); a failure between the two steps leaves the account labelled as a guest while unconfined, the safe direction, and a retry completes it. Why: otherwise any link holder who is admitted once becomes a permanent unrestricted user of the homeserver, bypassing whatever admission policy the operator may adopt later. A confined permanent account still serves the use case: rejoin the host's next meeting. | S, M | confined | none | After a claim, create a room and invite: refused; a later invite into a flagged room: allowed. After promotion the account may create a room and the record still exists with `promoted_at`. |
| GP-SEC-38 | **Claim authority is the `__Host-guest_session` cookie on the issuer origin, never a Bearer token (revised, see D4, D18).** The claim page and its routes are same-origin, use the existing link core (option `claim-authorised` of 05 section 3), and require a fresh passkey creation with user verification. The same cookie also authorises `POST /guest/end`, for the claim page's "Delete everything now" (D18, GP-SEC-65): the cookie path passes the `Origin` and `Sec-Fetch-Site` check of GP-SEC-40 like every cookie-authorised `POST` and answers 409 for a claimed account, while a Bearer request to that endpoint needs no such check. Why: tokens live in script-readable storage of the Meet origin and an XSS there would otherwise claim the account; the cookie is HttpOnly and Lax, so it is not sent on cross-site POSTs, the claim routes are JSON POSTs that pass the `Origin` and `Sec-Fetch-Site` check of GP-SEC-40, and the server checks the WebAuthn origin against `rp_origin` (the issuer origin), so a ceremony run from another origin fails verification. The shared RP ID work (per-credential `rp_id`, in flight) must not add the Meet origin to any accepted origin. | S | fixed | fixed | A claim with only a Bearer token: refused. A registration response produced on the Meet origin: rejected by origin verification. `POST /guest/end` with only the cookie ends an unclaimed guest, is refused from a foreign origin, and answers 409 for a claimed account. |
| GP-SEC-67 | **The silent hand-off is bounded per guest record (D4, revised, see D19).** The cookie is Lax, so in a `cross-site` topology a third-party page can drive the browser to `/authorize` and trigger a silent completion, and every completion creates a device. In the default `same-site` topology the marker branch of `/authorize` refuses such a navigation outright (`Sec-Fetch-Site: cross-site`, GP-SEC-34), so the bound below is the backstop there and the only defence in the other topology. Completions are limited per guest record to `guest_handoff_per_minute` (default 3), counted in the same script as the device append of GP-SEC-05; a refused completion answers `temporarily_unavailable` to the exact redirect URI and writes nothing. Why: the code cannot be stolen (exact redirect, PKCE, GP-SEC-34), but an unbounded trigger would burn the device cap of GP-SEC-05 and deny the guest their own resume. | S | 3 per minute | config | Nine navigations to `/authorize` with one valid cookie inside a minute, in the `cross-site` topology or with the header absent: at most three devices are created, the rest answer `temporarily_unavailable`. Under `same-site` a navigation marked `cross-site` creates none. |

Record states and what each confines. The same table stands in [05 section 5.1](05-claim-flow.md#51-record-states-and-what-a-claim-changes).

| Record state | Synapse account | Marker | Deadline and reaper | Sessions | Entered by |
|---|---|---|---|---|---|
| `minted` | none | none | yes | handle only | redeem |
| `provisioning` | may exist: `provision_user` has started or finished and the marker write may not have run (a failed marker write stays here) | set once the marker write succeeded, else none | yes: after one lease the reaper always erases, with no lookup shortcut | handle only | guest branch of `sign_in`, compare-and-set from `minted` before `provision_user` (01 section 6.2) |
| `active` | provisioned | set before the first token (GP-SEC-66) | yes | handle, tokens, devices | guest branch of `sign_in`, after the marker and the canonical name are written |
| `reaping` | being erased | set | the reaper owns it | revoked in the order of section 5.4 | deadline, host end, guest end, operator epoch |
| `claimed` | active | **set, and it stays** | none, the reaper skips it | handle deleted, pre-claim tokens revoked | claim compare-and-set from `active` |
| `claimed` with `promoted_at` | active | cleared by the operator | none | passkey sessions | operator promotion |
| `reaped` | erased | not applicable | record deleted | none | the reaper |

`active` to `claimed` and `active` to `reaping` are each one compare-and-set, so exactly one wins (GP-FLOW-16). `claimed` ends only
by the account's own erase action (GP-CLM-16) or by an operator.

### 3.7 The web ceremony

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-39 | **Security headers on every guest page and route.** `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`. Set in the application, not only at the proxy. Why: siwx-oidc sets none today (Verified: no hit for these headers in `src/` or `static/`), and the proxy is not something the application can verify. | S | fixed | fixed | Fetch each guest route and assert the headers; a page framed from another origin does not render. |
| GP-SEC-40 | **State-changing guest routes take JSON only and check origin (revised, see D4, D18).** `Content-Type: application/json` is required (form and plain-text bodies are refused). At least one of `Origin` and `Sec-Fetch-Site` must be present and every one that is present must match: `Origin` equal to the issuer origin, `Sec-Fetch-Site` equal to `same-origin`; a request with neither is refused. This check applies to routes authorised by a cookie or by no credential, and only to them (redeem, peek, continue, claim start and finish, and the cookie path of `POST /guest/end`, D18). A route authorised by a Bearer token (the host routes, and `POST /guest/end` and `GET /guest/context` from the Meet client) carries no ambient credential and is called from another origin by design, so it is not subject to the origin check; the `POST` routes among them need JSON only. Every `GET` guest route changes no state and returns nothing a script can read cross-origin (CORS carries no credentials). Why: the Lax cookie is not sent on cross-site POST or fetch requests, but `SameSite` (Lax or Strict) does not stop a same-site sibling origin, and JSON forces a preflight that the wildcard CORS layer cannot satisfy for credentials (`src/axum_lib.rs:1569-1577`); a Lax cookie does travel on cross-site top-level GET navigations, which is why no GET may act. Browser behaviour is **Unverified** until the browser test runs. | S | fixed | fixed | From a sibling origin: credentialed fetch and form post to redeem, claim start, claim finish, and end with the cookie: none takes effect. A request with neither header: refused. A Bearer `POST /guest/end` from the Meet origin: accepted. A cross-site top-level navigation to each GET route changes nothing. |
| GP-SEC-41 | **Cookie attributes (revised, see D4, D19).** `__Host-guest_session`: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`, `Max-Age` to the deadline; unprefixed only on plain-HTTP development, as the existing cookies relax `Secure`. The Redis key holds the SHA-256 of the handle, not the handle. Why: Lax rather than Strict so that one cookie works in both topologies: Strict is not sent on a cross-site navigation from the Meet client to `/authorize`, which a `guest_client_topology = cross-site` deployment needs, while in the default same-site topology that navigation is same-site and the topology gate of GP-SEC-34 does the work; and `Path=/guest` could not cover `/authorize`; `__Host-` cannot be planted by a sibling subdomain (01 left cookie tossing to this document); a hashed key keeps the value out of key listings and monitors. The `siwx` wallet cookie is set by JavaScript and is **not** HttpOnly (`js/ui/src/App.svelte:176-180`), so no guest rule may rely on it; the `session` cookie (`src/oidc.rs:1681-1689`) is the one that carries an OIDC session to `/authorize`. | S | fixed | fixed | Set-Cookie attributes asserted; a cookie named `guest_session` from a sibling is ignored; `redis-cli` key names contain no handle. |
| GP-SEC-42 | **No open redirect, https only.** Redeem answers with the fixed `guest_client_url`; the hand-off and `sign_in` take `redirect_uri` from the exact allow-list; guest mode refuses to start unless `base_url` and every guest redirect URI are https (a localhost development `base_url` excepted). Why: a return URL taken from a request is an open redirect on the issuer origin. | S | fixed | config (list) | A foreign `redirect_uri`, an `http` one, a redeem request naming a return URL: refused or ignored. |
| GP-SEC-43 | **Page script hygiene.** Guest pages load script only from the issuer origin (no inline script, no third-party asset), build the DOM with text nodes, and never put the secret, the handle or a name into a URL or `localStorage`. Why: the ceremony pages are where consent and the claim happen; one injected string must not run. | S, K | fixed | fixed | The CSP blocks an injected inline script in the browser test; storage and URL inspection after a flow show no secret. |

### 3.8 Logging

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-44 | **What a guest log line may contain.** Invite id, guest localpart, host localpart, state, reason class, counts, durations. Never: names, e-mail, IP address, user agent, invite secret, `guest_session` handle, tokens, cookies, key material, `key_ref`. Why: the request log already records method and path only (`src/axum_lib.rs:1542-1548`); guest code must not undo that. Existing lines that print a DID (for example `src/webauthn.rs:402`) print a pseudonymous guest DID as well. Decide if that is acceptable in section 5. | S | fixed | fixed | Run a full flow with sentinel name, e-mail, secret and handle; capture the output; grep finds none. |
| GP-SEC-45 | **No request or upstream bodies on the guest path, and one body-free log shape for every `SynapseClient` call that path reaches.** A failed Synapse call logs the HTTP status and the Synapse `errcode` only, and the error it returns carries the same two facts: never the response body, never the `message` text, at any log level. The rule covers every method of the table below, not one line: the provisioning line that logs the body (`src/synapse_client.rs:485`) is the first of more than ten. These methods are shared with ordinary accounts, so the change is one shared log helper for every caller, not a mode switch for guests: the body is the only place an upstream can reflect a guest-supplied string, and status plus errcode diagnose every case the current lines were written for (an operator loses the Synapse message text in the log). Methods added for the guest flow (the admin `PUT` of `user_type` and of the display name, the room-members read, the room-state read, the admin user-list read) are written in that shape from the start. Why: names and addresses must not reach logs by reflection, and an upstream error can echo input. | S | fixed | fixed | For each call of the table: a mock Synapse answers it with a failure status and a body that contains the sentinel name; the captured log has the status and the errcode and not the sentinel, and neither does the returned error text. One test per call. |
| GP-SEC-46 | **Audit events and alert conditions.** Events: `guest_invite_created`, `guest_minted`, `guest_signin`, `guest_refused` (reason class, route), `guest_reap` (reason, outcome, attempts), `guest_claimed`, `guest_control_changed`. Alerts (log level `error`, for the operator to wire up): oldest `reaping` over 15 minutes, live guests at 80 percent of the cap, daily mints at 80 percent, more than 50 refusals in a minute. Why: the quotas only help if somebody is told when they bite. | S | fixed | thresholds configurable | Each alert condition triggered in a test produces its event. |
| GP-SEC-47 | **Retention guidance** (not enforced by code). Proxy access logs on `/guest/*`: drop or truncate the address, retain at most 7 days. siwx-oidc application logs: at most 14 days. Why: the address plus a pseudonymous id plus a time is personal data; the abuse investigation window is days, not months. | O | recommended | operator | Deployment checklist line. |

Calls covered by GP-SEC-45. Paths: **R** redeem, **S** `sign_in` guest branch, **P** reaper, **C** claim, **A** the `/account` page that a claimed guest can use. Lines are in `src/synapse_client.rs` at the baseline.

| Method | Line | Body or Synapse message logged today at | Reached from |
|---|---|---|---|
| `read_profile` | 938 | 994, 1006 | R (host display name for GP-SEC-18), S (alias self-heal and migration, `src/oidc.rs:2282`) |
| `localpart_status` | 724 | 748, 792; the `Unusable` message also reaches `src/localpart.rs:254, 281` | S, C (through `resolve_identity` in `reject_if_new_identity` and `reject_if_deactivated`, `src/localpart.rs:235, 267`) |
| `is_localpart_available` | 817 | error text carries the Synapse message (821) | S (`src/oidc.rs:2221`) |
| `provision_user` | 468 | 485 | S |
| `upsert_device` | 502 | 521 | S |
| `update_device_display_name` | 534 | 557 | S |
| `allow_cross_signing_reset` | 567 | 581 | S (`src/oidc.rs:2466`), A |
| `publish_did_field`, with the `has_profile_row` probe it calls (920) | 1308 | 1355, 1370, 1385, 1401 | S |
| `query_user` | 843 | 864 | S, C (`reject_if_deactivated`, `src/webauthn.rs:400`), P |
| `delete_device` | 1089 | 1109 | P, A |
| `deactivate_user` | 1145 | 1165 | P, A |
| `list_devices`, `get_device` | 1023, 1061 | 1041 | A |
| `reactivate_user` | 1189 | 1204 | A |
| `has_cross_signing_keys` | 620 | 631 | A |
| `read_did_field` | 1468 | 1560 | the public `/resolve` (`src/resolve.rs:641, 736`), not a guest path; listed because the helper is shared |
| new: `user_type` and display name `PUT`, room members read, room state read, user-list read | none yet | none yet | S, C (members read), host invite audit, reaper, orphan scan |

### 3.9 Kill switch and operations

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-48 | **The kill switch is three Redis values, effective without a restart and without Synapse.** `guest:control` holds `disabled` (refuse mint, hand-off, resume and guest refresh at once), `reap_before` (an epoch: every unclaimed guest minted at or before it is due now), and the set `guest:banned_hosts` (their invites refused, their live guests due now). The reaper tick (15 s) and the refresh guard read it. There is no HTTP admin endpoint. Why: an emergency control must work when everything else is on fire and must add no attack surface. | S, O | off | operator | Set `disabled`: redeem, continue and guest refresh refuse within one tick. Set `reap_before` to now: every live guest is reaped with Synapse down (tokens revoked first). |
| GP-SEC-49 | **The reaper runs whenever guest records exist, regardless of `guest_enabled`.** The flag stops minting, the hand-off, resume and guest refresh; it never stops cleanup, including the cleanup of a half-created account left by a failed marker write (GP-SEC-66). Why: switching the feature off and restarting would otherwise orphan every live guest account. | S | fixed | fixed | Start with the flag off and a live record past its deadline: it is reaped. |
| GP-SEC-50 | **Orphan reconciliation is report-only.** A periodic, slow scan lists Synapse users that carry the marker but have no Redis record, and logs them. It never erases. Why: after a Redis loss a claimed account looks like an orphan (it keeps the marker and its record, so both are lost together); automatic erase would destroy a permanent account. An orphan stays confined because the marker lives in Synapse, and it stays findable: the admin user list rows carry `user_type` (`synapse/storage/databases/main/__init__.py:319`) and the server-side filter only excludes types, so the scan pages the list with `not_user_type` set to the empty string (untyped users excluded, `__init__.py:265-267`) and matches the value `io.inblock.guest` itself. | S, O | weekly | config | Delete a record by hand: the next scan reports the account and erases nothing. |
| GP-SEC-51 | **Startup refusals and the Redis contract.** Guest mode refuses to start without: `mas_shared_secret`, `synapse_endpoint`, `matrix_server_name`, `guest_client_url`, `guest_client_id` (GP-SEC-34), a non-empty redirect list, a non-empty `guest_hosts` (GP-SEC-01), `guest_key_secret` of at least 32 bytes that differs from the MAS secret (GP-SEC-53), `did:key` in `supported_did_methods` (the derived guest DID needs it, GP-SEC-34), https origins (GP-SEC-42). It warns when Redis persistence is off (01 open decision 16), and, best effort because a managed service may forbid `CONFIG`, when the server reports a `maxmemory-policy` other than `noeviction` or a version older than 5. The Redis contract the scripts rely on is: `noeviction`, because an evicting policy silently deletes live guest records and `erased:*` markers, and an orphaned live account or a lost erase marker is the failure this design must not have; Redis 5 or later, because the scripts read `TIME` and then write, which needs effects replication (the default from Redis 5); a single node, not Redis Cluster, because the scripts touch several keys that would need one hash slot. Why: a misconfiguration that silently weakens the flow is worse than a failed start. | S | fixed | fixed | Each missing item in turn: exit non-zero with the item named. A mock answering `CONFIG GET maxmemory-policy` with `allkeys-lru`, and one reporting a version 4 server: one warning each. |

## 4. Custodial key custody

R3 is decided: the operator manages the guest's key and the guest never handles one. This section documents the
consequences and what the key may and may not do. It covers guest keys only: the long-lived custodial keys of registered e-mail accounts (R11) are a separate class, wrapped under a key-encryption key with a migration path to an HSM ([09 section 4](09-registered-users.md#4-custody-with-a-migration-path-to-an-hsm)), and nothing here changes because of them. It invents no key-management scheme. The key-lifecycle roadmap
(rotation, delegation, loss) stays with the SDK.

### 4.1 Specification

| Aspect | Decision | Requirement |
|---|---|---|
| Curve | Ed25519. Policy never depends on it: the `did:key` method and the curve are an implementation detail, and the guest flow behaves identically with P-256. The headless client already builds an Ed25519 key from a 32-byte seed (`siwx-oidc-auth/src/lib.rs:111-131`). | GP-SEC-52, 59 |
| Generation | In siwx-oidc at redeem. The key is derived from a server secret plus a per-guest random value stored in the guest record, so destroying that value destroys the key. A 128-bit random `key_id` from the operating system CSPRNG is stored as `key_ref = {v: 1, id}`. The 32-byte seed is `HKDF-SHA256(ikm = guest_key_secret, salt = key_id, info = "siwx-oidc/guest-did-key/v1")`. The public key gives the `did:key`, `mxid::localpart_for` gives the localpart (01 B3). | GP-SEC-52 |
| Where the private key lives | **Nowhere at rest.** It is re-derived in memory for an operation that GP-SEC-54 permits (none in v1) and zeroized after use. A Redis dump, a backup or a log holds no signing material. | GP-SEC-53 |
| Secret source | `guest_key_secret`: at least 32 random bytes, supplied the way `mas_shared_secret` is, refused at startup if absent, short, equal to the MAS secret or derived from the provider signing key. It is never used for anything else. | GP-SEC-53, 51 |
| Lifetime | Redeem until reap or claim. | GP-SEC-57 |
| Destruction | **"Destroyed" means one thing (D9): the per-guest random value `key_ref.id` is deleted from the record, and the seed was never stored.** Reap deletes the record and with it the value; the claim commit deletes it inside the compare-and-set. After either, nothing can re-derive the key, not even the holder of `guest_key_secret`. The word does not cover: a Redis snapshot, append-only file or backup taken while the value existed, which holds it until rewritten or rotated (a stated residue, GP-SEC-62, GP-SEC-63); the public key and the DID, which are public by design; the claimant's passkey, which was never the operator's. Independently of all three, every signature path refuses a guest DID for ever (GP-SEC-56), so a key re-derived from a pre-destruction backup still signs nothing. | GP-SEC-57, 56 |
| Rotation of the secret | Bump `v`; an optional previous secret serves old records. In v1 nothing needs the key, so losing or rotating the secret breaks no guest. | GP-SEC-53 |

Alternatives weighed. Storing a random key encrypted under the same secret has the same exposure (secret plus dump), plus
ciphertext handling and nonce management, for no benefit. Generating a key and discarding it is the zero-risk variant;
R3 rules it out ("we manage the key"), and it forecloses a claim-time signature if the SDK ever defines one. A hardware
module or KMS is disproportionate for a two-hour key that signs nothing, and becomes the right call only if a future flow
signs with it. For a long-lived registered key it is the right call from the start, which is why R11 uses a different scheme (09 section 4.1).

### 4.2 What the key may and must not sign

| Use | Allowed | Requirement |
|---|---|---|
| The guest's own login assertion on the CAIP-122 path (Path B) | **No**, refused by GP-SEC-56 even though the key could produce it | GP-SEC-54, 56 |
| A server-signed claim challenge (`claim-signed`, see 05 section 3; 01 HK-4) | No: the recommended claim is `claim-authorised` and uses no signature | GP-SEC-54 |
| A delegation or rotation statement that the SDK key-lifecycle work may define, made at claim time | Only if and when the SDK defines one, signed at claim before destruction (GP-SEC-57) | GP-SEC-54 |
| Attestations, claims, evidence revisions, Aqua tree signatures, anything a third party could present as the guest's consent | **Never** | GP-SEC-55 |
| Signing outside the siwx-oidc process, export, operator tooling that signs as a guest | **Never** | GP-SEC-55 |
| The DID assertion in `io.inblock.did` | Not the guest key: the provider key signs it (`src/oidc.rs:2409-2417`, 01 HK-3) | existing |

The consequence for v1 is stark: **the key signs nothing.** The DID is an identifier the operator creates, and the
private half exists only because R3 says the operator manages it.

GP-SEC-52 to 57 are new requirements, written for the derived-key decision (D9) and R3; GP-SEC-58 is a revised requirement (see D9, D3).

| ID | Rule and why | Where | Default | Config | Abuse test |
|---|---|---|---|---|---|
| GP-SEC-52 | **Generation as specified in 4.1.** Why: a fresh key per guest from a CSPRNG keeps localparts unpredictable (01 section 7.4) and stops an attacker grinding toward a localpart. | S | fixed | fixed | Ten thousand mints: no repeated DID or localpart; no key material in the record. |
| GP-SEC-53 | **Derive, never store.** The record holds `key_ref` only. `guest_key_secret` requirements as in 4.1. Why: nothing signable at rest means a stolen dump signs nothing. | S | fixed | secret is config | Inspect every Redis value written by a full flow for the seed and for private-key encodings: none. |
| GP-SEC-54 | **Permitted signing is exactly what the guest login flow requires, which is nothing in v1 (D9).** A future use needs a written requirement naming the statement, who verifies it, and where it is destroyed. Why: an unused signing capability is liability. | S | none | fixed | Code search for a call that derives a guest seed outside the destruction path: none. |
| GP-SEC-55 | **Forbidden uses** (table above) are enforced by construction: no function exposes the derived key to any caller outside the module that derives it. Why: custody without a leash is impersonation. | S | fixed | fixed | Review gate and a test that the derive function has no public caller in v1. |
| GP-SEC-56 | **Every signature-based path refuses a guest DID, for its whole life including after claim and after promotion (deny by record, never by key structure).** That covers Path B of `sign_in` (`src/oidc.rs:2552-2628`), wallet approval on `/device`, signature re-auth on `/account`, and the `siwx` cookie check that opens `link_start` (`src/axum_lib.rs:864`). The rule is one helper: does a guest record (any state, `claimed` included, and promotion never deletes it) exist for `localpart_for(did)`. A claimed guest authenticates through its linked passkey only. After reap the account is deactivated and the deactivation gate (`reject_if_deactivated`, `src/oidc.rs:2673`) refuses. Why: this makes the key useless even to someone who holds it, and closes the operator-key and backup-plus-secret attacks against a claimed account. | S | fixed | fixed | Sign a valid CAIP-122 message with a guest's derived key: 400 or 403 on each of the four paths, before, during and after claim, and after promotion. |
| GP-SEC-57 | **Destruction** as defined in 4.1 (D9): at reap with the record, at the claim commit inside the compare-and-set. The DID does not change (maintainer ruling). Why: a retained key outlives its purpose. | S | fixed | fixed | After reap and after claim: no `key_ref` anywhere in a live Redis keyspace; the DID still resolves to the same account. |
| GP-SEC-58 | **The guest flag is explicit, server side, and travels to those who need it (revised, see D9, D3).** ID token and userinfo of an account that carries the marker, that is an unclaimed guest or a claimed-restricted one, carry `io.inblock.guest: true` (omitted, never `false` or `null`, like `io.inblock.mxid`). The flag derives from the record (present, without `promoted_at`), never from key type or name. A guest DID is a low-assurance identity and downstream systems key on the explicit marker or this flag, never on DID method. Downstream rules in 4.3. Why: a relying party cannot otherwise tell. | S | fixed | fixed | Unclaimed and claimed-restricted guest: flag present. Ordinary user and promoted account: flag absent. |
| GP-SEC-59 | **Method and curve independence.** No rule in this document or in the module branches on `did:key` versus `did:pkh` or on a curve. Why: maintainer ruling. | S, M | fixed | fixed | Run the guest flow with Ed25519 and with P-256 seeds: identical policy outcomes. |

### 4.3 Why a guest DID is a low-assurance identity, and how downstream must treat it

A guest DID is low assurance for six reasons. The operator created it, not the subject. The name and the address are
self-asserted and unverified. The only binding to a person is possession of a link at one moment, which anyone who held
the link could claim. The operator can derive its key. It lives for hours. And a claimed guest keeps it: the DID was born
custodial, and from the moment of a claim nobody can ever sign as that DID again (GP-SEC-56, 57), so the account is
**OIDC-only** for any consumer that requires "a fresh signature by the DID's own key" (identity-model.md, trust model).
Known limitation (D9): the only existing link route requires a signature by the DID key, so a claimed account cannot add a second
passkey until the key-lifecycle roadmap (signed links, rotation) lands. The claim design does not preclude it (05 section 7.2).

| Consumer | Rule |
|---|---|
| Grants and ACLs keyed on a DID | Never implicit. A host-made grant to an unclaimed guest DID dies with the account at reap. After a claim it carries to the claimant, which must be an explicit decision by the granting party, not something siwx-oidc does. |
| Attestations and identity claims | The operator never attests a guest or claimed-from-guest DID on the strength of the redeem event. Assurance comes from an attestation issued after the person was verified by someone who verified them. |
| Evidence and signed artefacts | No valid signature by a guest DID key can exist. A verifier that sees one rejects it. |
| Any system that must treat a guest differently | Key on the explicit marker or the `io.inblock.guest` flag, never on DID method or key structure (D9). |
| Verifiers of `io.inblock.did` | The assertion says the provider bound this DID to this MXID. It says nothing about the person. `attested: true` from `/resolve` is not assurance, for guests or anyone. |
| OIDC relying parties | Tokens of an unclaimed guest reach only the guest client (GP-SEC-34). After a claim the passkey sign-in can reach any client the operator registered, and the tokens carry the flag while the marker is set (GP-SEC-58). A relying party that needs assurance requires attested claims, never "not a guest". |
| Forensics | Until reap the record links guest, invite and host. Afterwards only the `erased:did` hash remains. |

### 4.4 Trust statement: operator and guest

| | The operator can | The operator does not, by design |
|---|---|---|
| Data | Read the guest's names, address, call metadata and, for the life of the record, the IP in proxy logs | Keep names or the address after reap (residues in section 5) |
| Identity | Mint tokens as the guest and act in Matrix as that account (siwx-oidc is the token issuer); re-derive the guest DID key while `key_ref` exists | Sign as the guest in any v1 flow (GP-SEC-54, 56) |
| Media | Serve modified client code that exfiltrates keys from the browser; add a device to the guest account and receive call keys sent to all of its devices (unverified devices are not blocked by default) | Read media at the SFU or on the network when the room is encrypted |
| Room | See who was admitted and when | Decide admission: the host does |

| The guest gets | The guest gives up |
|---|---|
| A bounded session, no key to lose or guard, erasure at the end, the option to claim | Any proof that they were that guest later, except through a claim |
| A marker that tells the host they are a guest | Non-repudiation: nothing signed by the guest DID is theirs |
| A one-click end (withdrawal, GP-SEC-65) | Protection against the operator: E2EE protects against the SFU and the network, not against the party that serves the client and issues the tokens |
| After a claim: a permanent, confined account tied to their own passkey | A second passkey and any recovery until the key-lifecycle roadmap lands: a lost passkey is a lost account |

## 5. Privacy and compliance

This section states facts and options. The lawful basis, the roles of the operator and the host, and any contract are the
operator's decisions with their own advisers. Nothing here is legal advice.

### 5.1 Personal data inventory

| Datum | Where it exists | Readers | Default retention | Erasure |
|---|---|---|---|---|
| First and second name | Guest record in Redis; Synapse profile displayname (with the suffix); member events (knock, invite, join, leave) | Operator, the creating host, every member of the room | Record: until reap; a claimed record keeps names and the consent record for the life of the account (GP-CLM-16). Profile: until erase | Erase clears the profile (`synapse/handlers/deactivate_account.py:168-177`). Historical member events persist but the account's own are censored before it leaves (02 section 6); viewers who were joined keep what they saw |
| E-mail address | Guest record in Redis only | Operator, the creating host (until the claim removes the invite membership) | Deleted at reap; at claim deleted unless the guest explicitly chose to keep it (default remove, D13, GP-SEC-26) | With the record; backups until rotation |
| IP address and user agent | Proxy access log; **Synapse `user_ips` for every authenticated request** (`synapse/api/auth/base.py:400-416`); the SFU and any TURN relay see the address | Operator | Proxy: operator. Synapse: 28 days by default (`synapse/config/server.py:683-685`) | The deactivation handler does not reference `user_ips`; whether device deletion prunes it is Unverified. Set `user_ips_max_age` |
| Device data | `SIWX_` device id, device display name (the client name), device keys | Synapse | Until the account is deactivated | Deleted with devices at deactivation |
| Call media | In transit through the SFU; content hidden from it when the room is encrypted | Participants; operator sees ciphertext | Not stored | Not applicable |
| Recordings and transcripts | Only if an agent is in the room | The agent's operator | The agent's policy | Outside this design (section 5.5) |
| Consent record `{version, variant, at}` | Guest record | Operator | Deleted with the record (`guest_consent_log_retention_secs` default 0); a claimed record keeps it | With the record |
| Guest DID (pseudonymous) | Record, `io.inblock.did` profile field, log lines, `erased:did` (hash only) | Operator, anyone who can read the profile | Hash: for ever | Profile field erased with the profile; hash remains by design (`src/account.rs:787-803`) |

### 5.2 Lawful basis, neutrally

| Option | Fits when | Consequence for this design |
|---|---|---|
| Consent | The guest's participation is voluntary and stands alone | The checkbox of GP-FLOW-20 is the mechanism. Consent must be withdrawable: "End session" is withdrawal and reaps at once (GP-SEC-65) |
| Contract or pre-contractual steps | The meeting is part of a service or a relationship the host already has with the guest | The notice still appears; the checkbox records acknowledgement |
| Legitimate interests | The operator or host has a security or delivery interest that survives a balancing test | Needs a recorded test; the same minimisation applies |

Roles (who is controller, who is processor, whether the operator runs the portal for itself or for a host organisation)
change which paper is needed. The design gives the technical levers, not the contract.

### 5.3 Minimisation and retention

| ID | Rule and why | Where | Default | Config | Test |
|---|---|---|---|---|---|
| GP-SEC-60 | **The inventory above is closed.** The guest record holds exactly: names, optional e-mail (after a claim only if the guest chose to keep it, D13), consent record, the guest DID, invite id, `minted_at`, deadline, state (`minted`, `provisioning`, `active`, `reaping` or `claimed`), device ids, `key_ref`, and after a claim `claimed_at`, `promoted_at`, the claim credential id and its derived `did:key`, and `pre_claim_devices` (random device ids, 05 GP-CLM-26). No phone, no address, no IP, no user agent, no fingerprint, no free text. Why: every extra field is an extra residue. | S | fixed | fixed | Dump the record after a flow, in each state (`provisioning` and `claimed` included): only those fields. |
| GP-SEC-61 | **Consent record and notice.** The notice names the operator, purpose, recipients (the host, the operator), retention (deleted when the session ends), how to withdraw ("End session" in the client, "Delete everything now" on the claim page, GP-SEC-65), the residues of 5.4 and, when the host set `recording_expected` on the invite (frozen at mint), says the meeting may be recorded or transcribed. The record stores `{version, variant, at}`. Why: the notice is shown at the point of collection (GP-FLOW-20) and the recording case changes what the guest agrees to. | S | fixed | text is operator's | Redeem without the flag: no recording line. With it: the line appears and the variant is recorded. |
| GP-SEC-62 | **Retention defaults.** Guest record: until reap, which is at most `session_secs` (ceiling 4 hours) plus retry backoff; a record stuck in `reaping` holds its personal fields until Synapse confirms the erase (alert at 15 minutes, GP-SEC-46); a claimed record lives as long as the account and is deleted with it (GP-CLM-16). E-mail and names: same, except that the e-mail is deleted at the claim commit unless the guest chose to keep it (D13). Consent log: 0. Proxy logs on guest routes: at most 7 days. Application logs: at most 14 days. Synapse `user_ips_max_age`: lowered to at most 7 days where guests exist (it applies to every user). Redis persistence and backups: rotated so a reaped record, and the per-guest key value of a claimed one, leaves them within 7 days. Why: an abuse report arrives within days. | S, O | as listed | operator | Deployment checklist. |

### 5.4 Teardown order, erasure semantics and what stays

Teardown order (D2; 01 section 7.2 carries the mechanics as GP-FLOW-15). The order is the requirement.

| Step | Action | Needs |
|---|---|---|
| 1 | Mark the guest record ended (`reaping`) under compare-and-set | Redis |
| 2 | Revoke the siwx-oidc access and refresh tokens, which stops any new introspection success | Redis |
| 3 | Delete the guest's Synapse device or devices: immediate revocation at Synapse, no two minute cache wait | Synapse |
| 4 | `delete_user` with erase | Synapse |
| 5 | Destroy the key material and the record's personal fields, and sweep any orphan passkey credential listed under the guest DID (GP-CLM-07); the record becomes `reaped` only after steps 3 and 4 are confirmed (GP-FLOW-18) | Redis |

Steps 1 and 2 need only Redis, so a guest loses access even while Synapse is down. v1 performs no active call-state cleanup: no
step acts as the guest to leave the call. The residue is a stale `m.call.member` entry for a deactivated user, accepted for v1 as
cosmetic, with a named mitigation in the plan (the host's client shows the participant as left once the account is gone). An active
cleanup step is a recorded v1.1 option, not a v1 requirement. The window of up to one hour for an OpenID or SFU token after teardown
stays documented (GP-SEC-31) and is gated by P1 and, for production, P2.

Reap runs Synapse erase (02 section 6; 01 section 7). What that does and does not do, stated to the operator and in
the guest notice:

| Removed | Stays |
|---|---|
| Redis record, handle, due entry, names, e-mail, `key_ref` | `erased:user` and `erased:did` markers (the DID as a hash only) |
| Synapse profile and custom profile fields, devices, tokens, account data, pushers, 3PIDs, directory entry | The Synapse `users` row and the consumed localpart, for ever |
| Room memberships (parted and forgotten), pending knocks and invites (rejected) | Historical member events (the account's own are censored at leave), what other participants saw, heard or recorded |
| Nothing in the room timeline, because guests post none (GP-SEC-27) | Uploaded media (none expected, bounded by the controls of GP-SYN-13; a refused upload can leave a file with no database row until the sweep); `m.call.member` state left behind (cosmetic, accepted for v1, D2); Synapse `user_ips` until pruned; proxy and application logs until rotated; Redis append-only file and snapshots until rewritten; LiveKit and TURN logs |

| ID | Rule and why | Where | Test |
|---|---|---|---|
| GP-SEC-63 | **The residues are documented and shown.** The operator guide lists the right-hand column; the guest notice states, in plain words, that the guest sends no messages, so none remain, that other participants may have seen or recorded the call, and that logs are kept for a stated short period. The design never claims full erasure. | S, O | Notice text contains the residue statements; guide checklist item. |

### 5.5 Recording, transcription and withdrawal

| ID | Rule and why | Where | Test |
|---|---|---|---|
| GP-SEC-64 | **An agent in a guest room is a separate processing with its own notice.** The invite carries `recording_expected` (GP-SEC-61). The design claims no technical enforcement that an agent only joins when the flag is set: agent presence is a room membership the host controls. The recording agent must announce itself in the room in a way a guest sees, and delete or hand over its output on its own schedule. Why: honesty about what this design cannot police. | host, agent, O | Checklist item and agent requirements outside this repository. |
| GP-SEC-65 | **Withdrawal is one action (revised, see D18).** The client's "End session" (Bearer token) and the claim page's "Delete everything now" (guest cookie, 05 CL-07) call one endpoint, `POST /guest/end`, which accepts the guest Bearer token or the `__Host-guest_session` cookie (GP-SEC-38, 05 GP-CLM-25); only the label differs by screen. It reaps an unclaimed guest immediately (01 E1) and clears the cookie and the client storage. Closing the tab is not withdrawal and the notice says so. A claimed account has no "End session" and the endpoint answers 409: its withdrawal is the erase action on `/account` with passkey re-authentication, which also deletes the guest record (GP-CLM-16). Why: withdrawal must be as easy as consent. | S, K | End session with the Bearer token, then resume: refused. "Delete everything now" with only the cookie: the same. Record gone within one reaper tick. |

What is explicitly **not** solved here: the choice of lawful basis and any contract; consent of the other participants;
the retention and security of recordings and transcripts; cross-border transfer for the SFU or relay hosting; children;
access and portability requests that reach into other participants' copies of the room; a DPO's or regulator's
position; Synapse retention for deactivated users (upstream issue 20014).

## 6. Limitations, non-goals, residual risks, test plan

### 6.1 Limitations v1 must enforce, and non-goals

| L | Limitation | GP-SEC ids |
|---|---|---|
| L-01 | Hosting is deny by default through an allow-list; invites are single-use and recipient-bound, a reusable link is a capped opt-in | 01, 10, 11 |
| L-02 | Quotas (per invite, host, deployment, day, claim, device) are counted in process; cleanup backlog brakes minting | 02, 03, 05 |
| L-03 | The link secret never reaches a log, a Referer or a scanner-burnable state; every failure is uniform | 09, 12, 13, 44 |
| L-04 | A guest sees, says and writes nothing in Matrix beyond call state; name and avatar are frozen and marked | 19, 20, 27 |
| L-05 | A guest reaches exactly one room, in Matrix and on the SFU (P1 is a hard dependency) | 28, 29, 30, 31 |
| L-06 | The deadline holds in four layers and survives the feature flag | 32, 33, 49 |
| L-07 | Claim needs admission, revokes old tokens per device, keeps the marker and the confinement, and is authorised by the issuer-origin cookie | 35 to 38 |
| L-08 | The guest key is derived, signs nothing, is refused on every signature path and is destroyed at reap and claim | 52 to 57 |
| L-09 | The e-mail is optional by default, syntax-checked, unverified everywhere, deleted at reap and, at claim, unless the guest chooses to keep it, never mailed | 21 to 26 |
| L-10 | Guest pages carry security headers, JSON only, `Origin` and fetch-site check, `__Host-` Lax cookie, no open redirect | 39 to 43, 67 |
| L-11 | Logs carry no personal data; retention is stated | 44 to 47, 62 |
| L-12 | One operator switch stops minting, and one epoch reaps everything, with Synapse down | 48 |
| L-13 | The notice and withdrawal exist and state the residues | 61, 63, 65 |
| L-14 | The enforcing marker is written fail closed by the mint path and is never cleared by a claim | 66, 37 |
| L-15 | A pending knock is visible to the host | 68 |

Non-goals of v1:

| NG | Non-goal |
|---|---|
| NG-01 | Verifying who the guest is (no identity proofing, no KYC, no e-mail verification) |
| NG-02 | Protecting guests from the operator, or the host from the operator |
| NG-03 | Preventing a participant from recording the call |
| NG-04 | Federation of guest rooms |
| NG-05 | Guest-to-guest or guest-to-host messaging, chat history, persistent guest content |
| NG-06 | Agent or bot guests (human versus agent is the job of attested claims) |
| NG-07 | A hard stop of an already connected SFU participant (waits for lk-jwt PR 235 or an equivalent) |
| NG-08 | Anti-automation beyond secrets, quotas, admission and proxy limits (section 7) |
| NG-09 | Second devices for one guest, post-call claim by e-mail, hand-over secrets |
| NG-10 | An account-admission policy for the homeserver (F1) |
| NG-11 | A second passkey for a claimed account, and any recovery of a lost one (known limitation until the key-lifecycle roadmap lands, D9) |
| NG-12 | Active call-state cleanup as the guest at teardown (a recorded v1.1 option, D2) |

### 6.2 Residual risks we accept

| RR | Risk | Owner role | Review trigger |
|---|---|---|---|
| RR-01 | SFU token and connected participant survive removal (up to the token lifetime), noise only in an E2EE room | lk-jwt and Synapse maintainers | lk-jwt PR 235 or LiveKit revocation lands; before production |
| RR-02 | Impersonation by a common real name that is neither reserved nor a lookalike of the host | host, product owner | first reported incident; a change to client disambiguation |
| RR-03 | The operator can read guest data and act as a guest session | operator | any third-party operator or multi-tenant deployment |
| RR-04 | A token stolen from a guest browser is usable until the deadline (at most 4 hours) | siwx-oidc maintainers | a reported XSS in the client |
| RR-05 | A guest left logged in on a shared computer can be continued or claimed by the next user within the deadline | product owner | a kiosk use case |
| RR-06 | A host admits the wrong person | host | repeated reports; a host-side admission panel showing link labels |
| RR-07 | A mail scanner holds a copy of the secret | host, communications owner | scanner behaviour change; a move to e-mail delivery of links |
| RR-08 | One Synapse row per guest for ever, plus two small Redis keys | operator | row count above an operator threshold; Synapse issue 20014 |
| RR-09 | Backups, `user_ips` and logs hold personal data beyond reap | operator, data-protection owner | a change of retention policy; a data-subject request |
| RR-10 | Guest confinement is not a perimeter because accounts are open to any valid proof (F1) | siwx-oidc maintainers | any account-admission policy is introduced |
| RR-11 | The design depends on experimental upstream pieces (MSC4502 and MSC4512 appservice mode, `user_type` modification, `check_event_allowed` on knock) | Synapse and lk-jwt maintainers | each Synapse, lk-jwt or Element Call upgrade |
| RR-12 | Login CSRF can put a victim into an attacker's meeting | client maintainers | a change in how the hand-off works |
| RR-13 | To-device and verification-request spam from a guest to a host | Synapse maintainers | upstream hook for to-device messages |
| RR-14 | Legacy wallet-derived MXIDs can be probed for existence | siwx-oidc maintainers | MSC4263 stabilises |
| RR-15 | A stale `m.call.member` entry for a deactivated guest stays in the room state | Synapse and client maintainers | a host-side "left" display is built, or an active cleanup step is adopted |
| RR-16 | A claimed account cannot add a second passkey, so a lost passkey loses the account | siwx-oidc maintainers, SDK key-lifecycle owner | the key-lifecycle roadmap delivers signed links or rotation |
| RR-17 | In the `cross-site` topology (`guest_client_topology`), a third-party page can trigger silent hand-offs for a guest with a live cookie, bounded by the device cap and the per-record rate; the default `same-site` topology refuses such a navigation (D19) | siwx-oidc maintainers | a change in cookie semantics or in the hand-off design; an operator choosing `cross-site` |

### 6.3 Security test plan

Levels: **U** unit (`src/guest.rs` tests and `tests/`, `cargo test`), **M** mock-stack end to end (`tests/e2e_guest_*.rs`, `#[ignore]`,
`e2e/synapse_mock.py` updated in the same change, `--test-threads=1`), **B** browser end to end (`e2e/browser/`), **L** live Synapse on
dev (and the module's own repository for module tests, `E2E_STRICT_SKIPS=1`), **D** deployment check script under `scripts/`.
Per AGENTS.md every test must be able to fail: assert the positive case, and make skips loud.

| Test | What it proves | Level | GP-SEC ids |
|---|---|---|---|
| ST-01 | Host allow-list: empty list refuses startup; unlisted token 403 | U, M | 01 |
| ST-02 | Each quota ceiling refuses exactly at its number, atomically under 50 concurrent calls | M | 02, 05 |
| ST-03 | Stuck erase brakes minting, recovery releases it; ending a meeting of `guest_max_guests` guests against a healthy mock never trips the brake | M | 03 |
| ST-04 | Proxy burst on every row of the proxy table (15 redeems, 429 after the burst; the `peek`, host list, host end, context, ended and media upload rows included); 5 KiB body 413 on a guest route; a 17 KiB body 413 on claim finish, which accepts a worst-case credential id | D | 04 |
| ST-05 | Guest, admin and unlisted tokens cannot mint; kill switch blocks mint | M | 06, 48 |
| ST-06 | Hostile `room_id` values never reach Synapse; cross-host IDOR 404 | U, M | 07 |
| ST-07 | Skewed instance clocks: one deadline | M | 08 |
| ST-08 | Unknown id, wrong secret, malformed body: identical bytes | U | 09, 13 |
| ST-09 | Only `single` by default; `open` refused; flag on: use cap, expiry clamp and one open link per host hold; bulk create with labels; 72 hour clamp | U | 10, 11 |
| ST-10 | Script-executing headless browser loads the link with fragment: no mint | B | 12 |
| ST-11 | Revoke one link, end the meeting, reap the guests | M | 14 |
| ST-12 | Markup and labels escaped on host-facing pages | B | 15 |
| ST-13 | Name vectors (markup, DID shape, marker, zero width, bidi, digits, mixed script, reserved, lookalike of the host) | U | 16 to 18 |
| ST-14 | First sign-in profile carries the suffix; rename and avatar changes reverted; per-room name frozen; a knock `reason` and unknown content keys are dropped from the stored member event | L | 19, 20 |
| ST-15 | E-mail: required, off, syntax vectors, no DNS query, absent from tokens, userinfo, profile, mock bodies and logs | U, M | 21 to 23 |
| ST-16 | No SMTP client in the dependency tree or config | U | 24 |
| ST-17 | Same address twice; identical answers; reap deletes it; claim deletes it unless `keep_email` is true (default false); another host sees nothing | M | 25, 26 |
| ST-18 | Guest posts a message, an encrypted event, a reaction, a redaction: all refused; the call still connects | L | 27 |
| ST-19 | Mint into a room missing each template item, on room versions 10, 11 and 12 (a v12 room whose creator is the host, with an empty `users` map, passes; a foreign `additional_creators` entry is refused); weaken the room after mint, then admit as an ordinary host and as a server admin: refused | M, L | 28, 29 |
| ST-20 | Deployment check reads each posture line as a guest and as an operator | D | 30 |
| ST-21 | Non-member `get_token` 403; host removes an ex-guest, who cannot decrypt new media; old OpenID token refused | L | 31 |
| ST-22 | Reaper stopped: refresh after deadline refused; `reap_before` reaps with Synapse down | M | 32, 48 |
| ST-23 | Session bounds and monotone deadline | U | 33 |
| ST-24 | Guest cookie for a foreign client or redirect: no code; a dynamic client that shares the Meet client's exact redirect URI: no code; under `same-site`, a navigation marked `cross-site` is refused | M | 34 |
| ST-25 | Claim before admission, after host removal, at the cap, concurrently with reap; old refresh token refused after claim, also after a crash between the compare-and-set and the revocation, while a passkey sign-in straight after works and refreshes (no user tombstone); marker and confinement after claim; promotion clears the marker and keeps the record; a code minted before the claim is refused at exchange; a pre-claim device id proposed at login is refused; a repeated finish in parallel leaves one credential and one claimed account; a finish naming an existing credential id is refused and deletes nothing | M, L | 35 to 37 |
| ST-26 | Claim with only a Bearer token refused; from a foreign origin the WebAuthn ceremony fails; `POST /guest/end` with only the cookie ends an unclaimed guest, is refused from a foreign origin and answers 409 for a claimed account | M, B | 38 |
| ST-27 | Headers on every guest route; framed page does not render; injected inline script blocked | B | 39, 43 |
| ST-28 | Sibling origin: credentialed fetch and form post to each state-changing route have no effect; foreign `Origin` refused; a request with neither `Origin` nor `Sec-Fetch-Site` refused; a cross-site top-level navigation to each GET route changes nothing; a Bearer `POST /guest/end` from the Meet origin is accepted | B | 40 |
| ST-29 | Cookie attributes (`__Host-`, Secure, HttpOnly, Lax, Path=/); sibling-planted cookie ignored; no handle in Redis key names | M, B | 41 |
| ST-30 | Foreign and `http` redirects, redirect named in redeem: refused | M | 42 |
| ST-31 | Full flow with sentinel strings: none in logs; for each call of the GP-SEC-45 table (one test per call) a Synapse failure whose body echoes the name leaves only status and errcode in the log and in the returned error | M | 44, 45 |
| ST-32 | Each alert condition produces its event | U | 46 |
| ST-33 | Flag off with a live overdue record: reaped | M | 49 |
| ST-34 | Deleted record: the orphan scan reports and erases nothing | L | 50 |
| ST-35 | Startup refusals, one per missing item (`guest_client_id` and `did:key` in the methods list included); the Redis warnings for an evicting policy and for a server older than 5 | U | 51 |
| ST-36 | Ten thousand mints: unique DIDs; no key material in any Redis value | U | 52, 53 |
| ST-37 | Signature with a guest key refused on Path B, device approval, account re-auth and `link_start`, before, during and after claim | M | 56 |
| ST-38 | After reap and claim no `key_ref`; the DID is unchanged | M | 57 |
| ST-39 | The guest flag is present for unclaimed and claimed-restricted accounts, absent for ordinary and promoted ones | U | 58 |
| ST-40 | Identical policy outcomes for an Ed25519 and a P-256 guest key | U | 59 |
| ST-41 | Record dump holds only the closed field list; notice variants and consent record | U, B | 60, 61 |
| ST-42 | End session reaps within one tick and clears the cookie and storage; "Delete everything now" with only the cookie does the same | M, B | 65 |
| ST-43 | Mock Synapse refusing the marker write: no device and no code, the next hand-off retries, an abandoned account is reaped; a guest token cannot change `user_type` | M | 66 |
| ST-44 | Nine silent completions in a minute for one record: at most three devices, the rest `temporarily_unavailable`; under `same-site` a navigation marked `cross-site` creates none | M | 67 |
| ST-45 | A pending knock shows the canonical name and no e-mail, secret or label | B | 68 |
| ST-46 | Retention: the deployment checklist carries the lines for proxy and application log retention, `user_ips_max_age` and backup rotation and reads the settings it can; a snapshot taken before a reap leaves rotation within 7 days | D, O | 47, 62 |
| ST-47 | No call site derives a guest seed outside the destruction path, and the derive function has no public caller (a source check that fails when a `pub` caller appears) | U | 54, 55 |
| ST-48 | The guest notice contains the residue statements (no messages remain, others may have seen or recorded the call, logs are kept for a stated period) and, when the invite sets `recording_expected`, the recording line; the operator guide carries the residue list and the requirement that a recording agent announces itself | U, B, O | 63, 64 |

Acceptance mapping for the requirements R2 and R3. 07 section 1.4 carries them as acceptance rows A7 and A8; the test rows above
are what those rows point at.

| Criterion | GP-SEC ids | Passes when |
|---|---|---|
| R2: the e-mail is optional by default and an operator can enforce it | 21 to 26 | ST-15 (`required` without an address and `off` with one answer 422, the syntax vectors, the address absent from tokens, userinfo, profile, mock bodies and logs) and ST-17 (the same address twice, deleted at reap and at claim unless `keep_email` is true) pass in each of the three modes `off`, `optional` and `required` |
| R3: the operator manages the key, which is derived, not stored, and destroyed | 52 to 57 | ST-36 (no key material in any Redis value), ST-47 (no seed derived outside the destruction path, no public caller), ST-37 (every signature path refuses a guest DID) and ST-38 (no `key_ref` after reap or claim, the DID unchanged) pass |

## 7. Question every requirement

| Candidate | What was tried | Outcome |
|---|---|---|
| E-mail field (R2) | Delete it | R2 requires it, so it stays optional by default. Deleted instead: verification, outbound mail, use as a claim factor or recovery, retention after reap, any copy outside the record (Synapse 3PID, profile, claims). The only v1 purposes left are the host seeing it and, on the guest's own choice at claim, notices to the permanent account (D13). Operators who do not need that should set `guest_email = off`. |
| Reusable "open" link | Replace with per-recipient single-use links created in bulk | Replaced as the default (D6). An open link survives only as a config-gated opt-in, off by default, with a hard use cap, an expiry ceiling and mandatory knock admission. The gain is attribution, per-person revocation, and the end of forwarding amplification. |
| Refresh token for guests | Access-only with a long TTL | Refresh stays, but for code-path reuse, not for security: a long access token and a refresh token have the same theft exposure, and a long access TTL needs a guest marker on every token construction site (01). |
| Anti-automation at v1 | Captcha, proof of work, none | None. A bot needs a valid secret, and mint is bounded by per-invite, per-host and global caps, a daily ceiling and human admission. Proof of work is deferred behind a trigger (7.1 comparison below). |
| Stored custodial key | Delete it | R3 keeps custody, but nothing signs in v1: the key is derived, not stored, and destroyed at reap and claim. |
| Guest marker as a profile field (01 open decision 5) | Keep it beside `user_type` | Deleted (D1): two markers that can disagree are a defect. `user_type` is admin-write only without a Synapse patch and invisible to clients, and orphans are findable by it. |
| Per-guest device cap (deleted in 01) | Keep it deleted | Reinstated as one integer on the record (GP-SEC-05). |
| In-process per-IP rate limiter | Add one | Not added (AGENTS.md convention). In-process **quotas** are kept because they are invariants, not shaping. |
| An HTTP admin endpoint for the kill switch | Add one | Not added. Three Redis values do the job with no new surface (GP-SEC-48). |
| Consent checkbox | Replace with a notice | Kept: the conservative default, and a bot must tick it. |
| Host list | Skip it, rely on the room audit | Kept, and deny by default (D5). The audit proves a room is safe, not that the host is entitled to open it to strangers. |
| Opt-out `guest_hosts_any` (any account may host) | Keep it, default off, logged at `warn` | **Deleted from v1 and listed here as a rejected option (D17).** siwx-oidc opens an account for any valid proof (F1), so "any account may host" means "anyone may host", which is the state D5 exists to remove. A switch that restores it in one line of configuration is a footgun, and a closed deployment loses nothing by listing its few hosts in `guest_hosts`. The maintainers may overrule this (open decision 1). |
| Claim lifts confinement (02) | Keep it | Reversed (D3, GP-SEC-37). Removing the lift is less code than adding a promotion path. Deleted with it: the `guest_claim_promotes` switch, because promotion is never a side effect of claiming. |
| Call-state cleanup as the guest (02 GP-SYN-09) | Keep it | Dropped from v1 (D2): a new privileged primitive for a cosmetic gain. A recorded v1.1 option. |
| Keep pre-claim tokens alive at claim (02) | Keep them so the call continues | Rejected (D3): a stolen pre-claim refresh token would become a permanent credential. Per-device revocation is cheaper than a second guard, and the claim is offered after the call. |
| E-mail on the claimed record | Delete it always at the commit, or keep it by default | Kept only on the guest's explicit opt-in (D13, GP-SEC-26): one choice at claim, default remove. Always deleting is simpler but gives up a contact address for notices to a permanent account; keeping by default would leave an unverified address on an account whose owner never chose that. |
| Full directory-wide confusable check | Add it | Not added: needs a directory. The host lookalike and the reserved list cover what the host sees. |
| Digits and emoji in names | Allow | Refused: they enable `Support2`, `Host 1`, fake markers. |
| Invite id separate from secret | Merge into one secret | Kept split: the request path is logged (`src/axum_lib.rs:1542-1548`). |
| Encrypt names and e-mail inside Redis | Add field-level encryption | Not added: Redis already holds passkeys, tokens and every session, so it is one trust zone. The operator secures Redis (network isolation, ACL, TLS, disk encryption); GP-SEC-60 keeps the field list closed. |
| A guest-only mode for body-free Synapse logs | Keep bodies for ordinary users, hide them for guests | Not added: one shared body-free helper for every caller (status plus errcode). A mode switch means plumbing a flag through more than a dozen methods for a debugging convenience, and the guest path reaches most of them. |
| Logging DIDs on the guest path | Stop | Left to section 5: a pseudonymous id that the guest record explains only while it exists. |

### 7.1 Anti-automation options compared

| Option | Privacy | Dependency and cost | Effect here | Verdict |
|---|---|---|---|---|
| None beyond secret, quotas, admission, proxy limits | None | None | Mint needs a valid secret; damage bounded by caps | **v1** |
| Self-hosted proof of work (adaptive) | None | Script on the issuer page; battery and delay for real guests; no third party | Slows bulk redeem; does not stop a valid link holder or a stolen host token | Deferred. Trigger: open links enabled, or redeem refusals with valid ids above a daily threshold |
| Third-party captcha | Address and browser fingerprint go to a third party, a new processor, extra consent text | External service; CSP widened; accessibility cost | Same as proof of work, with more leakage | Rejected |

## 8. Cross-document consistency

Concerns that more than one document touches, the rule that settles each, and the requirement IDs that carry it. `D<n>` is a
decision of the [decisions log in the overview](00-overview.md#7-decisions-log), still open for the maintainers.

| Id | Concern | Rule | Decision | Carried by |
|---|---|---|---|---|
| CDF-01 | How a guest is marked on the homeserver, so that the module confines guests and never ordinary users, and the marker write fails closed. | One enforcing marker, `user_type = io.inblock.guest`, written by the mint path right after `provision_user` and before the first token; a failed write means no token and the reaper cleans the account. There is no second marker. Unmarked users are not touched by the module. The marker means confined identity and a claim does not clear it. | D1 | GP-SEC-66, 19, 20, 49, 50; GP-SYN-07 |
| CDF-02 | The order of teardown, and whether call state is cleaned by acting as the guest. | The order of section 5.4. No active call-state cleanup in v1; the stale `m.call.member` entry is an accepted, named residue; the confined cleanup variant is a v1.1 option (open decision 6). | D2 | Section 5.4, GP-SEC-31, 32, 63, RR-15; GP-FLOW-15; GP-SYN-09 |
| CDF-03 | What a claim changes: a claim that lifted confinement or kept pre-claim tokens would make a stolen token permanent. | Claim keeps the marker and confinement; admission gate; per-device revocation, never `revoke_all_user_tokens`; promotion is an operator act; the record state `claimed` is distinct from the marker. | D3 | GP-SEC-06, 35 to 38; GP-CLM-04, 05, 08, 11, 20, 23, 24; GP-FLOW-04, 16; GP-SYN-07, 10 |
| CDF-04 | The content of the call room template. | Encryption enforced, a restrictive `events_default`, `m.federate: false`, the flag, neutral metadata, the room created by the host's client, and a host-visible knock notice. | D7 | GP-SEC-28, 29, 68 |
| CDF-05 | Display name: a Matrix-side rename bypasses every name rule kept in siwx-oidc, and no module hook vetoes a profile change. | Seed with the tag, fix the canonical name by admin write at mint, deny profile changes by marked users. The mechanism is a dev spike with the fallback stated. | D8 | GP-SEC-19, 20 |
| CDF-06 | Messages from guests, which Synapse does not restrict on its own. | The module denies every non-state event of a marked user by default. | none needed | GP-SEC-27 |
| CDF-07 | The number of devices a guest may hold. | A device cap per record, plus a per-record rate on the silent hand-off. | none needed | GP-SEC-05, 67 |
| CDF-08 | Who may host, link kind, link lifetime. | Deny-by-default allow-list with no opt-out; single-use default with a capped reusable opt-in; ceiling 72 hours. | D5, D6, D17 | GP-SEC-01, 02, 10, 11 |
| CDF-09 | Cookie attributes and the hand-off: a Strict cookie scoped to `/guest` would not be sent on the cross-site redirect into `/authorize`. | `__Host-guest_session`, Secure, HttpOnly, Lax, `Path=/`; silent hand-off with PKCE and `prompt=none`; JSON only with an `Origin` and `Sec-Fetch-Site` check. The `siwx` cookie is set by JavaScript and is not HttpOnly. The default topology is same-site, and the marker branch of `/authorize` refuses a navigation marked `cross-site`. | D4, D19 | GP-SEC-34, 38, 40, 41, 67; GP-CLM-01, 12, 25 |
| CDF-10 | Whether the reaper stops when the feature flag is off. | The reaper runs whenever guest records exist. | none needed | GP-SEC-49 |
| CDF-11 | How long a revoked access token keeps working. | 01 section 7.3 states the bound (expiry is enforced per request, the 2 minute cache delays only revocation); no design change and no requirement. | none (incidental) | Validation status |
| CDF-12 | Two host lists (siwx-oidc and the module) can drift. | The mint-time audit requires the room flag's sender to be in `guest_hosts`, so one list governs both sides and the module list may only be broader. | D5 | GP-SEC-01, 28 |
| CDF-13 | Telling a guest that an agent may record. | The notice names recording; an agent is a separate processing. | none needed | GP-SEC-61, 64 |

Rules that this document and [05](05-claim-flow.md) state identically, so either can be read alone:

| Topic | Here | In 05 |
|---|---|---|
| Confinement after a claim, promotion | GP-SEC-37, section 3.5 | GP-CLM-08, 20, 24; sections 5.3, 5.5 |
| Record states | table after GP-SEC-38 | section 5.1 |
| Claim gate | GP-SEC-35 | GP-CLM-04 (CP-01 to CP-12) |
| Token revocation at claim, including the keyspace scan and the pre-claim device ids | GP-SEC-36 | GP-CLM-11, 23, 26; section 4.3 |
| Cookie authority for `POST /guest/end` | GP-SEC-38, 65 | GP-CLM-25; CL-07 |
| Claim cookie and CSRF | GP-SEC-38, 40, 41 | GP-CLM-01, 12 |
| Key destruction and its limits | GP-SEC-56, 57, section 4.1 | GP-CLM-10; section 5.2 |
| E-mail at claim | GP-SEC-26 | GP-CLM-05, 16; 05 section 5.6 |
| Prerequisites P1 to P4 | section 0.1 | the table after the terms |

Incidental findings ([D12](00-overview.md#8-incidental-findings-d12)) that this document owns: siwx-oidc sets no security headers at all (GP-SEC-39, open decision 11); code
exchange consults no tombstone for any user (GP-FLOW-14, open decision 11); Element Call's default rooms let a joined guest rewrite
join rules (GP-SEC-28). The others are listed in the same section of the overview and kept by the documents that own them.

## Validation status

| Claim | Evidence | Status |
|---|---|---|
| siwx-oidc sets no security headers | grep of `src/` and `static/` for `frame-ancestors`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`: no hits | Verified (absence) |
| The request log records method and path only | `src/axum_lib.rs:1542-1548` | Verified |
| CORS allows any origin, GET, POST, OPTIONS, content-type and authorization, no credentials | `src/axum_lib.rs:1569-1577` | Verified |
| Wallet and headless sign-ins create the account directly; the passkey login asks one confirmation | `docs/passkeys.md:164-182` | Verified |
| `revoke_all_user_tokens` plants the 900 s user tombstone, and refresh refuses any token of a tombstoned user | `src/db/redis.rs:281-309`, `src/oidc.rs:976-984` | Verified |
| `revoke_device_tokens` deletes the indexed tokens of one device and plants a 900 s tombstone for that device id only; refresh refuses a revoked device | `src/db/redis.rs:212-245`, `src/oidc.rs:976-984` | Verified |
| `revoke_device_tokens` ends with a keyspace scan as a backstop, and `set_token` writes the token index with separate `SET`, `SADD` and `EXPIRE` commands, so the index is advisory | `src/db/redis.rs:247-251, 934-953` | Verified |
| `logout_all` ends in `revoke_all_user_tokens`, which plants the 900 s user tombstone | `src/compat.rs:322-324` | Verified |
| `resolve_device_id` accepts any client-proposed device id; `POST /register` checks only that a redirect URI has no fragment | `src/oidc.rs:2058-2063, 2775-2780` | Verified |
| The refresh path's post-mint revocation probe fails open on `Indeterminate` | `src/oidc.rs:1029-1047` | Verified |
| Synapse skips `user_may_invite` when the inviter is a server admin | `synapse/handlers/room_member.py:895-925` | Verified |
| The `siwx` cookie is set by JavaScript, so it is not HttpOnly | `js/ui/src/App.svelte:176-180` | Verified |
| The `session` cookie is HttpOnly and SameSite=Strict; `siwx_user` is Path=/, HttpOnly, SameSite=Strict | `src/oidc.rs:1681-1689`, `src/axum_lib.rs:942-952` | Verified |
| `link_finish` consumes stored challenge state and does not re-verify the DID; `link_start` verifies the `siwx` cookie | `src/webauthn.rs:905-949`, `src/axum_lib.rs:850-898` | Verified |
| `provision_user` sends only the localpart and the display name | `src/synapse_client.rs:468-480` | Verified |
| The provisioning failure path logs the upstream body, and so do more than ten other `SynapseClient` failure paths, most of them reachable from the guest flow | `src/synapse_client.rs:485, 521, 557, 581, 631, 748, 792, 864, 994, 1006, 1041, 1109, 1165, 1204, 1355, 1370, 1385, 1401, 1560` (`grep` of `%body`) | Verified |
| siwx-oidc can mint itself an admin credential and does so in process | `src/admin_token.rs` module doc | Verified |
| A token's granted scope is fixed at issuance | `src/oidc.rs:1464-1475` | Verified |
| The headless client builds Ed25519 keys from a 32-byte seed | `siwx-oidc-auth/src/lib.rs:111-131` | Verified |
| `io.inblock.did` content is world-readable and can federate | `docs/identity-model.md:291-295` | Verified |
| No module hook vetoes a global profile change; `ModuleApi.set_displayname` exists and no avatar setter was found | `synapse/handlers/profile.py:294,417`, `synapse/module_api/callbacks/third_party_event_rules_callbacks.py:487`, `synapse/module_api/__init__.py:2018` | Verified (by reading; absence of an avatar setter by search) |
| `user_type` is the last field applied by the admin modify request | `synapse/rest/admin/users.py:470-471` | Verified |
| Erase removes custom profile fields | `synapse/handlers/deactivate_account.py:168-177` | Verified |
| Synapse records client IP and user agent per authenticated request, pruned after 28 days by default | `synapse/api/auth/base.py:400-416`, `synapse/config/server.py:683-685` | Verified |
| Deactivation removes `user_ips` rows | handler has no reference to `user_ips` | Unverified |
| Under delegated auth 3PID add and delete, password and C-S deactivate are not registered; bind answers 404 | `synapse/rest/client/account.py:914-935`, `:622-623` | Verified (by reading, not run) |
| A first cross-signing upload needs no UIA; a replacement needs the IdP to mark the master key replaceable | `synapse/rest/client/keys.py:529-548` | Verified (by reading, not run) |
| Display names are capped at 256 characters in Synapse | `synapse/handlers/profile.py:63,264-266` | Verified |
| The admin user list rows carry `user_type`; the server-side filter only excludes types, and `not_user_type` set to the empty string excludes untyped users | `synapse/storage/databases/main/__init__.py:265-267,319`, `synapse/rest/admin/users.py:167`, `docs/admin_api/user_admin_api.md:259-261,280` | Verified |
| Synapse has an admin endpoint for the joined members of a room (the admission read) and siwx-oidc has only a private admin request helper today | `synapse/rest/admin/rooms.py:492`, `src/synapse_client.rs:445` | Verified (a public room-members method is new code) |
| The OpenID token lifetime is a fixed one hour | `synapse/rest/client/openid.py:72` | Verified |
| Element Call's own rooms set `state_default: 0` and `events_default: 0` | `ec/src/utils/matrix.ts:227-260` (Element Call v0.26.1) | Verified |
| lk-jwt fixes the LiveKit token lifetime at one hour with no configuration | `lk-jwt/src/handler.rs:70` (`with_ttl(Duration::from_secs(60 * 60))`; no other TTL in `src/*.rs` but the federation URL cache) | Verified |
| `SameSite` (Lax or Strict) does not stop a same-site sibling origin, and a JSON POST from it needs a preflight that `ACAO: *` cannot satisfy for credentials | browser and CORS semantics | Unverified (test ST-28) |
| A `SameSite=Lax` cookie is sent on a cross-site top-level GET navigation and withheld on a cross-site POST or fetch | browser semantics | Unverified (tests ST-28, ST-29, spike S4 of 03) |
| A `__Host-` cookie cannot be planted by a sibling subdomain | cookie prefix semantics | Unverified (test ST-29) |
| A navigation from the Meet client to `/authorize` carries `Sec-Fetch-Site: same-site` when both share a registrable domain, and `cross-site` from a third-party page | browser semantics | Unverified (spike SP-1 of 07, tests ST-24, ST-44) |
| axum `Json` rejects non-JSON content types | library behaviour | Unverified (test ST-28) |
| Element Call works when a guest may send no room events | not run | Unverified (spike S1 of 03) |
| Script-executing scanners cannot submit the redeem form | reasoning | Unverified (test ST-10) |
| `provision_user` accepts an optional `set_emails` list that siwx-oidc never sends | `synapse/rest/synapse/mas/users.py:114,161`, `src/synapse_client.rs:468-480` | Verified |
| A revoked access token stays usable for "300 s plus the 2 minute cache" | 02 C3 | Contradicted by 02 C3; 01 section 7.3 states it correctly (section 8, CDF-11) |
| A profile-field marker beside `user_type` | 01 P7 and open decision 5 against 02 GP-SYN-07 | Contradicted, resolved by D1 (section 8) |

## Open decisions

A decision marked `Recommendation adopted (D<n>)` is settled in the document set by the decision of that number. Each
decision stays listed in the [decisions log in the overview](00-overview.md#7-decisions-log), so the maintainers may still overrule it.

1. **Host gate.** Recommendation adopted (D5, D17): deny by default, non-empty `guest_hosts` required, no opt-out: the opt-out `guest_hosts_any` is not in v1 and is recorded as a rejected option (GP-SEC-01, section 7). **Still open, for the maintainers:** whether an attested host claim joins the allow-list once the identity-claims work provides one, and whether to overrule the deletion (recommendation: no).
2. **Link kind and lifetime.** Recommendation adopted (D6): single-use, recipient-bound, bulk create; `open` is an explicit opt-in, off by default, capped in uses and expiry, with knock admission always on; ceiling 72 hours (GP-SEC-10, 11). Remaining for the maintainers: whether v1 ships the reusable variant at all. Recommendation: no, single-use first.
3. **What claim means.** Recommendation adopted (D3): admission gate, per-device token revocation, marker and confinement stay, promotion is an operator act (GP-SEC-35 to 37). 02 GP-SYN-07 and GP-SYN-10 follow it.
4. **Key custody form.** Recommendation adopted (D9): derived from `guest_key_secret` and a per-guest random value, Ed25519, `key_ref` only, destroyed at reap and at the claim commit, with "destroyed" defined in 4.1 (GP-SEC-52 to 57). Alternative in one line: store a random key encrypted under the same secret; same exposure, more code.
5. **Signature paths and the guest flag.** Recommendation adopted (D9): every signature path refuses guest DIDs for life, promotion included; `io.inblock.guest: true` in the tokens of every marked account (GP-SEC-56, 58).
6. **Call-state cleanup as the guest.** Recommendation adopted (D2): drop it from v1 and accept the stale `m.call.member` entry (section 5.4, RR-15). If the maintainers want it later, use the confined variant: only for device ids in the guest record, token lifetime at most 60 s, only in state `reaping`, one audit event, never blocking the erase.
7. **Event allow-list.** Recommendation: deny all non-state events from guests (GP-SEC-27); confirm with spike S1 of 03 that Element Call needs none. If reactions or raise-hand are wanted, widen `guest_allowed_event_types` knowingly.
8. **Mandatory E2EE and the media tail.** Recommendation adopted (D7, D11): enforce `m.room.encryption` at audit (GP-SEC-28); P1 before any guest exists; P2 (SFU eviction and a short SFU token lifetime, 10 minutes) before production, not before dev (GP-SEC-31).
9. **Device cap.** Recommendation: reinstate, default 8 (GP-SEC-05), with the per-record hand-off rate of GP-SEC-67.
10. **Cookie and topology.** Recommendation adopted (D4, D19): `__Host-guest_session`, `Path=/`, `Lax`, plus the `Origin` and `Sec-Fetch-Site` check (GP-SEC-40, 41), and a same-site default topology (client and issuer share a registrable domain) in which the marker branch of `/authorize` refuses a navigation marked `cross-site` (`guest_client_topology`, GP-SEC-34). `Path=/guest` could not cover `/authorize`, and Strict is not sent on a cross-site hand-off, which operators of the `cross-site` topology need.
11. **Security headers.** Recommendation: set them in the application for guest routes (GP-SEC-39), and raise a separate change for the existing pages, which have none. Also land GP-FLOW-14 (code-exchange tombstone check) separately, as 01 already recommends (D12), with both tombstones probed with the code's device id, the recheck after the mint with rollback, and the effect of `logout_all` (the user tombstone now also refuses a code exchange) stated.
12. **Name policy and canonical name.** Recommendation adopted (D8) for the mechanism: the canonical-name mechanism of GP-SEC-20 (marker first, name second, module records the admin write and denies profile changes by marked users), with a dev spike before anything else depends on it and the stated fallback. The maintainers decide whether refusing digits and mixed scripts (GP-SEC-16, 17) costs too many real names; the operator-configurable reserved list is the safer place to add exceptions.
13. **Retention numbers.** Recommendation: proxy logs 7 days, application logs 14 days, `user_ips_max_age` 7 days where guests exist, backups rotated within 7 days (GP-SEC-62). `user_ips_max_age` affects every user of the homeserver, so the operator decides.
14. **Recording notice.** Recommendation: a `recording_expected` flag frozen on the invite and shown in the notice (GP-SEC-61). Agent behaviour is outside this repository.
15. **E-mail default.** Recommendation: keep `optional` as R2 says; advise operators to set `off` unless the host needs the address.
16. **Consent log.** Recommendation: retain nothing (`guest_consent_log_retention_secs` 0). If the operator's basis is consent and proof is needed after the record is gone, retaining `{version, at}` against the pseudonymous localpart (no name) is the least costly way; the operator decides.
17. **Kill switch.** Recommendation: three Redis values and no HTTP endpoint (GP-SEC-48), plus a short operator runbook in the deployment guide.
18. **Add the guest flow to SECURITY.md scope and `security/EXCEPTIONS.md`.** Recommendation: yes, with the residual risks of 6.2 as reviewable entries.
19. **E-mail after a claim.** Recommendation adopted (D13): the guest is asked once on the claim screen, keep the address on the account for notices or remove it, default remove; no answer, abandonment or reap means deletion (GP-SEC-26, 05 CL-02). `guest_email_retention_secs` governs the unclaimed case only. Alternative: always delete at the commit. The maintainers decide whether any purpose justifies letting an unverified address stay on a permanent account even on the guest's own opt-in.
20. **Prerequisites.** Recommendation adopted (D11): P1 to P4 of section 0.1 are hard gates in every document. Remaining for the maintainers: the licence path of the policy module (P4), decided with counsel.
