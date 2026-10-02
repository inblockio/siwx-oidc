# Guest portal 09: registered users (Element X parity and e-mail registration)

**Status:** DRAFT design document, added on 2026-10-02. Like the rest of the set it changes no code. **R10 and R11 are requirements set by the product owner, not candidates for the consolidation session.** The session (08) decides how they meet the other tracks (CS-10), not whether they apply.
**Scope:** two requirements about **registered** users, the people who are not guests. R10: Element X is a first-class client for them, without exception. R11: an e-mail address becomes a supported way to register with siwx-oidc. The operator then holds the account's key, and that custody has a migration path to a hardware security module (HSM). Guests are out of scope here. Nothing in this document changes a guest rule.
**Baseline:** siwx-oidc at `3547bd2`, as for the whole set. Upstream sources: Element Call `v0.26.1` (`ec:`), lk-jwt-service `v0.7.0` (`lk:`), element-x-android at `096a937` (`exa:`, 2026-10-02), element-x-ios at `a4ff68e` (`exi:`, 2026-09-30). The interoperability evidence of section 2.2 comes from the Track C investigation, [reference/meedio-connect.md](reference/meedio-connect.md).
**Identifiers:** `GP-REG-nn` (this document, section 6), spikes SP-8 and SP-9 (07 section 3), milestones M11 to M13 (07 section 4), acceptance rows A9 (07 section 1.4) and AE-1 to AE-4 (section 5.3), decisions D23 and D24 (00 section 7); register rows DR-79 to DR-85 (07 section 9).

## 0. Summary

1. **R10.** Every capability a registered user has in the guest-portal flows on Element Web, they also have on the current store release of Element X for Android and iOS. A gap blocks dev enablement; it is never a documented limitation (GP-REG-01). Guests stay exempt: they join from the browser (03 section 4.6).
2. **Element X is a moving target.** Today it embeds the web Element Call 0.26.0 on both platforms, and the default MatrixRTC mode there is `compatibility`. Both platforms also already list a native MatrixRTC component in pre-release. So parity is re-tested at every relevant upgrade, not proven once (GP-REG-03).
3. **One MatrixRTC mode per deployment**, pinned in every client configuration the deployment controls: `compatibility` in v1 (GP-REG-02). A deployment that mixes modes splits a call into participants who cannot see each other.
4. **R11.** A person with neither passkey nor wallet registers and signs in with an e-mail address and a one-time code. The first verified code creates an ordinary registered account: no guest marker, no deadline. Its DID is the `did:key` of a P-256 key that siwx-oidc creates and holds. This is a server-side ceremony in the sense of `AGENTS.md`, like the passkey ceremonies and the RFC 8628 approval page. It verifies a proof (the code) and writes a verified DID into the session, and `sign_in` stays the only code-issuing site.
5. **Custody is built for an HSM from the first day** (section 4). Each per-account key is held wrapped with AES key wrap with padding (RFC 5649) under a key-encryption key (KEK), behind one `KeyCustody` interface. Moving to an HSM moves the KEK into it. From then on, every key is unwrapped inside the HSM by standard PKCS#11 `C_UnwrapKey` and signs there. No DID, MXID, record or caller changes. No custodial key signs anything before that move (GP-REG-20).
6. **Guests are unchanged.** For guests the e-mail stays unverified and is never an authenticator (04 GP-SEC-23 to GP-SEC-26, NG-01). Their derived, short-lived key stays as D9 specifies. R11 adds a mailer for registered users only, which amends plan decision PD-7 (07).

## 1. Terms

| Term | Meaning |
|---|---|
| Registered user | An account without the guest marker: today's passkey, wallet and headless accounts, a promoted former guest (D3), and the e-mail accounts of R11. A claimed guest is not a registered user while the marker is set (D3); whether R10 covers claimed-restricted accounts is open decision 1 |
| Element X | The current app-store release of Element X for Android and for iOS. This project does not patch Element X (`docs/matrix-integration.md:632-633`) |
| Parity | The same outcome on Element X as on Element Web, for the same registered user, room and call. Parity of outcome, not of screens: a capability that lives in the host tool (07 C4) is reached in the phone's browser next to Element X |
| E-mail account | A registered account created by R11. Its key is custodial |
| Custodial | The operator, not the person, holds the private key of the account's DID (R3 uses the word the same way for guests) |
| KEK | Key-encryption key: the AES-256 key under which every custodial private key is wrapped at rest |

## 2. R10: Element X parity for registered users

### 2.1 What Element X runs today

| Platform | Embedded web call | Native MatrixRTC component | Evidence |
|---|---|---|---|
| Android | `element-call-embedded` 0.26.0 | `element-call-android` 0.1.0-rc.6 in the dependency catalogue | `exa:gradle/libs.versions.toml:68,244` |
| iOS | `element-call-swift` 0.26.0 | `element-call-ios` 0.1.0-rc.9 | `exi:project.yml:82-84,92-94` |

The source read here does not show which path a store build uses for a call, or behind which flag. SP-8 records it on each run.

### 2.2 Interoperability facts

| Layer | Element Call 0.26.x | What it means for parity | Evidence |
|---|---|---|---|
| MatrixRTC mode | `compatibility` is the default: membership as state events, multi-SFU, the legacy JWT route. `matrix_2_0` (sticky events MSC4354, hashed identity, the new route) is opt-in per deployment and needs every client to support it | The deployment's choice decides whether Element X participants see the others at all | `ec:docs/matrix_rtc_modes.md:15-21`, `ec:src/settings/settings.ts:151-154` |
| JWT route of the local member | `/sfu/get` in `compatibility`, `/get_token` in `matrix_2_0`. A remote membership tries `/get_token` first, then the legacy route | P1's membership check must cover both routes; workstream L1 already lists both | `ec:src/livekit/openIDSFU.ts:118-124,214` |
| LiveKit room | lk-jwt derives one alias from the room id and the slot `m.call#ROOM`, on both routes | Clients on different routes still meet in one SFU room | `lk:src/helper.rs:209-214`, `lk:src/handler.rs:847-849,924-926` |
| LiveKit identity | `<mxid>:<device_id>` on the legacy route; a hash of user, device and member id on the new one | A client that parses identities breaks on the new route (Track C's does) | `lk:src/handler.rs:847`, `lk:src/helper.rs:216-222` |
| Media E2EE | Per-participant keys when the room is encrypted, which every guest-portal room is (D7) | Element X must exchange call keys with unverified guest devices without a block. 03 spike S1 asks the same of Element Web | 03 section 4.2 |

### 2.3 The parity surface

| # | Capability of a registered user | Today on Element X | Proven by |
|---|---|---|---|
| 1 | Sign in through siwx-oidc (OAuth 2.0 code flow with PKCE, refresh), with a passkey or a wallet | Passkey-first login worked on iOS from May 2026; Android was not confirmed then (`docs/troubleshooting.md:170-206`). QR login has a documented failure mode (`docs/troubleshooting.md:128-144`) | SP-8 |
| 2 | Sign in with an e-mail account (R11) | Not built | SP-8, repeated after M12 |
| 3 | Join a guest-portal call room (encrypted, `knock`, the template of 01 section 4.3) as a participant, with two-way audio and video with guests on the thin client, Element Web users and other Element X users | Unverified | SP-8 at G1 (no guest yet), repeated at G3 |
| 4 | Exchange call keys with an unverified guest device, with no block or warning that stops the call | Unverified | SP-8 at G3 |
| 5 | As a host: see a knock, then admit or deny it | Unverified | SP-8 |
| 6 | As a host: create the call room from the template and mint invites | The host tool (07 C4) does both, so a host who has only a phone uses it in the phone's browser | SP-8 records the route |
| 7 | Leave the call, and be removed by a host | Unverified | SP-8 |

### 2.4 What R10 does not cover

Guests on Element X (03 section 4.6: guests use the browser), features that Element Web lacks too, and the legacy one-to-one call protocol, which Element X does not use.

## 3. R11: e-mail registration

### 3.1 Flow

1. The existing login page gains "Continue with e-mail". The person types an address.
2. `POST /email/start` normalises the address and always answers `202` with the same body. Within the limits of GP-REG-09 it sends one code: a sign-in code to a known address, a registration code to an unknown one. The answer never says which (GP-REG-08).
3. The person types the code. `POST /email/verify` checks it (GP-REG-07). On the first success for an address, the account is created: `KeyCustody::create` makes a P-256 key (section 4), the account's DID is that key's `did:key`, and the account record and the address index are written in one set-if-absent step (GP-REG-11). On a later success the existing account is looked up.
4. The ceremony writes `verified_did` into the Redis session and hands over to `sign_in`. That is the existing Path A, which the passkey ceremony also uses. `sign_in` runs its gates in their pinned order: `reject_if_deactivated` first, then resolution, provisioning, the alias and publication of `io.inblock.did`. It is still the only place a code is issued (`src/oidc.rs:2488-2753`). Nothing changes in `DIDMethod`, aqua-auth or the token endpoint.
5. Element Web and Element X reach this page as they reach the passkey page today. Element X opens it in the system browser (R10 row 2).

A code, not a link: link scanners and preview bots open links, the reason invites are single use (D6). A code also works across devices: the mail is read on a phone and the code typed on a laptop.

### 3.2 What the address is, and is not

| Aspect | Rule |
|---|---|
| Role | **The authenticator of an e-mail account.** Whoever controls the mailbox controls the account. That is a deliberate contrast with guests, for whom the address is never an authenticator (GP-SEC-23) |
| Assurance | Low, the mailbox's own. NIST SP 800-63B does not accept e-mail as an out-of-band authenticator (section 5.1.3.1). Downstream systems treat an e-mail account like the low-assurance case of 04 section 4.3 and key on the explicit flag of GP-REG-14, never on DID method |
| Identity | None. The key is random, so the DID and MXID carry no trace of the address and two deployments cannot correlate one person through it |
| Uniqueness | One account per normalised address, the opposite of the guest rule GP-SEC-25, because here the address selects the account |
| Visibility | Account record only. It never appears in tokens, the ID token, userinfo, the profile, `io.inblock.did`, a Synapse 3PID, account data or logs (GP-REG-10) |

### 3.3 Mail

R11 brings the first outbound mail into siwx-oidc. 04 GP-SEC-24 already names the gates any mailer must pass: double opt-in, per-address and global limits, fixed templates with no attacker-controlled text, and an identical response whether or not a mail was sent. GP-REG-09 adopts that list as the review baseline. The double opt-in is built in, because nothing happens until the code comes back. 04 GP-SEC-24 ("no outbound mail in v1") keeps applying to the guest path.

## 4. Custody with a migration path to an HSM

### 4.1 Why not the guest scheme

The guest key is derived: HKDF-SHA256 with the server secret as input keying material and a per-guest value as salt (04 section 4.1). That fits a two-hour key that signs nothing (D9). It does not carry into an HSM. In HKDF the input keying material is the message of the extract step, so an HSM that holds the root as a non-exportable key cannot run the extract with it. PKCS#11 key derivation gives a secret key object, not a non-exportable EC private key. A derived scheme therefore either keeps the root in software or makes each derived key extractable, and either way defeats the HSM. 04 section 4.1 weighed "a random key stored encrypted" for guests and found no benefit. For a long-lived key the benefit is concrete: the wrapped form is exactly what an HSM imports.

### 4.2 The scheme

| Aspect | Decision |
|---|---|
| Key type | P-256 ECDSA (secp256r1); the account DID is the `did:key` of the public key. P-256 is offered by every PKCS#11 HSM and every major cloud KMS and is a FIPS 186-5 curve; HSM support for Ed25519 is newer and uneven. Passkey accounts already have P-256 `did:key` DIDs. No rule branches on the curve (as GP-SEC-59 for guests) |
| Generation, stage 0 | Operating system CSPRNG in siwx-oidc, at account creation |
| At rest | The private key as PKCS#8 `PrivateKeyInfo`, wrapped with AES-256 key wrap with padding (RFC 5649; PKCS#11 `CKM_AES_KEY_WRAP_KWP`) under the active KEK. Stored as `custody:key/<key_id>` holding `{v, kek_id, wrapped, public_key, created_at}`. The account record holds only `key_ref = {v: 1, key_id}`. Key wrap is deterministic, so no nonce needs managing: that answers the objection of 04 section 4.1 |
| Integrity | After every unwrap the public key is recomputed and compared with the stored one; a mismatch is a hard error and nothing is signed |
| KEK | 32 random bytes, `custody_kek`, supplied the way `mas_shared_secret` is. Startup refuses it if absent, short, or equal to any other secret of the service, including `guest_key_secret`. `kek_id` is a fingerprint. Several KEKs may be configured for rotation; one is active |
| In memory | A key is unwrapped only inside the custody module, for one operation, and zeroised afterwards |
| Interface | `KeyCustody`: `create() -> (key_ref, public_key)`, `public_key(key_ref)`, `sign(key_ref, purpose, message)`, `destroy(key_ref)`. There is no export function. `purpose` is checked against the permitted set (GP-REG-15) |
| Backends | `software` and `pkcs11`, chosen by configuration over the same records |

### 4.3 Migration stages

| Stage | KEK | Where a key is unwrapped and used | What changes for accounts |
|---|---|---|---|
| 0, software (v1) | In process memory, from the secret source | In process memory, per operation | Nothing |
| 1, KEK in the HSM | Imported once, under dual control, as a non-exportable key allowed to unwrap only; the software copy is then destroyed | Inside the HSM: `C_UnwrapKey` turns the stored blob into a sensitive, non-extractable session object, `C_Sign` (`CKM_ECDSA`) signs, the object is destroyed. From here on a private key never exists outside the HSM | Nothing: same blobs, same `key_ref`, same DID and MXID |
| 2, optional | In the HSM | Keys persisted as token objects for latency; new keys generated inside the HSM. For a cloud KMS, which imports key material per key instead of unwrapping into a session, each key is re-wrapped once for the KMS import format | Nothing visible |

**Residual risk of stage 0.** While the KEK is in software, a compromise of the host can copy every key unnoticed. A `did:key` cannot be rotated without changing the DID, and an account's DID never changes (04 GP-SEC-57, maintainer ruling). So stage 0 is acceptable only while custodial keys sign nothing: login needs no signature (section 3.1), and GP-REG-20 refuses any signing purpose before stage 1. **The HSM is the precondition for the first custodial signature, not an upgrade after it.**

## 5. Spikes, milestones and acceptance

### 5.1 Spikes (rows of 07 section 3.1)

| Spike | Setup | Pass | Fail means |
|---|---|---|---|
| SP-8 Element X parity | The store builds of Element X for Android and iOS, Element Web, the room template of 01 section 4.3, the deployment's pinned MatrixRTC mode, patched lk-jwt once L1 exists. Runs at G1 for rows 1, 3 (registered users only), 5, 6 and 7 of section 2.3, at G3 for all rows with the guest client, and per GP-REG-03 after upgrades. Records the Element X version and whether the call ran in the embedded or the native component | Every row passes on both platforms | A blocker (GP-REG-01). The record names the row and the remedy chosen: a change on our side, an upstream issue with a dated workaround, or a register decision that narrows R10 by name |
| SP-9 Custody HSM path | SoftHSM2 through PKCS#11. Wrap a P-256 key in software under a KEK (AES-KWP), import the KEK, unwrap the blob into a sensitive non-extractable session object with `C_UnwrapKey`, sign with `CKM_ECDSA`, verify against the stored public key. Repeat on the target HSM model before production use | Same public key and `did:key`; a valid signature; no plaintext key outside the token | The HSM cannot unwrap an EC key with `CKM_AES_KEY_WRAP_KWP`: choose stage-2 per-key import or another HSM, recorded in DR-84 |

### 5.2 Milestones (rows of 07 section 4.1)

| Id | Content | Needs | Gate |
|---|---|---|---|
| M11 | `KeyCustody` interface, `software` backend, KEK configuration and startup checks, wrapped records, the resumable re-wrap job for KEK rotation | none | none: independent of the guest gates |
| M12 | E-mail ceremony: routes, code store, mailer and templates, the login-page option, account record and address index, the `io.inblock.custodial` flag, the refusal of login signatures, `email_registration_enabled` (default false) | M11 | Mailer review against GP-REG-09 before enablement on dev |
| M13 | `pkcs11` backend over the same records, the KEK import procedure, the signing-purpose gate | M11, SP-9 | Before any signing purpose is enabled (GP-REG-20) |

M11 and M3b (guest key derivation) are independent. If both land, the guest derivation may sit behind the same interface as a second scheme (D24), and neither waits for the other.

### 5.3 Acceptance

R10 adds row **A9** to the acceptance criterion of 07 section 1.4: SP-8 passes on the dev stack on both platforms. That includes a registered Element X user in the same encrypted call as a guest and an Element Web user, and a host on Element X admitting a knock. A9 gates guest v1.

R11 has its own acceptance. It does not gate guest v1 (D24):

| # | Criterion |
|---|---|
| AE-1 | A person with only an e-mail address registers, signs in on Element Web and on Element X for Android and iOS, and joins a call. A second registration with the same address signs in to the same account (same DID and MXID) |
| AE-2 | Known, unknown and rate-limited addresses get byte-identical answers from `/email/start`. A code is refused after five wrong attempts, after ten minutes, and in another session |
| AE-3 | After a full flow, no Redis value, log line or response holds a plaintext custodial key, the KEK or a live code. Every login signature path refuses an e-mail account's DID |
| AE-4 | SP-9 has passed, and the same accounts sign through the `pkcs11` backend with unchanged DIDs |

## 6. Requirements

| ID | Requirement and why | Where | Test |
|---|---|---|---|
| GP-REG-01 | **Parity rule (R10).** Every capability of section 2.3 that a registered user has on Element Web, they have on the current store release of Element X for Android and for iOS, with the same outcome. A failed row blocks dev enablement (G3) and production. It is never a documented limitation. The remedy is a change on our side, an upstream issue with a dated workaround, or a register decision that narrows R10 by name. Guests are exempt. Why: product-owner ruling | dev stack | SP-8: every row passes on both platforms |
| GP-REG-02 | **One MatrixRTC mode per deployment.** Every client configuration the deployment controls pins the same `matrix_rtc_mode`: the guest client's `initializeElementCall` configuration, Element Web's bundled Element Call, and any standalone Element Call. In v1 that is `compatibility`, the default of the Element Call that Element X embeds. A change is gated by a passing SP-8 on both platforms. Why: a mixed deployment splits a call | configuration, deployment check | The deployment check (M10) reads the pinned mode of each configuration; SP-8 after any change |
| GP-REG-03 | **Parity is re-tested, not assumed.** SP-8 runs at G1, at G3, and after each of these: an Element X store release that changes the embedded Element Call or moves calls to the native component, a change of the Element Call component pin, an lk-jwt upgrade, a Synapse upgrade. Each record names the versions. Why: both platforms already list a native call component (section 2.1) | operations | A record exists for each upgrade |
| GP-REG-04 | **Guest work does not touch a registered user's Element X path.** The policy module acts only on marked users (02). The room template lets an Element X host admit a knock. P1 covers both JWT routes (L1). The guest client runs the mode of GP-REG-02. Why: the guest design must not degrade registered users | module, L1, client | SP-8 with the module and patched lk-jwt in place |
| GP-REG-05 | **siwx-oidc keeps Element X sign-in working.** Discovery stays aligned with MAS (`docs/matrix-integration.md:616-624`), both MSC2967 scope forms stay accepted (`:629-631`), and the refresh grace window stays (`AGENTS.md`, "Tokens, sessions and devices"). Any change to discovery, scopes, refresh or the login page reruns rows 1 and 2 of SP-8. Why: Element X fails silently on discovery drift (`docs/troubleshooting.md:170-206`) | siwx-oidc | SP-8 rows 1 and 2 after such a change |
| GP-REG-06 | **The e-mail ceremony is a ceremony (R11).** It verifies the code server side, writes only `verified_did` into the session, and hands over to `sign_in`, which stays the only code-issuing site with its gate order unchanged. `email_registration_enabled` defaults to false; off, the routes answer 404 and the login page offers no e-mail option. Why: `AGENTS.md` "Architecture in brief" and the sign-in gate invariants | S | Flag off: 404 and no option. Flag on: a deactivated e-mail account is refused by `sign_in` before resolution |
| GP-REG-07 | **One-time code.** Eight digits from the operating system CSPRNG. Valid 10 minutes, single use, and at most 5 attempts, counted atomically (the fifth failure burns the code). Bound to the session that requested it. Stored only as an HMAC under a server key, so a Redis dump does not reveal a live code. Why: the code is full control of a custodial account | S | Attempt 6, minute 11, a second use and use from another session are all refused; no Redis value equals or reveals the code |
| GP-REG-08 | **No enumeration.** `/email/start` answers identically for a known, an unknown, a rate-limited and a domain-refused address, and sends any mail outside the request path. Only the mailbox owner can tell a sign-in mail from a registration mail. Why: the passkey picker's enumeration rule, applied to addresses | S | Byte-identical responses for the four cases; timing within the noise of the test |
| GP-REG-09 | **Mail gates.** The mailer passes the gates of 04 GP-SEC-24: fixed templates whose only variable is the code; at most 3 codes per address per hour and 10 per day, plus per-range and global ceilings; a configured relay. A send failure issues no usable code and changes no answer. Why: a form that mails is a spam relay unless bounded | S, O2 | Limits hit at their numbers; template search finds no user-controlled field; relay down gives the same 202 and no usable code |
| GP-REG-10 | **Address handling.** The address is normalised (trimmed, NFC, lower case) for lookup. The index key is an HMAC of the normalised address under a server key. The address is stored as typed only in the account record. It never reaches a token, the ID token, userinfo, the profile, `io.inblock.did`, a Synapse 3PID, account data or a log line (GP-SEC-44 holds for these code paths). Why: the address is personal data and an authenticator | S | Full-flow capture with a sentinel address: found only in the account record |
| GP-REG-11 | **One account per address, created once.** The first verified code creates the account with a set-if-absent write of the index, so two concurrent verifications create one account. Why: an address selects exactly one account | S | N concurrent first verifications: one account, one key, one DID |
| GP-REG-12 | **Every e-mail account has a custodial key** created at registration as in section 4.2, through `KeyCustody` only. Why: in siwx-oidc the account is a key, and R11 says the operator holds it | S | A new account has a `key_ref` whose public key gives its DID |
| GP-REG-13 | **Login signature paths refuse an e-mail account's DID** (deny by record, as GP-SEC-56 does for guests). That covers Path B of `sign_in`, wallet approval on `/device`, signature re-auth on `/account`, and the `siwx` cookie check that opens `link_start`. Why: a signature by a custodial key proves an operator action, not that the person is present | S | A valid CAIP-122 message signed with the custodial key is refused on all four paths |
| GP-REG-14 | **The custodial flag.** ID token and userinfo of an e-mail account carry `io.inblock.custodial: true`. The flag is omitted, never `false` or `null`, and is derived from the account record, never from key type. Why: a relying party cannot otherwise tell a custodial DID from a self-held one | S | E-mail account: present. Passkey, wallet and headless accounts: absent |
| GP-REG-15 | **Permitted signing set.** The set is empty in v1, because login needs no signature. A future purpose needs a written requirement naming the statement, its verifier and its audit (as GP-SEC-54), and every signature through `KeyCustody` is logged with `kid` and purpose only. Why: an unused signing capability is liability | S | `sign` with any purpose in v1 is refused; the log line carries no payload |
| GP-REG-16 | **One custody interface.** Key creation and custodial signing go through `KeyCustody`. No other module reads `custody:key/*` or the KEK, and no export function exists. Why: custody without a leash is impersonation (as GP-SEC-55) | S | Code search finds no other reader; no wrapped blob, KEK or unwrapped key in any log or response |
| GP-REG-17 | **Wrapped at rest, checked on use.** As section 4.2: AES-KWP under the active KEK. The public key is recomputed after every unwrap and must equal the stored one. Why: it is the HSM import format, and it catches a swapped blob | S | Swap two blobs: both refuse to sign; a Redis dump holds no PKCS#8 plaintext |
| GP-REG-18 | **KEK source and rotation.** As section 4.2. Rotation re-wraps every blob under the new KEK in a resumable job, and the old KEK is destroyed only after the job reports zero blobs under it. Why: rotation must not lose a key | S | Interrupt the job and resume it: every key still signs, and none is lost |
| GP-REG-19 | **HSM path.** The `pkcs11` backend reads the same records. Switching backends changes no `key_ref`, DID, MXID or record. Why: the migration path R11 demands | S, M13 | SP-9 on SoftHSM2 and on the target HSM |
| GP-REG-20 | **No custodial signature before stage 1.** Startup refuses a non-empty permitted signing set while the backend is `software`. Why: stage-0 keys can be copied unnoticed, and a `did:key` cannot be rotated | S | Configuration with a purpose and `software`: startup refused |
| GP-REG-21 | **KEK backup and loss.** The operator keeps KEK backups under dual control, and a restore drill is recorded. Losing every copy loses the keys, not the accounts: sign-in by code needs no signature, and the DID stays the account's identifier. Why: the keys are only as durable as the KEK | O | Restore drill record; with the keys unusable, sign-in by code still works |

## Validation status

| Claim | Evidence | Status |
|---|---|---|
| Element X embeds Element Call 0.26.0 on both platforms and lists a native call component in pre-release | `exa:gradle/libs.versions.toml:68,244`, `exi:project.yml:82-84,92-94` | Verified (dependency catalogues) |
| Which call path a store build of Element X uses | not read | Unverified (SP-8 records it) |
| Element Call 0.26.1 defaults to `compatibility` (state events, legacy route for the local member) | `ec:docs/matrix_rtc_modes.md:15-21`, `ec:src/settings/settings.ts:151-154`, `ec:src/livekit/openIDSFU.ts:118-124,214` | Verified |
| Both lk-jwt routes map a Matrix room to the same LiveKit room; identities differ by route | `lk:src/helper.rs:209-222`, `lk:src/handler.rs:847-849,924-926` | Verified |
| Passkey-first login works on Element X for iOS; Android unconfirmed | `docs/troubleshooting.md:170-206` (May 2026) | Verified as documented; not re-run |
| Rows 3 to 7 of the parity surface hold today | nothing run | Unverified (SP-8) |
| A ceremony that writes `verified_did` and hands over to `sign_in` needs no change to `DIDMethod`, aqua-auth or the token endpoint | `AGENTS.md` "Architecture in brief"; the passkey Path A at `src/webauthn.rs:834-858` (03 section 3.2) | Verified (read) |
| The guest key is HKDF-derived with the server secret as input keying material | 04 section 4.1 | Verified (read) |
| An HSM cannot run that extract with a non-exportable root, and PKCS#11 derivation yields no non-exportable EC private key | PKCS#11 3.0 mechanism set, read from memory | Unverified (SP-9 checks the target HSM) |
| PKCS#11 `C_UnwrapKey` with `CKM_AES_KEY_WRAP_KWP` imports a PKCS#8 EC private key as a sensitive, non-extractable object | PKCS#11 2.40 and 3.0 | Unverified (SP-9) |
| NIST SP 800-63B excludes e-mail as an out-of-band authenticator | SP 800-63B section 5.1.3.1 | Unverified (not re-read here) |
| GP-SEC-24 lists the mailer gates GP-REG-09 adopts | `04-security-and-limits.md`, row GP-SEC-24 | Verified (read) |

## Open decisions

1. **R10 for claimed-restricted accounts.** Recommendation: yes for rows 1, 3, 4 and 7 of section 2.3 (sign-in, joining, keys, leaving). The host rows do not apply, because a claimed guest cannot mint invites (01 step A3). Register DR-80.
2. **Code or link.** Recommendation: code only (section 3.1). Register DR-81.
3. **Name and shape of the custodial flag.** Recommendation: `io.inblock.custodial: true`, omitted otherwise, in line with `io.inblock.guest` (GP-SEC-58). Register DR-82.
4. **The OIDC `email` claim and a Synapse 3PID for e-mail accounts.** Recommendation: neither in v1. An `email` scope can come later, with explicit consent per client. Register DR-82.
5. **Adding a passkey to an e-mail account.** Recommendation: reuse the `claim-authorised` link core of 05, authorised by a fresh code. The DID stays the custodial key's, because an account's DID never changes. After the link, the code path can be switched off per account. Register DR-83.
6. **Address change and recovery.** Recommendation: not in v1. An address change later needs a code to both addresses, and recovery beyond the mailbox needs a second authenticator (decision 5). Register DR-83.
7. **Domain allow and block lists for registration** (compare RF-24). Recommendation: an optional operator allow-list, default off. Register DR-81.
8. **Stage 2 and the HSM product.** Recommendation: decide at M13 with SP-9's result. A cloud KMS needs per-key import (section 4.3). Register DR-84.
9. **Whether R11 gates guest v1.** Recommendation: no (D24). Its prerequisites (mailer, custody) share nothing with P1 to P4, and coupling the two would delay both. Register DR-85.
