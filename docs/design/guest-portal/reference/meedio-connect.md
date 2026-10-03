# Guest portal reference C: meedio-connect, a Matrix-native video client

**Status:** reference documentation, **Track C** of the [consolidation session](../08-consolidation-session.md). It does not belong to the design contract of [00](../00-overview.md) to [09](../09-registered-users.md): no `GP-` identifier depends on this file, and no milestone builds from it. Two things set it apart from Track B (the [case study](waiting-room-case-study.md) and the [reference wireframes](waiting-room-wireframes/)). It was written in this repository rather than received. And its statements were read from pinned sources and carry a status, as in the design set.
**Date and sources:** read on 2026-10-02 at:

| Prefix | Source | Pin |
|---|---|---|
| `mc:` | `github.com/meedio/meedio-connect` | commit `204593a` (head of `main`, 2026-08-12). Its code was last changed on 2025-10-06; the later commits change only the README |
| `ec:` | `github.com/element-hq/element-call` | tag `v0.26.1` (as in 03) |
| `lk:` | `github.com/element-hq/lk-jwt-service` | tag `v0.7.0` (as in 02 and 03) |
| `exa:` | `github.com/element-hq/element-x-android` | commit `096a937` (2026-10-02) |
| `exi:` | `github.com/element-hq/element-x-ios` | commit `a4ff68e` (2026-09-30) |

**Decision that uses this file:** D22 in [00 section 7](../00-overview.md#7-decisions-log). This file is reference material for the session and for D22. D10 stays as it is.

## 1. What it is

Meedio is a Danish vendor of Matrix-based video conferencing for healthcare, education and the public sector. It joined the Matrix.org Foundation as a Silver member in January 2026. In March 2026 Element announced that Meedio uses Element Server Suite Pro as its server and builds its own front-end client (element.io blog, 2026-03-26). Its public GitHub organisation (`github.com/meedio`) carries:

| Repository | What it is |
|---|---|
| `meedio-connect` | "Open-source version of Meedio Connect": the video front end, AGPL-3.0. A one-off snapshot: three commits, one author, code frozen in October 2025 |
| `livekit-helm` | A fork of LiveKit's Helm charts with 28 commits of their own (per-node media addresses, TURN NodePort fixes), the most active repository (pushed 2026-09-24) |
| `mscs` | Research notes on the MatrixRTC proposals (MSC4140, MSC4143, MSC4195, MSC4354), May 2026 |
| `matrix-js-sdk`, `client-sdk-js`, `element-web` and two `-development` forks | Forks whose default branches carry no change of their own, or one commit (the LiveKit client) |

The product Meedio sells today, rebuilt on ESS Pro since 2026, is not public. Everything below is about the public snapshot.

## 2. Why it is a reference and not a base for the guest client

The recommended guest client is a thin custom app with the Element Call component (T1 of 03, D10). meedio-connect is a second thin, Matrix-native client that already exists, so it was read against the gates of this set. It fails four of them:

| Gate in this set | What the guest client needs | What meedio-connect does | Status |
|---|---|---|---|
| D7, 03 GP-CLI-12: encrypted call room, per-participant media keys | Media E2EE with keys from the room's members | **No media E2EE.** The LiveKit room is created without encryption options (`mc:src/contexts/SimpleRoomContext/SimpleRoomContext.tsx:14`), and no Matrix crypto is set up: no `initRustCrypto`, no key provider, no source file names E2EE. It creates rooms with the `public_chat` preset and no `m.room.encryption` (`mc:src/hooks/useCreateRoom/useCreateRoom.ts:26-36`). The SDK generates media keys (`manageMediaKeys: true`, `mc:src/utils/matrixUtils.ts:80`), but nothing ever uses them | Verified |
| D4, 03 GP-CLI-02: OAuth 2.0 code flow with PKCE and `prompt=none`; guests never call `/register` | Native OAuth against siwx-oidc | Registered users sign in through the legacy SSO redirect and `m.login.token` (`mc:src/contexts/MatrixContext/useMatrixAuthentication.ts:55-65`). A guest gets a throwaway account through `/register` with `m.login.dummy` on a **separate guest homeserver** (`mc:src/contexts/MatrixContext/useRegisterGuestMatrixAccount.ts:19-37`). That is the open-registration recipe 03 section 1 rules out, and D20 does not adopt even in its delegated variant | Verified |
| 03 S1: the same call as stock Element Web and Element X | js-sdk v43, current MatrixRTC | The js-sdk is a 37.10.0 fork and livekit-client a 2.15.2 fork, both fetched as release tarballs (`mc:package.json:82,85`). Their changes add E2EE tracing; no change to the wire protocol was found. The JWT comes from the legacy `/sfu/get` (`mc:src/utils/openIDSFU.ts:22`). Keys would travel as room events (the to-device transport is never switched on, `mc:src/utils/matrixUtils.ts:79-88`) | Verified (versions, routes); the trace-only nature of the fork changes is Inferred from a filtered diff |
| Runs on Synapse, siwx-oidc, lk-jwt and LiveKit only | No vendor backend | Invite links, the pre-join lookup of a room and the waiting-list settings go through Meedio's own "identity server" (`REACT_APP_IDENTITY_SERVER_URL`, `mc:src/api/identityService/`) | Verified |

Making it fit would mean rewriting sign-in, crypto, key transport and invite resolution. Those are the hard parts of the guest client, and the Element Call component already brings them. What would remain is the call screen. **Verdict: a reference for patterns, not a base. D10 is unchanged (D22).**

Meedio's guest model has one more lesson. Its guests are open-registration accounts on a second homeserver, the recipe ESS documents (03 section 1, row 4). That is independent evidence of what vendors do by default. The design set differs on purpose: the guest's identity is minted by the identity provider and held in custody by the operator, and a claim path exists.

## 3. Element X compatibility of the public client

The question was whether a meedio-connect participant and an Element X participant can share one call. Element X embeds the web Element Call 0.26.0 on both platforms (`exa:gradle/libs.versions.toml:244`, `exi:project.yml:92-94`). It also already lists a native MatrixRTC component in pre-release: Android `element-call-android` 0.1.0-rc.6 (`exa:gradle/libs.versions.toml:68`), iOS `element-call-ios` 0.1.0-rc.9 (`exi:project.yml:82-84`).

| Layer | Element X (embedded Element Call 0.26.0, default mode) | meedio-connect | Same call? | Evidence |
|---|---|---|---|---|
| Membership | State events `org.matrix.msc3401.call.member` in the default `compatibility` mode | The same, written by the js-sdk 37 membership manager | Yes | `ec:docs/matrix_rtc_modes.md:15-21`, `ec:src/settings/settings.ts:151-154`; `mc:src/utils/matrixUtils.ts:79-82` |
| LiveKit token | Legacy `/sfu/get` for the local member in `compatibility` mode | Legacy `/sfu/get` | Yes | `ec:src/livekit/openIDSFU.ts:118-124,214`; `mc:src/utils/openIDSFU.ts:22` |
| LiveKit room | lk-jwt derives one alias from the room id and the slot `m.call#ROOM`, on both routes | The same, server side | Yes, one SFU room | `lk:src/helper.rs:209-214`, `lk:src/handler.rs:847-849,924-926` |
| LiveKit identity | `<mxid>:<device_id>` on the legacy route; a hash of user, device and member id on `/get_token` | Parses `<mxid>:<device_id>` | Yes on the legacy route; breaks on the new one | `lk:src/handler.rs:847`, `lk:src/helper.rs:216-222` |
| Media in an encrypted room (Element X direct messages and private rooms) | Per-participant frame encryption | None | **No**: participants appear in the call but receive no audio or video in either direction | Verified for meedio-connect; the Element X side follows from 03 section 4.2 and is Inferred |
| Media in an unencrypted room | No media E2EE | None | Probably yes | Inferred, not run |
| `matrix_2_0` mode (sticky events, MSC4354) | Opt-in per deployment | Not supported | **No**: neither sees the other | `ec:docs/matrix_rtc_modes.md:15-21` |

**Result.** The signalling matches, because Element Call 0.26 still defaults to the format meedio-connect froze in 2025. But the two share media only in an unencrypted room, and every call room of this design is encrypted (D7). Two things would break even the signalling: a deployment that pins `matrix_2_0`, and Element X calls moving to the native component. These findings are the evidence base of R10 and of [09 section 2](../09-registered-users.md#2-r10-element-x-parity-for-registered-users).

Neither Meedio nor Element claims publicly that Meedio's product works with Element X. Whether the current, closed product does is unknown. Two questions would settle it: does its client encrypt media per participant, and does it support `matrix_2_0`?

## 4. What Track C offers the consolidation session

Patterns only. Copying code would make the copied files AGPL. That is acceptable for the guest client, which is AGPL-covered anyway (00 open decision 3). But the snapshot is React 18 on js-sdk 37, while the Element Call component needs a React 19 host on js-sdk v43 (03 section 4.1). So a port would be a rewrite.

| Pattern in meedio-connect | Where | What it informs in this set | Status |
|---|---|---|---|
| Waiting room on the plain Matrix knock. The guest knocks and sees a waiting screen while its membership is `knock`. The host admits by inviting, after which the guest joins automatically, or denies by kicking | `mc:src/hooks/useRoomKnock.ts:35`, `mc:src/hooks/useKnockHandler.ts:14-35`, waiting list on with join rule `knock` at `mc:src/utils/matrixUtils.ts:107-111` | D14 and 03 GP-CLI-14 use the same primitive. This is a shipped example, but it does not replace SP-3, because Meedio's host side is its own client and ours is stock Element Web | Verified (code); production use Inferred |
| Host alert: a sound when the waiting list changes | `mc:src/contexts/WaitingListContext/WaitingListContext.tsx:4,24-26` | RF-08 and the alert gap of GP-FLOW-29, a Matrix-native precedent for CS-02 | Verified (sound wired to the waiting list); the exact trigger is Inferred |
| Accept and deny in a participants sidebar, for owners only | `mc:src/modules/PeopleSidebar/` | RF-05 and RF-07, the host panel question of CS-02 | Verified (present) |
| Camera and microphone failures. Separate dialogs cover blocked, in use, no device and waiting for permission, with browser-specific instructions to unblock, a Permissions API check and a diagnostics page | `mc:src/hooks/usePermissionsModal/`, `mc:src/hooks/useLivekitPermissions/` | 03 GP-CLI-09 and spike S5: the gap Element Call 0.26.1 leaves (03 section 4.5) | Verified (present) |
| In-app webview and old iOS detection before joining | `mc:src/utils/browsers.ts:22-27,46-50` | Spike S6 (mobile browsers) | Verified |
| **Lesson, not a pattern:** the snapshot sends call-key material and the LiveKit token to its telemetry. A received media key is logged with only three characters masked at each end, and the SFU configuration is logged including the JWT. Grafana Faro captures the console, and Sentry session replay is on | `mc:src/modules/ActiveRoom/ActiveRoom.tsx:25-30,77-93`, `mc:src/contexts/OpenIdSfuContext/useOpenIDSFU.ts:26`, `mc:src/utils/logging/initFaro.ts:28`, `mc:src/utils/sentry/initSentry.ts:4-12` | 04 GP-SEC-44 bans tokens and key material from **server** log lines. Nothing in the set covers the browser: console logs, rageshakes or third-party telemetry of the guest client. Candidate for the session (CS-09) | Verified |

## 5. Licence notes

`LICENSE` is AGPL-3.0. `package.json` declares MIT (`mc:package.json:4`), and the third-party notice file lists the project as UNLICENSED. The repository also carries Meedio brand assets (logo, sounds). Should a pattern ever be copied as code rather than rewritten, the AGPL file governs, and the brand assets stay out.

## Validation status

| Claim | Evidence | Status |
|---|---|---|
| meedio-connect has no media E2EE and no Matrix crypto | `mc:` lines in section 2; a search of `src/` and `libs/` for E2EE, key providers and crypto setup finds none | Verified |
| Guests are registered through `/register` on a separate homeserver | `mc:src/contexts/MatrixContext/useRegisterGuestMatrixAccount.ts:19-37` | Verified |
| The vendored js-sdk and livekit-client are 37.10.0 and 2.15.2, and change only tracing | `mc:package.json:82,85`; a filtered diff against the npm releases | Versions Verified; "tracing only" Inferred |
| Element X embeds Element Call 0.26.0 on both platforms and lists a native call component in pre-release | `exa:gradle/libs.versions.toml:68,244`, `exi:project.yml:82-84,92-94` | Verified (dependency catalogues); which path the store builds use for calls is Unverified |
| Element Call 0.26.1 defaults to `compatibility` mode (state events, legacy JWT route) | `ec:docs/matrix_rtc_modes.md:15-21`, `ec:src/settings/settings.ts:151-154`, `ec:src/livekit/openIDSFU.ts:118-124` | Verified |
| Both JWT routes of lk-jwt v0.7.0 map a room to the same LiveKit room | `lk:src/helper.rs:209-214`, `lk:src/handler.rs:847-849,924-926` | Verified |
| A meedio-connect participant and an Element X participant get no media from each other in an encrypted room | the two E2EE rows above | Inferred, not run |
| Neither company claims compatibility with Element X publicly | element.io blog of 2026-03-26, meedio.me, web search on 2026-10-02 | Unverified (an absence claim) |
| The snapshot logs media-key material and the LiveKit token to telemetry | lines in section 4 | Verified |

## Open decisions

1. **Vendor-specific findings in a public repository.** Recommendation: keep them. They cite public code at a pinned commit and describe a 2025 snapshot, not Meedio's current product. Before the pull request leaves draft, send Meedio a short private note on the telemetry finding of section 4 as a courtesy. This mirrors 08 open decision 1 for the case study.
2. **Ask Meedio the two questions of section 3** (per-participant media E2EE, `matrix_2_0`). Recommendation: yes, as a peer in the MatrixRTC work. Their LiveKit operations work (TURN NodePort, per-node media addresses) bears on P2 and on the TURN question of the deployment. Nothing in this set depends on the answer.
