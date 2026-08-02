# "Verify with other device" — integration gap evaluation

**Date:** 2026-07-25
**Branch:** `phase2/session-onboarding-lab`
**Method:** `/logic-model` (CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY CONDITIONS)
**Scope:** evaluation only. No source, config, or plan document was modified. No container was
started, stopped, or restarted. All live evidence is read-only `GET`.
**Question:** the repo owner suspects "verify with other device" is not actually integrated.
Confirm or refute, with evidence, and state whether plan requirement **R4** holds.

> **Labelling contract used throughout:** **VERIFIED** = backed by a file:line, a source
> reference, or a live read-only probe reproduced in this document. **ASSUMED** = a link in the
> causal chain that is plausible but that I did not test. Every ASSUMED item is listed in the
> assumptions register (§5.2) with the test that would settle it.

---

## 0. Verdict up front

| Protocol | Integrated? | Verdict |
|---|---|---|
| **1. Interactive verification (SAS / emoji, `m.key.verification.*`)** | Yes — server surface and client UI both present | **NO GAP (integration)** / **GAP (proof + reachability)** |
| **2. MSC4108 QR "link a new device"** | Yes — rendezvous live, OP metadata correct, Element button ungated | **NO GAP (integration)** / **GAP (proof)** |
| **3. Secret gossiping (`m.secret.send`) + MSC4108 secrets bundle** | Yes — transport present, `exportSecretsBundle` present | **NO GAP (integration)** / **GAP (proof)** |

**The owner's suspicion is CONFIRMED, but the suspected cause is REFUTED.**

There is a real gap. It is **not** a missing rendezvous server and **not** a missing client
affordance — both were the leading hypotheses and both are disproven by live evidence (§4.1,
§4.2). The gap is threefold:

* **G1 — Zero proof.** Not one test, at any layer, exercises to-device verification or secret
  transfer. The words `m.key.verification`, `sendToDevice`, `to_device`, `secret.send`, `SAS`,
  and `emoji` appear **zero times** across `src/`, `tests/`, and `e2e/` (§4.5). The test named
  "device link" (EW-D1) stops at token issuance. The one test that touches M5 Q2 (EW-D2)
  *asserts the dead-end exists*.
* **G2 — The verifier can silently lose the ability to verify.** Element Web 1.12.20 does not
  restore crypto across a page reload in this deployment (a P0-class finding already logged in
  the audited proposal). `isCrossSigningReady === false` is exactly the condition that **greys
  out the "Show QR code" button** (§4.2.3). The "live desktop session" R4 depends on is
  therefore not durably a valid verifier.
* **G3 — A near-term metadata landmine.** `response_modes_supported` is absent from the OP
  metadata (§4.6). It is fatal on matrix-js-sdk ≥ 42 (Element Web ≥ 1.12.24), and because
  `isSignInWithQRAvailable()` obtains its metadata through the *same* validated-metadata path, a
  validation failure degrades to "Not supported by your account provider" — silently disabling
  QR device-link on upgrade.

Plus one **unproven but high-value hypothesis** whose symptom signature matches the reported
failure exactly: Caddy compression is active on the rendezvous routes despite a comment claiming
otherwise (§4.7, **H-V4**).

**R4 does not currently hold**, and cannot be asserted to hold, because nothing has ever
demonstrated it. See §6.

---

## 1. CONTEXT

### 1.1 What exists

| Component | State |
|---|---|
| `siwx-oidc` | CAIP-122 → OIDC bridge; MAS replacement under MSC3861. Owns the RFC 8628 half of QR login (`src/device_auth.rs`, `/device*`). |
| Synapse | Read-only image overlay at `…/overlay/1513dc6dfd13…/diff/usr/local/lib/python3.13/site-packages/synapse`. MSC3861 delegated auth. |
| Element Web | **v1.12.20**, built from source at a pinned tag with one vendored patch (`patches/element-web/force-first-device-recovery.patch`). matrix-js-sdk **41.6.0**. Confirmed live: `https://element.inblock.io/version` → `1.12.20`. |
| Labs | Element lab = `siwx-oidc-matrix-server/docker-compose.local.yml` + `Caddyfile.local`, ports 28080/28081/28088 (`e2e/element/stack-up.sh`). Bare real stack = `e2e/real-stack/Caddyfile` (:8450). Hermetic harness = `Caddyfile.e2e`. |
| Prod | `matrix.inblock.io` / `siwx-oidc.inblock.io` / `element.inblock.io`. Caddy lives in the **portal** stack, not in this repo's compose — see §5.2 A6. |

### 1.2 The three protocols (must not be conflated)

| # | Protocol | Transport | siwx-oidc's role |
|---|---|---|---|
| 1 | Interactive verification (SAS / emoji) | `m.key.verification.*` over Synapse to-device, between two logged-in sessions of the same user | **None** |
| 2 | MSC4108 QR device-link | Rendezvous channel on Synapse + OIDC device authorization grant | **Owns the RFC 8628 half** |
| 3 | Secret gossiping / secrets bundle | `m.secret.send` over to-device (protocol 1) or the MSC4108 secrets bundle (protocol 2) | **None** |

A deployment can have any subset working. This evaluation keeps them separate throughout.

### 1.3 Prior art consulted

`CLAUDE.md`; `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md`
(**M5**, lines 365–386, and the Q1–Q5 terminal table);
`docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md` (**R4**, line 102;
**H-D8**, line 137; **AC4**, line 268);
`docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md` (EW-D1/D2 spec
contracts line 107–108; MSC conformance table line 181–185; the P0-class finding at line 456).

---

## 2. GOAL

> Determine, per protocol, whether "verify with other device" is integrated end-to-end in this
> deployment, and state whether plan requirement **R4** ("user adds a phone, desktop still signed
> in → QR/emoji verify from desktop, **no phrase typed**") currently holds.

**Acceptance criterion:** a per-protocol GAP / NO-GAP verdict, each backed by either a live probe,
a file:line, or an explicit ASSUMPTION; plus a statement of what must be true for R4 and whether
it is true today.

**Out of scope:** fixing anything; Element X mobile behaviour on a real handset; the WebAuthn-PRF
4S-unlock evaluation (owned by another agent).

---

## 3. INPUTS

| Class | Item | Consumed by |
|---|---|---|
| Code (siwx) | `src/oidc.rs` `provider_metadata_value`, `src/device_auth.rs` | W2, W4 |
| Code (Synapse, RO) | `config/experimental.py`, `rest/client/rendezvous.py`, `rest/synapse/client/__init__.py`, `rest/client/versions.py`, `rest/client/{sendtodevice,keys,devices}.py`, `rest/__init__.py` | W1, W3 |
| Code (Element Web v1.12.20, upstream tag) | `LoginWithQRSection.tsx`, `SessionManagerTab.tsx`, `SetupEncryptionStore.ts`, `SetupEncryptionBody.tsx` | W2 |
| Code (matrix-js-sdk 41.6.0) | `src/rendezvous/index.ts`, `src/rust-crypto/rust-crypto.ts`, `src/crypto-api/index.ts` | W2 |
| Config | `Caddyfile.production`, `Caddyfile.local`, `Caddyfile.e2e`, `e2e/real-stack/Caddyfile`, `entrypoints/matrix_server.sh`, `config/element-config.json`, `patches/element-web/force-first-device-recovery.patch` | W1, W2, W5 |
| Tests | `e2e/element/*.spec.mjs`, `e2e/browser/*.spec.mjs`, `tests/`, `src/` | W5 |
| Live (read-only) | prod `matrix.inblock.io`, `element.inblock.io`; lab `:28080/:28081/:28088` | W1, W2 |

---

## 4. ACTIVITIES → OUTPUTS (evidence)

### 4.1 W1 — Rendezvous endpoint (the prime suspect): **PRESENT**

**Hypothesis H-V1:** *IF no MSC4108 rendezvous server is configured and advertised, THEN QR
device-link cannot work regardless of siwx-oidc's correctness.* — Sound, but the antecedent is
**false**.

**Config chain (VERIFIED):**

| Link | Evidence |
|---|---|
| Synapse feature enabled | `siwx-oidc-matrix-server/entrypoints/matrix_server.sh:78` → `yq -i ".experimental_features.msc4108_enabled = true"`. That file is the container ENTRYPOINT: `dockerfiles/Dockerfile:5-6`. |
| Feature is legal under MSC3861 | Synapse `config/experimental.py:521-531` — MSC4108 raises `ConfigError` only when auth is **not** delegated; MSC3861 satisfies `auth_delegated`. **MSC4108 requires MSC3861; it is not blocked by it.** |
| Control-plane servlet registered | `rest/client/rendezvous.py:122-124` registers `MSC4108RendezvousServlet` (POST `/_matrix/client/unstable/org.matrix.msc4108/rendezvous`) when `msc4108_enabled`. |
| Data-plane resource mounted | `rest/synapse/client/__init__.py:87-88` mounts `/_synapse/client/rendezvous` when `msc4108_enabled`. |
| Advertised to clients | `rest/client/versions.py:184-191` sets `unstable_features["org.matrix.msc4108"]`. **Discovery is via `/_matrix/client/versions`, not `.well-known`** — so the absence of an `org.matrix.msc4108.rendezvous` key in `.well-known` is **correct**, not a defect (that key belongs to the superseded MSC3886 design, which this Synapse no longer implements). |
| Edge routes them | `Caddyfile.production:54-60` and `Caddyfile.local:89-95` both `handle` the two rendezvous prefixes → `matrix_synapse:8080`. |

**Live probes (VERIFIED, read-only GET; a registered POST-only servlet answers 405 / a mounted
resource answers 400, whereas an unrouted path answers 404 — the discriminator):**

```
PROD  /_matrix/client/versions               unstable_features["org.matrix.msc4108"] = true
PROD  /_matrix/client/unstable/org.matrix.msc4108/rendezvous   → 405   (registered, POST-only)
PROD  /_synapse/client/rendezvous                              → 400   (mounted)
PROD  /_matrix/client/unstable/org.matrix.definitely_not_a_thing/xyz → 404  (control)

LAB   /_matrix/client/versions               unstable_features["org.matrix.msc4108"] = true
LAB   /_matrix/client/unstable/org.matrix.msc4108/rendezvous   → 405
LAB   /_synapse/client/rendezvous                              → 400
LAB   /_matrix/client/unstable/org.matrix.definitely_not_a_thing/xyz → 404  (control)
```

> **FINDING (Q1): the rendezvous endpoint is PRESENT, enabled, advertised, and reachable through
> the edge in BOTH production and the Element lab. The prime suspect is REFUTED.**

**Sub-finding (lower severity).** Two of the four edge configs have **no** rendezvous route:
`e2e/real-stack/Caddyfile` (the :8450 bare-real-stack edge) and
`siwx-oidc-matrix-server/Caddyfile.e2e` (`grep -c -i rendezvous` → `0`). Both are headless-client
harnesses with no browser, so this does not affect users — but it does mean **no lab that could
run a real QR flow other than the Element lab**, and it silently caps what those harnesses can
ever prove.

**MSC4388 (the 2025 HPKE rendezvous) is structurally unavailable and that is correct.**
`config/experimental.py:551-557` raises `ConfigError("MSC4388 requires matrix_authentication_service
to be enabled")` — the *stable MAS* config block, which siwx-oidc does not and cannot provide
(it uses `experimental_features.msc3861`). Live: `unstable_features["io.element.msc4388"]` is
absent in prod and lab. This corroborates `skills/element-x-qr-code-specialist.md:61-70` and the
audited proposal line 185. **Consequence:** any future client that drops the 2024 MSC4108 path in
favour of MSC4388 loses QR login here with no server-side remedy short of migrating to real MAS.

### 4.2 W2 — Client offer: Element Web **does** offer both QR link and interactive verification

#### 4.2.1 Configuration

`siwx-oidc-matrix-server/config/element-config.json` (identical in prod — fetched live from
`https://element.inblock.io/config.json`):

```
:9   "sso_redirect_options": { "immediate": true },
:10  "force_verification": true,
```

`features` contains only `feature_group_calls`, `feature_video_rooms`,
`feature_element_call_video_rooms`, `feature_custom_themes`. **There is no QR-related labs flag
in Element 1.12.20 at all** — the complete `feature_*` set in the shipped bundle contains nothing
QR-related. So no flag is missing.

#### 4.2.2 The UI is in the build (VERIFIED against the live prod bundle)

`https://element.inblock.io/i18n/en_EN.751084b.json` contains the full string set for both
protocols:

```
settings|sessions|sign_in_with_qr             = "Link new device"
settings|sessions|sign_in_with_qr_button      = "Show QR code"
settings|sessions|sign_in_with_qr_unsupported = "Not supported by your account provider"
user_menu|link_new_device                     = "Link new device"
auth|qr_code_login|*                          (full MSC4108 login flow)
encryption|verification|use_another_device    = "Use another device"
encryption|verification|confirm_the_emojis    = "Confirm that the emojis below match…"
encryption|verification|scan_qr, …|qr_or_sas, …|waiting_other_device, …
```

#### 4.2.3 The exact gate (VERIFIED from upstream source at tag `v1.12.20`)

`apps/web/src/components/views/settings/devices/LoginWithQRSection.tsx`:

```ts
export async function shouldShowQrForLinkNewDevice(cli, isCrossSigningReady) {
    const doesServerHaveSupport = await isSignInWithQRAvailable(cli);
    return doesServerHaveSupport && !!cli.getCrypto()?.exportSecretsBundle && isCrossSigningReady;
}
```

`apps/web/src/components/views/settings/tabs/user/SessionManagerTab.tsx:274` renders
`<LoginWithQRSection …/>` **unconditionally**; only the button's `disabled` is gated. The
user-menu entry `user_menu|link_new_device` is gated only on `!client.isGuest()` and jumps
straight to `Mode.Show` with **no** capability pre-check.

matrix-js-sdk 41.6.0 `src/rendezvous/index.ts`:

```ts
export async function isSignInWithQRAvailable(client) {
    let metadata; try { metadata = await client.getAuthMetadata(); }
    catch (e) { logger.warn("Failed to fetch auth metadata, assuming sign-in with QR is unavailable", e); return false; }
    if (!metadata.grant_types_supported.includes(OAuthGrantType.DeviceAuthorization)) return false;
    return client.doesServerSupportUnstableFeature("org.matrix.msc4108");
}
```

Evaluating each conjunct against this deployment:

| Conjunct | Result | Evidence |
|---|---|---|
| `grant_types_supported ∋ urn:ietf:params:oauth:grant-type:device_code` | **TRUE** | `src/oidc.rs:289-293`; live PROD `GET /_matrix/client/v1/auth_metadata` → `["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]`; same in lab |
| `doesServerSupportUnstableFeature("org.matrix.msc4108")` | **TRUE** | live, prod + lab (§4.1) |
| `cli.getCrypto()?.exportSecretsBundle` | **TRUE** | matrix-js-sdk 41.6.0 `src/crypto-api/index.ts:720` (declared) and `src/rust-crypto/rust-crypto.ts:1514` (implemented) |
| `isCrossSigningReady` | **user-state dependent** | true on a healthy first device; **false after a reload** — see §4.4 |

> **FINDING (Q2): Element Web's "Show QR code" is ENABLED in this deployment for a
> cross-signing-ready session. The client-offer hypothesis is REFUTED.**
> Corollary worth recording: if a user ever *does* see the button greyed out, the displayed
> reason — "Not supported by your account provider" — is **misleading**; in this deployment the
> only realisable cause is `isCrossSigningReady === false`, i.e. the *user's own* crypto state,
> not the OP.

`sso_redirect_options.immediate: true` bypasses Element Web's own login page. That removes the
**login-page** entry point `auth|qr_code_login|scan_qr_code` ("Sign in with QR code", i.e.
Element Web acting as the *new* device). It does **not** affect the direction R4 needs (Element
Web as the *existing* device showing a QR for Element X to scan), which lives in Settings →
Sessions and in the user menu. Recorded as a scope limitation, not a gap.

#### 4.2.4 Interactive verification UI (VERIFIED)

`apps/web/src/components/structures/auth/SetupEncryptionBody.tsx:170-198`, `Phase.Intro`:

```tsx
let verifyButton;        if (store.hasDevicesToVerifyAgainst) { … use_another_device … }
let useRecoveryKeyButton; if (store.keyInfo)                   { … use_recovery_key   … }
let signOutButton;        if (this.props.allowLogout)          { … sign_out           … }
```

`onVerifyClick` → `crypto.requestOwnUserVerification()` → `VerificationRequestDialog` (SAS /
reciprocal QR). The UI is complete.

`apps/web/src/stores/SetupEncryptionStore.ts:104-119` computes the gate:

```ts
const userDevices = (await crypto.getUserDeviceInfo([ownUserId])).get(ownUserId)?.values() ?? [];
this.hasDevicesToVerifyAgainst = await asyncSome(userDevices, async (device) => {
    if (device.dehydrated) return false;
    if (!device.getIdentityKey()) return false;
    const verificationStatus = await crypto.getDeviceVerificationStatus(ownUserId, device.deviceId);
    return !!verificationStatus?.signedByOwner;
});
```

**Note (VERIFIED from source, consequence INFERRED):** the filter excludes dehydrated devices and
devices without an identity key, but it does **not** exclude the *current* device. On a reload
where the current device is still self-signed server-side, it satisfies `signedByOwner` and
counts itself — so "Use another device" can render for a user who has **no** other device. This
is consistent with `EW-L1b` (`e2e/element/ew-login.spec.mjs:135`) asserting that button visible
in a single-device test. Marked **INFERRED**, not verified end-to-end; see A7.

### 4.3 W3 — MSC3861 does not disable any of the three protocols

Read from the Synapse image overlay (read-only, unmodified):

| Surface | MSC3861 gating | Evidence |
|---|---|---|
| To-device (`/sendToDevice/*`) | **none** | `rest/client/sendtodevice.py:84-85` — `register_servlets` is unconditional |
| Keys (`/keys/query`, `/keys/upload`, `/keys/device_signing/upload`, `/keys/signatures/upload`) | **none** | `rest/client/keys.py:671-679` — all registered unconditionally. The MSC3861 references at `keys.py:539,572-578,612` only *relax* UIA for cross-signing upload; they never remove the servlet |
| Device list / single device | **partially** | `rest/client/devices.py:434-439`: only `DeleteDevicesRestServlet` is withheld under delegated auth; `DevicesRestServlet` and `DeviceRestServlet` stay |
| Rendezvous | **required by, not blocked by** | `config/experimental.py:521-531` |
| `rest/__init__.py:179-195` | worker-process gating only | not MSC3861 |

**Live confirmation that the edge does not shadow these paths** (a Caddy hijack would show a
Caddy 404 or a siwx-oidc error; instead Synapse's own errcodes come back):

```
PROD /_matrix/client/v3/devices                                  → 401 M_MISSING_TOKEN  (Synapse)
PROD /_matrix/client/v3/keys/query                               → 405 M_UNRECOGNIZED   (Synapse)
PROD /_matrix/client/v3/sendToDevice/m.key.verification.request/txn1 → 405 M_UNRECOGNIZED
PROD /_matrix/client/v3/sync                                     → 401 M_MISSING_TOKEN
LAB  /_matrix/client/v3/devices                                  → 401 M_MISSING_TOKEN
LAB  /_matrix/client/v3/sendToDevice/m.key.verification.request/txn1 → 405 M_UNRECOGNIZED
```

`Caddyfile.production:35-52` forwards only `/_matrix/client/v3/{login,logout,refresh}` to
siwx-oidc. Nothing on the verification path is intercepted.

> **FINDING (Q3): under MSC3861 Synapse continues to serve to-device messaging, all key
> endpoints, the device list, and the rendezvous server. No MSC3861 gating disables any of the
> three protocols.**

### 4.4 W4 — siwx-oidc's own half: correct, and honest about what it does not own

| Item | State | Evidence |
|---|---|---|
| `POST /device_authorization` returns `device_code`, `user_code`, `verification_uri`, **`verification_uri_complete`**, `expires_in`, `interval` | Correct (RFC 8628 complete; `verification_uri_complete` is what MSC4108's existing device needs) | `src/device_auth.rs:56-62`, `:109`, `:122` |
| Discovery advertises the grant + endpoint | Correct | `src/oidc.rs:289-295`; live prod `auth_metadata` |
| Approval issues tokens with a device_id and provisions Synapse additively | Correct | `src/device_auth.rs:917` `device_approve`; CLAUDE.md device-lifecycle contract (`provision_synapse_device_additive`, never delete-then-reuse) |
| New-identity policy on the QR path | Rejects, before `entry.did` is set | `src/device_auth.rs:1021` and `:1064` → `webauthn::reject_if_new_identity` |
| Approval-time cross-signing pre-flight | **Deliberately absent** | `src/device_auth.rs:853-859`: removed 2026-06-18 as a confirmed false positive; `DeviceApproveResponse.warning` is now always `None` |

**The critical honest boundary is already encoded in the code comment at
`src/device_auth.rs:857-859`:** *"The real MSC4108 prerequisite (cross-signing PRIVATE keys
present on the SENDING device) is not observable server-side."*

> **FINDING (Q4): siwx-oidc's half works and is correct. This is precisely the distinction the
> owner must hold: "siwx-oidc's part works" ≠ "the end-to-end flow works." Every failure mode
> below is post-token.**

### 4.5 W5 — Test coverage: **nothing proves the crypto transfer** (Q5)

**The decisive negative result.** Across `src/`, `tests/`, and `e2e/` (excluding `node_modules`),
a case-insensitive search for
`m\.key\.verification | sas | emoji | secret\.send | secret_send | verifyDevice |
requestVerification | startVerification | verificationRequest | to-device | sendToDevice |
to_device`
returns **zero matches**. No unit test, no Rust e2e suite, no Playwright spec touches interactive
verification or secret sharing at any layer.

Spec-by-spec, for the tests that *sound* like they cover this:

| Test | File:line | What it actually asserts | Proves R4? |
|---|---|---|---|
| **EW-D1** "device_authorization → wallet approve → device_code token → Matrix whoami" | `e2e/element/ew-device-link.spec.mjs:39` | Pure HTTP/OIDC: `/device_authorization` → `authorization_pending` → wallet CAIP-122 approve → `POST /token` yields `mat_`/`mcr_` → `whoami` returns the linked `device_id`. **Never opens a rendezvous session. No Element client. No crypto.** | **No.** This is the exact "a test named 'device link' that only asserts token issuance" case. |
| **EW-D2** "approver with NO cross-signing → honest terminal" | `ew-device-link.spec.mjs:160` | Asserts the server fabricates no crypto claim (`approve.body.warning ?? null` is null) and that the **dead end is externally detectable**: `expect(kqA.body.master_keys?.[seedA.user_id]).toBeUndefined()` (`:202`). A contrast leg proves the discriminator discriminates. | **No — it asserts the failure exists.** It is a truthfulness test, not a capability test. |
| **EW-X1 / EW-X2** | `e2e/element/ew-crypto.spec.mjs:33`, `:85` | Raw CS-API `keys/device_signing/upload` with **synthetic** keys from `buildCrossSigningUpload`, and the `/account` reset honesty gate. Single session. | **No.** |
| **EW-C1** full Element DOM click-path | `e2e/element/ew-clickpath.spec.mjs` | Real SPA login. But the shared helper `completeSecureBackupWizard` (`e2e/element/helpers/element-login.mjs`) **creates a recovery key on every login** (Continue → Copy → Continue → Done). Single browser context. | **No — and it does the opposite:** every Element login in the suite types through recovery-key creation. |
| **EW-L1b** | `e2e/element/ew-login.spec.mjs:135-136` | After reload, asserts the buttons `/use another device/i` and `/remove this device/i` are **visible**. It never clicks either. | **No.** This is the closest any test gets: it proves the *affordance renders*, nothing about whether it completes. |
| **EW-P2 / EW-P3** | `e2e/element/ew-passkey.spec.mjs` | "second device" = a second **OIDC session** on the same passkey. No Matrix crypto, no verification. | **No.** |
| `e2e/browser/*`, `tests/e2e_*.rs` | — | OIDC/OP layer only. | **No.** |

> **FINDING (Q5) — exact answer: NO test proves that a second device gets verified from a first
> live session without a recovery phrase.** The suite stops at the HTTP/OIDC layer in every case.
> The single spec that mentions the verification affordance (`ew-login.spec.mjs:135`) asserts
> button visibility only. `H-D8` / `AC4` in the durability plan (lines 137, 268) describe exactly
> the missing test; it does not exist yet.

**Corroborating self-assessment in the repo.** The audited proposal's own status table records
EW-D1 as **Green** and, separately, logs a P0-class finding (line 456) that on reload Element
1.12.20 lands on "Confirm your digital identity" whose *only* exits are "Use another device" or
identity **RESET** — no recovery-key entry — despite Secure Backup having completed seconds
earlier, with `room_keys/version` still returning 200. That is the deployment reproducing the
prod "verify session loop / half-reset" forensics in the lab.

**The consequence that the plan has not yet drawn (this evaluation's contribution):** that same
state, `isCrossSigningReady === false`, is the **third conjunct of `shouldShowQrForLinkNewDevice`**
(§4.2.3). A desktop session that has been reloaded therefore has its "Show QR code" button
**greyed out** at exactly the moment R4 needs it to be the verifier. G2 and the P0 finding are
the same defect seen from two sides.

### 4.6 G3 — `response_modes_supported` is absent from the OP metadata

**VERIFIED (live, both environments):** `GET /_matrix/client/v1/auth_metadata` on prod and lab
returns no `response_modes_supported` key. **VERIFIED:** matrix-js-sdk **41.6.0**
`src/oidc/validate.ts` contains **zero** references to it — hence Element Web 1.12.20 is
unaffected today, which is consistent with login working.

**REPO-SOURCED, NOT INDEPENDENTLY VERIFIED (A5):** `e2e/element/ew-zdiag-bump.spec.mjs:9-13`
records, as a first-hand lab diagnostic, that matrix-js-sdk **v42** (bundled in Element Web
1.12.24 — confirmed: `apps/web/package.json` at tag `v1.12.24` pins `matrix-js-sdk: 42.0.0`)
*hard-requires* `response_modes_supported ⊇ {query, fragment}`, and that without it 1.12.24 falls
back to the legacy `/login/sso/redirect`, which 404s under MSC3861. I could not fetch
`matrix-js-sdk` v42 sources to re-derive this (all `v42.*` tag paths returned 404 from both the
`matrix-org` and `element-hq` GitHub orgs), so it stays repo-sourced.

**Why this belongs in a "verify with other device" audit:** `isSignInWithQRAvailable()` obtains
its metadata via `client.getAuthMetadata()`, whose return type is `ValidatedAuthMetadata`, inside
a `try/catch` that **returns `false` on any validation throw**. So a metadata-validation
regression does not surface as a metadata error — it surfaces as *"QR code not supported / Not
supported by your account provider."* The Element Web upgrade is therefore simultaneously a login
blocker and a silent QR-device-link blocker.

### 4.7 H-V4 — Caddy compression on the rendezvous routes (**UNPROVEN, high value**)

**VERIFIED config divergence.** `Caddyfile.local:89` comments the rendezvous block
*"(no compression to preserve ETags)"* — but there is **no `encode off`** in that block or in
`Caddyfile.production`. `grep -n encode` finds site-level `encode zstd gzip` at
`Caddyfile.local:30` and `Caddyfile.production:25`, and the rendezvous `handle` blocks sit inside
that scope (`Caddyfile.local:89-95`, `Caddyfile.production:54-60`). **The comment describes an
intent that was never implemented.**

**VERIFIED that the encoder is live on the Synapse route:** lab `GET :28080/_matrix/client/versions`
with `Accept-Encoding: gzip` returns `Content-Encoding: gzip`, while Synapse itself sends none —
so Caddy is compressing Synapse responses on that vhost.

**ASSUMED (A4) — the causal link I could not test.** MSC4108's rendezvous channel is an
ETag-conditional protocol (`ETag` on POST/PUT, `If-Match` on PUT, `If-None-Match` for long-poll
GET). `If-Match` mandates *strong* comparison (RFC 9110 §13.1.1). Caddy's `encode` weakens ETags
on compressed responses. Synapse's handler is Rust-implemented
(`synapse/synapse_rust/rendezvous.pyi`, `max_content_length = 4 KB`) and not readable from the
image overlay, and Caddy's `encode` only fires above `min_length` (512 B default) — so the small
initial ECIES handshake would pass while a **larger later payload (the secrets bundle) would be
compressed**, weakening its ETag and 412-ing the next PUT.

**Why this hypothesis is worth the top of the queue:** its symptom signature is precisely the one
reported — *approval succeeds, tokens are issued, logs look clean, then the client dies 30–60 s
later mid-Phase-4.* That is currently attributed wholly to M5 Q2 (approver lacks XS private keys);
H-V4 is an alternative, purely infrastructural cause with the same signature that no test would
distinguish.

**Falsification test (cheap, decisive):** open a rendezvous session
(`POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous`) **through the edge**, note the
returned `ETag`, `PUT` a >512-byte body with `If-Match: <that etag>` and
`Accept-Encoding: gzip`, and compare against the same sequence direct to Synapse (bypassing
Caddy). A 412 through the edge and a 202 direct confirms H-V4. Do this in the lab, not prod.

---

## 5. Per-protocol integration table, verdicts, assumptions

### 5.1 Integration table

| # | Protocol | Integrated? | Evidence | Who owns the missing piece |
|---|---|---|---|---|
| **1** | Interactive verification (SAS / emoji) | **YES (server + client both present)** | Synapse: `sendtodevice.py:84-85`, `keys.py:671-679` unconditional; live 405 M_UNRECOGNIZED on the to-device path (reaches Synapse). Element: `SetupEncryptionBody.tsx:170-198` renders "Use another device" → `requestOwnUserVerification()`; i18n has the full SAS/emoji string set. | Nobody owns a *missing* piece. **Element Web** owns the reachability defect (crypto not restored across reload, `SetupEncryptionStore` counting the current device). **This repo** owns the total absence of proof. |
| **2** | MSC4108 QR device-link | **YES** | `msc4108_enabled` (`matrix_server.sh:78`); servlet + resource registered (`rest/client/rendezvous.py:122-124`, `rest/synapse/client/__init__.py:87-88`); advertised (`versions.py:184-191`) and **live 405/400 vs 404 control in prod AND lab**; edge routes (`Caddyfile.production:54-60`, `Caddyfile.local:89-95`); OP grant + endpoint (`src/oidc.rs:289-295`, live `auth_metadata`); `verification_uri_complete` (`src/device_auth.rs:60`); Element gate all-true (`LoginWithQRSection.tsx`, `rendezvous/index.ts`, `rust-crypto.ts:1514`). | **This repo** owns proof (G1) and the metadata landmine (G3, `src/oidc.rs`). **Element Web** owns `isCrossSigningReady` durability (G2). **Ops/matrix-server** owns H-V4 if it confirms. |
| **3** | Secret gossiping (`m.secret.send`) / secrets bundle | **YES (transport + capability present)** | To-device unconditional (as above); `exportSecretsBundle` declared `crypto-api/index.ts:720` and implemented `rust-crypto.ts:1514` in the shipped matrix-js-sdk 41.6.0. | Entirely **client-side** by design (`src/device_auth.rs:857-859` states siwx-oidc cannot observe it). **This repo** owns proof. |

### 5.2 Verdicts

| Protocol | Integration verdict | Proof verdict | Net |
|---|---|---|---|
| 1. SAS / emoji | **NO GAP** | **GAP** — zero coverage | **GAP** (reachability + proof) |
| 2. MSC4108 QR | **NO GAP** | **GAP** — zero coverage beyond token issuance | **GAP** (proof; G3 upgrade landmine; H-V4 open) |
| 3. Secret gossiping | **NO GAP** | **GAP** — zero coverage | **GAP** (proof) |

**Owner's suspicion: CONFIRMED that a gap exists. Suspected cause (missing rendezvous): REFUTED.**

### 5.3 Assumptions register

| ID | Assumption | Status | Test that settles it |
|---|---|---|---|
| **A1** | After a successful SAS verification the second device's `isSecretStorageReady()` returns true, so the patched `shouldForceVerification()` (`force-first-device-recovery.patch`) does not then demand a recovery key anyway. | **ASSUMED** — the patch's loop calls `accessSecretStorage(…, {forceReset: !hasExisting4S})`; with 4S already present it would prompt for the **existing** key. This is the single most load-bearing unknown for R4. | Two-context Playwright: login A → wizard → login B → verify B from A → assert B reaches `.mx_MatrixChat` with **zero** 4S prompts fired. This is exactly `H-D8` / `AC4`. |
| **A2** | Element X mobile still uses the 2024 MSC4108 path (not MSC4388) and scans an Element Web QR successfully. | **ASSUMED** — untestable here; no mobile in podman. MSC4388 is structurally unavailable (§4.1). | Manual: current Element X against prod. |
| **A3** | The repo's `Caddyfile.production` reflects the live prod edge. | **PARTIALLY REFUTED** — the repo file emits `m.authentication: {…, "account": …}` (nested) but live prod returns a **top-level** `"m.authentication.account"` key and no nested `account`. The files diverge. Rendezvous routing is nonetheless **VERIFIED live** (§4.1), so the conclusion is unaffected. | `cat /home/portal/portal/Caddyfile` on the prod host. |
| **A4** | Caddy weakens/alters ETags on compressed rendezvous responses, breaking MSC4108 `If-Match` (H-V4). | **ASSUMED** | §4.7 falsification test. |
| **A5** | matrix-js-sdk v42 hard-requires `response_modes_supported`. | **REPO-SOURCED** (`ew-zdiag-bump.spec.mjs:9-13`), not independently re-derived — v42 tag sources were unfetchable. The *absence* of the field is **VERIFIED** live. | Read `matrix-js-sdk@42.0.0/src/oidc/validate.ts` from npm. |
| **A6** | The lab (Element 1.12.20 + `Caddyfile.local`) is representative of prod. | **VERIFIED for the axes that matter** — same Element version (1.12.20 live), same config.json, same `msc4108` advertisement, same `grant_types_supported`. | — |
| **A7** | `SetupEncryptionStore.hasDevicesToVerifyAgainst` counts the current device, so "Use another device" can render with no other device present. | **Source VERIFIED** (`SetupEncryptionStore.ts:104-119` has no self-exclusion); **consequence INFERRED**. | Single-device lab session: reload, click "Use another device", observe whether any peer ever responds. |
| **A8** | `force_verification: true` + the vendored patch guarantee every Element **Web** first device has 4S, so M5 Q2 is rare. | **ASSUMED, and bounded** — the patch is Element-Web-only. An Element X *first* device gets no such enforcement. | Approve a QR from an EX-only account and observe. |

---

## 6. BOUNDARY CONDITIONS — what must be true for R4, and whether it holds

**R4** (`2026-07-25-session-durability-no-forced-logins.md:102`): *"User adds a phone, desktop
still signed in → QR / emoji verify from desktop, **no phrase typed**."*

The full conjunction R4 requires:

| # | Required condition | Status |
|---|---|---|
| C1 | Synapse serves to-device + key endpoints under MSC3861 | **VERIFIED TRUE** (§4.3) |
| C2 | An MSC4108 rendezvous server is enabled, advertised, and edge-reachable | **VERIFIED TRUE** (§4.1) |
| C3 | The OP advertises the device-code grant + `device_authorization_endpoint`, and returns `verification_uri_complete` | **VERIFIED TRUE** (§4.2.3, §4.4) |
| C4 | The existing device's client offers QR link and/or SAS | **VERIFIED TRUE** (§4.2) |
| C5 | The existing device **has** cross-signing private keys and a usable 4S at the moment of verifying | **NOT RELIABLY TRUE** — the P0 reload defect makes `isCrossSigningReady` false, which both blocks the QR button (§4.2.3) and is the documented M5 Q2 precondition |
| C6 | The rendezvous channel actually carries the payload end to end | **UNVERIFIED**; H-V4 is an open, untested threat to it (§4.7) |
| C7 | The new device, having received the secrets, does **not** then demand a recovery key | **ASSUMED (A1)** — the vendored `force-first-device-recovery` patch is precisely the code that could demand one, and nothing has tested it |
| C8 | Somebody has demonstrated the above at least once | **FALSE** (§4.5) |

> **R4 does not currently hold.** C1–C4 hold and are strong. R4 fails on **C8 unconditionally**
> (it has never been demonstrated at any layer), on **C5 whenever the desktop session has been
> reloaded**, and is **unresolved on C6 and C7**.
>
> This is a *weaker and more tractable* failure than "the capability is missing." Nothing needs
> to be built to make the rendezvous work — it already works. What is missing is (i) the test
> that would convert R4 from assumption to evidence, and (ii) a fix for the Element Web
> crypto-restore defect that makes the verifier unreliable.

### 6.1 Honest M5 Q1–Q5 classification of today's state

| Scenario | Terminal today | Reasoning |
|---|---|---|
| **(i) Emoji-verify a new browser session from a live desktop session** | **Q1-shaped `T_NewDeviceOK` is reachable, but UNPROVEN — and degrades to Q3/`T_ApprovedButDead` whenever the desktop has been reloaded.** The Q1–Q5 table does not have a row for "capability present, never exercised"; that is the true state. | Server surface complete (§4.3); Element offers "Use another device" (§4.2.4). But `hasDevicesToVerifyAgainst` may count the current device (A7), the desktop's crypto does not survive reload (P0 finding), and A1 is untested. |
| **(ii) QR-link a new Element X mobile from a live Element Web session** | **Q1 if and only if the desktop is cross-signing-ready at that moment; otherwise the button is disabled and the user never reaches a Q-row at all — a terminal the table does not currently name.** | The whole config chain is verified live (§4.1, §4.2.3). Given `force_verification` + the vendored patch, a *freshly logged-in* desktop is Q1-eligible. A *reloaded* one is not. Q2 (`T_ApprovedButDead`) remains the documented risk for approvers without XS; H-V4 could produce the identical signature for a fully-healthy approver. |

**Recommended addition to the M5 table:** a `Q0 / T_OfferWithheld` row — *approver not
cross-signing-ready → the QR affordance is disabled and mislabelled "Not supported by your account
provider"*. This is a distinct, currently-unnamed terminal, and it is the one a reloaded desktop
user actually hits.

### 6.2 What would settle this, in priority order

1. **Build `H-D8` / `AC4`** — the two-context Playwright leg: login A → wizard → login B →
   verify B from A → assert B cross-signed **and zero 4S prompts**. This alone converts C7/C8 and
   resolves A1. It is already specified in the durability plan; it simply does not exist.
2. **Run the H-V4 falsification test** (§4.7). Cheap, and it either eliminates a confound or
   finds a real prod bug with the exact reported signature.
3. **Fix or implement the `encode off` the rendezvous comment already claims** (`Caddyfile.local:89`,
   `Caddyfile.production:54-60`) — the comment/behaviour divergence is a defect regardless of
   whether H-V4 confirms.
4. **Add `response_modes_supported: ["query","fragment"]`** to `provider_metadata_value`
   (`src/oidc.rs:277-308`) before any Element Web upgrade — it blocks login *and* silently
   disables QR (§4.6).
5. **Escalate the Element Web crypto-restore defect (P0, line 456)** as an R4 blocker, not only a
   single-device-loop annoyance — it disables the verifier.
6. **Correct the misleading disabled-state string** context: in this deployment "Not supported by
   your account provider" can only mean `isCrossSigningReady === false`.
7. **Retire the claim in `skills/element-x-qr-code-specialist.md:74-87`** that every component is
   green with "No" blockers — that table asserts capability where this evaluation finds capability
   *without evidence*.

---

## 7. Invariants respected during this evaluation

- No source, config, or plan document modified; this file is the only artifact written.
- No container started, stopped, or restarted. All live evidence is idempotent read-only `GET`;
  no rendezvous session was created, on prod or in the lab.
- Synapse image overlay read only.
- `docs/design/2026-07-25-webauthn-prf-4s-unlock-evaluation.md` untouched.
