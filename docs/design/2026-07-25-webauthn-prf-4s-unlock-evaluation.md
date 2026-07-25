# WebAuthn PRF as a Matrix 4S unlock path — evaluation

**Written:** 2026-07-25
**Method:** `/logic-model` (CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY CONDITIONS)
**Status:** evaluation only. No code was written or modified.
**Verdict (short):** **REJECT as stated. PARK a narrowly-redefined variant.** The mechanism is
real, but the specific shape proposed — reusing this deployment's passkey-first *login*
credential to unlock 4S — is architecturally unsound, and every remaining variant requires
siwx-oidc to do nothing at all.

---

## The claim under evaluation (verbatim)

> "WebAuthn's PRF extension lets an authenticator derive a stable secret from a passkey
> locally, which could unlock 4S without a typed phrase — same security property (server never
> sees it), much better UX, and a natural fit for a passkey-first deployment like this one. I
> have not verified Element's current support for it and siwx-oidc cannot deliver it alone:
> it's client-side work in Element plus a 4S key-derivation change. Treat it as a direction to
> investigate, not an available fix."

Scorecard against the finished analysis:

| Sub-claim | Finding |
|---|---|
| "PRF lets an authenticator derive a stable secret from a passkey locally" | **TRUE** (§Q1) |
| "could unlock 4S without a typed phrase" | **TRUE mechanically, MISLEADING operationally** — a typed recovery key must remain enrolled, so PRF removes *typing it in the common case*, not the phrase (§Q5) |
| "same security property (server never sees it)" | **FALSE as scoped.** True only if the ceremony runs under an RP ID the *client* owns. Under this deployment's RP ID it is the auth provider's own origin, which collapses the MSC3861 trust separation (§Q2) |
| "much better UX" | **PARTLY** — Element Web only; Element X mobile is hard-blocked (§Q2.5, §Q6) |
| "a natural fit for a passkey-first deployment like this one" | **BACKWARDS.** The passkey-first login credential is precisely the one that must NOT be used (§Q2) |
| "I have not verified Element's current support" | Correct to flag. Support is **zero** — no MSC, no code, no issue (§Q3) |
| "siwx-oidc cannot deliver it alone" | **UNDERSTATED.** In the only sound design, siwx-oidc's contribution is *nil* (§Q7) |

---

## Phase 1 — CONTEXT

### Deployment topology (verified)

| Component | Host | Relevance |
|---|---|---|
| siwx-oidc (auth provider / OP) | `siwx-oidc.inblock.io` | WebAuthn RP ID and RP origin |
| Element Web (client) | `element.inblock.io` | would have to perform any 4S key derivation |
| Synapse (homeserver) | `matrix.inblock.io` | stores `m.secret_storage.*` ciphertext |

RP ID defaults to the hostname of `SIWEOIDC_BASE_URL` and is overridable by `SIWEOIDC_RP_ID`
(`src/webauthn.rs:671-707`, `build_webauthn`). Hosts confirmed in
`docs/2026-06-18-passkey-followup-test-plan-and-handoff.md:169` and
`docs/2026-05-19-third-party-client-cors-analysis.md:40,57`.

**So every passkey this deployment has ever issued is bound to RP ID `siwx-oidc.inblock.io` —
the authentication provider's own origin.** This single fact drives the verdict.

### Current WebAuthn surface (verified)

| # | Fact | Evidence |
|---|---|---|
| L1 | Registration requests **no** extensions: `start_passkey_registration(uid, name, name, None)`. The only post-hoc mutation is `require_resident_key`. | `src/webauthn.rs:244-247`, `:224-231`, `:570` |
| L2 | `webauthn-rs-proto 0.6.0-dev` `RequestRegistrationExtensions` exposes `hmac_create_secret` but has **no `prf` field**. Crate doc: *"Browsers support the creation of the secret, but not the retrieval of it."* | `~/.cargo/registry/.../webauthn-rs-proto-0.6.0-dev/src/extensions.rs:59-83` |
| L3 | The frontend passes the server's `publicKey` options through verbatim; no client-side extensions. | `js/ui/src/App.svelte:182-190, 253-263, 368-376` |
| L4 | Assertion verification is manual (aqua-auth): challenge, origin, RP ID, UV flag, sign counter. It never reads client extension results. | `src/webauthn.rs:409-516` |
| L5 | Zero occurrences of `prf`, `hmac-secret`, `largeBlob`, or related-origins anywhere in the repo. | repo-wide grep |

### Element client control (verified — materially changes the cost model)

| # | Fact | Evidence |
|---|---|---|
| L6 | **Element Web is already built from source at pinned tag `v1.12.20` with a vendored patch**, in CI. The patch edits `MatrixChat.tsx` and calls `accessSecretStorage` / `cli.secretStorage.hasKey()`. | `../siwx-oidc-matrix-server/dockerfiles/Dockerfile.element`, `patches/element-web/force-first-device-recovery.patch`, `docs/element-web-source-build.md` |
| L7 | Element X mobile authenticates through a **system browser** (Chrome Custom Tabs / `ASWebAuthenticationSession`) pointed at `siwx-oidc.inblock.io`. The native app performs no WebAuthn ceremony and is a stock app-store binary. | `../siwx-oidc-matrix-server/docs/2026-05-23-element-x-mobile-compatibility.md` steps 4-8 |
| L8 | "Forking Element Web" is an explicit non-goal of the current phase plans. | `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md:146,479` |
| L9 | The CDP virtual authenticator used by the e2e lab supports `hasPrf` and `hasHmacSecret`, so PRF *is* testable in the existing harness. | https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/ ; `e2e/element/ew-passkey.spec.mjs` |

### The actual user pain this idea was proposed against (verified)

> **P0-class open finding:** on reload, Element 1.12.20 + `force_verification` restores auth but
> NOT crypto: lands on "Confirm your digital identity" whose ONLY exits are "Use another device"
> or identity RESET — **no recovery-key entry**. 4S exists server-side and the backup is
> reachable at gate time. Element-build UX gap, not a siwx failure.
> — `docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md:456`

**This is decisive for prioritisation.** The bottleneck is not that entering the recovery key is
tedious; it is that Element **does not offer the unlock path at all** at the gate users actually
hit. A PRF-derived key would arrive at the same gate and find the same absent affordance.

---

## Phase 2 — GOAL

> **Decide whether siwx-oidc should invest in WebAuthn-PRF-derived unlocking of Matrix 4S.**

**Acceptance criterion:** a PURSUE / PARK / REJECT verdict in which every causal link is either
backed by a citation (spec text, file:line, issue number, URL) or explicitly labelled an
ASSUMPTION, and in which the RP-ID question is settled either way.

**Explicitly out of scope:** implementing anything; redesigning the recovery UX; authoring an
MSC; changing the vendored Element patch; any production change.

---

## Phase 3 — INPUTS

| Input | Consumed by |
|---|---|
| `src/webauthn.rs`, `js/ui/src/App.svelte`, `Cargo.lock` | Q1, Q2 (current ceremony + RP ID) |
| `../siwx-oidc-matrix-server/{dockerfiles,patches,docs}` | Q2.5, Q7 (who can change Element) |
| W3C WebAuthn L3 (§ prf, § related origins), FIDO CTAP 2.1 `hmac-secret`, MDN, Yubico PRF guides | Q1, Q2, Q6 |
| Matrix C-S spec § Secret storage; matrix-js-sdk `src/secret-storage.ts`, `src/crypto-api/index.ts`; element-web `apps/web/src/SecurityManager.ts`; matrix-rust-sdk `crates/matrix-sdk/src/encryption/secret_storage/` | Q4 |
| GitHub REST search over matrix-org / element-hq orgs; matrix-spec-proposals `proposals/` tree | Q3 |
| Bitwarden, Dashlane, Yubico envelope designs | Q5 (prior art) |

---

## Phase 4 — ACTIVITIES AND OUTPUTS

Each hypothesis is stated as a falsifiable if-then link, then tested.

### Q1 — Mechanism. What does PRF actually give you?

**H1: IF an authenticator supports the WebAuthn `prf` extension, THEN a relying party can obtain
a stable 32-byte secret bound to (credential, salt), which the server never sees.**
→ **CONFIRMED**, with several material qualifications — three of which (retrofittability,
create-time unavailability, and provider-dependent sync stability) change the design.

| Property | Finding | Source |
|---|---|---|
| Derivation | The client hashes the RP's salt with a domain-separation prefix before handing it to the authenticator. W3C L3 §10.1.4, verbatim: *"Let `salt1` be the value of `SHA-256(UTF8Encode("WebAuthn PRF") \|\| 0x00 \|\| eval.first)`."* The authenticator then computes `output1 = HMAC-SHA-256(CredRandom, salt1)`. | [W3C WebAuthn L3 §10.1.4](https://www.w3.org/TR/webauthn-3/); [CTAP 2.1 PS §12.5](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) |
| Purpose of the prefix | W3C: *"This separation is achieved by hashing the provided PRF inputs with a context string to prevent evaluation of the PRFs for arbitrary inputs."* Note it separates **WebAuthn from native/platform** use of the same authenticator — **it does not include the RP ID**. | W3C L3 §10.1.4 |
| Determinism | Same credential + same salt ⇒ same 32 bytes, *"for the lifetime of the credential."* | W3C L3 §10.1.4 |
| Output size | Exactly 32 bytes. *"The PRFs provided by this extension map from `BufferSource`s of any length to 32-byte `BufferSource`s."* `first`/`second` allow two outputs in one ceremony (designed for key rotation). | W3C L3 §10.1.4 |
| Binding | Bound to the credential's `CredRandom`, therefore to the credential — and the credential is bound to its RP ID (`rpIdHash` is inside signed `authenticatorData`). Another RP cannot obtain the same output, **because it can never obtain an assertion from that credential** — not because the salt is RP-scoped. | W3C L3 §6.1, §7.2, §13.4.9 |
| **UV does *not* change the web-visible output** | CTAP keeps two secrets, `CredRandomWithUV` / `CredRandomWithoutUV`, chosen by the `uv` bit in the *response*. But W3C L3 collapses this: *"This extension only exposes a single PRF per credential and, when implementing on top of `hmac-secret`, that PRF MUST be the one used for when user verification is performed. **This overrides the `UserVerificationRequirement` if necessary.**"* So requesting PRF from the web effectively **forces UV**, and the output is stable. (A native app speaking raw CTAP *can* reach the non-UV secret — a different 32 bytes.) | CTAP 2.1 §12.5; W3C L3 §10.1.4 |
| Create-time evaluation | `prf.enabled` at `create()` means only *"the PRF is available for use with the created credential"* — `results` may legitimately be absent. Getting outputs at `create()` requires the CTAP 2.2 **`hmac-secret-mc`** extension (§12.8; YubiKey firmware 5.8+) or an equivalent platform API. W3C's text still says only *"a future extension to [FIDO-CTAP]"*. **Design for `create()` → `get()`.** | W3C L3 §10.1.4; [CTAP 2.2 PS §12.8](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html); [Yubico yesdk](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html) |

**Must PRF be requested at registration? Largely NO — and this is load-bearing for §Phase 5 R1.**
CTAP 2.1 §12.5 `authenticatorMakeCredential`, verbatim:

> "The authenticator generates two random 32-byte values (called **CredRandomWithUV** and
> **CredRandomWithoutUV**) and associates them with the credential. **Note:** Authenticator SHOULD
> generate CredRandomWithUV / CredRandomWithoutUV and associate them with the credential, **even
> if hmac-secret extension is not present** in authenticatorMakeCredential request."

So **PRF is retrofittable onto credentials created without any PRF request** on conforming
authenticators. This is a `SHOULD`, not a `MUST`, so older security keys may not comply (Yubico's
developer guide still advises signalling intent at registration, and Corbado notes *"older
security keys may only generate an hmac-secret if it was explicitly requested during credential
creation"*). But the default posture is: **this deployment's existing extension-free credentials
(L1) are, on modern authenticators, already PRF-capable.**

**Loss of the secret:** authenticator factory reset (CTAP 2.2 §6.6 `authenticatorReset`
*"invalidates all generated credentials"*), credential deletion (§6.8.5), or re-registration all
destroy or replace `CredRandom`. Re-registration mints a **new random** CredRandom — there is no
re-derivation from a device seed, so PRF material cannot be recovered by re-enrolling.

**Synced-passkey portability — no spec guarantee, and there is a shipped data-loss precedent.**
Neither W3C nor CTAP says a synced copy of a credential yields the same PRF output; it is purely
provider behaviour. Apple's implementation *violated* the expectation for six months: on
iOS 18.0–18.3 / macOS 15.0–15.3 the hybrid (cross-device QR) path returned a **different** PRF
output than the local path for the same credential and salt. An Apple engineer confirmed on
[Apple Developer Forums 764730](https://developer.apple.com/forums/thread/764730): *"Yes this was
a bug. The PRF values returned over hybrid should match the ones returned locally for the same
input. This issue should be fixed in the current iOS 18.4 and macOS 15.4 betas."* Data encrypted
under the pre-18.4 value became permanently undecryptable, with no migration guidance.
**Google Password Manager cross-device sameness is unverified in either direction** (A-4).

---

### Q2 — THE CRITICAL QUESTION: origin / RP-ID binding

The claim frames the danger as *transmission*: siwx-oidc would obtain the secret and "have to
transmit it to Element". **That framing is too weak and it hides the real problem.** The problem
is **capability**, not transport.

#### H2.1: IF the siwx-oidc *server* obtains the PRF output, THEN the E2EE property is destroyed.
→ **CONFIRMED, but nearly vacuous.** PRF outputs are returned only in
`getClientExtensionResults()` in the browser; they appear in neither `clientDataJSON` nor
`authenticatorData`. The server is structurally excluded *unless its own JavaScript deliberately
POSTs the value*. So this variant is not something that could happen by accident — it would be
an active, auditable exfiltration. It is a REJECT, but it is not the interesting failure.

#### H2.2: IF the ceremony runs in siwx-oidc's *browser* context and the key is passed cross-origin to Element, THEN the property survives.
→ **REFUTED.** Two independent reasons:

1. The JS performing the derivation is served by the auth provider. The E2EE guarantee degrades
   from *cryptographic impossibility* to *the operator promises its login bundle is honest*.
   This is exactly the objection Matrix's own crypto lead raises against the structurally
   identical PAKE design in [element-meta#3038](https://github.com/element-hq/element-meta/issues/3038)
   (richvdh, 2025-11-21): *"We are basically trusting the auth server not to do anything
   nefarious, like exfiltrate the recovery key, or serve us compromised javascript. This means
   it wouldn't be appropriate for general-usage deployments."* siwx-oidc's stated purpose
   (CLAUDE.md, line 1) is **general community use**.
2. Cross-origin transport of a root E2EE secret (URL fragment, `postMessage`, opener channel) is
   an entirely new attack surface for no benefit — Element must be patched to receive it either
   way, and if you are patching Element you can have Element do the ceremony itself.

#### H2.3: IF Related Origin Requests let `element.inblock.io` run ceremonies under RP ID `siwx-oidc.inblock.io`, THEN the existing credentials can be reused safely with no re-enrollment.
→ **First half TRUE, second half REFUTED.** This is the crux of the whole evaluation.

Mechanism (verified): WebAuthn L3 Related Origin Requests. The RP ID's host serves
`https://{RP_ID}/.well-known/webauthn` with `Content-Type: application/json`:

```json
{ "origins": ["https://element.inblock.io"] }
```

A browser that supports ROR fetches this file (no credentials, no referrer, https only) and
permits a listed origin to run ceremonies under that RP ID. W3C L3 §5.11:

> "WebAuthn Clients supporting this feature **MUST support at least five registrable origin
> labels**."

The budget counts **registrable origin labels** (brands), not URLs: `element.inblock.io` and
`siwx-oidc.inblock.io` both reduce to the single label `inblock`, so this deployment would spend
**1 of 5**. Support: Safari/WebKit 18.0 (verified), Firefox 152 desktop + Android (May 2026),
Chrome/Edge ~128 (commonly cited; not listed in Chrome's own 128/129 release notes — treat as
approximate and feature-detect via `PublicKeyCredential.getClientCapabilities()`
`"relatedOrigins"`). Crucially, **the credential's RP ID does not change** — §5.11 requires RPs
to *"choose a common RP ID to use across all ceremonies from related origins"*; ROR widens the
set of *calling origins*, it never migrates a credential.
([W3C L3 §5.11](https://www.w3.org/TR/webauthn-3/), [WebKit Safari 18.0](https://webkit.org/blog/15865/webkit-features-in-safari-18-0/), [Firefox 152 release notes](https://www.firefox.com/en-US/firefox/152.0/releasenotes/), [web.dev](https://web.dev/articles/webauthn-related-origin-requests))

So ROR *would* technically work. **It is nevertheless the wrong answer, because it does not
remove the auth provider's own capability — it only adds a second holder of it.**

> **The RP-capability argument.**
> 1. A PRF output is a deterministic function of (credential `CredRandom`, salt), obtainable by
>    any ceremony run under the credential's RP ID from a permitted origin.
> 2. This deployment's login credentials have RP ID `siwx-oidc.inblock.io` — the auth provider's
>    own origin (§CONTEXT).
> 3. The salt and derivation are necessarily public: they live in open-source client code.
> 4. Therefore, if the 4S key were derived from that credential, **the siwx-oidc origin could
>    compute it during any ordinary login**, using the exact user-verification gesture the user
>    already performs to sign in. No extra prompt, no visible anomaly, every session.
> 5. With the 4S key the operator obtains `m.cross_signing.self_signing` — and it can already
>    mint a token for the user, so it can already read that ciphertext from the homeserver. It
>    could then **silently cross-sign a device it controls**, which is precisely the capability
>    Matrix E2EE exists to deny the server. It also obtains `m.megolm_backup.v1` → message
>    history.
> 6. Adding a salt-secret, an envelope, or a server-stored random does not help: the auth
>    provider can read anything the homeserver holds by minting a token.

This is not merely "one more origin with the secret". MSC3861's entire rationale is that the
authentication secret goes to the *authentication server* and the E2EE secret does not — richvdh
again, in #3038: *"the whole point of E2EE is that a user with access to the server should not
have access to the encrypted content of messages. So the client still has to have some secret
that isn't available to the authentication system."* Deriving 4S from a credential whose RP ID
is the auth provider re-merges the two trust domains that MSC3861 deliberately split.

Independent corroboration that this is the recognised crux — ara4n, same thread, 2025-12-01, in
the only place in the entire Matrix ecosystem where PRF is discussed for this purpose:

> *"it feels a bit like we should explain how this compares to encrypting they with prf from a
> passkey and storing it on the HS. as far as I can see they are almost equivalent (**ie you have
> to trust the domain the passkey secures**)…"*

Exactly so. And in this deployment, the domain the passkey secures is the auth provider.

#### H2.4: IF the passkeys were re-registered under the shared parent RP ID `inblock.io`, THEN both apps could use them.
→ **TRUE and strictly worse.** RP ID is fixed at credential creation and is immutable. W3C L3:
*"A public key credential can only be used for authentication with the same entity (as identified
by RP ID) it was registered with"*; `rpIdHash` is *"SHA-256 hash of the RP ID the credential is
scoped to"* and sits inside the signed `authenticatorData`, which both §7.1 and §7.2 require the
RP to verify. At the CTAP layer `authenticatorGetAssertion` looks credentials up **by** `rpId`, so
the authenticator will not even surface a credential scoped elsewhere. **There is no migration
mechanism in the spec** — the only path is re-registration, which mints a new credential with a
new random `CredRandom` and therefore entirely different PRF outputs (Q1).

So this variant costs **100% re-enrollment of every existing passkey**, with an unavoidable
re-wrap window for any PRF-derived material, and it widens the credential to *every* present and
future `*.inblock.io` subdomain plus any subdomain takeover — an implicit, unbounded allowlist
where ROR is at least explicit and capped at five labels. Note that setting the parent RP ID is
the *standard* advice for sibling subdomains (it needs no well-known file and no browser-version
gate); we reject it here for a deployment-specific reason, namely that one of those siblings is
the authentication provider. And it does not fix H2.3 anyway: the auth provider's origin is still
inside the widened set.

#### H2.5: IF Element performs its own ceremony under an RP ID it owns, THEN the property survives.
→ **CONFIRMED — and this is the only sound variant.**

Element Web at `element.inblock.io` registers its **own, separate** credential under RP ID
`element.inblock.io`. siwx-oidc's origin can never assert that RP ID, so it can never derive the
secret. And Element Web is already the party that legitimately holds the plaintext cross-signing
keys after any unlock, so this grants **no new capability to any party**. No trust regression.

Costs and consequences of the sound variant:
- A **second passkey** the user must enroll and understand (one for login, one for recovery).
- **Element X mobile is hard-blocked.** It is a stock app-store binary; native WebAuthn there
  would require `inblock.io` in element-hq's Digital Asset Links / `apple-app-site-association`,
  which this deployment cannot add (L7). The system-browser OIDC flow cannot help: the ceremony
  would run at the siwx-oidc origin, which is exactly H2.3.
- **siwx-oidc's contribution is zero.** The feature lives entirely in Element.

#### Q2 verdict

| Variant | Reuses login passkey? | Trust regression | Re-enrollment | Viable |
|---|---|---|---|---|
| siwx-oidc server obtains PRF | — | total | — | **REJECT** |
| siwx-oidc browser JS derives + transfers to Element | yes | severe (H2.2) | none | **REJECT** |
| Related Origin Requests (`/.well-known/webauthn`) | yes | severe (H2.3) — ROR adds a holder, never removes one | none | **REJECT** |
| Parent RP ID `inblock.io` | no (re-register) | severe + unbounded | **all credentials** | **REJECT** |
| Separate Element-origin credential | **no** | **none** | new credential, additive | **only sound variant** |

**Answer to the question as posed:** yes, the RP-ID binding determines viability — but not in the
direction the claim assumed. It does not merely forbid siwx-oidc from *running* the ceremony; it
forbids the login credential from *being* the PRF credential at all. The claim's "natural fit for
a passkey-first deployment like this one" is inverted: passkey-first login is what makes this
deployment the *wrong* place to put PRF-derived 4S.

---

### Q3 — Upstream reality check

**H3: IF Element / matrix-js-sdk / matrix-rust-sdk / Element X support PRF-derived 4S keys today,
THEN this is an integration exercise.** → **REFUTED, flatly.**

**No MSC exists.** Verified against the `proposals/` git tree (286 files: no filename contains
`passkey`, `webauthn`, `fido`, or `prf`) and against full-text issue/PR search of
`matrix-org/matrix-spec-proposals`. Targeted searches: `webauthn` → 3 hits (MSC3861 #3861,
MSC2271 #2271, MSC1998 #1998), `passkey` → 2 hits (MSC4161 #4161, MSC3861 #3861). Every hit is
incidental. The nearest conceptual ancestor,
[MSC3265 "Login and SSSS with a Single Password"](https://github.com/matrix-org/matrix-spec-proposals/pull/3265),
is password-based and was **closed 2022-12-12**.

**No implementation exists.** Zero PRF code or open work item in element-web, matrix-js-sdk,
matrix-rust-sdk, element-x-android, element-x-ios. `org:element-hq PRF in:title` → **0 results**.
`matrix-org/matrix-rust-sdk "PRF"` → **0 results**. Also nothing in third-party clients (Cinny,
FluffyChat).

**The entire upstream footprint of this idea is two stale discussion threads:**

| Ref | State | Last activity | Content |
|---|---|---|---|
| [matrix-org/matrix-spec#1987](https://github.com/matrix-org/matrix-spec/issues/1987) — "Should we do away with 4S secret storage in favour of deriving everything deterministically from the recovery key?" | **open** | **2025-02-20** (stale ~17 months) | The only place PRF is proposed as a mechanism: *"a **WebAuthn PRF-enabled key (e.g. a Yubikey) could directly act as your entire crypto identity**"*. richvdh: *"I really like this idea… represents security improvements and (ultimately) a simplification."* Blocker identified in-thread: indefinite two-way backward compatibility with the deployed 4S ecosystem. |
| [element-hq/element-meta#3038](https://github.com/element-hq/element-meta/issues/3038) — "Derive or store encrypted a 4S key on the Authentication server" | **open**, no labels, no assignee | **2025-12-02** | Proposes a **PAKE**, not PRF. ara4n's comment asks how it compares to *"encrypting they with prf from a passkey"*; richvdh replies *"I'm still trying to wrap my head around the different approaches here"* and the thread has been silent since. |

**Element's actual direction of travel is the opposite.** The 2025-26 "Recovery" rework is copy
and flow changes with zero crypto change, and
[element-meta#3228 (ER-233)](https://github.com/element-hq/element-meta/issues/3228) is
**re-introducing user-chosen passphrases** — already shipping in Element X
([element-x-android#6944](https://github.com/element-hq/element-x-android/pull/6944), merged
2026-06-17; [element-x-ios#5849](https://github.com/element-hq/element-x-ios/pull/5849)).
Element's most recent public statement on recovery UX
([2026-02-04](https://element.io/blog/decoding-the-hidden-trade-offs-of-e2ee-and-usability/))
does not mention passkeys, WebAuthn, PRF, or hardware authenticators at all.

**MAS is behind siwx-oidc even on passkey *login*.**
[MAS PR #4234 "Passkeys (experimental)"](https://github.com/element-hq/matrix-authentication-service/pull/4234)
is an **open draft** (created 2025-03-17, last updated 2026-06-26), community-authored, blocked
partly on design; its own out-of-scope list mentions nothing about PRF or 4S. Community
assessment 2026-06-08: *"Both seem to have lost traction."*

**Plainly: nothing exists. This is not "unverified support" — it is confirmed absence.**

---

### Q4 — 4S key-derivation compatibility

**H4: IF a PRF-derived 32-byte key can be slotted in as an additional 4S key descriptor without a
spec change, THEN the spec is not the blocker.** → **CONFIRMED at the spec layer, REFUTED at the
client layer.**

**Spec layer — no MSC needed.** The `algorithm` field
(`m.secret_storage.v1.aes-hmac-sha2`) describes how *secrets are encrypted*, not where the key
came from; the spec has no notion of key provenance. `passphrase` is **optional** — a raw-key
descriptor is the normal case today (that *is* a recovery key). The `iv`/`mac` check is a pure
function of the 32 raw key bytes (HKDF-SHA256 with a zero salt and empty `info` → AES key ‖ MAC
key; encrypt 32 zero bytes; HMAC the ciphertext), so **any** 32 bytes from any source produce a
valid check. Both SDKs also treat the check as optional and fail open.
([spec § Key storage](https://spec.matrix.org/latest/client-server-api/#key-storage))

**Multiple keys are explicitly specified.** *"Users can have multiple keys"*, and the spec's own
worked example shows one secret's `encrypted` map carrying `key_id_1` and `key_id_2`
simultaneously, with `m.secret_storage.default_key` naming one. So PRF and a typed recovery key
coexisting is spec-legal by construction.

**Client layer — four independent blockers, all verified in source:**

| # | Blocker | Where |
|---|---|---|
| 1 | Element Web refuses non-default keys outright: `throw new Error("Multiple storage key requests not implemented")` when >1 non-default key is offered, and `throw new Error("Request for non-default 4S key")` — *"We only prompt the user for the default key"* | element-web `apps/web/src/SecurityManager.ts`, `getSecretStorageKey` |
| 2 | matrix-rust-sdk (⇒ Element X) only ever opens the **default** key; a non-default descriptor is never looked at. `Recovery::recover(&str)` takes a base58 string, with no public raw-bytes entry point (`SecretStorageKey::from_bytes` is `pub(crate)`) | `crates/matrix-sdk/src/encryption/secret_storage/mod.rs`, `.../recovery/mod.rs` |
| 3 | js-sdk readiness checks are default-key-only, so an extra key never counts toward "4S is ready" and cannot silence Element's out-of-sync nagging | `src/rust-crypto/secret-storage.ts`, `src/rust-crypto/rust-crypto.ts` |
| 4 | js-sdk `ServerSideSecretStorageImpl.store()` **rebuilds the whole `encrypted` map**; every internal caller omits the `keys` argument ⇒ default key only ⇒ **a co-tenant PRF entry is silently deleted** on the next secret write. (matrix-rust-sdk does the opposite and preserves co-tenants.) | `src/secret-storage.ts` |

**Extension points that do exist:**
- `CryptoCallbacks.getSecretStorageKey?: (opts: { keys: Record<string, SecretStorageKeyDescription> }, name: string) => Promise<[string, Uint8Array] | null>` — public, **async**, returns raw bytes. An embedder building on matrix-js-sdk could implement PRF-backed 4S today with **zero forks**. (`matrix-js-sdk/src/crypto-api/index.ts`)
- Element Web consults a module extension before prompting:
  `ProvideCryptoSetupExtensions.getSecretStorageKey(): Uint8Array | null`
  (`matrix-react-sdk-module-api/src/lifecycles/CryptoSetupExtensions.ts`). It **bypasses** the
  non-default-key throw. Two hard limits: it is **synchronous** and takes **no arguments**, so a
  `navigator.credentials.get()` (async, requires user activation) cannot run inside it — the PRF
  output would have to be obtained earlier and cached.

**The elegant zero-MSC shape** (if the sound variant were ever pursued): make the PRF output *be*
the 4S key bytes, set it as the default key, **and additionally render those same 32 bytes in the
standard base58 `EsT…` representation and show them to the user once**. To Element Web and
Element X it is then an ordinary recovery key they can accept by paste; a patched/extended client
reproduces it silently via PRF. This neutralises blockers 1-3. Note it also makes the mandatory
fallback fall out for free — and it makes the H2.3 argument *sharper*, because the PRF output
then literally **is** the recovery key.

---

### Q5 — Multi-credential and loss scenarios

**H5: IF PRF unlocks 4S, THEN the typed recovery key can be removed.** → **REFUTED.**

**Enrollment of passkey #2.** Each credential has its own `CredRandom`, so
`PRF(cred_A, salt) ≠ PRF(cred_B, salt)`. Two schemes, both standard:

- **Per-credential 4S key** — each passkey gets its own `m.secret_storage.key.<id>` and an entry
  in every secret's `encrypted` map. Spec-native; blocked client-side by Q4 blockers 1-4.
- **Envelope / wrapping** — the industry-standard shape. Bitwarden: PRF output → HKDF → 32-byte
  AES key + 32-byte MAC key; that key encrypts a **PRF private key**; the matching **public key**
  encrypts the account symmetric key. Up to five passkeys, *"each maintaining independent
  encryption status"* — the asymmetric indirection is exactly what makes enrolling passkey N+1
  cheap and independent. Yubico recommends the same *"multiple encrypted copies of the DEK, each
  wrapped by a different KEK"*.
  ([Bitwarden](https://bitwarden.com/help/login-with-passkeys/), [Yubico](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html))

**Invariant shared by both: enrolling an additional PRF passkey requires a session that already
holds the plaintext secrets.** You cannot cold-enroll. The bootstrap problem is therefore
unchanged — first unlock on a new platform still needs a typed recovery key or device-to-device
verification.

| Event | Effect on the PRF path | Recovery |
|---|---|---|
| Authenticator factory reset | `CredRandom` destroyed | another enrolled key |
| Passkey deleted (user, or GPM/iCloud wipe) | same | another enrolled key |
| **Only PRF key enrolled and lost** | **4S unrecoverable** → identity reset + history loss | **none** |
| iCloud Keychain → Android migration | credential does not portably migrate; PRF output does not follow | re-enroll from an unlocked session, or typed key |
| Authenticator lacks PRF (older security keys; iOS + any roaming key; see Q6) | no PRF path | typed key |
| **Provider changes the PRF output for the same credential** | **Not hypothetical.** iOS 18.0–18.3 / macOS 15.0–15.3 returned a different PRF output over the hybrid path than locally; Apple confirmed it as a bug fixed in 18.4/15.4. Anything encrypted under the old value became **permanently undecryptable**, with no migration path. | none — must version-tag every PRF-wrapped blob and retain the typed key |

**Every shipped product keeps a fallback.** Bitwarden: *"Your master password is required to
unlock your vault."* Dashlane removed the master password but replaced it with a
device-transfer flow, and ships multi-key support explicitly *"so users aren't locked out if a
key is lost or damaged."* Yubico: on PRF failure, *"do not treat it as a hard error."*

**Conclusion:** PRF is an **unlock accelerator layered over a retained fallback secret, not a
replacement for it.** It removes *typing the phrase in the common case*, not the phrase.

**Consequence specific to this deployment:** the vendored `force-first-device-recovery` patch
exists precisely to force recovery-key **creation** at first login. PRF would not remove that
step. The onboarding friction stays; only re-entry becomes a biometric tap — on Element Web, on
a device holding the credential.

---

### Q6 — Support matrix

**H6: IF PRF is broadly supported, THEN a PRF-only path is viable.** → **REFUTED; support is good
but uneven, and the gaps land exactly where this deployment needs them not to.**

Browser engines (PRF at `get()`; create-time `results` is a separate, much narrower capability —
see Q1):

| Engine | PRF at `get()` | Confidence |
|---|---|---|
| Chrome / Edge desktop + Android | 116 | MDN BCD; the Chrome Status entry records no milestone |
| Safari / iOS / iPadOS / macOS | Safari 18 / iOS 18 / macOS 15 | **Verified** — [WebKit Safari 18.0 notes](https://webkit.org/blog/15865/webkit-features-in-safari-18-0/). (MDN/caniuse record `safari: false` for the `get()` path; that BCD cell is a known data defect) |
| Firefox desktop | 135 Windows/Linux, **139** all desktop incl. macOS | **Verified** — [Bugzilla meta 1863819](https://bugzilla.mozilla.org/show_bug.cgi?id=1863819), MDN Firefox 139 notes |
| Firefox Android | 149 | Bugzilla 1958716 FIXED; MDN BCD still says `false` (stale) |
| **Android WebView** | **not supported** | MDN BCD |

Authenticator-type restrictions matter more than browser versions. Per Adam Langley (Chromium
WebAuthn owner), blink-dev, 2024-08-27: security keys ✅, hybrid/caBLE ✅, Google Password Manager
✅, iCloud Keychain ✅, **Windows Hello ❌**, **macOS profile authenticator ❌**.

| Authenticator | PRF |
|---|---|
| YubiKey 5 Series / Bio Series | Yes (`hmac-secret` in firmware since 2019). Create-time `hmac-secret-mc` needs **firmware 5.8+** |
| Nitrokey 3, Token2 T2F2, SoloKeys Solo 1 | Yes (vendor-confirmed) |
| **Any roaming key on iOS / iPadOS** | **No** — *"Apple's current WebAuthn implementation on iOS and iPadOS does not support passing extension data, including `prf`, to or from an external, roaming authenticator"* ([Yubico](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)). Android NFC also ✗ (USB ✓) |
| KeePassXC | No, both directions ([#3560](https://github.com/keepassxreboot/keepassxc/issues/3560), open since 2019) |
| **Element X (native)** | **Not applicable at all** — no WebAuthn in matrix-rust-sdk; stock app-store binary (L7) |

Feature detection: `PublicKeyCredential.getClientCapabilities()["extension:prf"]` for the client
half, then check for the presence of `results` — **never** branch on `enabled === false` (Firefox
returns a bare `{}` where Chromium returns `{"enabled": false}`).

**Claims deliberately NOT repeated here because primary-source checking failed:** that Windows
KB5077181 (Feb 2026) added `hmac-secret` to Windows Hello (Microsoft's changelog mentions none of
WebAuthn/PRF/hmac-secret/FIDO2); that Chrome 147 added PRF-on-create for Windows; that Firefox
148 first supported Windows Hello PRF (Mozilla's own meta bug puts Windows PRF at 139). These
circulate widely and trace to single vendor blogs.

**The load-bearing gap is not a browser version — it is Element X.** Even a perfect Element Web
implementation leaves every mobile user on the typed recovery key, producing a two-tier
experience *and* forcing the typed key to remain the default 4S key anyway (Q4 blocker 2).

---

## Phase 5 — BOUNDARY CONDITIONS

### Invariants (must never be violated)

1. **No server component — auth provider, homeserver, or otherwise — may be able to obtain
   cross-signing private keys or the 4S key.** Any design that reaches this is a REJECT finding,
   not a design to refine.
2. **New, proposed here:** *No Matrix 4S / secret-storage key may ever be derived from a WebAuthn
   credential whose RP ID is the authentication provider's.* The party that authenticates you
   must not be able to derive the key that protects you from it. This is the durable form of the
   Q2 finding and it survives changes in browser behaviour, ROR support, and `hmac-secret`
   request semantics.
3. **Corollary:** do **not** publish `https://siwx-oidc.inblock.io/.well-known/webauthn`. It
   would be a prerequisite only for a design that invariant 2 forbids.
4. Never present a passkey-based unlock as removing the need for a recovery key (Q5).

### Exclusions

Implementation; MSC authoring; recovery-UX redesign; changes to the vendored Element patch;
production deployment.

### Risks (each assumption inverted)

| # | Risk | Impact |
|---|---|---|
| R1 | **The "don't request `hmac-secret` at registration" hygiene is largely ineffective.** CTAP 2.1 §12.5 says authenticators SHOULD mint `CredRandom` *"even if hmac-secret extension is not present"*, and synced platform providers expose PRF unconditionally. **This deployment's existing extension-free credentials (L1) are therefore, on modern authenticators, already PRF-capable.** | Invariant 2 must be enforced by *design policy* — the flag is weak defence-in-depth for older security keys only, not a control. |
| R2 | Upstream could adopt PRF via matrix-spec#1987 with an RP-ID model unsuitable for split auth/client domains. | This deployment would inherit an unsound default. Worth a comment on #1987 if it revives. |
| R3 | Building the sound variant means a permanent, growing Element Web patch (L6, L8) tracking a fast-moving monorepo, for an Element-Web-only benefit. | Maintenance cost compounds at every tag bump. |
| R4 | js-sdk `store()` clobbering co-tenant keys (Q4 blocker 4) could silently delete a PRF key entry, stranding users mid-migration. | Data-loss class. |
| R5 | A platform provider silently changes the PRF output for an existing credential. **Precedent, not speculation:** Apple's hybrid path diverged from the local path on iOS 18.0–18.3 / macOS 15.0–15.3 and was fixed only in 18.4/15.4, permanently bricking data encrypted under the old value (Q1). | Data-loss class, outside our control. Mitigation is to version-tag every PRF-wrapped blob and never let PRF be the sole path — which is invariant 4. |

---

## VERDICT

### **REJECT as stated. PARK a narrowly-redefined variant.**

**The single strongest argument (the killing one):** the PRF output is obtainable by *any*
ceremony run under the credential's RP ID, and this deployment's passkeys are bound to
`siwx-oidc.inblock.io` — the authentication provider's own origin. Deriving the 4S key from them
would let the auth provider compute the root E2EE secret during any routine login, using the
gesture the user already performs, and then silently cross-sign a device it controls. That is
precisely the capability MSC3861 exists to deny it, and no salt, envelope, or transport choice
repairs it, because the provider can already read anything the homeserver holds. The claim's
"same security property (server never sees it)" is therefore false for the deployment it was
written about — and "a natural fit for a passkey-first deployment like this one" is exactly
backwards: passkey-first login is what makes this the wrong place for PRF-derived 4S.

**What is PARKed, not rejected:** a *separate* credential registered by Element Web under RP ID
`element.inblock.io` (H2.5). That is architecturally clean — siwx-oidc's origin can never assert
it, and Element Web already holds the plaintext secrets, so no party gains a capability. It is
parked, not pursued, because:

- Upstream support is **zero** — no MSC, no code, two stale threads (Q3), and Element's actual
  roadmap is moving the *other* way, re-introducing typed passphrases (ER-233).
- Element X mobile is **hard-blocked** (L7, Q6), so the typed recovery key must remain the
  default 4S key regardless, and the win is Element-Web-only.
- It does not remove the recovery key, only the typing (Q5) — so it does not remove the
  onboarding friction the `force-first-device-recovery` patch imposes.
- It does not touch the P0 pain actually observed here: Element offers **no recovery-key entry at
  all** at the verify gate users hit on reload (CONTEXT, L-P0). A PRF key would arrive at the
  same gate and find the same missing affordance.

**Unblock conditions (revisit if any of these becomes true):**
1. matrix-spec#1987 revives, or an MSC lands defining a non-passphrase 4S key provenance with an
   explicit RP-ID/trust-domain model.
2. Element Web ships a first-class multi-4S-key path (removing the
   `"Multiple storage key requests not implemented"` throw) **and** matrix-rust-sdk exposes a
   raw-bytes/non-default key entry point, so Element X is not stranded.
3. Element X gains any client-owned WebAuthn capability.

### What siwx-oidc can do unilaterally today

| Action | Cost | Value |
|---|---|---|
| **Nothing that delivers the feature.** In the only sound variant siwx-oidc's contribution is nil. | — | — |
| Record invariant 2 as a standing architectural rule | doc-only | Prevents a future "quick win" that would quietly collapse the E2EE trust boundary. This is the real deliverable of this evaluation. |
| **Keep** registration extension-free (`start_passkey_registration(..., None)`, L1) — i.e. do **not** add `prf: {}` / `hmacCreateSecret` | zero (status quo) | Weak defence-in-depth, for older CTAP security keys only. Modern authenticators mint `CredRandom` regardless (CTAP 2.1 §12.5 `SHOULD`), so **this is hygiene, not a control** (R1). Do not mistake it for enforcement of invariant 2. |
| Do **not** publish `/.well-known/webauthn` | zero (status quo) | Invariant 3 |

### Strictly blocked on Element / upstream

The 4S key derivation, its enrollment and envelope scheme, the fallback UX, and every line of
ceremony code. All of it. There is no siwx-oidc-side prerequisite worth building in advance.

### Higher-value alternative (noted, out of scope)

The observed P0 (`AUDITED-PROPOSAL.md:456`) is that Element 1.12.20 offers **no recovery-key
entry** at the post-reload verify gate — the exits are "use another device" or identity reset.
Users already hold a recovery key (this deployment's own patch forces them to create one); they
simply cannot use it at the moment they need it. Extending the existing, already-maintained
Element patch to surface recovery-key entry at that gate addresses the real failure at a
fraction of the cost of a PRF programme, with no trust-model change and no upstream dependency.

---

## Assumptions register

Everything above labelled VERIFIED is backed by spec text, `file:line`, or an issue/PR number.
The following are **not** verified and would need testing before any decision changes.

| # | Assumption | Why it matters | How to falsify |
|---|---|---|---|
| **A-1** | Element Web's build-time module extension point (`ProvideCryptoSetupExtensions.getSecretStorageKey()`, sync + arg-less) cannot host a WebAuthn ceremony, so the sound variant still needs a source patch rather than a module. | Determines whether the cost is "a module" or "a permanent patch" (R3). | Prototype a module that caches a PRF output obtained at login and returns it; check user-activation and timing constraints. |
| **A-2** | Element X / matrix-rust-sdk cannot be given a client-owned WebAuthn RP ID without element-hq adding `inblock.io` to their Digital Asset Links / `apple-app-site-association`. | If false, mobile is not hard-blocked and the value calculus changes materially. | Inspect Element X's published association files; check for any configurable associated-domain mechanism. |
| **A-3** | This deployment's *existing* extension-free credentials (L1) are in practice PRF-capable. The CTAP 2.1 `SHOULD` (Q1) makes this the expected behaviour, but it is a SHOULD, and I did not test it against a credential this server actually issued. | Determines whether the latent capability described in R1 exists **today** or only for future credentials. Does not change the verdict — invariant 2 holds either way — but it changes how urgent the invariant is. | Cheap: the CDP virtual authenticator supports `hasPrf`/`hasHmacSecret` (L9). Register via the normal siwx-oidc flow, then request `prf.eval` at `get()` and check for `results`. |
| **A-4** | Google Password Manager yields the **same** PRF output for a synced credential on a second device. | Any multi-device design depends on it; Apple's shipped implementation violated exactly this inference for six months (Q1). | No Google source states it in either direction. Test empirically on two GPM-synced Android devices before relying on it. |
| **A-5** | No Matrix client outside element-hq has shipped PRF-derived 4S. | If false there is prior art to copy. | Searched Cinny and FluffyChat only; a broader client sweep could falsify. |
| **A-6** | Reading `m.cross_signing.self_signing` ciphertext from Synapse is within the siwx-oidc operator's reach (it can mint a token for any user). | Step 5 of the RP-capability argument. Strongly implied by MSC3861 delegated auth + `provision_synapse_device`, but not separately tested here. | Attempt an account_data read with an OP-minted token in the lab. |
| **A-7** | The claim that Element's roadmap direction is "away from hardware-backed recovery" is inferred from ER-233 and the 2026-02 blog post; Element has not stated a position on PRF. | Affects the PARK unblock conditions, not the REJECT. | Ask on matrix-spec#1987 or element-meta#3038. |

---

*Evaluation ends. No source code was written or modified.*
