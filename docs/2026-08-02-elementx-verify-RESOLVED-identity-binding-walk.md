# RESOLVED: Element X ↔ Element Web verification — it was identity, not crypto

**Date:** 2026-08-02 **Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`)
**Supersedes:** the open question in `2026-08-01-HANDOVER-elementx-verify-open-question.md` §1.
**Method:** owner-walked user journey on dev-staging (dev-aquafire), assistant-verified server-side
at every step. Plan: `~/.claude/plans/reactive-floating-starlight.md`.

## Verdicts

1. **"Verify with other device" between Element Web and Element X WORKS** — walked end-to-end
   on dev 2026-08-01/02: EX passkey sign-in → verify gate → "Use another device" → EW popup →
   SAS emoji → verified, and the recovery-phrase fallback was offered correctly. None of the
   handover's three candidates (busy-wedge, method mismatch, version gap) was the cause.
2. **The original failure was an identity split.** The owner's EW session was
   `did:pkh:eip155:…` (wallet), the EX session an *unlinked* passkey `did:key:zDn…` — two
   different Matrix users. Interactive verification structurally cannot connect two accounts;
   no popup was ever possible. The three candidates were investigated against the wrong layer.
3. **The binding path exists and is the designed one:** wallet sign-in on the web → "Link a
   passkey" → WebAuthn **hybrid CTAP** puts the credential on the phone (`link_start` sets no
   authenticator attachment, `require_resident_key`; frontend passes options through) →
   `webauthn:link/{cred_id} → wallet DID` → EX passkey sign-in resolves the **wallet** account.
   Binding is **web-first only**: no wallet works in the EX webview, there is no reverse
   link flow, accounts cannot be merged. The Matrix-layer reverse QR (phone spawns browser
   session) is a client-side dead end (EW cannot scan; its `LOGIN_ON_NEW_DEVICE` show-QR intent
   is unreachable in 1.12.24 and doubly removed by `sso_redirect_options.immediate`); the
   equivalent flow exists one layer down as the FIDO cross-device passkey QR at browser sign-in.

## What the walk proved (dev, fresh wallet address)

reset accounts → passkeys removed from iPhone → new wallet → EW wallet sign-in → link passkey
to iPhone (hybrid QR, iCloud Keychain) → Continue → Secure Backup wizard → EX "Sign in with
Passkey" (picker showed exactly one "linked-passkey") → landed on the **wallet** MXID → verify
with other device → EW popup unprompted → emoji match → confirmed both sides → verified; the
recovery-key fallback path was also visible/correct. Owner: "It worked end to end."

## Incidents hit and resolved along the way

- **First attempt bound passkeys to a dead account.** The owner's original dev wallet account
  `@did-pkh-…4b23…` was `deactivated + erased` (own `account_erase` testing, ~07-30). Erased
  accounts are unrecoverable and their localpart stays blocked (`M_USER_IN_USE` verified), but
  the link ceremony happily wrote `webauthn:link/*` entries for the dead DID — the link layer
  checks only the CAIP-122 cookie, not Synapse account state. Two linked creds + one
  accidental standalone registration (fresh `did:key` account born 19:53 UTC) resulted.
  **Cleanup executed (owner-approved):** all 7 `webauthn:*` keys + 13 dead `user:session/*`
  hints deleted from dev Redis; the clutter `did:key` account admin-erased. Dev `webauthn:*`
  keyspace was empty before the re-walk.
- **Possible product refinement (not filed):** the link offer could warn when the wallet DID's
  localpart resolves to a deactivated/erased account (link-to-dead-account is silent today).
  Also still true: no way to adopt an existing standalone passkey into a wallet link.

## User manual

`docs/user-instructions/onboarding-wallet-passkey-flows.md` — Path A (computer-first,
recommended, tested) and Path B (phone-first reverse path + its passkey-only limit), with the
"why" section and troubleshooting. Branded PDF exported to
`~/export/2026-08-02_SIWX_Onboarding_Flows_User_Manual.pdf`.

## Still open (unchanged from the plan)

- **Prod repeat** of the walk (needs a fresh link ceremony — passkeys are RP-ID-scoped, the
  dev passkey cannot work on prod). Prod wallet account is alive; no deploys needed.
- Deferred: matrix-rust-sdk headless EX-surrogate (automated cross-client SAS regression);
  lab Element tag bump v1.12.20 → v1.12.24; `stack-up.sh` path resolution + Playwright skew;
  `gh` credential re-provisioning (SEC-0001 rotation happened — 401 since 2026-08-01).
