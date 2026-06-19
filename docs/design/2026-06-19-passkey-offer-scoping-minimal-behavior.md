# Passkey offer-scoping — minimal correct behavior (all 3 paths)

**Purpose:** the smallest correct behavior spec for which keys are *offered* in each flow.
Behavior only — no implementation. Those details live *under* this spec and must not
change it.
**Written:** 2026-06-19.

---

## Principle

The picker only ever **offers** keys. It is **never** the security check.
Security is always: *the server performs the action under whatever key was actually
proven.* So the offer just has to be **helpful and honest**, not bulletproof.

The only variable across the three paths is **whose identity is known in this context.**

The offer is scoped by **identity** (which keys belong to this account) — never by a guess
about which device can present them. Whether a method can actually run here is resolved
**live, not predicted**: the **wallet** is locally detectable (is a provider injected?)
and greys out if not; **passkeys roam** across devices and transports, so the server
cannot know reachability — offer by identity and let the ceremony resolve it, falling
open with a friendly message if nothing is present.

---

## 1. Login — *identity unknown (first contact)*

- Offer: all of the user's own passkeys (the OS picker resolves which one).
- If a returning user is recognized, narrow to that account — but **always** keep
  "use a different one."
- Proven key, existing account → sign in. Proven **new** identity → **one**
  "this will create a new account" confirm, then create.
- This is the **only** path where an account can be born.

## 2. Account / device management — *identity known (arrived from your session)*

- **MUST offer only this account's keys** (identity scoping). Other accounts' keys can
  never manage it → never offered.
- Method availability: **wallet** greys out if no provider is present
  here; **passkey** is offered by identity and resolved live — never predicted. If no key
  is reachable, fall open with a friendly "use another device, or another method."
- Proven key → manage **that** account's own sessions/devices. **No creation, ever.**
  Unknown identity has nothing to manage → rejected.

## 3. Device / QR approval — *identity known (approve from where you're signed in)*

- **MUST offer only your own keys** (identity scoping).
- Method availability: an Element-X secondary device has no injected
  wallet → **wallet greyed out**; **passkey** is offered by identity — the device may
  hold a synced key, or you may approve via another device (hybrid). Let the ceremony
  resolve it; friendly fallback if none.
- Proven key → approve; the new device joins **that** account. **No creation.**
  Approving into a non-existent account is meaningless → rejected.

---

## Server-side truth (the only thing the server must hold)

Paths 2 and 3 need exactly one server-side fact:

- **Which credentials belong to this identity** — a reliable identity → credentials
  mapping (`webauthn:by_did`). The offer (`allowCredentials`) is built from this, never
  from the client and never from the URL.

The server does **not** track "which device can present which key" — it can't.
Availability is resolved live by the ceremony, not stored.

## Non-goals (keep it minimal)

- The picker is not an authorization boundary — do not try to make it one.
- No new account creation outside Login.
- No "show all then reject after the ceremony" — relevance is decided **before** the
  offer, by **identity scoping** (not by predicting device availability).
