# Onboarding: your wallet account on computer AND phone

*User manual — wallet + passkey onboarding flows for inblock.io chat (Element Web / Element X
with SIWX sign-in). Verified end-to-end 2026-08-02.*

## The one thing to understand first

Your chat account is created from the identity you sign in with:

- Signing in with your **wallet** creates (or opens) your **wallet account**.
- Signing in with a **passkey alone** creates a **different, separate account**.

Two different accounts can never be "verified" against each other or merged later. So if you
want your wallet account on your phone — where there is no wallet — you first **link a
passkey to your wallet**. From then on, that passkey opens your *wallet* account anywhere.

---

## Path A — Start on your computer (recommended)

Use this path if you have (or want) a wallet identity. It gives you both devices on one
account in about five minutes.

1. **Sign in on the computer.** Open `https://element.inblock.io` in your browser and choose
   **Sign in with Ethereum**. Approve the signature in your wallet.
2. **Link a passkey to your phone.** The sign-in page now offers **"Link a passkey"** — click
   it. Your browser asks where to save the passkey: choose **"Use another device"** (or
   "iPhone / phone"), scan the QR code with your phone's camera, and save the passkey to your
   phone (iCloud Keychain on iPhone). *Bluetooth must be on, on both machines.*
3. **Continue into chat.** Back in the browser, click **Continue**. On first sign-in you will
   be asked to set up a **Recovery Key** — save it somewhere safe (password manager). This key
   is your last-resort door back in.
4. **Sign in on the phone.** Install **Element X**, enter the server
   (`matrix.inblock.io`), and choose **Sign in with Passkey**. Pick the passkey named
   **"linked-passkey"**. Your phone unlocks it with Face ID / fingerprint — and you land in
   your *wallet* account.
5. **Confirm it's really you.** Element X asks you to verify the new session: choose
   **"Use another device"**. Your computer pops up a request — accept it, compare the emoji
   shown on both screens, and confirm on both. Done: both devices share one verified account.

> **Optional — alternative for step 4/5:** instead of the passkey you can add the phone via
> QR: on the computer open *Settings → Sessions → Link new device*, and scan the shown QR
> code with Element X. Same result. The passkey route has one advantage: it keeps working
> later, on any device, even when no other session is around to show a QR.

---

## Path B — Start on your phone (the reverse path)

Use this path if you begin phone-only, with no wallet involved.

1. **Create your account on the phone.** Element X → server `matrix.inblock.io` →
   **Sign in with Passkey** → **Register a new passkey** → Face ID / fingerprint. Your
   account is created from the passkey itself.
2. **Set up recovery.** In Element X, set up the Recovery Key when prompted (Settings →
   Encryption & recovery) and store it safely.
3. **Add your computer later.** Open `https://element.inblock.io` in the browser and choose
   **Sign in with Passkey**. The browser offers **"use a passkey from another device"** — a
   QR code appears, you scan it with the phone, and the phone's passkey signs the browser in.
   (On a Mac with the same iCloud account, the passkey is simply there already — no QR
   needed.)
4. **Verify the new browser session from the phone** (compare emoji), or enter your Recovery
   Key in the browser.

> **Important limit of Path B:** an account that *starts* from a passkey is a passkey-only
> identity. A wallet **cannot** be attached to it afterwards, and the account cannot be
> merged into your wallet account later. If your wallet identity matters to you, always start
> with **Path A**.

---

## Optional: why it works this way

*You can use everything above without reading this section.*

- **Accounts are identities.** Under the hood every account is a DID (decentralized
  identifier). A wallet yields `did:pkh:…` (derived from your Ethereum address); a passkey
  yields `did:key:…` (derived from the passkey's public key). Different key, different DID,
  different account — that is a security feature, not a bug: nobody can claim your account
  without your key.
- **Linking is a signed statement.** "Link a passkey" is only offered *after* you signed in
  with the wallet, because the link is the server-side statement "this passkey belongs to
  this wallet DID" — and only a proven wallet owner may make it. That is why linking always
  starts from the wallet side (Path A), never from the passkey side.
- **Verification connects devices, not accounts.** The emoji comparison ("verify with other
  device") cryptographically connects two *sessions of the same account*. It can never bridge
  two different accounts — which is exactly why an unlinked phone session sees no popup on
  the computer: the two sessions simply don't belong to the same user.
- **Why there is no "scan from phone to spawn a browser session" inside the chat app:** the
  chat-level QR flow only works in the direction *computer shows → phone scans* (browsers
  cannot scan QR codes). The reverse direction exists anyway — one layer down: the **passkey
  QR** your browser shows at sign-in (Path B step 3) is the phone-authorizes-computer flow,
  provided by the passkey standard itself.

---

## Troubleshooting

- **The passkey picker shows several entries** → choose **"linked-passkey"** for your wallet
  account. An entry named "passkey-user" is a standalone (passkey-only) identity.
- **No popup appears on the other device during verification** → check both devices really
  show the *same* account ID (profile/settings). Two different IDs = the sessions are on two
  different accounts; verification cannot connect them.
- **"…not linked to an existing account. Create an account at sign-in first."** → you used a
  passkey the server doesn't know for an existing account (e.g. after a reset). Sign in on
  the computer with the wallet and link a fresh passkey (Path A step 2).
- **Wrong or stale passkey on the phone** → delete it under iPhone Settings → Passwords
  (search for the server name), then link a fresh one.

---

*Verification record (2026-08-01/02, staging): accounts reset; passkeys removed from iPhone;
user logged out; new wallet created; Element Web wallet sign-in; passkey linked to phone via
cross-device QR; Element X passkey sign-in onto the wallet account; "verify with other
device" completed with emoji comparison; recovery-phrase fallback offered correctly. All
steps green, exactly as written above.*
