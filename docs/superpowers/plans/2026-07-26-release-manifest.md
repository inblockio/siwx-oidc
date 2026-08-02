# Release manifest — 2026-07-26

**Purpose:** what ships tomorrow morning, in what order, and what cannot be undone.
**Method:** every claim below is tagged **MEASURED** (I ran the check, output quoted) or
**INFERRED** (reasoning from measured inputs). Nothing is carried on trust.
**Scope of this document:** analysis only. No code was changed, nothing was committed,
pushed, built, or deployed. No container was touched. The only production contact was
unauthenticated `GET` of public static assets and public metadata.

---

## 0. LEAD FINDING — the two repos are coupled. Do not deploy element-web alone.

**Prod siwx-oidc does NOT arm `allow_cross_signing_reset` at login.**

```
MEASURED:  git show db79e75:src/oidc.rs | grep -c allow_cross_signing_reset   ->  0
MEASURED:  git show HEAD:src/oidc.rs    | grep -c allow_cross_signing_reset   ->  4
MEASURED:  git log -S allow_cross_signing_reset -- src/oidc.rs
             1094efe 2026-07-25 restore login-time XS allow (3B)     <- ADDS it back
             e1b2fb7 2026-05-29 drop per-login reset                 <- REMOVED it
```

`CLAUDE.md` states "`allow_cross_signing_reset` fires unconditionally on sign-in".
**That sentence is stale and false for production.** It is true only on the branch.

Why it matters for tomorrow:

- The Element fix `1de0906` makes the forced-recovery wizard **correctly re-fire** after
  `resetEncryption`. Before the fix the wizard was skipped and the user was silently
  admitted with no recovery key.
- That wizard bootstraps **new cross-signing keys** → `POST /_matrix/client/v3/keys/device_signing/upload`.
- MEASURED in the lab walk (`docs/audits/2026-07-26-reset-after-no-recovery-walk.md`,
  server-side state table): after the reset the user's **cross-signing master key is
  published** — so MSC3967's "no existing keys, no UIA" path does **not** apply. The
  upload needs an allow window.
- MEASURED: `e2e/element/stack-up.sh` builds siwx-oidc from the **branch**
  (`SIWX_REPO="$(cd "$(dirname "$0")/../.." && pwd)"`, `docker compose up --build`).
  So the configuration that validated `1de0906` **included 3B**.

**INFERRED (high confidence):** shipping element-web without siwx-oidc puts users through a
newly-enforced wizard whose key upload prod is not armed for. Element Web's fallback is the
MSC4312 deep link to `account_management_uri?action=org.matrix.cross_signing_reset`, which
prod does advertise (MEASURED in discovery) — but prod also lacks **`f0d991d`**, so a grant
that fails still renders the green *"Encryption keys reset"* banner. That is precisely the
"stranded half-reset identity" documented in the 2026-06-24 forensics.

> **Rule: siwx-oidc ships first, or both ship together. element-web never ships alone.**
> The reverse is safe: siwx-oidc alone is strictly better for prod's current Element
> (see §2, Step 1 rationale).

---

## 1. Where production actually is — MEASURED, B10 is closed

### 1.1 siwx-oidc = `sha-db79e75` — no longer an assumption

Three independent measurements agree:

| # | Check | Result |
|---|---|---|
| 1 | GHCR config blob for `ghcr.io/inblockio/siwx-oidc:sha-db79e75` | label `revision=db79e753b102d4958756e10cc80a8c0c54db18af`, `created 2026-06-18T14:29:56.815Z` |
| 2 | `curl -I https://siwx-oidc.inblock.io/` | `last-modified: Thu, 18 Jun 2026 14:29:55 GMT`; `/build/bundle.js` → `14:31:07 GMT` |
| 3 | `GET /.well-known/openid-configuration` | **no** `response_modes_supported` (added by `3018ffe`, 2026-07-25); served UI bundle **has** `detected_mxid` (introduced at `db79e75`) |

The image label and the served-asset mtime agree **to the second** (14:29:56 vs 14:29:55).
Check 3 brackets prod into `[db79e75, 3018ffe)`; the mtime excludes every candidate inside
that bracket (all later than 2026-06-18).

**Assumption B10 is therefore RESOLVED as CORRECT.** Carry it as measured, not assumed.

*Residual gap:* this identifies the **image**. It does not prove the running container was
created from it, nor read its env/config. Only `docker compose images` on the server closes
that — see §5.

### 1.2 element-web = `sha-1e7f81b` (2026-06-13) — six weeks stale

The prior note said "at or before `cb75cce`". That is true but far too loose. MEASURED:

| # | Check | Result |
|---|---|---|
| 1 | GHCR `element-web:sha-1e7f81b` | `created 2026-06-13T11:09:11Z` |
| 2 | `curl -I https://element.inblock.io/element-theme-overrides.css` | `last-modified: Sat, 13 Jun 2026 11:06:47 GMT`, and the file **contains** the UserMenu MXID-wrap rule added by `7eb6ce2` (2026-06-13 10:56:39 UTC) |
| 3 | `curl -I https://element.inblock.io/` | `last-modified: Sat, 13 Jun 2026 11:17:40 GMT` — the entrypoint's *idempotent, one-time* `sed` on index.html, so this ≈ **container creation** |

Prod's element-web container has not been recreated since **2026-06-13 11:17 UTC**.

### 1.3 Re-verifying the bundle-marker method (it had been invalidated once before)

Two traps, both checked:

1. **Which chunk holds the marker.** `index.html` loads only
   `bundles/0a20451d7d3b2d55b5eb/bundle.js` — a **27 KB webpack runtime** containing *none*
   of the markers. The app code is in `element-web-app.js` (1.15 MB), which the runtime
   loads. Grepping `bundle.js` would have produced three false negatives.
2. **Which markers survive minification.** Only **string literals** do. `shouldForceVerification`
   as a *method name* is minified away; the *log string* `shouldForceVerification: crossSigningReady=`
   is not. I built the marker→commit table from the patch files themselves:

```
MEASURED (per patch version, counts in force-first-device-recovery.patch):
                default_key   logstring   title
9ec414d  0           0           2
b7e594f  0           0           2
cb75cce  0           0           2
1259f0b  0           1           2     <- log string introduced here
00e76f4  2           1           2     <- raw authed GET introduced here
1de0906  2           1           2
```

Grep of the **served** `element-web-app.js`:

```
force_recovery_setup_title                  : 1     (added c23e646, 2026-05-30)
account_data/m.secret_storage.default_key   : 0     (added 00e76f4)
shouldForceVerification: crossSigningReady= : 0     (added 1259f0b)
sign_in_with_qr_unverified_session          : 0     (uncommitted patch)
sign_in_with_qr_unsupported                 : 1     <- CONTROL: upstream string, proves the grep reads real content
```

Consistent with §1.2 in every position. The control marker is what makes the three zeros
mean "absent" rather than "grepped the wrong file".

### 1.4 What prod's Element therefore contains — two live defects

Prod runs the `c23e646` (2026-05-30) patch. MEASURED from that file:

```
+ return !crossSigningReady || !secretStorageReady;               # no hasServer4S widening
+ const hasExisting4S = await cli.secretStorage.hasKey();          # COLD LOCAL CACHE
+ await accessSecretStorage(async () => {}, { forceReset: !hasExisting4S });
```

- **Reload gate (fixed by `9ec414d`).** `isSecretStorageReady()` is transiently false on
  session restore before account_data rehydrates → **every page reload of a fully-set-up
  session lands on an inescapable "Confirm your digital identity" gate.** Empirically proven
  2026-07-25 against vanilla 1.12.20/1.12.24 (which never gate). **Live in prod.**
- **Data loss (fixed by `cb75cce`).** On a cold cache the probe reads false → `forceReset`
  becomes true → Element **mints a new 4S key, orphaning the user's existing recovery key
  and their message-key backup**, while reporting success. **Live in prod.**

**Not deploying is not the safe option.** It is continued exposure to a measured data-loss path.

### 1.5 The registry landmine — `:main` and `:latest` are traps right now

```
MEASURED (anonymous GHCR pull token, public packages):

siwx-oidc      newest sha- tag published : sha-d21329e   (2026-07-25T17:11)
               :main resolves to revision : d21329e
               sha-7b9cec0                : HTTP 404  <- DOES NOT EXIST

element-web    :main = :latest = revision : 00e76f4     (2026-07-26T01:36)
               sha-1e7f81b (prod)         : 2026-06-13T11:09
```

Two separate hazards:

1. **siwx-oidc CI has not built origin/main's tip.** `origin/main` is `7b9cec0` (MEASURED via
   `git ls-remote`), pushed today, but no image exists for it — nor for `c826468`, `3018ffe`,
   `bdc7dbf`, `17a1d34`. `:main` is stale at `d21329e`. A `docker compose pull siwx-oidc`
   right now would silently fetch a build that **lacks `3018ffe`**. The Actions run for the
   2026-07-26 pushes either failed or never fired — I could not check (§5, item 4).
2. **element-web `:main`/`:latest` = `00e76f4`, which is the version whose probes read
   `200 {}` as "4S exists"** → the gate is skipped and **the user is silently admitted with
   no recovery key at all** (MEASURED in the lab, and the reason `1de0906` exists). This is
   what a naive `docker compose pull element-web` gets **today**. It is a *different* bad
   outcome from prod's, not an improvement.

> Deploy by **immutable `sha-` tag**, never by `main` or `latest`.

---

## 2. What ships — user-visible behaviour, grouped by risk

### 2.1 siwx-oidc: `sha-db79e75` → marathon tip (`a69947c`)

60 commits; **7 touch `src/`, 1 more touches `js/ui/`**. MEASURED: 6 of the 7 src commits are
**already on `origin/main`**; only `b277451` and `a69947c` are unpushed.

MEASURED (Dockerfile): the image contains only `src/`, `siwx-oidc-auth/`, `Cargo.*`,
`siwe-oidc.toml`, `static/`, `js/ui`. The other 52 commits (docs, `e2e/`, `tests/`, CI) **do
not enter the image** and carry zero deploy risk.

| Risk | Commit | What a USER experiences differently |
|---|---|---|
| **HIGH value / MED risk** | `1094efe` (3B) | A half-reset identity can republish its keys **without a separate `/account` visit**. Every login now arms the reset window. Cost: one extra Synapse admin call per login; failure is non-fatal (logged `warn`). |
| **HIGH** | `f0d991d` | The `/account` cross-signing reset **stops claiming success when the grant did not take effect**. Users see an honest "unconfirmed + what to do" message instead of a green banner over a broken identity. |
| **HIGH** | `3f40485` | Element X mobile **stops randomly signing users out**. A client that lost the token-rotation response can replay the old refresh token once within 60 s instead of being hard-logged-out. |
| **HIGH** *(unpushed)* | `b277451` | A **transient Redis blip no longer hard-logs-you-out and wipes your crypto store**. Indeterminate revocation probes fail *open* (definite tombstones still fail closed — regression-tested); `/oauth2/introspect` returns 5xx rather than `active:false` on a store error, which Synapse would otherwise cache as a negative for 2 minutes. |
| **MED** *(unpushed)* | `a69947c` (js/ui) | **Passkey registration completes in one step.** MEASURED on the *served prod bundle*: today the chained auto-sign-in is a guaranteed no-op — the user completes the biometric prompt, the credential IS stored, and then **nothing happens**. Present since `edff2b2`; this flow has never once completed in production. |
| **MED** | `e1a8383` | The account and QR/device passkey pickers show **your** passkey instead of every passkey on the device (scoped by the opaque `siwx_user` cookie). |
| **MED — visible removal** | `a074795` | **Removes** the server-side method prediction and the login-button grey-out. MEASURED: prod HAS it (`methods_for_did` count = 6 at `db79e75`, 0 at HEAD). After deploy both buttons are always enabled; wallet availability is detected locally, passkey reachability is resolved live by the ceremony. *This will look like a change to anyone who liked the grey-out.* |
| **LOW** | `3018ffe` | Honors `response_mode=fragment`, advertises `response_modes_supported`. Forward-compat for js-sdk v42 / Element ≥ 1.12.24. Prod Element is pinned at **v1.12.20**, so **no user-visible effect today**. |

### 2.2 element-web: `sha-1e7f81b` → `1de0906` (`fix/4s-tombstone-probe`)

| Risk | Commit | What a USER experiences differently |
|---|---|---|
| **CRITICAL** | `cb75cce` | **Stops destroying message history.** No longer mints a fresh 4S key on a cold-cache probe, which orphaned the user's recovery key and message-key backup while reporting success. |
| **CRITICAL** | `9ec414d` | **Page reload stops trapping users.** A fully-set-up session no longer lands on an inescapable "Confirm your digital identity" gate on every refresh. |
| **CRITICAL** | `b7e594f` | The 4S probe reads the **server**, not the cold local cache — the correctness basis for both fixes above. |
| **CRITICAL** | `1de0906` | Fixes the **owner-reported prod failure**: "login, skip recovery setup, log out, log in, reset identity → cannot get into the session". The probes now read the response **body**; `{}` (what `resetEncryption` leaves behind, since Matrix has no account-data deletion) is no longer mistaken for a real key. |
| **HIGH** | `6c23298` + `cd17c90` | **The UI stops hanging after verification.** After a successful SAS verification, and after the 4S passphrase unlock, the phase no longer sticks on Busy forever. MEASURED: device reaches Finished in **21 s** instead of sitting wedged for 3.4 min. |
| **HIGH** | `fda5931` (nginx) | Ends the **"Your Element is misconfigured"** stale-bundle TDZ crash. `index.html` is served `no-cache, must-revalidate` so browsers always load current content-hashed chunks. |
| **LOW** | `1259f0b` | Ops log line only. No user-visible change. |

### 2.3 HOLD — do not ship tomorrow (uncommitted)

`patches/element-web/honest-qr-disabled-reason.patch` and
`offer-verify-current-session.patch` are **untracked**, together with the
`dockerfiles/Dockerfile.element` edit that applies them. They are genuine honesty fixes
("Show QR code" falsely blaming the account provider; an unverified-session card whose only
exit is the destructive reset). Reasons to hold — see §6.3.

### 2.4 Third moving part nobody mentioned — the Synapse image

MEASURED: `docker-compose.yml` co-versions **synapse and element-web under one `${IMAGE_TAG}`**
(siwx-oidc has its own `${SIWX_OIDC_TAG}`). `entrypoints/matrix_server.sh` is `COPY`d into the
**synapse** image and **has changed** since `1e7f81b`:

- forces a **trailing slash** on the MSC3861 `issuer` (RFC 8414 byte-match),
- adds `client_auth_method: client_secret_post`,
- adds `SIWEOIDC_INTERNAL_URL` / `issuer_metadata` handling.

**INFERRED risk:** bumping `IMAGE_TAG` and then running a bare `docker compose up -d` (no
service argument) would recreate **Synapse** with a changed MSC3861 configuration — untested
against prod. Every command in §3 is therefore scoped to a single service and uses `--no-deps`.

---

## 3. Order of operations

Nothing is deployable as-is: the correct element-web image **does not exist yet** and neither
does an image for siwx-oidc's intended payload. Steps 1–2 and 4–5 are build work.

```
  Step 0   pre-flight (§4.0)                             ~5 min
  Step 1   siwx-oidc: merge marathon -> main, push       CI ~10 min
  Step 2   verify siwx-oidc image exists by sha
  Step 3   DEPLOY siwx-oidc            <-- must be first
  Step 4   element: merge 4s-tombstone-probe -> main, push   CI ~20 min (source build)
  Step 5   verify element-web image exists by sha
  Step 6   DEPLOY element-web          <-- never before Step 3
```

### Step 1 — siwx-oidc: merge + push

```bash
cd /home/waldknoten-01/wt/siwx-durability
git status --short                     # MUST be clean
git log --oneline origin/main..HEAD -- src/ js/    # expect exactly: b277451, a69947c
git checkout main && git pull --ff-only
git merge --no-ff feat/session-durability-marathon
git push origin main
git rev-parse --short HEAD             # -> NEWSIWX, note it
```

### Step 2 — verify the image exists (do NOT skip; `:main` is stale, §1.5)

```bash
docker manifest inspect ghcr.io/inblockio/siwx-oidc:sha-<NEWSIWX> >/dev/null && echo OK
```
If this 404s, CI failed or is still running. **Stop.** Check
`https://github.com/inblockio/siwx-oidc/actions`. Do not fall back to `:main`.

### Step 3 — deploy siwx-oidc (SAFE ALONE)

```bash
# on deploy@142.93.168.4
cd /home/deploy/matrix/stack
cp .env .env.bak.$(date +%F-%H%M)          # rollback record
docker compose images siwx-oidc            # RECORD the current tag  <- your rollback target
# set SIWX_OIDC_TAG=sha-<NEWSIWX> in .env
docker compose pull siwx-oidc
docker compose up -d --no-deps siwx-oidc
```

**Why siwx-oidc alone is safe with prod's 6-week-old Element:** every change is additive or
strictly better for it. 3B *adds* an allow window prod lacks. `f0d991d` replaces a false
success with an honest one. `3f40485` and `b277451` only *reduce* spurious sign-outs.
`3018ffe` is inert against v1.12.20. `a074795`/`e1a8383`/`a69947c` are siwx-oidc's own login
page, which Element does not parse. There is no path where new-siwx-oidc + old-element is
worse than old+old.

### Step 4 — element: merge + push

```bash
cd /home/waldknoten-01/siwx-oidc-matrix-server
git status --short          # expect ONLY the 3 held items (§2.3). If Dockerfile.element is
                            # modified, `git stash push dockerfiles/Dockerfile.element` first.
python3 scripts/check-patch-hunks.py        # hunk-header integrity on the vendored patches
git checkout main && git merge --ff-only fix/4s-tombstone-probe   # brings 6c23298, cd17c90, 1de0906
git push origin main
git rev-parse --short HEAD  # -> NEWELEM
```

### Step 5 — verify

```bash
docker manifest inspect ghcr.io/inblockio/siwx-oidc-matrix-server/element-web:sha-<NEWELEM> >/dev/null && echo OK
```

### Step 6 — deploy element-web ONLY

```bash
cd /home/deploy/matrix/stack
docker compose images element-web matrix_synapse   # RECORD both  <- rollback targets
# set IMAGE_TAG=sha-<NEWELEM> in .env
docker compose pull element-web                    # pulls ONLY element-web
docker compose up -d --no-deps element-web         # --no-deps is LOAD-BEARING (§2.4)
docker compose images matrix_synapse               # MUST be unchanged from the line above
```

### Can either ship alone?

| | Alone? | Why |
|---|---|---|
| siwx-oidc | **YES** | Strictly-better superset for prod's old Element (Step 3 rationale). |
| element-web | **NO** | §0. The wizard it correctly re-enables needs the allow window prod does not arm, and prod renders a failed grant as success. |

**Window of a half-deployed pair:** between Steps 3 and 6 users run new-siwx-oidc +
old-element. That is the *good* half-state and can persist safely for hours or days. The
reverse ordering has no safe window at all. If you must stop partway, stop after Step 3.

---

## 4. Pre-flight and post-flight checks

### 4.0 Before anything

```bash
# Both worktrees clean except the 3 held items
cd /home/waldknoten-01/wt/siwx-durability && git status --short
cd /home/waldknoten-01/siwx-oidc-matrix-server && git status --short

# Build + tests green BEFORE merging (not run by me — read-only task)
cd /home/waldknoten-01/wt/siwx-durability
cargo build --workspace && cargo test --lib && cargo test --bin siwx-oidc
#   expect (per b277451's own record): --lib 24 passed, --bin 119 passed, 0 failed
#   note: the const assertion TOMBSTONE_TTL_SECS > 2*ACCESS_TOKEN_TTL fails the BUILD if violated

# gh CLI is BROKEN on this box (MEASURED): "The token in hosts.yml is invalid."
#   -> git push over SSH still works (ls-remote verified against both repos)
#   -> but you cannot watch CI from the terminal. Use the Actions web UI, or:
gh auth login -h github.com
```

### 4.1 After Step 3 (siwx-oidc)

```bash
# 1. The new build is actually serving — this field does not exist in sha-db79e75
curl -s https://siwx-oidc.inblock.io/.well-known/openid-configuration | jq .response_modes_supported
#    EXPECT: ["query","fragment"]      (null => you are still on the old image)

# 2. Health
curl -sf https://siwx-oidc.inblock.io/health && echo OK

# 3. 3B is armed — log in once, then:
docker compose logs --since 10m siwx-oidc | grep 'allow_cross_signing_reset armed after login provision'
```

**Log signatures that mean it went wrong:**

| Signature | Meaning |
|---|---|
| `allow_cross_signing_reset after login provision failed (non-fatal)` | 3B is NOT working — Synapse admin token / endpoint wrong. Non-fatal for login but the §0 coupling is unresolved. **Do not proceed to Step 6.** |
| `introspect: token store unavailable; returning 500` | Redis unreachable. Every occurrence is a near-miss for a 2-minute cached hard-logout. |
| `refresh: revocation probe indeterminate before mint` (503s) | Redis flaky. Clients retry; not fatal, but investigate. |
| `refresh: revocation probe indeterminate after mint; committing` | Fail-open fired. Bounded by the 900 s tombstone, but a burst means Redis instability. |
| Any spike in `invalid_grant` on `/token` | The grace window is not doing its job — regression in `3f40485`. |

### 4.2 After Step 6 (element-web)

```bash
# 1. The no-cache fix landed — prod currently has NO Cache-Control on index.html (MEASURED)
curl -sI https://element.inblock.io/ | grep -i cache-control
#    EXPECT: cache-control: no-cache, must-revalidate     (absent => old image still serving)

# 2. Re-run the §1.3 fingerprint against the NEW bundle
H=$(curl -s https://element.inblock.io/ | grep -oE 'bundles/[a-z0-9]+/' | head -1)
curl -s --compressed "https://element.inblock.io/${H}element-web-app.js" -o /tmp/app.js
grep -c 'account_data/m.secret_storage.default_key' /tmp/app.js   # EXPECT >= 2  (was 0)
grep -c 'shouldForceVerification: crossSigningReady=' /tmp/app.js # EXPECT 1     (was 0)
grep -c 'sign_in_with_qr_unverified_session' /tmp/app.js          # EXPECT 0     (held, §2.3)

# 3. Confirm the body-read form actually shipped (this is the whole point of 1de0906)
grep -o 'then(e=>!(null==e||!e.key))' /tmp/app.js | head    # EXPECT: 2 hits

# 4. Synapse was NOT recreated
docker compose images matrix_synapse    # unchanged
```

**Manual smoke test — walk the owner's exact reported path:**
login → **skip** recovery setup → log out → log in → **reset** the identity.
**EXPECT:** the forced wizard re-fires, a new recovery key is minted, backup version
increments, and you land in the app shell. **FAIL** if you land in the app shell with no
recovery key (that is `00e76f4` behaviour — wrong image), or if you are returned to
"Set up recovery to continue" (that is prod behaviour — old image).

**Element-side failure signature:** browser console `Cannot access 'B' before initialization`
/ "Your Element is misconfigured" = stale-bundle TDZ; hard-refresh once, then re-check the
`Cache-Control` header from check 1.

---

## 5. Known-unverifiable without the owner's prod access

| # | Unverifiable | Exact command for the owner |
|---|---|---|
| 1 | Which image the **running containers** were created from. §1.1/§1.2 identify images via public artifacts; they cannot read container state. | `cd /home/deploy/matrix/stack && docker compose images` |
| 2 | `.env` contents — `SIWX_OIDC_TAG`, `IMAGE_TAG`, `SIWEOIDC_BASE_URL` (trailing slash?), `MAS_SHARED_SECRET`. §2.4's Synapse-entrypoint risk turns on these. | `grep -E 'IMAGE_TAG\|SIWX_OIDC_TAG\|BASE_URL' /home/deploy/matrix/stack/.env` |
| 3 | **T7 / H-D6** — whether prod's *stored* tokens carry the current `TokenMetadata` shape. I proved the **code** shape is unchanged (§6.1); I cannot read live Redis. | `docker compose exec redis redis-cli --scan --pattern 'token/*' \| head -3` then `GET` one and confirm `did` + `name` keys are present |
| 4 | Whether the CI run for `7b9cec0` **failed** or never fired (`sha-7b9cec0` 404s, §1.5). The local `gh` token is invalid, so I could not query Actions. | `https://github.com/inblockio/siwx-oidc/actions` — or `gh auth login -h github.com` then `gh run list --limit 5` |
| 5 | **H-D5** — the self-contradictory `invalid_grant` baseline (~548/72 h vs ~7/4 d). Needs a prod log read; the hypothesis cannot be evaluated until reconciled. | `docker compose logs --since 72h siwx-oidc \| grep -c invalid_grant` |
| 6 | Whether prod Redis uses the durable named volume the repo declares (F9). Repo config is durable; **running state unverified**. | `docker compose config --volumes` and `docker volume inspect <name>` |
| 7 | Whether the two **held** patches (§2.3) apply cleanly to a pristine v1.12.20 and pass i18n lint. Never built in CI — the files are untracked. | `docker build -f dockerfiles/Dockerfile.element .` on a scratch branch |

**B10 is deliberately NOT in this table — §1.1 closes it.**

---

## 6. Reversibility

### 6.1 Redis / stored shapes — no flush required

MEASURED:

- `TokenMetadata` is **byte-identical** between `db79e75` and `HEAD` (8 fields: `username`,
  `device_id`, `scope`, `client_id`, `iat`, `exp`, `did`, `name`). No field added, removed, or
  renamed.
- `SessionEntry` unchanged over the same range (`git diff db79e75..HEAD -- src/db/mod.rs`
  filtered for it returns nothing). `CodeEntry`, `DeviceCodeEntry` likewise.
- New key prefixes are **purely additive** and all but one carry a TTL:

| Key | TTL | Introduced |
|---|---|---|
| `token_rotated/*` | 60 s | `3f40485` |
| `tombstone:device/*`, `tombstone:user/*` | 600 → **900 s** | pre-existing; TTL raised by `b277451` |
| `user:session/*` | 30 d | `db79e75` (already in prod) |
| `webauthn:by_did/*` | none | `db79e75` (already in prod); explicitly **advisory + self-healing** |

> **No Redis flush is required for this upgrade.** The historical "flush on upgrade" notes
> refer to the MSC3861 `TokenMetadata` change (2026-05-19) and the pre-refresh-token
> migration — both long since in prod. A rollback reads the same shapes; the new keys simply
> expire unread.
>
> `TOMBSTONE_TTL_SECS` 600 → 900 applies only to **newly written** tombstones. Rolling back
> leaves at most 900 s of longer-lived tombstones, whose only effect is to make a refresh
> refuse. Harmless.

### 6.2 Rollback per step

| Step | Rollback | Clean? |
|---|---|---|
| 1 — siwx merge/push | `git revert -m 1 <merge>` + push, or just never deploy the tag | Clean. GHCR sha tags are immutable, so the old image never disappears. |
| 3 — siwx deploy | set `SIWX_OIDC_TAG=sha-db79e75` (or the tag recorded in Step 3), `docker compose pull siwx-oidc && docker compose up -d --no-deps siwx-oidc` | **Clean.** No schema change, no data migration. ~1 min. |
| 4 — element merge/push | as Step 1 | Clean. |
| 6 — element deploy | set `IMAGE_TAG=sha-1e7f81b`, `docker compose pull element-web && docker compose up -d --no-deps element-web` | **Image rollback is clean. User-side effects are NOT** — see §6.3. |

### 6.3 IRREVERSIBLE

1. **Per-user crypto state created while the new Element is live.** Once a user is pushed
   through the forced wizard and mints a new recovery key + backup version, rolling the image
   back does **not** undo it. MEASURED in the lab walk: megolm backup went `1` → `2`, "old one
   deleted, new one created". Every user who reaches the wizard during the deploy window
   permanently changes state.
2. **Message history already destroyed by the live prod defect.** `cb75cce`'s forceReset path
   has been live since 2026-06-13. Any orphaned backup is gone; the fix is preventive only,
   with no recovery for users already hit. This is an argument **for** shipping, not against.
3. **Account-level actions** (`account_deactivate`, `account_erase`) remain irreversible, but
   are unchanged by this release.
4. **Not irreversible, contrary to reflex:** Redis (§6.1), and the git merges (revertible;
   sha-tagged images are immutable).

### 6.4 Why the two held patches (§2.3) should not ship tomorrow

- They are **untracked working-tree files**. No CI has ever applied them; no image has ever
  been built with them.
- Three of the four vendored patches touch `en_EN.json`. The Dockerfile comment asserts the
  order was "verified against a pristine v1.12.20 tree" — that is the author's claim, and
  MEASURED the hunk headers do not overlap (`@@ -972`, `@@ -2960`, `@@ -2987`), which is
  supporting but not conclusive.
- `honest-qr-disabled-reason.patch` calls `_t("settings|sessions|verify_session")` — a key it
  does **not** define. If that key does not exist upstream in v1.12.20, i18n lint fails the
  build. Unverified (§5, item 7).
- They fix **honesty and dead-end** problems, not data loss or lockout. Real, but not worth
  adding unbuilt code to a release whose critical payload is the 4S fix.

**Recommendation:** commit them on a branch today, let CI build the image, deploy them as a
separate follow-up once §4.2's smoke test has passed on the 4S release.

---

## 7. Recommendation: **GO WITH CAVEATS**

**GO on the sequence in §3, with three hard conditions.**

The case for going:

- Prod is running an Element image from **2026-06-13** carrying **two measured defects**: a
  data-loss path that silently orphans recovery keys and message backups (`cb75cce`), and a
  reload gate that traps fully-set-up sessions (`9ec414d`). Holding is not neutral.
- The owner-reported production lockout has a **measured root cause and a verified fix**
  (`1de0906`), walked end-to-end against a rebuilt image.
- The siwx-oidc payload is **low-risk and mostly already reviewed on `main`**: no stored-shape
  change, no migration, one-minute tag rollback.
- **B10 is closed** (§1.1). The largest standing unknown in the plan is now measured.

The three conditions:

1. **Order is not negotiable.** siwx-oidc (Step 3) before element-web (Step 6). §0. If Step 3's
   `allow_cross_signing_reset armed` log line does not appear, **stop** — do not deploy element.
2. **Deploy by immutable `sha-` tag only.** `:main` and `:latest` are both actively wrong right
   now (§1.5): siwx-oidc `:main` is stale at `d21329e` and lacks `3018ffe`; element-web
   `:latest` is `00e76f4`, which silently admits users with **no recovery key**. Deploying
   `latest` tomorrow morning would be the single worst available outcome.
3. **Hold the two uncommitted Element patches** (§2.3, §6.4). Ship them as a follow-up.

**What should NOT ship tomorrow, stated plainly:**

- The two untracked Element patches + the uncommitted `Dockerfile.element` edit. Unbuilt,
  untested by CI, and they fix cosmetic honesty problems. Adding them multiplies the build-risk
  of a release whose payload is a data-loss fix.
- Any **Synapse** image bump. `IMAGE_TAG` co-versions synapse with element-web and
  `matrix_server.sh` has changed materially (§2.4). Use `--no-deps` and verify
  `docker compose images matrix_synapse` is unchanged afterwards.

**If the morning is short:** do **Step 3 only**. New-siwx-oidc + old-element is a safe,
indefinitely stable configuration that already delivers 3B, honest reset outcomes, the refresh
grace window, the introspect guard, and the one-step passkey registration. Element can follow
in the afternoon once its CI image exists and §4.2 has been walked by hand.

---

## Appendix — top three risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | **element-web deployed alone, or from `:main`/`:latest`.** `latest` = `00e76f4`, which skips the recovery gate and silently admits users with no recovery key. Deployed without siwx-oidc, even the *correct* image re-enables a wizard whose key upload prod is not armed for, and prod reports a failed grant as success. | **HIGH** — it is the default tag and the intuitive "just update Element" move | **HIGH** — users land in sessions with no recoverable identity, or wedge mid-reset | §3 order; `sha-` tags only; gate Step 6 on Step 3's log line |
| 2 | **CI has not published `sha-7b9cec0`; `:main` is stale at `d21329e`.** A pull "to get the latest" silently fetches a build missing `3018ffe`, and the `gh` token is invalid so CI cannot be checked from the terminal. | **HIGH** — already true, measured | **MED** — wrong-but-not-broken build; wastes the deploy window | Step 2/5 `docker manifest inspect` gates; fix `gh auth` or use the Actions web UI |
| 3 | **Synapse recreated as collateral.** `IMAGE_TAG` co-versions synapse + element-web, and `matrix_server.sh` changed (issuer trailing slash, `client_auth_method`, `issuer_metadata`). A bare `docker compose up -d` rewrites Synapse's MSC3861 config. | **MED** — only if a service argument is forgotten | **HIGH** — MSC3861 misconfiguration breaks login for everyone | `--no-deps` on every `up`; verify `docker compose images matrix_synapse` unchanged; `.env` backed up |
