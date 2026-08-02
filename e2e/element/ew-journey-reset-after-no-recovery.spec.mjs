/**
 * EW-R — RESET AFTER NO RECOVERY. The reported production failure, walked.
 *
 * The owner's report, verbatim:
 *
 *     "login, do not complete setting up your recovery key, log out, login
 *      (do NOT use the recovery key but reset the identity). This is expected to
 *      lead into the session without past messages (not decryptable) but with the
 *      option to now get new recovery keys. On prod this leads to the user not
 *      being able to get into the session."
 *
 * That is one specific path, and it is walked here one click at a time. Every screen
 * is recorded (headings + enabled controls + disabled controls) via helpers/journey.mjs
 * so the answer is measured rather than argued.
 *
 * WHY THIS PATH IS DIFFERENT FROM EW-J3. J3 walked a second device whose account
 * already HAD 4S, and measured that "Use recovery key" IS offered there. This path
 * produces an account with a published cross-signing identity and NO 4S ANYWHERE,
 * which is a different precondition: `SetupEncryptionBody` renders the
 * "Use recovery key" button only `if (store.keyInfo)` (v1.12.20
 * apps/web/src/components/structures/auth/SetupEncryptionBody.tsx:182-189), and
 * `keyInfo` comes from `secretStorage.isStored("m.cross_signing.master")`
 * (SetupEncryptionStore.ts:91-102). With no 4S that is null. Do not conflate the two
 * walks; this spec measures its own gate and does not inherit J3's finding.
 *
 * THE THREE HYPOTHESES UNDER TEST (any may be wrong):
 *   H1  On re-login the forced gate fires, because the vendored
 *       `shouldForceVerification` returns `!crossSigningReady || !(secretStorageReady
 *       || hasServer4S)` — cross-signing ready, no 4S anywhere → true.
 *       (patches/element-web/force-first-device-recovery.patch, MatrixChat.tsx hunk 1)
 *   H2  At that gate "Use recovery key" is ABSENT, so reset is genuinely the only
 *       forward exit on this path.
 *   H3  After reset, `onCompleteSecurityE2eSetupFinished` re-evaluates
 *       `shouldForceVerification`; if reset re-creates cross-signing but NOT 4S the
 *       forced-recovery `while (!recoverySetUp)` loop re-fires and the user can never
 *       enter the session — the reported prod symptom.
 *       (same patch, MatrixChat.tsx hunk 2)
 *
 * SCOPE, STATED HONESTLY. This walks the LAB, which builds Element v1.12.20 with FOUR
 * vendored patches (siwx-oidc-matrix-server/dockerfiles/Dockerfile.element), including
 * the Busy-wedge fix that is UNPUSHED. The lab is therefore AHEAD of production.
 * "Green here" is a statement about the lab only; "fixed in lab, broken in prod" is a
 * live and important possibility, not a contradiction.
 *
 * WHAT MAKES THIS TEST GO RED (stated up front, because four green-but-vacuous tests
 * were written this session):
 *   - any screen on the walk with no app shell and no enabled control (assertExit)
 *   - the preconditions evaporating: no Cancel in the wizard, no Logout in the
 *     recovery-required dialog, or 4S already present after the cancel+logout
 *   - re-login NOT producing a gate (H1 wrong — recorded and asserted)
 *   - the post-reset driver seeing the SAME screen 4 passes running (the loop of H3)
 *   - the user never reaching `.mx_MatrixChat` after reset  <-- THE PROD SYMPTOM
 *   - reaching the shell with no server-side 4S (admitted with no recovery key)
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, MATRIX_URL, SIWX_URL } from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';
import { settle, assertExit } from './helpers/journey.mjs';

const SERVER_NAME = 'localhost';
const M = MATRIX_URL.replace(/\/$/, '');

test.beforeAll(async () => {
  await requireElementStack();
});

/**
 * Server-side truth for this identity, read over the Matrix CS API with a token
 * minted independently of the browser session.
 *
 * NOT read from localStorage: measured 2026-07-26 (EW-J4) `mx_access_token` is absent
 * there under OIDC-native login, so a localStorage probe silently returns nothing and
 * every assertion downstream of it becomes unfalsifiable.
 *
 * Side effect, declared: minting this token runs a headless OIDC login, which
 * provisions one more Synapse device for the user. That device uploads no E2EE device
 * keys, so it cannot be `signedByOwner` and should be invisible to
 * `SetupEncryptionStore.fetchKeyInfo`'s `hasDevicesToVerifyAgainst` probe — but that
 * is inference, so `keys/query` is reported here too and the caller can SEE which
 * devices have published keys instead of trusting the claim.
 */
async function serverState(browser, wallet, label) {
  const ctx = await browser.newContext();
  let tok;
  try {
    const p = await ctx.newPage();
    tok = await loginWalletToTokens(p, { siwxUrl: SIWX_URL, matrixUrl: MATRIX_URL, wallet });
  } finally {
    await ctx.close().catch(() => {});
  }
  const auth = { Authorization: `Bearer ${tok.access_token}` };
  const mxid = tok.user_id || wallet.mxid;

  const defaultKey = await fetch(
    `${M}/_matrix/client/v3/user/${encodeURIComponent(mxid)}/account_data/m.secret_storage.default_key`,
    { headers: auth },
  );
  // The BODY, not just the status. Matrix has no account-data deletion, so js-sdk
  // "removes" the default key by WRITING AN EMPTY OBJECT:
  // `setDefaultKeyId(null)` -> `setAccountData("m.secret_storage.default_key", {})`
  // (matrix-js-sdk v41.6.0 src/secret-storage.ts:373-397, and its own comment says
  // exactly that). A GET therefore returns **HTTP 200 with `{}`** for a user who has
  // NO recovery key. A status-only probe reports has4S=true for precisely the state
  // this walk exists to detect, and the assertion built on it can never fail. 4S
  // exists only when the content actually names a key.
  const defaultKeyBody = await defaultKey.json().catch(() => null);
  const backup = await fetch(`${M}/_matrix/client/v3/room_keys/version`, { headers: auth });
  const backupBody = await backup.json().catch(() => ({}));

  const keysRes = await fetch(`${M}/_matrix/client/v3/keys/query`, {
    method: 'POST',
    headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({ device_keys: { [mxid]: [] } }),
  });
  const keys = await keysRes.json().catch(() => ({}));

  const state = {
    label,
    mxid,
    probeDevice: tok.device_id,
    default_key_status: defaultKey.status,
    default_key_body: defaultKeyBody,
    // What the vendored patch's own probe concludes: it does `.then(() => true)` on
    // the raw GET and never looks at the body. Reported separately from the truth so
    // the divergence is visible in the log rather than argued about.
    patchProbeSees4S: defaultKey.status === 200,
    has4S: defaultKey.status === 200 && !!defaultKeyBody && typeof defaultKeyBody.key === 'string',
    backup_status: backup.status,
    backup_version: backupBody.version ?? null,
    backup_algorithm: backupBody.algorithm ?? null,
    hasMasterKey: !!keys?.master_keys?.[mxid],
    devicesWithPublishedKeys: Object.keys(keys?.device_keys?.[mxid] || {}),
  };
  // eslint-disable-next-line no-console
  console.log(`[SERVER] ${label} ${JSON.stringify(state)}`);
  return state;
}

/** Sign in through the real siwx UI. Logs every screen it passes. */
async function siwxSignIn(page, tag) {
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 120_000 });
  assertExit(await settle(page, `${tag} siwx login page`, { budgetMs: 60_000 }));

  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  const after = await settle(page, `${tag} after signature`, { budgetMs: 90_000 });
  assertExit(after);

  const skip = page.getByRole('button', { name: 'Skip for now', disabled: false }).first();
  const offered = (await skip.count()) > 0;
  if (offered) await skip.click();
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] ${tag} passkey-offer shown=${offered}`);

  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 120_000 });
}

const fingerprint = (s) => JSON.stringify([s.appShell, s.headings, s.controls]);

/**
 * Walk forward from wherever we are until the app shell appears, clicking only
 * NON-destructive, forward-moving controls.
 *
 * Deliberately refuses to click Logout / Sign out / Cancel / Reset: those leave the
 * flow, and a driver that takes them would report "the walk terminated" for a walk
 * that never happened.
 *
 * Convergence criterion (the loop check this walk exists to answer): the app shell,
 * or the SAME screen fingerprint `stallLimit` passes running, or `maxSteps`. Without
 * one of those it is drift, not iteration.
 */
async function driveToShell(page, tag, { maxSteps = 24, stallLimit = 4 } = {}) {
  const ADVANCE = [/^Continue$/i, /^Copy$/i, /^Done$/i, /^Retry$/i, /^Next$/i, /^Finish$/i, /^Got it$/i];
  const screens = [];
  let lastPrint = null;
  let stall = 0;

  for (let i = 0; i < maxSteps; i += 1) {
    const s = await settle(page, `${tag}.${i + 1}`, { budgetMs: 90_000 });
    screens.push(s);
    assertExit(s);
    if (s.appShell) return { screens, outcome: 'APP_SHELL', stall };

    const print = fingerprint(s);
    stall = print === lastPrint ? stall + 1 : 0;
    lastPrint = print;
    if (stall >= stallLimit) return { screens, outcome: 'LOOP', stall };

    // Scope the click to the TOPMOST visible dialog, not `.first()` in DOM order.
    //
    // Measured 2026-07-26: after a reset the page can carry TWO stacked dialogs,
    // each with its own "Done" — "Your new device is now verified…" and "Secure
    // Backup successful…". Element `unshift`s regular modals while always
    // rendering the static one, so DOM order does not equal stacking order, and
    // `.first()` can target an obscured button. Clicking an obscured control and
    // observing nothing happen is INDISTINGUISHABLE from a product dead end — that
    // confusion has cost this project repeatedly, so the driver now aims at what
    // the user can actually see.
    const dialogs = page.locator('.mx_Dialog');
    const nDialogs = await dialogs.count();
    const scope = nDialogs > 0 ? dialogs.nth(nDialogs - 1) : page;
    if (nDialogs > 1) {
      // eslint-disable-next-line no-console
      console.log(`[JOURNEY] ${tag}.${i + 1} STACKED DIALOGS n=${nDialogs} — clicking the topmost`);
    }

    let clicked = null;
    for (const re of ADVANCE) {
      const btn = scope.getByRole('button', { name: re, disabled: false }).first();
      if (await btn.count()) {
        await btn.click({ timeout: 60_000 }).catch(() => {});
        clicked = String(re);
        break;
      }
    }
    // eslint-disable-next-line no-console
    console.log(`[JOURNEY] ${tag}.${i + 1} advance=${clicked ?? 'NONE'}`);
    if (!clicked) {
      // Nothing forward-moving is offered. The screen still has SOME control
      // (assertExit passed) — but every one of them is a way OUT, not a way ON.
      return { screens, outcome: 'NO_FORWARD_CONTROL', stall };
    }
    await page.waitForTimeout(1_500);
  }
  return { screens, outcome: 'MAX_STEPS', stall };
}

test('EW-R1: cancel recovery setup → logout → re-login → reset identity — does the user get in?', async ({
  browser,
}) => {
  test.setTimeout(1_500_000);
  const w = makeWallet(undefined, SERVER_NAME);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  try {
    // -----------------------------------------------------------------------
    // LEG 1 — first login, and CANCEL the forced recovery wizard.
    // -----------------------------------------------------------------------
    await injectMockWallet(page, w);
    await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
    await siwxSignIn(page, 'R1.L1');

    const wizard = await settle(page, 'R1.1 forced recovery wizard', { budgetMs: 180_000 });
    assertExit(wizard);
    expect(
      wizard.controls.some((c) => /^Cancel$/i.test(c)),
      `PRECONDITION GONE — the first-device wizard offered ${JSON.stringify(wizard.controls)} with no ` +
        `Cancel. The reported path starts by cancelling recovery setup; without Cancel this walk cannot ` +
        `be performed and this spec is obsolete rather than passing.`,
    ).toBe(true);

    await page.getByRole('button', { name: /^Cancel$/, disabled: false }).first().click();

    const areYouSure = await settle(page, 'R1.2 after Cancel', { budgetMs: 90_000 });
    assertExit(areYouSure);
    if (/are you sure/i.test((areYouSure.headings || []).join(' '))) {
      await page.getByRole('button', { name: /^Cancel$/, disabled: false }).first().click().catch(() => {});
    }

    const required = await settle(page, 'R1.3 recovery-required dialog', { budgetMs: 120_000 });
    assertExit(required);
    expect(
      required.controls.some((c) => /^Logout$/i.test(c)),
      `PRECONDITION GONE — after cancelling, the forced-recovery dialog offered ` +
        `${JSON.stringify(required.controls)} with no Logout. The reported path logs out from here.`,
    ).toBe(true);

    // -----------------------------------------------------------------------
    // LEG 2 — log out. This is the state the report starts from: an identity with
    // cross-signing published and NO recovery key.
    // -----------------------------------------------------------------------
    await page.getByRole('button', { name: /^Logout$/, disabled: false }).first().click();
    const afterLogout = await settle(page, 'R1.4 after Logout', { budgetMs: 120_000 });
    assertExit(afterLogout);

    const s1 = await serverState(browser, w, 'after-cancel-and-logout');
    expect(
      s1.has4S,
      `PRECONDITION WRONG — after cancelling recovery setup and logging out the server ALREADY has ` +
        `m.secret_storage.default_key (HTTP ${s1.default_key_status}). The reported path requires a user ` +
        `with NO recovery key; if 4S exists here the rest of this walk measures a different scenario.`,
    ).toBe(false);
    // Recorded, not assumed: is cross-signing actually published with no 4S? That
    // composition is what makes this path distinct from EW-J3.
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 precondition — crossSigningPublished=${s1.hasMasterKey} has4S=${s1.has4S} ` +
        `backupStatus=${s1.backup_status} devicesWithKeys=${JSON.stringify(s1.devicesWithPublishedKeys)}`,
    );

    // -----------------------------------------------------------------------
    // LEG 3 — log back in as the SAME identity. H1 says a gate fires here.
    // -----------------------------------------------------------------------
    await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
    const relanding = await settle(page, 'R1.5 re-login landing', { budgetMs: 120_000 });
    assertExit(relanding);
    if (new URL(page.url()).origin === new URL(ELEMENT_URL).origin && !relanding.appShell) {
      // Element did not bounce straight to siwx (explicit logout suppresses the
      // immediate-SSO redirect). Take whatever sign-in affordance it offers.
      const signIn = page
        .getByRole('button', { name: /^(Sign in|Continue|Sign In with .*)$/i, disabled: false })
        .first();
      if (await signIn.count()) await signIn.click().catch(() => {});
    }
    await siwxSignIn(page, 'R1.L3');

    // -----------------------------------------------------------------------
    // THE GATE. The single most important measurement in this spec.
    // -----------------------------------------------------------------------
    const gate = await settle(page, 'R1.6 re-login gate', { budgetMs: 180_000 });
    assertExit(gate);

    const offersRecoveryKey = gate.controls.some((c) => /use recovery key/i.test(c));
    const offersAnotherDevice = gate.controls.some((c) => /another device/i.test(c));
    const offersCantConfirm = gate.controls.some((c) => /can'?t confirm/i.test(c));
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 GATE MEASUREMENT — shell=${gate.appShell} headings=${JSON.stringify(gate.headings)} ` +
        `controls=${JSON.stringify(gate.controls)} useRecoveryKey=${offersRecoveryKey} ` +
        `useAnotherDevice=${offersAnotherDevice} cantConfirm=${offersCantConfirm}`,
    );

    // H1, asserted. If re-login drops the user straight into the app with no 4S, the
    // forced-recovery mandate has a hole and this walk's premise is wrong — either way
    // that must fail loudly rather than be skipped past.
    expect(
      gate.appShell,
      `H1 FALSIFIED — re-login put the user straight into the app shell with no gate, even though the ` +
        `server has no 4S (default_key HTTP ${s1.default_key_status}). shouldForceVerification is supposed ` +
        `to return true for crossSigningReady && !4S. Controls: ${JSON.stringify(gate.controls)}.`,
    ).toBe(false);

    // H2, MEASURED AND PINNED. 2026-07-26: "Use recovery key" is ABSENT at this gate.
    // `SetupEncryptionBody` renders it only `if (store.keyInfo)`
    // (SetupEncryptionBody.tsx:182-189) and `keyInfo` comes from
    // `secretStorage.isStored("m.cross_signing.master")` (SetupEncryptionStore.ts:91-102),
    // which is null when no 4S was ever created. So on THIS path — unlike EW-J3, whose
    // account had 4S — reset really is the only forward exit. Pinned because it is the
    // answer to the question this spec was written to settle; if it becomes present,
    // the product got better and the audit note must be rewritten, not the assertion.
    expect(
      offersRecoveryKey,
      `"Use recovery key" is now offered at the no-4S gate (controls: ${JSON.stringify(gate.controls)}). ` +
        `Measured 2026-07-26 it was absent, which is what made reset the only exit on this path.`,
    ).toBe(false);

    // Recorded, not asserted: "Use another device" IS offered, and on this path it can
    // only point at the session the user just logged OUT of. Under OIDC-native logout
    // Element revokes tokens via the OP (`/oauth2/revoke`, TeardownPolicy::TokensOnly —
    // src/compat.rs) which by design does NOT delete the Synapse device, so the dead
    // device survives with its cross-signing signature intact and still satisfies
    // `hasDevicesToVerifyAgainst`. Whether that offer can ever succeed is a separate
    // question this spec does not answer; `devicesWithPublishedKeys` above shows it.
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 stale-peer note — useAnotherDevice=${offersAnotherDevice} ` +
        `devicesWithPublishedKeysAtLogout=${JSON.stringify(s1.devicesWithPublishedKeys)}`,
    );

    // -----------------------------------------------------------------------
    // LEG 4 — take the RESET path, explicitly NOT the recovery key.
    // -----------------------------------------------------------------------
    expect(
      offersCantConfirm,
      `NO RESET ENTRY — the gate offers ${JSON.stringify(gate.controls)}, none of which opens the reset ` +
        `flow ("Can't confirm?" → ResetIdentityDialog). The reported path resets from here; without that ` +
        `control the walk cannot proceed.`,
    ).toBe(true);

    await page.getByRole('button', { name: /can'?t confirm/i, disabled: false }).first().click();
    const resetConfirm = await settle(page, 'R1.7 reset confirmation', { budgetMs: 90_000 });
    assertExit(resetConfirm);
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 reset confirmation — headings=${JSON.stringify(resetConfirm.headings)} ` +
        `controls=${JSON.stringify(resetConfirm.controls)} body=${JSON.stringify(resetConfirm.body)}`,
    );
    expect(
      resetConfirm.controls.some((c) => /^Continue$/i.test(c)),
      `The reset confirmation offered ${JSON.stringify(resetConfirm.controls)} with no Continue. ` +
        `ResetIdentityBody's destructive button is labelled "Continue" (v1.12.20 ` +
        `apps/web/src/components/views/settings/encryption/ResetIdentityBody.tsx); if that changed, ` +
        `re-measure rather than loosening this.`,
    ).toBe(true);

    await page.getByRole('button', { name: /^Continue$/, disabled: false }).first().click();

    // -----------------------------------------------------------------------
    // LEG 5 — after reset: does the user get in? H3 says the forced-recovery loop
    // may re-fire and trap them. Walked, with an explicit convergence criterion.
    // -----------------------------------------------------------------------
    const drive = await driveToShell(page, 'R1.8 post-reset');
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 POST-RESET OUTCOME=${drive.outcome} screens=${drive.screens.length} ` +
        `trail=${JSON.stringify(drive.screens.map((s) => ({ h: s.headings, c: s.controls })))}`,
    );

    const shell = page.locator('.mx_MatrixChat');
    const reachedShell = drive.outcome === 'APP_SHELL' || (await shell.count()) > 0;

    // Is the user offered a way to get NEW recovery keys? Second half of the owner's
    // expectation, and MEASURED — but it must be POLLED, not sampled.
    //
    // Measured 2026-07-26: a single sample taken the instant the shell appears is
    // FLAKY. Element's home surface rotates its nags, and consecutive runs of this
    // exact walk landed on "Back up your chats" (the recovery offer) and on
    // "You have unverified sessions" (not one). The one-shot version of this probe
    // therefore passed and failed on identical product behaviour — the same
    // single-sample defect the journey helper's `settle` exists to avoid. Poll
    // instead, and report how long the offer took to appear.
    const recoveryOffer = await (async () => {
      const RE = /back up your chats|set up recovery|set up secure backup|turn on backup|recovery key/i;
      const started = Date.now();
      const deadline = started + 45_000;
      let last = { offered: false, affordances: [] };
      for (;;) {
        last = await page.evaluate((src) => {
          const re = new RegExp(src, 'i');
          const hit = [...document.querySelectorAll('button, [role="button"], a[href], h1, h2, h3')]
            .filter((el) => {
              const r = el.getBoundingClientRect();
              return r.width > 0 && r.height > 0 && re.test(el.innerText || '');
            })
            .map((el) => (el.innerText || '').replace(/\s+/g, ' ').trim())
            .slice(0, 8);
          return { offered: hit.length > 0, affordances: [...new Set(hit)] };
        }, RE.source);
        if (last.offered || Date.now() >= deadline) break;
        await page.waitForTimeout(2_000);
      }
      return { ...last, waitedMs: Date.now() - started };
    })();

    const s2 = await serverState(browser, w, 'after-reset');
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] R1 VERDICT — reachedShell=${reachedShell} outcome=${drive.outcome} ` +
        `has4S=${s2.has4S} patchProbeSees4S=${s2.patchProbeSees4S} ` +
        `default_key=${s2.default_key_status}:${JSON.stringify(s2.default_key_body)} ` +
        `backupVersion=${s2.backup_version} crossSigningPublished=${s2.hasMasterKey} ` +
        `recoveryOffer=${JSON.stringify(recoveryOffer)}`,
    );

    // THE PROD SYMPTOM, asserted. Red here means it reproduces in the lab.
    expect(
      reachedShell,
      `PROD SYMPTOM REPRODUCED — after resetting the identity the user never reached the app shell ` +
        `(driver outcome: ${drive.outcome}). This is exactly the reported failure: "on prod this leads to ` +
        `the user not being able to get into the session". Last screen: ` +
        `${JSON.stringify(drive.screens[drive.screens.length - 1] || null)}. Server after reset: ` +
        `has4S=${s2.has4S} default_key=${s2.default_key_status} backup=${s2.backup_status}/${s2.backup_version}.`,
    ).toBe(true);

    // MEASURED, DELIBERATELY NOT ASSERTED — and the reason matters.
    //
    // The owner's other expectation is "with the option to now get new recovery keys".
    // Measured across six runs of this identical walk, that offer is NOT reliably
    // surfaced: 3 of 6 landed on "Back up your chats" (the offer), and 3 of 6 landed on
    // "You have unverified sessions" with NO recovery affordance found in a full 45s
    // poll. Element's home surface rotates its nags, so the offer is a COIN FLIP, not a
    // guarantee.
    //
    // Asserting a race produces a flaky-red test, and flaky tests get deleted — which
    // would lose the finding entirely. So this is recorded loudly and carried in
    // docs/audits/2026-07-26-reset-after-no-recovery-walk.md as an OPEN finding
    // instead. The deterministic facts (the user gets in; they get in with no real 4S)
    // are asserted below and above.
    //
    // Note the scope of the claim: this measures what is offered on the surface the
    // user LANDS on, without navigating. A recovery route still exists in Settings;
    // nothing proactively points them at it.
    // eslint-disable-next-line no-console
    console.log(
      `[FINDING] R1 recovery-offer-after-reset — offered=${recoveryOffer.offered} ` +
        `waitedMs=${recoveryOffer.waitedMs} affordances=${JSON.stringify(recoveryOffer.affordances)} ` +
        `landingHeadings=${JSON.stringify((drive.screens[drive.screens.length - 1] || {}).headings)} ` +
        `— the user has NO real 4S at this point (default_key=${s2.default_key_status} ` +
        `${JSON.stringify(s2.default_key_body)}).`,
    );

    // VERDICT REWRITTEN 2026-07-26 (second walk), exactly as the previous version of
    // this assertion instructed: "if this flips to has4S=true, the probe was fixed —
    // re-walk and rewrite this spec's verdict rather than deleting the assertion."
    //
    // What the first walk found: `resetEncryption` -> `deleteSecretStorage` ->
    // `setDefaultKeyId(null)` writes an EMPTY OBJECT, because Matrix has no account-data
    // deletion (matrix-js-sdk v41.6.0 src/secret-storage.ts:373-397, whose own comment
    // says so). Both vendored probes then did `.then(() => true)`, inspecting only the
    // HTTP status and never the body — so a 200 carrying `{}` read as "4S exists".
    //
    // Consequences of that one mistake, both now measured:
    //   - on THIS build the gate was skipped and the user was admitted with NO recovery
    //     key, silently;
    //   - on PROD (patch <= cb75cce, probes reading the cold local cache) the loop
    //     instead tries to UNLOCK the `{}` key, `hasKey()` is false, it throws, and the
    //     user is returned to "Set up recovery to continue" — the reported symptom,
    //     "not being able to get into the session".
    //
    // FIX: both probes now read the body (`!!r?.key`). An empty `{}` is a DEFINITE
    // tombstone, not an indeterminate read, so treating it as absent honours I8 and does
    // not weaken U3′'s fail-toward-unlock rule, which governs ERRORS only.
    //
    // Post-fix behaviour, measured: the forced-recovery wizard re-fires after the reset,
    // mints a fresh recovery key and a new backup version, and the user reaches the app.
    // That is precisely the outcome the owner specified: a session without the old
    // history, plus the option to obtain new recovery keys.
    expect(
      { has4S: s2.has4S, patchProbeSees4S: s2.patchProbeSees4S },
      `POST-RESET MANDATE REGRESSED. After a reset the user must end up with a REAL 4S key ` +
        `(has4S=true) and the patch probe must agree (patchProbeSees4S=true). A ` +
        `has4S=false/probe=true split means the body-blind probe is back and the user is ` +
        `either admitted with no recovery key or stuck in the unlock loop. Now: ` +
        `${JSON.stringify(s2)}.`,
    ).toEqual({ has4S: true, patchProbeSees4S: true });

    // And the key must be real, not the `{}` tombstone that started all of this.
    expect(
      s2.default_key_body?.key,
      `The post-reset default_key has no \`key\` property — this is the empty-object ` +
        `tombstone the fix exists to detect: ${JSON.stringify(s2.default_key_body)}.`,
    ).toBeTruthy();
  } finally {
    await ctx.close().catch(() => {});
  }
});
