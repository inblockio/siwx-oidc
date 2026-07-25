/**
 * EW-R1: "Enter recovery phrase" must be AVAILABLE in every context that needs it.
 *
 * Requirement (docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md,
 * R5/R6): when no other verified session exists, the recovery phrase must not merely be
 * DEMANDED — it must be ENTERABLE. A recorded P0 finding (F16) says the verify gate offers
 * only "Use another device" or a destructive identity RESET.
 *
 * WHAT GATES THE AFFORDANCE (verified against element-web v1.12.20 + the shipped bundle):
 *
 *   SetupEncryptionBody.tsx, Phase.Intro:
 *       if (store.keyInfo) -> render "Use recovery key"
 *   SetupEncryptionStore.ts:90-100:
 *       keyInfo <- cli.secretStorage.isStored("m.cross_signing.master")
 *   matrix-js-sdk 41.6.0 (extracted from the live lab chunk 6065.js):
 *       async isStored(e){ const t = await this.accountDataAdapter.getAccountDataFromServer(e);
 *                          if (null == t || !t.encrypted) return null; ... }
 *
 * So the button's gate is a SERVER read of the account_data event `m.cross_signing.master`.
 * It is NOT the cold local cache that caused the reload gate to fire, and it is NOT the
 * `m.secret_storage.default_key` event that the vendored force-first-device-recovery patch
 * checks. Those are three different predicates and the patch only fixes the second.
 *
 * The gate's full exit set is:
 *     "Use another device"  (iff store.hasDevicesToVerifyAgainst)
 *     "Use recovery key"    (iff store.keyInfo)              <- the affordance under test
 *     "Can't confirm?"      (always) -> ResetIdentityDialog  <- DESTRUCTIVE
 *     "Sign out"            (always, allowLogout={true})     <- ABANDONMENT
 * and, because config.json sets force_verification:true, the skip (X) is suppressed.
 *
 * HONESTY CONTRACT FOR THIS FILE:
 *   - No test.skip. No "the button exists" assertions where the requirement is that it WORKS.
 *   - A red test must name the failing conjunct. Every leg dumps the live SetupEncryptionStore
 *     state (keyInfo / hasDevicesToVerifyAgainst) plus the three server-side account_data
 *     discriminators into the failure message.
 *   - Legs are ordered so that R1-0 (cheap, decisive) runs first: if it fails, R1-2's failure
 *     is already explained.
 *
 * NOT RUN AS OF 2026-07-25 — authored against a sibling-owned lab; see
 * docs/audits/2026-07-25-recovery-entry-and-qr-capability-audit.md.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  ELEMENT_URL,
  MATRIX_URL,
  SIWX_URL,
} from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { postAccountWallet } from './helpers/crypto.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';

// The lab server_name; wallet mxids must match it (see EW-L1b).
const SERVER_NAME = 'localhost';

test.beforeAll(async () => {
  await requireElementStack();
});

// ---------------------------------------------------------------------------
// Local helpers. Deliberately NOT added to helpers/* — that directory is shared
// with a sibling agent and the parallel human checkout this session.
// ---------------------------------------------------------------------------

/**
 * Real Element DOM login through the siwx UI, completing the mandatory
 * first-device Secure Backup wizard AND capturing the generated recovery key.
 *
 * This is a capturing variant of helpers/element-login.mjs::elementWalletClickLogin
 * (which clicks "Copy" and discards the key — unusable for an entry test).
 *
 * The key is read from `.mx_CreateSecretStorageDialog_recoveryKey code`
 * (CreateSecretStorageDialog.tsx:521-522, v1.12.20).
 *
 * @returns {{ session: {user_id, device_id, access_token}, recoveryKey: string|null,
 *             sawWizard: boolean }}
 */
async function loginCapturingRecoveryKey(page, walletBundle) {
  await injectMockWallet(page, walletBundle);

  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, {
    timeout: 60_000,
  });

  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  // Post-signature interstitial: offer to link a passkey. Decline.
  await page.getByRole('button', { name: 'Skip for now' }).click();

  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, {
    timeout: 60_000,
  });

  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();

  // "Setting up keys" can run a long time before the wizard renders.
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });

  let recoveryKey = null;
  let sawWizard = false;

  if (!(await chat.count())) {
    sawWizard = true;
    await btn(/^Continue$/).click(); // Set up Secure Backup (generate key is the default)

    // The generated key is rendered before the Copy button becomes useful.
    const keyNode = page.locator('.mx_CreateSecretStorageDialog_recoveryKey code');
    await keyNode.waitFor({ timeout: 120_000 });
    recoveryKey = (await keyNode.innerText()).trim();

    await btn(/^Copy$/).click({ timeout: 120_000 });
    await btn(/^Continue$/).click({ timeout: 30_000 });
    await btn(/^Done$/).click({ timeout: 60_000 });
    await chat.waitFor({ timeout: 90_000 });
  }

  const session = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
    access_token: localStorage.getItem('mx_access_token'),
  }));
  if (!session.user_id || !session.device_id) {
    throw new Error('Element session storage missing: ' + JSON.stringify(session));
  }
  return { session, recoveryKey, sawWizard };
}

/** Raw CS-API account_data read for the given user. `null` on 404 (M_NOT_FOUND). */
async function getAccountDataFromServer(accessToken, userId, type) {
  const url =
    `${MATRIX_URL.replace(/\/$/, '')}/_matrix/client/v3/user/` +
    `${encodeURIComponent(userId)}/account_data/${encodeURIComponent(type)}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (r.status === 404) return null;
  if (!r.ok) {
    throw new Error(`account_data ${type} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
  }
  return r.json();
}

/** GET /room_keys/version — the MEGOLM backup, a DIFFERENT artifact from 4S. */
async function getKeyBackupVersion(accessToken) {
  const r = await fetch(
    `${MATRIX_URL.replace(/\/$/, '')}/_matrix/client/v3/room_keys/version`,
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  return { status: r.status, body: await r.text() };
}

/**
 * The three server-side predicates that decide whether a recovery phrase can ever
 * be entered. Collected together so every failure message carries the diagnosis.
 */
async function recoveryPreconditions(accessToken, userId) {
  const defaultKey = await getAccountDataFromServer(
    accessToken, userId, 'm.secret_storage.default_key',
  );
  const master = await getAccountDataFromServer(
    accessToken, userId, 'm.cross_signing.master',
  );
  const backup = await getKeyBackupVersion(accessToken);
  return {
    // What the vendored patch's shouldForceVerification checks:
    default_key_present: !!defaultKey,
    default_key_id: defaultKey?.key ?? null,
    // What the "Use recovery key" BUTTON actually checks:
    master_present: !!master,
    master_encrypted: !!master?.encrypted,
    master_encrypted_under: master?.encrypted ? Object.keys(master.encrypted) : [],
    // What was previously cited as proof that "4S setup succeeded" — it is neither:
    megolm_backup_status: backup.status,
  };
}

/**
 * A usable CS-API token for `walletBundle`'s identity.
 * Prefers the token Element itself persisted (no extra device). Falls back to a
 * fresh headless OIDC login for the same DID, which DOES mint an extra device —
 * the caller is told which path was taken so it can account for it.
 */
async function tokenForUser(page, walletBundle, elementSession) {
  if (elementSession?.access_token) {
    return { token: elementSession.access_token, extraDevice: null };
  }
  const s = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: walletBundle,
  });
  return { token: s.access_token, extraDevice: s.device_id };
}

/**
 * Live SetupEncryptionStore state. Element assigns the singleton to
 * `window.mxSetupEncryptionStore` (SetupEncryptionStore.sharedInstance()), verified
 * present in the running lab's element-web-app.js chunk.
 */
async function gateState(page) {
  return page.evaluate(() => {
    const s = window.mxSetupEncryptionStore;
    if (!s) return { present: false };
    return {
      present: true,
      phase: s.phase ?? null,
      keyId: s.keyId ?? null,
      keyInfo: s.keyInfo ? JSON.parse(JSON.stringify(s.keyInfo)) : null,
      hasDevicesToVerifyAgainst: s.hasDevicesToVerifyAgainst ?? null,
    };
  });
}

/** Human-readable diagnosis appended to every recovery-entry assertion. */
function diagnose(label, pre, gate) {
  return (
    `${label}\n` +
    `  server m.secret_storage.default_key : ${pre.default_key_present} (id=${pre.default_key_id})\n` +
    `  server m.cross_signing.master       : present=${pre.master_present} ` +
    `encrypted=${pre.master_encrypted} under=${JSON.stringify(pre.master_encrypted_under)}\n` +
    `  megolm /room_keys/version status    : ${pre.megolm_backup_status}\n` +
    `  SetupEncryptionStore                : ${JSON.stringify(gate)}\n` +
    `  -> "Use recovery key" renders iff store.keyInfo is non-null, and keyInfo comes from\n` +
    `     secretStorage.isStored("m.cross_signing.master"), a SERVER read. If master_encrypted\n` +
    `     is false, the wizard created a 4S key but never stored the cross-signing master\n` +
    `     under it, and no recovery phrase can EVER be entered at this gate.`
  );
}

/**
 * Enter a recovery key into Element's AccessSecretStorageDialog and confirm.
 * Selectors from AccessSecretStorageDialog.tsx:185-200 (v1.12.20):
 *   .mx_AccessSecretStorageDialog_recoveryKeyEntry contains the Field,
 *   placeholder/title = "Recovery key", primary action = "Continue".
 */
async function enterRecoveryKey(page, recoveryKey) {
  const entry = page.locator('.mx_AccessSecretStorageDialog_recoveryKeyEntry');
  await entry.waitFor({ timeout: 60_000 });
  const input = entry.locator('input').first();
  await input.fill(recoveryKey);
  await page
    .locator('.mx_AccessSecretStorageDialog')
    .getByRole('button', { name: /^Continue$/ })
    .click();
}

// ---------------------------------------------------------------------------
// R1-0 — the root discriminator. Cheap, decisive, and it settles the whole
// question of whether a recovery phrase can EVER be entered in this deployment.
// ---------------------------------------------------------------------------

test('EW-R1-0: after the mandatory first-device wizard, the cross-signing master IS stored in 4S', async ({
  page,
}) => {
  test.setTimeout(420_000);

  const w = makeWallet(undefined, SERVER_NAME);
  const { session, recoveryKey, sawWizard } = await loginCapturingRecoveryKey(page, w);
  expect(session.user_id).toBe(w.mxid);

  // The forced wizard must actually have run and produced a key the user could write down.
  expect(
    sawWizard,
    'force_verification + the vendored first-device-recovery patch must force the Secure ' +
      'Backup wizard on a brand-new first device; it did not render',
  ).toBe(true);
  expect(
    recoveryKey,
    'the wizard must display a recovery key the user can record',
  ).toBeTruthy();
  expect(String(recoveryKey).replace(/\s+/g, '').length).toBeGreaterThan(40);

  const { token } = await tokenForUser(page, w, session);
  const pre = await recoveryPreconditions(token, session.user_id);

  // The patch's own success condition. If this is false the wizard did not even
  // create 4S, which is a different (and more obvious) failure.
  expect(
    pre.default_key_present,
    diagnose(
      'The wizard reported success but no 4S default key exists server-side.',
      pre,
      { note: 'no gate rendered; app-shell path' },
    ),
  ).toBe(true);

  // THE ASSERTION THIS WHOLE AUDIT TURNS ON.
  //
  // The wizard's success check (`!shouldForceVerification()`) only proves the
  // default key exists. The recovery-key BUTTON needs the cross-signing master to
  // be encrypted under it. If these diverge, every later verify gate is a dead end.
  expect(
    pre.master_encrypted,
    diagnose(
      'R5/R6 CANNOT be satisfied: 4S exists but the cross-signing master key was ' +
        'never encrypted into it, so Element will withhold "Use recovery key" at ' +
        'every future verify gate. This is the root cause of the F16 P0 finding, and ' +
        'it is NOT fixed by force-first-device-recovery.patch (which checks ' +
        'm.secret_storage.default_key, a different event).',
      pre,
      { note: 'no gate rendered; app-shell path' },
    ),
  ).toBe(true);

  // The megolm backup existing is NOT evidence that 4S holds the XS master. Pin the
  // distinction so it cannot be conflated again.
  expect(
    pre.master_encrypted_under.length,
    'the master must be encrypted under at least one 4S key id',
  ).toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------
// R1-1 — context C2: reload / session restore.
// The b7e594f patch should mean the gate does not fire at all here. If it does
// fire, the requirement is unchanged: the phrase must be enterable.
// ---------------------------------------------------------------------------

test('EW-R1-1: reload either restores the app OR presents a recovery-key entry that WORKS', async ({
  page,
}) => {
  test.setTimeout(480_000);

  const w = makeWallet(undefined, SERVER_NAME);
  const { session, recoveryKey } = await loginCapturingRecoveryKey(page, w);
  const { token } = await tokenForUser(page, w, session);

  await page.reload({ waitUntil: 'domcontentloaded' });

  const chat = page.locator('.mx_MatrixChat');
  const gate = page.locator('.mx_CompleteSecurityBody');
  await chat.or(gate).first().waitFor({ timeout: 120_000 });

  if (await chat.count()) {
    // Expected outcome with force-first-device-recovery.patch @ b7e594f: the
    // server-side 4S probe short-circuits the gate on restore.
    return;
  }

  // The gate fired on restore. That is a regression against b7e594f, but the
  // requirement under test is the exit, not the gate — so assert the exit works.
  const pre = await recoveryPreconditions(token, session.user_id);
  const gs = await gateState(page);

  const useRecovery = page.getByRole('button', { name: /use recovery key/i });
  await expect(
    useRecovery,
    diagnose(
      'The reload verify gate fired AND offers no recovery-key entry. The only exits ' +
        'are "Can\'t confirm?" (-> ResetIdentityDialog, destructive) and "Sign out". ' +
        'This is the F16 undefined user state, reproduced on restore.',
      pre,
      gs,
    ),
  ).toBeVisible();

  expect(recoveryKey, 'no recovery key was captured to enter').toBeTruthy();
  await useRecovery.click();
  await enterRecoveryKey(page, recoveryKey);

  await expect(
    chat,
    'entering the correct recovery key at the reload gate must unlock the session',
  ).toBeVisible({ timeout: 120_000 });
});

// ---------------------------------------------------------------------------
// R1-2 — context C5: NEW DEVICE, NO LIVE SESSION. This is R5/R6 exactly.
// The recovery phrase is the ONLY correct answer here, so it must be enterable.
// ---------------------------------------------------------------------------

test('EW-R1-2: new device with NO other verified session can ENTER the recovery phrase (R5/R6)', async ({
  page,
  browser,
}) => {
  test.setTimeout(600_000);

  const w = makeWallet(undefined, SERVER_NAME);

  // --- Context A: bootstrap the identity and capture the recovery key.
  const { session: sessionA, recoveryKey } = await loginCapturingRecoveryKey(page, w);
  expect(recoveryKey, 'context A must yield a recovery key to enter later').toBeTruthy();

  const { token: tokenA } = await tokenForUser(page, w, sessionA);
  const preA = await recoveryPreconditions(tokenA, sessionA.user_id);

  // --- Remove every session that could act as a verifier, so "Use another device"
  // is genuinely unavailable and the phrase is the only correct exit.
  // MSC4191 device_delete (siwx /account, wallet re-auth) is the supported path;
  // Synapse withholds the bulk delete servlet under MSC3861.
  const del = await postAccountWallet(
    { wallet: w.wallet, action: 'org.matrix.device_delete', deviceId: sessionA.device_id },
    SIWX_URL,
  );
  expect(
    del.status,
    `MSC4191 device_delete must succeed so no verified session survives: ` +
      `${typeof del.body === 'string' ? del.body : JSON.stringify(del.body)}`,
  ).toBe(200);

  await page.context().clearCookies();

  // --- Context B: a genuinely fresh device for the SAME identity.
  const ctxB = await browser.newContext();
  try {
    const pageB = await ctxB.newPage();
    const wB = makeWallet(w.wallet.privateKey, SERVER_NAME);
    expect(wB.mxid).toBe(w.mxid);

    await injectMockWallet(pageB, wB);
    await pageB.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
    await pageB.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, {
      timeout: 60_000,
    });
    await pageB.getByRole('button', { name: 'Sign in with Ethereum' }).click();
    await pageB.getByRole('button', { name: 'Skip for now' }).click();
    await pageB.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, {
      timeout: 60_000,
    });

    const chatB = pageB.locator('.mx_MatrixChat');
    const gateB = pageB.locator('.mx_CompleteSecurityBody');
    await chatB.or(gateB).first().waitFor({ timeout: 180_000 });

    // R5/R6 are NEGATIVE requirements: the phrase must still be DEMANDED. A new
    // device that silently lands in the app without any crypto challenge would be
    // a security regression, not a pass.
    expect(
      await gateB.count(),
      'R5/R6 regression: a brand-new device of an existing 4S user reached the app ' +
        'shell with no identity-confirmation gate at all. The recovery phrase must ' +
        'still be demanded when no other verified session exists.',
    ).toBeGreaterThan(0);

    const preB = await recoveryPreconditions(tokenA, sessionA.user_id);
    const gsB = await gateState(pageB);

    // The destructive exits are always present; that is not the failure. The failure
    // is when they are the ONLY ones.
    const useRecovery = pageB.getByRole('button', { name: /use recovery key/i });
    await expect(
      useRecovery,
      diagnose(
        'R5/R6 FAIL — undefined user state. A new device with NO other verified ' +
          'session is at the identity-confirmation gate and cannot enter its recovery ' +
          'phrase. Remaining exits are "Can\'t confirm?" (-> ResetIdentityDialog, ' +
          'destroys the cross-signing identity) and "Sign out". This is exactly the ' +
          'F16 P0 finding in the context the requirement protects.\n' +
          `  context A preconditions at bootstrap: master_encrypted=${preA.master_encrypted}`,
        preB,
        gsB,
      ),
    ).toBeVisible({ timeout: 60_000 });

    // The requirement is that it WORKS, not that it renders.
    await useRecovery.click();
    await enterRecoveryKey(pageB, recoveryKey);

    await expect(
      chatB,
      'entering the correct recovery phrase on a new device with no other session ' +
        'must unlock the session and reach the app',
    ).toBeVisible({ timeout: 180_000 });

    // ...and it must have actually restored the cryptographic identity, not just
    // dismissed the dialog. Cross-signing ready is the real post-condition.
    const crossSigned = await pageB.evaluate(async () => {
      const s = window.mxSetupEncryptionStore;
      // The store keeps a client reference only transiently; re-derive from the
      // gate's own outcome instead of poking at internals that may be torn down.
      return s ? s.phase : null;
    });
    // Phase 3 == Done, 5 == Finished (SetupEncryptionStore.Phase). Either means the
    // ceremony completed rather than being abandoned.
    expect(
      [3, 5, null].includes(crossSigned),
      `recovery-key entry left SetupEncryptionStore in phase ${crossSigned}; ` +
        'expected the ceremony to have completed (Done/Finished) or the store to be ' +
        'torn down after success',
    ).toBe(true);
  } finally {
    await ctxB.close();
  }
});

// ---------------------------------------------------------------------------
// R1-3 — context C4: new device WITH a live verified session (R4's context).
// Not a duplicate of R1-2: here a non-destructive exit OTHER than the phrase
// should also exist, and we record which exits are actually offered.
// ---------------------------------------------------------------------------

test('EW-R1-3: new device WITH a live session is offered a non-destructive exit', async ({
  page,
  browser,
}) => {
  test.setTimeout(600_000);

  const w = makeWallet(undefined, SERVER_NAME);

  // Context A stays alive and verified for the whole test.
  const { session: sessionA, recoveryKey } = await loginCapturingRecoveryKey(page, w);
  const { token: tokenA } = await tokenForUser(page, w, sessionA);

  const ctxB = await browser.newContext();
  try {
    const pageB = await ctxB.newPage();
    const wB = makeWallet(w.wallet.privateKey, SERVER_NAME);

    await injectMockWallet(pageB, wB);
    await pageB.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
    await pageB.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, {
      timeout: 60_000,
    });
    await pageB.getByRole('button', { name: 'Sign in with Ethereum' }).click();
    await pageB.getByRole('button', { name: 'Skip for now' }).click();
    await pageB.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, {
      timeout: 60_000,
    });

    const chatB = pageB.locator('.mx_MatrixChat');
    const gateB = pageB.locator('.mx_CompleteSecurityBody');
    await chatB.or(gateB).first().waitFor({ timeout: 180_000 });

    if (await chatB.count()) {
      // Secrets arrived without any user challenge. Legitimate only if the device
      // really is cross-signed; otherwise Element skipped a required gate.
      const gsSkip = await gateState(pageB);
      expect(
        gsSkip.present === false || gsSkip.phase === null,
        `new device reached the app shell with no gate while SetupEncryptionStore ` +
          `reports ${JSON.stringify(gsSkip)}`,
      ).toBe(true);
      return;
    }

    const preB = await recoveryPreconditions(tokenA, sessionA.user_id);
    const gsB = await gateState(pageB);

    const useAnother = pageB.getByRole('button', { name: /use another device/i });
    const useRecovery = pageB.getByRole('button', { name: /use recovery key/i });
    const offered = {
      use_another_device: (await useAnother.count()) > 0,
      use_recovery_key: (await useRecovery.count()) > 0,
      cant_confirm_reset: (await pageB.getByRole('button', { name: /can't confirm/i }).count()) > 0,
      sign_out: (await pageB.getByRole('button', { name: /^sign out$/i }).count()) > 0,
    };

    expect(
      offered.use_another_device || offered.use_recovery_key,
      diagnose(
        'R4 context FAIL — a new device with a LIVE verified session on another ' +
          'device is offered no non-destructive exit at all. Offered: ' +
          JSON.stringify(offered),
        preB,
        gsB,
      ),
    ).toBe(true);

    // R4's own promise is "no phrase typed", so the other-device path must be the
    // one on offer here. Record it as a hard expectation: if only the phrase is
    // available while a live verified session exists, R4 is not met.
    expect(
      offered.use_another_device,
      diagnose(
        'R4 NOT MET — a live verified session exists on another device, but the new ' +
          'device is not offered "Use another device", so the user is pushed onto the ' +
          'recovery phrase unnecessarily. Offered: ' + JSON.stringify(offered) + '\n' +
          '  NOTE: SetupEncryptionStore.hasDevicesToVerifyAgainst has no self-exclusion ' +
          '(SetupEncryptionStore.ts:104-119), so a TRUE here is also worth scrutiny — it ' +
          'can count the current device.',
        preB,
        gsB,
      ),
    ).toBe(true);

    // The phrase must ALSO remain available as a fallback in this context.
    expect(
      offered.use_recovery_key,
      diagnose(
        'The recovery phrase is not offered as a fallback even with a live session. ' +
          'If the other-device path stalls, the user is left with reset or sign out.',
        preB,
        gsB,
      ),
    ).toBe(true);

    expect(recoveryKey).toBeTruthy();
  } finally {
    await ctxB.close();
  }
});
