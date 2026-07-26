/**
 * EW-V1: a SECOND Matrix device is verified from a FIRST live session by
 * SAS/emoji — with NO recovery phrase typed.
 *
 * This is the proof for plan requirement R4 ("user adds a device, existing
 * session still signed in -> emoji verify, no phrase typed") and for AC4/H-D8.
 * Two audits established that the capability is present and only the proof is
 * missing (`docs/audits/2026-07-25-R4-recheck-verdict.md` §4.4,
 * `docs/audits/2026-07-25-verify-with-other-device-gap-evaluation.md` §4.5):
 * `m.key.verification`, `sendToDevice`, `SAS` and `emoji` had ZERO occurrences
 * across `src/`, `tests/` and `e2e/`. EW-L1b is explicitly NOT this test — it
 * asserts the "Use another device" button is *visible* and never clicks it.
 *
 * Entry point under test is E2 from the R4 re-check: Settings -> Sessions ->
 * (unverified session) -> "Verify session", gated only on
 * `isCurrentDeviceVerified && userId` (`useOwnDevices.ts:184-191`) — not on
 * `isCrossSigningReady`, 4S, `exportSecretsBundle`, MSC4108, or OP metadata.
 *
 * SHAPE (the two legs are kept strictly separate, because assertion 5 depends
 * on it):
 *
 *   SETUP LEG   context A logs in as a brand-new wallet identity and completes
 *               the mandatory first-device Secure Backup wizard. That wizard
 *               CREATES a recovery key (Continue / Copy / Continue / Done) —
 *               setup, not verification. A third, headless OIDC session
 *               (observer) provides an independent CS-API channel and doubles
 *               as a negative control. Context B then logs in as the SAME
 *               wallet and is deliberately NOT run through any wizard.
 *
 *   SAS LEG     tripwires are armed on both browser contexts, then verification
 *               is driven A -> B entirely through the real Element DOM, the
 *               emoji are compared, and "They match" is clicked on BOTH sides.
 *
 * ASSERTIONS
 *   1  A and B are two distinct Synapse devices of one user.
 *   2  A is a legitimate verifier: its own device is signed by the SSK.
 *   3  BASELINE: B is not cross-signed before the SAS leg.
 *   4  The emoji comparison really happened: the SAS strip renders on BOTH
 *      sides and the two strips are identical.
 *   5  NO RECOVERY PHRASE (positive assertion, per-context tripwire): during
 *      the SAS leg, zero `input` events on any field, and zero appearances of
 *      any 4S / key-backup ENTRY surface, on either context. Plus: every click
 *      the VERIFICATION driver made came from a closed whitelist, none of it
 *      recovery- or reset-shaped. (Plain navigation — user menu, Settings tab,
 *      "Show details" — is not part of that whitelist and is not logged; it
 *      cannot enter a phrase, and the tripwire covers it regardless.)
 *   6  OUTCOME: B is cross-signed — `/keys/query` shows the user's self-signing
 *      key signature over B's device keys.
 *   7  NEGATIVE CONTROL: the observer device, which was never verified, is
 *      still NOT cross-signed — so assertion 6 is specific to the SAS.
 *   8  B reaches the Element app shell (a usable session, no phrase).
 *   9  A's session list flips B to a verified session (the user-visible payoff).
 *
 * Execution order is 1,2,3,4,6,7,5,9,8: the R4 proof (through 5 and 9) is fully
 * evaluated BEFORE the Element-side session-transition check (8), so a defect in
 * 8 can never hide whether the proof itself holds.
 *
 * FAILURE POLICY: if SAS does not work, this test FAILS with the surface dump
 * of both contexts. It is never to be weakened into "the button exists".
 *
 * CURRENT STATE ON THIS LAB (2026-07-25, Element 1.12.20 + matrix-js-sdk 41.6.0,
 * reproduced identically on three consecutive runs): 1-7 and 9 PASS. **8 FAILS.**
 * SAS itself is completely healthy — the to-device tally is
 * `request/ready/start/key/mac/done` plus 7 `m.secret.request` from B answered by
 * 4 encrypted to-device sends from A — and B ends up cross-signed with the
 * cross-signing private keys gossiped in
 * (`privateKeysCachedLocally: {master,self,user} = true`,
 * `crossSigningReady && secretStorageReady`, `ownDeviceStatus.crossSigningVerified`).
 * What breaks is purely Element's view transition: `SetupEncryptionStore` is left
 * in `Phase.Busy` (2). Its `onVerificationRequestChange` samples
 * `getCrossSigningKeyId()` at the instant the request reaches Done and picks
 * `Done : Busy` from it; the sample loses the race, and the only escape,
 * `onUserTrustStatusChanged`, does not fire again — so B sits on a
 * "Verify this device" screen with ZERO buttons, for the full 180 s budget.
 * The failure path then probes severity: **one page reload clears it and B lands
 * in the app shell, still with no phrase typed.** So the R4 claim holds and the
 * residual defect is an Element-side dead-end view that costs the user a refresh.
 * Do not "fix" this test by dropping assertion 8 — it is the only thing watching
 * that dead end.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, SIWX_URL, MATRIX_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { keysQuery } from './helpers/crypto.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import {
  ALLOWED_CLICKS,
  RECOVERY_PATTERN,
  advanceVerification,
  clickTheyMatch,
  crossSigningStatus,
  cryptoProbe,
  describeSurface,
  elementWalletLoginNoWizard,
  emojiVisible,
  finishVerification,
  findDeviceListItem,
  installNoPhraseTripwire,
  openSessionsTab,
  readSasEmoji,
  readTripwire,
} from './helpers/verify-sas.mjs';
import { assertCeremonyInvariant, ceremonySample } from './helpers/ceremony-view.mjs';

test.beforeAll(async () => {
  await requireElementStack();
});

/** Count `PUT /sendToDevice/{type}/...` calls by event type. */
function tally(list) {
  const out = {};
  for (const t of list) out[t] = (out[t] || 0) + 1;
  return out;
}

test('EW-V1: second session cross-signed by SAS/emoji from a live first session — no recovery phrase', async ({
  browser,
}) => {
  test.setTimeout(900_000);

  const w = makeWallet(undefined, 'localhost');
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const ctxO = await browser.newContext();
  const clickLog = [];

  const toDevice = { A: [], B: [] };

  const dump = async (why) => {
    const grab = async (page) => {
      if (!page) return null;
      const [surface, probe, tripwire] = await Promise.all([
        describeSurface(page).catch((e) => ({ error: String(e) })),
        cryptoProbe(page).catch((e) => ({ error: String(e) })),
        readTripwire(page).catch(() => null),
      ]);
      return { surface, probe, tripwire };
    };
    const [sa, sb] = await Promise.all([grab(pageA), grab(pageB)]);
    return (
      `${why}\n` +
      `clicks: ${JSON.stringify(clickLog)}\n` +
      `sendToDevice A: ${JSON.stringify(tally(toDevice.A))}\n` +
      `sendToDevice B: ${JSON.stringify(tally(toDevice.B))}\n` +
      `A: ${JSON.stringify(sa, null, 1)}\n` +
      `B: ${JSON.stringify(sb, null, 1)}`
    );
  };

  let pageA;
  let pageB;
  try {
    // ================= SETUP LEG =================================
    // Recovery-key CREATION lives HERE (first-device Secure Backup wizard) and
    // nowhere else. Everything after the marker below is the SAS leg.
    pageA = await ctxA.newPage();
    const A = await elementWalletClickLogin(pageA, w);
    expect(A.user_id).toBe(w.mxid);
    expect(A.device_id).toBeTruthy();

    // Independent CS-API channel (ground truth) + negative control device.
    const pageO = await ctxO.newPage();
    const observer = await loginWalletToTokens(pageO, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
      wallet: w,
    });
    expect(observer.user_id).toBe(A.user_id);

    // [2] A must be a legitimate verifier: its own device signed by the SSK.
    // (This is exactly the `isCurrentDeviceVerified` term that gates the
    // "Verify session" trigger.)
    await expect
      .poll(
        async () => {
          const kq = await keysQuery(observer.access_token, A.user_id);
          return !!crossSigningStatus(kq.body, A.user_id, A.device_id).signature;
        },
        { timeout: 120_000, intervals: [3_000] },
      )
      .toBe(true);

    // Device B: same wallet, fresh context, NO wizard.
    pageB = await ctxB.newPage();
    const B = await elementWalletLoginNoWizard(pageB, w);

    // [1] Two distinct devices, one user.
    expect(B.user_id).toBe(A.user_id);
    expect(B.device_id).toBeTruthy();
    expect(B.device_id).not.toBe(A.device_id);
    expect(B.device_id).not.toBe(observer.device_id);

    // B must NOT have been pushed into recovery-key creation; if it was, the
    // premise of this test is gone and we say so instead of playing along.
    expect(
      B.surface,
      `device B landed on an unexpected surface: ${B.surface} :: ${B.text}`,
    ).not.toBe('recovery-wizard');
    // eslint-disable-next-line no-console
    console.log(`[EW-V1] A=${A.device_id} B=${B.device_id} (B surface: ${B.surface})`);

    // [3] BASELINE: B is not cross-signed yet.
    const kqBefore = await keysQuery(observer.access_token, A.user_id);
    expect(kqBefore.status).toBe(200);
    const beforeB = crossSigningStatus(kqBefore.body, A.user_id, B.device_id);
    expect(beforeB.ssk, 'user has no self-signing key — setup leg did not bootstrap').toBeTruthy();
    expect(
      beforeB.signature,
      `device B was ALREADY cross-signed before the SAS leg: ${JSON.stringify(beforeB.deviceSignatures)}`,
    ).toBeUndefined();

    // ================= SAS LEG BEGINS ============================
    // From here on nothing may be typed, and no 4S entry surface may appear.
    await installNoPhraseTripwire(pageA, 'A');
    await installNoPhraseTripwire(pageB, 'B');

    // Watch the to-device traffic that carries the whole ceremony
    // (m.key.verification.*) and the post-verification secret gossip
    // (m.secret.request / m.room.encrypted). Diagnostic only.
    for (const [tag, page] of [
      ['A', pageA],
      ['B', pageB],
    ]) {
      page.on('request', (r) => {
        const m = r.url().match(/\/sendToDevice\/([^/?]+)/);
        if (m) toDevice[tag].push(decodeURIComponent(m[1]));
      });
    }

    // A: Settings -> Sessions -> B's tile -> Show details -> "Verify session".
    await openSessionsTab(pageA);

    let item = null;
    const findDeadline = Date.now() + 120_000;
    while (Date.now() < findDeadline && !item) {
      item = await findDeviceListItem(pageA, B.device_id);
      if (!item) await pageA.waitForTimeout(2_000);
    }
    if (!item) {
      throw new Error(await dump(`device B (${B.device_id}) never appeared in A's session list`));
    }

    const expand = item.locator('.mx_DeviceExpandDetailsButton');
    if (await expand.count()) {
      const alreadyOpen = await item.getByRole('button', { name: /^verify session$/i }).count();
      if (!alreadyOpen) await expand.first().click({ timeout: 20_000 });
    }

    const verifyBtn = item.getByRole('button', { name: /^verify session$/i }).first();
    try {
      await expect(verifyBtn).toBeVisible({ timeout: 60_000 });
    } catch (e) {
      throw new Error(
        await dump(
          '"Verify session" did not render for device B. It is gated on ' +
            '`device.isVerified === false && !!onVerifyDevice`, i.e. on A itself being verified. ' +
            String(e).slice(0, 300),
        ),
      );
    }
    await verifyBtn.click();
    clickLog.push('A: Verify session');

    // Drive both sides to the emoji comparison using only whitelisted clicks.
    const sasDeadline = Date.now() + 180_000;
    let bothShowEmoji = false;
    while (Date.now() < sasDeadline) {
      const [ea, eb] = await Promise.all([emojiVisible(pageA), emojiVisible(pageB)]);
      if (ea && eb) {
        bothShowEmoji = true;
        break;
      }
      for (const [tag, page] of [
        ['B', pageB],
        ['A', pageA],
      ]) {
        const clicked = await advanceVerification(page);
        if (clicked) clickLog.push(`${tag}: ${clicked}`);
      }
      await pageA.waitForTimeout(1_000);
    }
    if (!bothShowEmoji) {
      throw new Error(await dump('the SAS emoji comparison never rendered on both sides'));
    }

    // [4] The emoji comparison really happened, and the two sides agree.
    const emojiA = await readSasEmoji(pageA);
    const emojiB = await readSasEmoji(pageB);
    // eslint-disable-next-line no-console
    console.log(`[EW-V1] SAS emoji A: ${emojiA}\n[EW-V1] SAS emoji B: ${emojiB}`);
    expect(emojiA.length).toBeGreaterThan(0);
    expect(emojiB).toBe(emojiA);
    // m.sas.v1 shows 7 emoji; each carries a text label.
    expect(emojiA.split(/\s+/).filter(Boolean).length).toBeGreaterThanOrEqual(7);

    // Confirm the match on BOTH sides — this is the human act being proven.
    await clickTheyMatch(pageA);
    clickLog.push('A: SAS: They match');
    await clickTheyMatch(pageB);
    clickLog.push('B: SAS: They match');

    // ================= OUTCOME ===================================
    // [6] B is cross-signed. Ground truth from Synapse, not from Element's UI.
    await expect
      .poll(
        async () => {
          const kq = await keysQuery(observer.access_token, A.user_id);
          return !!crossSigningStatus(kq.body, A.user_id, B.device_id).signature;
        },
        {
          timeout: 120_000,
          intervals: [3_000],
          message: 'device B never acquired a self-signing-key signature after SAS',
        },
      )
      .toBe(true);

    // [7] NEGATIVE CONTROL: the observer device was never verified and must
    // still be unsigned — proving [6] came from the SAS, not from a blanket
    // account-level signing pass.
    const kqAfter = await keysQuery(observer.access_token, A.user_id);
    const afterO = crossSigningStatus(kqAfter.body, A.user_id, observer.device_id);
    expect(
      afterO.signature,
      `negative control failed: the never-verified observer device ${observer.device_id} is cross-signed`,
    ).toBeUndefined();

    // [5] NO RECOVERY PHRASE — the point of this test. Asserted HERE, as soon
    // as the verification itself is complete, so the R4 proof is fully
    // evaluated before the (Element-side) session-transition checks below.
    // Re-asserted at the very end so the terminal leg is covered too.
    const assertNoPhrase = async (stage) => {
      const tws = [await readTripwire(pageA), await readTripwire(pageB)];
      for (const tw of tws) {
        expect(tw, `tripwire missing at ${stage} — instrumentation was lost`).not.toBeNull();
        expect(
          tw.typed,
          `[${stage}] text was typed into a field during the SAS leg on context ${tw.label}: ${JSON.stringify(tw.typed)}`,
        ).toEqual([]);
        expect(
          tw.recoveryUi,
          `[${stage}] a recovery-key / 4S entry surface appeared during the SAS leg on context ${tw.label}: ${JSON.stringify(tw.recoveryUi)}`,
        ).toEqual([]);
      }
      // Every click was whitelisted, and none of them was recovery/reset-shaped.
      for (const entry of clickLog) {
        const label = entry.replace(/^[AB]: /, '');
        expect(
          label === 'Verify session' || ALLOWED_CLICKS.includes(label) || /^terminal /.test(label),
          `driver clicked something outside the whitelist: ${entry}`,
        ).toBe(true);
        expect(entry).not.toMatch(RECOVERY_PATTERN);
      }
    };
    await assertNoPhrase('post-SAS');
    // eslint-disable-next-line no-console
    console.log(`[EW-V1] clicks: ${JSON.stringify(clickLog)}`);

    // [9] User-visible payoff: A's session list now shows B as verified.
    // The verification modal stacks on top of Settings; if it took Settings
    // with it on close, reopen the tab before looking.
    if (!(await pageA.locator('li.mx_FilteredDeviceList_listItem').count())) {
      await openSessionsTab(pageA).catch(() => {});
    }
    await expect
      .poll(
        async () => {
          const it = await findDeviceListItem(pageA, B.device_id);
          if (!it) return 'gone';
          const t = await it.innerText().catch(() => '');
          return /unverified/i.test(t) ? 'unverified' : /verified/i.test(t) ? 'verified' : 'unknown';
        },
        {
          timeout: 90_000,
          intervals: [3_000],
          message: "A's session list never flipped device B to verified",
        },
      )
      .toBe('verified');

    // [8] B ends up in a usable session — no phrase, no reset.
    // Keep confirming whatever terminal affordance appears (a real user would)
    // while waiting for B to land in the app shell.
    const shellDeadline = Date.now() + 180_000;
    const ceremonyT0 = Date.now();
    const ceremonySamples = [];
    let bInShell = false;
    while (Date.now() < shellDeadline) {
      // [8a] I-C1 WATCHER (M4c). Sampled BEFORE finishVerification clicks
      // anything, so what is recorded is what a real user would be looking at —
      // not what the harness just dismissed on their behalf. Never throws; the
      // verdict is evaluated once, after the loop.
      ceremonySamples.push(await ceremonySample(pageB, { at: Date.now() - ceremonyT0 }));
      for (const [tag, p] of [
        ['B', pageB],
        ['A', pageA],
      ]) {
        for (const d of await finishVerification(p)) {
          const entry = `${tag}: terminal ${d}`;
          if (!clickLog.includes(entry)) clickLog.push(entry);
        }
      }
      bInShell = await pageB
        .locator('.mx_MatrixChat')
        .isVisible()
        .catch(() => false);
      if (bInShell) break;
      await pageB.waitForTimeout(3_000);
    }
    // eslint-disable-next-line no-console
    console.log(`[EW-V1] post-SAS probe A: ${JSON.stringify(await cryptoProbe(pageA))}`);
    // eslint-disable-next-line no-console
    console.log(`[EW-V1] post-SAS probe B: ${JSON.stringify(await cryptoProbe(pageB))}`);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-V1] sendToDevice A=${JSON.stringify(tally(toDevice.A))} B=${JSON.stringify(tally(toDevice.B))}`,
    );
    if (!bInShell) {
      const p = await cryptoProbe(pageB).catch(() => ({}));
      const phase = p?.setupEncryption?.phase;
      const diagnosis = await dump(
        'device B never reached the app shell after a SUCCESSFUL SAS. ' +
          `SetupEncryptionStore phase=${phase} (0 Loading, 1 Intro, 2 Busy, 3 Done, 4 ConfirmSkip, 5 Finished); ` +
          `crossSigningReady=${p?.crossSigningReady} secretStorageReady=${p?.secretStorageReady} ` +
          `crossSigningKeyId=${p?.crossSigningKeyId ? 'present' : String(p?.crossSigningKeyId)} ` +
          `privateKeysCachedLocally=${JSON.stringify(p?.crossSigningStatus?.privateKeysCachedLocally)}. ` +
          'If the crypto state is healthy and phase===2, this is an Element 1.12.20 ' +
          'SetupEncryptionStore race: onVerificationRequestChange sampled ' +
          'getCrossSigningKeyId() before the identity refresh landed, set Phase.Busy, ' +
          'and no later UserTrustStatusChanged re-checked it — leaving a buttonless ' +
          '"Verify this device" screen with no user-visible way forward.',
      );
      // Severity probe, on the failure path only — the test is already lost, so
      // mutating B is fine here. Does the natural user recovery (reload) clear
      // the wedge? "Wedged until reload" and "wedged permanently" are very
      // different bugs and the report must not guess which one this is.
      let afterReload;
      try {
        await pageB.reload({ waitUntil: 'domcontentloaded' });
        await pageB.locator('.mx_MatrixChat').waitFor({ state: 'visible', timeout: 120_000 });
        afterReload = 'RELOAD RECOVERS: app shell reached without any phrase';
      } catch {
        afterReload =
          'RELOAD DOES NOT RECOVER :: ' + JSON.stringify(await describeSurface(pageB).catch(() => null));
      }
      throw new Error(`${diagnosis}\nreload probe: ${afterReload}`);
    }

    // [8a] I-C1 VERDICT — evaluated on the SUCCESS path, which is the point.
    //
    // Assertion 8 above only fires when B never reaches the app shell at all. A
    // run where B sat in a buttonless "Verify this device" screen for 60s and
    // *then* recovered passed it silently — the user was trapped, the test said
    // nothing. That is the `C_Working` coverage gap in matrix §5.9: nothing
    // asserted the difference between a healthy transient Busy (>=1 control) and
    // `T_C_Wedged` (zero controls). This states it.
    //
    // Deliberately placed AFTER the block above so the failure path keeps its
    // richer diagnosis (including the reload severity probe) — this is additive,
    // and assertion 8 is not weakened by it.
    assertCeremonyInvariant(ceremonySamples, { label: 'EW-V1 device B post-SAS' });

    // [5b] The tripwire must still be clean after the terminal leg.
    await assertNoPhrase('final');
  } finally {
    await ctxA.close().catch(() => {});
    await ctxB.close().catch(() => {});
    await ctxO.close().catch(() => {});
  }
});
