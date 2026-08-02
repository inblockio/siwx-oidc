/**
 * EW-D1 — "I GOT A NEW LAPTOP": adding a second device while the first session is
 * still live, walked SCREEN BY SCREEN on BOTH devices.
 *
 * WHY THIS EXISTS, AND WHAT IT IS NOT
 * ----------------------------------
 * This journey is the mitigation for every lost-key scenario in the audit: a user
 * who still has one signed-in device never needs a recovery key to onboard the
 * next one. Two specs already touch it and neither answers the product question:
 *
 *   - `ew-verify-sas.spec.mjs` (EW-V1) proves the CRYPTO outcome — device B really
 *     is cross-signed by SAS from a live session, with no phrase typed, verified
 *     against Synapse `/keys/query`. It drives the UI only as far as it must to
 *     get there, and it CLICKS the terminal on the user's behalf without ever
 *     asking whether that click was necessary.
 *   - `ew-journey-exits.spec.mjs` (EW-J3) walks the second-device gate for the
 *     OPPOSITE composition — no other live session — and stops at the gate.
 *
 * The gap is the one this file fills: the SCREEN-level exit walk, on BOTH devices,
 * for the whole journey, against the single product invariant:
 *
 *     At every screen a user reaches, they must be able to DO something:
 *     either the app shell is present (they are in), or at least one enabled,
 *     visible control is offered (they can act).
 *     A disabled/greyed-out button is not an exit.
 *
 * `helpers/journey.mjs` (`settle` / `assertExit`) is the invariant, reused
 * verbatim — not reimplemented — so a change to what counts as an exit changes
 * every journey spec at once.
 *
 * THE TWO STATES THAT MUST NEVER BE COLLAPSED
 * -------------------------------------------
 * `T_C_OkAwaitAck` (the ceremony SUCCEEDED and is waiting on a click: phase 3/5,
 * >=1 enabled control) and `T_C_Wedged` (a genuine dead end: phase 2, ZERO
 * controls) both render as "no app shell". Treating them as one event previously
 * produced two wrong diagnoses and one withdrawn P0. The discriminator is
 * **phase + enabled-control count**, implemented in `helpers/ceremony-view.mjs`
 * and reused here.
 *
 * That has a concrete consequence for the ORDER of the checks below. In the
 * ceremony legs, `ceremonySample` is taken and LOGGED before `assertExit` is
 * allowed to judge the same screen, and in the terminal leg the whole ack probe
 * runs to completion (asserting nothing) and `assertCeremonyInvariant` is
 * evaluated BEFORE `assertExit`. So no failure of this spec can ever report a
 * bare "DEAD END" without the phase and the control count printed immediately
 * above it. Do not reorder these.
 *
 * THE HEADLINE MEASUREMENT (§D1.6)
 * --------------------------------
 * After both sides confirm the emoji, this spec DELIBERATELY CLICKS NOTHING for
 * up to ACK_PROBE_MS and records whether device B reaches an unobstructed app
 * shell on its own. "Unobstructed" is load-bearing: an app shell behind a modal
 * the user must dismiss is still a click the product is demanding, so the probe
 * ends only when the shell is up AND no `.mx_Dialog` / `.mx_CompleteSecurityBody`
 * is covering it. EW-V1 cannot answer this — it clicks the terminal inside its
 * polling loop, so "needed a click" and "resolved by itself" look identical to it.
 *
 * WHERE THE INVARIANT IS STRONG AND WHERE IT IS WEAK — STATED, NOT HIDDEN
 * ----------------------------------------------------------------------
 * `readScreen` scopes control-counting to `.mx_Dialog` / `.mx_CompleteSecurityBody`
 * / `.mx_AuthPage`, and to `document.body` only when the app shell is ABSENT; with
 * the shell up and no dialog it returns `controls: []` and passes on `appShell`
 * alone. (Measured: EW-J1 logs `J1.5 after wizard EXIT shell=true controls=[]`.)
 * That is correct for the invariant — a user in the app can act — but it means
 * `assertExit` on device A, which is inside the app for this entire journey, is
 * nearly free. It is still asserted, because a regression that throws A out of the
 * shell must be caught; but it is NOT where A's coverage comes from. A's real
 * coverage is `readVerificationSurface` below, which scopes to the four surfaces
 * the verification prompt can render into and asserts that the prompt itself
 * offers an ENABLED control at the emoji step.
 *
 * SCOPE. Walks the LAB (Element :28088 / Matrix :28080 / siwx :28081). A green run
 * is a statement about this lab, not about production. Not walked here, and not
 * covered elsewhere either: the B-INITIATED direction, where the user presses
 * "Use another device" on B's own gate instead of A pushing from Settings. EW-L1b
 * asserts that button is visible and never clicks it; this spec uses the
 * A-initiated entry point (Settings -> Sessions -> Verify session), which is the
 * one EW-V1 established works. That gap is real and should be named, not implied.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import { settle, assertExit } from './helpers/journey.mjs';
import { assertCeremonyInvariant, ceremonySample, PHASE_NAMES } from './helpers/ceremony-view.mjs';
import {
  advanceVerification,
  clickTheyMatch,
  cryptoProbe,
  describeSurface,
  elementWalletLoginNoWizard,
  emojiVisible,
  finishVerification,
  findDeviceListItem,
  openSessionsTab,
  readSasEmoji,
} from './helpers/verify-sas.mjs';

const SERVER_NAME = 'localhost';
/** How long the SAS ceremony may take to reach the emoji comparison on both sides. */
const SAS_BUDGET_MS = 180_000;
/** How long device B is watched, WITH NOTHING CLICKED, after the emoji confirmation. */
const ACK_PROBE_MS = 60_000;
const POLL_MS = 3_000;

test.beforeAll(async () => {
  await requireElementStack();
});

// ---------------------------------------------------------------------------
// Scoped readers. Neither replaces `readScreen` — they answer questions its
// scoping rules deliberately do not.
// ---------------------------------------------------------------------------

/**
 * The verification prompt on a page that is ALREADY in the app shell.
 *
 * Needed because `readScreen` reports `controls: []` for an in-app page with no
 * dialog, so it cannot say whether the verification prompt itself is actionable.
 *
 * ROOTS ARE DELIBERATELY NARROW. `.mx_VerificationPanel` and
 * `.mx_VerificationShowSas` are unambiguous. Toasts are NOT: this build has no
 * `mx_VerificationRequestToast` class (checked in the served
 * `bundles/b1848b64aa8f57bcfc88/element-web-app.js` — only the generic
 * `mx_Toast_toast` exists), and the lab's Element permanently shows an
 * "inblock.io Chat does not support this browser" toast. A first cut of this
 * function took every `.mx_Toast_toast` and duly reported the verification
 * surface as `present=true controls=["Learn more","Dismiss"]` — the BROWSER
 * WARNING — at every step. That is precisely the vacuous-instrumentation failure
 * this spec exists to avoid, so toasts are admitted only when their own text is
 * verification-shaped.
 *
 * Same strictness as the invariant: visible AND not disabled AND not
 * aria-disabled.
 */
async function readVerificationSurface(page) {
  return page
    .evaluate(() => {
      const vis = (el) => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return false;
        const cs = window.getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
      };
      const label = (el) =>
        (el.innerText || '').replace(/\s+/g, ' ').trim() ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        '';
      const txt = (el) => (el.innerText || '').replace(/\s+/g, ' ');
      const roots = [
        ...document.querySelectorAll('.mx_VerificationPanel, .mx_VerificationShowSas'),
      ]
        .concat(
          [...document.querySelectorAll('.mx_Toast_toast')].filter((el) =>
            /verif|encrypt|digital identity|session/i.test(txt(el)),
          ),
        )
        .filter(vis);
      const all = roots.flatMap((r) => [
        ...r.querySelectorAll('button, [role="button"], a[href]'),
      ]);
      const enabled = all.filter(
        (el) =>
          vis(el) &&
          !el.hasAttribute('disabled') &&
          el.getAttribute('aria-disabled') !== 'true' &&
          el.getAttribute('aria-hidden') !== 'true',
      );
      const off = all.filter(
        (el) => vis(el) && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true'),
      );
      return {
        present: roots.length > 0,
        text: roots.map(txt).join(' | ').slice(0, 220),
        controls: [...new Set(enabled.map(label).filter(Boolean))].slice(0, 20),
        disabled: [...new Set(off.map(label).filter(Boolean))].slice(0, 20),
      };
    })
    .catch((e) => ({ present: false, error: String(e).slice(0, 160), controls: [], disabled: [] }));
}

/**
 * The "Current session" card in Settings -> Sessions.
 *
 * Anchored on the heading TEXT rather than a class, because the live lab bundle
 * (Element 1.12.x, `bundles/b1848b64aa8f57bcfc88/element-web-app.js`) no longer
 * carries a `mx_CurrentDeviceSection` container class — only the child
 * `mx_CurrentDeviceSection_deviceDetails` survives, and the enclosing
 * `mx_SettingsSubsection` is likewise gone (only `_content` / `_description`
 * remain). The card is therefore delimited in DOCUMENT ORDER: everything between
 * the "Current session" heading and the next section heading ("Security
 * recommendations" / "Other sessions"). All three strings are confirmed in the
 * served `i18n/en_EN.751084b.json`.
 *
 * Returns `found:false` (never a silent empty result) when the heading is absent,
 * so a rename fails the assertion loudly instead of reporting an inert card.
 */
async function readCurrentSessionCard(page) {
  return page
    .evaluate(() => {
      const vis = (el) => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return false;
        const cs = window.getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
      };
      const label = (el) =>
        (el.innerText || '').replace(/\s+/g, ' ').trim() ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        '';
      const text = (el) => (el.textContent || '').replace(/\s+/g, ' ').trim();

      const heads = [...document.querySelectorAll('h1,h2,h3,h4,h5,[role="heading"]')].filter(vis);
      const cur = heads.find((h) => /^current session\b/i.test(text(h)));
      if (!cur) return { found: false, headings: heads.map(text).slice(0, 15) };

      const FOLLOWING = 4; // Node.DOCUMENT_POSITION_FOLLOWING
      const PRECEDING = 2; // Node.DOCUMENT_POSITION_PRECEDING
      const next = heads.find(
        (h) =>
          /^(other sessions|security recommendations)\b/i.test(text(h)) &&
          !!(cur.compareDocumentPosition(h) & FOLLOWING),
      );
      const inRange = (el) =>
        !!(cur.compareDocumentPosition(el) & FOLLOWING) &&
        (!next || !!(next.compareDocumentPosition(el) & PRECEDING));

      const all = [...document.querySelectorAll('button, [role="button"], a[href]')].filter(inRange);
      return {
        found: true,
        boundedBy: next ? text(next) : null,
        controls: [
          ...new Set(
            all
              .filter(
                (el) =>
                  vis(el) &&
                  !el.hasAttribute('disabled') &&
                  el.getAttribute('aria-disabled') !== 'true' &&
                  el.getAttribute('aria-hidden') !== 'true',
              )
              .map(label)
              .filter(Boolean),
          ),
        ].slice(0, 20),
        disabled: [
          ...new Set(
            all
              .filter(
                (el) =>
                  vis(el) && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true'),
              )
              .map(label)
              .filter(Boolean),
          ),
        ].slice(0, 20),
      };
    })
    .catch((e) => ({ found: false, error: String(e).slice(0, 160) }));
}

/** Enabled + disabled controls inside one session-list tile. */
async function readTile(locator) {
  return locator
    .evaluate((root) => {
      const vis = (el) => {
        const r = el.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return false;
        const cs = window.getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
      };
      const label = (el) =>
        (el.innerText || '').replace(/\s+/g, ' ').trim() || el.getAttribute('aria-label') || '';
      const all = [...root.querySelectorAll('button, [role="button"], a[href]')];
      return {
        text: (root.innerText || '').replace(/\s+/g, ' ').slice(0, 200),
        controls: [
          ...new Set(
            all
              .filter(
                (el) =>
                  vis(el) && !el.hasAttribute('disabled') && el.getAttribute('aria-disabled') !== 'true',
              )
              .map(label)
              .filter(Boolean),
          ),
        ].slice(0, 15),
        disabled: [
          ...new Set(
            all
              .filter(
                (el) =>
                  vis(el) && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true'),
              )
              .map(label)
              .filter(Boolean),
          ),
        ].slice(0, 15),
      };
    })
    .catch((e) => ({ error: String(e).slice(0, 160), controls: [], disabled: [] }));
}

/** Is something covering the app shell that the user must dismiss? */
async function obstructed(page) {
  return page
    .locator('.mx_Dialog, .mx_CompleteSecurityBody')
    .first()
    .isVisible()
    .catch(() => false);
}

// ---------------------------------------------------------------------------

test('EW-D1: add a second device while device A is live — every screen on both devices offers an exit', async ({
  browser,
}) => {
  test.setTimeout(900_000);

  // Fresh identity every run: the lab is shared, and a colliding Synapse user
  // would make "B is a new unverified device" untrue without saying so.
  const w = makeWallet(undefined, SERVER_NAME);
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();

  /** Every screen the walk recorded, per device. Drives the non-vacuity guard. */
  const screens = { A: [], B: [] };
  const ceremonySamples = [];
  const clickLog = [];
  let ackRequiredOnB = null;
  let ackRequiredOnA = null;

  const step = async (tag, page, label, opts) => {
    const s = await settle(page, label, opts);
    screens[tag].push(s);
    return s;
  };

  let pageA;
  let pageB;
  try {
    // =====================================================================
    // D1.1 — DEVICE A: sign in and complete first-device setup.
    //
    // Driven by the shared helper, NOT walked click-by-click: EW-J1 already
    // walks the first-device Secure Backup wizard's interior screen by screen
    // and there is nothing to add. Here it is setup, and only its terminal is
    // recorded.
    // =====================================================================
    pageA = await ctxA.newPage();
    const A = await elementWalletClickLogin(pageA, w);
    expect(A.user_id).toBe(w.mxid);
    expect(A.device_id).toBeTruthy();

    assertExit(await step('A', pageA, 'D1.1 A after first-device setup', { budgetMs: 120_000 }));
    await expect(
      pageA.locator('.mx_MatrixChat'),
      'device A never reached the app shell after its own setup — the journey has no live session to verify from',
    ).toBeVisible({ timeout: 120_000 });

    // PRECONDITION, not a result. Element gates the "Verify session" trigger on
    // `isCurrentDeviceVerified` (useOwnDevices.ts), so if A is not cross-signed
    // the trigger will not render and the failure would look like a B-side
    // defect. Asserted here so it is attributed correctly. Client self-report is
    // adequate for a precondition; EW-V1 owns the server-truth version.
    const probeA = await cryptoProbe(pageA);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] A device=${A.device_id} crossSigningReady=${probeA?.crossSigningReady} ` +
        `secretStorageReady=${probeA?.secretStorageReady} ` +
        `ownDeviceStatus=${JSON.stringify(probeA?.ownDeviceStatus)} server4S=${probeA?.server4S}`,
    );
    expect(
      probeA?.ownDeviceStatus?.crossSigningVerified,
      `device A is not cross-signed after its own setup, so it cannot act as a verifier and ` +
        `"Verify session" will never render. probe=${JSON.stringify(probeA)}`,
    ).toBe(true);

    // =====================================================================
    // D1.2 — DEVICE B: same identity, fresh browser, A STILL LIVE.
    // Walk the gate it lands on and record every control, enabled and not.
    // =====================================================================
    pageB = await ctxB.newPage();
    const B = await elementWalletLoginNoWizard(pageB, w);
    expect(B.user_id).toBe(A.user_id);
    expect(
      B.device_id,
      'device B was issued the SAME Synapse device id as A — there is no second device and the ' +
        'whole journey is a no-op',
    ).not.toBe(A.device_id);

    const gate = await step('B', pageB, 'D1.2 B second-device gate', { budgetMs: 90_000 });
    const gateSample = await ceremonySample(pageB, { at: 0 });
    ceremonySamples.push(gateSample);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.2 B gate — class=${gateSample.classification} ` +
        `phase=${gateSample.phase} (${PHASE_NAMES[gateSample.phase] ?? 'n/a'}) ` +
        `hasDevicesToVerifyAgainst=${gateSample.hasDevicesToVerifyAgainst} ` +
        `controls=${JSON.stringify(gate.controls)} disabled=${JSON.stringify(gate.disabled)}`,
    );
    assertExit(gate);

    // If B were admitted straight into the app this walk would assert nothing
    // about a gate, so the premise is asserted rather than assumed. It is also a
    // finding either way: an unverified second session silently reaching the app
    // is its own defect.
    expect(
      gate.appShell,
      `device B reached the app shell with NO verification gate. Either force_verification is off ` +
        `on this lab (this spec then walks a journey that no longer exists and must be re-scoped) ` +
        `or an unverified session was silently admitted. headings=${JSON.stringify(gate.headings)}`,
    ).toBe(false);

    // THE point of "while a live session exists": the peer-verification exit must
    // be offered, and offered ENABLED. This is the non-destructive route the whole
    // lost-key mitigation depends on.
    expect(
      gate.controls.some((c) => /another device/i.test(c)),
      `the second-device gate offers no ENABLED "Use another device" control even though device A ` +
        `is signed in and live. Without it the user's only routes are the recovery key they may not ` +
        `have and the destructive reset. enabled=${JSON.stringify(gate.controls)} ` +
        `disabled-but-visible=${JSON.stringify(gate.disabled)}`,
    ).toBe(true);
    expect(
      gateSample.hasDevicesToVerifyAgainst,
      `SetupEncryptionStore reports NO devices to verify against while device A is live — B cannot ` +
        `be offered peer verification it does not know is possible`,
    ).toBe(true);

    // =====================================================================
    // D1.3 — DEVICE A drives: Settings -> Sessions -> B's tile -> Verify session.
    // =====================================================================
    await openSessionsTab(pageA);
    assertExit(await step('A', pageA, 'D1.3 A settings → sessions', { budgetMs: 30_000 }));

    let item = null;
    const findDeadline = Date.now() + 120_000;
    while (Date.now() < findDeadline && !item) {
      item = await findDeviceListItem(pageA, B.device_id);
      if (!item) await pageA.waitForTimeout(2_000);
    }
    expect(
      item,
      `device B (${B.device_id}) never appeared in device A's session list, so A cannot start the ` +
        `verification at all`,
    ).not.toBeNull();

    const expand = item.locator('.mx_DeviceExpandDetailsButton');
    if (await expand.count()) {
      const alreadyOpen = await item.getByRole('button', { name: /^verify session$/i }).count();
      if (!alreadyOpen) await expand.first().click({ timeout: 20_000 });
    }

    const tileBefore = await readTile(item);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.3 A tile for B (before) — controls=${JSON.stringify(tileBefore.controls)} ` +
        `disabled=${JSON.stringify(tileBefore.disabled)} text="${tileBefore.text}"`,
    );

    const verifyBtn = item.getByRole('button', { name: /^verify session$/i }).first();
    await expect(
      verifyBtn,
      `"Verify session" did not render on device B's tile. It is gated on ` +
        `device.isVerified === false && !!onVerifyDevice. tile=${JSON.stringify(tileBefore)}`,
    ).toBeVisible({ timeout: 60_000 });
    expect(
      await verifyBtn.isEnabled(),
      `"Verify session" is rendered DISABLED on device B's tile. A greyed-out button is not an exit; ` +
        `this is the shape of the U5 complaint. tile=${JSON.stringify(tileBefore)}`,
    ).toBe(true);
    await verifyBtn.click();
    clickLog.push('A: Verify session');

    // =====================================================================
    // D1.4 — THE CEREMONY, walked on BOTH sides.
    //
    // Per iteration and in this order: sample B's ceremony discriminator and LOG
    // it, then judge B's screen, then judge A's screen and its verification
    // surface, then advance by exactly one whitelisted click. The ordering
    // guarantees that a "DEAD END" verdict is always printed underneath the phase
    // and control count that distinguish T_C_Wedged from T_C_OkAwaitAck.
    //
    // B's settle budget (25s) is deliberately above the I-C1 dwell (20s) so a
    // slow-but-healthy transition is never reported as a dead end.
    // =====================================================================
    const t0 = Date.now();
    const sasDeadline = t0 + SAS_BUDGET_MS;
    let bothShowEmoji = false;
    let round = 0;
    while (Date.now() < sasDeadline) {
      const [ea, eb] = await Promise.all([emojiVisible(pageA), emojiVisible(pageB)]);
      if (ea && eb) {
        bothShowEmoji = true;
        break;
      }
      round += 1;

      const cs = await ceremonySample(pageB, { at: Date.now() - t0 });
      ceremonySamples.push(cs);
      // eslint-disable-next-line no-console
      console.log(
        `[EW-D1] D1.4.${round} B ceremony sample — class=${cs.classification} ` +
          `phase=${cs.phase} (${PHASE_NAMES[cs.phase] ?? 'n/a'}) ` +
          `controls=${JSON.stringify(cs.controls)} shell=${cs.appShell} ` +
          `crossSigningReady=${cs.crypto?.crossSigningReady}`,
      );
      assertExit(await step('B', pageB, `D1.4.${round} B ceremony`, { budgetMs: 25_000 }));

      assertExit(await step('A', pageA, `D1.4.${round} A ceremony`, { budgetMs: 10_000 }));
      const vsA = await readVerificationSurface(pageA);
      // eslint-disable-next-line no-console
      console.log(
        `[EW-D1] D1.4.${round} A verification surface — present=${vsA.present} ` +
          `controls=${JSON.stringify(vsA.controls)} disabled=${JSON.stringify(vsA.disabled)} ` +
          `text="${vsA.text ?? ''}"`,
      );

      for (const [tag, p] of [
        ['B', pageB],
        ['A', pageA],
      ]) {
        const clicked = await advanceVerification(p);
        if (clicked) clickLog.push(`${tag}: ${clicked}`);
      }
      await pageA.waitForTimeout(1_000);
    }
    if (!bothShowEmoji) {
      const [da, db] = await Promise.all([
        describeSurface(pageA).catch(() => null),
        describeSurface(pageB).catch(() => null),
      ]);
      throw new Error(
        `the SAS emoji comparison never rendered on BOTH sides within ${SAS_BUDGET_MS / 1000}s.\n` +
          `clicks: ${JSON.stringify(clickLog)}\nA: ${JSON.stringify(da, null, 1)}\nB: ${JSON.stringify(db, null, 1)}`,
      );
    }

    // =====================================================================
    // D1.5 — the emoji comparison screen, on both devices.
    // =====================================================================
    assertExit(await step('B', pageB, 'D1.5 B SAS emoji', { budgetMs: 20_000 }));
    assertExit(await step('A', pageA, 'D1.5 A SAS emoji', { budgetMs: 20_000 }));

    const vsAEmoji = await readVerificationSurface(pageA);
    const vsBEmoji = await readVerificationSurface(pageB);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.5 A emoji surface — controls=${JSON.stringify(vsAEmoji.controls)} ` +
        `disabled=${JSON.stringify(vsAEmoji.disabled)}\n` +
        `[EW-D1] D1.5 B emoji surface — controls=${JSON.stringify(vsBEmoji.controls)} ` +
        `disabled=${JSON.stringify(vsBEmoji.disabled)}`,
    );

    // Device A's REAL assertion. `assertExit(A)` above is satisfied by the app
    // shell alone and says nothing about the prompt; this says the prompt is
    // actionable. It goes red if Element ever renders the SAS confirmation
    // greyed out on the verifying side.
    expect(
      vsAEmoji.controls.some((c) => /they match/i.test(c)),
      `device A is showing the SAS comparison but "They match" is not offered as an ENABLED control. ` +
        `enabled=${JSON.stringify(vsAEmoji.controls)} disabled-but-visible=${JSON.stringify(vsAEmoji.disabled)}`,
    ).toBe(true);
    expect(
      vsBEmoji.controls.some((c) => /they match/i.test(c)),
      `device B is showing the SAS comparison but "They match" is not offered as an ENABLED control. ` +
        `enabled=${JSON.stringify(vsBEmoji.controls)} disabled-but-visible=${JSON.stringify(vsBEmoji.disabled)}`,
    ).toBe(true);

    // Harness anchor, not a crypto claim (EW-V1 owns the crypto): if the two
    // strips were not identical the walk would be walking two unrelated
    // ceremonies and every screen below would be meaningless.
    const emojiA = await readSasEmoji(pageA);
    const emojiB = await readSasEmoji(pageB);
    // eslint-disable-next-line no-console
    console.log(`[EW-D1] SAS emoji A: ${emojiA}\n[EW-D1] SAS emoji B: ${emojiB}`);
    expect(emojiB, 'the two devices are showing DIFFERENT SAS strips').toBe(emojiA);
    expect(emojiA.split(/\s+/).filter(Boolean).length).toBeGreaterThanOrEqual(7);

    await clickTheyMatch(pageA);
    clickLog.push('A: SAS: They match');
    await clickTheyMatch(pageB);
    clickLog.push('B: SAS: They match');

    // =====================================================================
    // D1.6 — THE TERMINAL, AND THE ACK QUESTION. Nothing is clicked in this
    // block. This is the measurement EW-V1 structurally cannot make.
    // =====================================================================
    const ackT0 = Date.now();
    let bClearUnaided = false;
    let lastB = null;
    while (Date.now() - ackT0 < ACK_PROBE_MS) {
      lastB = await ceremonySample(pageB, { at: Date.now() - t0 });
      lastB.obstructed = await obstructed(pageB);
      ceremonySamples.push(lastB);
      if (lastB.appShell && !lastB.obstructed) {
        bClearUnaided = true;
        break;
      }
      await pageB.waitForTimeout(POLL_MS);
    }
    ackRequiredOnB = !bClearUnaided;
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.6 ACK PROBE (device B, nothing clicked for ` +
        `${Math.round((Date.now() - ackT0) / 1000)}s) — reachedUnobstructedShell=${bClearUnaided} ` +
        `=> ackRequired=${ackRequiredOnB}; terminal class=${lastB?.classification} ` +
        `phase=${lastB?.phase} (${PHASE_NAMES[lastB?.phase] ?? 'n/a'}) ` +
        `shell=${lastB?.appShell} obstructed=${lastB?.obstructed} ` +
        `controls=${JSON.stringify(lastB?.controls)} ` +
        `crossSigningReady=${lastB?.crypto?.crossSigningReady}`,
    );

    // I-C1 FIRST. Evaluated before any exit verdict so the phase + control count
    // is always on record ahead of a "dead end" claim. Throws only on a SUSTAINED
    // zero-control ceremony view with healthy crypto — i.e. T_C_Wedged, never
    // T_C_OkAwaitAck.
    assertCeremonyInvariant(ceremonySamples, { label: 'EW-D1 device B post-SAS' });

    const termB = await step('B', pageB, 'D1.6 B terminal', { budgetMs: 25_000 });
    assertExit(termB);

    if (!bClearUnaided) {
      // Name which of the two look-alike states this is, explicitly. A dialog on
      // top of a live shell and a phase-3/5 SetupEncryptionBody are both valid
      // "waiting on a click"; a phase-2 zero-control view is not.
      const shape = lastB?.appShell ? 'dialog-ack' : lastB?.classification;
      expect(
        ['dialog-ack', 'T_C_OkAwaitAck'],
        `device B did not reach an unobstructed app shell in ${ACK_PROBE_MS / 1000}s AND is not in a ` +
          `valid acknowledgement-pending terminal. shape=${shape} phase=${lastB?.phase} ` +
          `(${PHASE_NAMES[lastB?.phase] ?? 'n/a'}) controls=${JSON.stringify(lastB?.controls)} ` +
          `crossSigningReady=${lastB?.crypto?.crossSigningReady}. ` +
          `T_C_OkAwaitAck (success awaiting a click) and T_C_Wedged (zero controls) are opposite in ` +
          `kind and must never be collapsed — the discriminator is phase + enabled-control count.`,
      ).toContain(shape);

      const clickedB = await finishVerification(pageB);
      for (const d of clickedB) clickLog.push(`B: terminal ${d}`);
      expect(
        clickedB.length,
        `device B is waiting on an acknowledgement but no terminal control ("Got It" / "Done") could ` +
          `be clicked. controls=${JSON.stringify(lastB?.controls)}`,
      ).toBeGreaterThan(0);
    }

    await expect(
      pageB.locator('.mx_MatrixChat'),
      `device B never reached the app shell${ackRequiredOnB ? ' even after the acknowledgement click' : ''} ` +
        `after a successful SAS`,
    ).toBeVisible({ timeout: 120_000 });

    const afterB = await step('B', pageB, 'D1.7 B after terminal', { budgetMs: 60_000 });
    assertExit(afterB);
    expect(afterB.appShell).toBe(true);

    // Device A's terminal. A is inside the app for the whole journey, so the
    // question is not "can A act" but "did the ceremony leave a prompt A must
    // dismiss". `obstructed()` is useless here — A has the Settings dialog open
    // by construction.
    //
    // The attempted dismissal is UNCONDITIONAL, and what was on screen is
    // recorded from `describeSurface` (which reads `.mx_Dialog`,
    // `.mx_CompleteSecurityBody`, `.mx_Toast_toast` and `.mx_VerificationPanel`)
    // BEFORE and AFTER. An earlier version gated the dismissal on
    // `readVerificationSurface` finding a control, which — via the browser-warning
    // toast — was true unconditionally anyway, so `ackRequiredOnA` was an accident
    // rather than a measurement. Now the click is always attempted and the answer
    // is simply whether a terminal control was there to take it.
    // Attributability is checked with the SAME instrument that does the clicking
    // (`getByRole('button', ...)`), not with `describeSurface`'s button list:
    // measured 2026-07-26, that list enumerates literal `<button>` elements only,
    // and Element renders "Got it" as an AccessibleButton `[role="button"]`, so it
    // is absent from `buttons` while plainly present in `panels`
    // ("Device verified ... Got it"). A guard written against the wrong instrument
    // fails a healthy product.
    const aTerminalBtn = pageA.getByRole('button', { name: /^(got it|done)$/i }).first();
    const aTerminalVisible =
      (await aTerminalBtn.count()) > 0 && (await aTerminalBtn.isVisible().catch(() => false));
    const aBefore = await describeSurface(pageA).catch(() => ({ panels: [], buttons: [] }));
    const clickedA = await finishVerification(pageA);
    for (const d of clickedA) clickLog.push(`A: terminal ${d}`);
    ackRequiredOnA = clickedA.length > 0;
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.7 A terminal — terminalControlVisibleBefore=${aTerminalVisible} ` +
        `clicked=${JSON.stringify(clickedA)} => ackRequired=${ackRequiredOnA}\n` +
        `[EW-D1] D1.7 A panels BEFORE=${JSON.stringify((aBefore.panels || []).map((p) => p.slice(0, 160)))}`,
    );
    if (ackRequiredOnA) {
      // 1. The control really was on screen before the click.
      expect(
        aTerminalVisible,
        `device A was dismissed with ${JSON.stringify(clickedA)} but no visible "Got It"/"Done" ` +
          `control was found beforehand — the measurement is not attributable. ` +
          `panels=${JSON.stringify(aBefore.panels)}`,
      ).toBe(true);
      // 2. It really was the verification acknowledgement, not some other dialog.
      expect(
        (aBefore.panels || []).some((p) => /device verified/i.test(p)),
        `device A held a "Got It"/"Done" control but no "Device verified" panel — the ` +
          `acknowledgement being measured is not the verification one. ` +
          `panels=${JSON.stringify(aBefore.panels)}`,
      ).toBe(true);
      // 3. And the click actually cleared it. Without this, "an acknowledgement was
      //    required" could be recorded for a click that changed nothing.
      await expect
        .poll(
          async () => {
            const s = await describeSurface(pageA).catch(() => ({ panels: [] }));
            return (s.panels || []).some((p) => /device verified/i.test(p));
          },
          {
            timeout: 30_000,
            intervals: [2_000],
            message:
              'device A\'s "Device verified" acknowledgement panel is STILL on screen after clicking ' +
              `${JSON.stringify(clickedA)} — the acknowledgement did not take`,
          },
        )
        .toBe(false);
    }
    assertExit(await step('A', pageA, 'D1.7 A after verification', { budgetMs: 30_000 }));

    // =====================================================================
    // D1.8 — Settings -> Sessions on device A, afterwards.
    // =====================================================================
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
          message:
            "device A's session list never showed device B as verified after a successful SAS — the " +
            'user-visible payoff of the whole journey never lands',
        },
      )
      .toBe('verified');

    assertExit(await step('A', pageA, 'D1.8 A sessions after verification', { budgetMs: 30_000 }));

    const tileAfterLoc = await findDeviceListItem(pageA, B.device_id);
    const tileAfter = tileAfterLoc ? await readTile(tileAfterLoc) : null;
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.8 A tile for B (after) — controls=${JSON.stringify(tileAfter?.controls ?? [])} ` +
        `disabled=${JSON.stringify(tileAfter?.disabled ?? [])} text="${tileAfter?.text ?? ''}"`,
    );

    const card = await readCurrentSessionCard(pageA);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] D1.8 A current-session card — found=${card.found} boundedBy=${JSON.stringify(card.boundedBy)} ` +
        `controls=${JSON.stringify(card.controls ?? [])} disabled=${JSON.stringify(card.disabled ?? [])}` +
        (card.found ? '' : ` headingsSeen=${JSON.stringify(card.headings ?? [])}`),
    );
    expect(
      card.found,
      `Settings → Sessions renders no "Current session" heading, so the current-session card could not ` +
        `be located at all. headings seen: ${JSON.stringify(card.headings ?? [])}`,
    ).toBe(true);
    expect(
      (card.controls || []).length,
      `the current-session card offers NO enabled control — the user can see their own session but do ` +
        `nothing with it. disabled-but-visible: ${JSON.stringify(card.disabled ?? [])}`,
    ).toBeGreaterThan(0);

    // =====================================================================
    // NON-VACUITY GUARD. Every assertion above is conditional on the walk having
    // actually happened; these say it did. Without them a harness that
    // short-circuited (no gate found, loop never entered, nothing clicked) would
    // report green having exercised nothing.
    // =====================================================================
    // eslint-disable-next-line no-console
    console.log(
      `[EW-D1] SUMMARY — screensA=${screens.A.length} screensB=${screens.B.length} ` +
        `ceremonySamples=${ceremonySamples.length} ackRequiredOnB=${ackRequiredOnB} ` +
        `ackRequiredOnA=${ackRequiredOnA} clicks=${JSON.stringify(clickLog)}`,
    );
    expect(
      screens.B.length,
      `the walk recorded only ${screens.B.length} screen(s) on device B; the journey short-circuited ` +
        `and the exit invariant was never really exercised`,
    ).toBeGreaterThanOrEqual(4);
    expect(
      screens.A.length,
      `the walk recorded only ${screens.A.length} screen(s) on device A`,
    ).toBeGreaterThanOrEqual(4);
    expect(
      clickLog.filter((c) => /SAS: They match/.test(c)).length,
      `the emoji comparison was not confirmed on both devices; clicks=${JSON.stringify(clickLog)}`,
    ).toBe(2);
    expect(
      ceremonySamples.length,
      'no ceremony samples were taken, so the T_C_OkAwaitAck / T_C_Wedged discriminator never ran',
    ).toBeGreaterThanOrEqual(2);
  } finally {
    await ctxA.close().catch(() => {});
    await ctxB.close().catch(() => {});
  }
});
