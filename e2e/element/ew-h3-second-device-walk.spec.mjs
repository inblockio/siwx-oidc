/**
 * H3 — "Second-device authentication of a session works end to end."
 *
 * This file exists because EW-Q1-c reported the "Link new device" section did not
 * render AT ALL, and that report was produced by a spec that had never been run.
 *
 * THE NAVIGATION EW-Q1-c USED IS A NO-OP. `ew-qr-second-device.spec.mjs:286` does
 *   page.goto(`${ELEMENT_URL}/#/settings/sessions`)
 * Element Web 1.12.20's `MatrixChat.showScreen` (structures/MatrixChat.tsx:1844-2007)
 * matches `screen === "settings"` EXACTLY (:1899) and has no `settings/…` prefix
 * branch; the final `else if` (:2005) is a module-API location renderer. So the
 * string "settings/sessions" falls through every branch and NOTHING is dispatched:
 * the settings dialog never opens, `SessionManagerTab` never mounts, and
 * `LoginWithQRSection` — which that tab renders UNCONDITIONALLY at
 * tabs/user/SessionManagerTab.tsx:274 — is legitimately absent from the DOM.
 * Even `#/settings` would be wrong: it opens `UserTab.Account`
 * (dialogs/UserSettingsDialog.tsx:254 defaults to Account).
 *
 * The correct entry point is the one the already-executed specs use:
 * `openSessionsTab` (helpers/verify-sas.mjs:209) — user menu → All settings →
 * Sessions tab. This file re-walks the journey through it.
 *
 * WHAT WOULD TURN EACH LEG RED (stated up front, because a green test that asserts
 * nothing is the failure mode this project keeps hitting):
 *
 *   H3-A  red if the "Link new device" subsection is absent after REAL navigation;
 *         red if the "Show QR code" button is disabled; red if the
 *         "Not supported by your account provider" string renders; red if clicking
 *         it produces no POST to the MSC4108 rendezvous endpoint; red if no QR
 *         graphic is painted. The in-page probe reproduces
 *         `shouldShowQrForLinkNewDevice`'s three conjuncts INDEPENDENTLY of the
 *         DOM, so a green DOM with a false conjunct would still be caught.
 *
 *   H3-C  red if B's gate offers no ENABLED "Use another device"; red if clicking
 *         it lands B on a screen with no enabled control and no app shell; red if
 *         device A never receives a verification request within the budget. The
 *         emoji strips are compared A-vs-B, so a "verification" that showed two
 *         different SAS values fails.
 *
 * SHARED LAB: every identity here is a freshly generated wallet, so no Synapse
 * user collides with a concurrently running suite. Nothing is restarted.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, MATRIX_URL, SIWX_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import {
  registerDeviceClient,
  requestDeviceAuthorization,
  pollDeviceToken,
  matrixWhoami,
} from './helpers/device-code.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';
import { settle, assertExit } from './helpers/journey.mjs';
import {
  advanceVerification,
  clickTheyMatch,
  cryptoProbe,
  describeSurface,
  elementWalletLoginNoWizard,
  emojiVisible,
  finishVerification,
  openSessionsTab,
  readSasEmoji,
} from './helpers/verify-sas.mjs';

const SERVER_NAME = 'localhost';
const RZ_PATH = 'org.matrix.msc4108/rendezvous';

test.beforeAll(async () => {
  await requireElementStack();
});

/**
 * Reproduce `shouldShowQrForLinkNewDevice` (LoginWithQRSection.tsx:29-31) and the
 * two conjuncts inside `isSignInWithQRAvailable` (matrix-js-sdk 41.6.0
 * src/rendezvous/index.ts, read out of the LIVE lab bundle's source map) from
 * inside the page, so the offer's state is known independently of what the DOM shows.
 */
async function qrGateProbe(page) {
  return page.evaluate(async () => {
    const out = {};
    const peg = window.mxMatrixClientPeg;
    const cli = peg && typeof peg.get === 'function' ? peg.get() : null;
    if (!cli) return { client: false };
    out.client = true;
    try {
      const meta = await cli.getAuthMetadata();
      out.authMetadataOk = true;
      out.grantTypes = meta.grant_types_supported;
      out.deviceGrant = (meta.grant_types_supported || []).includes(
        'urn:ietf:params:oauth:grant-type:device_code',
      );
      out.responseModes = meta.response_modes_supported ?? null;
    } catch (e) {
      // isSignInWithQRAvailable returns false on ANY throw here — the exact
      // silent-disable path Finding 3 is about.
      out.authMetadataOk = false;
      out.authMetadataError = String(e).slice(0, 200);
      out.deviceGrant = false;
    }
    out.msc4108 = !!cli.doesServerSupportUnstableFeature?.('org.matrix.msc4108');
    const crypto = cli.getCrypto ? cli.getCrypto() : null;
    out.exportSecretsBundle = !!crypto?.exportSecretsBundle;
    try {
      out.crossSigningReady = await crypto?.isCrossSigningReady();
    } catch (e) {
      out.crossSigningReady = 'ERR: ' + String(e).slice(0, 120);
    }
    out.shouldShowQr =
      out.deviceGrant && out.msc4108 && out.exportSecretsBundle && out.crossSigningReady === true;
    return out;
  });
}

/** The LoginWithQRSection subsection, as the user sees it. */
async function readQrSection(page) {
  return page.evaluate(() => {
    const vis = (el) => {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const sect = document.querySelector('.mx_LoginWithQRSection');
    const heading = [...document.querySelectorAll('h2,h3,.mx_SettingsSubsection_heading')]
      .filter(vis)
      .map((h) => (h.innerText || '').trim())
      .find((t) => /link new device/i.test(t));
    if (!sect) return { present: false, heading: heading ?? null };
    const btn = sect.querySelector('button, [role="button"], .mx_AccessibleButton');
    const text = (sect.innerText || '').replace(/\s+/g, ' ').trim();
    return {
      present: true,
      heading: heading ?? null,
      text,
      unsupportedMessage: /not supported by your account provider/i.test(text),
      button: btn
        ? {
            label: (btn.innerText || '').replace(/\s+/g, ' ').trim(),
            visible: vis(btn),
            disabled:
              btn.hasAttribute('disabled') || btn.getAttribute('aria-disabled') === 'true',
          }
        : null,
    };
  });
}

// ---------------------------------------------------------------------------
// H3-A — the QR / "Link new device" offer, reached by the navigation that works.
// ---------------------------------------------------------------------------

test('H3-A: Settings → Sessions offers an ENABLED "Show QR code" that opens a real rendezvous', async ({
  page,
}) => {
  test.setTimeout(600_000);

  const rendezvousPosts = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().includes(RZ_PATH)) rendezvousPosts.push(r.url());
  });
  const rendezvousResponses = [];
  page.on('response', async (r) => {
    if (r.url().includes(RZ_PATH)) {
      rendezvousResponses.push(`${r.request().method()} ${r.status()}`);
    }
  });

  const w = makeWallet(undefined, SERVER_NAME);
  const A = await elementWalletClickLogin(page, w);
  // eslint-disable-next-line no-console
  console.log(`[H3-A] logged in user=${A.user_id} device=${A.device_id} wizard=${A.wizard}`);

  assertExit(await settle(page, 'A0 after login', { budgetMs: 60_000 }));

  // The gate's conjuncts, measured in-page BEFORE looking at any DOM.
  const gate = await qrGateProbe(page);
  // eslint-disable-next-line no-console
  console.log(`[H3-A] shouldShowQrForLinkNewDevice probe = ${JSON.stringify(gate)}`);

  // Navigate the way a user does. NOT `#/settings/sessions` — that route does not exist.
  await openSessionsTab(page);
  const s1 = await settle(page, 'A1 settings → sessions', { budgetMs: 60_000 });
  assertExit(s1);

  // The offer is DOUBLY async: `isCrossSigningReady` is a useAsyncMemo with NO initial
  // value (SessionManagerTab.tsx:165) and `offerShowQr` is a useAsyncMemo whose initial
  // value is literally `false` (LoginWithQRSection.tsx:35-39, hooks/useAsyncMemo.ts).
  // So the button is disabled and the "unsupported" text is shown on the FIRST paint of
  // every visit, by construction. Sampling once here would manufacture a false red, so
  // the trajectory is recorded and only the SETTLED state is judged.
  const trajectory = [];
  let qr = null;
  const qrDeadline = Date.now() + 90_000;
  for (;;) {
    qr = await readQrSection(page);
    trajectory.push({
      t: Math.round((Date.now() - (qrDeadline - 90_000)) / 1000),
      disabled: qr.button?.disabled ?? null,
      unsupported: qr.unsupportedMessage ?? null,
    });
    if (qr.present && qr.button && !qr.button.disabled && !qr.unsupportedMessage) break;
    if (Date.now() >= qrDeadline) break;
    await page.waitForTimeout(2_000);
  }
  // eslint-disable-next-line no-console
  console.log(`[H3-A] LoginWithQRSection SETTLED = ${JSON.stringify(qr)}`);
  // eslint-disable-next-line no-console
  console.log(`[H3-A] offer trajectory (s, disabled, unsupported) = ${JSON.stringify(trajectory)}`);

  expect(
    qr.present,
    `The "Link new device" subsection (.mx_LoginWithQRSection) did not render after REAL ` +
      `navigation (user menu → All settings → Sessions). SessionManagerTab.tsx:274 renders it ` +
      `unconditionally, so its absence here means the Sessions tab itself never mounted. ` +
      `screen=${JSON.stringify({ headings: s1.headings, controls: s1.controls })}`,
  ).toBe(true);

  expect(
    qr.unsupportedMessage,
    `Element STILL renders "Not supported by your account provider" after 90s on the Sessions ` +
      `tab. Measured conjuncts (in-page, same client): ${JSON.stringify(gate)}. ` +
      `trajectory=${JSON.stringify(trajectory)}. If deviceGrant/msc4108 are true this is a ` +
      `CLIENT-side finding (crypto readiness or a useAsyncMemo that never re-resolves), ` +
      `not a siwx-oidc one — and the message shown to the user is false either way.`,
  ).toBe(false);

  expect(qr.button, 'the QR subsection rendered no button at all').not.toBeNull();
  expect(qr.button.label).toMatch(/show qr code/i);
  expect(
    qr.button.disabled,
    `"Show QR code" is rendered but DISABLED — the offer-withheld terminal, in which the ` +
      `user never reaches the QR flow. conjuncts=${JSON.stringify(gate)}`,
  ).toBe(false);

  // Independent of the DOM: the gate function itself must evaluate true.
  expect(
    gate.shouldShowQr,
    `shouldShowQrForLinkNewDevice evaluated FALSE in-page: ${JSON.stringify(gate)}`,
  ).toBe(true);

  await page.getByRole('button', { name: /show qr code/i }).first().click();

  const s2 = await settle(page, 'A2 after Show QR code', { budgetMs: 60_000 });
  // eslint-disable-next-line no-console
  console.log(`[H3-A] rendezvous wire so far: posts=${rendezvousPosts.length} ${JSON.stringify(rendezvousResponses.slice(0, 8))}`);

  await expect
    .poll(() => rendezvousPosts.length, {
      timeout: 60_000,
      message:
        `Clicking "Show QR code" opened no MSC4108 rendezvous session (no POST to ${RZ_PATH}). ` +
        `The affordance renders but does not engage the server. wire=${JSON.stringify(rendezvousResponses)}`,
    })
    .toBeGreaterThan(0);

  const qrRendered = page.locator(
    '.mx_LoginWithQR svg, .mx_LoginWithQR canvas, [data-testid="qr-code"], .mx_QRCode svg, .mx_QRCode canvas',
  );
  await expect(
    qrRendered.first(),
    `a rendezvous session was opened but no QR graphic was painted for the second device to ` +
      `scan. screen=${JSON.stringify({ headings: s2.headings, controls: s2.controls, body: s2.body })}`,
  ).toBeVisible({ timeout: 60_000 });

  const s3 = await settle(page, 'A3 QR displayed', { budgetMs: 30_000 });
  assertExit(s3);
  // eslint-disable-next-line no-console
  console.log(
    `[H3-A] VERDICT posts=${rendezvousPosts.length} wire=${JSON.stringify(rendezvousResponses.slice(0, 12))}`,
  );
});

// ---------------------------------------------------------------------------
// H3-B — the RFC 8628 device flow's own USER-VISIBLE screen. EW-D1/EW-D2 prove the
// HTTP contract but approve by POSTing a CAIP-122 signature directly; nothing walks
// siwx-oidc's `/device` approval page, which is the surface a real second-device user
// actually sees — and it is ours, not Element's.
// ---------------------------------------------------------------------------

test('H3-B: the /device approval page is walkable and its approval issues a working token', async ({
  page,
  browser,
}) => {
  test.setTimeout(300_000);

  // Seed the identity: device approval REJECTS unprovisioned identities by design
  // (create-at-sign-in only), so an unseeded wallet would test the reject path.
  const w = makeWallet(undefined, SERVER_NAME);
  const seed = await loginWalletToTokens(page, { siwxUrl: SIWX_URL, matrixUrl: MATRIX_URL, wallet: w });
  expect(seed.access_token).toMatch(/^mat_/);

  const rc = await registerDeviceClient(SIWX_URL);
  const da = await requestDeviceAuthorization({ clientId: rc.client_id }, SIWX_URL);
  expect(da.user_code).toBeTruthy();
  expect(da.verification_uri_complete).toBeTruthy();
  // eslint-disable-next-line no-console
  console.log(`[H3-B] user_code=${da.user_code} uri=${da.verification_uri_complete}`);

  const ctx = await browser.newContext();
  try {
    // --- The BARE page (user typed the URL off their TV). Must be walkable. ---
    const bare = await ctx.newPage();
    await injectMockWallet(bare, w);
    await bare.goto(`${SIWX_URL.replace(/\/$/, '')}/device`, { waitUntil: 'domcontentloaded' });
    const b0 = await settle(bare, 'B0 /device bare (no user_code)', { budgetMs: 30_000 });
    assertExit(b0);
    expect(
      b0.controls.some((c) => /verify|continue/i.test(c)),
      `the bare /device page offers no way to submit a code. controls=${JSON.stringify(b0.controls)} ` +
        `disabled=${JSON.stringify(b0.disabled)}`,
    ).toBe(true);
    await bare.close();

    // --- The deep link the device actually prints / encodes in its QR. ---
    const appr = await ctx.newPage();
    await injectMockWallet(appr, w);
    await appr.goto(da.verification_uri_complete, { waitUntil: 'domcontentloaded' });

    const b1 = await settle(appr, 'B1 /device?user_code deep link', { budgetMs: 60_000 });
    assertExit(b1);
    expect(
      b1.body.includes(da.user_code),
      `the approval page never displayed the user_code ${da.user_code}, so the user cannot ` +
        `confirm it matches their device. body="${b1.body}"`,
    ).toBe(true);

    const walletBtn = appr.getByRole('button', { name: /sign with wallet/i }).first();
    await expect(
      walletBtn,
      `"Sign with wallet" is not offered on the approval page. controls=${JSON.stringify(b1.controls)}`,
    ).toBeVisible({ timeout: 30_000 });
    await expect(walletBtn, '"Sign with wallet" is rendered but disabled').toBeEnabled();

    await walletBtn.click();

    // `settle` alone is NOT a terminal detector here: while the signature is in flight
    // only #btn-wallet is set busy, so "Sign with passkey" / "Deny request" stay enabled
    // and settle returns EXIT immediately on a screen that has decided nothing. Wait for
    // the page to actually resolve — terminal section unhidden, or a visible error — and
    // record whichever it is, so a stuck approval cannot read as a green terminal.
    const outcome = await appr
      .evaluate(
        () =>
          new Promise((resolve) => {
            const read = () => {
              const term = document.getElementById('terminal-section');
              const status = document.getElementById('status');
              if (term && !term.classList.contains('hidden')) {
                return {
                  kind: 'terminal',
                  title: (document.getElementById('terminal-title')?.innerText || '').trim(),
                  text: (term.innerText || '').replace(/\s+/g, ' ').trim(),
                };
              }
              if (status && !status.classList.contains('hidden')) {
                return { kind: 'error', text: (status.innerText || '').replace(/\s+/g, ' ').trim() };
              }
              return null;
            };
            const t0 = Date.now();
            const tick = () => {
              const r = read();
              if (r) return resolve(r);
              if (Date.now() - t0 > 60_000) return resolve({ kind: 'timeout', text: '' });
              setTimeout(tick, 500);
            };
            tick();
          }),
      )
      .catch((e) => ({ kind: 'probe-error', text: String(e).slice(0, 200) }));
    // eslint-disable-next-line no-console
    console.log(`[H3-B] approval outcome = ${JSON.stringify(outcome)}`);
    expect(
      outcome.kind,
      `the /device approval never resolved to a terminal. outcome=${JSON.stringify(outcome)}`,
    ).toBe('terminal');

    const b2 = await settle(appr, 'B2 after approve', { budgetMs: 60_000 });
    assertExit(b2);
    // eslint-disable-next-line no-console
    console.log(`[H3-B] B2 body="${b2.body}"`);
    expect(
      /approved/i.test(b2.body),
      `the approval terminal does not say the device was approved. body="${b2.body}" ` +
        `headings=${JSON.stringify(b2.headings)}`,
    ).toBe(true);
    // The removed false-positive pre-flight must stay removed (H9 counterpart).
    expect(
      /secure backup|cross-signing|no cross/i.test(b2.body),
      `the approval terminal fabricated a crypto claim: "${b2.body}"`,
    ).toBe(false);

    // The device on the other end must now actually get in.
    const tok = await pollDeviceToken(
      { clientId: rc.client_id, deviceCode: da.device_code, intervalSec: da.interval || 2, maxWaitMs: 60_000 },
      SIWX_URL,
    );
    expect(tok.access_token).toMatch(/^mat_/);
    const who = await matrixWhoami(tok.access_token, MATRIX_URL);
    expect(who.status).toBe(200);
    expect(
      who.body.user_id,
      'the linked device authenticated as a DIFFERENT user than the approver',
    ).toBe(seed.user_id);
    // eslint-disable-next-line no-console
    console.log(`[H3-B] linked device=${who.body.device_id} user=${who.body.user_id}`);
  } finally {
    await ctx.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// H3-C — the B-INITIATED direction: "Use another device" on the new laptop's own
// gate. Covered nowhere: ew-journey-add-device walks A→B only; EW-L1b asserts the
// button is visible and never clicks it.
// ---------------------------------------------------------------------------

test('H3-C: B-initiated "Use another device" on the new device gate reaches a verified session', async ({
  browser,
}) => {
  test.setTimeout(900_000);

  const w = makeWallet(undefined, SERVER_NAME);
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();

  try {
    // --- A: the existing, healthy, cross-signed session. ---
    const A = await elementWalletClickLogin(pageA, w);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] A user=${A.user_id} device=${A.device_id} wizard=${A.wizard}`);
    const probeA = await cryptoProbe(pageA);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] A crypto = ${JSON.stringify(probeA)}`);
    expect(
      probeA.crossSigningReady,
      `device A is not cross-signing ready, so it cannot act as a verifier and this walk would ` +
        `prove nothing. probe=${JSON.stringify(probeA)}`,
    ).toBe(true);

    // --- B: the new laptop. Same identity, fresh browser, A still live. ---
    const B = await elementWalletLoginNoWizard(pageB, w);
    expect(B.user_id).toBe(A.user_id);
    expect(
      B.device_id,
      'device B got the SAME Synapse device id as A — there is no second device',
    ).not.toBe(A.device_id);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] B user=${B.user_id} device=${B.device_id} surface=${B.surface}`);

    const gateB = await settle(pageB, 'C1 B second-device gate', { budgetMs: 120_000 });
    assertExit(gateB);
    expect(
      gateB.appShell,
      `device B reached the app shell with NO verification gate — either force_verification is ` +
        `off on this lab (then this walk is mis-scoped) or an unverified session was silently ` +
        `admitted. headings=${JSON.stringify(gateB.headings)}`,
    ).toBe(false);

    const useAnother = pageB.getByRole('button', { name: /use another device/i }).first();
    expect(
      gateB.controls.some((c) => /another device/i.test(c)),
      `B's gate offers no ENABLED "Use another device". enabled=${JSON.stringify(gateB.controls)} ` +
        `disabled=${JSON.stringify(gateB.disabled)}`,
    ).toBe(true);

    // === THE CLICK NOTHING ELSE MAKES ===
    await useAnother.click({ timeout: 20_000 });
    const c2 = await settle(pageB, 'C2 B after Use another device', { budgetMs: 90_000 });
    assertExit(c2);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C2 B surface = ${JSON.stringify(await describeSurface(pageB))}`);

    // A must LEARN about it without anyone touching A.
    const reqDeadline = Date.now() + 180_000;
    let sawOnA = null;
    while (Date.now() < reqDeadline && !sawOnA) {
      const d = await describeSurface(pageA);
      if (
        d.panels.some((p) => /verification request|verify.*session|incoming/i.test(p)) ||
        d.buttons.some((b) => /^start verification$/i.test(b) || /^verify session$/i.test(b))
      ) {
        sawOnA = d;
        break;
      }
      await pageA.waitForTimeout(3_000);
    }
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C3 A incoming-request surface = ${JSON.stringify(sawOnA)}`);
    expect(
      sawOnA,
      `device A never surfaced an incoming verification request within 180s after B pressed ` +
        `"Use another device". The B-initiated direction dead-ends: B is waiting for a peer ` +
        `that is never told to respond. A surface: ${JSON.stringify(await describeSurface(pageA))}`,
    ).not.toBeNull();

    // Drive both sides with the closed whitelist until the SAS emoji appears.
    const sasDeadline = Date.now() + 240_000;
    while (Date.now() < sasDeadline) {
      if ((await emojiVisible(pageA)) && (await emojiVisible(pageB))) break;
      const a = await advanceVerification(pageA);
      const b = await advanceVerification(pageB);
      if (a || b) {
        // eslint-disable-next-line no-console
        console.log(`[H3-C] advance A=${a ?? '-'} B=${b ?? '-'}`);
      }
      await pageA.waitForTimeout(3_000);
    }

    const emojiA = (await emojiVisible(pageA)) ? await readSasEmoji(pageA) : null;
    const emojiB = (await emojiVisible(pageB)) ? await readSasEmoji(pageB) : null;
    // eslint-disable-next-line no-console
    console.log(`[H3-C] SAS A=${JSON.stringify(emojiA)}`);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] SAS B=${JSON.stringify(emojiB)}`);
    expect(
      emojiA && emojiB,
      `the SAS emoji comparison never rendered on both sides. A=${!!emojiA} B=${!!emojiB}. ` +
        `A=${JSON.stringify(await describeSurface(pageA))} B=${JSON.stringify(await describeSurface(pageB))}`,
    ).toBeTruthy();
    expect(emojiA, 'the two devices showed DIFFERENT SAS strings').toBe(emojiB);

    await clickTheyMatch(pageA);
    await clickTheyMatch(pageB);

    // Does B become a usable session? Measured, not clicked into place.
    const okDeadline = Date.now() + 120_000;
    let verified = null;
    while (Date.now() < okDeadline) {
      const p = await cryptoProbe(pageB);
      if (p.crossSigningReady === true || p.ownDeviceStatus?.crossSigningVerified === true) {
        verified = p;
        break;
      }
      await pageB.waitForTimeout(4_000);
    }
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C5 B crypto after SAS = ${JSON.stringify(verified ?? (await cryptoProbe(pageB)))}`);
    expect(
      verified,
      `device B never became cross-signing verified after the emoji were confirmed on both ` +
        `sides. probe=${JSON.stringify(await cryptoProbe(pageB))} ` +
        `surface=${JSON.stringify(await describeSurface(pageB))}`,
    ).not.toBeNull();

    const c6 = await settle(pageB, 'C6 B terminal after SAS', { budgetMs: 90_000 });
    assertExit(c6);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C6 B terminal shell=${c6.appShell} controls=${JSON.stringify(c6.controls)}`);

    // C7 — "verified" is NOT "usable". C6 is a terminal dialog ("Device verified" /
    // "Got it") sitting over the gate, with the app shell still absent. Stopping here
    // would report a destination that is really a confirmation box. Dismiss it the way
    // a user must, and require an UNOBSTRUCTED app shell: no `.mx_Dialog`, no
    // `.mx_CompleteSecurityBody` covering it.
    // NOTE ON THE CLICK. `finishVerification` (helpers/verify-sas.mjs:323) guards its
    // click by reading `document.querySelector('.mx_Dialog, .mx_CompleteSecurityBody')`
    // — the FIRST match in document order. Here two surfaces are stacked and the first
    // match is the GATE underneath, whose own text contains "Use recovery key", so the
    // guard fires and the click is silently skipped. Using it here would manufacture a
    // false red. The click is therefore scoped to the surface that actually shows the
    // terminal, and the number of clicks landed is recorded.
    const gotIt = pageB
      .locator('.mx_Dialog, .mx_CompleteSecurityBody')
      .filter({ hasText: /device verified/i })
      .getByRole('button', { name: /^got it$/i })
      .first();
    let clicks = 0;
    let unobstructed = null;
    const useDeadline = Date.now() + 120_000;
    while (Date.now() < useDeadline) {
      unobstructed = await pageB.evaluate(() => ({
        appShell: !!document.querySelector('.mx_MatrixChat'),
        dialog: !!document.querySelector('.mx_Dialog'),
        gate: !!document.querySelector('.mx_CompleteSecurityBody'),
      }));
      if (unobstructed.appShell && !unobstructed.dialog && !unobstructed.gate) break;
      if (await gotIt.count().catch(() => 0)) {
        await gotIt.click({ timeout: 5_000 }).then(
          () => {
            clicks += 1;
          },
          () => {},
        );
      }
      await pageB.waitForTimeout(3_000);
    }
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C7 "Got it" clicks landed = ${clicks}`);
    // eslint-disable-next-line no-console
    console.log(`[H3-C] C7 B after dismissing terminal = ${JSON.stringify(unobstructed)}`);
    expect(
      unobstructed.appShell && !unobstructed.dialog && !unobstructed.gate,
      `device B is cross-signing verified but never reached an UNOBSTRUCTED app shell after the ` +
        `terminal was dismissed. state=${JSON.stringify(unobstructed)} ` +
        `surface=${JSON.stringify(await describeSurface(pageB))}`,
    ).toBe(true);

    const c8 = await settle(pageB, 'C8 B in the app', { budgetMs: 60_000 });
    assertExit(c8);
    expect(c8.appShell, 'device B fell back out of the app shell').toBe(true);
  } finally {
    await ctxA.close().catch(() => {});
    await ctxB.close().catch(() => {});
  }
});
