/**
 * PH — coverage for the two verify-UX honesty patches
 * (patches/element-web/honest-qr-disabled-reason.patch and
 *  offer-verify-current-session.patch in siwx-oidc-matrix-server; registry:
 *  patches/element-web/README.md).
 *
 * HONESTY NOTE (read before trusting a green run): PH-1 and PH-2 FORCE the
 * crypto-state precondition by monkey-patching the live client's crypto API
 * in-page (isCrossSigningReady -> false / getDeviceVerificationStatus -> null)
 * before the component mounts. Reason: an organically not-ready session sits at
 * the force_verification gate and cannot reach Settings -> Sessions in this lab,
 * while the states these patches fix arise in the field (reload crypto-loss,
 * degraded crypto) with no deterministic producer here. So these legs prove the
 * PATCHED RENDER PATH — the exact branch each patch adds — under its input
 * condition; they do NOT prove the organic reachability of that condition.
 *
 * WHAT WOULD TURN EACH LEG RED:
 *
 *   PH-0 red if either new i18n key is missing from the SERVED bundle's English
 *        strings — that means the patch is not in the build at all, and it
 *        separates "patch missing" from "behavior broken" for PH-1/PH-2.
 *
 *   PH-1 red if, with isCrossSigningReady forced false, the "Link new device"
 *        section still renders the lie ("Not supported by your account
 *        provider"); red if the honest replacement string is absent; red if no
 *        enabled "Verify session" control renders next to it. On an UNPATCHED
 *        build this leg fails on the first assertion — verified discriminating.
 *
 *   PH-2 red if, with the current device's verification status forced null, the
 *        session manager renders the false "doesn't support encryption" copy;
 *        red if the current-session card offers no verify control (the
 *        non-destructive exit the patch restores).
 *
 * SHARED LAB: fresh wallet per test, nothing restarted, no state mutated outside
 * the test's own account.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import { settle, assertExit } from './helpers/journey.mjs';
import { openSessionsTab } from './helpers/verify-sas.mjs';

const SERVER_NAME = 'localhost';

const HONEST_QR_SNIPPET = /isn.t verified yet, so it can.t set up another device/i;
const LIE_QR = /not supported by your account provider/i;
const FALSE_ENCRYPTION_COPY = /do(es)?n.t support encryption/i;
const BLOCKED_OTHER_SESSION = /verify your current session first/i;

test.beforeAll(async () => {
  await requireElementStack();
});

// ---------------------------------------------------------------------------
// PH-0 — both patch strings are present in the served English strings.
// ---------------------------------------------------------------------------
test('PH-0: served i18n carries both honesty-patch keys', async ({ request }) => {
  const langs = await (await request.get(`${ELEMENT_URL}/i18n/languages.json`)).json();
  const en = langs.en;
  const fileName = typeof en === 'string' ? en : en?.fileName;
  expect(fileName, `languages.json shape: ${JSON.stringify(langs).slice(0, 200)}`).toBeTruthy();
  const strings = await (await request.get(`${ELEMENT_URL}/i18n/${fileName}`)).json();
  const sessions = strings?.settings?.sessions ?? {};
  // eslint-disable-next-line no-console
  console.log(
    `[PH-0] i18n file=${fileName} qr_unverified=${!!sessions.sign_in_with_qr_unverified_session} verify_blocked=${!!sessions.verify_blocked_current_session_unverified}`,
  );
  expect(sessions.sign_in_with_qr_unverified_session, 'honest-qr key missing from build').toMatch(
    HONEST_QR_SNIPPET,
  );
  expect(
    sessions.verify_blocked_current_session_unverified,
    'offer-verify key missing from build',
  ).toMatch(BLOCKED_OTHER_SESSION);
});

// ---------------------------------------------------------------------------
// Shared probes
// ---------------------------------------------------------------------------

/** Force the third conjunct of shouldShowQrForLinkNewDevice to false. */
async function forceCrossSigningNotReady(page) {
  await page.evaluate(() => {
    const crypto = window.mxMatrixClientPeg.get().getCrypto();
    crypto.isCrossSigningReady = async () => false;
  });
}

/** Force the current device's verification status to null (unknown). */
async function forceOwnVerificationNull(page) {
  await page.evaluate(() => {
    const cli = window.mxMatrixClientPeg.get();
    const crypto = cli.getCrypto();
    const ownUser = cli.getUserId();
    const ownDevice = cli.getDeviceId();
    const orig = crypto.getDeviceVerificationStatus.bind(crypto);
    crypto.getDeviceVerificationStatus = async (userId, deviceId) =>
      userId === ownUser && deviceId === ownDevice ? null : orig(userId, deviceId);
  });
}

/** Read the Link-new-device subsection as the user sees it. */
async function readQrSection(page) {
  return page.evaluate(() => {
    const vis = (el) => {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const sect = document.querySelector('.mx_LoginWithQRSection');
    if (!sect) return { present: false };
    const text = (sect.innerText || '').replace(/\s+/g, ' ').trim();
    const buttons = [...sect.querySelectorAll('button, [role="button"], .mx_AccessibleButton')]
      .filter(vis)
      .map((b) => ({
        label: (b.innerText || '').replace(/\s+/g, ' ').trim(),
        disabled: b.hasAttribute('disabled') || b.getAttribute('aria-disabled') === 'true',
      }));
    return { present: true, text, buttons };
  });
}

/** Read everything the settings dialog says, plus its visible buttons. */
async function readSettingsSurface(page) {
  return page.evaluate(() => {
    const vis = (el) => {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const root = document.querySelector('.mx_Dialog') || document.body;
    const text = (root.innerText || '').replace(/\s+/g, ' ').trim();
    const buttons = [...root.querySelectorAll('button, [role="button"], .mx_AccessibleButton')]
      .filter(vis)
      .map((b) => (b.innerText || '').replace(/\s+/g, ' ').trim())
      .filter(Boolean);
    return { text, buttons };
  });
}

// ---------------------------------------------------------------------------
// PH-1 — honest disabled-reason + verify affordance instead of the provider lie.
// ---------------------------------------------------------------------------
test('PH-1: not-ready session sees the honest QR reason and a Verify session action', async ({
  page,
}) => {
  test.setTimeout(600_000);

  const w = makeWallet(undefined, SERVER_NAME);
  const A = await elementWalletClickLogin(page, w);
  // eslint-disable-next-line no-console
  console.log(`[PH-1] logged in user=${A.user_id} device=${A.device_id} wizard=${A.wizard}`);
  assertExit(await settle(page, 'PH-1 after login', { budgetMs: 60_000 }));

  // Patch the input condition BEFORE the tab mounts, so SessionManagerTab's
  // isCrossSigningReady memo computes false on first render.
  await forceCrossSigningNotReady(page);
  await openSessionsTab(page);

  // The section re-probes asynchronously; poll until it settles into a branch.
  let qr = null;
  for (let i = 0; i < 30; i++) {
    qr = await readQrSection(page);
    if (qr.present && (LIE_QR.test(qr.text) || HONEST_QR_SNIPPET.test(qr.text))) break;
    await page.waitForTimeout(1000);
  }
  // eslint-disable-next-line no-console
  console.log(`[PH-1] section=${JSON.stringify(qr)}`);

  expect(qr.present, 'Link new device section absent after real navigation').toBe(true);
  expect(LIE_QR.test(qr.text), `the provider-blame lie still renders: "${qr.text}"`).toBe(false);
  expect(HONEST_QR_SNIPPET.test(qr.text), `honest reason absent: "${qr.text}"`).toBe(true);

  const verifyBtn = qr.buttons.find((b) => /verify session/i.test(b.label));
  expect(verifyBtn, `no "Verify session" control in section; buttons=${JSON.stringify(qr.buttons)}`).toBeTruthy();
  expect(verifyBtn.disabled, '"Verify session" control is disabled').toBe(false);
});

// ---------------------------------------------------------------------------
// PH-2 — current session with unknown verification status keeps a verify exit.
// ---------------------------------------------------------------------------
test('PH-2: current session with null verification status gets a verify exit, not the encryption lie', async ({
  page,
}) => {
  test.setTimeout(600_000);

  const w = makeWallet(undefined, SERVER_NAME);
  const A = await elementWalletClickLogin(page, w);
  // eslint-disable-next-line no-console
  console.log(`[PH-2] logged in user=${A.user_id} device=${A.device_id} wizard=${A.wizard}`);
  assertExit(await settle(page, 'PH-2 after login', { budgetMs: 60_000 }));

  await forceOwnVerificationNull(page);
  await openSessionsTab(page);

  // Give useOwnDevices time to compute with the patched crypto, then read the
  // whole settings surface: the false copy must appear NOWHERE, and the current
  // session area must offer a verify control.
  let surface = null;
  let verifyOffered = false;
  for (let i = 0; i < 30; i++) {
    surface = await readSettingsSurface(page);
    verifyOffered = surface.buttons.some((b) => /verify session|verify this session/i.test(b));
    if (verifyOffered || FALSE_ENCRYPTION_COPY.test(surface.text)) break;
    await page.waitForTimeout(1000);
  }
  // eslint-disable-next-line no-console
  console.log(
    `[PH-2] verifyOffered=${verifyOffered} falseCopy=${FALSE_ENCRYPTION_COPY.test(surface.text)} buttons=${JSON.stringify(surface.buttons.slice(0, 15))}`,
  );

  expect(
    FALSE_ENCRYPTION_COPY.test(surface.text),
    'the false "doesn\'t support encryption" copy renders for a live Element session',
  ).toBe(false);
  expect(verifyOffered, 'no verify control offered — the non-destructive exit is missing').toBe(
    true,
  );
});
