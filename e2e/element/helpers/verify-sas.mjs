/**
 * EW-V1 helpers: interactive SAS/emoji device verification ("verify with other
 * device") plus the no-recovery-phrase tripwire.
 *
 * NEW FILE BY DESIGN. The shared helpers in this directory (element.mjs,
 * element-login.mjs, oidc-login.mjs, sessions.mjs, crypto.mjs) are consumed by
 * the other EW-* specs and are deliberately left untouched.
 *
 * UI vocabulary below was read out of the LIVE lab bundle
 * (`/bundles/<hash>/{init,element-web-app}.js`, Element Web 1.12.20) rather
 * than guessed:
 *
 *   Settings -> Sessions list item   `li.mx_FilteredDeviceList_listItem`
 *                                    containing `#device-tile-checkbox-{device_id}`
 *   expand a session                 `.mx_DeviceExpandDetailsButton` ("Show details")
 *   trigger (DeviceVerificationStatusCard)
 *                                    primary button "Verify session", rendered iff
 *                                    `device.isVerified === false && !!onVerifyDevice`
 *   incoming request (toast / EncryptionInfo)
 *                                    primary button "Start Verification"
 *   method chooser (VerificationPanel, dialog layout)
 *                                    `.mx_VerificationPanel_QRPhase_startOption` with
 *                                    "Compare unique emoji" + a primary "Start" button
 *   method chooser (right-panel layout)
 *                                    `.mx_VerificationPanel_verifyByEmojiButton`
 *   SAS comparison                   `.mx_VerificationShowSas` /
 *                                    `.mx_VerificationShowSas_emojiSas` +
 *                                    `.mx_VerificationShowSas_buttonRow`
 *                                    ("They match" / "They don't match")
 *   terminal                         "Got It" (dialog) / "Done" (SetupEncryptionBody)
 */
import { ELEMENT_URL, SIWX_URL } from './element.mjs';
import { injectMockWallet } from '../../browser/wallet-helper.mjs';

/** Labels the SAS driver is allowed to click. Nothing else may ever be clicked. */
export const ALLOWED_CLICKS = [
  'toast/panel: Start Verification',
  'dialog: Compare unique emoji -> Start',
  'panel: Verify by emoji',
  'incoming dialog: Continue',
  'SAS: They match',
  'terminal: Got It',
  'terminal: Done',
];

/** Anything matching this must never be clicked, and never appear as an entry field. */
export const RECOVERY_PATTERN = /recovery key|recovery phrase|security phrase|security key|reset/i;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Element SSO click-login (Element -> siwx wallet UI -> back), stopping at
 * WHATEVER Element shows next.
 *
 * Deliberately NOT `elementWalletClickLogin`: that shared helper drives the
 * Secure Backup wizard to completion, which mints a NEW recovery key. Device B
 * must not do that — it would reset the account's 4S and make "B got verified"
 * meaningless. Here we only observe where B lands.
 *
 * @returns {Promise<{user_id: string, device_id: string, access_token: string|null,
 *                    surface: 'app'|'verify-gate'|'recovery-wizard'|'unknown', text: string}>}
 */
export async function elementWalletLoginNoWizard(page, wallet, { timeout = 180_000 } = {}) {
  const elementOrigin = new URL(ELEMENT_URL).origin;
  await injectMockWallet(page, wallet);

  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  // Post-signature interstitial ("link a passkey?"). Decline if offered.
  try {
    await page.getByRole('button', { name: 'Skip for now' }).click({ timeout: 30_000 });
  } catch {
    /* no interstitial on this pass */
  }
  await page.waitForURL((u) => u.origin === elementOrigin, { timeout: 60_000 });

  // Wait for Element to finish the code exchange and persist the session.
  const deadline = Date.now() + timeout;
  let session = { user_id: null, device_id: null, access_token: null };
  while (Date.now() < deadline) {
    session = await page.evaluate(() => ({
      user_id: localStorage.getItem('mx_user_id'),
      device_id: localStorage.getItem('mx_device_id'),
      access_token: localStorage.getItem('mx_access_token'),
    }));
    if (session.user_id && session.device_id) break;
    await sleep(500);
  }
  if (!session.user_id || !session.device_id) {
    throw new Error('Element session storage missing after login: ' + JSON.stringify(session));
  }

  // Classify the landing surface (app shell / verify gate / recovery wizard).
  let surface = 'unknown';
  let text = '';
  while (Date.now() < deadline) {
    const probe = await page.evaluate(() => {
      const t = (el) => (el ? (el.innerText || '').replace(/\s+/g, ' ').trim() : '');
      const chat = document.querySelector('.mx_MatrixChat');
      const gate = document.querySelector('.mx_CompleteSecurityBody');
      const dlg = document.querySelector('.mx_Dialog');
      return { chat: !!chat, gate: t(gate), dialog: t(dlg) };
    });
    if (probe.chat) {
      surface = 'app';
      break;
    }
    if (/recovery key|secure backup|security phrase/i.test(probe.dialog)) {
      surface = 'recovery-wizard';
      text = probe.dialog;
      break;
    }
    if (probe.gate) {
      surface = 'verify-gate';
      text = probe.gate;
      break;
    }
    await sleep(500);
  }
  return { ...session, surface, text };
}

/**
 * Arm the "no recovery phrase" tripwire on a page.
 *
 * POSITIVE instrumentation, not an absence-of-code claim. It records, in the
 * page:
 *   - every `input` event on an <input>/<textarea>/contenteditable (this is what
 *     fires when a human — or Playwright's fill()/type() — enters a recovery key
 *     or passphrase), with enough context to identify the field, and
 *   - every appearance of a 4S / key-backup ENTRY surface (the
 *     AccessSecretStorage / CreateSecretStorage / RestoreKeyBackup dialogs, or
 *     any dialog that contains a text input alongside recovery-key wording).
 *
 * Deliberately NOT tripped by the mere existence of a "Use recovery key" BUTTON
 * on the verify gate: offering the phrase path is fine, taking it is not.
 *
 * Call AFTER the setup leg (login + first-device Secure Backup wizard) and
 * BEFORE the SAS leg, so the assertion is about the SAS leg alone.
 */
export async function installNoPhraseTripwire(page, label) {
  await page.evaluate((lbl) => {
    if (window.__ewv1) return;
    const rec = { label: lbl, armedAt: Date.now(), typed: [], recoveryUi: [] };
    window.__ewv1 = rec;

    const describe = (el) => {
      const dlg = el.closest ? el.closest('.mx_Dialog, [role="dialog"], .mx_CompleteSecurityBody') : null;
      return {
        tag: (el.tagName || '').toLowerCase(),
        type: el.getAttribute ? el.getAttribute('type') : null,
        id: el.id || null,
        cls: (el.className && el.className.toString().slice(0, 140)) || null,
        placeholder: el.getAttribute ? el.getAttribute('placeholder') : null,
        aria: el.getAttribute ? el.getAttribute('aria-label') : null,
        context: dlg ? (dlg.innerText || '').replace(/\s+/g, ' ').slice(0, 200) : null,
      };
    };

    document.addEventListener(
      'input',
      (e) => {
        const t = e.target;
        if (!t) return;
        const editable = t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable;
        if (!editable) return;
        rec.typed.push({ at: Date.now(), ...describe(t) });
      },
      true,
    );

    const seen = new Set();
    const note = (kind, text) => {
      const key = kind + '::' + text.slice(0, 80);
      if (seen.has(key)) return;
      seen.add(key);
      rec.recoveryUi.push({ at: Date.now(), kind, text: text.slice(0, 240) });
    };
    const scan = () => {
      const hard = document.querySelectorAll(
        '.mx_AccessSecretStorageDialog, .mx_CreateSecretStorageDialog, .mx_RestoreKeyBackupDialog',
      );
      for (const el of hard) note('4s-dialog', (el.innerText || '').replace(/\s+/g, ' '));
      for (const inp of document.querySelectorAll('.mx_Dialog input, [role="dialog"] input')) {
        const dlg = inp.closest('.mx_Dialog, [role="dialog"]');
        const t = dlg ? (dlg.innerText || '').replace(/\s+/g, ' ') : '';
        if (/recovery key|recovery phrase|security phrase|security key/i.test(t)) {
          note('recovery-entry-field', t);
        }
      }
    };
    rec.__timer = setInterval(scan, 400);
    new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
    scan();
  }, label);
}

/** Read back the tripwire record ({label, typed[], recoveryUi[]}). */
export async function readTripwire(page) {
  return page.evaluate(() => {
    const r = window.__ewv1;
    if (!r) return null;
    return { label: r.label, armedAt: r.armedAt, typed: r.typed, recoveryUi: r.recoveryUi };
  });
}

/** Element chrome: user menu -> All settings -> Sessions tab. */
export async function openSessionsTab(page) {
  await page.locator('.mx_UserMenu').click();
  await page.getByRole('menuitem', { name: /all settings/i }).click({ timeout: 20_000 });
  await page
    .locator('[role="tab"], .mx_TabbedView_tabLabel')
    .filter({ hasText: /sessions/i })
    .first()
    .click({ timeout: 20_000 });
}

/**
 * Locate the "Other sessions" list item for a specific device_id.
 * Primary key is the per-device checkbox id Element renders
 * (`device-tile-checkbox-{device_id}`); falls back to expanding tiles until the
 * "Session ID" metadata reveals the id (tiles show display_name when set).
 */
export async function findDeviceListItem(page, deviceId) {
  const byCheckbox = page.locator('li.mx_FilteredDeviceList_listItem', {
    has: page.locator(`[id="device-tile-checkbox-${deviceId}"]`),
  });
  if (await byCheckbox.count()) return byCheckbox.first();

  const items = page.locator('li.mx_FilteredDeviceList_listItem');
  const n = await items.count();
  for (let i = 0; i < n; i++) {
    const item = items.nth(i);
    if ((await item.innerText()).includes(deviceId)) return item;
    const expand = item.locator('.mx_DeviceExpandDetailsButton');
    if (await expand.count()) {
      await expand.first().click().catch(() => {});
      await page.waitForTimeout(300);
      if ((await item.innerText()).includes(deviceId)) return item;
    }
  }
  return null;
}

/** True once this page is showing the SAS emoji comparison. */
export async function emojiVisible(page) {
  return page.locator('.mx_VerificationShowSas_emojiSas').first().isVisible().catch(() => false);
}

/** The SAS emoji strip as normalised text (emoji + labels), for A-vs-B equality. */
export async function readSasEmoji(page) {
  const loc = page.locator('.mx_VerificationShowSas_emojiSas').first();
  const raw = await loc.innerText();
  return raw.replace(/\s+/g, ' ').trim();
}

/**
 * Advance the verification UI by exactly one WHITELISTED click, if one is
 * available on this page right now. Returns the label clicked, or null.
 *
 * The whitelist is closed: no button outside it is ever clicked, so the driver
 * cannot wander into "Use recovery key", "Reset", "Proceed with reset", or the
 * Secure Backup wizard.
 */
export async function advanceVerification(page) {
  const candidates = [
    [
      'toast/panel: Start Verification',
      page.getByRole('button', { name: /^start verification$/i }).first(),
    ],
    [
      'dialog: Compare unique emoji -> Start',
      page
        .locator('.mx_VerificationPanel_QRPhase_startOption')
        .filter({ hasText: /compare unique emoji/i })
        .getByRole('button')
        .first(),
    ],
    ['panel: Verify by emoji', page.locator('.mx_VerificationPanel_verifyByEmojiButton').first()],
    [
      'incoming dialog: Continue',
      page
        .locator('.mx_Dialog')
        .filter({ hasText: /incoming verification request/i })
        .getByRole('button', { name: /^continue$/i })
        .first(),
    ],
  ];

  for (const [label, loc] of candidates) {
    let ok = false;
    try {
      ok = (await loc.count()) > 0 && (await loc.isVisible()) && (await loc.isEnabled());
    } catch {
      ok = false;
    }
    if (!ok) continue;
    try {
      await loc.click({ timeout: 5_000 });
      return label;
    } catch {
      /* raced with a re-render; try again next pass */
    }
  }
  return null;
}

/** Click "They match" in the SAS comparison on this page. */
export async function clickTheyMatch(page) {
  await page
    .locator('.mx_VerificationShowSas')
    .getByRole('button', { name: /^they match$/i })
    .first()
    .click({ timeout: 20_000 });
}

/**
 * Dismiss the post-verification terminal ("Got It" in the dialog, "Done" on the
 * SetupEncryptionBody). Scoped so it can never hit a Secure Backup wizard's own
 * "Done": the container must not carry recovery wording.
 */
export async function finishVerification(page) {
  const clicked = [];
  for (const name of [/^got it$/i, /^done$/i]) {
    const btn = page.getByRole('button', { name }).first();
    let visible = false;
    try {
      visible = (await btn.count()) > 0 && (await btn.isVisible());
    } catch {
      visible = false;
    }
    if (!visible) continue;
    const context = await page
      .evaluate(() => {
        const el = document.querySelector('.mx_Dialog, .mx_CompleteSecurityBody');
        return el ? (el.innerText || '').replace(/\s+/g, ' ') : '';
      })
      .catch(() => '');
    if (/recovery key|security phrase|security key/i.test(context)) continue;
    await btn.click({ timeout: 10_000 }).catch(() => {});
    clicked.push(name.source);
  }
  return clicked;
}

/**
 * Read-only probe of Element's own crypto + setup-encryption state.
 *
 * Element 1.12.20 exposes `window.mxSetupEncryptionStore` and
 * `window.mxMatrixClientPeg`; both are read here, nothing is mutated. This is
 * what distinguishes "SAS worked and the session is usable" from "SAS worked but
 * the new device is wedged", and names the wedge precisely.
 *
 * SetupEncryptionStore phases: 0 Loading, 1 Intro, 2 Busy, 3 Done,
 * 4 ConfirmSkip, 5 Finished.
 */
export async function cryptoProbe(page) {
  return page.evaluate(async () => {
    const out = {};
    const st = window.mxSetupEncryptionStore;
    if (st) {
      out.setupEncryption = {
        phase: st.phase,
        activeRequest: !!st.verificationRequest,
        keyInfo: !!st.keyInfo,
        hasDevicesToVerifyAgainst: st.hasDevicesToVerifyAgainst,
      };
    }
    const peg = window.mxMatrixClientPeg;
    const cli = peg && typeof peg.get === 'function' ? peg.get() : null;
    if (!cli) return { ...out, client: false };
    out.client = true;
    out.deviceId = cli.getDeviceId ? cli.getDeviceId() : null;
    const crypto = cli.getCrypto ? cli.getCrypto() : null;
    if (!crypto) return out;
    const attempt = async (name, fn) => {
      try {
        out[name] = await fn();
      } catch (e) {
        out[name] = 'ERR: ' + String(e).slice(0, 120);
      }
    };
    await attempt('crossSigningKeyId', () => crypto.getCrossSigningKeyId());
    await attempt('crossSigningStatus', () => crypto.getCrossSigningStatus());
    await attempt('crossSigningReady', () => crypto.isCrossSigningReady());
    await attempt('secretStorageReady', () => crypto.isSecretStorageReady());
    await attempt('ownDeviceStatus', async () => {
      const s = await crypto.getDeviceVerificationStatus(cli.getUserId(), cli.getDeviceId());
      return s ? { crossSigningVerified: s.crossSigningVerified, signedByOwner: s.signedByOwner } : null;
    });
    await attempt('userVerified', async () => {
      const v = await crypto.getUserVerificationStatus(cli.getUserId());
      return v ? v.isCrossSigningVerified() : null;
    });
    await attempt('server4S', async () =>
      !!(await cli.getAccountDataFromServer('m.secret_storage.default_key')),
    );
    return out;
  });
}

/** Compact description of what a page is showing — for failure diagnosis. */
export async function describeSurface(page) {
  return page.evaluate(() => {
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const txt = (el) => (el.innerText || '').replace(/\s+/g, ' ').trim();
    const panels = [
      ...document.querySelectorAll(
        '.mx_Dialog, .mx_CompleteSecurityBody, .mx_Toast_toast, .mx_VerificationPanel',
      ),
    ]
      .filter(visible)
      .map((el) => txt(el).slice(0, 400));
    const buttons = [...document.querySelectorAll('button')]
      .filter(visible)
      .map((b) => txt(b) || b.getAttribute('aria-label') || '')
      .filter(Boolean)
      .slice(0, 40);
    return {
      url: location.href,
      appShell: !!document.querySelector('.mx_MatrixChat'),
      sas: !!document.querySelector('.mx_VerificationShowSas_emojiSas'),
      panels,
      buttons,
    };
  });
}

/**
 * Ground truth for "device X is cross-signed": the self-signing key's signature
 * over that device's keys, straight out of `POST /keys/query`.
 *
 * @returns {{ssk: string|null, signature: string|undefined, deviceSignatures: object}}
 */
export function crossSigningStatus(keysQueryBody, userId, deviceId) {
  const sskKeys = keysQueryBody?.self_signing_keys?.[userId]?.keys || {};
  const ssk = Object.values(sskKeys)[0] || null;
  const deviceSignatures = keysQueryBody?.device_keys?.[userId]?.[deviceId]?.signatures?.[userId] || {};
  return {
    ssk,
    signature: ssk ? deviceSignatures[`ed25519:${ssk}`] : undefined,
    deviceSignatures,
  };
}
