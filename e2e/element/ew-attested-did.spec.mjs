/**
 * EW-DID1, EW-DID2, EW-MX25: the attested DID in Element Web, and the layout of
 * the MXID row above it.
 *
 * EW-DID1 and EW-DID2 are the leg of siwx-oidc-matrix-server
 * patches/element-web entry 7 (`show-attested-did.patch`, tag @ew-p7). A fresh
 * wallet signs in through Element; siwx-oidc publishes the attested binding
 * `{did, proof}` into the account's MSC4133 profile field `io.inblock.did` at
 * that first sign-in. Element must then show it:
 *
 *   EW-DID1 (user-info panel, the right panel a member tile opens): a DID row
 *       directly under the MXID row, label "DID" (the signed label: the lab's
 *       provider signs the binding), the DID abbreviated from the front, so it
 *       starts with the wallet's `did:pkh:eip155:1:0` prefix and ends with the
 *       last characters of the wallet address, and its copy button puts the
 *       FULL DID on the clipboard.
 *   EW-DID2 (Settings -> Account): a "DID" row under "Username" showing the full
 *       DID, case kept, whose copy button copies it.
 *
 * Both first wait (up to 30 s) until the homeserver serves the binding, read
 * from this process with the account's own token, and require it to be exactly
 * the wallet's DID with a non-empty proof: without it the row has nothing to
 * show and the leg would prove nothing about Element.
 *
 * EW-MX25 is the leg of siwx-oidc-matrix-server#25 (tag
 * @ew-delta-theme-overrides: `config/element-theme-overrides.css`, a runtime
 * delta of `dockerfiles/Dockerfile.element`, not a patch). In the user-info
 * panel the MXID's copy button must sit right after the MXID, and the MXID with
 * its button must be centred like the display name above it:
 *
 *   gap     the copy button's left edge minus the right edge of the MXID text's
 *           LAST line box (measured with a Range over the text, so a wrapped
 *           MXID is judged by the line the button follows), in CSS px:
 *           -1 <= gap <= 8. Element's own button margin is 4 px
 *           (--cpd-space-1x); 8 allows twice that, and -1 sub-pixel overlap.
 *           The button must also sit on that last line (vertical overlap).
 *   centre  the pair runs from the MXID text's leftmost line box to the
 *           button's right edge; its centre must be within 4 px of the centre
 *           of `.mx_UserInfo_profile`'s content box (the column the display
 *           name is centred in).
 *
 * The served CSS of 2026-10 fails `gap`: `.mx_CopyableText { width: 100% }`
 * plus Element's `justify-content: space-between` pins the button to the far
 * right of the panel (the issue's screenshot). That failure is this leg's
 * negative control.
 *
 * EW_THEME_OVERRIDES_CSS=<path> serves that file for every request to
 * `element-theme-overrides.css` (a browser-context route), so a CSS fix can be
 * judged before an image carries it; the leg then also checks that the sheet
 * the page applied is exactly that file (rule for rule), or the run would judge
 * the served CSS while claiming to judge the file. run.sh mounts the file.
 *
 * EW_DID_NEGATIVE=hide-field is the negative control of EW-DID1/EW-DID2: the
 * browser's reads of the `io.inblock.did` profile field are answered 404
 * M_NOT_FOUND (what a homeserver without the binding answers), so Element has no
 * DID to show and both legs must fail on the missing row. The binding check
 * above reads from this process, not through the browser, so it still passes.
 *
 * TARGET: ELEMENT_URL / MATRIX_URL / SIWX_URL (defaults: the local lab). Creates
 * one throwaway did:pkh account per worker (a fresh random wallet), logged as
 * "[DID] account <mxid>", and one private room named "ew-attested-did". Nothing
 * else is touched; on a shared deployment, deactivate the logged MXIDs.
 */
import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { requireElementStack, MATRIX_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

const DID_FIELD = 'io.inblock.did';
const SENTINEL = 'ew-attested-did clipboard sentinel';
const CSS_OVERRIDE = process.env.EW_THEME_OVERRIDES_CSS || '';
const DID_NEGATIVE = process.env.EW_DID_NEGATIVE || '';

/** #25 tolerances, CSS px (see the header). */
const GAP_MIN = -1;
const GAP_MAX = 8;
const CENTRE_MAX = 4;

let context;
let page;
let wallet;
let session;
let roomId;
let overrideCss = null;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(240_000);
  await requireElementStack();
  if (DID_NEGATIVE && DID_NEGATIVE !== 'hide-field') {
    throw new Error(`EW_DID_NEGATIVE=${DID_NEGATIVE}: the only negative control is hide-field`);
  }
  context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  if (CSS_OVERRIDE) {
    overrideCss = readFileSync(CSS_OVERRIDE, 'utf8');
    await context.route('**/element-theme-overrides.css', (route) =>
      route.fulfill({ status: 200, contentType: 'text/css; charset=utf-8', body: overrideCss }),
    );
  }
  if (DID_NEGATIVE === 'hide-field') {
    await context.route(
      (url) => url.pathname.includes('/profile/') && decodeURIComponent(url.pathname).endsWith(`/${DID_FIELD}`),
      (route) =>
        route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ errcode: 'M_NOT_FOUND', error: 'hidden by EW_DID_NEGATIVE' }),
        }),
    );
  }
  page = await context.newPage();
  wallet = makeWallet();
  session = await elementWalletClickLogin(page, wallet);
  // eslint-disable-next-line no-console
  console.log(`[DID] account ${session.user_id}`);

  roomId = await page.evaluate(
    async () =>
      (await window.mxMatrixClientPeg.get().createRoom({ name: 'ew-attested-did', preset: 'private_chat' })).room_id,
  );
});

test.afterAll(async () => {
  await context?.close();
});

/**
 * The binding the homeserver serves for this account, read from this process (not
 * through the browser, so EW_DID_NEGATIVE does not touch it): `{did, proof}` or null.
 */
async function servedBinding() {
  const user = encodeURIComponent(session.user_id);
  for (const prefix of ['/_matrix/client/v3', '/_matrix/client/unstable/uk.tcpip.msc4133']) {
    const r = await fetch(`${MATRIX_URL}${prefix}/profile/${user}/${DID_FIELD}`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    }).catch(() => null);
    if (r?.ok) {
      const body = await r.json().catch(() => ({}));
      return body[DID_FIELD] ?? null;
    }
  }
  return null;
}

/** Wait until siwx-oidc's first-sign-in binding is served; it must be this wallet's DID, signed. */
async function expectPublishedBinding() {
  let binding = null;
  await expect
    .poll(
      async () => {
        binding = await servedBinding();
        return binding?.did ?? null;
      },
      { timeout: 30_000, message: `the provider never published ${DID_FIELD} for a fresh wallet sign-in` },
    )
    .toBe(wallet.did);
  expect(typeof binding.proof === 'string' && binding.proof.length > 0, 'the binding carries no proof').toBe(true);
  return binding.did;
}

/** Open (or reuse) the right panel's user info for the signed-in account, through the member list. */
async function openOwnUserInfo() {
  const profile = page.locator('.mx_UserInfo_profile').first();
  if (await profile.isVisible().catch(() => false)) return profile;
  await page.keyboard.press('Escape').catch(() => {});
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, roomId);
  await page.locator('.mx_MessageComposer').waitFor({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Dismiss' }).click({ timeout: 3_000 }).catch(() => {});
  const panel = page.locator('.mx_RightPanel');
  if (!(await panel.locator('.mx_MemberListView').isVisible().catch(() => false))) {
    if (!(await panel.isVisible().catch(() => false))) {
      await page.getByRole('button', { name: 'Room info' }).last().click();
    }
    await panel.getByText(/^People/).first().click({ timeout: 15_000 });
  }
  const displayName = await page.evaluate(() => {
    const cli = window.mxMatrixClientPeg.get();
    return cli.getUser(cli.getUserId())?.displayName || cli.getUserId();
  });
  await panel.locator('.mx_MemberTileView').filter({ hasText: displayName }).first().click({ timeout: 15_000 });
  await expect(profile.locator('.mx_UserInfo_profile_mxid')).toBeVisible({ timeout: 20_000 });
  return profile;
}

/** Click a copy button with a sentinel on the clipboard first; return what it copied. */
async function copyVia(button) {
  await page.evaluate((s) => navigator.clipboard.writeText(s), SENTINEL);
  await button.click();
  let copied = SENTINEL;
  await expect
    .poll(async () => (copied = await page.evaluate(() => navigator.clipboard.readText())), {
      timeout: 10_000,
      message: 'the copy button left the clipboard unchanged',
    })
    .not.toBe(SENTINEL);
  return copied;
}

test(
  'EW-DID1: user-info panel shows the attested DID under the MXID; copy copies the full DID',
  { tag: '@ew-p7' },
  async () => {
    const did = await expectPublishedBinding();
    const profile = await openOwnUserInfo();
    const row = profile.locator('.mx_UserInfo_profile_did');
    await expect(row, 'no DID row in the user-info panel').toBeVisible({ timeout: 20_000 });
    const follows = await profile.evaluate(
      (el) => el.querySelector('.mx_UserInfo_profile_mxid')?.nextElementSibling?.classList.contains('mx_UserInfo_profile_did') ?? false,
    );
    expect(follows, 'the DID row must sit directly under the MXID row').toBe(true);
    await expect(row.locator('.mx_UserInfo_profile_did_label')).toHaveText('DID');
    const shown = await row.evaluate((el) => {
      const label = el.querySelector('.mx_UserInfo_profile_did_label')?.textContent ?? '';
      const text = el.querySelector('.mx_CopyableText > span')?.textContent ?? '';
      return text.startsWith(label) ? text.slice(label.length) : text;
    });
    // eslint-disable-next-line no-console
    console.log(`[DID1] shown "${shown}"`);
    expect(shown, 'the panel must show the DID from its did:pkh prefix').toMatch(/^did:pkh:eip155:1:0/);
    expect(shown.endsWith(did.slice(-6)), `"${shown}" must end with the wallet address's last characters`).toBe(true);
    const copied = await copyVia(row.locator('.mx_CopyableText_copyButton'));
    expect(copied, 'the copy button must copy the FULL DID').toBe(did);
  },
);

test(
  'EW-DID2: Settings > Account shows the attested DID in full; copy copies it',
  { tag: '@ew-p7' },
  async () => {
    const did = await expectPublishedBinding();
    await page.keyboard.press('Escape').catch(() => {});
    await page.locator('.mx_UserMenu').click();
    await page.getByRole('menuitem', { name: /all settings/i }).click({ timeout: 20_000 });
    try {
      const account = page.locator('.mx_UserProfileSettings');
      await expect(account, 'Settings did not open on the Account tab').toBeVisible({ timeout: 20_000 });
      const row = account.locator('.mx_UserProfileSettings_profile_controls_did');
      await expect(row, 'no DID row in Settings > Account').toBeVisible({ timeout: 20_000 });
      await expect(row.locator('.mx_UserProfileSettings_profile_controls_userId_label')).toHaveText('DID');
      const shown = await row.locator('.mx_CopyableText').evaluate((el) =>
        [...el.childNodes]
          .filter((n) => !(n.nodeType === 1 && n.matches('button, .mx_CopyableText_copyButton')))
          .map((n) => n.textContent)
          .join('')
          .trim(),
      );
      expect(shown, 'Settings must show the DID in full, case kept').toBe(did);
      const copied = await copyVia(row.locator('.mx_CopyableText_copyButton'));
      expect(copied, 'the copy button must copy the full DID').toBe(did);
    } finally {
      await page.keyboard.press('Escape').catch(() => {});
    }
  },
);

test(
  'EW-MX25: user-info panel: the MXID copy button follows the MXID and the pair is centred (#25)',
  { tag: '@ew-delta-theme-overrides' },
  async () => {
    if (overrideCss !== null) {
      // The page must have applied exactly the file under test, rule for rule.
      const applied = await page.evaluate((css) => {
        const sheet = [...document.styleSheets].find((s) => (s.href || '').endsWith('element-theme-overrides.css'));
        if (!sheet) return { found: false };
        const want = new CSSStyleSheet();
        want.replaceSync(css);
        const a = [...sheet.cssRules].map((r) => r.cssText);
        const b = [...want.cssRules].map((r) => r.cssText);
        return { found: true, same: a.length === b.length && a.every((t, i) => t === b[i]), applied: a.length, file: b.length };
      }, overrideCss);
      expect(applied, `EW_THEME_OVERRIDES_CSS=${CSS_OVERRIDE} is not the sheet the page applied`).toMatchObject({
        found: true,
        same: true,
      });
    }
    const profile = await openOwnUserInfo();
    const m = await profile.evaluate((root) => {
      const ct = root.querySelector('.mx_UserInfo_profile_mxid .mx_CopyableText');
      const btn = ct?.querySelector('.mx_CopyableText_copyButton');
      if (!ct || !btn) return { error: 'no MXID CopyableText or copy button' };
      // Every text node of the MXID, none inside the button.
      const range = document.createRange();
      const walker = document.createTreeWalker(ct, NodeFilter.SHOW_TEXT, {
        acceptNode: (n) => (btn.contains(n) || !n.textContent.trim() ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
      });
      const nodes = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push(n);
      if (!nodes.length) return { error: 'the MXID has no text' };
      range.setStart(nodes[0], 0);
      range.setEnd(nodes.at(-1), nodes.at(-1).textContent.length);
      const rects = [...range.getClientRects()].filter((r) => r.width > 0 && r.height > 0);
      const lastTop = Math.max(...rects.map((r) => r.top));
      const last = rects.filter((r) => Math.abs(r.top - lastTop) < 2);
      const lastLine = {
        left: Math.min(...last.map((r) => r.left)),
        right: Math.max(...last.map((r) => r.right)),
        top: Math.min(...last.map((r) => r.top)),
        bottom: Math.max(...last.map((r) => r.bottom)),
      };
      const textLeft = Math.min(...rects.map((r) => r.left));
      const b = btn.getBoundingClientRect();
      const box = root.getBoundingClientRect();
      const cs = getComputedStyle(root);
      const cLeft = box.left + parseFloat(cs.paddingLeft);
      const cRight = box.right - parseFloat(cs.paddingRight);
      const r1 = (x) => Math.round(x * 10) / 10;
      return {
        mxid: nodes.map((n) => n.textContent).join(''),
        lines: new Set(rects.map((r) => Math.round(r.top))).size,
        gap: r1(b.left - lastLine.right),
        buttonOnLastLine: b.top < lastLine.bottom && b.bottom > lastLine.top,
        pair: { left: r1(textLeft), right: r1(b.right) },
        container: { left: r1(cLeft), right: r1(cRight) },
        centreOffset: r1((textLeft + b.right) / 2 - (cLeft + cRight) / 2),
      };
    });
    test.info().annotations.push({ type: 'mx25', description: JSON.stringify(m) });
    // eslint-disable-next-line no-console
    console.log(`[MX25] ${CSS_OVERRIDE ? `css=${CSS_OVERRIDE} ` : ''}${JSON.stringify(m)}`);
    expect(m.error, m.error).toBeUndefined();
    expect
      .soft(m.gap, `gap between the MXID's last line and its copy button: ${m.gap} px, allowed ${GAP_MIN}..${GAP_MAX}`)
      .toBeGreaterThanOrEqual(GAP_MIN);
    expect
      .soft(m.gap, `gap between the MXID's last line and its copy button: ${m.gap} px, allowed ${GAP_MIN}..${GAP_MAX}`)
      .toBeLessThanOrEqual(GAP_MAX);
    expect.soft(m.buttonOnLastLine, 'the copy button must sit on the MXID\'s last line').toBe(true);
    expect
      .soft(Math.abs(m.centreOffset), `MXID + copy button centre is ${m.centreOffset} px off the panel's centre, allowed ${CENTRE_MAX}`)
      .toBeLessThanOrEqual(CENTRE_MAX);
  },
);
