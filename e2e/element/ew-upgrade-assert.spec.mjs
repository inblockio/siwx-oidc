/**
 * T2 assert (EW-UA1..UA10, EW-UZ): Element Web upgrade continuity, the stage that runs after
 * ONLY the siwx-oidc image was switched from the baseline to the candidate (Redis, Synapse
 * and Element Web kept). It reopens user A's browser profile written by
 * ew-upgrade-capture.spec.mjs and checks, as a user would notice it:
 *
 *   EW-UA1   Element opens signed in: no login screen, no trip to the provider's sign-in;
 *   EW-UA2   the same account and the same device id, and the candidate itself (/userinfo,
 *            not Synapse's two-minute introspection cache) accepts the token Element holds;
 *   EW-UA3   no "verify this session" prompt, and the crypto identity (cross-signing, 4S,
 *            key backup, this device verified) is what it was on the baseline;
 *   EW-UA4   the room history from before the switch decrypts (A's own message and B's);
 *   EW-UA5   a new message sends from the composer, encrypted on the wire;
 *   EW-UA6   Spotlight still resolves a DID to its MXID;
 *   EW-UA7   the passkey registered on the baseline signs in to the same account (the
 *            credential is re-imported into a new virtual authenticator), and the picker is
 *            scoped by the hint cookie the baseline set;
 *   EW-UA8   the Sessions manager signs out the second device created on the baseline
 *            (Manage this session -> the provider's account page -> Sign out this session),
 *            and that device's refresh token, issued by the baseline, is refused afterwards;
 *   EW-UA9   a second tab on the same profile takes the session over and hands it back,
 *            and nothing signs the session out;
 *   EW-UA10  Element refreshed its token against the candidate (seen in the network log;
 *            the first refresh presents the baseline's refresh token, so the answer must be a
 *            new-format token); it waits up to T2_REFRESH_WAIT_S (default 420 s) for one;
 *   EW-UZ    cleanup: the throwaway accounts A, B and the passkey account are deactivated.
 *
 * Every check is its own test, so a failing one does not hide the others (a negative
 * control reports exactly which checks broke). Playwright restarts the worker after a
 * failure, so beforeAll is safe to run again: it only relaunches the persistent profile.
 * The order matters in one place: EW-UA7 (passkey) runs before EW-UA8, whose account-page
 * re-auth replaces the picker hint cookie with A's.
 *
 * Needs ELEMENT_URL, MATRIX_URL, SIWX_URL and the QUALIFY_STATE_DIR the capture wrote (no
 * older than T2_MAX_STATE_AGE_S, default 3600 s).
 */
import { test, expect } from '@playwright/test';
import { injectMockWallet, makeWallet } from '../browser/wallet-helper.mjs';
import { addVirtualAuthenticator } from '../browser/webauthn-helper.mjs';
import { loginPasskeyToTokens, importPasskeys } from './helpers/passkey-login.mjs';
import { openSessionsTab, findDeviceListItem } from './helpers/verify-sas.mjs';
import {
  T2,
  serverName,
  passkeyPath,
  statePath,
  readJson,
  loadCapturedState,
  launchProfile,
  openElementApp,
  closeTab,
  elementSession,
  cryptoStatus,
  verificationPrompts,
  decryptRecorded,
  sendThroughComposer,
  wireType,
  spotlightFindsDid,
  deactivateWalletAccount,
  deactivatePasskeyAccount,
  refreshOutcome,
  providerAcceptsElementToken,
} from './helpers/upgrade.mjs';

let state;
let profile;
let page;
let launchedAt;
const refreshes = []; // { status, new_format, at_ms } of every refresh-grant call at /token
const signOuts = []; // every call that would end a session: logout, logout/all, revoke

test.beforeAll(async () => {
  test.setTimeout(180_000);
  // T2_CLEANUP_ONLY=1 (the driver after a failed capture, with --grep EW-UZ): whatever the
  // capture got to write, with no window and no completeness check.
  state = process.env.T2_CLEANUP_ONLY === '1' ? await readJson(statePath()) : await loadCapturedState();
  for (const k of ['element', 'matrix', 'siwx']) {
    const now = { element: T2.elementUrl, matrix: T2.matrixUrl, siwx: T2.siwxUrl }[k];
    if (state.targets[k] !== now) throw new Error(`the capture ran against another ${k} target`);
  }
  profile = await launchProfile();
  launchedAt = Date.now();
  const tokenUrl = `${T2.siwxUrl}/token`;
  profile.on('response', async (r) => {
    const req = r.request();
    const url = r.url().replace(/\?.*$/, '');
    if (req.method() === 'POST' && /\/logout(\/all)?$|\/oauth2\/revoke$/.test(url)) signOuts.push(url);
    if (req.method() !== 'POST' || url !== tokenUrl) return;
    if (!/grant_type=refresh_token/.test(req.postData() || '')) return;
    let newFormat = false;
    try {
      newFormat = /^mcr_/.test((await r.json()).refresh_token || '');
    } catch {
      /* not JSON: an error answer */
    }
    refreshes.push({ status: r.status(), new_format: newFormat, at_ms: Date.now() });
  });
  page = profile.pages()[0] || (await profile.newPage());
});

test.afterAll(async () => {
  for (const p of profile?.pages() || []) await closeTab(p);
  await profile?.close().catch(() => {});
});

/** Element in A's tab, opened once per worker; later tests reuse it. */
async function app() {
  const ok = await page
    .evaluate(() => !!window.mxMatrixClientPeg?.get?.()?.isInitialSyncComplete?.())
    .catch(() => false);
  if (ok) return { landed: 'app', reused: true };
  const r = await openElementApp(page);
  expect(r.landed, `Element did not open signed in: ${JSON.stringify(r)}`).toBe('app');
  return r;
}

async function openRoom() {
  await app();
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, state.room_id);
  await page.locator('.mx_MessageComposer').first().waitFor({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Dismiss' }).click({ timeout: 3_000 }).catch(() => {});
}

test('EW-UA1: candidate: Element opens signed in, no login screen', async () => {
  const r = await openElementApp(page);
  test.info().annotations.push({ type: 'open', description: JSON.stringify(r) });
  expect(r.landed, 'Element showed a login screen after the switch').toBe('app');
  expect(r.siwx_navigation, 'Element sent the user to the provider to sign in again').toBe(0);
});

test('EW-UA2: candidate: the same account and the same device id', async () => {
  await app();
  const s = await elementSession(page);
  expect(s.user_id).toBe(state.accounts.a.user_id);
  expect(s.device_id, 'Element holds another device id than before the switch').toBe(state.accounts.a.device_id);
  expect(s.client_device_id).toBe(state.accounts.a.device_id);
  // And the homeserver agrees, through the edge and the candidate's introspection.
  const who = await page.evaluate(() => window.mxMatrixClientPeg.get().whoami());
  expect(who.user_id).toBe(state.accounts.a.user_id);
  expect(who.device_id).toBe(state.accounts.a.device_id);
  // The candidate itself accepts the token Element holds (the baseline's, unless Element
  // refreshed already): Synapse's two-minute introspection cache cannot answer for it.
  const ui = await providerAcceptsElementToken(page, T2.siwxUrl);
  expect(ui.status, "the candidate refuses the access token Element holds").toBe(200);
  expect(ui.sub).toBe(state.accounts.a.did);
});

test('EW-UA3: candidate: no "verify this session" prompt, crypto identity unchanged', async () => {
  await app();
  // Element raises its verification toasts shortly after the first sync; give them time.
  await page.waitForTimeout(10_000);
  expect(await verificationPrompts(page), 'Element asks to verify this session or for the recovery key').toEqual([]);
  expect(await cryptoStatus(page)).toEqual(state.accounts.a.crypto);
});

test('EW-UA4: candidate: the history from before the switch decrypts', async () => {
  await openRoom();
  const ids = state.messages.map((m) => m.id);
  let got = [];
  await expect
    .poll(
      async () => {
        got = await decryptRecorded(page, state.room_id, ids);
        return got.map((g) => g.body);
      },
      { timeout: 60_000, message: 'a message from before the switch does not decrypt' },
    )
    .toEqual(state.messages.map((m) => m.body));
  for (const m of state.messages) {
    await expect(page.locator(`[data-event-id="${m.id}"]`).first(), 'the timeline does not show it').toContainText(
      m.body,
      { timeout: 30_000 },
    );
  }
});

test('EW-UA5: candidate: a new message sends from the composer, encrypted', async () => {
  await openRoom();
  const body = `t2 from A after the switch ${Date.now()}`;
  const id = await sendThroughComposer(page, state.room_id, body);
  expect(await wireType(page, state.room_id, id)).toBe('m.room.encrypted');
});

test('EW-UA6: candidate: Spotlight resolves a DID to its MXID', async () => {
  await app();
  await page.bringToFront();
  const r = await spotlightFindsDid(page, state.accounts.b.did, state.accounts.b.user_id);
  test.info().annotations.push({ type: 'filter', description: String(r.filter) });
  expect(r.ok, `Spotlight did not offer the MXID for a DID; it showed: ${r.shown}`).toBe(true);
});

test('EW-UA7: candidate: the passkey registered on the baseline signs in to the same account', async () => {
  test.setTimeout(180_000);
  const saved = await readJson(passkeyPath());
  const p = await profile.newPage();
  try {
    const auth = await addVirtualAuthenticator(p);
    await importPasskeys(auth, saved.credentials, saved.rp_id);
    const s = await loginPasskeyToTokens(p, { siwxUrl: T2.siwxUrl, matrixUrl: T2.matrixUrl });
    expect(s.new_user, 'the passkey was treated as a new identity').toBe(false);
    expect(s.did).toBe(state.accounts.passkey.did);
    expect(s.user_id, 'the passkey signed in to another account').toBe(state.accounts.passkey.user_id);
    expect(s.device_id).toBeTruthy();
    // The browser still carries the picker hint the baseline set at its passkey sign-in.
    expect(s.detected_mxid, 'the picker hint written by the baseline was not read').toBe(state.accounts.passkey.user_id);
    expect(s.allow_count).toBe(1);
  } finally {
    await closeTab(p);
  }
});

test('EW-UA8: candidate: the Sessions manager signs out the second device', async () => {
  test.setTimeout(240_000);
  await app();
  const target = state.second_device.device_id;
  await openSessionsTab(page);
  let item = null;
  await expect
    .poll(async () => !!(item = await findDeviceListItem(page, target)), {
      timeout: 30_000,
      message: 'the Sessions manager does not list the second device',
    })
    .toBe(true);
  await item.click();

  let path;
  const manage = page.getByRole('button', { name: /manage this session/i }).first();
  if (await manage.isVisible().catch(() => false)) {
    // Delegated auth: Element hands device management to the provider's account page.
    path = 'account-page';
    const [acct] = await Promise.all([profile.waitForEvent('page'), manage.click()]);
    await acct.waitForLoadState('domcontentloaded');
    const actions = [];
    acct.on('response', (r) => {
      if (/\/account\/action$/.test(r.url().replace(/\?.*$/, ''))) actions.push(r.status());
    });
    await injectMockWallet(acct, makeWallet(state.accounts.a.private_key, serverName()));
    await acct.reload({ waitUntil: 'domcontentloaded' });
    const signOut = acct.getByRole('button', { name: /sign out this session/i }).first();
    const reauth = acct.getByRole('button', { name: /sign with wallet/i }).first();
    await signOut.or(reauth).first().waitFor({ timeout: 30_000 });
    if (!(await signOut.isVisible().catch(() => false))) await reauth.click();
    await signOut.click({ timeout: 60_000 });
    await expect(acct.locator('body'), 'the account page did not confirm the sign-out').toContainText(
      /session signed out/i,
      { timeout: 30_000 },
    );
    expect(actions, 'the account action was not answered 200').toContain(200);
    await closeTab(acct);
  } else {
    // An Element that signs other sessions out itself: DELETE /devices/{id} through the edge.
    path = 'in-app';
    await page.getByRole('button', { name: /sign out/i }).first().click({ timeout: 20_000 });
    await page.locator('.mx_Dialog').getByRole('button', { name: /sign out/i }).first().click({ timeout: 20_000 });
  }
  test.info().annotations.push({ type: 'path', description: path });

  await expect
    .poll(
      () =>
        page.evaluate(async () => (await window.mxMatrixClientPeg.get().getDevices()).devices.map((d) => d.device_id)),
      { timeout: 60_000, message: 'the second device is still on the homeserver' },
    )
    .not.toContain(target);
  const mine = await page.evaluate(async () => (await window.mxMatrixClientPeg.get().getDevices()).devices.map((d) => d.device_id));
  expect(mine, "A's own device went too").toContain(state.accounts.a.device_id);
  // The signed-out device's refresh token, issued by the baseline, is dead on the candidate.
  const r = await refreshOutcome(T2.siwxUrl, state.second_device.refresh_token, state.second_device.client_id);
  expect(r.status, `the signed-out device can still refresh (${r.status} ${r.error})`).toBe(400);
  expect(r.error).toBe('invalid_grant');
});

test('EW-UA9: candidate: a second tab does not end the session', async () => {
  test.setTimeout(240_000);
  await app();
  const before = signOuts.length;
  const tab2 = await profile.newPage();
  const r2 = await openElementApp(tab2);
  test.info().annotations.push({ type: 'tab2', description: JSON.stringify(r2) });
  expect(r2.landed, 'the second tab did not open signed in').toBe('app');
  expect(r2.siwx_navigation).toBe(0);
  const s2 = await elementSession(tab2);
  expect(s2.client_device_id).toBe(state.accounts.a.device_id);
  const sent = await tab2.evaluate(
    async ({ rid, body }) => (await window.mxMatrixClientPeg.get().sendTextMessage(rid, body)).event_id,
    { rid: state.room_id, body: `t2 from the second tab ${Date.now()}` },
  );
  expect(sent).toMatch(/^\$/);
  await closeTab(tab2);

  // Back in the first tab (Element disconnected it while the second one held the session).
  const r1 = await openElementApp(page);
  test.info().annotations.push({ type: 'tab1', description: JSON.stringify(r1) });
  expect(r1.landed, 'the first tab lost the session after the second tab').toBe('app');
  expect(r1.siwx_navigation).toBe(0);
  expect((await elementSession(page)).client_device_id).toBe(state.accounts.a.device_id);
  expect((await providerAcceptsElementToken(page, T2.siwxUrl)).status, 'the candidate refuses the token after the tab handover').toBe(200);
  expect(signOuts.slice(before), 'a tab called a sign-out endpoint').toEqual([]);
});

test('EW-UA10: candidate: Element refreshed its token against the candidate', async () => {
  const waitS = Number(process.env.T2_REFRESH_WAIT_S || 420);
  test.setTimeout((waitS + 60) * 1000);
  await app();
  const deadline = launchedAt + waitS * 1000;
  // Keep the client busy (sync runs on its own); poll the network log.
  while (!refreshes.some((r) => r.status === 200) && Date.now() < deadline) {
    await page.waitForTimeout(5_000);
  }
  test.info().annotations.push({
    type: 'refreshes',
    description: JSON.stringify(refreshes.map((r) => ({ ...r, after_s: Math.round((r.at_ms - launchedAt) / 1000) }))),
  });
  expect(refreshes.length, `no refresh within ${waitS} s of reopening Element`).toBeGreaterThan(0);
  expect(refreshes.map((r) => r.status), 'a refresh was refused').toEqual(refreshes.map(() => 200));
  expect(refreshes[0].new_format, 'the first refresh did not answer with a new-format token').toBe(true);
  // The session is still usable after the refresh.
  const who = await page.evaluate(() => window.mxMatrixClientPeg.get().whoami());
  expect(who.device_id).toBe(state.accounts.a.device_id);
  expect((await providerAcceptsElementToken(page, T2.siwxUrl)).status, 'the candidate refuses the refreshed token').toBe(200);
  expect(signOuts, 'something called a sign-out endpoint').toEqual([]);
});

test('EW-UZ: cleanup: the throwaway accounts are deactivated', async () => {
  test.setTimeout(180_000);
  const out = {};
  for (const k of ['a', 'b']) {
    if (!state.accounts[k]?.private_key) continue;
    out[k] = await deactivateWalletAccount(makeWallet(state.accounts[k].private_key, serverName()).wallet, T2.siwxUrl);
  }
  const saved = await readJson(passkeyPath()).catch(() => null);
  if (state.accounts.passkey && saved) {
    const p = await profile.newPage();
    try {
      const auth = await addVirtualAuthenticator(p);
      await importPasskeys(auth, saved.credentials, saved.rp_id);
      await p.goto(`${T2.siwxUrl}/account`, { waitUntil: 'domcontentloaded' });
      out.passkey = await deactivatePasskeyAccount(p);
    } finally {
      await closeTab(p);
    }
  }
  test.info().annotations.push({ type: 'deactivated', description: JSON.stringify(out) });
  for (const [k, v] of Object.entries(out)) expect(v, `account ${k}`).toBe('deactivated');
});
