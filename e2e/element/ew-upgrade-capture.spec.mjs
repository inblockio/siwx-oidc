/**
 * T2 capture (EW-U1..U6): Element Web upgrade continuity, the stage that runs on the
 * BASELINE siwx-oidc. Its partner ew-upgrade-assert.spec.mjs runs after only the siwx-oidc
 * image was switched to the candidate (Redis, Synapse and Element Web kept), and
 * upgrade-survival.sh drives the three steps.
 *
 * What it builds, all on throwaway accounts it creates (the assert stage deactivates them):
 *   EW-U1  user A signs in through Element with a wallet in a PERSISTENT browser profile and
 *          sets the recovery key (Secure Backup: cross-signing, 4S, key backup);
 *   EW-U2  user B signs in through Element in a second browser; A creates an encrypted room,
 *          B joins, each sends a message, each decrypts the other's;
 *   EW-U3  a second device of A, signed in headlessly, for the Sessions manager to sign out
 *          after the switch;
 *   EW-U4  a passkey account registered in A's browser (CDP virtual authenticator; the
 *          credential is exported to the state, since a virtual authenticator dies with its
 *          browser);
 *   EW-U5  Spotlight resolves B's DID to B's MXID (the DID search the assert repeats);
 *   EW-U6  the observations the assert compares against, written to QUALIFY_STATE_DIR.
 *
 * Needs ELEMENT_URL, MATRIX_URL, SIWX_URL and an empty QUALIFY_STATE_DIR (mode 700).
 * State is written after every step, so a failed capture still names the accounts the
 * assert stage's cleanup (EW-UZ) deactivates.
 */
import { test, expect } from '@playwright/test';
import { promises as fs } from 'node:fs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { loginPasskeyToTokens, exportPasskeys } from './helpers/passkey-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import { addVirtualAuthenticator } from '../browser/webauthn-helper.mjs';
import {
  T2,
  serverName,
  statePath,
  passkeyPath,
  profileDir,
  writePrivateJson,
  launchProfile,
  elementSession,
  waitForAppShell,
  cryptoStatus,
  verificationPrompts,
  decryptRecorded,
  wireType,
  spotlightFindsDid,
} from './helpers/upgrade.mjs';

test.describe.configure({ mode: 'serial' });

const state = { version: 1, accounts: {} };
const save = () => writePrivateJson(statePath(), state);
let profile; // A's persistent browser context
let page; // A's Element tab

test.beforeAll(async () => {
  // Refuse to capture into a used directory: an old profile or state would be "continuity"
  // that this baseline never produced.
  for (const p of [profileDir(), statePath(), passkeyPath()]) {
    const exists = await fs.stat(p).then(() => true, () => false);
    if (exists) throw new Error(`${p} exists: the capture stage needs a fresh QUALIFY_STATE_DIR`);
  }
  state.targets = { element: T2.elementUrl, matrix: T2.matrixUrl, siwx: T2.siwxUrl };
  const disc = await (await fetch(`${T2.siwxUrl}/.well-known/openid-configuration`)).json();
  state.baseline_discovery = {
    subject_types_supported: disc.subject_types_supported,
    has_resolve_endpoint: 'io.inblock.resolve_endpoint' in disc,
  };
  await save();
  profile = await launchProfile();
  page = profile.pages()[0] || (await profile.newPage());
});

test.afterAll(async () => {
  await profile?.close().catch(() => {});
});

test('EW-U1: baseline: wallet sign-in through Element with the recovery key set', async () => {
  test.setTimeout(420_000);
  const a = makeWallet(undefined, serverName());
  state.accounts.a = { private_key: a.wallet.privateKey, did: a.did };
  await save();

  const s = await elementWalletClickLogin(page, a);
  await waitForAppShell(page);
  expect(s.user_id, 'Element signed in as another account').toBe(a.mxid);
  expect(s.wizard, 'the first device must be walked through Secure Backup (recovery key)').toBe(true);

  const crypto = await cryptoStatus(page);
  expect(crypto, 'Secure Backup did not leave a fully set-up identity').toEqual({
    cross_signing_ready: true,
    secret_storage_ready: true,
    device_cross_signing_verified: true,
    key_backup_active: true,
  });
  Object.assign(state.accounts.a, { user_id: s.user_id, device_id: s.device_id, crypto });
  state.baseline_prompts = await verificationPrompts(page);
  await save();
});

test('EW-U2: baseline: an encrypted room with a second account, a message from each, both decrypt', async ({
  browser,
}) => {
  test.setTimeout(480_000);
  const b = makeWallet(undefined, serverName());
  state.accounts.b = { private_key: b.wallet.privateKey, did: b.did };
  await save();

  const ctxB = await browser.newContext();
  try {
    const pageB = await ctxB.newPage();
    const sb = await elementWalletClickLogin(pageB, b);
    await waitForAppShell(pageB);
    Object.assign(state.accounts.b, { user_id: sb.user_id, device_id: sb.device_id });
    await save();

    const roomId = await page.evaluate(async (invitee) => {
      const cli = window.mxMatrixClientPeg.get();
      const r = await cli.createRoom({
        name: 'ppq-t2-upgrade',
        preset: 'private_chat',
        invite: [invitee],
        initial_state: [
          { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
        ],
      });
      return r.room_id;
    }, sb.user_id);
    state.room_id = roomId;
    await save();

    await pageB.evaluate((rid) => window.mxMatrixClientPeg.get().joinRoom(rid), roomId);
    // A must see B joined before it shares its room key with B's device.
    await expect
      .poll(
        () =>
          page.evaluate(
            ({ rid, uid }) => window.mxMatrixClientPeg.get().getRoom(rid)?.getMember(uid)?.membership ?? null,
            { rid: roomId, uid: sb.user_id },
          ),
        { timeout: 60_000, message: 'A never saw B join the room' },
      )
      .toBe('join');
    for (const p of [page, pageB]) {
      await expect
        .poll(
          () => p.evaluate((rid) => window.mxMatrixClientPeg.get().getCrypto().isEncryptionEnabledInRoom(rid), roomId),
          { timeout: 30_000, message: 'a client never treated the room as encrypted' },
        )
        .toBe(true);
    }

    const sendText = (p, body) =>
      p.evaluate(
        async ({ rid, body }) => (await window.mxMatrixClientPeg.get().sendTextMessage(rid, body)).event_id,
        { rid: roomId, body },
      );
    const m1 = { body: `t2 from A before the switch ${Date.now()}` };
    m1.id = await sendText(page, m1.body);
    const m2 = { body: `t2 from B before the switch ${Date.now()}` };
    m2.id = await sendText(pageB, m2.body);
    expect(await wireType(page, roomId, m1.id), 'A sent in the clear').toBe('m.room.encrypted');
    expect(await wireType(page, roomId, m2.id), 'B sent in the clear').toBe('m.room.encrypted');

    // Each side decrypts the other's message: real Megolm keys travelled over Olm.
    for (const [p, ev, who] of [
      [page, m2, 'A decrypting B'],
      [pageB, m1, 'B decrypting A'],
    ]) {
      await expect
        .poll(async () => (await decryptRecorded(p, roomId, [ev.id]))[0]?.body ?? null, {
          timeout: 60_000,
          message: `${who}: the message never decrypted`,
        })
        .toBe(ev.body);
    }
    state.messages = [m1, m2];
    await save();
  } finally {
    await ctxB.close();
  }
});

test('EW-U3: baseline: a second device of A for the Sessions manager to sign out later', async ({
  browser,
}) => {
  test.setTimeout(180_000);
  const ctx = await browser.newContext();
  try {
    const p = await ctx.newPage();
    const a = makeWallet(state.accounts.a.private_key, serverName());
    const s = await loginWalletToTokens(p, { siwxUrl: T2.siwxUrl, matrixUrl: T2.matrixUrl, wallet: a });
    expect(s.user_id).toBe(state.accounts.a.user_id);
    expect(s.device_id).not.toBe(state.accounts.a.device_id);
    state.second_device = { device_id: s.device_id, client_id: s.client_id, refresh_token: s.refresh_token };
    await save();
  } finally {
    await ctx.close();
  }
  // Element knows about it, so the Sessions manager will list it.
  await expect
    .poll(
      () => page.evaluate(async () => (await window.mxMatrixClientPeg.get().getDevices()).devices.map((d) => d.device_id)),
      { timeout: 30_000 },
    )
    .toContain(state.second_device.device_id);
});

test('EW-U4: baseline: a passkey account registered in the same browser', async () => {
  test.setTimeout(180_000);
  const p = await profile.newPage();
  try {
    const auth = await addVirtualAuthenticator(p);
    const s = await loginPasskeyToTokens(p, { siwxUrl: T2.siwxUrl, matrixUrl: T2.matrixUrl, register: true });
    expect(s.new_user, 'a fresh passkey must create a new account').toBe(true);
    expect(s.user_id).toBe(s.mxid);
    state.accounts.passkey = { did: s.did, user_id: s.user_id, device_id: s.device_id };
    const creds = await exportPasskeys(auth);
    expect(creds.length, 'the virtual authenticator holds exactly the one passkey').toBe(1);
    await writePrivateJson(passkeyPath(), { rp_id: new URL(T2.siwxUrl).hostname, credentials: creds });
    await save();
  } finally {
    await p.close();
  }
});

test('EW-U5: baseline: Spotlight resolves a DID to its MXID', async () => {
  test.setTimeout(120_000);
  await page.bringToFront();
  const r = await spotlightFindsDid(page, state.accounts.b.did, state.accounts.b.user_id);
  expect(r.ok, `Spotlight did not offer the MXID for a DID on the baseline; it showed: ${r.shown}`).toBe(true);
  state.baseline_did_search_filter = r.filter;
  await save();
});

test('EW-U6: baseline: the session is live and the state is written', async () => {
  const s = await elementSession(page);
  expect(s.device_id).toBe(state.accounts.a.device_id);
  expect(s.client_device_id).toBe(state.accounts.a.device_id);
  state.captured_at_ms = Date.now();
  await save();
  // Close the browser the way a user does, so Element releases its session lock and the
  // profile is flushed to disk before the switch.
  await profile.close();
  profile = null;
  // eslint-disable-next-line no-console
  console.log(`[EW-U6] captured on the baseline -> ${statePath()}`);
});
