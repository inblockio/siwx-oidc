/**
 * Sign in to a deployed Element Web as a STANDING test user (a persistent wallet key and recovery key kept in a
 * state directory), never as a new identity.
 *
 * Ported from aqua-ops `siwx-matrix-ops/promote/checks/ew-browser-signin.mjs` (the post-deploy user check), because
 * the container cannot import from ~/aqua-meet. The state directory holds `wallet.key` and `recovery.key` (0600) as in
 * `~/.local/state/element-dev-check/`; `run.sh` mounts it writable when it is named by an `EW_*` variable. No value
 * read from these files is ever logged.
 *
 * Rules (Tim 2026-10-19/20/26): keep the user, never deactivate it, never create a new one (a missing key is an
 * error, there is no EW_INIT here), and at the end remove its other devices and log the run's own device out so
 * devices do not pile up.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ELEMENT_URL, SIWX_URL } from './element.mjs';
import { makeWallet, injectMockWallet } from '../../browser/wallet-helper.mjs';

const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim() : null);

/**
 * Load the standing user from its state directory. Throws (names the directory, never a value) when a key is
 * missing: the standing user is never re-created implicitly.
 */
export function loadStandingUser(dir) {
  if (!dir || !path.isAbsolute(dir)) throw new Error('standing user: the state directory must be an absolute path');
  const walletKey = read(path.join(dir, 'wallet.key'));
  const recoveryKey = read(path.join(dir, 'recovery.key'));
  if (!walletKey || !recoveryKey) {
    throw new Error(
      `standing user: ${dir} needs wallet.key and recovery.key; this spec never creates a new identity ` +
        `(restore the standing user's files, see aqua-ops promote/README.md)`,
    );
  }
  return {
    dir,
    recoveryKey,
    bundle: makeWallet(walletKey),
    readFile: (name) => read(path.join(dir, name)),
    writeFile: (name, value) => fs.writeFileSync(path.join(dir, name), `${value}\n`, { mode: 0o600 }),
  };
}

/** One pass of the recovery-key verification dialog; throws with a named step when it does not complete. */
async function verifyWithRecoveryKey(page, user) {
  const verify = page.getByRole('button', {
    name: /Use recovery key|Verify with (Recovery|Security) Key|Use Security Key/i,
  });
  await verify.first().waitFor({ timeout: 60_000 }).catch(() => {
    throw new Error('standing user sign-in: no recovery-key option was offered on the new device');
  });
  await verify.first().click();
  const input = page.locator('.mx_Dialog input, .mx_AccessSecretStorageDialog input').first();
  await input.waitFor({ timeout: 30_000 });
  await input.fill(user.recoveryKey);
  const done = page.getByRole('button', { name: /^Done$/ });
  // Element may accept a valid key by itself and go straight to "Device verified" (Continue stays disabled).
  const cont = page.locator('.mx_Dialog').getByRole('button', { name: /^Continue$/ }).first();
  await Promise.race([cont.click().catch(() => {}), done.first().waitFor({ timeout: 60_000 }).catch(() => {})]);
  await done.first().waitFor({ timeout: 60_000 }).catch(() => {
    throw new Error('standing user sign-in: no "Done" after the recovery key');
  });
  await done.first().click();
}

/**
 * Wallet sign-in through siwx, then verify the new device with the stored recovery key. Leaves the page in the
 * signed-in app shell. Never presses Escape on the verification dialog: Element's forced-recovery patch treats a
 * dismissal as a sign-out.
 */
export async function standingUserSignIn(page, user) {
  const siwxOrigin = new URL(SIWX_URL).origin;
  const elementOrigin = new URL(ELEMENT_URL).origin;
  await injectMockWallet(page, user.bundle);
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });

  // Element redirects a logged-out browser to siwx at once (sso_redirect_options.immediate), or shows "Sign in".
  // Decide first, then click: a click chained onto the race would stay pending and fire later on an unrelated
  // "Continue" button of the verification dialog.
  const onSiwx = (u) => u.origin === siwxOrigin;
  const signIn = page
    .getByRole('link', { name: /^Sign in$/ })
    .or(page.getByRole('button', { name: /^Sign in$/ }));
  const first = await Promise.race([
    page.waitForURL(onSiwx, { timeout: 60_000 }).then(() => 'siwx'),
    signIn.first().waitFor({ timeout: 60_000 }).then(() => 'button'),
  ]);
  if (first === 'button') await signIn.first().click();
  await page.waitForURL(onSiwx, { timeout: 30_000 });

  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  await page.getByRole('button', { name: 'Skip for now' }).click({ timeout: 30_000 }).catch(() => {});
  await page.waitForURL((u) => u.origin === elementOrigin, { timeout: 60_000 });

  // A returning user's new device: verify with the stored recovery key. Element may ask again after "Done"
  // (first run 2 showed the "Confirm your digital identity" dialog a second time and it blocked every click),
  // so repeat while that dialog shows up within a few seconds, at most three times.
  const askAgain = page.getByRole('dialog').getByRole('button', { name: /Use recovery key/i });
  for (let attempt = 1; attempt <= 3; attempt++) {
    await verifyWithRecoveryKey(page, user);
    const again = await askAgain.first().waitFor({ timeout: 8_000 }).then(() => true, () => false);
    if (!again) break;
    console.log(`[RR] sign-in: the verification dialog came back after attempt ${attempt}`);
  }

  await page.locator('.mx_LeftPanel, .mx_RoomList').first().waitFor({ timeout: 60_000 });
  // The client is ready once it has synced once.
  await page.waitForFunction(() => window.mxMatrixClientPeg?.get()?.isInitialSyncComplete?.() === true, null, {
    timeout: 90_000,
    polling: 1000,
  });
}

/**
 * End of run: remove every other device of the standing user, then log this one out (an explicit logout deletes the
 * device). Never throws: it runs from afterAll, also after a failure, and the logout must be tried regardless.
 * Returns a short text for the log.
 */
export async function standingUserSignOut(page) {
  if (!page || page.isClosed()) return 'page already closed';
  const hasClient = await page.evaluate(() => !!window.mxMatrixClientPeg?.get?.()).catch(() => false);
  if (!hasClient) return 'no signed-in client on the page';
  const others = await page
    .evaluate(async () => {
      const c = window.mxMatrixClientPeg.get();
      const me = c.getDeviceId();
      const ids = (await c.getDevices()).devices.map((d) => d.device_id).filter((d) => d !== me);
      if (ids.length) await c.deleteMultipleDevices(ids);
      return ids.length;
    })
    .catch((e) => `error ${String(e).slice(0, 120)}`);
  const out = await page
    .evaluate(() => window.mxMatrixClientPeg.get().logout(true))
    .then(() => 'logged out')
    .catch((e) => `logout error ${String(e).slice(0, 120)}`);
  return `other devices removed: ${others}; ${out}`;
}

/**
 * The standing user's persistent room for one check: created once through the in-page client, its id kept in
 * `<state dir>/<idFile>`, reused by every later run. Returns the room id. Throws when a stored room does not show
 * up in the synced client (it never silently creates a second one).
 */
export async function ensureStandingRoom(page, user, idFile, name) {
  let roomId = user.readFile(idFile);
  if (!roomId) {
    roomId = await page.evaluate(
      async (n) => (await window.mxMatrixClientPeg.get().createRoom({ name: n, preset: 'private_chat' })).room_id,
      name,
    );
    user.writeFile(idFile, roomId);
  }
  await page
    .waitForFunction((rid) => window.mxMatrixClientPeg.get().getRoom(rid)?.getMyMembership() === 'join', roomId, {
      timeout: 60_000,
      polling: 1000,
    })
    .catch(() => {
      throw new Error(`standing room: the room in ${idFile} is not joined by the signed-in user after sync`);
    });
  return roomId;
}

/** Open a room by id (location hash) and wait for the room view and composer. */
export async function openRoomById(page, roomId) {
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, roomId);
  await page.locator('.mx_RoomView, .mx_RoomHeader').first().waitFor({ timeout: 60_000 });
  await page.locator('.mx_MessageComposer').first().waitFor({ timeout: 60_000 });
}
