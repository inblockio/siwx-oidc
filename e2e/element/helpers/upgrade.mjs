/**
 * Shared pieces of T2, the Element Web upgrade-continuity pair
 * (ew-upgrade-capture.spec.mjs, ew-upgrade-assert.spec.mjs, driven by upgrade-survival.sh).
 *
 * The two specs run as separate Playwright invocations with a siwx-oidc image switch in
 * between, so everything the second one needs lives on disk under QUALIFY_STATE_DIR:
 *
 *   profile/           the Chromium user-data dir of user A's browser (launchPersistentContext):
 *                      cookies, localStorage and IndexedDB, so Element's session and its crypto
 *                      store survive the browser closing, exactly as on a user's machine
 *   t2-state.json      identities, room and event ids, the baseline observations (mode 600)
 *   t2-passkeys.json   the virtual authenticator's exported credential (mode 600): a CDP
 *                      virtual authenticator lives only as long as its browser
 *
 * Targets come only from ELEMENT_URL, MATRIX_URL and SIWX_URL; there is no default host.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { chromium, devices, expect } from '@playwright/test';

/** Name of a required variable's value, or a thrown error naming it. */
export function requireEnv(name) {
  const v = process.env[name];
  if (!v || !v.trim()) {
    throw new Error(`${name} is not set: T2 takes its targets and state only from the environment`);
  }
  return v.trim().replace(/\/$/, '');
}

export const T2 = {
  get elementUrl() {
    return requireEnv('ELEMENT_URL');
  },
  get matrixUrl() {
    return requireEnv('MATRIX_URL');
  },
  get siwxUrl() {
    return requireEnv('SIWX_URL');
  },
  get stateDir() {
    const d = requireEnv('QUALIFY_STATE_DIR');
    if (!path.isAbsolute(d)) throw new Error('QUALIFY_STATE_DIR must be an absolute path');
    return d;
  },
};

export const statePath = () => path.join(T2.stateDir, 't2-state.json');
export const passkeyPath = () => path.join(T2.stateDir, 't2-passkeys.json');
export const profileDir = () => path.join(T2.stateDir, 'profile');

/** The Matrix server name the lab's MXIDs carry (the part after the colon). */
export const serverName = () => process.env.T2_SERVER_NAME || 'localhost';

/** Write a JSON file readable by its owner only. */
export async function writePrivateJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await fs.writeFile(file, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(file, 0o600);
}

export async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

/**
 * The state written by the capture stage, refused when it is missing or older than the
 * window (T2_MAX_STATE_AGE_S, default 3600 s): a check against stale state proves nothing
 * about this switch.
 */
export async function loadCapturedState() {
  let state;
  try {
    state = await readJson(statePath());
  } catch (e) {
    throw new Error(`no capture state at ${statePath()} (${e.code || e.message}): run the capture stage first`);
  }
  const maxAge = Number(process.env.T2_MAX_STATE_AGE_S || 3600) * 1000;
  const age = Date.now() - state.captured_at_ms;
  if (!(age >= 0 && age <= maxAge)) {
    throw new Error(`capture state is ${Math.round(age / 1000)} s old, outside the ${maxAge / 1000} s window`);
  }
  return state;
}

/**
 * User A's browser: a persistent Chromium profile, so a later launch finds the same
 * cookies, localStorage and IndexedDB (Element's session and crypto store).
 */
export async function launchProfile() {
  const { defaultBrowserType, ...desktop } = devices['Desktop Chrome']; // eslint-disable-line no-unused-vars
  await fs.mkdir(profileDir(), { recursive: true, mode: 0o700 });
  return chromium.launchPersistentContext(profileDir(), {
    ...desktop,
    headless: true,
    navigationTimeout: 60_000,
  });
}

/** Element's own view of its session, from the page's localStorage and the live client. */
export async function elementSession(page) {
  return page.evaluate(() => {
    const cli = window.mxMatrixClientPeg?.get?.();
    return {
      user_id: localStorage.getItem('mx_user_id'),
      device_id: localStorage.getItem('mx_device_id'),
      client_user_id: cli ? cli.getUserId() : null,
      client_device_id: cli ? cli.getDeviceId() : null,
    };
  });
}

/**
 * Open Element in `page` and classify where the user lands:
 *   'app'    the app shell with a started client (still signed in);
 *   'login'  the provider's sign-in page or Element's own auth/welcome screens.
 * Element allows one tab per session: when another tab (or a browser closed less than
 * Element's lock expiry ago) still holds the session lock, it shows "open in another
 * window" with Continue. That is not a sign-out; it is clicked and recorded (lock_seen).
 * siwx_navigation counts top-level navigations of this page to the provider's origin: an
 * Element that lost its session sends the user there to sign in again.
 */
export async function openElementApp(page, { timeout = 120_000 } = {}) {
  const siwxOrigin = new URL(T2.siwxUrl).origin;
  let siwxNavigation = 0;
  const onNav = (frame) => {
    if (frame === page.mainFrame() && frame.url().startsWith(siwxOrigin)) siwxNavigation += 1;
  };
  page.on('framenavigated', onNav);
  let lockSeen = false;
  let landed = 'unknown';
  try {
    await page.goto(T2.elementUrl, { waitUntil: 'domcontentloaded' });
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const s = await page
        .evaluate((siwxOrigin) => {
          const body = document.body?.innerText || '';
          if (location.origin === siwxOrigin) return 'login';
          if (/open in another (window|tab)/i.test(body)) return 'lock';
          if (document.querySelector('.mx_AuthPage, .mx_Welcome, .mx_Login')) return 'login';
          const cli = window.mxMatrixClientPeg?.get?.();
          if (document.querySelector('.mx_MatrixChat') && cli?.isInitialSyncComplete?.()) return 'app';
          return 'wait';
        }, siwxOrigin)
        .catch(() => 'wait');
      if (s === 'lock') {
        lockSeen = true;
        await page.getByRole('button', { name: /^continue$/i }).first().click({ timeout: 5_000 }).catch(() => {});
      } else if (s === 'app' || s === 'login') {
        landed = s;
        break;
      }
      await page.waitForTimeout(500);
    }
  } finally {
    page.off('framenavigated', onNav);
  }
  return { landed, lock_seen: lockSeen, siwx_navigation: siwxNavigation };
}

/**
 * Close a tab the way a browser does, so Element's unload handler releases its session
 * lock (Playwright's default close skips the unload handlers).
 */
export async function closeTab(page) {
  await page.close({ runBeforeUnload: true }).catch(() => {});
  await page.waitForEvent('close', { timeout: 10_000 }).catch(() => {});
}

/** Wait for Element's app shell (logged in, client started). */
export async function waitForAppShell(page, timeout = 120_000) {
  await page.locator('.mx_MatrixChat').first().waitFor({ timeout });
  await expect
    .poll(() => page.evaluate(() => !!window.mxMatrixClientPeg?.get?.()?.isInitialSyncComplete?.()), {
      timeout,
      message: 'Element never completed its initial sync',
    })
    .toBe(true);
}

/** Crypto facts of the running client that an upgrade must not change. */
export async function cryptoStatus(page) {
  return page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const c = cli.getCrypto();
    const status = await c.getDeviceVerificationStatus(cli.getUserId(), cli.getDeviceId());
    const backup = await c.getActiveSessionBackupVersion().catch(() => null);
    return {
      cross_signing_ready: await c.isCrossSigningReady(),
      secret_storage_ready: await c.isSecretStorageReady(),
      device_cross_signing_verified: !!status?.crossSigningVerified,
      key_backup_active: !!backup,
    };
  });
}

/**
 * Visible prompts that ask the user to verify this session or to re-enter a recovery key.
 * An upgrade of the identity provider must not produce any of them.
 */
export async function verificationPrompts(page) {
  return page.evaluate(() => {
    const found = [];
    const text = (el) => (el?.innerText || '').replace(/\s+/g, ' ').trim();
    for (const sel of ['.mx_CompleteSecurityBody', '.mx_SetupEncryptionBody', '.mx_AccessSecretStorageDialog']) {
      if (document.querySelector(sel)) found.push(sel);
    }
    for (const t of document.querySelectorAll('.mx_Toast_toast, .mx_ToastContainer [role="alert"], .mx_ToastContainer [role="status"]')) {
      const s = text(t);
      if (/verify this (session|device)|unverified|confirm your identity|recovery key|enter your recovery|verify your identity/i.test(s)) {
        found.push(`toast: ${s.slice(0, 120)}`);
      }
    }
    return found;
  });
}

/**
 * Decrypt the recorded events in the client and return what each one says.
 * @returns {Promise<{id: string, found: boolean, failure: boolean, body: string|null}[]>}
 */
export async function decryptRecorded(page, roomId, ids) {
  return page.evaluate(
    async ({ roomId, ids }) => {
      const cli = window.mxMatrixClientPeg.get();
      const room = cli.getRoom(roomId);
      const out = [];
      for (const id of ids) {
        let ev = room?.findEventById(id) || null;
        if (!ev) {
          // Not in the live timeline: fetch it and let the client decrypt it.
          try {
            const raw = await cli.fetchRoomEvent(roomId, id);
            const mapper = cli.getEventMapper();
            ev = mapper(raw);
          } catch {
            ev = null;
          }
        }
        if (!ev) {
          out.push({ id, found: false, failure: false, body: null });
          continue;
        }
        await cli.decryptEventIfNeeded(ev).catch(() => {});
        out.push({
          id,
          found: true,
          failure: ev.isDecryptionFailure(),
          body: ev.isDecryptionFailure() ? null : ev.getContent()?.body ?? null,
        });
      }
      return out;
    },
    { roomId, ids },
  );
}

/**
 * Send `text` through Element's composer in the open room; resolve once the homeserver
 * accepted it (server event id) and return the id. Proves the send path, not just the client.
 */
export async function sendThroughComposer(page, roomId, text) {
  const known = await page.evaluate(
    (rid) => window.mxMatrixClientPeg.get().getRoom(rid).getLiveTimeline().getEvents().map((e) => e.getId()),
    roomId,
  );
  const composer = page.locator('.mx_MessageComposer [role="textbox"][contenteditable="true"]').first();
  await composer.click({ timeout: 30_000 });
  await page.keyboard.type(text);
  await page.keyboard.press('Enter');
  let sent = null;
  await expect
    .poll(
      async () => {
        sent = await page.evaluate(
          ({ rid, known, text }) => {
            const cli = window.mxMatrixClientPeg.get();
            const me = cli.getUserId();
            const ev = cli
              .getRoom(rid)
              .getLiveTimeline()
              .getEvents()
              .find(
                (e) =>
                  e.getSender() === me &&
                  !known.includes(e.getId()) &&
                  e.getContent()?.body === text,
              );
            if (!ev) return null;
            return { id: ev.getId(), status: ev.status };
          },
          { rid: roomId, known, text },
        );
        return sent && sent.id.startsWith('$') ? 'sent' : sent?.status === 'not_sent' ? 'not_sent' : 'pending';
      },
      { timeout: 60_000, message: 'the composer message never reached the homeserver' },
    )
    .toBe('sent');
  return sent.id;
}

/** The event as the homeserver stores it: must be m.room.encrypted in an encrypted room. */
export async function wireType(page, roomId, eventId) {
  return page.evaluate(
    async ({ rid, id }) => (await window.mxMatrixClientPeg.get().fetchRoomEvent(rid, id)).type,
    { rid: roomId, id: eventId },
  );
}

/**
 * Element's Spotlight search for a DID: the patched Element (siwx-oidc-matrix-server
 * patches/element-web, resolve-did-search) turns a typed DID into the user's MXID. Older
 * builds of the patch show the hit only under the People filter, newer ones with no filter
 * too, so the search runs with no filter first and then under People.
 * Returns { ok, filter, shown }: ok when a result naming `mxid` shows (filter says under
 * which), else `shown` is what the dialog offered instead.
 */
export async function spotlightFindsDid(page, did, mxid) {
  await page.keyboard.press('Escape').catch(() => {});
  await page.keyboard.press('Control+k');
  const dialog = page.locator('.mx_SpotlightDialog').first();
  await dialog.waitFor({ timeout: 20_000 });
  await dialog.locator('input').first().fill(did);
  const hit = dialog.locator('[role="option"], .mx_SpotlightDialog_option').filter({ hasText: mxid }).first();
  const found = (timeout) =>
    hit
      .waitFor({ timeout })
      .then(() => true)
      .catch(() => false);
  let filter = 'none';
  let ok = await found(15_000);
  if (!ok) {
    filter = 'people';
    await dialog.getByRole('option', { name: /^People$/ }).or(dialog.getByRole('button', { name: /^People$/ })).first().click({ timeout: 10_000 }).catch(() => {});
    ok = await found(30_000);
  }
  // On a miss, say what Spotlight offered instead (MXIDs of throwaway lab accounts only).
  const shown = ok ? '' : (await dialog.innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 400);
  await page.keyboard.press('Escape').catch(() => {});
  return { ok, filter: ok ? filter : null, shown };
}

/**
 * Deactivate a throwaway wallet account through the provider's account API (MSC4191
 * `org.matrix.account_deactivate`, wallet re-auth). Returns a short outcome string.
 */
export async function deactivateWalletAccount(wallet, siwxUrl) {
  const base = siwxUrl.replace(/\/$/, '');
  const action = 'org.matrix.account_deactivate';
  const nr = await fetch(`${base}/account/nonce?action=${encodeURIComponent(action)}`);
  if (!nr.ok) return `nonce ${nr.status}`;
  const np = await nr.json();
  let message =
    `${new URL(base).hostname} wants you to sign in with your Ethereum account:\n` +
    `${wallet.address}\n\nDeactivate this throwaway account.\n\nURI: ${base}\nVersion: 1\nChain ID: 1\n` +
    `Nonce: ${np.nonce}\nIssued At: ${new Date().toISOString()}\nExpiration Time: ${np.expiration_time}`;
  if (np.resources?.length) message += '\nResources:' + np.resources.map((r) => `\n- ${r}`).join('');
  const signature = await wallet.signMessage(message);
  const r = await fetch(`${base}/account/wallet`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action, did: `did:pkh:eip155:1:${wallet.address}`, message, signature }),
  });
  const body = await r.json().catch(() => ({}));
  return r.ok && body.kind === 'deactivated' ? 'deactivated' : `answered ${r.status} ${body.kind || ''}`.trim();
}

/**
 * Deactivate a throwaway passkey account: account re-auth with the passkey held by the
 * page's virtual authenticator. The page must be on the provider's origin.
 */
export async function deactivatePasskeyAccount(page) {
  return page.evaluate(async () => {
    const action = 'org.matrix.account_deactivate';
    const b64uToBuf = (s) => {
      const pad = '='.repeat((4 - (s.length % 4)) % 4);
      const r = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
      const u = new Uint8Array(r.length);
      for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
      return u.buffer;
    };
    const bufToB64u = (buf) => {
      let s = '';
      new Uint8Array(buf).forEach((x) => (s += String.fromCharCode(x)));
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const sr = await fetch('/account/passkey/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (!sr.ok) return `start ${sr.status}`;
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    for (const c of opts.publicKey.allowCredentials || []) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const rr = cred.response;
    const fr = await fetch('/account/passkey/finish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        action,
        session_id: opts.session_id,
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
          authenticatorData: bufToB64u(rr.authenticatorData),
          clientDataJSON: bufToB64u(rr.clientDataJSON),
          signature: bufToB64u(rr.signature),
          userHandle: rr.userHandle ? bufToB64u(rr.userHandle) : null,
        },
      }),
    });
    const body = await fr.json().catch(() => ({}));
    return fr.ok && body.kind === 'deactivated' ? 'deactivated' : `answered ${fr.status} ${body.kind || ''}`.trim();
  });
}

/**
 * Ask the provider itself whether the access token Element holds right now is live:
 * GET /userinfo with it, from this process (never logged). Synapse caches introspection
 * for two minutes, so a whoami through the homeserver can pass on a token the provider
 * already forgot; /userinfo cannot. Returns { status, sub } (sub = the DID).
 */
export async function providerAcceptsElementToken(page, siwxUrl) {
  const token = await page.evaluate(() => window.mxMatrixClientPeg.get().getAccessToken());
  if (!token) return { status: 0, sub: null };
  const r = await fetch(`${siwxUrl.replace(/\/$/, '')}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, sub: body.sub ?? null };
}

/** Refresh a token at the provider's /token; never returns a token, only the outcome. */
export async function refreshOutcome(siwxUrl, refreshToken, clientId) {
  const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId });
  const r = await fetch(`${siwxUrl.replace(/\/$/, '')}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, error: body.error || null, new_format: /^mcr_/.test(body.refresh_token || '') };
}
