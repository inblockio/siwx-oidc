/**
 * T2-EW assert (EW-EA1..EA7, EW-EZ): Element Web continuity after ONLY the element-web image
 * was switched (Redis, siwx-oidc, Synapse and the edge kept). It reopens the browser profile
 * ew-upgrade-ew-capture.spec.mjs wrote on the build before the switch and checks, one test per
 * check, what the switch must not break:
 *
 *   EW-EA1  Element opens signed in: no login screen, no trip to the provider's sign-in;
 *   EW-EA2  the same account and the same device id;
 *   EW-EA3  the browser EventIndex (patches/element-web entry 6) was NOT reset: its database
 *           still carries the salt the capture saw (a reset index, or one created anew, has a
 *           new random salt), still holds chunk records, and the sentinel, an event that only
 *           ever existed in the index (never on the homeserver, so no re-crawl can bring it
 *           back), is found within 15 s; once hydrated the index holds at least as many events
 *           as it did before the switch. Read from IndexedDB as counts and a salt fingerprint,
 *           never as content;
 *   EW-EA4  the kept and the edited message from before the switch are found at once (within
 *           15 s of the check, no waiting for a crawl); the time to the first hit is recorded;
 *   EW-EA5  the edited message is found by its new text, under its original event id, and NOT
 *           by its pre-edit text;
 *   EW-EA6  the redacted message is not found (no hit, count 0);
 *   EW-EA7  a new message typed into the composer is indexed and found;
 *   EW-EZ   cleanup: the throwaway account is deactivated.
 *
 * EA4 to EA6 alone cannot tell a surviving index from a rebuilt one, since the crawler refills
 * a small room in seconds; EA3 can, and it is what the negative control breaks.
 *
 * Negative control: T2_NEGATIVE=drop-eventindex deletes the `element-eventindex` database from
 * the profile (on Element's origin, from its static config.json, so no Element code runs)
 * before Element is opened. EW-EA3 must then fail; the driver exits with this stage's status.
 * The deletion runs once per run (a marker in QUALIFY_STATE_DIR), not again when Playwright
 * restarts the worker after a failure.
 *
 * Needs ELEMENT_URL, MATRIX_URL, SIWX_URL and the QUALIFY_STATE_DIR the capture wrote (no older
 * than T2_MAX_STATE_AGE_S, default 3600 s).
 */
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { test, expect } from '@playwright/test';
import { makeWallet } from '../browser/wallet-helper.mjs';
import {
  T2,
  serverName,
  statePath,
  readJson,
  loadCapturedState,
  launchProfile,
  openElementApp,
  closeTab,
  elementSession,
  sendThroughComposer,
  deactivateWalletAccount,
  indexSearch,
  eventIndexStats,
  eventIndexFingerprint,
  EVENTINDEX_DB,
} from './helpers/upgrade.mjs';

let state;
let profile;
let page;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  state = process.env.T2_CLEANUP_ONLY === '1' ? await readJson(statePath()) : await loadCapturedState();
  if (state.kind !== 'element-web') throw new Error(`${statePath()} was not written by ew-upgrade-ew-capture.spec.mjs`);
  for (const k of ['element', 'matrix', 'siwx']) {
    const now = { element: T2.elementUrl, matrix: T2.matrixUrl, siwx: T2.siwxUrl }[k];
    if (state.targets[k] !== now) throw new Error(`the capture ran against another ${k} target`);
  }
  if (process.env.T2_CLEANUP_ONLY === '1') return;
  profile = await launchProfile();
  page = profile.pages()[0] || (await profile.newPage());

  if (process.env.T2_NEGATIVE === 'drop-eventindex') {
    const marker = path.join(T2.stateDir, 't2-negative-drop-eventindex.done');
    if (!(await fs.stat(marker).then(() => true, () => false))) {
      const p = await profile.newPage();
      await p.goto(`${T2.elementUrl}/config.json`, { waitUntil: 'load' });
      const r = await p.evaluate(async (name) => {
        const before = (await indexedDB.databases()).some((d) => d.name === name);
        const outcome = await new Promise((resolve) => {
          const q = indexedDB.deleteDatabase(name);
          q.onsuccess = () => resolve('deleted');
          q.onerror = () => resolve(`error ${q.error}`);
          q.onblocked = () => resolve('blocked');
        });
        const after = (await indexedDB.databases()).some((d) => d.name === name);
        return { before, outcome, after };
      }, EVENTINDEX_DB);
      await p.close();
      // eslint-disable-next-line no-console
      console.log(`[T2-EW] NEGATIVE CONTROL: ${EVENTINDEX_DB} ${JSON.stringify(r)}`);
      if (!r.before || r.outcome !== 'deleted' || r.after) {
        throw new Error(`negative control: could not delete ${EVENTINDEX_DB}: ${JSON.stringify(r)}`);
      }
      await fs.writeFile(marker, `${new Date().toISOString()}\n`, { mode: 0o600 });
    }
  } else if (process.env.T2_NEGATIVE) {
    throw new Error(`unknown T2_NEGATIVE=${process.env.T2_NEGATIVE} for the Element Web swap`);
  }
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
  if (ok) return;
  const r = await openElementApp(page);
  expect(r.landed, `Element did not open signed in: ${JSON.stringify(r)}`).toBe('app');
}

/** Search until `term` has at least one hit or `timeout` passes; return the last answer and the time taken. */
async function firstHit(term, timeout = 15_000) {
  const t0 = Date.now();
  let last = await indexSearch(page, term);
  while (last.ids.length === 0 && Date.now() - t0 < timeout) {
    await page.waitForTimeout(500);
    last = await indexSearch(page, term);
  }
  return { ...last, ms: Date.now() - t0 };
}

test('EW-EA1: after the switch: Element opens signed in, no login screen', async () => {
  const r = await openElementApp(page);
  test.info().annotations.push({ type: 'open', description: JSON.stringify(r) });
  expect(r.landed, 'Element showed a login screen after the switch').toBe('app');
  expect(r.siwx_navigation, 'Element sent the user to the provider to sign in again').toBe(0);
});

test('EW-EA2: after the switch: the same account and the same device id', async () => {
  await app();
  const s = await elementSession(page);
  expect(s.user_id).toBe(state.accounts.a.user_id);
  expect(s.device_id, 'Element holds another device id than before the switch').toBe(state.accounts.a.device_id);
  expect(s.client_device_id).toBe(state.accounts.a.device_id);
});

test('EW-EA3: after the switch: the EventIndex was not reset', async () => {
  await app();
  const before = state.index_before;
  const sentinel = await firstHit(state.tokens.sentinel);
  const fp = await eventIndexFingerprint(page, state.accounts.a.user_id);
  await page.evaluate(() => window.mxPlatformPeg.get().getEventIndexingManager().waitForHydration?.());
  const stats = await eventIndexStats(page);
  const seen = { sentinel: { hits: sentinel.ids.length, ms: sentinel.ms }, fingerprint: fp, stats, before };
  test.info().annotations.push({ type: 'index_after', description: JSON.stringify(seen) });
  // eslint-disable-next-line no-console
  console.log(`[EW-EA3] ${JSON.stringify(seen)}`);
  expect.soft(fp.exists, `no ${EVENTINDEX_DB} database after the switch`).toBe(true);
  expect
    .soft(fp.salt_fp, 'the index salt changed: the index was deleted and created anew')
    .toBe(before.fingerprint.salt_fp);
  expect.soft(fp.chunks ?? 0, 'the index lost its chunk records').toBeGreaterThan(0);
  expect
    .soft(sentinel.ids, 'the sentinel, held only by the index, is gone: the index did not survive')
    .toContain(state.events.sentinel);
  expect
    .soft(stats?.eventCount ?? 0, 'the hydrated index holds fewer events than before the switch')
    .toBeGreaterThanOrEqual(before.stats.eventCount);
});

test('EW-EA4: after the switch: messages from before the switch are found at once', async () => {
  await app();
  const kept = await firstHit(state.tokens.keep);
  const edited = await firstHit(state.tokens.new);
  test.info().annotations.push({ type: 'first_hit_ms', description: JSON.stringify({ kept: kept.ms, edited: edited.ms }) });
  expect.soft(kept.ids, 'the kept message is not found within 15 s').toContain(state.events.keep);
  expect.soft(edited.ids, 'the edited message is not found by its new text within 15 s').toContain(state.events.edited);
});

test('EW-EA5: after the switch: the edited message is found by its new text only', async () => {
  await app();
  const fresh = await firstHit(state.tokens.new);
  expect(fresh.ids, 'the new text does not find the edited message under its original id').toContain(
    state.events.edited,
  );
  const old = await indexSearch(page, state.tokens.old);
  test.info().annotations.push({
    type: 'old_text',
    description: JSON.stringify({ after: { count: old.count, hits: old.ids.length }, before: state.old_text_before }),
  });
  expect(old.ids, 'the pre-edit text still finds the edited message').toEqual([]);
  expect(old.count, 'the pre-edit text still counts a hit').toBe(0);
});

test('EW-EA6: after the switch: the redacted message is not found', async () => {
  await app();
  // Give a late hit the same chance the others get.
  await page.waitForTimeout(2_000);
  const red = await indexSearch(page, state.tokens.red);
  expect(red.noIndex, 'there is no index to ask').toBe(false);
  expect(red.ids, 'the redacted message is found').toEqual([]);
  expect(red.count, 'the redacted message is counted').toBe(0);
});

test('EW-EA7: after the switch: a new message is indexed and found', async () => {
  await app();
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, state.room_id);
  await page.locator('.mx_MessageComposer').first().waitFor({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Dismiss' }).click({ timeout: 3_000 }).catch(() => {});
  const token = `${state.tokens.keep.replace(/keep$/, '')}post${Date.now().toString(36)}`;
  const id = await sendThroughComposer(page, state.room_id, `after the switch ${token}`);
  const hit = await firstHit(token, 30_000);
  expect(hit.ids, 'a message sent after the switch is not indexed').toContain(id);
});

test('EW-EZ: cleanup: the throwaway account is deactivated', async () => {
  test.setTimeout(120_000);
  let out = 'not attempted';
  if (state.accounts.a?.private_key) {
    try {
      out = await deactivateWalletAccount(makeWallet(state.accounts.a.private_key, serverName()).wallet, T2.siwxUrl);
    } catch (e) {
      out = `error ${String(e?.message || e).slice(0, 120)}`;
    }
  }
  test.info().annotations.push({ type: 'deactivated', description: out });
  expect(out, 'account a').toBe('deactivated');
});
