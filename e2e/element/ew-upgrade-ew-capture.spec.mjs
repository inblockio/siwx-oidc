/**
 * T2-EW capture (EW-EC1..EC4): Element Web continuity across an ELEMENT WEB image switch, the
 * stage that runs on the Element build the lab runs BEFORE the switch (the baseline for an
 * upgrade, the candidate for the rollback drill, T2_DIRECTION=rollback). Its partner
 * ew-upgrade-ew-assert.spec.mjs runs after only the element-web image was switched (Redis,
 * siwx-oidc, Synapse and the edge kept); upgrade-survival.sh with T2_SWAP=element-web drives the
 * steps.
 *
 * The state that matters across an Element switch is the browser's: the session in
 * localStorage, the crypto store, and the encrypted search index of siwx-oidc-matrix-server
 * patches/element-web entry 6 (the browser EventIndex, IndexedDB database
 * `element-eventindex`). What it builds, on a throwaway account it creates (the assert stage
 * deactivates it):
 *
 *   EW-EC1  user A signs in through Element with a wallet in a PERSISTENT browser profile and
 *           sets the recovery key; the EventIndex is on (the lab's config.json sets
 *           features.feature_web_event_index);
 *   EW-EC2  an encrypted room with three messages carrying unique tokens: one kept, one edited
 *           (a real m.replace, so the old token must leave the index), one redacted (a real
 *           redaction, so its token must leave the index); waits until the search returns the
 *           kept and the edited message (by its new text) and not the redacted one. Whether the
 *           pre-edit text still finds the edited message is recorded (annotation `old_text`),
 *           not asserted here: the assert judges it on the build after the switch;
 *   EW-EC3  a sentinel only the index holds: an event with a unique token fed to the index
 *           manager directly (the path the live timeline takes), never sent to the homeserver.
 *           A re-crawl cannot bring it back, so finding it after the switch proves the index
 *           itself survived;
 *   EW-EC4  everything is flushed to IndexedDB, the index's fingerprint (salt fingerprint, chunk
 *           and checkpoint counts; see helpers/upgrade.mjs eventIndexFingerprint) and its stats
 *           are recorded, the state is written, and the browser is closed the way a user does.
 *
 * Needs ELEMENT_URL, MATRIX_URL, SIWX_URL and an empty QUALIFY_STATE_DIR (mode 700). State is
 * written after every step, so a failed capture still names the account the assert stage's
 * cleanup (EW-EZ) deactivates.
 */
import { test, expect } from '@playwright/test';
import { promises as fs } from 'node:fs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import {
  T2,
  serverName,
  statePath,
  profileDir,
  writePrivateJson,
  launchProfile,
  elementSession,
  waitForAppShell,
  cryptoStatus,
  wireType,
  indexSearch,
  eventIndexStats,
  eventIndexFingerprint,
} from './helpers/upgrade.mjs';

test.describe.configure({ mode: 'serial' });

const RUN = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const state = { version: 1, kind: 'element-web', accounts: {} };
const save = () => writePrivateJson(statePath(), state);
let profile; // A's persistent browser context
let page; // A's Element tab

test.beforeAll(async () => {
  // Refuse a used directory: an old profile or state would be "continuity" this build never produced.
  for (const p of [profileDir(), statePath()]) {
    const exists = await fs.stat(p).then(() => true, () => false);
    if (exists) throw new Error(`${p} exists: the capture stage needs a fresh QUALIFY_STATE_DIR`);
  }
  state.targets = { element: T2.elementUrl, matrix: T2.matrixUrl, siwx: T2.siwxUrl };
  state.from_version = (await (await fetch(`${T2.elementUrl}/version`)).text()).trim();
  state.tokens = {
    keep: `t2ew${RUN}keep`,
    old: `t2ew${RUN}old`,
    new: `t2ew${RUN}new`,
    red: `t2ew${RUN}red`,
    sentinel: `t2ew${RUN}sentinel`,
  };
  await save();
  profile = await launchProfile();
  page = profile.pages()[0] || (await profile.newPage());
});

test.afterAll(async () => {
  await profile?.close().catch(() => {});
});

/** Poll the index until `term` gives the wanted number of hits (0 or at least 1). */
async function expectHits(term, want, what, timeout = 60_000) {
  let last = null;
  await expect
    .poll(
      async () => {
        last = await indexSearch(page, term);
        if (last.noIndex) return 'no index';
        return want === 0 ? (last.count === 0 && last.ids.length === 0 ? 'none' : 'hits') : last.ids.length > 0 ? 'hits' : 'none';
      },
      { timeout, message: what },
    )
    .toBe(want === 0 ? 'none' : 'hits');
  return last;
}

test('EW-EC1: before the switch: wallet sign-in through Element, recovery key set, EventIndex on', async () => {
  test.setTimeout(420_000);
  const a = makeWallet(undefined, serverName());
  state.accounts.a = { private_key: a.wallet.privateKey, did: a.did };
  await save();

  const s = await elementWalletClickLogin(page, a);
  await waitForAppShell(page);
  expect(s.user_id, 'Element signed in as another account').toBe(a.mxid);
  expect(s.wizard, 'the first device must be walked through Secure Backup (recovery key)').toBe(true);
  const crypto = await cryptoStatus(page);
  expect(crypto.cross_signing_ready && crypto.secret_storage_ready, 'Secure Backup left no identity').toBe(true);
  Object.assign(state.accounts.a, { user_id: s.user_id, device_id: s.device_id });
  await save();

  const on = await page.evaluate(() => ({
    manager: Boolean(window.mxPlatformPeg?.get()?.getEventIndexingManager?.()),
    index: window.mxEventIndexPeg?.get?.() != null,
  }));
  expect(on, 'the EventIndex is off: the target must set features.feature_web_event_index').toEqual({
    manager: true,
    index: true,
  });
});

test('EW-EC2: before the switch: kept, edited and redacted messages; the index answers for each', async () => {
  test.setTimeout(240_000);
  const t = state.tokens;
  const roomId = await page.evaluate(async () => {
    const r = await window.mxMatrixClientPeg.get().createRoom({
      name: 'ppq-t2-ew',
      preset: 'private_chat',
      initial_state: [{ type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } }],
    });
    return r.room_id;
  });
  state.room_id = roomId;
  await save();
  await expect
    .poll(() => page.evaluate((rid) => window.mxMatrixClientPeg.get().getCrypto().isEncryptionEnabledInRoom(rid), roomId), {
      timeout: 30_000,
      message: 'the client never treated the room as encrypted',
    })
    .toBe(true);
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, roomId);
  await page.locator('.mx_MessageComposer').first().waitFor({ timeout: 30_000 });

  const send = (content) =>
    page.evaluate(
      async ({ rid, content }) => (await window.mxMatrixClientPeg.get().sendEvent(rid, 'm.room.message', content)).event_id,
      { rid: roomId, content },
    );
  const keepId = await send({ msgtype: 'm.text', body: `kept ${t.keep}` });
  const editId = await send({ msgtype: 'm.text', body: `to be edited ${t.old}` });
  const redId = await send({ msgtype: 'm.text', body: `to be redacted ${t.red}` });
  for (const id of [keepId, editId, redId]) {
    expect(await wireType(page, roomId, id), 'a message went out in the clear').toBe('m.room.encrypted');
  }
  state.events = { keep: keepId, edited: editId, redacted: redId };
  await save();

  // Each message is indexed from the live timeline before it is edited or redacted.
  for (const [term, id] of [
    [t.keep, keepId],
    [t.old, editId],
    [t.red, redId],
  ]) {
    const r = await expectHits(term, 1, `the live index never found a message just sent (${id})`);
    expect(r.ids).toContain(id);
  }

  await page.evaluate(
    async ({ rid, id, body }) =>
      window.mxMatrixClientPeg.get().sendEvent(rid, 'm.room.message', {
        msgtype: 'm.text',
        body: `* ${body}`,
        'm.new_content': { msgtype: 'm.text', body },
        'm.relates_to': { rel_type: 'm.replace', event_id: id },
      }),
    { rid: roomId, id: editId, body: `edited ${t.new}` },
  );
  await page.evaluate(async ({ rid, id }) => window.mxMatrixClientPeg.get().redactEvent(rid, id), {
    rid: roomId,
    id: redId,
  });

  const edited = await expectHits(t.new, 1, 'the index never found the edited message by its new text');
  expect(edited.ids, 'the edit must be filed under the original event id').toContain(editId);
  await expectHits(t.red, 0, 'the redacted message is still found');
  const kept = await expectHits(t.keep, 1, 'the kept message is no longer found');
  expect(kept.ids).toContain(keepId);
  const old = await indexSearch(page, t.old);
  state.old_text_before = { count: old.count, hits: old.ids.length };
  test.info().annotations.push({ type: 'old_text', description: JSON.stringify(state.old_text_before) });
  await save();
});

test('EW-EC3: before the switch: a sentinel only the index holds is found', async () => {
  const id = `$t2ew-sentinel-${RUN}`;
  await page.evaluate(
    async ({ rid, id, body }) => {
      const cli = window.mxMatrixClientPeg.get();
      await window.mxPlatformPeg.get().getEventIndexingManager().addEventToIndex(
        {
          event_id: id,
          room_id: rid,
          sender: cli.getUserId(),
          type: 'm.room.message',
          origin_server_ts: Date.now(),
          content: { msgtype: 'm.text', body },
        },
        {},
      );
    },
    { rid: state.room_id, id, body: `sentinel ${state.tokens.sentinel}` },
  );
  const r = await expectHits(state.tokens.sentinel, 1, 'the index does not find the sentinel just added', 15_000);
  expect(r.ids).toContain(id);
  state.events.sentinel = id;
  await save();
});

test('EW-EC4: before the switch: the index is on disk, its fingerprint and the state are written', async () => {
  // Flush the live write buffer and wait for the encrypted writes, then read what is on disk.
  await page.evaluate(() => window.mxPlatformPeg.get().getEventIndexingManager().commitLiveEvents());
  const fp = await eventIndexFingerprint(page, state.accounts.a.user_id);
  expect(fp.exists, `no ${'element-eventindex'} database on disk`).toBe(true);
  expect(fp.salt_fp, 'no meta row with a salt for this user').toBeTruthy();
  expect(fp.chunks, 'no chunk records for this user').toBeGreaterThan(0);
  const stats = await eventIndexStats(page);
  expect(stats.eventCount, 'the index holds fewer events than were indexed').toBeGreaterThanOrEqual(3);
  state.index_before = { fingerprint: fp, stats };
  test.info().annotations.push({ type: 'index_before', description: JSON.stringify(state.index_before) });

  const s = await elementSession(page);
  expect(s.device_id).toBe(state.accounts.a.device_id);
  state.captured_at_ms = Date.now();
  await save();
  // Close the browser the way a user does: Element releases its session lock and Chromium
  // flushes the profile (IndexedDB included) to disk before the switch.
  await profile.close();
  profile = null;
  // eslint-disable-next-line no-console
  console.log(`[EW-EC4] captured on Element ${state.from_version} -> ${statePath()}`);
});
