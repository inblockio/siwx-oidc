/**
 * EW-RR1: disappearing messages (siwx-oidc-matrix-server `patches/element-web` registry entry 13, room retention).
 *
 * With the Element config key `io.inblock.room_retention` = {"choices":[{"ms":..,"label":..}, ..]}, Room Settings >
 * Security & Privacy shows a "Disappearing messages" section: Off plus the configured choices. A choice sends the
 * state event `m.room.retention` {"max_lifetime": ms}, Off sends {"min_lifetime": 0}, and a timeline notice says so.
 * Element hides a message once it is older than max_lifetime, without a reload; Synapse stops serving it at that
 * moment and purges it later.
 *
 * The test needs a short choice on the target, e.g. {"ms": 120000, "label": "2 minutes (test)"} (EW_RET_SHORT_MS, default
 * 120000), and waits out that lifetime twice. It needs an Element image that carries entry 13 and the config key:
 * on any other build it fails at step 1 on the missing "Disappearing messages" section (expected red, as the other
 * patch legs).
 *
 * Standing user only: it signs in with the wallet key and recovery key stored in EW_RET_USER_DIR (an absolute
 * directory, for dev ~/.local/state/element-dev-check, mounted writable by run.sh because the name starts with
 * EW_) and NEVER creates an identity. Without EW_RET_USER_DIR the test skips. One persistent room "rret-e2e" is
 * created once through the in-page client; its id lives in <EW_RET_USER_DIR>/retention-room.id and later runs reuse it.
 * At the end (afterAll, also after a failure) the user's other devices are removed and the run's device is logged out.
 *
 *   EW_RET_USER_DIR=~/.local/state/element-dev-check ELEMENT_URL=<dev element url> MATRIX_URL=<dev matrix url> \
 *   SIWX_URL=<dev siwx url> ./run.sh --grep '@ew-p13' ew-room-retention.spec.mjs
 *
 * Steps (one test, test.step each):
 *  1 settings show the section with Off and the choice whose radio value is EW_RET_SHORT_MS
 *  2 choosing it sets the room's m.room.retention to max_lifetime === EW_RET_SHORT_MS; the notice appears
 *  3 a unique message is sent, seen in the timeline, and served by the server (positive control)
 *  4 with no reload the tile disappears no earlier than the lifetime and no later than lifetime + 75 s (measured)
 *  5 the server no longer serves GET /rooms/{id}/event/{eventId} (404)
 *  6 after a reload the message is still gone
 *  7 choosing Off sets exactly {min_lifetime: 0}; the "turned off" notice appears
 *  8 a second message stays visible and served after lifetime + 30 s
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, MATRIX_URL } from './helpers/element.mjs';
import {
  loadStandingUser,
  standingUserSignIn,
  standingUserSignOut,
  ensureStandingRoom,
  openRoomById,
} from './helpers/standing-user.mjs';

const USER_DIR = process.env.EW_RET_USER_DIR;
const SHORT_MS = Number(process.env.EW_RET_SHORT_MS || 120_000);
const RETENTION = 'm.room.retention';
const ROOM_NAME = 'rret-e2e';
const ROOM_ID_FILE = 'retention-room.id';
const HIDE_SLACK_MS = 75_000; // the client must hide the message within this long after the lifetime
const SKEW_TOLERANCE_MS = 2_000; // the server clock is read from a one-second Date header

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const uniq = () => `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

/** Server clock minus runner clock (ms), from the Date header of a plain request (1 s resolution). */
async function serverClockSkewMs() {
  try {
    const t0 = Date.now();
    const r = await fetch(`${MATRIX_URL}/_matrix/client/versions`);
    const t1 = Date.now();
    const d = Date.parse(r.headers.get('date') || '');
    return Number.isFinite(d) ? d + 500 - (t0 + t1) / 2 : 0;
  } catch {
    return 0;
  }
}

/** Current m.room.retention state of the room, read through the in-page client: { id, content } or null. */
const retentionState = (page, roomId) =>
  page.evaluate(
    ([rid, type]) => {
      const ev = window.mxMatrixClientPeg.get().getRoom(rid)?.currentState.getStateEvents(type, '');
      return ev ? { id: ev.getId(), content: ev.getContent() } : null;
    },
    [roomId, RETENTION],
  );

/** HTTP status of GET /rooms/{id}/event/{eventId} with the signed-in client's token (never /sync: Synapse caches it). */
const eventStatus = (page, roomId, eventId) =>
  page.evaluate(
    async ([rid, eid]) => {
      const c = window.mxMatrixClientPeg.get();
      const url = `${c.getHomeserverUrl()}/_matrix/client/v3/rooms/${encodeURIComponent(rid)}/event/${encodeURIComponent(eid)}`;
      const r = await fetch(url, { headers: { Authorization: `Bearer ${c.getAccessToken()}` } });
      return r.status;
    },
    [roomId, eventId],
  );

/** Open Room Settings > Security & Privacy through the room info panel. Returns the dialog and the section. */
async function openRetentionSettings(page) {
  const settingsItem = page.locator('.mx_RightPanel').getByRole('menuitem', { name: 'Settings' });
  if (!(await settingsItem.isVisible())) await page.getByRole('button', { name: 'Room info' }).first().click();
  await settingsItem.click();
  const dialog = page.locator('.mx_Dialog').filter({ has: page.locator('.mx_RoomSettingsDialog') });
  await dialog.getByRole('tab', { name: 'Security & Privacy' }).click();
  const group = dialog.getByRole('group', { name: 'Disappearing messages' });
  await expect(group, 'the "Disappearing messages" section (registry entry 13 and the config key on the target)').toBeVisible({
    timeout: 30_000,
  });
  return { dialog, group };
}

/** The section's radios as { value, label }; the radio's value attribute is String(ms), or "off". */
const radios = (group) =>
  group.getByRole('radio').evaluateAll((els) =>
    els.map((e) => ({ value: e.value, label: (e.closest('label')?.textContent ?? '').trim() })),
  );

async function chooseRadio(group, label) {
  const radio = group.getByRole('radio', { name: label, exact: true });
  // The styled radio hides the native input; fall back to its label when a direct check is refused.
  await radio.check({ timeout: 10_000 }).catch(() => group.getByText(label, { exact: true }).click());
  await expect(radio).toBeChecked();
}

async function closeSettings(page, dialog) {
  await page.keyboard.press('Escape'); // the room settings dialog; never the recovery-key dialog
  await expect(dialog).toBeHidden({ timeout: 15_000 });
}

/** Send a unique message through the composer; returns { text, eventId, ts } once the server has confirmed it. */
async function sendMessage(page, roomId, label) {
  const text = `rret-e2e ${label} ${uniq()}`;
  const composer = page.locator('.mx_BasicMessageComposer_input, [contenteditable=true][role=textbox]').first();
  await composer.click();
  await composer.fill(text);
  await page.keyboard.press('Enter');
  // The local echo has an id starting with "~"; the confirmed event has a real "$" id and the server's timestamp.
  const handle = await page.waitForFunction(
    ([rid, t]) => {
      const ev = window.mxMatrixClientPeg
        .get()
        .getRoom(rid)
        ?.getLiveTimeline()
        .getEvents()
        .find((e) => e.getContent()?.body === t && String(e.getId()).startsWith('$'));
      return ev ? { eventId: ev.getId(), ts: ev.getTs() } : null;
    },
    [roomId, text],
    { timeout: 60_000, polling: 500 },
  );
  return { text, ...(await handle.jsonValue()) };
}

test.describe('Disappearing messages (room retention, registry entry 13)', { tag: '@ew-p13' }, () => {
  let context;
  let page;

  test.afterAll(async () => {
    // Also after a failure: remove the standing user's other devices, then log this run's device out.
    if (page) console.log(`[RR] cleanup: ${await standingUserSignOut(page)}`);
    await context?.close().catch(() => {});
  });

  test('EW-RR1: a short lifetime hides and unserves messages, Off keeps them', async ({ browser }) => {
    test.skip(!USER_DIR, 'needs EW_RET_USER_DIR (the standing test user\'s state directory) and an Element build with registry entry 13');
    test.setTimeout(2 * SHORT_MS + 5 * 60_000);
    expect(Number.isInteger(SHORT_MS) && SHORT_MS >= 30_000, 'EW_RET_SHORT_MS is an integer of at least 30000').toBe(true);
    await requireElementStack();

    const user = loadStandingUser(USER_DIR);
    context = await browser.newContext();
    page = await context.newPage();
    await standingUserSignIn(page, user);
    const roomId = await ensureStandingRoom(page, user, ROOM_ID_FILE, ROOM_NAME);
    console.log(`[RR] standing user ${user.bundle.did}, room ${roomId}, lifetime ${SHORT_MS} ms`);

    // A previous failed run may have left a lifetime on the room: start from Off through the client, so that
    // choosing the short value in the UI is a real change.
    const before = await retentionState(page, roomId);
    if (before?.content?.max_lifetime !== undefined) {
      await page.evaluate(
        ([rid, type]) => window.mxMatrixClientPeg.get().sendStateEvent(rid, type, { min_lifetime: 0 }, ''),
        [roomId, RETENTION],
      );
      await expect.poll(async () => (await retentionState(page, roomId))?.content?.max_lifetime, { timeout: 30_000 }).toBeUndefined();
    }
    await openRoomById(page, roomId);

    let shortLabel;

    await test.step('1 settings show Disappearing messages with Off and the short choice', async () => {
      const { dialog, group } = await openRetentionSettings(page);
      const all = await radios(group);
      console.log(`[RR] choices on the target: ${all.map((r) => `${r.value}=${r.label}`).join(' | ')}`);
      expect(all.find((r) => r.value === 'off')?.label, 'the Off option').toBe('Off');
      const short = all.find((r) => r.value === String(SHORT_MS));
      expect(short, `a choice whose value is ${SHORT_MS} ms (add {"ms": ${SHORT_MS}, ...} to io.inblock.room_retention)`).toBeTruthy();
      shortLabel = short.label;
      await expect(group.getByRole('radio', { name: 'Off', exact: true })).toBeChecked();
      await closeSettings(page, dialog);
    });

    await test.step('2 choosing the short choice sets max_lifetime and shows the notice', async () => {
      const { dialog, group } = await openRetentionSettings(page);
      await chooseRadio(group, shortLabel);
      await expect.poll(async () => (await retentionState(page, roomId))?.content, { timeout: 30_000 }).toEqual({ max_lifetime: SHORT_MS });
      const state = await retentionState(page, roomId);
      await closeSettings(page, dialog);
      const notice = page.locator(`[data-event-id="${state.id}"]`);
      await expect(notice).toContainText(new RegExp(`set messages in this room to disappear after ${reEscape(shortLabel)}\\.`), { timeout: 30_000 });
    });

    let sent;
    let skew;

    await test.step('3 a unique message is sent, visible and served', async () => {
      sent = await sendMessage(page, roomId, 'short');
      await expect(page.locator('.mx_EventTile').filter({ hasText: sent.text })).toBeVisible({ timeout: 30_000 });
      skew = await serverClockSkewMs();
      // Positive control: the event URL answers 200 while the message is young, so a later 404 means retention.
      expect(await eventStatus(page, roomId, sent.eventId), 'GET event while young').toBe(200);
      console.log(`[RR] sent ${sent.eventId} at origin_server_ts ${sent.ts}; server clock minus runner clock ${Math.round(skew)} ms`);
    });

    await test.step('4 without a reload the tile disappears within lifetime + 75 s', async () => {
      const tile = page.locator('.mx_EventTile').filter({ hasText: sent.text });
      const serverNow = () => Date.now() + skew;
      const giveUpAt = sent.ts + SHORT_MS + HIDE_SLACK_MS + 10_000;
      let goneAt = null;
      while (serverNow() < giveUpAt) {
        if ((await tile.count()) === 0) {
          goneAt = serverNow();
          break;
        }
        await page.waitForTimeout(500);
      }
      expect(goneAt, `the tile was still shown ${Math.round((serverNow() - sent.ts) / 1000)} s after the send`).not.toBeNull();
      const seconds = (goneAt - sent.ts) / 1000;
      test.info().annotations.push({
        type: 'client-hide-latency',
        description: `tile gone ${seconds.toFixed(1)} s after origin_server_ts; lifetime ${SHORT_MS / 1000} s, so ${(seconds - SHORT_MS / 1000).toFixed(1)} s late (clock skew ${Math.round(skew)} ms)`,
      });
      console.log(`[RR] tile gone after ${seconds.toFixed(1)} s (lifetime ${SHORT_MS / 1000} s)`);
      expect(seconds * 1000, 'the message was hidden before its lifetime was over').toBeGreaterThanOrEqual(SHORT_MS - SKEW_TOLERANCE_MS);
      expect(seconds * 1000, 'the client hid the message too late').toBeLessThanOrEqual(SHORT_MS + HIDE_SLACK_MS);
    });

    await test.step('5 the server no longer serves the event', async () => {
      const status = await eventStatus(page, roomId, sent.eventId);
      test.info().annotations.push({ type: 'server-event-status', description: `GET event after expiry: ${status}` });
      // 401 or a server error would be a broken request, not retention.
      expect(status, 'GET event after expiry').not.toBe(200);
      expect(status, 'GET event after expiry (404 expected)').toBeGreaterThanOrEqual(400);
      expect(status, 'GET event after expiry (404 expected)').toBeLessThan(500);
      expect(status, 'GET event after expiry: not an auth failure').not.toBe(401);
    });

    await test.step('6 after a reload the message is still gone', async () => {
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => window.mxMatrixClientPeg?.get()?.isInitialSyncComplete?.() === true, null, {
        timeout: 90_000,
        polling: 1000,
      });
      await openRoomById(page, roomId);
      await page.waitForTimeout(5_000); // let the timeline render before asserting an absence
      await expect(page.getByText(sent.text)).toHaveCount(0);
    });

    await test.step('7 choosing Off sets exactly min_lifetime 0 and shows the notice', async () => {
      const { dialog, group } = await openRetentionSettings(page);
      await expect(group.getByRole('radio', { name: shortLabel, exact: true })).toBeChecked();
      await chooseRadio(group, 'Off');
      await expect.poll(async () => (await retentionState(page, roomId))?.content, { timeout: 30_000 }).toEqual({ min_lifetime: 0 });
      const state = await retentionState(page, roomId);
      expect('max_lifetime' in state.content, 'no max_lifetime key after Off').toBe(false);
      await closeSettings(page, dialog);
      const notice = page.locator(`[data-event-id="${state.id}"]`);
      await expect(notice).toContainText(/turned off disappearing messages\./, { timeout: 30_000 });
    });

    await test.step('8 with Off a message outlives the old lifetime', async () => {
      const second = await sendMessage(page, roomId, 'off');
      await expect(page.locator('.mx_EventTile').filter({ hasText: second.text })).toBeVisible({ timeout: 30_000 });
      await page.waitForTimeout(SHORT_MS + 30_000);
      expect(Date.now() + skew - second.ts, 'enough time passed (server clock)').toBeGreaterThan(SHORT_MS);
      await expect(page.locator('.mx_EventTile').filter({ hasText: second.text })).toBeVisible();
      expect(await eventStatus(page, roomId, second.eventId), 'GET event after the old lifetime with Off').toBe(200);
    });
  });
});
