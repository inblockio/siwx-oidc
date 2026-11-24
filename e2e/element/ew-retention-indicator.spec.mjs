/**
 * EW-RR3: the room retention indicator (siwx-oidc-matrix-server `patches/element-web` registry entry 16,
 * `room-retention-indicator.patch`, on top of entries 13 and 15). A room whose messages are deleted automatically
 * (`m.room.retention`, state key "", positive integer `max_lifetime`; only while the config key
 * `io.inblock.room_retention` is set) shows:
 *  - in the room list a clock BEFORE the room name, with the accessible label and tooltip
 *    "Messages are deleted after <period>"; the row (a button with its own label) names the clock as its description;
 *  - in the room header a line visible without hovering, "Messages here are deleted after <period>";
 *  and the same two in the Rocket.Chat face (`client_views` kit): `[data-kit-retention-clock]` in the sidebar row and
 *  `[data-kit-retention-text]` after the header title. <period> is the label of the configured choice for the room's
 *  `max_lifetime` (EW_RR3_MS, default 14 days, the "2 weeks" choice that aqua-meet meeting rooms get).
 *
 * Standing user A (never a new identity) from EW_RET_USER_DIR, as in EW-RR1 and EW-RR2; without it the test skips.
 * Rooms: "rret-e2e" (A admin, id in <EW_RET_USER_DIR>/retention-room.id, shared with EW-RR1/RR2) carries the setting
 * during the run; "rret-indicator-none" (created once, id in retention-indicator-none-room.id) never gets one and is
 * the control. The setting is written through A's in-page client while the views stay open, so every appearance and
 * disappearance is checked live: a marker on the window (and one on the kit's window) proves no reload happened.
 *
 * Steps (one test; each step records PASS / FAIL / NOT-REACHED / SKIPPED with what it saw, printed and, when EW_RR3_OUT
 * is set, written to <EW_RR3_OUT>/results.json; the test fails at the end if any step failed):
 *  S0  sign in A in stock Element; served config carries io.inblock.room_retention with a choice for EW_RR3_MS
 *  S1  stock, setting on: the clock before the name in the room list (label, description, tooltip) and the header line
 *  S2  stock, control room without the setting: no clock, no description, no header line
 *  S3  stock, setting Off: clock and header line go, without reload
 *  S4  face, setting on: the clock appears in the sidebar row (label, title, description, before the name) and the header
 *      text after the title; the control room shows neither (SKIPPED when the served config has no client_views)
 *  S5  face, setting Off: both go, without reload of the kit
 *  S6  cleanup, always: rret-e2e Off, A back on stock, A signed out (other devices removed)
 *
 *   EW_RET_USER_DIR=~/.local/state/element-dev-check \
 *   ELEMENT_URL=<dev element url> MATRIX_URL=<dev matrix url> SIWX_URL=<dev siwx url> \
 *   [EW_RR3_MS=1209600000] [EW_RR3_OUT=<abs dir>] [EW_RET_SHOTS=<abs dir>] \
 *   ./run.sh --grep '@ew-p16' ew-retention-indicator.spec.mjs
 *
 * No tracing, no video: the typed recovery key would be recorded. Screenshots only (EW_RET_SHOTS), none while sign-in
 * is in progress; they are the material for the eye check of the look (contrast, truncation, spacing).
 */
import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { ELEMENT_URL, MATRIX_URL } from './helpers/element.mjs';
import {
  loadStandingUser,
  standingUserSignIn,
  standingUserSignOut,
  ensureStandingRoom,
  openRoomById,
} from './helpers/standing-user.mjs';

const USER_DIR = process.env.EW_RET_USER_DIR;
const OUT = process.env.EW_RR3_OUT; // optional absolute directory: results.json
const SHOTS = process.env.EW_RET_SHOTS; // optional absolute directory: screenshots of the key moments
const RR3_MS = Number(process.env.EW_RR3_MS || 14 * 86_400_000);
const RET = 'm.room.retention';
const OFF = { min_lifetime: 0 };
const ROOM = 'rret-e2e';
const ROOM_ID_FILE = 'retention-room.id';
const NONE = 'rret-indicator-none';
const NONE_ID_FILE = 'retention-indicator-none-room.id';
const LIVE_MS = 20_000; // the views follow the room state; this is the wait for a sync round trip
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const check = (cond, msg) => { if (!cond) throw new Error(msg); };
const until = async (fn, timeout = 30_000, step = 500) => {
  const t = Date.now();
  for (;;) {
    const v = await fn().catch(() => false);
    if (v) return v;
    if (Date.now() - t > timeout) return false;
    await sleep(step);
  }
};

const R = { started: new Date().toISOString(), target: { element: ELEMENT_URL, matrix: MATRIX_URL }, steps: {}, final: {} };
const save = () => { if (OUT) { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(R, null, 1)); } };
const failed = [];

let page, context;
let signedIn = false; // no screenshot before sign-in is complete (the recovery key is typed during it)
let cleaned = false;
const shot = async (name) => { if (!SHOTS || !signedIn || !page || page.isClosed()) return; fs.mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/rr3-${name}.png` }).catch(() => {}); };

async function step(id, title, fn, needs = [], skipReason = null) {
  const bad = needs.filter((n) => R.steps[n]?.status !== 'PASS');
  if (skipReason) R.steps[id] = { title, status: 'SKIPPED', saw: skipReason };
  else if (bad.length) R.steps[id] = { title, status: 'NOT-REACHED', saw: `needs ${bad.join(', ')} (not PASS)` };
  else {
    try {
      R.steps[id] = { title, status: 'PASS', saw: (await fn()) ?? '' };
    } catch (e) {
      R.steps[id] = { title, status: 'FAIL', saw: String(e?.message || e).slice(0, 900) };
      failed.push(id);
      await shot(`fail-${id}`);
    }
  }
  console.log(`[RR3] ${id} ${R.steps[id].status}: ${JSON.stringify(R.steps[id].saw).slice(0, 400)}`);
  save();
  return R.steps[id].status === 'PASS';
}

// ---------- A's in-page client ----------
const retState = (rid) => page.evaluate(([r, t]) => { const ev = window.mxMatrixClientPeg.get().getRoom(r)?.currentState.getStateEvents(t, ''); return ev ? ev.getContent() : null; }, [rid, RET]);
const setState = (rid, content) => page.evaluate(([r, t, c]) => window.mxMatrixClientPeg.get().sendStateEvent(r, t, c, ''), [rid, RET, content]);
const stateIs = async (rid, want) => JSON.stringify(await retState(rid)) === JSON.stringify(want);
const ready = () => page.waitForFunction(() => window.mxMatrixClientPeg?.get()?.isInitialSyncComplete?.() === true, null, { timeout: 90_000, polling: 1000 });
/** A marker on the window: still there later means the page was not reloaded in between. */
const markWindow = () => page.evaluate(() => { window.__rr3Mark = Math.random().toString(36).slice(2); return window.__rr3Mark; });
const windowMark = () => page.evaluate(() => window.__rr3Mark ?? null);

// ---------- stock Element ----------
const stockRow = (name) => page.locator('.mx_RoomListItemView').filter({ has: page.locator('[data-testid="room-name"]', { hasText: new RegExp(`^${reEscape(name)}$`) }) }).first();
const headerLine = () => page.locator('.mx_RoomHeader_retention');
const headerInfoButton = () => page.locator('button.mx_RoomHeader_infoWrapper').first();
/** The clock of a row and where it sits: before the name element, inside the same row. */
const clockFacts = (row) => row.evaluate((el) => {
  const icon = el.querySelector('[data-testid="room-retention-icon"]');
  const name = el.querySelector('[data-testid="room-name"]');
  return {
    icon: !!icon,
    role: icon?.getAttribute('role') ?? null,
    label: icon?.getAttribute('aria-label') ?? null,
    id: icon?.id || null,
    beforeName: !!(icon && name && icon.compareDocumentPosition(name) & Node.DOCUMENT_POSITION_FOLLOWING),
    describedBy: el.getAttribute('aria-describedby'),
    rowLabel: el.getAttribute('aria-label'),
    nameTruncates: name ? getComputedStyle(name).textOverflow === 'ellipsis' : null,
  };
});

// ---------- the face ----------
const KIT = 'iframe[src*="/kits/rocketchat"]';
const fr = () => page.frameLocator(KIT);
const kitUp = () => page.locator(KIT).count().then((n) => n > 0);
const faceRow = (name) => fr().locator('a.rcx-sidebar-item').filter({ has: fr().locator('.rcx-sidebar-item__title', { hasText: new RegExp(`^${reEscape(name)}$`) }) }).first();
const faceHeaderText = () => fr().locator('[data-kit-retention-text]');
const faceClockFacts = (row) => row.evaluate((el) => {
  const clock = el.querySelector('[data-kit-retention-clock]');
  const title = el.querySelector('.rcx-sidebar-item__title');
  return {
    clock: !!clock,
    role: clock?.getAttribute('role') ?? null,
    label: clock?.getAttribute('aria-label') ?? null,
    // Rocket.Chat's tooltip provider moves `title` to `data-title` while the pointer is on it
    tooltip: clock ? clock.getAttribute('title') || clock.getAttribute('data-title') : null,
    id: clock?.id || null,
    beforeName: !!(clock && title && clock.compareDocumentPosition(title) & Node.DOCUMENT_POSITION_FOLLOWING),
    describedBy: el.getAttribute('aria-describedby'),
  };
});
const markKit = () => page.locator(KIT).first().evaluate((f) => { f.contentWindow.__rr3Mark = Math.random().toString(36).slice(2); return f.contentWindow.__rr3Mark; });
const kitMark = () => page.locator(KIT).first().evaluate((f) => f.contentWindow.__rr3Mark ?? null);
async function switchToFace() {
  await page.getByRole('button', { name: /User menu/i }).first().click({ timeout: 20_000 });
  const entry = page.getByRole('menuitem', { name: /Rocket\.?Chat/i }).first();
  await entry.waitFor({ timeout: 15_000 });
  await entry.click();
  await page.locator(KIT).first().waitFor({ timeout: 60_000 });
  check(await until(async () => (await faceRow(ROOM).count()) > 0, 60_000, 1000), `the kit did not list the room ${ROOM} within 60 s`);
}
async function openFaceRoom(name) {
  await faceRow(name).click({ timeout: 20_000 });
  await fr().locator('textarea').first().waitFor({ timeout: 30_000 });
  await sleep(1000);
}
async function backToStock() {
  if (await kitUp()) {
    const um = fr().getByRole('button', { name: 'User menu' }).first();
    if (await um.count().catch(() => 0)) { await um.click({ timeout: 5000 }).catch(() => {}); await sleep(1200); }
    const back = fr().getByText(/Back to Element|Switch to Element|Switch to stock/i).first();
    if ((await back.count().catch(() => 0)) > 0) { await back.click().catch(() => {}); await sleep(3000); }
  }
  if (await kitUp()) {
    await page.goto(`${ELEMENT_URL}/?client_view=stock#/home`, { waitUntil: 'domcontentloaded' });
    await sleep(3000); await ready();
  }
  check(await until(async () => !(await kitUp()) && (await page.locator('.mx_LeftPanel, .mx_RoomList').count()) > 0, 30_000, 1000), 'still not on stock Element');
}

// ============================================================ the test
test.describe.configure({ mode: 'serial' });
test.beforeAll(async ({ browser }) => {
  if (!USER_DIR) return;
  context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  page = await context.newPage();
});

async function cleanup(ADMIN) {
  if (cleaned) return; cleaned = true;
  const c = {};
  try {
    if (page && !page.isClosed() && (await page.evaluate(() => !!window.mxMatrixClientPeg?.get?.()).catch(() => false))) {
      if (ADMIN && !(await stateIs(ADMIN, OFF).catch(() => false)) && (await retState(ADMIN).catch(() => null)) !== null) {
        await setState(ADMIN, OFF).catch((e) => { c.offError = String(e).slice(0, 100); });
      }
      if (ADMIN) R.final.adminState = await retState(ADMIN).catch((e) => String(e).slice(0, 80));
      await backToStock().catch((e) => { c.backToStockError = String(e).slice(0, 100); });
      c.signOut = await standingUserSignOut(page);
    } else c.signOut = 'no signed-in client on the page';
  } catch (e) { c.error = String(e).slice(0, 200); }
  R.final.cleanup = c;
  R.steps.S6 = { title: 'cleanup', status: c.error || /error/i.test(JSON.stringify(c)) ? 'FAIL' : 'PASS', saw: c };
  if (R.steps.S6.status === 'FAIL') failed.push('S6');
  console.log(`[RR3] S6 ${R.steps.S6.status}: ${JSON.stringify(c).slice(0, 400)}`);
  save();
}
let ROOMS = { ADMIN: null };
test.afterAll(async () => { if (!USER_DIR) return; await cleanup(ROOMS.ADMIN); R.finished = new Date().toISOString(); save(); });

test.describe('Room retention indicator (EW-RR3)', { tag: '@ew-p16' }, () => {
test('EW-RR3 the clock in the room list and the line in the header, in Element and in the face', async () => {
  test.skip(!USER_DIR, "needs EW_RET_USER_DIR (the standing test user's state directory) and an Element build with registry entry 16");
  test.setTimeout(15 * 60_000);
  let ADMIN, CONTROL, listText, headerText, hasFace = false;
  try {
    // ---------------- S0
    await step('S0', 'sign in A in stock Element; served config', async () => {
      const cfg = await (await fetch(`${ELEMENT_URL}/config.json`)).json();
      const rcfg = cfg['io.inblock.room_retention'];
      check(rcfg && typeof rcfg === 'object', 'served config has no io.inblock.room_retention (the indicator is off by design without it)');
      const choice = (rcfg.choices || []).find((c) => c.ms === RR3_MS);
      check(choice, `served config has no retention choice for ${RR3_MS} ms (EW_RR3_MS)`);
      listText = `Messages are deleted after ${choice.label}`;
      headerText = `Messages here are deleted after ${choice.label}`;
      hasFace = Array.isArray(cfg.client_views) && cfg.client_views.length > 0;
      const user = loadStandingUser(USER_DIR);
      await standingUserSignIn(page, user);
      signedIn = true;
      ADMIN = await ensureStandingRoom(page, user, ROOM_ID_FILE, ROOM);
      CONTROL = await ensureStandingRoom(page, user, NONE_ID_FILE, NONE);
      ROOMS = { ADMIN };
      // normalise: rret-e2e starts Off (not part of the verdict); the control room must carry no lifetime at all
      const a0 = await retState(ADMIN);
      if (a0?.max_lifetime !== undefined) { await setState(ADMIN, OFF); check(await until(() => stateIs(ADMIN, OFF), 20_000), 'could not switch rret-e2e Off before the run'); }
      const n0 = await retState(CONTROL);
      check(n0 === null || n0.max_lifetime === undefined, `the control room ${NONE} carries a lifetime: ${JSON.stringify(n0)}`);
      return { listText, headerText, face: hasFace, startStates: { admin: a0, control: n0 } };
    });
    check(R.steps.S0.status === 'PASS', 'S0 failed, nothing else can run');

    // ---------------- S1 stock, on
    await step('S1', 'stock: setting on shows the clock before the name and the header line, live', async () => {
      await openRoomById(page, ADMIN);
      await expect(headerLine()).toHaveCount(0);
      expect((await clockFacts(stockRow(ROOM))).icon, 'a clock before the setting is on').toBe(false);
      const mark = await markWindow();
      await setState(ADMIN, { max_lifetime: RR3_MS });
      // the header line: visible text, no hover
      await expect(headerLine()).toBeVisible({ timeout: LIVE_MS });
      await expect(headerLine()).toHaveText(headerText);
      await expect(headerInfoButton()).toHaveAccessibleDescription(headerText);
      // the room list: the clock before the name, its label, the row's description
      const row = stockRow(ROOM);
      await expect(row.getByTestId('room-retention-icon')).toBeVisible({ timeout: LIVE_MS });
      const f = await clockFacts(row);
      check(f.role === 'img' && f.label === listText, `clock role/label: ${JSON.stringify(f)}`);
      check(f.beforeName, 'the clock is not before the room name');
      check(f.describedBy && f.describedBy === f.id, `the row does not name the clock as its description: ${JSON.stringify(f)}`);
      check(f.nameTruncates, 'the room name no longer truncates with an ellipsis');
      await expect(row).toHaveAccessibleDescription(listText);
      await shot('S1-stock-on');
      // the tooltip
      await row.getByTestId('room-retention-icon').hover();
      await expect(page.getByText(listText, { exact: true }).first()).toBeVisible({ timeout: 5000 });
      await shot('S1-stock-tooltip');
      await page.mouse.move(0, 0);
      check((await windowMark()) === mark, 'the page was reloaded');
      return { header: headerText, clock: f };
    }, ['S0']);

    // ---------------- S2 stock, control room
    await step('S2', 'stock: a room without the setting shows neither', async () => {
      await openRoomById(page, CONTROL);
      await sleep(1500);
      await expect(headerLine()).toHaveCount(0);
      check((await headerInfoButton().getAttribute('aria-describedby')) === null, 'the header button of the control room has a description');
      const f = await clockFacts(stockRow(NONE));
      check(!f.icon && f.describedBy === null, `the control room row: ${JSON.stringify(f)}`);
      await shot('S2-stock-control');
      return f;
    }, ['S0']);

    // ---------------- S3 stock, off
    await step('S3', 'stock: setting Off removes clock and header line, live', async () => {
      await openRoomById(page, ADMIN);
      await expect(headerLine()).toBeVisible({ timeout: LIVE_MS });
      const mark = await markWindow();
      await setState(ADMIN, OFF);
      check(await until(() => stateIs(ADMIN, OFF), 20_000), `state is ${JSON.stringify(await retState(ADMIN))}`);
      await expect(headerLine()).toHaveCount(0, { timeout: LIVE_MS });
      await expect(stockRow(ROOM).getByTestId('room-retention-icon')).toHaveCount(0, { timeout: LIVE_MS });
      const f = await clockFacts(stockRow(ROOM));
      check(f.describedBy === null, `the row still has a description: ${JSON.stringify(f)}`);
      check((await headerInfoButton().getAttribute('aria-describedby')) === null, 'the header button still has a description');
      check((await windowMark()) === mark, 'the page was reloaded');
      await shot('S3-stock-off');
      return f;
    }, ['S1']);

    const NO_FACE = 'the served config has no client_views (no Rocket.Chat face on this deployment)';
    // ---------------- S4 face, on
    await step('S4', 'face: setting on shows the sidebar clock and the header text, live; the control room neither', async () => {
      await switchToFace();
      await openFaceRoom(ROOM);
      const kitMarkBefore = await markKit();
      expect((await faceClockFacts(faceRow(ROOM))).clock, 'a clock before the setting is on').toBe(false);
      await expect(faceHeaderText()).toHaveCount(0);
      await setState(ADMIN, { max_lifetime: RR3_MS });
      const row = faceRow(ROOM);
      await expect(row.locator('[data-kit-retention-clock]')).toBeVisible({ timeout: LIVE_MS });
      const f = await faceClockFacts(row);
      check(f.role === 'img' && f.label === listText && f.tooltip === listText, `clock role/label/title: ${JSON.stringify(f)}`);
      check(f.beforeName, 'the clock is not before the room name');
      check(f.describedBy && f.describedBy === f.id, `the row does not name the clock as its description: ${JSON.stringify(f)}`);
      await expect(row).toHaveAccessibleDescription(listText);
      await expect(faceHeaderText()).toBeVisible({ timeout: LIVE_MS });
      await expect(faceHeaderText()).toHaveText(headerText);
      await shot('S4-face-on');
      await row.locator('[data-kit-retention-clock]').hover();
      await sleep(1000);
      await shot('S4-face-tooltip');
      check((await kitMark()) === kitMarkBefore, 'the kit was reloaded');
      // the control room
      const n = await faceClockFacts(faceRow(NONE));
      check(!n.clock && n.describedBy === null, `the control room row in the face: ${JSON.stringify(n)}`);
      await openFaceRoom(NONE);
      await expect(faceHeaderText()).toHaveCount(0);
      await shot('S4-face-control');
      await openFaceRoom(ROOM);
      return { clock: f, control: n };
    }, ['S0'], hasFace ? null : NO_FACE);

    // ---------------- S5 face, off
    await step('S5', 'face: setting Off removes the sidebar clock and the header text, live', async () => {
      await expect(faceHeaderText()).toBeVisible({ timeout: LIVE_MS });
      const kitMarkBefore = await markKit();
      await setState(ADMIN, OFF);
      check(await until(() => stateIs(ADMIN, OFF), 20_000), `state is ${JSON.stringify(await retState(ADMIN))}`);
      await expect(faceRow(ROOM).locator('[data-kit-retention-clock]')).toHaveCount(0, { timeout: LIVE_MS });
      await expect(faceHeaderText()).toHaveCount(0, { timeout: LIVE_MS });
      const f = await faceClockFacts(faceRow(ROOM));
      check(f.describedBy === null, `the row still has a description: ${JSON.stringify(f)}`);
      check((await kitMark()) === kitMarkBefore, 'the kit was reloaded');
      await shot('S5-face-off');
      return f;
    }, ['S4'], hasFace ? null : NO_FACE);
  } finally {
    await cleanup(ADMIN);
    R.finished = new Date().toISOString();
    save();
  }
  expect(failed, `failed steps: ${failed.join(', ')}`).toEqual([]);
});
});
