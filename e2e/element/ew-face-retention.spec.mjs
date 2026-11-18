/**
 * EW-RR2: disappearing messages in the Rocket.Chat "face" (client_views kit) on top of registry entry 13
 * (see ew-room-retention.spec.mjs, EW-RR1, which does the stock Element side).
 *
 * Standing user A signs in to stock Element (never a new identity) with the wallet key and recovery key in
 * EW_RET_USER_DIR (same state directory and helpers as EW-RR1; without it the test skips). Rooms: "rret-e2e" (A admin,
 * id in <EW_RET_USER_DIR>/retention-room.id) and, for S8 only, "rret-e2e-member" (B admin, A plain member, id in
 * <EW_RET_USER_DIR>/retention-member-room.id).
 *
 * User B is needed by API only (it never signs in to a browser) and its host-side access lives outside this repo. S8 (the
 * member view) therefore runs only when EW_FACE_B_HOST is set to the absolute path of an ES module that exports
 * `hostApi()` (returns { req(method, path, body) -> { status, json } }, an authenticated Matrix client-API caller for B)
 * and `rd(name)` (reads a value of B's state, here 'mxid'). Without it S8 is skipped with that reason and the rest runs.
 * That module imports from its own checkout, so S8 needs a host run (plain `npx playwright test`, not run.sh's
 * container, where only EW_* directories are mounted).
 *
 * Needs an Element build with entry 13, `client_views` (the Rocket.Chat kit) and `io.inblock.room_retention` with a short
 * choice in the target's config.json; on any other build it fails at S0. It is therefore NOT part of the promotion
 * selection (README).
 *
 * Steps (one test; each step records PASS / FAIL / NOT-REACHED / SKIPPED with what it saw, printed and, when EW_FACE_OUT
 * is set, written to <EW_FACE_OUT>/results.json; a failed step does not hide later ones that can still run; the test
 * fails at the end if any step failed):
 *  S0  sign in A in stock Element; served config carries client_views and io.inblock.room_retention
 *  S1  stock Room Settings > Security & Privacy: "7 days"; state m.room.retention = {max_lifetime: 604800000}
 *  S2  Switch to Rocket.Chat; kit loads; open rret-e2e in the face; a message posted from the face shows in its timeline
 *  S3  face Room Information card offers "Disappearing messages" and the click opens it
 *  S4  Room Settings dialog on Security & Privacy shows "7 days" checked
 *  S5  choose "2 minutes (test)": state {max_lifetime: 120000}; the face timeline shows "<A> set messages in this room to disappear after 2 minutes (test)."
 *  S6  a face message leaves the face timeline without reload within lifetime..lifetime+75 s (measured); stays gone after a reload
 *      (the face comes back by itself); server answers 404 to A
 *  S7  Off from the face: state {min_lifetime: 0}; line "<A> turned off disappearing messages."; a message posted now is still there after 150 s (S7b, checked after S8)
 *  S8  member view (B sets 7 days by API): "7 days" checked, all radios disabled, hint "Only room admins can change this.", click on "1 day" changes nothing, no raw error text
 *  S9  back on stock Element: the notices of S5 and S7 are in the stock timeline of rret-e2e
 *  S10 cleanup, always: both rooms Off, A on stock, A signed out (other devices removed)
 *
 *   EW_RET_USER_DIR=~/.local/state/element-dev-check EW_RET_SHORT_MS=120000 \
 *   ELEMENT_URL=<dev element url> MATRIX_URL=<dev matrix url> SIWX_URL=<dev siwx url> \
 *   [EW_FACE_B_HOST=<abs path of B's host module>] [EW_FACE_OUT=<abs dir>] [EW_RET_SHOTS=<abs dir>] \
 *   npx playwright test --trace off --grep '@ew-delta-face-retention' ew-face-retention.spec.mjs     (host run)
 *
 * No tracing, no video: the typed recovery key would be recorded. Screenshots only (EW_RET_SHOTS), none while sign-in is
 * in progress.
 */
import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ELEMENT_URL, MATRIX_URL } from './helpers/element.mjs';
import { loadStandingUser, standingUserSignIn, standingUserSignOut, openRoomById } from './helpers/standing-user.mjs';

const OUT = process.env.EW_FACE_OUT; // optional absolute directory (EW_* so run.sh mounts it): results.json
const SHOTS = process.env.EW_RET_SHOTS; // optional absolute directory: screenshots of the key moments
const USER_DIR = process.env.EW_RET_USER_DIR;
const B_HOST = process.env.EW_FACE_B_HOST; // optional absolute path of the module that gives API access as user B
const ELEMENT = ELEMENT_URL;
const HS = MATRIX_URL;
const SHORT_MS = Number(process.env.EW_RET_SHORT_MS || 120_000);
const SHORT_LABEL = '2 minutes (test)';
const RET = 'm.room.retention';
const HIDE_SLACK_MS = 75_000;
const SKEW_TOLERANCE_MS = 2_000;
const OFF = { min_lifetime: 0 };
const enc = encodeURIComponent;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const squash = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const uniq = () => `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const until = async (fn, timeout = 30_000, step = 500) => {
  const t = Date.now();
  for (;;) {
    const v = await fn().catch(() => false);
    if (v) return v;
    if (Date.now() - t > timeout) return false;
    await sleep(step);
  }
};
const check = (cond, msg) => { if (!cond) throw new Error(msg); };

const R = { started: new Date().toISOString(), target: { element: ELEMENT, matrix: HS }, steps: {}, probes: {}, final: {}, notes: [] };
const save = () => { if (OUT) { fs.mkdirSync(OUT, { recursive: true }); fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(R, null, 1)); } };
const note = (s) => { R.notes.push(s); console.log('[FACE] ' + s); save(); };
const failed = [];

let page, context, B, rd;
let signedIn = false; // no screenshot before sign-in is complete (the recovery key is typed during it)
let cleaned = false;
const shot = async (name) => { if (!SHOTS || !signedIn || !page || page.isClosed()) return; fs.mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/${name}.png` }).catch(() => {}); };

async function step(id, title, fn, needs = [], skipReason = null) {
  const bad = needs.filter((n) => R.steps[n]?.status !== 'PASS');
  if (skipReason) {
    R.steps[id] = { title, status: 'SKIPPED', saw: skipReason };
  } else if (bad.length) {
    R.steps[id] = { title, status: 'NOT-REACHED', saw: `needs ${bad.join(', ')} (not PASS)` };
  } else {
    try {
      R.steps[id] = { title, status: 'PASS', saw: (await fn()) ?? '' };
    } catch (e) {
      R.steps[id] = { title, status: 'FAIL', saw: String(e?.message || e).slice(0, 900) };
      failed.push(id);
      await shot(`fail-${id}`);
    }
  }
  console.log(`[FACE] ${id} ${R.steps[id].status}: ${JSON.stringify(R.steps[id].saw).slice(0, 400)}`);
  save();
  return R.steps[id].status === 'PASS';
}
const NO_B = 'EW_FACE_B_HOST is not set: user B (admin of the member room, API only) is not configured, so the member view cannot be prepared';

// ---------- B (API only) ----------
let bStopped = false;
const bReq = async (m, p, body) => { const r = await B.req(m, p, body); if (r.status === 429) { bStopped = true; throw new Error('B: 429 from Synapse'); } return r; };
const bRet = (room, content) => bReq('PUT', `/_matrix/client/v3/rooms/${enc(room)}/state/${RET}`, content);
const bState = async (room) => { const r = await bReq('GET', `/_matrix/client/v3/rooms/${enc(room)}/state/${RET}`); return r.status === 200 ? r.json : { __status: r.status }; };

// ---------- A in the page ----------
const retState = (rid) => page.evaluate(([r, t]) => { const ev = window.mxMatrixClientPeg.get().getRoom(r)?.currentState.getStateEvents(t, ''); return ev ? ev.getContent() : null; }, [rid, RET]);
const aEventStatus = (rid, eid) => page.evaluate(async ([r, e]) => { try { await window.mxMatrixClientPeg.get().fetchRoomEvent(r, e); return 200; } catch (e2) { return e2?.httpStatus ?? `no status: ${String(e2).slice(0, 80)}`; } }, [rid, eid]);
const aSetState = (rid, content) => page.evaluate(([r, t, c]) => window.mxMatrixClientPeg.get().sendStateEvent(r, t, c, ''), [rid, RET, content]);
const aName = (rid) => page.evaluate((r) => { const c = window.mxMatrixClientPeg.get(); return c.getRoom(r)?.getMember(c.getUserId())?.name ?? c.getUser(c.getUserId())?.displayName ?? c.getUserId(); }, rid);
const stateIs = (want) => async (rid) => JSON.stringify(await retState(rid)) === JSON.stringify(want);
async function skewMs() {
  let prev = null;
  for (let i = 0; i < 60; i++) {
    const t0 = Date.now(); const r = await fetch(`${HS}/_matrix/client/versions`); const t1 = Date.now();
    const d = Date.parse(r.headers.get('date') || '');
    if (prev !== null && d !== prev) return d - (t0 + t1) / 2;
    prev = d; await sleep(60);
  }
  return 0;
}
const ready = () => page.waitForFunction(() => window.mxMatrixClientPeg?.get()?.isInitialSyncComplete?.() === true, null, { timeout: 90_000, polling: 1000 });

// ---------- stock Element ----------
async function openSettings() {
  const item = page.locator('.mx_RightPanel').getByRole('menuitem', { name: 'Settings' });
  for (let a = 0; a < 3; a++) {
    if (await item.waitFor({ timeout: a === 0 ? 3000 : 5000 }).then(() => true, () => false)) break;
    await page.getByRole('button', { name: 'Room info' }).first().click();
  }
  await item.click();
  const dialog = page.locator('.mx_Dialog').filter({ has: page.locator('.mx_RoomSettingsDialog') });
  await dialog.getByRole('tab', { name: 'Security & Privacy' }).click();
  await sleep(1500);
  return dialog;
}
const dialogLoc = () => page.locator('.mx_Dialog').filter({ has: page.locator('.mx_RoomSettingsDialog') });
const groupOf = (dialog) => dialog.getByRole('group', { name: 'Disappearing messages' });
const radiosOf = (group) => group.getByRole('radio').evaluateAll((els) => els.map((e) => ({ value: e.value, label: (e.closest('label')?.textContent ?? '').replace(/\s+/g, ' ').trim(), checked: e.checked, disabled: e.disabled || e.getAttribute('aria-disabled') === 'true' })));
const pick = async (group, label) => {
  const radio = group.getByRole('radio', { name: label, exact: true });
  await group.scrollIntoViewIfNeeded().catch(() => {});
  await radio.check({ timeout: 4000 }).catch(() => group.getByText(label, { exact: true }).click({ timeout: 8000 }));
};
async function closeDialog() { await page.keyboard.press('Escape'); await until(async () => !(await dialogLoc().first().isVisible()), 15_000); }
const clientViewSetting = () => page.evaluate(() => { try { return JSON.parse(localStorage.getItem('mx_local_settings') || '{}').clientView ?? null; } catch { return 'err'; } });

// ---------- the face ----------
const KIT = 'iframe[src*="/kits/rocketchat"]';
const fr = () => page.frameLocator(KIT);
const faceText = async () => squash(await fr().locator('body').innerText({ timeout: 5000 }).catch(() => ''));
// The face (Rocket.Chat) prints a system line as "<name> @<mxid> <text>"; the optional "@mxid" is its own rendering, not a second name.
const faceLineRe = (name, tail) => new RegExp(`${reEscape(name)}(?: @\\S+)? ${reEscape(tail)}`);
const faceLine = async (name, tail) => (squash(await fr().locator('body').innerText({ timeout: 5000 }).catch(() => '')).match(faceLineRe(name, tail)) || [null])[0];
const faceSystemFacts = () => fr().locator('body').evaluate((b) => ({ typed: [...b.querySelectorAll('[data-system-message-type]')].map((e) => e.getAttribute('data-system-message-type')).slice(-8), retention: [...b.querySelectorAll('[data-system-message-type="room_retention_changed"]')].map((e) => (e.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 160)) }), undefined, { timeout: 8000 }).catch(() => null);
const kitUp = () => page.locator(KIT).count().then((n) => n > 0);
async function switchToFace() {
  await page.getByRole('button', { name: /User menu/i }).first().click({ timeout: 20_000 });
  const entry = page.getByRole('menuitem', { name: /Rocket\.?Chat/i }).first();
  await entry.waitFor({ timeout: 15_000 });
  await entry.click();
  await page.locator(KIT).first().waitFor({ timeout: 60_000 });
  check(await until(async () => (await faceText()).includes('rret-e2e'), 60_000, 1000), 'the kit did not list the room rret-e2e within 60 s');
}
async function backToStock() {
  const how = [];
  if (await kitUp()) {
    const um = fr().getByRole('button', { name: 'User menu' }).first();
    if (await um.count().catch(() => 0)) { await um.click({ timeout: 5000 }).catch(() => {}); await sleep(1200); }
    const avatar = (await um.count().catch(() => 0)) ? fr().locator('nonexistent-never') : fr().locator('header button, [class*=avatar] button, button[aria-label*="menu" i], button[aria-label*="user" i]').last();
    if (await avatar.count().catch(() => 0)) { await avatar.click({ timeout: 5000 }).catch(() => {}); await sleep(1200); }
    R.probes.kitUserMenu = await fr().locator('[role=menu] *, [role=menuitem], [class*=option], [class*=Option], li').evaluateAll((els) => [...new Set(els.filter((e) => e.getBoundingClientRect().width > 0).map((e) => (e.innerText || '').replace(/\s+/g, ' ').trim()).filter((t) => t && t.length < 60))].slice(0, 40)).catch(() => null); save();
    await shot('backToStock-kit-menu');
    const back = fr().getByText(/Switch to Element|Switch to stock|Back to Element|Element \(|Default view|Stock/i).first();
    if ((await back.count().catch(() => 0)) > 0) { await back.click().catch(() => {}); how.push('kit menu entry'); await sleep(3000); }
  }
  if (await kitUp()) {
    await page.goto(`${ELEMENT}/?stock=1#/home`, { waitUntil: 'domcontentloaded' }); how.push('?stock=1 escape');
    await sleep(3000); await ready();
  }
  const ok = await until(async () => !(await kitUp()) && (await page.locator('.mx_LeftPanel, .mx_RoomList').count()) > 0, 30_000, 1000);
  check(ok, `still not on stock after ${how.join(' + ') || 'no action'}`);
  return how.join(' + ') || 'already stock';
}
const toastsSeen = [];
async function dismissToasts() {
  for (let i = 0; i < 6; i++) {
    const t = page.locator('.mx_ToastContainer');
    if (!(await t.count().catch(() => 0))) return;
    const txt = squash(await t.first().innerText().catch(() => '')).slice(0, 120);
    const btn = t.getByRole('button', { name: /^(Dismiss|Later|Not now|Close)$/i }).first();
    if (!(await btn.count().catch(() => 0))) return;
    if (txt && !toastsSeen.includes(txt)) { toastsSeen.push(txt); R.toastsDismissed = toastsSeen; save(); }
    await btn.click({ timeout: 3000 }).catch(() => {});
    await sleep(600);
  }
}
async function openFaceRoom(name) {
  await dismissToasts();
  await fr().getByText(name, { exact: true }).first().click({ timeout: 20_000 });
  await fr().locator('textarea').first().waitFor({ timeout: 30_000 });
  await sleep(1500);
}
async function postFromFace(rid, label) {
  await dismissToasts();
  const text = `rret-face ${label} ${uniq()}`;
  const composer = fr().locator('textarea[name="msg"]').or(fr().locator('textarea')).first();
  await composer.click({ timeout: 15_000 }); await composer.fill(text, { timeout: 15_000 }); await page.keyboard.press('Enter');
  check(await until(async () => (await faceText()).includes(text), 30_000, 500), `the posted message "${text}" did not show in the face timeline within 30 s`);
  const h = await page.waitForFunction(([r, t]) => { const ev = window.mxMatrixClientPeg.get().getRoom(r)?.getLiveTimeline().getEvents().find((e) => e.getContent()?.body === t && String(e.getId()).startsWith('$')); return ev ? { eventId: ev.getId(), ts: ev.getTs() } : null; }, [rid, text], { timeout: 60_000, polling: 500 });
  return { text, ...(await h.jsonValue()) };
}
/** Smallest elements in the face whose own text matches: ancestor chain with tag, role, data-* and class head. */
const faceDomChain = (reSource) => fr().locator('body').evaluate((body, src) => {
  const re = new RegExp(src);
  let best = null;
  for (const el of body.querySelectorAll('*')) {
    const own = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent).join(' ');
    if (re.test(own)) { best = el; break; }
  }
  if (!best) return null;
  const chain = [];
  for (let e = best, i = 0; e && e !== body && i < 7; e = e.parentElement, i++) {
    const data = {}; for (const a of e.attributes) if (/^(data-|role|aria-label|title|name)/.test(a.name)) data[a.name] = a.value.slice(0, 60);
    chain.push({ tag: e.tagName.toLowerCase(), cls: (e.getAttribute('class') || '').slice(0, 70), ...data });
  }
  return chain;
}, reSource, { timeout: 8000 }).catch(() => null);
const faceHeaderButtons = () => fr().locator('button, [role=button]').evaluateAll((els) => els.map((e) => ({ t: (e.getAttribute('title') || e.getAttribute('aria-label') || e.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 40), qa: e.getAttribute('data-qa-id') || '' })).filter((x) => x.t).slice(0, 60)).catch(() => []);
const roomInfoButton = () => fr().getByRole('button', { name: /room info|team info/i }).or(fr().locator('[title*="room info" i], [aria-label*="room info" i], [data-qa-id*="room-info" i]')).first();
const topMenuItems = () => page.evaluate(() => {
  const items = [...document.querySelectorAll('[role=menuitem]')].filter((e) => e.getBoundingClientRect().width > 0);
  const first = items[0];
  const chain = []; for (let e = first, i = 0; e && i < 4; e = e.parentElement, i++) chain.push(`${e.tagName.toLowerCase()}.${(e.getAttribute('class') || '').slice(0, 60)}`);
  return { texts: items.map((e) => (e.innerText || e.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim()), firstChain: first ? chain : null, cardHead: first ? (first.closest('[class*=Card], .mx_RightPanel, [class*=card]')?.innerText || '').replace(/\s+/g, ' ').slice(0, 120) : null };
});
const entryLoc = () => page.getByRole('menuitem', { name: /Disappearing messages/i });
/** Open the face's Room Information card; return what it offers. */
async function openCard() {
  await dismissToasts();
  if ((await entryLoc().count()) === 0) {
    const btn = roomInfoButton();
    const n = await btn.count();
    if (!n) throw new Error(`no Room Information button in the face header; header buttons: ${JSON.stringify((await faceHeaderButtons()).map((b) => b.t).slice(0, 25))}`);
    await btn.click({ timeout: 10_000 });
    await page.locator('[role=menuitem]').first().waitFor({ timeout: 15_000 }).catch(() => {});
    await sleep(800);
  }
  return topMenuItems();
}

/** Post a message in the face and watch it leave the face timeline without reload; then reload. */
async function measureExpiry(rid, label, lifetimeMs, capS) {
  const skew = await skewMs();
  const m = await postFromFace(rid, label);
  const probeText = m.text;
  await shot(`${label}-posted`);
  let goneAtS = null;
  const deadline = m.ts + (lifetimeMs + capS * 1000) - skew;
  while (Date.now() < deadline) {
    if (!(await faceText()).includes(probeText)) { goneAtS = +((Date.now() + skew - m.ts) / 1000).toFixed(1); break; }
    await sleep(1000);
  }
  const out = { posted: m, skewMs: Math.round(skew), goneAfterS: goneAtS, stillThereAtCap: goneAtS === null };
  out.serverStatusBeforeReload = await aEventStatus(rid, m.eventId);
  await shot(`${label}-after-wait`);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await ready();
  out.faceBackAfterReload = await page.locator(KIT).first().waitFor({ timeout: 60_000 }).then(() => true, () => false);
  out.deviceSetting = await clientViewSetting();
  if (out.faceBackAfterReload) {
    out.listedAfterReload = await until(async () => (await faceText()).includes('rret-e2e'), 60_000, 1000);
    await openFaceRoom('rret-e2e').catch((e) => { out.openRoomError = String(e).slice(0, 100); });
    await sleep(4000);
    out.messageAfterReload = (await faceText()).includes(probeText) ? 'present' : 'absent';
    out.roomLoadedControl = (await faceText()).includes('rret-e2e');
  }
  out.serverStatusAfterReload = await aEventStatus(rid, m.eventId);
  return out;
}

// ============================================================ the test
test.describe.configure({ mode: 'serial' });
test.beforeAll(async ({ browser }) => {
  if (!USER_DIR) return;
  context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  page = await context.newPage();
});

async function cleanup(ADMIN, MEM) {
  if (cleaned) return; cleaned = true;
  const c = {};
  try {
    if (page && !page.isClosed() && (await page.evaluate(() => !!window.mxMatrixClientPeg?.get?.()).catch(() => false))) {
      if (ADMIN && !(await stateIs(OFF)(ADMIN))) await aSetState(ADMIN, OFF).catch((e) => { c.adminOffError = String(e).slice(0, 100); });
      if (MEM && B) { const s = await bState(MEM).catch(() => null); if (!s || JSON.stringify(s) !== JSON.stringify(OFF)) await bRet(MEM, OFF).catch((e) => { c.memOffError = String(e).slice(0, 100); }); }
      c.backToStock = await backToStock().catch((e) => `error: ${String(e).slice(0, 100)}`);
      c.deviceSettingClientView = await clientViewSetting().catch(() => null);
      if (ADMIN) R.final.adminState = await retState(ADMIN).catch((e) => String(e).slice(0, 80)); // B is not a member of rret-e2e (403), so A reads it
      if (B && MEM) R.final.memberState = await bState(MEM).catch((e) => String(e).slice(0, 80));
      c.signOut = await standingUserSignOut(page);
    } else c.signOut = 'no signed-in client on the page';
  } catch (e) { c.error = String(e).slice(0, 200); }
  R.final.cleanup = c;
  R.steps.S10 = { title: 'cleanup', status: c.error || /error/i.test(JSON.stringify(c)) ? 'FAIL' : 'PASS', saw: c };
  if (R.steps.S10.status === 'FAIL') failed.push('S10');
  console.log(`[FACE] S10 ${R.steps.S10.status}: ${JSON.stringify(c).slice(0, 500)}`);
  save();
}
let ROOMS = { ADMIN: null, MEM: null };
test.afterAll(async () => { if (!USER_DIR) return; await cleanup(ROOMS.ADMIN, ROOMS.MEM); R.finished = new Date().toISOString(); save(); });

test.describe('Disappearing messages in the Rocket.Chat face (EW-RR2)', { tag: '@ew-delta-face-retention' }, () => {
test('EW-RR2 face: disappearing messages', async () => {
  test.skip(!USER_DIR, "needs EW_RET_USER_DIR (the standing test user's state directory) and an Element build with registry entry 13 and the client_views kit");
  test.setTimeout(2 * SHORT_MS + 20 * 60_000);
  if (B_HOST) {
    const mod = await import(pathToFileURL(B_HOST).href);
    B = mod.hostApi();
    rd = mod.rd;
  }
  let ADMIN, MEM, myName;
  try {
    // ---------------- S0
    await step('S0', 'sign in A in stock Element; served config', async () => {
      const cfg = await (await fetch(`${ELEMENT}/config.json`)).json();
      if (B) {
        const who = await B.req('GET', '/_matrix/client/v3/account/whoami');
        check(who.status === 200 && who.json.user_id === rd('mxid'), `B whoami gate failed (${who.status})`);
      }
      const user = loadStandingUser(USER_DIR);
      ADMIN = user.readFile('retention-room.id'); MEM = B ? user.readFile('retention-member-room.id') : null;
      ROOMS = { ADMIN, MEM };
      check(ADMIN && (MEM || !B), 'room id files missing in the state dir');
      await standingUserSignIn(page, user);
      signedIn = true;
      const me = await page.evaluate(() => window.mxMatrixClientPeg.get().getUserId());
      check(/^@[^:]+:/.test(me), `signed in as an unexpected user id: ${me}`);
      await until(async () => (await page.evaluate((r) => window.mxMatrixClientPeg.get().getRoom(r)?.getMyMembership(), ADMIN)) === 'join', 60_000, 1000);
      if (MEM) await until(async () => (await page.evaluate((r) => window.mxMatrixClientPeg.get().getRoom(r)?.getMyMembership(), MEM)) === 'join', 60_000, 1000);
      myName = await aName(ADMIN);
      // normalise: both rooms start Off (not part of the verdict)
      const a0 = await retState(ADMIN); if (a0?.max_lifetime !== undefined) await aSetState(ADMIN, OFF);
      const m0 = MEM ? await bState(MEM) : null; if (m0 && m0.max_lifetime !== undefined) await bRet(MEM, OFF);
      const hasCv = Array.isArray(cfg.client_views) && cfg.client_views.length > 0;
      const rcfg = cfg['io.inblock.room_retention'];
      check(hasCv, 'served config has no client_views');
      check(!!rcfg, 'served config has no io.inblock.room_retention');
      check((rcfg.choices || []).some((c) => c.ms === SHORT_MS), `retention choices lack ${SHORT_MS} ms`);
      return { client_views: cfg.client_views, retentionChoices: (rcfg.choices || []).map((c) => `${c.ms}=${c.label}`), startStates: { admin: a0, member: m0 }, displayName: myName, signedInAs: me };
    });
    check(R.steps.S0.status === 'PASS', 'S0 failed, nothing else can run');

    // ---------------- S1 stock
    await step('S1', 'stock Room Settings: 7 days', async () => {
      await openRoomById(page, ADMIN);
      const dialog = await openSettings(); const group = groupOf(dialog);
      check(await group.isVisible().catch(() => false), 'group "Disappearing messages" not visible in stock Room Settings');
      await pick(group, '7 days');
      const want = { max_lifetime: 604_800_000 };
      check(await until(() => stateIs(want)(ADMIN), 20_000), `state is ${JSON.stringify(await retState(ADMIN))}, wanted ${JSON.stringify(want)}`);
      await closeDialog();
      return { state: await retState(ADMIN) };
    }, ['S0']);

    // ---------------- S2 face
    let posted2;
    await step('S2', 'Switch to Rocket.Chat; open rret-e2e; post and see a message', async () => {
      await switchToFace();
      await openFaceRoom('rret-e2e');
      posted2 = await postFromFace(ADMIN, 's2');
      await shot('S2-face-timeline');
      return { iframe: await page.locator(KIT).first().getAttribute('src'), posted: posted2.text, deviceSetting: await clientViewSetting() };
    }, ['S0']);

    // ---------------- S3 the entry
    await step('S3', 'face Room Information offers "Disappearing messages" and opens it', async () => {
      const info = await openCard();
      await shot('S3-card');
      const entry = entryLoc();
      check((await entry.count()) > 0, `the card has no "Disappearing messages" entry; entries it offers: ${JSON.stringify(info.texts)}`);
      await entry.first().click();
      await dialogLoc().first().waitFor({ timeout: 15_000 });
      return { entries: info.texts };
    }, ['S2']);

    // ---------------- S4..S6 (face path)
    await step('S4', 'dialog on Security & Privacy shows 7 days checked', async () => {
      const dialog = dialogLoc();
      const sel = await dialog.getByRole('tab', { name: 'Security & Privacy' }).getAttribute('aria-selected');
      check(sel === 'true', 'the dialog is not on the Security & Privacy tab');
      const rs = await radiosOf(groupOf(dialog));
      const checked = rs.filter((r) => r.checked).map((r) => r.label);
      check(checked.length === 1 && checked[0] === '7 days', `checked radios: ${JSON.stringify(checked)}`);
      return { checked, radios: rs.map((r) => r.label) };
    }, ['S3']);

    await step('S5', 'choose 2 minutes (test): state + line in the face timeline', async () => {
      const dialog = dialogLoc(); const group = groupOf(dialog);
      await pick(group, SHORT_LABEL);
      const want = { max_lifetime: SHORT_MS };
      check(await until(() => stateIs(want)(ADMIN), 20_000), `state is ${JSON.stringify(await retState(ADMIN))}`);
      await closeDialog();
      const tail = `set messages in this room to disappear after ${SHORT_LABEL}.`; const line = `${myName} ${tail}`;
      const ok = await until(async () => !!(await faceLine(myName, tail)), 25_000, 500);
      await shot('S5-face-line');
      R.steps.S5_line = { text: await faceLine(myName, tail), system: await faceSystemFacts(), chain: await faceDomChain('set messages in this room'), cardStillOpen: (await entryLoc().count()) > 0 }; save();
      const t = await faceText();
      check(ok, `the face timeline has no line "${line}"`);
      check(!t.includes(`${myName} ${myName} set messages`), 'the sender name is printed twice in the line');
      return { line };
    }, ['S4']);

    await step('S6', 'face message leaves the timeline; stays gone after reload; server 404', async () => {
      const o = await measureExpiry(ADMIN, 's6', SHORT_MS, HIDE_SLACK_MS / 1000);
      R.steps.S6_measure = o; save();
      check(o.goneAfterS !== null, `the message was still in the face timeline at lifetime + ${HIDE_SLACK_MS / 1000} s`);
      check(o.goneAfterS * 1000 >= SHORT_MS - SKEW_TOLERANCE_MS, `gone too early: ${o.goneAfterS} s`);
      check(o.goneAfterS * 1000 <= SHORT_MS + HIDE_SLACK_MS, `gone too late: ${o.goneAfterS} s`);
      check(o.faceBackAfterReload, 'the face did not come back by itself after the reload');
      check(o.messageAfterReload === 'absent', `after reload the message is ${o.messageAfterReload}`);
      check(o.serverStatusAfterReload === 404, `server status ${o.serverStatusAfterReload}`);
      return o;
    }, ['S5']);

    // ---------------- S7, S8 (face path)
    let posted7 = null;
    await step('S7', 'Off from the face: state, line, message posted now', async () => {
      const info = await openCard(); await entryLoc().first().click(); await dialogLoc().first().waitFor({ timeout: 15_000 });
      await pick(groupOf(dialogLoc()), 'Off');
      check(await until(() => stateIs(OFF)(ADMIN), 20_000), `state is ${JSON.stringify(await retState(ADMIN))}`);
      await closeDialog();
      const tail = 'turned off disappearing messages.'; const line = `${myName} ${tail}`;
      check(await until(async () => !!(await faceLine(myName, tail)), 25_000, 500), `the face timeline has no line "${line}"`);
      R.steps.S7_line = { text: await faceLine(myName, tail), system: await faceSystemFacts() }; save();
      posted7 = await postFromFace(ADMIN, 's7');
      return { line, entries: info.texts };
    }, ['S3', 'S5']);

    await step('S8', 'member view: 7 days checked, radios disabled, hint, click changes nothing, no raw error', async () => {
      await bRet(MEM, { max_lifetime: 604_800_000 });
      check(await until(() => stateIs({ max_lifetime: 604_800_000 })(MEM), 30_000), 'A does not see the 7 days state B set');
      await openFaceRoom('rret-e2e-member');
      await openCard(); await entryLoc().first().click(); await dialogLoc().first().waitFor({ timeout: 15_000 });
      const dialog = dialogLoc(); const group = groupOf(dialog);
      const rs = await radiosOf(group);
      const checked = rs.filter((r) => r.checked).map((r) => r.label);
      check(checked.length === 1 && checked[0] === '7 days', `checked: ${JSON.stringify(checked)}`);
      check(rs.every((r) => r.disabled), `not all radios disabled: ${JSON.stringify(rs.filter((r) => !r.disabled).map((r) => r.label))}`);
      check((await dialog.innerText()).includes('Only room admins can change this.'), 'hint "Only room admins can change this." missing');
      const before = await retState(MEM);
      await group.getByText('1 day', { exact: true }).click({ force: true, timeout: 5000 }).catch(() => {});
      await sleep(3000);
      const after = await retState(MEM);
      check(JSON.stringify(before) === JSON.stringify(after), `state changed ${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
      const raw = /M_FORBIDDEN|user_level/.test((await page.locator('body').innerText()) + ' ' + (await faceText()));
      check(!raw, 'raw error text (M_FORBIDDEN / user_level) is on screen');
      await shot('S8-member-dialog');
      await closeDialog();
      return { checked, allDisabled: true, state: after };
    }, ['S3'], B ? null : NO_B);

    await step('S7b', 'message posted in S7 still there after 150 s (Off)', async () => {
      await openFaceRoom('rret-e2e');
      const left = posted7.ts + 150_000 - (Date.now() + (await skewMs()));
      if (left > 0) await sleep(left);
      check((await faceText()).includes(posted7.text), 'the message is gone from the face timeline after 150 s');
      check((await aEventStatus(ADMIN, posted7.eventId)) === 200, 'server no longer serves the event');
      return { waitedS: 150 };
    }, ['S7']);

    // ---------------- S9 stock
    const stockNotices = async () => {
      await backToStock();
      await openRoomById(page, ADMIN);
      await sleep(3000);
      for (let i = 0; i < 4; i++) { const ex = page.locator('.mx_RoomView_MessageList, main').getByRole('button', { name: 'Expand', exact: true }); if (!(await ex.count())) break; await ex.first().click().catch(() => {}); await sleep(500); }
      return squash(await page.locator('.mx_RoomView_MessageList, main').first().innerText().catch(() => ''));
    };
    await step('S9', 'stock timeline carries the notices of S5 and S7', async () => {
      const t = await stockNotices();
      const a = `${myName} set messages in this room to disappear after ${SHORT_LABEL}.`; const b = `${myName} turned off disappearing messages.`;
      check(t.includes(a), `stock timeline lacks: ${a}`);
      check(t.includes(b), `stock timeline lacks: ${b}`);
      return { both: true };
    }, ['S5', 'S7']);
  } finally {
    await cleanup(ADMIN, MEM);
    R.finished = new Date().toISOString();
    save();
  }
  expect(failed, `failed steps: ${failed.join(', ')}`).toEqual([]);
});
});
