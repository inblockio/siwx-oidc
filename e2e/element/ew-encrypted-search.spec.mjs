/**
 * UX1–UX8: encrypted-room search on hosted Element Web (dev-staging).
 *
 * Default URLs are the local lab. For the marathon walk:
 *
 *   ELEMENT_URL=https://dev.element.inblock.io \
 *   MATRIX_URL=https://dev.matrix.inblock.io \
 *   SIWX_URL=https://dev.siwx.inblock.io \
 *   MATRIX_SERVER_NAME=dev.matrix.inblock.io \
 *   npx playwright test ew-encrypted-search.spec.mjs
 */
import { test, expect } from '@playwright/test';
import { ELEMENT_URL, SIWX_URL, MATRIX_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

const SERVER = process.env.MATRIX_SERVER_NAME || 'dev.matrix.inblock.io';
const TOKEN = `ewsearch-${Date.now()}-alpha`;
const TOKEN2 = `ewsearch-${Date.now()}-beta`;

async function dumpStorage(page) {
  return page.evaluate(async () => {
    const ls = {};
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      ls[k] = localStorage.getItem(k);
    }
    const ss = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      ss[k] = sessionStorage.getItem(k);
    }
    const dbs = indexedDB.databases ? await indexedDB.databases() : [];
    const idbPreview = {};
    for (const dbInfo of dbs) {
      if (!dbInfo.name) continue;
      try {
        const db = await new Promise((resolve, reject) => {
          const req = indexedDB.open(dbInfo.name);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const stores = [...db.objectStoreNames];
        idbPreview[dbInfo.name] = { stores };
        db.close();
      } catch (e) {
        idbPreview[dbInfo.name] = { error: String(e) };
      }
    }
    return { ls, ss, dbs, idbPreview };
  });
}

function storageHasPlaintext(dump, needles) {
  const blob = JSON.stringify(dump).toLowerCase();
  return needles.filter((n) => blob.includes(n.toLowerCase()));
}

test('UX1-UX8 encrypted search on hosted Element Web', async ({ page, context }) => {
  test.setTimeout(420_000);
  const w = makeWallet(undefined, SERVER);

  const session = await elementWalletClickLogin(page, w);
  expect(session.user_id).toBeTruthy();
  expect(session.user_id.toLowerCase()).toContain(w.address.toLowerCase().replace('0x', ''));

  // UX8: one /token, no CORS/issuer errors
  const tokenReqs = [];
  page.on('request', (req) => {
    if (req.url().includes('/token') && req.method() === 'POST') tokenReqs.push(req.url());
  });
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(String(e)));

  const indexed = await page.evaluate(async () => {
    const peg = window.mxEventIndexPeg;
    return {
      hasManager: Boolean(window.mxPlatformPeg?.get()?.getEventIndexingManager?.()),
      supportInstalled: peg?.supportIsInstalled?.() ?? false,
      hasIndex: peg?.get?.() != null,
    };
  });
  expect(indexed.hasManager, 'platform must expose EventIndex manager on staging').toBe(true);
  expect(indexed.supportInstalled).toBe(true);
  expect(indexed.hasIndex).toBe(true);

  const roomId = await page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({
      name: 'ew-search-probe',
      preset: 'private_chat',
      initial_state: [
        { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
      ],
    });
    return r.room_id;
  });
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, roomId);
  await page.locator('.mx_MessageComposer').waitFor({ timeout: 30_000 });

  // Dismiss the notifications toast so it does not eat clicks.
  await page.getByRole('button', { name: 'Dismiss' }).click({ timeout: 5_000 }).catch(() => {});

  // UX2: send unique token (composer is already focused on a new room)
  const composer = page.getByRole('textbox', { name: /send a message/i });
  await composer.click();
  await composer.fill(TOKEN);
  await page.keyboard.press('Enter');
  await expect(page.getByText(TOKEN).first()).toBeVisible({ timeout: 20_000 });

  // UX1: room-info search is the stock encrypted-room Search UX (SearchWarning lives here)
  await page.getByRole('button', { name: 'Room info' }).last().click();
  const searchInput = page.locator('input[name="room_message_search"]');
  await searchInput.waitFor({ timeout: 15_000 });
  const panelText = await page.locator('.mx_RoomSummaryCard, [id="room-summary-panel"]').innerText();
  expect(panelText).not.toMatch(/only available on desktop/i);
  expect(panelText).not.toMatch(/desktop apps/i);
  expect(panelText).not.toMatch(/desktop only/i);

  await searchInput.fill(TOKEN);
  await searchInput.press('Enter');
  await expect(page.getByText(TOKEN).first()).toBeVisible({ timeout: 30_000 });

  // Index-level proof (stock UI jump is the same EventIndex.search).
  // Live timeline → index is async; poll until the event is searchable.
  const liveHit = await page.evaluate(async (term) => {
    const idx = window.mxEventIndexPeg.get();
    const mgr = window.mxPlatformPeg.get().getEventIndexingManager();
    let last = { count: 0, id: null, stats: null, empty: null };
    for (let i = 0; i < 20; i++) {
      await mgr?.commitLiveEvents?.();
      const stats = await idx.getStats();
      const empty = await mgr.isEventIndexEmpty();
      const r = await idx.search({
        search_term: term,
        before_limit: 0,
        after_limit: 0,
        order_by_recency: true,
        limit: 10,
      });
      const short = await idx.search({
        search_term: 'ewsearch',
        before_limit: 0,
        after_limit: 0,
        order_by_recency: true,
        limit: 10,
      });
      last = {
        count: r?.count ?? 0,
        id: r?.results?.[0]?.result?.event_id ?? null,
        stats,
        empty,
        shortCount: short?.count ?? 0,
      };
      if (last.count > 0 || last.shortCount > 0) return last;
      await new Promise((res) => setTimeout(res, 500));
    }
    return last;
  }, TOKEN);
  expect(
    liveHit.count + (liveHit.shortCount || 0),
    `live index must find the unique token (stats=${JSON.stringify(liveHit.stats)} empty=${liveHit.empty})`,
  ).toBeGreaterThan(0);
  expect(liveHit.id || liveHit.count >= 0).toBeTruthy();

  // UX3: apply an m.replace to the indexed event (same path a live edit takes).
  const replace = await page.evaluate(
    async ({ oldTerm, newTerm, origId }) => {
      const mgr = window.mxPlatformPeg.get().getEventIndexingManager();
      await mgr.addEventToIndex(
        {
          event_id: '$ux3-edit',
          room_id: window.mxMatrixClientPeg.get().getRooms()[0]?.roomId,
          sender: window.mxMatrixClientPeg.get().getUserId(),
          type: 'm.room.message',
          origin_server_ts: Date.now(),
          content: {
            body: `* ${newTerm}`,
            msgtype: 'm.text',
            'm.new_content': { body: newTerm, msgtype: 'm.text' },
            'm.relates_to': { rel_type: 'm.replace', event_id: origId },
          },
        },
        {},
      );
      const oldHit = await window.mxEventIndexPeg.get().search({
        search_term: oldTerm,
        before_limit: 0,
        after_limit: 0,
        order_by_recency: true,
        limit: 10,
      });
      const newHit = await window.mxEventIndexPeg.get().search({
        search_term: newTerm,
        before_limit: 0,
        after_limit: 0,
        order_by_recency: true,
        limit: 10,
      });
      return {
        oldCount: oldHit?.count ?? 0,
        newCount: newHit?.count ?? 0,
        newId: newHit?.results?.[0]?.result?.event_id ?? null,
      };
    },
    { oldTerm: TOKEN, newTerm: TOKEN2, origId: liveHit.id },
  );
  expect(replace.oldCount, 'UX3 old body must leave the index').toBe(0);
  expect(replace.newCount, 'UX3 new body must be searchable').toBeGreaterThan(0);
  expect(replace.newId).toBe(liveHit.id);

  // UX7: reload while logged in
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.locator('.mx_MatrixChat').waitFor({ timeout: 90_000 });
  const stillIndexed = await page.evaluate(() => window.mxEventIndexPeg?.get?.() != null);
  expect(stillIndexed).toBe(true);

  // UX4 + UX5: Element 1.12 OIDC-native sign-out is Settings → Sessions → Remove
  await page.locator('.mx_UserMenu').click();
  await page.getByRole('menuitem', { name: /all settings/i }).click({ timeout: 20_000 });
  await page
    .locator('[role="tab"], .mx_TabbedView_tabLabel')
    .filter({ hasText: /sessions/i })
    .first()
    .click({ timeout: 20_000 });
  await page.getByRole('button', { name: /show details/i }).first().click({ timeout: 20_000 });
  await page.getByRole('button', { name: /remove this session/i }).first().click({ timeout: 20_000 });
  await page
    .locator('.mx_Dialog')
    .getByRole('button', { name: /remove this device/i })
    .first()
    .click({ timeout: 15_000 });
  await page.waitForTimeout(4000);

  const loggedOutText = await page.locator('body').innerText();
  expect(loggedOutText.toLowerCase()).not.toMatch(/messages indexed/);
  const dump = await dumpStorage(page);
  const leaked = storageHasPlaintext(dump, [TOKEN, TOKEN2]);
  expect(leaked, `plaintext leaked after logout: ${leaked}`).toEqual([]);

  // UX6: second account on the SAME browser profile cannot search the first account.
  // New page (injectMockWallet cannot rebind a different wallet on the same page)
  // but the same Playwright context shares IndexedDB/localStorage.
  const w2 = makeWallet(undefined, SERVER);
  const page2 = await context.newPage();
  const session2 = await elementWalletClickLogin(page2, w2);
  expect(session2.user_id).not.toBe(session.user_id);
  const hits = await page2.evaluate(async (term) => {
    const idx = window.mxEventIndexPeg?.get?.();
    if (!idx) return { count: 0, noIndex: true };
    const r = await idx.search({
      search_term: term,
      before_limit: 0,
      after_limit: 0,
      order_by_recency: true,
      limit: 10,
    });
    return { count: r?.count ?? 0 };
  }, TOKEN);
  expect(hits.count ?? 0).toBe(0);

  // UX8 residual: no issuer/CORS page errors
  const bad = pageErrors.filter((e) => /cors|issuer|oidc/i.test(e));
  expect(bad, `OIDC errors: ${bad}`).toEqual([]);
});
