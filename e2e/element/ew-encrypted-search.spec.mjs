/**
 * UX1–UX8 — search in encrypted rooms on hosted Element Web, through the
 * browser EventIndex (siwx-oidc-matrix-server patches/element-web/README.md,
 * entry 6: browser-eventindex.patch, upstream element-hq/element-web#34718).
 *
 * This is the leg in this suite that the patch registry's rule 2 asks for. The
 * patch also carries upstream's own Playwright spec
 * (apps/web/playwright/e2e/crypto/web-event-index.spec.ts), but that one runs
 * inside an element-web checkout with a password user. This one drives a
 * DEPLOYED Element Web build (every vendored patch in Dockerfile order, the
 * served config.json) and signs in through siwx-oidc, so it is what to re-run
 * when the patch is forward-ported to a new Element tag, and when #34718 merges
 * and the patch is retired. The UX numbering follows the acceptance script
 * siwx-oidc-matrix-server docs/2026-08-14-encrypted-search-ux-script.md.
 *
 * PRECONDITION: the feature is a labs flag, default OFF. The target's
 * config.json must set `features.feature_web_event_index: true` (the local lab
 * config does); beforeAll fails naming the key otherwise.
 *
 * WHAT WOULD TURN EACH LEG RED:
 *
 *   UX1 (search is offered): the room-info search field is missing, or the
 *       panel shows the "only available on desktop" dead end that stock Element
 *       Web shows for an encrypted room.
 *   UX2 (unique token is found): a message typed into a new encrypted room is
 *       not rendered in the search results panel within 30 s (the search is
 *       re-submitted, because one run before indexing answers "No results"
 *       for good), or EventIndex.search does not return it with an event id.
 *   UX3 (edit): after an m.replace for that event, the old body is still
 *       searchable, the new body is not, or the hit is not filed under the
 *       ORIGINAL event id (Seshat semantics). The replacement is fed to the
 *       manager the way the live timeline feeds it, not typed through the
 *       composer's edit UI.
 *   UX7 (reload): after a reload while logged in there is no index.
 *   UX4 (logout): the logged-out tab still shows "messages indexed".
 *   UX5 (storage): either token appears in localStorage or sessionStorage, or
 *       in an IndexedDB database or store name, of the logged-out tab or of
 *       the Element origin. IndexedDB RECORD CONTENTS are not read here: the
 *       ciphertext-at-rest proof is the patch's vitest suite and
 *       siwx-oidc-matrix-server scripts/browser-eventindex-invariants.mjs.
 *   UX6 (second account, same browser profile): the second account has no
 *       index (which would make the next check vacuous), or its index finds
 *       the first account's token.
 *   UX8 (siwx login unchanged): either login fails to get through the siwx UI
 *       and the Secure Backup wizard, the first account is not the Matrix user
 *       derived from its DID, or an uncaught page error mentioning CORS,
 *       issuer or OIDC fires after the first login.
 *
 * TARGET: ELEMENT_URL / MATRIX_URL / SIWX_URL (defaults: local lab). Against a
 * remote (non-production) deployment: ELEMENT_URL=https://element.example.org
 * MATRIX_URL=https://matrix.example.org SIWX_URL=https://siwx.example.org.
 * Creates two throwaway did:pkh accounts per run (fresh random wallets) and one
 * private encrypted room named "ew-search-probe", and logs both MXIDs as
 * "[UX] account <mxid>". The first account is signed out through Settings →
 * Sessions, which removes its device. Nothing else is touched. Cleanup on a
 * shared deployment: deactivate exactly the logged MXIDs through the Synapse
 * admin API with a token from siwx-oidc's POST /oauth2/admin_token.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import { localpartFor } from '../browser/mxid-helper.mjs';

const LABS_FLAG = 'feature_web_event_index';
const TOKEN = `ewsearch-${Date.now()}-alpha`;
const TOKEN2 = `ewsearch-${Date.now()}-beta`;

test.beforeAll(async () => {
  await requireElementStack();
  const configUrl = new URL('/config.json', ELEMENT_URL).href;
  let features;
  try {
    features = (await (await fetch(configUrl)).json()).features ?? {};
  } catch (e) {
    throw new Error(`Could not read ${configUrl}: ${e}`);
  }
  if (features[LABS_FLAG] !== true) {
    throw new Error(
      `Encrypted search is off on this target: ${configUrl} does not set ` +
        `features.${LABS_FLAG}: true, so there is nothing to test.`,
    );
  }
});

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
    return { origin: location.origin, ls, ss, dbs, idbPreview };
  });
}

function storageHasPlaintext(dump, needles) {
  const blob = JSON.stringify(dump).toLowerCase();
  return needles.filter((n) => blob.includes(n.toLowerCase()));
}

test('UX1-UX8 encrypted search on hosted Element Web', async ({ page, context }) => {
  test.setTimeout(420_000);
  const w = makeWallet();

  const session = await elementWalletClickLogin(page, w);
  console.log(`[UX] account ${session.user_id}`);
  // A fresh wallet is a new identity, so it gets the modern opaque localpart.
  expect(session.user_id.split(':')[0]).toBe(`@${localpartFor(w.did)}`);

  // UX8: no CORS/issuer page errors
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
  expect(indexed.hasManager, 'platform must expose an EventIndex manager with the labs flag on').toBe(true);
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

  // UX2 through the UI: the hit must render in the search RESULTS panel, not
  // merely somewhere on the page (the timeline shows the message too). A
  // search is one-shot, so re-submit it until indexing has caught up.
  const results = page.locator('.mx_RoomView_searchResultsPanel');
  await expect(async () => {
    await searchInput.fill('');
    await searchInput.fill(TOKEN);
    await searchInput.press('Enter');
    await expect(results.getByText(TOKEN)).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 30_000, intervals: [1_000] });

  // Index-level proof (the stock UI calls the same EventIndex.search), and the
  // event id UX3 edits.
  const liveHit = await page.evaluate(async (term) => {
    const idx = window.mxEventIndexPeg.get();
    const mgr = window.mxPlatformPeg.get().getEventIndexingManager();
    let last = { count: 0, id: null, stats: null, empty: null };
    for (let i = 0; i < 20; i++) {
      await mgr?.commitLiveEvents?.();
      const r = await idx.search({
        search_term: term,
        before_limit: 0,
        after_limit: 0,
        order_by_recency: true,
        limit: 10,
      });
      last = {
        count: r?.count ?? 0,
        id: r?.results?.[0]?.result?.event_id ?? null,
        stats: await idx.getStats(),
        empty: await mgr.isEventIndexEmpty(),
      };
      if (last.count > 0) return last;
      await new Promise((res) => setTimeout(res, 500));
    }
    return last;
  }, TOKEN);
  expect(
    liveHit.count,
    `live index must find the unique token (stats=${JSON.stringify(liveHit.stats)} empty=${liveHit.empty})`,
  ).toBeGreaterThan(0);
  expect(liveHit.id, 'the hit must carry the event id that UX3 edits').toBeTruthy();

  // UX3: apply an m.replace to the indexed event (same path a live edit takes).
  const replace = await page.evaluate(
    async ({ oldTerm, newTerm, origId, rid }) => {
      const mgr = window.mxPlatformPeg.get().getEventIndexingManager();
      await mgr.addEventToIndex(
        {
          event_id: '$ux3-edit',
          room_id: rid,
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
    { oldTerm: TOKEN, newTerm: TOKEN2, origId: liveHit.id, rid: roomId },
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
  // A logged-out Element may bounce straight on to the siwx login page, so the
  // tab alone can end up on the wrong origin: also inspect the Element origin
  // itself, from a static file that does not boot the app.
  const probe = await context.newPage();
  await probe.goto(new URL('/config.json', ELEMENT_URL).href);
  const dumps = [await dumpStorage(page), await dumpStorage(probe)];
  await probe.close();
  const leaked = storageHasPlaintext(dumps, [TOKEN, TOKEN2]);
  expect(leaked, `plaintext leaked after logout: ${leaked}`).toEqual([]);

  // UX6: second account on the SAME browser profile cannot search the first account.
  // New page (injectMockWallet cannot rebind a different wallet on the same page)
  // but the same Playwright context shares IndexedDB/localStorage.
  // Close the first tab first. Signed out, it stays on #/welcome with Element
  // still running and holding Element's one-tab session lock, and the second
  // login then ends on "connected in another tab" instead of the Secure Backup
  // wizard. Closing it changes nothing UX6 checks: storage belongs to the
  // context, not the tab.
  await page.close();
  const w2 = makeWallet();
  const page2 = await context.newPage();
  // UX8: the second tab's page errors count too, second login included
  page2.on('pageerror', (e) => pageErrors.push(String(e)));
  const session2 = await elementWalletClickLogin(page2, w2);
  console.log(`[UX] account ${session2.user_id}`);
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
    return { count: r?.count ?? 0, noIndex: false };
  }, TOKEN);
  expect(hits.noIndex, 'the second account must have an index, or a zero-hit search proves nothing').toBe(
    false,
  );
  expect(hits.count).toBe(0);

  // UX8 residual: no issuer/CORS page errors
  const bad = pageErrors.filter((e) => /cors|issuer|oidc/i.test(e));
  expect(bad, `OIDC errors: ${bad}`).toEqual([]);
});
