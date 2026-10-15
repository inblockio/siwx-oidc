/**
 * EW-S1 - a deleted message that had been edited stays deleted after a NEW device's
 * backward crawl, on hosted Element Web with the browser EventIndex (siwx-oidc-matrix-server
 * patches/element-web entry 6, browser-eventindex.patch).
 *
 * THE DEFECT THIS LEG CATCHES (S1). Element's "Remove" redacts the ORIGINAL event only. The
 * edit (an m.replace event) stays on the server. A crawler that walks a room backward meets
 * the edit first, then the redacted original, and used to rebuild the index record from the
 * edit, so the deleted message came back with its EDITED text. Builds without the redaction
 * tombstones have the defect, so this leg must be RED on them (it is the negative control)
 * and green on a build that carries the fix.
 *
 * WHAT THE LEG DOES. Device 1 signs in a fresh throwaway account (wallet through siwx) and
 * completes the first-device Secure Backup wizard, keeping the recovery key. In a new
 * encrypted room it sends, in order, with one unique token set per run:
 *
 *   C0 control      s1ctl<ts>    never touched (the OLDEST message)
 *   O  original     s1orig<ts>
 *   E  edit of O    s1edit<ts>   a real m.replace, shaped the way Element's composer sends it
 *   K  keep         s1keep<ts>   edited to s1kept<ts> (positive control: edited, NOT deleted)
 *   C1 late         s1late<ts>
 *   then DELETE O (redact the original only, as Element's "Remove" does; E is not redacted)
 *
 * followed by filler messages, so that everything above lies BEHIND the 20 events the new
 * device's initial sync carries and can only reach its index through the backward crawl.
 * Device 1's room keys are waited for on the server's key backup. Device 2 is the same
 * account in a NEW browser context (fresh profile): it passes the new-device gate with the
 * recovery key, restores the key backup, and only then is its crawler let loose (see
 * HOLDING THE CRAWL).
 *
 * WHAT WOULD TURN EACH LEG RED:
 *
 *   LEG-BROKEN (positive controls, never a verdict on S1): device 2 shows no verify gate or
 *       no recovery-key entry; the wizard minted a new key; the search for C0 (the oldest
 *       message, so a hit proves the crawl walked past O, E and the redaction and decrypted
 *       them) never hits within the bound; s1kept<ts> or s1late<ts> is not found.
 *   S1 (the verdict): a search for s1edit<ts> (the deleted message's edited text) or for
 *       s1orig<ts> returns a hit on device 2.
 *
 * HOLDING THE CRAWL. Element's crawler silently drops events it cannot decrypt (stock
 * EventIndex.ts: "TODO if there are no events at this point we're missing a lot decryption
 * keys, do we want to retry this checkpoint at a later stage?") and it starts about 3 s after
 * the first sync, long before anyone can type a recovery key. A crawl that ran behind the
 * gate would find nothing to index and prove nothing about S1. So device 2's context holds
 * every /rooms/<id>/messages request until the key backup is restored, and releases it then.
 * The held request is the crawler's own; nothing else is changed in the page.
 *
 * TARGET: ELEMENT_URL / MATRIX_URL / SIWX_URL, as run.sh passes them. Needs
 * `features.feature_web_event_index: true` in the target's config.json. Creates ONE throwaway
 * did:pkh account per run and one private encrypted room "ew-s1-probe". The MXID is logged as
 * "[S1] account <mxid>" and, when EW_S1_OUT_DIR names a directory, written to account.txt in
 * it with the creation time (UTC), so the operator can deactivate it later. EW_S1_OUT_DIR
 * also receives s1-searches.json and screenshots. Nothing else is touched.
 */
import fs from 'node:fs';
import path from 'node:path';
import { test, expect, devices } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, SIWX_URL } from './helpers/element.mjs';
import { elementWalletLoginNoWizard } from './helpers/verify-sas.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';

const LABS_FLAG = 'feature_web_event_index';
const TS = Date.now();
const TOK = {
  ctl: `s1ctl${TS}`,
  orig: `s1orig${TS}`,
  edit: `s1edit${TS}`,
  keep: `s1keep${TS}`,
  kept: `s1kept${TS}`,
  late: `s1late${TS}`,
};
const FILLERS = 22; // more than the 20 events of Element's initial sync window
const OUT_DIR = process.env.EW_S1_OUT_DIR || '';
const CRAWL_WAIT_MS = 180_000;

function log(line) {
  // eslint-disable-next-line no-console
  console.log(`[S1] ${line}`);
}

async function shot(page, name) {
  if (!OUT_DIR) return;
  try {
    await page.screenshot({ path: path.join(OUT_DIR, `${name}.png`) });
  } catch {
    /* a screenshot never decides a verdict */
  }
}

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

/**
 * First-device login through the real siwx UI, completing the Secure Backup wizard AND
 * keeping the recovery key (helpers/element-login.mjs clicks Copy and discards it).
 */
async function loginKeepingRecoveryKey(page, wallet) {
  await injectMockWallet(page, wallet);
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  await page.getByRole('button', { name: 'Skip for now' }).click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });

  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });
  if (await chat.count()) {
    throw new Error('LEG-BROKEN: device 1 reached the app without the Secure Backup wizard, so there is no recovery key');
  }
  await btn(/^Continue$/).click();
  const keyNode = page.locator('.mx_CreateSecretStorageDialog_recoveryKey code');
  await keyNode.waitFor({ timeout: 120_000 });
  const recoveryKey = (await keyNode.innerText()).trim();
  await btn(/^Copy$/).click({ timeout: 120_000 });
  await btn(/^Continue$/).click({ timeout: 30_000 });
  await btn(/^Done$/).click({ timeout: 60_000 });
  await chat.waitFor({ timeout: 90_000 });

  const session = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
  }));
  if (!session.user_id || !session.device_id) {
    throw new Error('Element session storage missing: ' + JSON.stringify(session));
  }
  return { session, recoveryKey };
}

/** One EventIndex search on a page, the way the stock search calls it. */
async function searchIndex(page, term) {
  return page.evaluate(async (t) => {
    const idx = window.mxEventIndexPeg?.get?.();
    if (!idx) return { noIndex: true, count: 0, ids: [] };
    try {
      await window.mxPlatformPeg.get().getEventIndexingManager().commitLiveEvents?.();
    } catch {
      /* the manager may not expose it; the search below is the judge */
    }
    const r = await idx.search({
      search_term: t,
      before_limit: 0,
      after_limit: 0,
      order_by_recency: true,
      limit: 10,
    });
    return {
      noIndex: false,
      count: r?.count ?? 0,
      ids: (r?.results ?? []).map((x) => x?.result?.event_id ?? null),
    };
  }, term);
}

async function indexStats(page) {
  return page.evaluate(async () => {
    try {
      return await window.mxEventIndexPeg.get().getStats();
    } catch (e) {
      return { error: String(e).slice(0, 200) };
    }
  });
}

test(
  'EW-S1: a deleted edited message stays deleted after a new device\'s backward crawl',
  { tag: '@ew-p6' },
  async ({ browser }) => {
    test.setTimeout(1_200_000);
    const ctxOpts = { ...devices['Desktop Chrome'], baseURL: ELEMENT_URL };
    const w = makeWallet();
    const ctx1 = await browser.newContext(ctxOpts);
    let ctx2 = null;
    let releaseCrawl = () => {};
    try {
      // ------------------------------------------------------------------ device 1
      const page1 = await ctx1.newPage();
      const { session, recoveryKey } = await loginKeepingRecoveryKey(page1, w);
      log(`account ${session.user_id}`);
      if (OUT_DIR) {
        fs.writeFileSync(
          path.join(OUT_DIR, 'account.txt'),
          `${session.user_id} ${new Date().toISOString()}\n`,
          { mode: 0o600 },
        );
      }
      expect(String(recoveryKey).replace(/\s+/g, '').length, 'the wizard must show a recovery key').toBeGreaterThan(40);

      const roomId = await page1.evaluate(async () => {
        const cli = window.mxMatrixClientPeg.get();
        const r = await cli.createRoom({
          name: 'ew-s1-probe',
          preset: 'private_chat',
          initial_state: [
            { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
          ],
        });
        return r.room_id;
      });
      await page1.evaluate((rid) => {
        window.location.hash = `#/room/${rid}`;
      }, roomId);
      await page1.locator('.mx_MessageComposer').waitFor({ timeout: 30_000 });
      await page1.getByRole('button', { name: 'Dismiss' }).click({ timeout: 5_000 }).catch(() => {});

      // The sequence. The client sends exactly what Element's composer sends: a plain
      // m.text, an m.replace with m.new_content for an edit, and a redaction of the
      // original event id for "Remove".
      const sent = await page1.evaluate(
        async ({ rid, tok, fillers }) => {
          const cli = window.mxMatrixClientPeg.get();
          const text = async (body) =>
            (await cli.sendMessage(rid, { msgtype: 'm.text', body })).event_id;
          const edit = async (origId, body) =>
            (
              await cli.sendMessage(rid, {
                msgtype: 'm.text',
                body: `* ${body}`,
                'm.new_content': { msgtype: 'm.text', body },
                'm.relates_to': { rel_type: 'm.replace', event_id: origId },
              })
            ).event_id;
          const ids = {};
          ids.c0 = await text(tok.ctl);
          ids.o = await text(tok.orig);
          ids.e = await edit(ids.o, tok.edit);
          ids.k = await text(tok.keep);
          ids.kEdit = await edit(ids.k, tok.kept);
          ids.c1 = await text(tok.late);
          await cli.redactEvent(rid, ids.o);
          ids.redactedOriginal = ids.o;
          for (let i = 0; i < fillers; i++) await text(`fill${tok.ts}x${i}`);
          return ids;
        },
        { rid: roomId, tok: { ...TOK, ts: TS }, fillers: FILLERS },
      );
      log(`device 1 sent ${Object.keys(sent).length} ids, ${FILLERS} fillers, original redacted (edit not redacted)`);
      await shot(page1, 'd1-after-sends');

      // Device 1's room keys must be on the server's key backup before device 2 starts.
      let backup = null;
      const backupDeadline = Date.now() + 120_000;
      for (;;) {
        backup = await page1.evaluate(async () => {
          const cli = window.mxMatrixClientPeg.get();
          try {
            const v = await cli.http.authedRequest('GET', '/room_keys/version', undefined, undefined, {
              prefix: '/_matrix/client/v3',
            });
            return { version: v.version, count: v.count ?? 0, active: await cli.getCrypto().getActiveSessionBackupVersion() };
          } catch (e) {
            return { error: String(e).slice(0, 200), count: 0 };
          }
        });
        if (backup.count >= 1) break;
        if (Date.now() >= backupDeadline) break;
        await page1.waitForTimeout(3_000);
      }
      log(`device 1 key backup: count=${backup.count} active=${backup.active ?? null} err=${backup.error ?? ''}`);
      expect(
        backup.count,
        `LEG-BROKEN: device 1's room keys never reached the key backup (${JSON.stringify(backup)}), device 2 could not decrypt anything`,
      ).toBeGreaterThanOrEqual(1);

      // ------------------------------------------------------------------ device 2
      ctx2 = await browser.newContext(ctxOpts);
      const crawlGate = new Promise((r) => {
        releaseCrawl = r;
      });
      let held = 0;
      await ctx2.route(/\/_matrix\/client\/v3\/rooms\/[^/]+\/messages/, async (route) => {
        held += 1;
        await crawlGate;
        try {
          await route.continue();
        } catch {
          /* the context closed while the request was held */
        }
      });
      const page2 = await ctx2.newPage();
      const w2 = makeWallet(w.wallet.privateKey);
      const s2 = await elementWalletLoginNoWizard(page2, w2, { timeout: 180_000 });
      log(`device 2 landed on surface=${s2.surface}`);
      await shot(page2, 'd2-landing');
      expect(s2.user_id, 'device 2 must be the same account').toBe(session.user_id);
      expect(s2.device_id, 'device 2 must be a different device').not.toBe(session.device_id);
      expect(
        s2.surface,
        `LEG-BROKEN: device 2 must stop at the verify gate (an existing account with a recovery key); got ${s2.surface}: ${s2.text}`,
      ).toBe('verify-gate');

      await page2.getByRole('button', { name: /use recovery key/i }).click({ timeout: 60_000 });
      const entry = page2.locator('.mx_AccessSecretStorageDialog_recoveryKeyEntry');
      await entry.waitFor({ timeout: 60_000 });
      await entry.locator('input').first().fill(recoveryKey);
      await page2.locator('.mx_AccessSecretStorageDialog').getByRole('button', { name: /^Continue$/ }).click();
      const done = page2.locator('.mx_CompleteSecurityBody').getByRole('button', { name: /^Done$/ });
      const chat2 = page2.locator('.mx_MatrixChat');
      await done.or(chat2).first().waitFor({ timeout: 180_000 });
      if (await done.count()) await done.click();
      await chat2.waitFor({ timeout: 180_000 });
      log('device 2 passed the gate with the recovery key');

      // Decrypt history: load the backup key, restore the backup, then release the crawl.
      const restore = await page2.evaluate(async () => {
        const c = window.mxMatrixClientPeg.get().getCrypto();
        const out = {};
        const deadline = Date.now() + 60_000;
        for (;;) {
          out.hasKey = !!(await c.getSessionBackupPrivateKey());
          if (out.hasKey || Date.now() > deadline) break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        if (!out.hasKey) {
          try {
            await c.loadSessionBackupPrivateKeyFromSecretStorage();
            out.loaded = true;
          } catch (e) {
            out.loadErr = String(e).slice(0, 200);
          }
        }
        try {
          await c.checkKeyBackupAndEnable();
        } catch (e) {
          out.checkErr = String(e).slice(0, 200);
        }
        out.version = (await c.getActiveSessionBackupVersion()) ?? null;
        try {
          const r = await c.restoreKeyBackup();
          out.total = r?.total ?? null;
          out.imported = r?.imported ?? null;
        } catch (e) {
          out.restoreErr = String(e).slice(0, 200);
        }
        return out;
      });
      log(`device 2 backup restore: ${JSON.stringify(restore)} heldMessagesRequests=${held}`);
      expect(
        restore.imported ?? 0,
        `LEG-BROKEN: device 2 restored no room keys from the backup (${JSON.stringify(restore)})`,
      ).toBeGreaterThanOrEqual(1);
      await shot(page2, 'd2-after-unlock');

      releaseCrawl();
      log('crawl released');

      // ------------------------------------------------------------ wait for C0
      const searches = [];
      const record = async (label, term) => {
        const r = await searchIndex(page2, term);
        const stats = await indexStats(page2);
        const row = { label, term, hits: r.count, noIndex: r.noIndex, ids: r.ids, stats };
        searches.push(row);
        log(`search ${label} term=${term} hits=${r.count} noIndex=${r.noIndex} stats=${JSON.stringify(stats)}`);
        return r;
      };

      const crawlStart = Date.now();
      let c0 = null;
      let tick = 0;
      while (Date.now() - crawlStart < CRAWL_WAIT_MS) {
        const r = await searchIndex(page2, TOK.ctl);
        if (r.count > 0) {
          c0 = r;
          break;
        }
        tick += 1;
        if (tick % 4 === 1) {
          log(`waiting for C0 (${Math.round((Date.now() - crawlStart) / 1000)}s) noIndex=${r.noIndex} stats=${JSON.stringify(await indexStats(page2))}`);
        }
        await page2.waitForTimeout(5_000);
      }
      const crawlSecs = Math.round((Date.now() - crawlStart) / 1000);
      await shot(page2, 'd2-after-crawl');
      if (!c0) {
        await record('C0-final', TOK.ctl);
        if (OUT_DIR) fs.writeFileSync(path.join(OUT_DIR, 's1-searches.json'), JSON.stringify({ tokens: TOK, searches }, null, 2));
        throw new Error(
          `LEG-BROKEN: the oldest message ${TOK.ctl} was not in device 2's index after ${CRAWL_WAIT_MS / 1000}s, ` +
            'so the crawl never walked the history; this run says nothing about S1',
        );
      }
      log(`C0 found after ${crawlSecs}s, /messages requests seen on device 2 so far: ${held}`);
      await page2.waitForTimeout(5_000); // let a trailing batch and the tombstone release land

      // ------------------------------------------------------------------ verdicts
      await record('C0', TOK.ctl);
      const kept = await record('K-edited-kept', TOK.kept);
      const late = await record('C1-late', TOK.late);
      const keepOld = await record('K-original-text', TOK.keep);
      const edit = await record('E-deleted-edit-text', TOK.edit);
      const orig = await record('O-deleted-original', TOK.orig);
      const finalStats = await indexStats(page2);
      log(`final stats ${JSON.stringify(finalStats)} crawlSecs=${crawlSecs}`);

      const report = {
        tokens: TOK,
        crawlSecs,
        messagesRequestsOnDevice2: held,
        redactionTombstonesInStats: 'redactionTombstones' in (finalStats ?? {}),
        searches,
      };
      const body = JSON.stringify(report, null, 2);
      await test.info().attach('s1-searches.json', { body, contentType: 'application/json' });
      if (OUT_DIR) fs.writeFileSync(path.join(OUT_DIR, 's1-searches.json'), body);

      // Positive controls first: if one fails the leg is broken, not S1.
      expect(kept.count, `LEG-BROKEN: the edited, not deleted message ${TOK.kept} was not found by its new text`).toBeGreaterThan(0);
      expect(late.count, `LEG-BROKEN: the late message ${TOK.late} was not found`).toBeGreaterThan(0);

      // The S1 verdict, with the edited-not-deleted message's old text beside it (soft, so
      // that every count is reported when one fails).
      expect.soft(
        keepOld.count,
        `the kept message was found by its OLD text ${TOK.keep}: the edit did not replace the record`,
      ).toBe(0);
      expect.soft(
        edit.count,
        `S1: the deleted message came back with its EDITED text (${TOK.edit}) after the backward crawl`,
      ).toBe(0);
      expect.soft(
        orig.count,
        `S1: the deleted message is searchable by its original text (${TOK.orig})`,
      ).toBe(0);
    } finally {
      releaseCrawl();
      if (ctx2) await ctx2.close().catch(() => {});
      await ctx1.close().catch(() => {});
    }
  },
);
