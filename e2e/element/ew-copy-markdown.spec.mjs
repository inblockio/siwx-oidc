/**
 * CM1-CM4: the message context menu's "Copy Markdown" entry on hosted Element
 * Web (siwx-oidc-matrix-server issue #24). Right-click a message, choose "Copy
 * Markdown", and the clipboard holds the message as clean CommonMark + GFM,
 * converted from the message's HTML (`formatted_body`), or from the plain `body`
 * with its Markdown metacharacters escaped when there is no HTML.
 *
 * Every event is sent through the logged-in client in the page, into a private
 * ENCRYPTED room (asserted: the room carries an `m.room.encryption` state event,
 * and each sent event is fetched back from the homeserver and must be
 * `m.room.encrypted`), so the menu is exercised on events that were decrypted
 * locally, like real traffic. Clipboard access is granted to the browser context
 * (`clipboard-read`, `clipboard-write`; localhost is a secure context) and read
 * back with `navigator.clipboard.readText()` in the page.
 *
 * WHAT WOULD TURN EACH LEG RED:
 *
 *   CM1 (position): the text message's context menu has no "Copy Markdown"
 *       entry, or the entry is not immediately followed by "Pin". Against an
 *       Element without the entry this fails on the "Copy Markdown" lookup.
 *   CM2 (content after edit): the entry is missing, or the clipboard after
 *       clicking it differs by a single character from the expected Markdown
 *       for the EDITED message (heading, link, strikethrough, underline kept as
 *       plain text, nested list, fenced code with language, GFM table). The
 *       original body "draft" must not be what is copied: the edit's
 *       `m.new_content` is.
 *   CM3 (absent on media): an `m.image` event shows a "Copy Markdown" entry. The
 *       leg asserts "View source" is visible first, so a menu that never opened
 *       cannot pass vacuously. Green against an Element without the entry too,
 *       so on its own it proves nothing about the feature: it guards the
 *       opposite direction.
 *   CM4 (plain body escaped): the entry is missing, or a message with no HTML is
 *       copied without escaping its Markdown and HTML metacharacters.
 *
 * Discrimination: run this spec against an Element without the entry (the
 * baseline image); CM1, CM2 and CM4 must fail on the missing "Copy Markdown"
 * menu item while CM3 passes.
 *
 * WHY NOT serial MODE: in serial mode the first failure skips every later leg,
 * so a red run would show one failure instead of the full picture. The legs
 * only share a login and a room (beforeAll) and each sends its own events.
 * Playwright restarts the worker after a failing test, which logs in again, so a
 * red run costs one extra login per failure; a green run logs in once.
 *
 * TARGET: ELEMENT_URL / MATRIX_URL / SIWX_URL (defaults: local lab). Creates one
 * throwaway did:pkh account per login (fresh random wallet) and one private
 * encrypted room named "ew-copy-markdown", and logs the account's MXID as "[CM]
 * account <mxid>". Nothing else is touched. Cleanup on a shared deployment:
 * deactivate exactly the logged MXIDs through the Synapse admin API with a token
 * from siwx-oidc's POST /oauth2/admin_token.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

const ENTRY = 'Copy Markdown';
const SENTINEL = 'cm-sentinel-before-copy';

/** CM2: the edited formatted_body. */
const CM2_HTML = [
  '<h2>Plan</h2>',
  '<p>Ask <a href="https://matrix.to/#/@bob:localhost">Bob</a> about <del>old</del> <u>new</u> <a href="https://example.com/docs">docs</a>.</p>',
  '<ul>',
  '<li>one',
  '<ul>',
  '<li>nested</li>',
  '</ul>',
  '</li>',
  '<li>two</li>',
  '</ul>',
  '<pre><code class="language-js">const x = 1;',
  '</code></pre>',
  '<table><thead><tr><th>k</th><th>v</th></tr></thead><tbody><tr><td>a</td><td>1</td></tr></tbody></table>',
].join('\n');

/** CM2: the exact clipboard text expected for CM2_HTML (no trailing newline). */
const CM2_EXPECTED = [
  '## Plan',
  '',
  'Ask [Bob](https://matrix.to/#/@bob:localhost) about ~~old~~ new [docs](https://example.com/docs).',
  '',
  '- one',
  '  - nested',
  '- two',
  '',
  '```js',
  'const x = 1;',
  '```',
  '',
  '| k | v |',
  '| --- | --- |',
  '| a | 1 |',
].join('\n');

/** Plain-text fallback bodies for the CM2 events (deliberately not the expected Markdown). */
const CM2_PLAIN = 'Plan\n\nAsk Bob about old new docs.\n\none\nnested\ntwo\n\nconst x = 1;\n\nk v\na 1';

/** CM4: a body with Markdown and HTML metacharacters, and no HTML. */
const CM4_BODY = '2*3*4 and <b>not bold</b>';
const CM4_EXPECTED = '2\\*3\\*4 and \\<b>not bold\\</b>';

test.describe('Copy Markdown context-menu entry (encrypted room)', () => {
  test.describe.configure({ timeout: 240_000 });

  let context;
  let page;
  let roomId;

  test.beforeAll(async ({ browser }) => {
    await requireElementStack();
    context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    page = await context.newPage();

    const session = await elementWalletClickLogin(page, makeWallet());
    // eslint-disable-next-line no-console
    console.log(`[CM] account ${session.user_id}`);

    roomId = await page.evaluate(async () => {
      const cli = window.mxMatrixClientPeg.get();
      const r = await cli.createRoom({
        name: 'ew-copy-markdown',
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

    // The room must really be encrypted: the state event is on the homeserver,
    // and the client's crypto layer has picked it up.
    const state = await page.evaluate(
      (rid) => window.mxMatrixClientPeg.get().getStateEvent(rid, 'm.room.encryption', ''),
      roomId,
    );
    expect(state.algorithm, 'the test room needs an m.room.encryption state event').toBe(
      'm.megolm.v1.aes-sha2',
    );
    await expect
      .poll(
        () =>
          page.evaluate(
            (rid) => window.mxMatrixClientPeg.get().getCrypto().isEncryptionEnabledInRoom(rid),
            roomId,
          ),
        { timeout: 30_000, message: 'the client never treated the room as encrypted' },
      )
      .toBe(true);
  });

  test.afterEach(async () => {
    // A leg that failed with the menu still open must not leak it into the page.
    await page?.keyboard.press('Escape').catch(() => {});
  });

  test.afterAll(async () => {
    await context?.close();
  });

  /** Send an m.room.message through the client; assert it went out encrypted. */
  async function sendMessage(content) {
    const eventId = await page.evaluate(
      async ({ rid, content }) => {
        const cli = window.mxMatrixClientPeg.get();
        return (await cli.sendEvent(rid, 'm.room.message', content)).event_id;
      },
      { rid: roomId, content },
    );
    const wire = await page.evaluate(
      ({ rid, id }) => window.mxMatrixClientPeg.get().fetchRoomEvent(rid, id),
      { rid: roomId, id: eventId },
    );
    expect(wire.type, 'the event must travel encrypted, like real traffic').toBe('m.room.encrypted');
    return eventId;
  }

  const tileOf = (eventId) => page.locator(`[data-event-id="${eventId}"]`).first();

  /** Right-click the tile (empty right edge of its line, clear of links and media); return the open menu. */
  async function openContextMenu(eventId) {
    const tile = tileOf(eventId);
    await expect(tile).toBeVisible({ timeout: 30_000 });
    await tile.scrollIntoViewIfNeeded();
    const line = tile.locator('.mx_EventTile_line').first();
    const box = await line.boundingBox();
    await line.click({
      button: 'right',
      position: { x: Math.max(box.width - 16, 1), y: Math.min(8, box.height / 2) },
    });
    const menu = page.locator('.mx_ContextualMenu[role="menu"]').last();
    await expect(menu).toBeVisible();
    // The menu really opened: a known entry is there, so an absence below means something.
    await expect(
      menu.getByRole('menuitem', { name: 'View source', exact: true }),
      'the message context menu did not open',
    ).toBeVisible();
    return menu;
  }

  const entryIn = (menu) => menu.getByRole('menuitem', { name: ENTRY, exact: true });

  /** Accessible labels of the menu's items, in DOM order. */
  const labelsOf = (menu) =>
    menu
      .getByRole('menuitem')
      .evaluateAll((els) => els.map((e) => (e.getAttribute('aria-label') ?? e.textContent ?? '').trim()));

  /** Right-click, click "Copy Markdown", return once the menu has closed. */
  async function clickCopyMarkdown(eventId) {
    await page.evaluate((s) => navigator.clipboard.writeText(s), SENTINEL);
    const menu = await openContextMenu(eventId);
    const entry = entryIn(menu);
    await expect(entry, `the "${ENTRY}" menu entry is missing from the message context menu`).toBeVisible({
      timeout: 5_000,
    });
    await entry.click();
    await expect(menu).toBeHidden();
  }

  const readClipboard = () => page.evaluate(() => navigator.clipboard.readText());

  test('CM1 position: "Copy Markdown" sits directly above "Pin"', async () => {
    const id = await sendMessage({ msgtype: 'm.text', body: 'cm1 plain text message' });
    const menu = await openContextMenu(id);
    await expect(entryIn(menu), `the "${ENTRY}" menu entry is missing from the message context menu`).toBeVisible({
      timeout: 5_000,
    });
    const labels = await labelsOf(menu);
    const at = labels.indexOf(ENTRY);
    expect(at, `menu labels: ${JSON.stringify(labels)}`).toBeGreaterThanOrEqual(0);
    expect(labels[at + 1], `"${ENTRY}" must be immediately followed by "Pin"; menu labels: ${JSON.stringify(labels)}`).toBe(
      'Pin',
    );
  });

  test('CM2 content after edit: the edited HTML is copied as Markdown', async () => {
    const id = await sendMessage({
      msgtype: 'm.text',
      body: 'draft',
      format: 'org.matrix.custom.html',
      formatted_body: '<p>draft</p>',
    });
    await expect(tileOf(id)).toContainText('draft');
    await sendMessage({
      msgtype: 'm.text',
      body: `* ${CM2_PLAIN}`,
      'm.new_content': {
        msgtype: 'm.text',
        body: CM2_PLAIN,
        format: 'org.matrix.custom.html',
        formatted_body: CM2_HTML,
      },
      'm.relates_to': { rel_type: 'm.replace', event_id: id },
    });
    // The tile now shows the edited content under the original event id.
    await expect(tileOf(id)).toContainText('Plan', { timeout: 30_000 });
    await expect(tileOf(id)).not.toContainText('draft');

    await clickCopyMarkdown(id);
    await expect
      .poll(readClipboard, { timeout: 10_000, message: 'clipboard after "Copy Markdown" on the edited message' })
      .toBe(CM2_EXPECTED);
  });

  test('CM3 absent on media: an image has no "Copy Markdown" entry', async () => {
    const id = await sendMessage({
      msgtype: 'm.image',
      url: 'mxc://localhost/fake',
      body: 'cat.png',
      info: { mimetype: 'image/png', w: 1, h: 1 },
    });
    const menu = await openContextMenu(id); // asserts the menu is open (View source visible)
    await expect(entryIn(menu)).toHaveCount(0);
    // Same menu, by labels: nothing resembling the entry slipped in under another name.
    const labels = await labelsOf(menu);
    expect(labels.filter((l) => /markdown/i.test(l)), `menu labels: ${JSON.stringify(labels)}`).toEqual([]);
  });

  test('CM4 plain body escaped: no HTML, Markdown and HTML metacharacters escaped', async () => {
    const id = await sendMessage({ msgtype: 'm.text', body: CM4_BODY });
    await expect(tileOf(id)).toContainText('not bold');
    await clickCopyMarkdown(id);
    await expect
      .poll(readClipboard, { timeout: 10_000, message: 'clipboard after "Copy Markdown" on the plain message' })
      .toBe(CM4_EXPECTED);
  });
});
