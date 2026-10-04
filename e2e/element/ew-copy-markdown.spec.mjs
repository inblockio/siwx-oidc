/**
 * CM1-CM7: the message context menu's "Copy Markdown" entry on hosted Element
 * Web (siwx-oidc-matrix-server issue #24). Right-click a message, choose "Copy
 * Markdown", and the clipboard holds the message as clean CommonMark + GFM:
 * the sender's own `body` whenever that is provably the Markdown source of what
 * is displayed (whoever sent it: Element, a Rust SDK agent, a plain-body bot),
 * otherwise the message's HTML (`formatted_body`) converted to Markdown, or the
 * plain `body` with its Markdown metacharacters escaped when there is no HTML
 * and the body is not Markdown the leg can know about (CM4).
 *
 * CM1-CM4, CM6 and CM7 send their events through the logged-in client in the
 * page; CM5 types into the real composer. Everything goes into a private
 * ENCRYPTED room (asserted: the room carries an `m.room.encryption` state event,
 * and each client-sent event is fetched back from the homeserver and must be
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
 *       copied without escaping its Markdown and HTML metacharacters. The body
 *       holds raw HTML, which is the reason it must stay escaped: the copy of a
 *       plain body is the body itself only when it is safe Markdown (CM7).
 *   CM5 (round trip of typed Markdown): a synthetic Markdown message (heading,
 *       bold, nested task list, GFM table, soft line breaks, fenced code) is
 *       put on the clipboard, pasted into the room's message composer and sent
 *       with Enter, Element's own send path rather than the client API. The sent
 *       event must be `m.room.encrypted` on the wire, carry the typed text as
 *       `body` byte for byte, and have a string `formatted_body` (logged as
 *       "[CM5] formatted_body"). The leg then right-clicks the tile, clicks "Copy
 *       Markdown" and compares the clipboard (the sentinel is written first) with
 *       the typed text. It fails when the copy is a re-rendering of Element's
 *       lossy display instead of the sender's own Markdown: Element's renderer
 *       has no GFM tables or task lists and turns newlines into <br>, so table
 *       rows come back as `| a | b |\` with escaped pipes, soft breaks as `\`
 *       hard breaks, `- [ ]` as `- \[ \]` and `### 1.` as `### 1\.`. The
 *       clipboard text is logged as "[CM5] clipboard".
 *   CM6 (Rust SDK sender): an event whose `body` is Markdown and whose
 *       `formatted_body` is the REAL rendering of that body by the Rust SDK's
 *       ruma (`RoomMessageEventContent::text_markdown`, see CM6_HTML), sent
 *       through the client API: it is not Element's rendering of the text, so
 *       Element's own composer pipeline cannot be what vouches for it. "Copy
 *       Markdown" must return exactly the body. It fails when the copy is a
 *       conversion of the displayed HTML instead of the sender's source: ruma
 *       renders soft line breaks as `<br />` and the table with a `<thead>`, so
 *       the converter returns a `\` hard break at the end of each soft-broken
 *       line and a re-spaced table delimiter row (`| --- | --- | --- |` for
 *       `|---|---|---|`); nothing else differs. The clipboard text is logged as
 *       "[CM6] clipboard".
 *   CM7 (plain Markdown bot): an `m.text` event with only a `body` (Markdown,
 *       the same text as CM5) and no `format` or `formatted_body`, as bots that
 *       send Markdown as plain text do. "Copy Markdown" must return exactly the
 *       body. It fails when the plain-body path escapes the message: every
 *       metacharacter comes back backslash-escaped (`\#`, `\*\*`, `\``, `\-`,
 *       `\[ \]`, `\|`, so the table and the fenced code are no longer Markdown),
 *       and each line followed by another line of its block ends in a `\` hard
 *       break. The clipboard text is logged as "[CM7] clipboard".
 *
 * Discrimination: run this spec against an Element without the entry (the
 * baseline image); CM1, CM2, CM4, CM5, CM6 and CM7 must fail on the missing
 * "Copy Markdown" menu item while CM3 passes. Against an Element that has the
 * entry but converts only the displayed HTML (the image deployed before the
 * sender-source fix) CM1-CM4 pass and CM5, CM6 and CM7 fail on the clipboard
 * comparison, with the symptoms above visible in the diff. With the fix, all
 * seven pass. CM5 alone cannot tell a general rule from a special case: it only
 * proves the copy for a message Element composed itself. CM6 and CM7 prove the
 * rule holds for senders that are not Element, and CM4 proves it stops where the
 * body is not safe Markdown.
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

/**
 * CM5: what the user types. Synthetic text, no trailing newline. It holds what
 * Element's own renderer cannot show faithfully: a GFM table, a nested task
 * list, soft line breaks inside a paragraph, and a heading that starts with
 * "1.". The leg expects the copy to be this text exactly.
 */
const CM5_INPUT = [
  '### 1. +14.3% overall, driver Alice',
  '',
  '**core-client (main, dev): replace the `../core` path dependency with a git pin on the `vX.Y.Z` tag, then redeploy**',
  '',
  '- Moves: core +57.1%. Overall after this step: 53.9%.',
  '- Repository: `core-client`. Kind: release.',
  '- Tasks:',
  '  - [ ] Alice: cut the first annotated `vX.Y.Z` tag of core.',
  '  - [ ] `core-client`: switch to a git dependency on that tag, commit Cargo.lock, open a PR.',
  '',
  '| train | driver | score | cells |',
  '|---|---|---|---|',
  '| core | Alice | 🟥🟥🚂⬜⬜🏁 42.6% | 13 |',
  '| client | Bob | 🚂⬜⬜⬜⬜🏁 0.0% | 7 |',
  '',
  '- `short-rev`: a `rev = "..."` shorter than 40 characters.',
  '- `url-spelling`: the git URL is spelled differently from `https://example.org/<repo>`.',
  '',
  'Every **cell** is one (consumer, train) pair: each tracked branch that uses the',
  'train, and each deployed service that runs it.',
  '',
  '```',
  'cell  = max(0, value(status) - min(0.05 * flags, 0.15))',
  '```',
].join('\n');

/**
 * CM6: an event as the Rust SDK sends it. Both strings are the fields of
 * `RoomMessageEventContent::text_markdown(md)` for the synthetic Markdown
 * report below, byte for byte, generated with ruma-events 0.33.0 (feature
 * "markdown", which renders with pulldown-cmark 0.13.4). `text_markdown` is given
 * the Markdown without a trailing newline, and so is the `body` it returns.
 * The text has what Element's renderer and ruma disagree on: soft line breaks
 * (ruma renders them as `<br />`), a GFM table (`<thead>`, `|---|` delimiter
 * row), a fenced code block with a language and a pipe in it, a quote and an
 * ordered list. The expected copy is the body itself, no re-rendering.
 */
const CM6_BODY = [
  '# Weekly status report',
  '',
  'Summary of the build and deploy state for the sample project.',
  '',
  '## Findings',
  '',
  'The nightly run finished without errors.',
  'Two services restarted after the config change.',
  'No data was lost.',
  '',
  '- **core-client**: pinned to `v1.2.3`',
  '- **sample-bot**: needs `cargo update -p sample-lib`',
  '- Plain item without markup',
  '',
  '| service | state | notes |',
  '|---|---|---|',
  '| `core-client` | ok | see [docs](https://example.org/docs) |',
  '| `sample-bot` | stale | run `make deploy` |',
  '',
  '```rust',
  'fn main() {',
  '    println!("hello | world");',
  '}',
  '```',
  '',
  '> Quoted advice: restart only after the backup finished.',
  '',
  '1. Cut the tag.',
  '2. Update the pin.',
  '3. Redeploy.',
].join('\n');

const CM6_HTML = [
  '<h1>Weekly status report</h1>',
  '<p>Summary of the build and deploy state for the sample project.</p>',
  '<h2>Findings</h2>',
  '<p>The nightly run finished without errors.<br />',
  'Two services restarted after the config change.<br />',
  'No data was lost.</p>',
  '<ul>',
  '<li><strong>core-client</strong>: pinned to <code>v1.2.3</code></li>',
  '<li><strong>sample-bot</strong>: needs <code>cargo update -p sample-lib</code></li>',
  '<li>Plain item without markup</li>',
  '</ul>',
  '<table><thead><tr><th>service</th><th>state</th><th>notes</th></tr></thead><tbody>',
  '<tr><td><code>core-client</code></td><td>ok</td><td>see <a href="https://example.org/docs">docs</a></td></tr>',
  '<tr><td><code>sample-bot</code></td><td>stale</td><td>run <code>make deploy</code></td></tr>',
  '</tbody></table>',
  '<pre><code class="language-rust">fn main() {',
  '    println!("hello | world");',
  '}',
  '</code></pre>',
  '<blockquote>',
  '<p>Quoted advice: restart only after the backup finished.</p>',
  '</blockquote>',
  '<ol>',
  '<li>Cut the tag.</li>',
  '<li>Update the pin.</li>',
  '<li>Redeploy.</li>',
  '</ol>',
  '',
].join('\n');

/**
 * CM7: a bot that sends Markdown as a plain body, with no `format` and no
 * `formatted_body`. The text is CM5's, which is plain, safe Markdown (no raw
 * HTML, no unsafe link or image), so the expected copy is the body itself.
 */
const CM7_BODY = CM5_INPUT;

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

  /** Fetch the event back from the homeserver; it must be stored as m.room.encrypted. */
  async function expectEncryptedOnTheWire(eventId) {
    const wire = await page.evaluate(
      ({ rid, id }) => window.mxMatrixClientPeg.get().fetchRoomEvent(rid, id),
      { rid: roomId, id: eventId },
    );
    expect(wire.type, 'the event must travel encrypted, like real traffic').toBe('m.room.encrypted');
  }

  /** Send an m.room.message through the client; assert it went out encrypted. */
  async function sendMessage(content) {
    const eventId = await page.evaluate(
      async ({ rid, content }) => {
        const cli = window.mxMatrixClientPeg.get();
        return (await cli.sendEvent(rid, 'm.room.message', content)).event_id;
      },
      { rid: roomId, content },
    );
    await expectEncryptedOnTheWire(eventId);
    return eventId;
  }

  /**
   * Send text the way a user does, through Element's own send path: put it on
   * the clipboard, focus the room's message composer, paste (Control+V), press
   * Enter. Returns the sent event's id and content once the homeserver has
   * accepted it (the local echo has its real id), as the client holds them.
   */
  async function sendThroughComposer(text) {
    const known = await page.evaluate(
      (rid) =>
        window.mxMatrixClientPeg
          .get()
          .getRoom(rid)
          .getLiveTimeline()
          .getEvents()
          .map((e) => e.getId()),
      roomId,
    );
    await page.evaluate((t) => navigator.clipboard.writeText(t), text);
    const composer = page.locator('.mx_MessageComposer [role="textbox"][contenteditable="true"]').first();
    await composer.click();
    await page.keyboard.press('Control+V');
    // The paste landed: the composer holds the last line of the text.
    const lastLine = text.split('\n').at(-1);
    await expect(composer, 'the paste did not reach the message composer').toContainText(lastLine);
    await page.keyboard.press('Enter');

    let sent = null;
    await expect
      .poll(
        async () => {
          sent = await page.evaluate(
            ({ rid, known }) => {
              const cli = window.mxMatrixClientPeg.get();
              const me = cli.getUserId();
              const ev = cli
                .getRoom(rid)
                .getLiveTimeline()
                .getEvents()
                .find((e) => e.getType() === 'm.room.message' && e.getSender() === me && !known.includes(e.getId()));
              // A local echo still has a "~" id; the real one starts with "$".
              return ev && ev.getId().startsWith('$') ? { id: ev.getId(), content: ev.getContent() } : null;
            },
            { rid: roomId, known },
          );
          return sent !== null;
        },
        { timeout: 30_000, message: 'the composer never sent the message (no event with a server id appeared)' },
      )
      .toBe(true);
    return sent;
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

  test('CM5 round trip: Markdown typed in the composer is copied back exactly', async () => {
    const sent = await sendThroughComposer(CM5_INPUT);
    await expectEncryptedOnTheWire(sent.id);

    // The event is what Element's own send path produced for the typed text.
    // eslint-disable-next-line no-console
    console.log(`[CM5] formatted_body:\n${sent.content.formatted_body}`);
    expect(sent.content.body, 'content.body must be exactly what was typed').toBe(CM5_INPUT);
    expect(sent.content.format, 'Element must send the Markdown as HTML').toBe('org.matrix.custom.html');
    expect(typeof sent.content.formatted_body, 'content.formatted_body must be a string').toBe('string');

    await expect(tileOf(sent.id)).toContainText('overall, driver Alice', { timeout: 30_000 });
    await clickCopyMarkdown(sent.id);
    await expect
      .poll(readClipboard, {
        timeout: 10_000,
        message: 'the clipboard still holds the sentinel: "Copy Markdown" copied nothing',
      })
      .not.toBe(SENTINEL);
    const copied = await readClipboard();
    // eslint-disable-next-line no-console
    console.log(`[CM5] clipboard:\n${copied}`);
    expect(copied, 'clipboard after "Copy Markdown" must equal the text that was typed').toBe(CM5_INPUT);
  });

  /**
   * Click "Copy Markdown" on the event's tile and return what is on the clipboard
   * afterwards. The sentinel is written first (clickCopyMarkdown), so a copy that
   * wrote nothing fails here instead of passing on a stale clipboard.
   */
  async function copyMarkdownOf(eventId, tag) {
    await clickCopyMarkdown(eventId);
    await expect
      .poll(readClipboard, {
        timeout: 10_000,
        message: 'the clipboard still holds the sentinel: "Copy Markdown" copied nothing',
      })
      .not.toBe(SENTINEL);
    const copied = await readClipboard();
    // eslint-disable-next-line no-console
    console.log(`[${tag}] clipboard:\n${copied}`);
    return copied;
  }

  test('CM6 Rust SDK sender: the body of a ruma Markdown message is copied back exactly', async () => {
    const id = await sendMessage({
      msgtype: 'm.text',
      body: CM6_BODY,
      format: 'org.matrix.custom.html',
      formatted_body: CM6_HTML,
    });
    await expect(tileOf(id)).toContainText('Weekly status report', { timeout: 30_000 });
    const copied = await copyMarkdownOf(id, 'CM6');
    expect(copied, 'clipboard after "Copy Markdown" must equal the body the SDK sender wrote').toBe(CM6_BODY);
  });

  test('CM7 plain Markdown bot: a body with no HTML is copied back exactly', async () => {
    const id = await sendMessage({ msgtype: 'm.text', body: CM7_BODY });
    await expect(tileOf(id)).toContainText('overall, driver Alice', { timeout: 30_000 });
    const copied = await copyMarkdownOf(id, 'CM7');
    expect(copied, 'clipboard after "Copy Markdown" must equal the plain Markdown body the bot sent').toBe(CM7_BODY);
  });
});
