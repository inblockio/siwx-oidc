/**
 * SW — Element's service worker keeps authenticated media working when its
 * /_matrix/client/versions check fails (siwx-oidc-matrix-server
 * patches/element-web/README.md, entries 9 and 10:
 * sw-versions-no-cache-on-error.patch and sw-media-401-token-retry.patch).
 *
 * The defect: stock sw.js parses the /versions body without a status check and
 * caches the result for 2 h. An error answer (a 401 for an expired stored
 * access token, or a 5xx) has no `versions`, is cached as "no authenticated
 * media", and every later media request of that SW instance goes to the legacy
 * /_matrix/media/v3 endpoints, which a Synapse enforcing authenticated media
 * answers 404. Images stay broken until the browser terminates the SW.
 *
 * HOW THE LEGS FORCE THE CONDITION (read before trusting a green run): every
 * failure is injected with context.route() on requests the SERVICE WORKER sends
 * (route.request().serviceWorker() is set; Chromium routes SW requests since
 * Playwright 1.2x, and SW-1 asserts the route actually fired, so a Playwright
 * that stopped routing SW traffic turns this red instead of vacuously green).
 * The page's own requests pass through untouched, except the one whoami 401 in
 * SW-3 that makes the app refresh its token. The SW is restarted with CDP
 * ServiceWorker.stopAllWorkers, which is what browser idle termination does:
 * its in-memory server-support cache is empty afterwards. Every image is
 * rendered for the first time AFTER the injection, so the browser's image
 * cache cannot mask a broken fetch.
 *
 * WHAT WOULD TURN EACH LEG RED:
 *
 *   SW-1 (authed /versions 401, anonymous 200): red if the image does not
 *        render, if the SW sent any legacy /_matrix/media/v3 request to the
 *        network, if the SW console lacks "retrying without one", or if the
 *        injected 401 never fired. Stock sw.js caches the 401 -> legacy 404.
 *   SW-2 (all SW /versions 503 for one check, then healthy): red if a room
 *        opened after the outage does not render its image, or if the room
 *        opened during the outage does not render on re-open. Stock sw.js
 *        caches the 503 for 2 h.
 *   SW-3 (media 401 with the stored token while the app refreshes it): red if
 *        the image does not render or the SW console lacks "retrying media
 *        request with a refreshed access token". Stock sw.js leaves it blank.
 *
 * Discrimination: run with EW_SW_OVERRIDE=<path to a stock sw.js> (e.g.
 * /app/sw.js from docker.io/vectorim/element-web:v1.12.29) to serve the
 * unpatched service worker instead of the deployment's, through a local
 * pass-through proxy (helpers/stock-sw-proxy.mjs); all three legs must then
 * FAIL. Never point this at production.
 *
 * Network-instrument caveat: request events of a freshly started SW can miss
 * its very first requests, so "zero legacy requests" is a supporting check.
 * The primary signals are the SW console markers and the image render state.
 *
 * TARGET: ELEMENT_URL / MATRIX_URL / SIWX_URL (defaults: local lab). Against
 * dev-staging: ELEMENT_URL=https://dev.element.inblock.io
 * MATRIX_URL=https://dev.matrix.inblock.io SIWX_URL=https://dev.siwx.inblock.io.
 * Creates one throwaway did:pkh account per run (fresh random wallet), five
 * private unencrypted rooms of its own (the text room is named
 * "sw-media-auth text") and four tiny PNGs, and logs the account's MXID as
 * "[SW] account <mxid>". Nothing else is touched and nothing is restarted.
 * Cleanup on a shared deployment: deactivate exactly the logged MXIDs (or the
 * creators of "sw-media-auth text" rooms) through the Synapse admin API with
 * a token from siwx-oidc's POST /oauth2/admin_token.
 */
import fs from 'node:fs';
import zlib from 'node:zlib';
import { test, expect, chromium } from '@playwright/test';
import { startStockSwProxy } from './helpers/stock-sw-proxy.mjs';
import { requireElementStack, ELEMENT_URL, SIWX_URL } from './helpers/element.mjs';
import { completeSecureBackupWizard } from './helpers/element-login.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';

const SW_OVERRIDE = process.env.EW_SW_OVERRIDE;

/** A w x h solid-ish PNG; `seed` varies the colour so every image is distinct. */
function makePng(seed, w = 64, h = 64) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++)
      raw.set([(seed * 53) & 255, (x * 4) & 255, (y * 4) & 255], y * (w * 3 + 1) + 1 + x * 3);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

test.describe.configure({ mode: 'serial', timeout: 240_000 });

let context;
let page;
let swProxy;
let ownBrowser;
/** Room ids: a text-only parking room and one image room per leg (A/B for SW-2). */
const rooms = {};
/** Every SW console line, and every request the SW sent to the network. */
const swConsole = [];
const swRequests = [];

async function login(pg, wallet) {
  await injectMockWallet(pg, wallet);
  await pg.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await pg.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await pg.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  // Deployments differ in the post-signature interstitials (a consent gate, the
  // passkey offer): step through whichever appear until we are back in Element.
  const gate = pg.getByRole('button', { name: 'Continue' }).first();
  const skip = pg.getByRole('button', { name: 'Skip for now' }).first();
  for (let i = 0; i < 3; i++) {
    const which = await Promise.race([
      gate.waitFor({ timeout: 20_000 }).then(() => 'gate').catch(() => null),
      skip.waitFor({ timeout: 20_000 }).then(() => 'skip').catch(() => null),
      pg
        .waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 20_000 })
        .then(() => 'element')
        .catch(() => null),
    ]);
    if (which === 'gate') await gate.click();
    else if (which === 'skip') await skip.click();
    else break;
  }
  await pg.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(pg);
}

function openRoom(roomId) {
  return page.evaluate((rid) => (window.location.hash = `#/room/${rid}`), roomId);
}

/** Wait until the open room shows a media image that actually decoded. */
async function imageRenders(timeout = 30_000) {
  const deadline = Date.now() + timeout;
  let last = [];
  while (Date.now() < deadline) {
    last = await page.evaluate(() =>
      [...document.querySelectorAll('.mx_RoomView_body img')]
        .filter((i) => /_matrix|^blob:/.test(i.currentSrc || i.src))
        .map((i) => ({ loaded: i.complete && i.naturalWidth > 0 })),
    );
    if (last.some((i) => i.loaded)) return true;
    await page.waitForTimeout(500);
  }
  // eslint-disable-next-line no-console
  console.log(`[SW] image state at timeout: ${JSON.stringify(last)}`);
  return false;
}

async function restartServiceWorker() {
  const cdp = await context.newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await cdp.detach();
}

const consoleSince = (n) => swConsole.slice(n).join('\n');
const legacySince = (n) =>
  swRequests.slice(n).filter((p) => p.startsWith('/_matrix/media/v3/')).length;

test.beforeAll(async ({ browser }, testInfo) => {
  await requireElementStack();
  if (SW_OVERRIDE) {
    // A separate browser behind a pass-through proxy that serves the stock
    // sw.js for the Element origin; see helpers/stock-sw-proxy.mjs for why
    // context.route() cannot do this.
    swProxy = await startStockSwProxy({
      elementUrl: ELEMENT_URL,
      swPath: SW_OVERRIDE,
      workDir: testInfo.outputPath('stock-sw-proxy'),
    });
    ownBrowser = await chromium.launch({ headless: true, args: swProxy.launchArgs });
    context = await ownBrowser.newContext();
  } else {
    context = await browser.newContext();
  }
  const hook = (worker) =>
    worker.on('console', (m) => swConsole.push(m.text().replace(/(Bearer\s+)\S+/g, '$1<redacted>')));
  context.on('serviceworker', hook);
  context.on('request', (req) => {
    if (req.serviceWorker()) swRequests.push(new URL(req.url()).pathname);
  });

  page = await context.newPage();
  await login(page, makeWallet());
  // eslint-disable-next-line no-console
  console.log(`[SW] account ${await page.evaluate(() => localStorage.getItem('mx_user_id'))}`);

  // Seed while parked in a text room, so no image is rendered before its leg.
  const pngs = [1, 2, 3, 4].map((s) => makePng(s).toString('base64'));
  Object.assign(
    rooms,
    await page.evaluate(async (images) => {
      const cli = window.mxMatrixClientPeg.get();
      const mk = async (name) =>
        (await cli.createRoom({ name, preset: 'private_chat' })).room_id;
      const text = await mk('sw-media-auth text');
      window.location.hash = `#/room/${text}`;
      const out = { text };
      const names = ['sw1', 'sw2a', 'sw2b', 'sw3'];
      for (let i = 0; i < names.length; i++) {
        const roomId = await mk(`sw-media-auth ${names[i]}`);
        const bytes = Uint8Array.from(atob(images[i]), (c) => c.charCodeAt(0));
        const { content_uri } = await cli.uploadContent(new Blob([bytes], { type: 'image/png' }), {
          type: 'image/png',
          name: `${names[i]}.png`,
        });
        await cli.sendMessage(roomId, {
          msgtype: 'm.image',
          body: `${names[i]}.png`,
          url: content_uri,
          info: { mimetype: 'image/png', size: bytes.length, w: 64, h: 64 },
        });
        out[names[i]] = roomId;
        out[`${names[i]}Media`] = content_uri.split('/').pop();
      }
      return out;
    }, pngs),
  );
  await expect
    .poll(() => page.evaluate(() => !!navigator.serviceWorker.controller), { timeout: 30_000 })
    .toBe(true);
  if (SW_OVERRIDE) {
    // eslint-disable-next-line no-console
    console.log(`[SW] stock sw.js served ${swProxy.served()}x`);
    expect(swProxy.served(), 'EW_SW_OVERRIDE set but /sw.js was never replaced').toBeGreaterThan(0);
    // The installed worker must be the stock one: the patched build logs these.
    expect(swConsole.join('\n')).not.toContain('not caching server support');
  }
});

test.afterAll(async () => {
  await context?.close();
  await ownBrowser?.close();
  await swProxy?.close();
});

test('SW-1: an authenticated /versions 401 is retried anonymously, media stays authenticated', async () => {
  let injected = 0;
  const handler = (route) => {
    const req = route.request();
    if (req.serviceWorker() && req.headers()['authorization']) {
      injected++;
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ errcode: 'M_UNKNOWN_TOKEN', error: 'Token is not active' }),
      });
    }
    return route.fallback();
  };
  const isVersions = (u) => u.pathname === '/_matrix/client/versions';
  await context.route(isVersions, handler);
  const c0 = swConsole.length;
  const r0 = swRequests.length;
  try {
    await restartServiceWorker();
    await openRoom(rooms.sw1);
    const rendered = await imageRenders();
    // eslint-disable-next-line no-console
    console.log(`[SW-1] injected=${injected} legacy=${legacySince(r0)}\n${consoleSince(c0)}`);
    expect(injected, 'the 401 route never fired: Playwright is not routing SW requests').toBeGreaterThan(0);
    expect(rendered, 'image did not render after the authed /versions 401').toBe(true);
    expect(consoleSince(c0)).toContain('retrying without one');
    expect(legacySince(r0), 'SW sent legacy /_matrix/media/v3 requests').toBe(0);
  } finally {
    await context.unroute(isVersions, handler);
    await openRoom(rooms.text);
  }
});

test('SW-2: a failed /versions check is not cached', async () => {
  let failing = true;
  let injected = 0;
  const handler = (route) => {
    if (failing && route.request().serviceWorker()) {
      injected++;
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ errcode: 'M_UNKNOWN', error: 'Service unavailable' }),
      });
    }
    return route.fallback();
  };
  const isVersions = (u) => u.pathname === '/_matrix/client/versions';
  await context.route(isVersions, handler);
  const c0 = swConsole.length;
  try {
    await restartServiceWorker();
    await openRoom(rooms.sw2a);
    await expect.poll(() => injected, { timeout: 30_000 }).toBeGreaterThan(0);
    await page.waitForTimeout(3000); // let the failed check and its media request finish
    failing = false;

    await openRoom(rooms.text);
    await page.waitForTimeout(1000);
    await openRoom(rooms.sw2b);
    const freshRoom = await imageRenders();
    await openRoom(rooms.text);
    await page.waitForTimeout(1000);
    await openRoom(rooms.sw2a);
    const reopened = await imageRenders();
    // eslint-disable-next-line no-console
    console.log(`[SW-2] injected=${injected} fresh=${freshRoom} reopened=${reopened}\n${consoleSince(c0)}`);
    expect(freshRoom, 'image in a room opened after the outage did not render: failure was cached').toBe(true);
    expect(reopened, 'image in the room opened during the outage did not render on re-open').toBe(true);
  } finally {
    await context.unroute(isVersions, handler);
    await openRoom(rooms.text);
  }
});

test('SW-3: a media 401 is retried once the app has refreshed its token', async () => {
  let mediaInjected = 0;
  const mediaHandler = (route) => {
    const req = route.request();
    if (mediaInjected === 0 && req.serviceWorker() && req.headers()['authorization']) {
      mediaInjected++;
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ errcode: 'M_UNKNOWN_TOKEN', error: 'Token is not active' }),
      });
    }
    return route.fallback();
  };
  const isImage = (u) => u.pathname.includes('/_matrix/client/v1/media/') && u.pathname.endsWith(`/${rooms.sw3Media}`);
  // The app refreshes its token on its own next 401: give it exactly one.
  let whoamiInjected = 0;
  const whoamiHandler = (route) => {
    if (whoamiInjected === 0 && !route.request().serviceWorker()) {
      whoamiInjected++;
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ errcode: 'M_UNKNOWN_TOKEN', error: 'Token is not active', soft_logout: false }),
      });
    }
    return route.fallback();
  };
  const isWhoami = (u) => u.pathname === '/_matrix/client/v3/account/whoami';
  await context.route(isImage, mediaHandler);
  await context.route(isWhoami, whoamiHandler);
  const c0 = swConsole.length;
  try {
    await openRoom(rooms.sw3);
    await expect.poll(() => mediaInjected, { timeout: 30_000 }).toBe(1);
    await page.evaluate(() => window.mxMatrixClientPeg.get().whoami());
    const rendered = await imageRenders();
    // eslint-disable-next-line no-console
    console.log(`[SW-3] media401=${mediaInjected} whoami401=${whoamiInjected}\n${consoleSince(c0)}`);
    expect(whoamiInjected).toBe(1);
    expect(rendered, 'image did not render after its 401 and the token refresh').toBe(true);
    expect(consoleSince(c0)).toContain('retrying media request with a refreshed access token');
  } finally {
    await context.unroute(isImage, mediaHandler);
    await context.unroute(isWhoami, whoamiHandler);
  }
});
