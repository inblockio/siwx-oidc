/**
 * EW-Q1: QR / device-code login with a SECOND DEVICE — the part nothing proves today.
 *
 * WHAT IS ALREADY PROVEN AND IS DELIBERATELY NOT REPEATED HERE:
 *   EW-D1 (ew-device-link.spec.mjs:39)  RFC 8628: /device_authorization -> authorization_pending
 *                                       -> wallet approve -> mat_/mcr_ -> whoami on the linked
 *                                       device_id. Pure HTTP/OIDC. No rendezvous. No crypto.
 *   EW-D2 (ew-device-link.spec.mjs:160) the approval terminal is HONEST: no fabricated crypto
 *                                       claim, and the Q2 dead-end (approver has no published
 *                                       cross-signing master) stays externally detectable.
 *
 * So "siwx-oidc's part works" is settled. What is NOT settled is everything past token
 * issuance, and that is what this file attacks:
 *
 *   Q1-a  Does the MSC4108 rendezvous channel actually carry a realistic payload THROUGH THE
 *         EDGE?  Caddyfile.local:89 carries the comment "(no compression to preserve ETags)"
 *         but there is no `encode off`; the site-level `encode zstd gzip` (Caddyfile.local:30)
 *         covers the block, and Caddy is verifiably gzipping Synapse responses on that vhost.
 *         MSC4108 is ETag-conditional (If-Match uses STRONG comparison, RFC 9110 13.1.1) and
 *         Caddy weakens ETags on compressed responses. Because `encode` only fires above
 *         min_length (512 B), the small initial handshake would pass while a LARGER later
 *         payload -- the secrets bundle -- would break. Symptom: approval succeeds, tokens
 *         issue, logs look clean, client dies 30-60 s later. That is INDISTINGUISHABLE from
 *         the documented Q2 failure mode, which is why this must be tested rather than assumed.
 *
 *   Q1-b  Can a SECOND party actually read what the first wrote? (the "second device" half)
 *
 *   Q1-c  Does Element Web's "Show QR code" really engage the rendezvous, or does it merely
 *         render?  shouldShowQrForLinkNewDevice was shown to evaluate all-true by inspection,
 *         but inspection is not execution.
 *
 *   Q1-d  Regression guard for response_modes_supported. On matrix-js-sdk >= 42 its absence
 *         fails issuer validation, and isSignInWithQRAvailable() returns false on ANY
 *         validation throw -- so the failure surfaces as "Not supported by your account
 *         provider" and silently disables QR device-link. VERIFIED 2026-07-25: the running lab
 *         image emits it; `main` @ d21329e does NOT (grep src/oidc.rs -> 0 hits). This leg
 *         fails against any build from main, which is correct and intended.
 *
 * SERVER CONTRACT USED (verified read-only from the Synapse image overlay,
 * rest/client/rendezvous.py:59-68): MSC4108RendezvousServlet.on_POST performs NO
 * auth.get_user_by_req -- the rendezvous POST is unauthenticated by design, in explicit
 * contrast to the MSC4388 servlets at :80-95 which do check. A not-yet-logged-in device must
 * be able to open a channel, so this test needs no token for legs Q1-a/b.
 *
 * HONESTY CONTRACT: no test.skip; no assertion weakened to get green. What this file CANNOT
 * do is drive a real MSC4108 ECIES handshake -- there is no second Matrix client in this lab.
 * It therefore proves the CHANNEL and the CLIENT ENGAGEMENT, and says so, rather than
 * pretending to prove Phase 4.
 *
 * NOT RUN AS OF 2026-07-25 — authored against a sibling-owned lab; see
 * docs/audits/2026-07-25-recovery-entry-and-qr-capability-audit.md.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  ELEMENT_URL,
  MATRIX_URL,
  SIWX_URL,
} from './helpers/element.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';
import { openSessionsTab } from './helpers/verify-sas.mjs';

const SERVER_NAME = 'localhost';
const RZ_CREATE = '/_matrix/client/unstable/org.matrix.msc4108/rendezvous';

test.beforeAll(async () => {
  await requireElementStack();
});

/** Resolve a rendezvous `url` (may be relative) against the Matrix edge. */
function resolveRzUrl(url) {
  return new URL(url, MATRIX_URL).toString();
}

/**
 * Open a rendezvous channel through the edge.
 * MSC4108: POST -> 201 { url, etag, expires }, ETag also on the response header.
 */
async function createRendezvous(initialBody = 'x') {
  const r = await fetch(`${MATRIX_URL.replace(/\/$/, '')}${RZ_CREATE}`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: initialBody,
  });
  const text = await r.text();
  let body = {};
  try {
    body = JSON.parse(text);
  } catch {
    /* keep raw */
  }
  return {
    status: r.status,
    etag: r.headers.get('etag') ?? body.etag ?? null,
    body,
    raw: text,
  };
}

// ---------------------------------------------------------------------------
// Q1-a — H-V4 falsification: does a realistic (>512 B) payload survive the edge?
// ---------------------------------------------------------------------------

test('EW-Q1-a: rendezvous carries a >512-byte payload with If-Match through the edge', async () => {
  const created = await createRendezvous('handshake');
  expect(
    created.status,
    `MSC4108 rendezvous POST must create a channel (unauthenticated per ` +
      `rest/client/rendezvous.py:59-68). Got ${created.status}: ${created.raw.slice(0, 300)}`,
  ).toBe(201);
  expect(created.body.url, `POST must return a channel url: ${created.raw.slice(0, 300)}`).toBeTruthy();
  expect(created.etag, 'POST must return an ETag for If-Match conditional writes').toBeTruthy();

  const channel = resolveRzUrl(created.body.url);

  // The small-payload path. Caddy's `encode` has a 512-byte min_length default, so this
  // is expected to pass even if compression is on -- it establishes the baseline and
  // proves the failure below is size-dependent, i.e. compression-shaped.
  const small = await fetch(channel, {
    method: 'PUT',
    headers: {
      'content-type': 'text/plain',
      'if-match': created.etag,
      'accept-encoding': 'gzip',
    },
    body: 'a'.repeat(64),
  });
  const smallEtag = small.headers.get('etag');
  expect(
    [200, 202].includes(small.status),
    `small conditional PUT must be accepted; got ${small.status} ` +
      `(content-encoding=${small.headers.get('content-encoding')})`,
  ).toBe(true);
  expect(smallEtag, 'a successful PUT must return the next ETag').toBeTruthy();

  // The realistic path: an MSC4108 secrets bundle is far larger than 512 bytes.
  // This is the leg H-V4 predicts will 412 if Caddy is compressing and weakening ETags.
  const bigBody = 'B'.repeat(1536);
  const big = await fetch(channel, {
    method: 'PUT',
    headers: {
      'content-type': 'text/plain',
      'if-match': smallEtag,
      'accept-encoding': 'gzip',
    },
    body: bigBody,
  });

  expect(
    [200, 202].includes(big.status),
    `H-V4 CONFIRMED if this is 412: a >512-byte conditional PUT was rejected through the ` +
      `edge while a 64-byte one succeeded.\n` +
      `  status              : ${big.status}\n` +
      `  If-Match sent       : ${smallEtag}\n` +
      `  response ETag       : ${big.headers.get('etag')}\n` +
      `  content-encoding    : ${big.headers.get('content-encoding')}\n` +
      `  vary                : ${big.headers.get('vary')}\n` +
      `  -> Caddyfile.local:89 comments "(no compression to preserve ETags)" but has no ` +
      `\`encode off\`; site-level \`encode zstd gzip\` at :30 covers the block. Caddy ` +
      `weakens ETags on compressed responses and RFC 9110 13.1.1 requires STRONG ` +
      `comparison for If-Match. This produces exactly the reported signature: approval ` +
      `succeeds, tokens issue, client dies 30-60 s later mid-Phase-4 -- indistinguishable ` +
      `from the Q2 "approver has no cross-signing private keys" failure mode.`,
  ).toBe(true);

  // A stale If-Match must still be rejected: the conditional semantics MSC4108 relies on
  // have to be real, not merely permissive. Weakening this to get green would defeat the leg.
  const stale = await fetch(channel, {
    method: 'PUT',
    headers: { 'content-type': 'text/plain', 'if-match': created.etag },
    body: 'stale write must not win',
  });
  expect(
    stale.status,
    'a PUT with a superseded If-Match must be rejected with 412 — if this passes, the ' +
      'channel offers no write-ordering guarantee and MSC4108 cannot be safe on it',
  ).toBe(412);
});

// ---------------------------------------------------------------------------
// Q1-b — the "second device" half: another party reads what the first published.
// ---------------------------------------------------------------------------

test('EW-Q1-b: a second party reads the channel content and observes updates via If-None-Match', async () => {
  const created = await createRendezvous('initial');
  expect(created.status).toBe(201);
  const channel = resolveRzUrl(created.body.url);

  const payload = 'MSC4108-payload-' + 'c'.repeat(900);
  const put = await fetch(channel, {
    method: 'PUT',
    headers: { 'content-type': 'text/plain', 'if-match': created.etag },
    body: payload,
  });
  expect(
    [200, 202].includes(put.status),
    `publishing to the channel must succeed; got ${put.status}`,
  ).toBe(true);
  const publishedEtag = put.headers.get('etag');
  expect(publishedEtag).toBeTruthy();

  // Second party: a distinct HTTP client with no shared state, exactly as the scanning
  // device would be.
  const read = await fetch(channel, { headers: { 'accept-encoding': 'gzip' } });
  expect(read.status, 'the second party must be able to GET the channel').toBe(200);
  const got = await read.text();
  expect(
    got,
    `the second party must receive byte-identical content. This is the link the audit ` +
      `lists as UNVERIFIED (C6: "the rendezvous channel actually carries the payload end ` +
      `to end"). Observed content-encoding=${read.headers.get('content-encoding')}, ` +
      `length=${got.length} vs published ${payload.length}.`,
  ).toBe(payload);

  // Long-poll semantics: a GET with the current ETag must not re-deliver, and a
  // subsequent write must become visible. MSC4108's handshake depends on both.
  const notModified = await fetch(channel, {
    headers: { 'if-none-match': read.headers.get('etag') ?? publishedEtag },
  });
  expect(
    [304, 200].includes(notModified.status),
    `conditional GET must answer 304 (or 200 with new content); got ${notModified.status}`,
  ).toBe(true);

  const second = 'second-write-' + 'd'.repeat(700);
  const put2 = await fetch(channel, {
    method: 'PUT',
    headers: {
      'content-type': 'text/plain',
      'if-match': read.headers.get('etag') ?? publishedEtag,
    },
    body: second,
  });
  expect([200, 202].includes(put2.status), `second write must succeed; got ${put2.status}`).toBe(true);

  const read2 = await fetch(channel);
  expect(read2.status).toBe(200);
  expect(
    await read2.text(),
    'the second party must observe the updated payload — a channel that cannot carry a ' +
      'second turn cannot carry an MSC4108 handshake',
  ).toBe(second);
});

// ---------------------------------------------------------------------------
// Q1-c — Element Web really engages the rendezvous when the user asks for a QR.
// ---------------------------------------------------------------------------

test('EW-Q1-c: Element "Show QR code" is enabled and opens a REAL rendezvous session', async ({
  page,
}) => {
  test.setTimeout(480_000);

  // Observe the wire before anything navigates.
  const rendezvousPosts = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().includes('org.matrix.msc4108/rendezvous')) {
      rendezvousPosts.push(r.url());
    }
  });

  const w = makeWallet(undefined, SERVER_NAME);
  await injectMockWallet(page, w);

  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  await page.getByRole('button', { name: 'Skip for now' }).click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });

  // Complete the mandatory first-device Secure Backup wizard. A cross-signing-ready
  // session is the precondition for the QR offer (shouldShowQrForLinkNewDevice's third
  // conjunct), so skipping it would make this leg vacuous.
  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });
  if (!(await chat.count())) {
    await btn(/^Continue$/).click();
    await btn(/^Copy$/).click({ timeout: 120_000 });
    await btn(/^Continue$/).click({ timeout: 30_000 });
    await btn(/^Done$/).click({ timeout: 60_000 });
    await chat.waitFor({ timeout: 90_000 });
  }

  // Settings -> Sessions. SessionManagerTab renders <LoginWithQRSection/> unconditionally;
  // only the button's `disabled` is gated, so reaching the section proves nothing on its own.
  // NOT `page.goto('#/settings/sessions')`. Element 1.12.20's MatrixChat.showScreen
  // matches `screen === "settings"` EXACTLY (MatrixChat.tsx:1899) -- there is no
  // `settings/...` prefix branch, so "settings/sessions" falls through every branch and
  // NOTHING is dispatched. The settings dialog never opens, SessionManagerTab never
  // mounts, and LoginWithQRSection is legitimately absent. This spec's original failure
  // was that no-op, not a missing feature. (`#/settings` alone is also wrong -- it opens
  // UserTab.Account.) Drive the real user path instead.
  await openSessionsTab(page);

  const qrSection = page.getByText('Link new device', { exact: false }).first();
  await expect(
    qrSection,
    'Settings -> Sessions must render the "Link new device" section (LoginWithQRSection)',
  ).toBeVisible({ timeout: 60_000 });

  // The mislabelled failure state. In this deployment the only realisable cause of the
  // disabled button is isCrossSigningReady === false, NOT an OP capability gap — so this
  // string appearing is a client-crypto finding, not a server one.
  await expect(
    page.getByText('Not supported by your account provider', { exact: false }),
    'Element reports the OP does not support QR device-link. In this deployment every ' +
      'server-side conjunct of shouldShowQrForLinkNewDevice is verified true ' +
      '(grant_types_supported includes the device_code grant, org.matrix.msc4108 is ' +
      'advertised, exportSecretsBundle exists), so the real cause is either ' +
      'isCrossSigningReady === false on this session or an auth-metadata validation ' +
      'failure (see EW-Q1-d). The displayed message is misleading in both cases.',
  ).toHaveCount(0);

  const showQr = page.getByRole('button', { name: /show qr code/i }).first();
  await expect(showQr, '"Show QR code" must be present').toBeVisible({ timeout: 30_000 });
  await expect(
    showQr,
    '"Show QR code" must be ENABLED — a rendered-but-disabled button is the ' +
      'Q0/T_OfferWithheld terminal, in which the user never reaches the QR flow at all',
  ).toBeEnabled();

  await showQr.click();

  // The requirement is that clicking engages the SERVER, not that a spinner appears.
  await expect
    .poll(
      () => rendezvousPosts.length,
      {
        timeout: 60_000,
        message:
          'Clicking "Show QR code" did not open an MSC4108 rendezvous session. No POST to ' +
          `${RZ_CREATE} was observed. The affordance renders but does not engage the ` +
          'rendezvous server, so QR device-link cannot work regardless of the server config.',
      },
    )
    .toBeGreaterThan(0);

  // ...and a QR must actually be drawn for a second device to scan.
  const qrRendered = page.locator(// Must include `.mx_LoginWithQR` — that is where Element 1.12.20 paints it.
    // Measured 2026-07-26: the narrower selector missed a QR that WAS rendered, so this
    // test reported "the flow is dead at the display step" for a working flow.
    '.mx_LoginWithQR svg, .mx_LoginWithQR canvas, [data-testid="qr-code"], .mx_QRCode svg, .mx_QRCode canvas');
  await expect(
    qrRendered.first(),
    'a rendezvous session was opened but no QR code was rendered for the second device ' +
      'to scan — the flow is dead at the display step',
  ).toBeVisible({ timeout: 60_000 });
});

// ---------------------------------------------------------------------------
// Q1-d — metadata regression guard. Fails against any build from `main` @ d21329e.
// ---------------------------------------------------------------------------

test('EW-Q1-d: auth metadata advertises response_modes_supported (QR + login guard)', async () => {
  const meta = await (
    await fetch(`${MATRIX_URL.replace(/\/$/, '')}/_matrix/client/v1/auth_metadata`)
  ).json();

  // Preconditions the QR gate reads through the same validated-metadata path.
  expect(
    meta.grant_types_supported,
    'the OP must advertise the device-code grant or isSignInWithQRAvailable() returns false',
  ).toContain('urn:ietf:params:oauth:grant-type:device_code');
  expect(meta.device_authorization_endpoint).toBeTruthy();

  const modes = meta.response_modes_supported;
  expect(
    modes,
    'response_modes_supported is absent from the OP metadata. VERIFIED 2026-07-25: it is ' +
      'emitted by the currently-running lab image but is NOT in `main` @ d21329e ' +
      '(grep response_modes_supported src/oidc.rs -> 0 hits), so any build from main ' +
      'regresses it. On matrix-js-sdk >= 42 (Element Web >= 1.12.24) its absence fails ' +
      'issuer validation; because isSignInWithQRAvailable() returns false on ANY validation ' +
      'throw, this silently disables QR device-link AND mislabels it "Not supported by your ' +
      'account provider", on top of blocking login outright. Fix: advertise ["query", ' +
      '"fragment"] in src/oidc.rs::provider_metadata_value AND honour fragment delivery in ' +
      'sign_in — together, never metadata-only.',
  ).toBeTruthy();
  expect(modes).toContain('query');
  expect(modes).toContain('fragment');
});
