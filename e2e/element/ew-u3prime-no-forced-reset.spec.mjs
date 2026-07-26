/**
 * EW-U3P: **U3′ — an indeterminate 4S probe must NEVER take the destructive branch.**
 *
 * (Coverage matrix §6.2 "U3′", §8 gap #1: *"Then a lab test: blip the probe, assert no
 * new default key."* This file is that test. Until it exists, U3′ is code-closed and
 * UNWATCHED — the register's own worst state, silent AND destructive.)
 *
 * ---------------------------------------------------------------------------
 * THE STATE UNDER WATCH
 * ---------------------------------------------------------------------------
 * `patches/element-web/force-first-device-recovery.patch`, inside
 * `onCompleteSecurityE2eSetupFinished`, decides RESET vs UNLOCK:
 *
 *     const hasExisting4S = await cli.http
 *         .authedRequest("GET", "/user/<uid>/account_data/m.secret_storage.default_key")
 *         .then(() => true)
 *         .catch((e) => e?.errcode !== "M_NOT_FOUND");      // <-- the whole fix
 *     await accessSecretStorage(async () => {}, { forceReset: !hasExisting4S });
 *
 * `forceReset: true` opens `CreateSecretStorageDialog` (SecurityManager.ts:224-238) and
 * mints a NEW 4S key, orphaning the user's recovery key and their message-key backup —
 * while reporting success. Every other undefined state costs a session; this one costs
 * message history. The fallback direction is therefore INVERTED relative to the gate's:
 * an indeterminate read must resolve to "4S EXISTS" (unlock), and ONLY a definitive
 * `M_NOT_FOUND` tombstone may authorise a create.
 *
 * ---------------------------------------------------------------------------
 * WHY THE STATE HAS TO BE MANUFACTURED (three measured facts, not guesses)
 * ---------------------------------------------------------------------------
 * The loop is entered only when, at the instant the ceremony finishes,
 *
 *     crossSigningReady === true  &&  secretStorageReady === false  &&  hasServer4S === false
 *
 * (`!crossSigningReady` returns early — "we must verify but cross-signing isn't ready").
 * So the leg has to hold all three simultaneously:
 *
 * 1. `hasServer4S === false` — forced by intercepting the raw GET. This is the literal
 *    "network blip" the register names, and it is ALSO what makes the reload gate fire:
 *    the v4 image was measured landing straight in the app shell on reload
 *    (`matrixChat: true, completeSecurityBody: false`, 2026-07-25-verify-gate-root-cause-
 *    SETTLED.md UPDATE 1) precisely BECAUSE that GET returns 200. Blip it and the gate
 *    re-appears deterministically.
 *
 * 2. `crossSigningReady === true` — a reloaded first device. Measured true at +5s on
 *    every sample of `ew-reload-state-probe`.
 *
 * 3. `secretStorageReady === false` — the hard one. On restore it is transiently false
 *    (js-sdk 41.6.0 short-circuits `getAccountDataFromServer` to a cold local store), but
 *    it is TRUE again within seconds — long before a harness can click anything. That
 *    transient cannot be held open from Playwright.
 *
 *    So the leg makes it false DURABLY, with the smallest possible fixture: one PUT of
 *    `m.cross_signing.user_signing` to `{}`. Measured from the served js-sdk bundle
 *    (chunk 2343.js, `getSecretStorageStatus`), readiness is
 *        ready = every one of [master, user_signing, self_signing] (+ megolm_backup.v1
 *                when a backup version is active) is stored UNDER the default key id
 *    so removing exactly one secret flips `ready` to false and touches NOTHING this test
 *    asserts on: the default key id, the megolm backup version, and `m.cross_signing.master`
 *    (which is what `store.keyInfo` reads) all stay intact.
 *
 *    This is not a contrived state either — "4S exists but is not fully populated" is the
 *    shape U2 (`T_XS_HalfReset`, CONFIRMED open in §6.1) leaves behind. What matters for
 *    U3′ is only that **4S genuinely exists server-side while the local readiness reads
 *    false and the probe is indeterminate**, which is exactly what is assembled here.
 *
 * The ceremony is then finished deterministically by clicking **"Use another device"**:
 * `SetupEncryptionBody.onVerifyClick` calls `props.onFinished()` SYNCHRONOUSLY, before any
 * verification happens (v1.12.20), so it drives `onCompleteSecurityE2eSetupFinished` with
 * the crypto state untouched. "Use recovery key" is deliberately NOT used — `usePassPhrase`
 * runs `accessSecretStorage` itself and re-populates 4S, so it would heal the precondition
 * BEFORE the handler runs and the decision point would never be reached.
 *
 * ---------------------------------------------------------------------------
 * HOW TO PROVE THIS TEST GENUINELY FAILS  (it has to be able to go red, or it is worthless)
 * ---------------------------------------------------------------------------
 * ONE-LINE REVERT, in `siwx-oidc-matrix-server/patches/element-web/force-first-device-recovery.patch`,
 * inside `onCompleteSecurityE2eSetupFinished` — restore the pre-`cb75cce` fallback:
 *
 *       -    .catch((e: any) => e?.errcode !== "M_NOT_FOUND");
 *       +    .catch(() => false);
 *
 * rebuild the Element image (`dockerfiles/Dockerfile.element`) and re-run. EXPECTED RED:
 * `.mx_CreateSecretStorageDialog` renders in U3P-1/U3P-2 (assertion "no reset wizard"), and
 * — if the wizard is walked — the server-side default key id and backup version both change.
 * EW-U3P-0 stays GREEN under that revert, because it feeds the discriminator a genuine
 * `M_NOT_FOUND`, which both versions treat identically. That asymmetry is the point: the
 * pair cannot be satisfied by disabling forced recovery, nor by hard-coding either answer.
 *
 * SECOND REGRESSION SHAPE, also caught: revert the discriminator to the `b7e594f` original
 *
 *       -    const hasExisting4S = await cli.http.authedRequest("GET", …)…
 *       +    const hasExisting4S = await cli.secretStorage.hasKey();
 *
 * That read never touches the network, so the intercepted probe count stops at 2 (restore
 * gate + the handler's own `shouldForceVerification`) and never reaches 3. Assertion
 * "the loop consulted the SERVER" goes red. Note honestly that this revert would NOT
 * destroy anything *in this fixture* — `hasKey()` reads the hot local cache, which still
 * has the default key — so it is the SHAPE that is caught here, not the data loss. The
 * sub-second cold-cache window in which `hasKey()` actually returns false cannot be held
 * open from Playwright; that is a real limitation of this watcher, stated rather than hidden.
 *
 * ---------------------------------------------------------------------------
 * HONESTY CONTRACT (inherited from ew-recovery-entry.spec.mjs)
 * ---------------------------------------------------------------------------
 * - No `test.skip`. A leg that fails to REACH the decision point fails LOUDLY as
 *   inconclusive; it never passes green on a state it did not observe.
 * - The probe/observation helpers never throw: a probe-side failure degrades to a logged
 *   string, so a torn-down page can never masquerade as data loss.
 * - Every hard assertion carries the full server-side + wire-level diagnosis.
 * - Only GET of the probe URL is faulted. PUTs pass through UNTOUCHED and are counted —
 *   blocking them would let the harness itself prevent the destruction it claims to detect,
 *   and the "no new key" assertion would pass for the wrong reason.
 *
 * NOT RUN AS OF 2026-07-26 — authored against a shared, orchestrator-serialised lab.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, MATRIX_URL, SIWX_URL } from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';

/** The lab server_name; wallet mxids must match it (see EW-L1b). */
const SERVER_NAME = 'localhost';

/** The account_data event the whole decision turns on. */
const DEFAULT_KEY_EVENT = 'm.secret_storage.default_key';

/**
 * The secret removed from 4S to hold `isSecretStorageReady() === false` durably.
 * Chosen because it is the ONLY one of the three cross-signing secrets that neither
 * gates the "Use recovery key" button (that reads `m.cross_signing.master`) nor is an
 * artifact this test asserts on.
 */
const FIXTURE_SECRET = 'm.cross_signing.user_signing';

test.beforeAll(async () => {
  await requireElementStack();
});

// ---------------------------------------------------------------------------
// File-local helpers. Deliberately NOT added to helpers/* (shared with sibling
// agents), and deliberately NOT imported from ew-recovery-entry.spec.mjs —
// importing a spec file registers that file's tests here too.
// ---------------------------------------------------------------------------

/**
 * Real Element DOM login through the siwx UI, completing the mandatory first-device
 * Secure Backup wizard AND capturing the generated recovery key.
 *
 * Capturing variant of helpers/element-login.mjs::elementWalletClickLogin, mirroring
 * ew-recovery-entry.spec.mjs::loginCapturingRecoveryKey.
 */
async function loginCapturingRecoveryKey(page, walletBundle) {
  await injectMockWallet(page, walletBundle);

  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });

  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  // Post-signature interstitial: offer to link a passkey. Decline.
  await page.getByRole('button', { name: 'Skip for now' }).click();

  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });

  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();

  // "Setting up keys" can run a long time before the wizard renders.
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });

  let recoveryKey = null;
  let sawWizard = false;

  if (!(await chat.count())) {
    sawWizard = true;
    await btn(/^Continue$/).click(); // Set up Secure Backup (generate key is the default)

    const keyNode = page.locator('.mx_CreateSecretStorageDialog_recoveryKey code');
    await keyNode.waitFor({ timeout: 120_000 });
    recoveryKey = (await keyNode.innerText()).trim();

    await btn(/^Copy$/).click({ timeout: 120_000 });
    await btn(/^Continue$/).click({ timeout: 30_000 });
    await btn(/^Done$/).click({ timeout: 60_000 });
    await chat.waitFor({ timeout: 90_000 });
  }

  const session = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
    access_token: localStorage.getItem('mx_access_token'),
  }));
  if (!session.user_id || !session.device_id) {
    throw new Error('Element session storage missing: ' + JSON.stringify(session));
  }
  return { session, recoveryKey, sawWizard };
}

/**
 * A usable CS-API token for `walletBundle`'s identity.
 *
 * MEASURED 2026-07-26: under OIDC/MSC3861 Element never persists the access token in
 * localStorage, so this ALWAYS mints a fresh headless OIDC session — which means it must
 * NOT run on the Element page (`loginWalletToTokens` navigates whatever page it is given,
 * and a navigated Element tab produced a 120s "user is trapped" phantom in EW-R1-1). Use a
 * throwaway page and leave the Element tab where it is.
 */
async function tokenForUser(page, walletBundle) {
  const helper = await page.context().newPage();
  try {
    const s = await loginWalletToTokens(helper, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
      wallet: walletBundle,
    });
    return { token: s.access_token, extraDevice: s.device_id };
  } finally {
    await helper.close();
  }
}

const csApi = (p) => `${MATRIX_URL.replace(/\/$/, '')}/_matrix/client/v3${p}`;

/** Raw CS-API account_data read. `null` on 404 (M_NOT_FOUND). Throws on other errors. */
async function serverAccountData(accessToken, userId, type) {
  const r = await fetch(
    csApi(`/user/${encodeURIComponent(userId)}/account_data/${encodeURIComponent(type)}`),
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  if (r.status === 404) return null;
  if (!r.ok) {
    throw new Error(`GET account_data ${type} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
  }
  return r.json();
}

/** Raw CS-API account_data write (the fixture lever). */
async function putAccountData(accessToken, userId, type, body) {
  const r = await fetch(
    csApi(`/user/${encodeURIComponent(userId)}/account_data/${encodeURIComponent(type)}`),
    {
      method: 'PUT',
      headers: { Authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
  const text = await r.text();
  if (!r.ok) {
    throw new Error(`PUT account_data ${type} -> ${r.status} ${text.slice(0, 200)}`);
  }
  return { status: r.status, body: text };
}

/**
 * The MEGOLM key backup — a different artifact from 4S, and the second thing a forced
 * reset destroys. `auth_data.public_key` is the backup's real identity: a reset mints a
 * new version AND a new public key, so both are compared.
 */
async function keyBackupVersion(accessToken) {
  const r = await fetch(csApi('/room_keys/version'), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  return {
    status: r.status,
    version: body?.version ?? null,
    publicKey: body?.auth_data?.public_key ?? null,
    raw: text.slice(0, 200),
  };
}

/** The two artifacts U3′ destroys, read from SERVER truth (never from the page). */
async function snapshot4S(accessToken, userId) {
  const defaultKey = await serverAccountData(accessToken, userId, DEFAULT_KEY_EVENT);
  const master = await serverAccountData(accessToken, userId, 'm.cross_signing.master');
  const backup = await keyBackupVersion(accessToken);
  return {
    defaultKeyPresent: !!defaultKey,
    defaultKeyId: defaultKey?.key ?? null,
    masterEncrypted: !!master?.encrypted,
    backupStatus: backup.status,
    backupVersion: backup.version,
    backupPublicKey: backup.publicKey,
  };
}

/**
 * Capture the browser console. The vendored patch logs
 *   `shouldForceVerification: crossSigningReady=… secretStorageReady=… hasServer4S=…`
 * once per gate evaluation, and SecurityManager logs `accessSecretStorage: resetting 4S`
 * (SecurityManager.ts:225) IFF `forceReset: true` was passed — i.e. the destructive branch's
 * own signature, independent of the DOM.
 *
 * Never asserted on for ABSENCE (log level is not guaranteed), only for PRESENCE.
 */
function attachConsoleCapture(page) {
  const lines = [];
  page.on('console', (msg) => {
    try {
      const t = msg.text();
      if (
        t.includes('shouldForceVerification:') ||
        t.includes('accessSecretStorage:') ||
        t.includes('Forced recovery-key setup was not completed')
      ) {
        lines.push(t.slice(0, 300));
      }
    } catch {
      /* a probe must never throw */
    }
  });
  return lines;
}

/**
 * Fault-inject the 4S probe.
 *
 * ONLY `GET` of the probe URL is faulted, and never with 404/`M_NOT_FOUND` — that is a
 * definite "no key exists" tombstone which legitimately authorises a create. The faults
 * used are the two shapes a real blip takes:
 *   - `abort`        → ConnectionError, `e.errcode === undefined`
 *   - `server_error` → MatrixError, `e.errcode === "M_UNKNOWN"`
 * Both must resolve to "4S exists".
 *
 * `PUT` of the same URL and `POST/DELETE /room_keys/version` pass through UNTOUCHED and are
 * counted: they are the wire-level signature of the destruction actually happening, and
 * blocking them would make the "no new key" assertion pass for the wrong reason.
 */
async function installProbeFault(page, mode) {
  const seen = {
    mode,
    probeGet: 0,
    probeGetFaulted: 0,
    probePut: 0,
    backupPost: 0,
    backupDelete: 0,
  };
  await page.route(
    (url) =>
      url.pathname.endsWith(`/account_data/${DEFAULT_KEY_EVENT}`) ||
      url.pathname.endsWith('/room_keys/version') ||
      url.pathname.includes('/room_keys/version/'),
    async (route) => {
      let method = 'GET';
      let pathname = '';
      try {
        method = route.request().method();
        pathname = new URL(route.request().url()).pathname;
      } catch {
        return route.continue().catch(() => {});
      }

      if (pathname.endsWith(`/account_data/${DEFAULT_KEY_EVENT}`)) {
        if (method === 'GET') {
          seen.probeGet += 1;
          seen.probeGetFaulted += 1;
          if (mode === 'abort') {
            return route.abort('failed').catch(() => {});
          }
          return route
            .fulfill({
              status: 502,
              contentType: 'application/json',
              body: JSON.stringify({
                errcode: 'M_UNKNOWN',
                error: 'simulated upstream failure (EW-U3P probe blip)',
              }),
            })
            .catch(() => {});
        }
        // A PUT here IS the destruction. Let it through so it can be detected.
        if (method === 'PUT') seen.probePut += 1;
        return route.continue().catch(() => {});
      }

      if (method === 'POST') seen.backupPost += 1;
      if (method === 'DELETE') seen.backupDelete += 1;
      return route.continue().catch(() => {});
    },
  );
  return seen;
}

/** Passive (no interception) observation of the probe, for the negative control. */
function attachPassiveProbeWatch(page) {
  const seen = { probeResponses: [], backupPost: 0 };
  page.on('response', (res) => {
    try {
      const u = new URL(res.url());
      if (u.pathname.endsWith(`/account_data/${DEFAULT_KEY_EVENT}`)) {
        seen.probeResponses.push(res.status());
      }
    } catch {
      /* never throw */
    }
  });
  page.on('request', (req) => {
    try {
      const u = new URL(req.url());
      if (u.pathname.endsWith('/room_keys/version') && req.method() === 'POST') {
        seen.backupPost += 1;
      }
    } catch {
      /* never throw */
    }
  });
  return seen;
}

/**
 * Poll the live client until `isSecretStorageReady()` reports false — the third
 * precondition. This is a readiness gate that CAN fail, and its failure is the honest
 * outcome when the fixture did not reach the client: the leg would otherwise "pass" without
 * ever entering the loop.
 *
 * Never throws; returns the last observed value.
 */
async function waitForSecretStorageNotReady(page, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'unread';
  while (Date.now() < deadline) {
    last = await page
      .evaluate(async () => {
        const cli = window.mxMatrixClientPeg?.get?.();
        const c = cli?.getCrypto?.();
        if (!c) return 'no-crypto';
        try {
          return await c.isSecretStorageReady();
        } catch (e) {
          return `ERR ${String(e).slice(0, 80)}`;
        }
      })
      .catch((e) => `ERR ${String(e).slice(0, 80)}`);
    if (last === false) return last;
    await page.waitForTimeout(2_000);
  }
  return last;
}

/**
 * Finish the ceremony so `onCompleteSecurityE2eSetupFinished` runs.
 *
 * "Use another device" is the deterministic trigger: `SetupEncryptionBody.onVerifyClick`
 * calls `props.onFinished()` synchronously, BEFORE the verification request resolves, so the
 * handler runs with the crypto state untouched. Its render condition
 * (`store.hasDevicesToVerifyAgainst`) has no self-exclusion (SetupEncryptionStore.ts:104-119)
 * so a reloaded, self-signed device satisfies it — measured present on exactly this screen
 * (2026-07-25-verify-gate-root-cause-SETTLED.md §2: buttons
 * `["Use another device", "Can't confirm?", "Remove this device"]`).
 *
 * NEVER clicks "Use recovery key" (heals the precondition before the handler),
 * "Can't confirm?" (destructive reset) or "Remove this device" (sign out).
 */
async function driveCeremonyToFinish(page) {
  const gate = page.locator('.mx_CompleteSecurityBody');
  const chat = page.locator('.mx_MatrixChat');
  await gate.or(chat).first().waitFor({ timeout: 180_000 });

  if (!(await gate.count())) {
    return { trigger: 'none', why: 'the app shell rendered; the verify gate never engaged' };
  }

  const useAnother = gate.getByRole('button', { name: /use another device/i });
  if (await useAnother.count()) {
    await useAnother.first().click();
    return { trigger: 'use_another_device', why: 'onVerifyClick calls onFinished synchronously' };
  }
  // The ceremony may have auto-advanced to Phase.Done (T_C_OkAwaitAck); its "Done" button
  // also reaches onFinished, via store.done() -> Phase.Finished.
  const done = gate.getByRole('button', { name: /^done$/i });
  if (await done.count()) {
    await done.first().click();
    return { trigger: 'done', why: 'store.done() -> Phase.Finished -> onFinished' };
  }

  const controls = await gate
    .evaluate((root) =>
      [...root.querySelectorAll('button,[role=button]')].map((b) => b.textContent.trim()),
    )
    .catch(() => ['<unreadable>']);
  return {
    trigger: 'none',
    why: `the gate offered no non-destructive way to finish the ceremony: ${JSON.stringify(controls)}`,
  };
}

/**
 * One instant of the post-trigger surface, reduced to the branch discriminator.
 * Never throws.
 *
 *   resetWizard  — `.mx_CreateSecretStorageDialog`: accessSecretStorage took forceReset:true.
 *                  (SecurityManager.ts:228 — the ONLY caller that opens this dialog here.)
 *   unlockPrompt — `.mx_AccessSecretStorageDialog`: forceReset:false and 4S is being UNLOCKED.
 *   forcedRecoveryQuestion — the patch's own "Set up recovery to continue" Retry/Sign-out
 *                  dialog: the loop ran and `accessSecretStorage` threw. Non-destructive.
 */
async function sampleBranchSurface(page) {
  return page
    .evaluate(() => {
      const vis = (el) => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      };
      const text = document.body?.innerText || '';
      return {
        resetWizard: !!document.querySelector('.mx_CreateSecretStorageDialog'),
        unlockPrompt: !!document.querySelector('.mx_AccessSecretStorageDialog'),
        forcedRecoveryQuestion: text.includes('Set up recovery to continue'),
        appShell: !!document.querySelector('.mx_MatrixChat'),
        gate: !!document.querySelector('.mx_CompleteSecurityBody'),
        headings: [...document.querySelectorAll('h1,h2,h3')]
          .filter(vis)
          .map((h) => h.textContent.trim())
          .slice(0, 6),
        bodyTextHead: text.replace(/\s+/g, ' ').slice(0, 240),
      };
    })
    .catch((e) => ({ error: String(e).slice(0, 160) }));
}

/** Diagnosis appended to every hard assertion in this file. */
function diagnose(label, { before, after, wire, logs, samples, mode }) {
  const last = samples?.[samples.length - 1] ?? {};
  return (
    `${label}\n` +
    `  probe fault mode                    : ${mode}\n` +
    `  4S BEFORE  default_key.key          : ${before?.defaultKeyId}\n` +
    `  4S AFTER   default_key.key          : ${after?.defaultKeyId}\n` +
    `  backup BEFORE version/public_key    : ${before?.backupVersion} / ${before?.backupPublicKey}\n` +
    `  backup AFTER  version/public_key    : ${after?.backupVersion} / ${after?.backupPublicKey}\n` +
    `  master still encrypted into 4S      : ${after?.masterEncrypted}\n` +
    `  wire counters                       : ${JSON.stringify(wire)}\n` +
    `  last surface                        : ${JSON.stringify(last)}\n` +
    `  patch/SecurityManager log lines     : ${JSON.stringify((logs || []).slice(-12))}\n` +
    `  -> probeGet accounting: #1 restore gate, #2 the handler's own shouldForceVerification,\n` +
    `     #3 the LOOP's forceReset discriminator, #4 the loop's post-access re-check. A count\n` +
    `     that stops at 2 means the discriminator never consulted the server.`
  );
}

// ---------------------------------------------------------------------------
// EW-U3P-0 — NEGATIVE CONTROL, first because it is cheap and decisive.
//
// A genuine M_NOT_FOUND must still take the CREATE path. Without this, U3P-1/U3P-2
// could be satisfied by hard-coding `hasExisting4S = true` (or deleting forced
// recovery altogether), which would leave every first device with no recovery key
// at all — a different, equally bad failure.
// ---------------------------------------------------------------------------

test('EW-U3P-0: a genuine M_NOT_FOUND still takes the CREATE path (control)', async ({ page }) => {
  test.setTimeout(420_000);

  const logs = attachConsoleCapture(page);
  const watch = attachPassiveProbeWatch(page); // observe only — no interception at all
  const w = makeWallet(undefined, SERVER_NAME);

  const { session, recoveryKey, sawWizard } = await loginCapturingRecoveryKey(page, w);
  expect(session.user_id).toBe(w.mxid);

  // The wizard IS `accessSecretStorage(..., { forceReset: true })` reached through the
  // loop: for a brand-new identity the server genuinely 404s the probe.
  expect(
    sawWizard,
    'CONTROL FAILED: a brand-new first device did NOT get the forced recovery-key wizard. ' +
      'Either forced first-device recovery was disabled, or the forceReset discriminator now ' +
      'answers "4S exists" for an identity that has none — in which case U3P-1/U3P-2 passing ' +
      'proves nothing.\n' +
      `  observed probe statuses: ${JSON.stringify(watch.probeResponses)}\n` +
      `  log lines: ${JSON.stringify(logs.slice(-12))}`,
  ).toBe(true);
  expect(recoveryKey, 'the create path must yield a recovery key the user can record').toBeTruthy();
  expect(String(recoveryKey).replace(/\s+/g, '').length).toBeGreaterThan(40);

  const { token } = await tokenForUser(page, w);
  const after = await snapshot4S(token, session.user_id);

  expect(
    after.defaultKeyPresent,
    `CONTROL FAILED: the wizard ran but no ${DEFAULT_KEY_EVENT} exists server-side afterwards.\n` +
      `  snapshot: ${JSON.stringify(after)}`,
  ).toBe(true);
  expect(
    after.backupStatus,
    `CONTROL FAILED: no megolm backup version exists after the create path ` +
      `(status ${after.backupStatus}). U3P-1/U3P-2 assert this artifact is PRESERVED, so it ` +
      `must exist for them to be meaningful.`,
  ).toBe(200);

  // The probe was genuinely answered "absent" by the server at least once. 404 on this
  // endpoint is always M_NOT_FOUND in Synapse — the definite tombstone the contract allows.
  expect(
    watch.probeResponses.filter((s) => s === 404).length,
    `CONTROL: expected at least one 404 (M_NOT_FOUND) on ${DEFAULT_KEY_EVENT} before 4S was ` +
      `created. Observed statuses: ${JSON.stringify(watch.probeResponses)}. If this is empty, ` +
      `the discriminator is no longer issuing the raw authed GET at all.`,
  ).toBeGreaterThan(0);

  console.log(
    `[EW-U3P-0] probe statuses=${JSON.stringify(watch.probeResponses)} ` +
      `backupPOST=${watch.backupPost} defaultKeyId=${after.defaultKeyId} ` +
      `backupVersion=${after.backupVersion}\n  logs=${JSON.stringify(logs.slice(-12))}`,
  );
});

// ---------------------------------------------------------------------------
// U3P-1 / U3P-2 — the watcher itself, once per blip shape.
// ---------------------------------------------------------------------------

/**
 * @param {'abort'|'server_error'} mode
 */
async function runIndeterminateProbeLeg(page, mode, label) {
  const logs = attachConsoleCapture(page);
  const w = makeWallet(undefined, SERVER_NAME);

  // --- 1. A session with a KNOWN, real 4S key and a real message-key backup.
  const { session, recoveryKey, sawWizard } = await loginCapturingRecoveryKey(page, w);
  expect(session.user_id).toBe(w.mxid);
  expect(sawWizard, 'the leg needs the forced wizard to have created 4S').toBe(true);
  // The key is captured as proof that a real, user-recordable recovery key exists to be
  // orphaned — that is the artifact U3′ destroys. It is deliberately NOT typed in later: the
  // claim under test is "no reset happened", and completing the unlock journey on the user's
  // behalf could only ever MASK an outcome, never reveal one. If the unlock prompt appears,
  // it is left standing as the observation.
  expect(recoveryKey, 'the leg needs a recovery key to have been minted').toBeTruthy();

  const { token } = await tokenForUser(page, w);
  const before = await snapshot4S(token, session.user_id);

  expect(
    before.defaultKeyPresent && !!before.defaultKeyId,
    `precondition: ${DEFAULT_KEY_EVENT} must exist server-side before the blip. ` +
      `Got ${JSON.stringify(before)}`,
  ).toBe(true);
  expect(
    before.backupStatus,
    `precondition: a megolm backup version must exist before the blip (this is the second ` +
      `artifact a forced reset destroys). Got ${JSON.stringify(before)}`,
  ).toBe(200);

  // --- 2. Hold `isSecretStorageReady() === false` durably (see the header). One PUT.
  await putAccountData(token, session.user_id, FIXTURE_SECRET, {});
  const afterFixture = await snapshot4S(token, session.user_id);
  expect(
    afterFixture.defaultKeyId,
    'the fixture must not disturb the artifact under test (the 4S default key id)',
  ).toBe(before.defaultKeyId);
  expect(
    afterFixture.backupVersion,
    'the fixture must not disturb the megolm backup version',
  ).toBe(before.backupVersion);
  expect(
    afterFixture.masterEncrypted,
    'the fixture must leave m.cross_signing.master in 4S (it is what store.keyInfo reads)',
  ).toBe(true);

  const ssReady = await waitForSecretStorageNotReady(page);
  expect(
    ssReady,
    `PRECONDITION NOT REACHED: isSecretStorageReady() never went false after removing ` +
      `${FIXTURE_SECRET} from 4S (last read: ${JSON.stringify(ssReady)}). Without it the ` +
      `forceReset decision point is never entered and this leg would assert nothing. Do NOT ` +
      `"fix" this by dropping the assertion — check that the PUT reached the client via /sync, ` +
      `and that getSecretStorageStatus() still requires ${FIXTURE_SECRET}.`,
  ).toBe(false);

  // --- 3. Blip the probe, and start counting the destructive writes.
  //
  // Mark the console buffer HERE. Step 1's forced-recovery wizard creates the user's
  // FIRST 4S key, and it does that through `accessSecretStorage(..., {forceReset: true})`
  // -- so `SecurityManager: accessSecretStorage: resetting 4S` is ALWAYS in the buffer
  // by this point, legitimately. Asserting over the whole buffer made the log check
  // structurally incapable of passing: it reported the leg's own setup as the defect it
  // was hunting. Only lines emitted AFTER the fault is installed are evidence about the
  // discriminator under test.
  const logMarkFrom = logs.length;
  const wire = await installProbeFault(page, mode);

  // --- 4. Restore. hasServer4S is now unanswerable, so the gate fires by design
  // ("falls back toward enforcing" — §7.1 finding 3, the very fallback that carries the
  // user INTO this loop).
  await page.reload({ waitUntil: 'domcontentloaded' });

  const trigger = await driveCeremonyToFinish(page);

  // --- 5. Watch the branch. Sampling is bounded and early-exits on a decisive marker.
  const samples = [];
  let decisive = null;
  for (let i = 0; i < 20; i += 1) {
    await page.waitForTimeout(2_000);
    const s = await sampleBranchSurface(page);
    samples.push({ at: (i + 1) * 2, ...s });
    if (s.resetWizard) {
      decisive = 'RESET_WIZARD';
      break;
    }
    if (s.unlockPrompt) decisive = decisive ?? 'UNLOCK_PROMPT';
    if (s.forcedRecoveryQuestion) decisive = decisive ?? 'FORCED_RECOVERY_QUESTION';
    if (decisive) break;
  }
  const last = samples[samples.length - 1] ?? {};
  if (!decisive && last.appShell) decisive = 'APP_SHELL';

  const after = await snapshot4S(token, session.user_id);
  // Everything the client logged AFTER the probe was blipped. The full buffer stays in
  // `ctx` for diagnosis; only this slice is evidence about the discriminator.
  const logsSinceBlip = logs.slice(logMarkFrom);
  const ctx = { before, after, wire, logs, samples, mode };

  console.log(
    `[${label}] trigger=${trigger.trigger} (${trigger.why}) outcome=${decisive} ` +
      `wire=${JSON.stringify(wire)}\n  logs(all)=${JSON.stringify(logs.slice(-12))}` +
      `\n  logs(sinceBlip)=${JSON.stringify(logsSinceBlip)}`,
  );

  // ======================= THE ASSERTIONS =======================

  // (a) The destructive branch must not have been taken. This is the sharp one: the reset
  //     wizard renders the instant `forceReset: true` is passed, long before the user could
  //     click anything, so it is detectable without letting any data actually be destroyed.
  expect(
    samples.some((s) => s.resetWizard),
    diagnose(
      'U3′ IS LIVE — an INDETERMINATE 4S probe took the DESTRUCTIVE branch. ' +
        '`accessSecretStorage(..., { forceReset: true })` opened CreateSecretStorageDialog for a ' +
        'user whose 4S key and message-key backup ALREADY EXIST server-side. Completing that ' +
        'wizard mints a new 4S key and orphans the recovery key and the entire message-key ' +
        'backup, while reporting success.\n' +
        '  The contract: only a definitive M_NOT_FOUND may authorise a create. A network blip ' +
        'or 5xx must resolve to "4S exists" and UNLOCK.',
      ctx,
    ),
  ).toBe(false);

  // (b) Wire-level corroboration, independent of the DOM: the destruction writes never happened.
  expect(
    wire.probePut,
    diagnose(
      `U3′ IS LIVE (wire) — ${wire.probePut} PUT(s) to ${DEFAULT_KEY_EVENT} were observed while ` +
        'the probe was indeterminate. A PUT to that event IS the new 4S key being installed.',
      ctx,
    ),
  ).toBe(0);
  expect(
    wire.backupPost,
    diagnose(
      `U3′ IS LIVE (wire) — ${wire.backupPost} POST(s) to /room_keys/version were observed. ` +
        "That is a NEW megolm backup version replacing the user's existing one.",
      ctx,
    ),
  ).toBe(0);
  // Scoped to post-blip (see `logMarkFrom`): the setup wizard's own legitimate
  // `forceReset:true` must not be mistaken for the defect.
  expect(
    logsSinceBlip.some((l) => l.includes('accessSecretStorage: resetting 4S')),
    diagnose(
      'U3′ IS LIVE (log) — after the probe was blipped, SecurityManager logged ' +
        '"accessSecretStorage: resetting 4S", which it emits ONLY when forceReset:true was ' +
        'passed. The indeterminate read was resolved toward RESET instead of UNLOCK.',
      ctx,
    ),
  ).toBe(false);

  // Positive corroboration, not just absence: the else-branch must actually have run.
  // Without this the assertion above would also pass if the handler never reached
  // accessSecretStorage at all -- i.e. if the leg silently stopped testing anything.
  expect(
    logsSinceBlip.some((l) => l.includes('accessSecretStorage: bootstrapCrossSigning')),
    diagnose(
      'INCONCLUSIVE — after the blip, SecurityManager logged neither "resetting 4S" nor ' +
        '"bootstrapCrossSigning", so the forceReset decision point was never reached and this ' +
        'leg asserted nothing. Do NOT read this as a pass.',
      ctx,
    ),
  ).toBe(true);

  // (c) SERVER TRUTH — the two artifacts are byte-identical to what they were.
  expect(
    after.defaultKeyId,
    diagnose(
      `The 4S default key id CHANGED (${before.defaultKeyId} -> ${after.defaultKeyId}). The ` +
        "user's recorded recovery key no longer opens their secret storage.",
      ctx,
    ),
  ).toBe(before.defaultKeyId);
  expect(
    after.backupVersion,
    diagnose(
      `The megolm backup version CHANGED (${before.backupVersion} -> ${after.backupVersion}). ` +
        'The old message keys are orphaned — this is the history loss U3′ names.',
      ctx,
    ),
  ).toBe(before.backupVersion);
  expect(
    after.backupPublicKey,
    diagnose('The megolm backup public key CHANGED — a new backup replaced the old one.', ctx),
  ).toBe(before.backupPublicKey);

  // (d) NON-VACUITY. Everything above is a negative claim, so the leg must prove it reached
  //     the decision point at all.
  //
  //     `UNLOCK_PROMPT` and `FORCED_RECOVERY_QUESTION` are LOOP-ONLY surfaces: in this flow
  //     nothing else opens `AccessSecretStorageDialog`, and the "Set up recovery to continue"
  //     Retry/Sign-out dialog exists ONLY inside the vendored loop. Either sighting is direct
  //     proof, with no dependency on log levels or request accounting. `APP_SHELL` is
  //     ambiguous — the loop may have run and healed silently, or never run at all — so it is
  //     accepted only when the probe count corroborates it.
  const loopOnlySurface = ['UNLOCK_PROMPT', 'FORCED_RECOVERY_QUESTION'].includes(decisive);
  expect(
    loopOnlySurface || (decisive === 'APP_SHELL' && wire.probeGet >= 3),
    diagnose(
      `INCONCLUSIVE — this leg never demonstrably reached the forceReset decision point, so ` +
        `its negative assertions above are vacuous. outcome=${decisive}, probeGet=` +
        `${wire.probeGet}, trigger=${trigger.trigger} (${trigger.why}).\n` +
        `  Investigate rather than mute; the likely causes are:\n` +
        `   (1) the ceremony never finished, so onCompleteSecurityE2eSetupFinished never ran;\n` +
        `   (2) shouldForceVerification returned false at handler time — secretStorageReady was\n` +
        `       true again, i.e. the ${FIXTURE_SECRET} fixture stopped holding;\n` +
        `   (3) crossSigningReady was false at handler time, so the handler returned early.\n` +
        `  Do NOT relax this assertion. A green U3′ watcher that never entered the loop is the\n` +
        `  precise failure this file exists to prevent.`,
      ctx,
    ),
  ).toBe(true);

  // (e) THE DISCRIMINATOR MUST CONSULT THE SERVER. Accounting is in diagnose(): with the
  //     fixture holding secretStorageReady false, every `shouldForceVerification` issues one
  //     probe, and the loop's own discriminator issues another — so a run that entered the
  //     loop cannot stop at 2. A count <= 2 alongside a loop-only surface above means the
  //     discriminator read something OTHER than the network: the `b7e594f` regression shape
  //     (`cli.secretStorage.hasKey()`), which reads the cold local cache and is exactly as
  //     unreliable as the probe it replaced.
  //
  //     Stated honestly: this is a HEURISTIC, not a proof. Early-boot reads of the same event
  //     (before the persisted store reports the initial sync complete) can also issue HTTP and
  //     inflate the count, so it can under-report a regression; it cannot over-report one,
  //     because the fixed code always exceeds the threshold.
  expect(
    wire.probeGet >= 3,
    diagnose(
      `The loop ran (outcome=${decisive}) but only ${wire.probeGet} probe GET(s) reached the ` +
        `network. The forceReset discriminator must be a RAW AUTHED GET of ` +
        `${DEFAULT_KEY_EVENT}; a local-cache read (secretStorage.hasKey() / ` +
        `getAccountDataFromServer(), both of which short-circuit to a cold store on restore) ` +
        `is the exact defect U3′ names, even on a run where it happened not to destroy anything.`,
      ctx,
    ),
  ).toBe(true);
}

test('EW-U3P-1: a probe that fails with a NETWORK error must UNLOCK, never reset', async ({
  page,
}) => {
  test.setTimeout(600_000);
  await runIndeterminateProbeLeg(page, 'abort', 'EW-U3P-1 net-abort');
});

test('EW-U3P-2: a probe that fails with 5xx (errcode !== M_NOT_FOUND) must UNLOCK, never reset', async ({
  page,
}) => {
  test.setTimeout(600_000);
  await runIndeterminateProbeLeg(page, 'server_error', 'EW-U3P-2 http-502');
});
