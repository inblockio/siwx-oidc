/**
 * EW-DL5: the concurrency race behind the 2026-07-31 prod media outage.
 *
 * Element's service worker asks the PAGE for {userId, deviceId, homeserver} on
 * EVERY intercepted media request, via postMessage under a hard 1000 ms timeout,
 * and caches nothing (apps/web/src/serviceworker/index.ts, byte-identical in
 * v1.12.20 and v1.12.24). When a room full of attachments loads at once, the
 * main thread cannot answer N round-trips inside 1 s; each timeout lands in the
 * catch-all that refetches the LEGACY url with NO token, which an
 * authenticated-media Synapse answers 404 -> images blank, downloads dead.
 *
 * Prod evidence: 175 legacy tokenless 404s in one 27-minute burst covering 27
 * distinct media ids, 26 of which ALSO succeeded via the authed path in the same
 * window (same session, same media, both outcomes) — the signature of a race,
 * not a config gate. Dev never reproduced it organically because its all-time
 * peak is 4 media requests per second.
 *
 * This spec manufactures that concurrency deterministically.
 *
 * PASS  = every media request was authenticated (zero legacy 404s).
 * FAIL  = the race reproduced; count of tokenless 404s is reported.
 */
import { test, expect } from "@playwright/test";
import { ELEMENT_URL, SIWX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

const BURST = Number(process.env.BURST || 30);
const PNG_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

test(`EW-DL5: ${BURST} concurrent encrypted media loads stay authenticated`, async ({ page }) => {
  test.setTimeout(420_000);
  const legacy404 = [];
  const authed200 = [];
  const legacy200 = [];
  page.on("response", (r) => {
    const u = r.url();
    if (!/\/_matrix\/(client\/v1\/)?media\/(download|thumbnail)/.test(u)) return;
    const isLegacy = /\/_matrix\/media\/v3\//.test(u);
    if (isLegacy && r.status() === 404) legacy404.push(u.split("/").pop().slice(0, 24));
    else if (isLegacy && r.status() < 400) legacy200.push(u.split("/").pop().slice(0, 24));
    else if (r.status() < 400) authed200.push(u.split("/").pop().slice(0, 24));
  });

  const wallet = makeWallet();
  await injectMockWallet(page, wallet);
  await page.goto(ELEMENT_URL, { waitUntil: "domcontentloaded" });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole("button", { name: "Sign in with Ethereum" }).click();
  const gate = page.getByRole("button", { name: "Continue" }).first();
  const skip = page.getByRole("button", { name: "Skip for now" }).first();
  for (let i = 0; i < 2; i++) {
    const which = await Promise.race([
      gate.waitFor({ timeout: 20_000 }).then(() => "gate").catch(() => null),
      skip.waitFor({ timeout: 20_000 }).then(() => "skip").catch(() => null),
      page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 20_000 }).then(() => "el").catch(() => null),
    ]);
    if (which === "gate") await gate.click();
    else if (which === "skip") await skip.click();
    else break;
  }
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(page);

  const roomId = await page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({
      name: "media-burst-probe",
      preset: "private_chat",
      initial_state: [{ type: "m.room.encryption", state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } }],
    });
    return r.room_id;
  });
  console.log(`>>> room ${roomId}, uploading ${BURST} encrypted images`);

  // Upload BURST encrypted images up front, keeping their mxc urls so we can
  // drive the concurrency directly at the service worker.
  const mxcs = await page.evaluate(async ({ rid, b64, n }) => {
    const cli = window.mxMatrixClientPeg.get();
    const plaintext = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const out = [];
    for (let i = 0; i < n; i++) {
      const key = await crypto.subtle.generateKey({ name: "AES-CTR", length: 256 }, true, ["encrypt"]);
      const jwk = await crypto.subtle.exportKey("jwk", key);
      const iv = new Uint8Array(16);
      crypto.getRandomValues(iv.subarray(0, 8));
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, key, plaintext));
      const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));
      const u = (a) => btoa(String.fromCharCode(...a)).replace(/=+$/, "");
      const { content_uri: url } = await cli.uploadContent(new Blob([ct], { type: "application/octet-stream" }), {
        includeFilename: false, type: "application/octet-stream",
      });
      await cli.sendMessage(rid, {
        msgtype: "m.image", body: `burst-${i}.png`,
        file: { v: "v2", url, iv: u(iv), hashes: { sha256: u(dg) }, key: { alg: "A256CTR", ext: true, k: jwk.k, key_ops: ["encrypt", "decrypt"], kty: "oct" } },
        info: { mimetype: "image/png", size: plaintext.length, w: 1, h: 1 },
      });
      out.push(url);
    }
    return out;
  }, { rid: roomId, b64: PNG_B64, n: BURST });

  // Reload so the worker is respawned cold and nothing is warm.
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator(".mx_MatrixChat").waitFor({ timeout: 120_000 });
  await page.waitForTimeout(3000);
  legacy404.length = 0; authed200.length = 0; legacy200.length = 0;

  // Fire every media request AT ONCE, exactly as a room full of attachments
  // does. Each one makes the worker do its own postMessage round-trip to this
  // page under a 1 s timeout.
  const statuses = await page.evaluate(async (urls) => {
    const toHttp = (mxc) => {
      const [, serverAndId] = mxc.split("mxc://");
      return `${window.location.protocol}//${new URL(window.mxMatrixClientPeg.get().getHomeserverUrl()).host}/_matrix/media/v3/download/${serverAndId}`;
    };
    // Occupy the main thread the way a rendering timeline does, so the worker's
    // postMessage replies have to compete for it.
    const hog = setInterval(() => {
      const t = Date.now();
      while (Date.now() - t < 120) {} // 120 ms of blocking work, repeatedly
    }, 150);
    const results = await Promise.all(
      urls.map((u) => fetch(toHttp(u)).then((r) => r.status).catch(() => -1)),
    );
    clearInterval(hog);
    return results;
  }, mxcs);

  const bad = statuses.filter((s) => s !== 200);
  console.log(`>>> direct burst statuses: 200=${statuses.filter((s) => s === 200).length} non200=${bad.length} ${bad.length ? JSON.stringify(bad.slice(0, 12)) : ""}`);
  await page.waitForTimeout(3000);

  const uniq = (a) => [...new Set(a)];
  console.log(
    `>>> BURST=${BURST}  authed_ok=${authed200.length} (${uniq(authed200).length} uniq)  ` +
      `legacy_ok=${legacy200.length}  LEGACY_TOKENLESS_404=${legacy404.length} (${uniq(legacy404).length} uniq)`,
  );
  if (legacy404.length) console.log(">>> RACE REPRODUCED — these media fell back tokenless:", uniq(legacy404).slice(0, 10).join(" "));

  expect(legacy404.length, "media requests that fell back to the tokenless legacy endpoint").toBe(0);
});
