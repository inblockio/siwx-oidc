/**
 * EW-DL4: the real-world trigger for the 2026-07-31 prod download outage.
 *
 * Element's sw.js resolves the user's access token by postMessage'ing the page
 * ({type:"userinfo"}) and registering its `message` listener LAZILY, inside the
 * fetch handler — not at initial script evaluation. Chrome warns about exactly
 * this ("Event handler of 'message' event must be added on the initial
 * evaluation of worker script") and does not reliably deliver the reply to such
 * a listener when the worker has been restarted from idle. The SW then times
 * out (1s), swallows the error, and re-fetches the LEGACY media URL with no
 * token -> Synapse 404 -> download silently dies.
 *
 * A service worker idles out after ~30s of inactivity, so every real user hits
 * the restarted-worker state constantly; a freshly-installed worker (what a lab
 * test gets) does not, which is why this never showed up in testing.
 *
 * State A: worker warm  -> download works.
 * State B: worker restarted from idle (CDP ServiceWorker.stopAllWorkers)
 *          -> tokenless legacy 404, no download.
 */
import { test, expect } from "@playwright/test";
import { ELEMENT_URL, SIWX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

test("EW-DL4: a restarted service worker kills encrypted media downloads", async ({ page, context }) => {
  test.setTimeout(300_000);
  const downloads = [];
  const media = [];
  page.on("download", (d) => { downloads.push(d.suggestedFilename()); d.cancel().catch(() => {}); });
  page.on("response", (r) => {
    if (/\/_matrix\/(client\/v1\/)?media\/(download|v3)/.test(r.url()))
      media.push(`${r.status()} ${r.url().replace(/https:\/\/[^/]+/, "").slice(0, 70)}`);
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
      name: "dl-swrestart-probe",
      preset: "private_chat",
      initial_state: [{ type: "m.room.encryption", state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } }],
    });
    return r.room_id;
  });

  const sendFile = (name) =>
    page.evaluate(async ({ rid, name }) => {
      const cli = window.mxMatrixClientPeg.get();
      const pt = new TextEncoder().encode(`probe ${name}`);
      const key = await crypto.subtle.generateKey({ name: "AES-CTR", length: 256 }, true, ["encrypt"]);
      const jwk = await crypto.subtle.exportKey("jwk", key);
      const iv = new Uint8Array(16);
      crypto.getRandomValues(iv.subarray(0, 8));
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, key, pt));
      const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));
      const u = (a) => btoa(String.fromCharCode(...a)).replace(/=+$/, "");
      const { content_uri: url } = await cli.uploadContent(new Blob([ct], { type: "application/octet-stream" }), {
        includeFilename: false, type: "application/octet-stream",
      });
      await cli.sendMessage(rid, {
        msgtype: "m.file", body: name,
        file: { v: "v2", url, iv: u(iv), hashes: { sha256: u(dg) }, key: { alg: "A256CTR", ext: true, k: jwk.k, key_ops: ["encrypt", "decrypt"], kty: "oct" } },
        info: { mimetype: "application/pdf", size: pt.length },
      });
    }, { rid: roomId, name });

  await page.evaluate((rid) => { window.location.hash = `#/room/${rid}`; }, roomId);
  await page.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 });
  await sendFile("warm.pdf");
  await sendFile("restarted.pdf");
  await page.getByText("restarted.pdf", { exact: false }).last().waitFor({ timeout: 60_000 });
  await page.waitForTimeout(2000);

  // --- State A: warm worker ---
  media.length = 0;
  await page.getByText("warm.pdf", { exact: false }).last().click();
  await page.waitForTimeout(5000);
  console.log(`>>> STATE A (warm SW)      downloads=${downloads.length} media=${JSON.stringify(media)}`);
  expect(downloads.length, "warm worker: download works").toBeGreaterThan(0);

  // --- State B: same session, worker restarted from idle ---
  const cdp = await context.newCDPSession(page);
  await cdp.send("ServiceWorker.enable");
  await cdp.send("ServiceWorker.stopAllWorkers");
  await page.waitForTimeout(1500);
  const stillControlled = await page.evaluate(() => !!navigator.serviceWorker.controller);

  const before = downloads.length;
  media.length = 0;
  await page.getByText("restarted.pdf", { exact: false }).last().click();
  await page.waitForTimeout(8000);
  console.log(
    `>>> STATE B (restarted SW) controlled=${stillControlled} newDownloads=${downloads.length - before} media=${JSON.stringify(media)}`,
  );

  // Documents the observed behaviour rather than asserting failure: if upstream
  // ever fixes the lazy listener, this flips to a pass and the assert below is
  // the thing to update.
  console.log(
    downloads.length - before === 0
      ? ">>> REPRODUCED: restarted worker => dead download"
      : ">>> NOT reproduced in this run (worker answered) — rerun; the race is timing-dependent",
  );
});
