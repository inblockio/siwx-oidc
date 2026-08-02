/**
 * EW-DL3: causal proof for the 2026-07-31 prod "download does nothing" incident.
 *
 * Same session, same file, two states:
 *   A. service worker intercepting  -> media authenticated -> download fires
 *   B. service worker NOT intercepting (uncontrolled page, as produced by a
 *      hard reload / DevTools "Bypass for network") -> the app's LEGACY media
 *      URL goes out tokenless -> Synapse 404 -> download silently dies.
 *
 * State B is the reported symptom, and matches the prod Synapse access log
 * signature ({None} 404s on /_matrix/media/v3/download).
 */
import { test, expect } from "@playwright/test";
import { ELEMENT_URL, SIWX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

test("EW-DL3: an uncontrolled page reproduces the tokenless-404 dead download", async ({ page, context }) => {
  test.setTimeout(300_000);
  const downloads = [];
  const media = [];
  page.on("download", (d) => { downloads.push(d.suggestedFilename()); d.cancel().catch(() => {}); });
  page.on("response", (r) => {
    if (/\/_matrix\/(client\/v1\/)?media\/(download|v3)/.test(r.url()))
      media.push(`${r.status()} ${r.url().replace(/https:\/\/[^/]+/, "").slice(0, 80)}`);
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
      name: "dl-sw-probe",
      preset: "private_chat",
      initial_state: [{ type: "m.room.encryption", state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } }],
    });
    return r.room_id;
  });

  const sendFile = async (name) =>
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
  await sendFile("state-a.pdf");
  await sendFile("state-b.pdf");
  await page.getByText("state-b.pdf", { exact: false }).last().waitFor({ timeout: 60_000 });
  await page.waitForTimeout(2000);

  // --- State A: service worker intercepting (normal) ---
  media.length = 0;
  await page.getByText("state-a.pdf", { exact: false }).last().click();
  await page.waitForTimeout(5000);
  const controlled = await page.evaluate(() => !!navigator.serviceWorker.controller);
  console.log(`>>> STATE A controlled=${controlled} downloads=${downloads.length} media=${JSON.stringify(media)}`);
  expect(downloads.length, "state A: SW intercepting -> download works").toBeGreaterThan(0);

  // --- State B: same session, service worker no longer intercepting ---
  const cdp = await context.newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.setBypassServiceWorker", { bypass: true });
  const before = downloads.length;
  media.length = 0;
  await page.getByText("state-b.pdf", { exact: false }).last().click();
  await page.waitForTimeout(6000);
  console.log(`>>> STATE B (SW bypassed) newDownloads=${downloads.length - before} media=${JSON.stringify(media)}`);

  // The point of the test: state B is where the button silently dies.
  expect(media.join(" "), "state B: legacy media request 404s").toMatch(/404/);
  expect(downloads.length - before, "state B: no download fires").toBe(0);
});
