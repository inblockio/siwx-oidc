/**
 * EW-DL2: encrypted IMAGE download via the hover action bar / lightbox.
 *
 * Distinct from EW-DL1 (m.file tile): images download through
 * useDownloadMedia -> new FileDownloader() with NO iframeFn, i.e. the MANAGED
 * hidden singleton iframe and DEFAULT_STYLES (empty imgSrc/style). That is the
 * path that emits the "Unsafe attempt to load URL .../usercontent/" console
 * error reported in the 2026-07-31 prod incident.
 */
import { test, expect } from "@playwright/test";
import { ELEMENT_URL, SIWX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

// 1x1 red PNG
const PNG_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

test("EW-DL2: encrypted image download fires a browser download", async ({ page }) => {
  test.setTimeout(300_000);
  const downloads = [];
  const notable = [];
  page.on("console", (m) => {
    const t = m.text();
    if (/unsafe|usercontent|download|worker|decrypt|SW:/i.test(t)) notable.push(`[${m.type()}] ${t.slice(0, 220)}`);
  });
  page.on("download", (d) => {
    downloads.push(d.suggestedFilename());
    console.log(`>>> DOWNLOAD EVENT: ${d.suggestedFilename()}`);
    d.cancel().catch(() => {});
  });
  page.on("response", (r) => {
    if (/\/_matrix\/(client\/v1\/)?media\//.test(r.url()))
      console.log(`>>> MEDIA ${r.status()} ${r.url().replace(/https:\/\/[^/]+/, "").slice(0, 100)}`);
  });

  const wallet = makeWallet();
  await injectMockWallet(page, wallet);
  await page.goto(ELEMENT_URL, { waitUntil: "domcontentloaded" });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole("button", { name: "Sign in with Ethereum" }).click();
  const gateBtn = page.getByRole("button", { name: "Continue" }).first();
  const skipBtn = page.getByRole("button", { name: "Skip for now" }).first();
  for (let i = 0; i < 2; i++) {
    const which = await Promise.race([
      gateBtn.waitFor({ timeout: 20_000 }).then(() => "gate").catch(() => null),
      skipBtn.waitFor({ timeout: 20_000 }).then(() => "skip").catch(() => null),
      page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 20_000 }).then(() => "element").catch(() => null),
    ]);
    if (which === "gate") await gateBtn.click();
    else if (which === "skip") await skipBtn.click();
    else break;
  }
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(page);
  console.log(">>> logged in");

  const roomId = await page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({
      name: "dl-image-probe",
      preset: "private_chat",
      initial_state: [{ type: "m.room.encryption", state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } }],
    });
    return r.room_id;
  });
  await page.evaluate((rid) => { window.location.hash = `#/room/${rid}`; }, roomId);
  await page.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 });

  // encrypted m.image
  await page.evaluate(async ({ rid, b64 }) => {
    const cli = window.mxMatrixClientPeg.get();
    const plaintext = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.generateKey({ name: "AES-CTR", length: 256 }, true, ["encrypt"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv.subarray(0, 8));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, key, plaintext));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));
    const u = (a) => btoa(String.fromCharCode(...a)).replace(/=+$/, "");
    const { content_uri: url } = await cli.uploadContent(new Blob([ct], { type: "application/octet-stream" }), {
      includeFilename: false,
      type: "application/octet-stream",
    });
    await cli.sendMessage(rid, {
      msgtype: "m.image",
      body: "dl-probe.png",
      file: { v: "v2", url, iv: u(iv), hashes: { sha256: u(digest) }, key: { alg: "A256CTR", ext: true, k: jwk.k, key_ops: ["encrypt", "decrypt"], kty: "oct" } },
      info: { mimetype: "image/png", size: plaintext.length, w: 1, h: 1 },
    });
  }, { rid: roomId, b64: PNG_B64 });

  const tile = page.locator(".mx_EventTile_last, .mx_EventTile").filter({ hasText: "dl-probe.png" }).last();
  const img = page.locator(".mx_MImageBody, .mx_EventTile img").last();
  await img.or(tile).first().waitFor({ timeout: 60_000 });
  await page.waitForTimeout(3000);
  console.log(">>> image event rendered");

  // Path A: hover action bar -> Download
  await img.first().hover().catch(() => {});
  await page.waitForTimeout(500);
  const dlBtn = page.getByRole("button", { name: /^download$/i }).first();
  if (await dlBtn.count()) {
    await dlBtn.click();
    console.log(">>> clicked action-bar Download");
    await page.waitForTimeout(6000);
  } else {
    console.log(">>> no action-bar Download button found");
  }

  // Path B: open lightbox and use its Download button
  if (downloads.length === 0) {
    await img.first().click().catch(() => {});
    await page.waitForTimeout(2000);
    const lightboxDl = page.getByRole("button", { name: /^download$/i }).first();
    if (await lightboxDl.count()) {
      await lightboxDl.click();
      console.log(">>> clicked lightbox Download");
      await page.waitForTimeout(6000);
    }
  }

  console.log("=== notable console ===");
  for (const l of notable) console.log(l);
  expect(downloads.length, "image download should have fired").toBeGreaterThan(0);
});
