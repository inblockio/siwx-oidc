// The guest's browser-made identity: one non-extractable signing key per browser, kept
// as a CryptoKeyPair in IndexedDB on the issuer origin, and the did:key made from its
// PUBLIC half. The private key is never exported, never stored anywhere else
// (localStorage and sessionStorage are not used) and never leaves this origin.
//
// Reused by the join page now, and by /guest/continue and /guest/ended later.
// Nothing here touches a browser global at load time, so a Node test can import it.

export const DB_NAME = 'siwx-guest';
export const STORE = 'keys';
const RECORD = 'current';

const ED = { gen: { name: 'Ed25519' }, sign: { name: 'Ed25519' }, label: 'Ed25519' };
const P256 = {
  gen: { name: 'ECDSA', namedCurve: 'P-256' },
  sign: { name: 'ECDSA', hash: 'SHA-256' },
  label: 'P-256',
};
const BY_ALG = { Ed25519: ED, 'P-256': P256 };

/** The curve label ('Ed25519' or 'P-256') of a CryptoKey. */
export function algOf(key) {
  return key.algorithm.name === 'Ed25519' ? 'Ed25519' : 'P-256';
}

// ---------------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58btc(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

/** base64url without padding, as the redeem route reads a signature. */
export function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** did:key from a raw public key: multicodec 0xed01 + 32 bytes (Ed25519), or 0x1200 + the
 *  33-byte compressed point (P-256). `raw` is what WebCrypto exports as 'raw'. */
export function didFromRaw(alg, raw) {
  let body;
  if (alg === 'Ed25519') {
    if (raw.length !== 32) throw new Error('bad Ed25519 public key');
    body = new Uint8Array(2 + 32);
    body.set([0xed, 0x01]);
    body.set(raw, 2);
  } else {
    if (raw.length !== 65 || raw[0] !== 4) throw new Error('bad P-256 public key');
    body = new Uint8Array(2 + 33);
    body.set([0x80, 0x24]); // varint of 0x1200
    body[2] = 0x02 | (raw[64] & 1); // y parity
    body.set(raw.subarray(1, 33), 3);
  }
  return 'did:key:z' + base58btc(body);
}

// ---------------------------------------------------------------------------------
// The redeem message (CAIP-122), byte-identical to guest_admission::format_redeem_message
// ---------------------------------------------------------------------------------

export const REDEEM_STATEMENT = 'Join as a guest';
export const REDEEM_RESOURCE_PREFIX = 'urn:io.inblock:guest:invite:';

/** `domain` is `location.host`, `uri` is `location.origin`; `issuedAt` and `expiration`
 *  are Dates (ISO form with milliseconds and Z, which is what toISOString gives). */
export function buildRedeemMessage({ domain, alg, did, uri, nonce, issuedAt, expiration, inviteId }) {
  const label = BY_ALG[alg].label;
  return (
    `${domain} wants you to sign in with your ${label} account:\n` +
    `${did}\n` +
    `\n` +
    `${REDEEM_STATEMENT}\n` +
    `\n` +
    `URI: ${uri}\n` +
    `Version: 1\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt.toISOString()}\n` +
    `Expiration Time: ${expiration.toISOString()}\n` +
    `Resources:\n` +
    `- ${REDEEM_RESOURCE_PREFIX}${inviteId}`
  );
}

// ---------------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------------

/** Which curve this browser can sign with, or why none: `{ok:true, alg}` or
 *  `{ok:false, reason}` with reason 'no_webcrypto', 'no_indexeddb' or 'no_curve'. */
export async function capability() {
  if (typeof indexedDB === 'undefined' || indexedDB === null) return { ok: false, reason: 'no_indexeddb' };
  if (typeof crypto === 'undefined' || !crypto.subtle) return { ok: false, reason: 'no_webcrypto' };
  for (const alg of ['Ed25519', 'P-256']) {
    try {
      const probe = await crypto.subtle.generateKey(BY_ALG[alg].gen, false, ['sign', 'verify']);
      const sig = await crypto.subtle.sign(BY_ALG[alg].sign, probe.privateKey, new Uint8Array([1]));
      if (sig.byteLength > 0) return { ok: true, alg };
    } catch (_) {
      /* try the next curve */
    }
  }
  return { ok: false, reason: 'no_curve' };
}

// ---------------------------------------------------------------------------------
// IndexedDB: one record, the CryptoKeyPair
// ---------------------------------------------------------------------------------

function openDb() {
  return new Promise((ok, fail) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => ok(req.result);
    req.onerror = () => fail(req.error);
    req.onblocked = () => fail(new Error('indexeddb blocked'));
  });
}

async function withStore(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((ok, fail) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => ok(req ? req.result : undefined);
      tx.onerror = () => fail(tx.error);
      tx.onabort = () => fail(tx.error);
    });
  } finally {
    db.close();
  }
}

async function load() {
  const kp = await withStore('readonly', (s) => s.get(RECORD));
  if (kp && kp.privateKey && kp.publicKey) return kp;
  return null;
}

async function create(alg) {
  const kp = await crypto.subtle.generateKey(BY_ALG[alg].gen, false, ['sign', 'verify']);
  await withStore('readwrite', (s) => s.put(kp, RECORD));
  return kp;
}

/** The stored key pair, or a new non-extractable one (stored before it is returned).
 *  `alg` is the curve to generate with, from `capability()`. */
export async function getOrCreateKey(alg) {
  const have = await load();
  if (have) return have;
  return create(alg);
}

/** The public key exported raw and made into a did:key. Only the public half is exported. */
export async function didOf(publicKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return didFromRaw(algOf(publicKey), raw);
}

/** Sign `text` (UTF-8) with the stored key: base64url without padding. For P-256 the
 *  signature is the raw r||s (64 bytes) that WebCrypto returns. */
export async function sign(text, keyPair) {
  const kp = keyPair || (await load());
  if (!kp) throw new Error('no key');
  const sig = await crypto.subtle.sign(
    BY_ALG[algOf(kp.privateKey)].sign,
    kp.privateKey,
    new TextEncoder().encode(text),
  );
  return base64url(new Uint8Array(sig));
}

/** Delete the stored key. */
export async function forgetKey() {
  await withStore('readwrite', (s) => s.delete(RECORD));
}

/** Forget and make a new one (after `did_unusable`, and only then). */
export async function rotateKey(alg) {
  await forgetKey();
  return create(alg);
}
