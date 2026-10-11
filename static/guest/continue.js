// The guest hand-off page. It never creates a key: it looks for the one the join page
// stored in this browser, checks that it is the DID of the guest record, signs the login
// session's nonce with it (the message names the exact redirect URI) and posts the proof.
// The server then lets /sign_in finish. No key material leaves this browser.
import { DB_NAME, STORE, algOf, didOf, sign } from '/guest/assets/guest-key.js';
import { buildContinueMessage } from '/guest/assets/continue-message.js';

const $ = (id) => document.getElementById(id);

const MESSAGES = {
  no_guest: 'Open your invitation link again in this browser.',
  no_key: 'Open your invitation link again in this browser. This browser does not hold the key for this guest, and there is no way to recover it: ask the person who invited you for a new link.',
  no_session: 'Go back to the meeting and start again.',
  unavailable: 'Joining is not available right now. Please try again in a few minutes.',
  framed: 'This page cannot be shown inside another page. Open the link in its own tab.',
  did_mismatch: 'Open your invitation link again in this browser. This browser holds a different key.',
  signature_invalid: 'Your request could not be checked. Please go back to the meeting and try again.',
  network: 'Could not reach the server. Check your connection and try again.',
  other: 'Something went wrong. Go back to the meeting and try again.',
};

function stop(key) {
  $('status').hidden = true;
  $('error').textContent = MESSAGES[key] || MESSAGES.other;
}

/** The stored key pair if there is one. Reads only: never creates. */
function storedKey() {
  return new Promise((ok) => {
    if (typeof indexedDB === 'undefined' || indexedDB === null) return ok(null);
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE); // first visit: empty
    open.onerror = () => ok(null);
    open.onsuccess = () => {
      const db = open.result;
      try {
        const req = db.transaction(STORE, 'readonly').objectStore(STORE).getAll();
        req.onsuccess = () => {
          db.close();
          ok((req.result || []).find((kp) => kp && kp.privateKey && kp.publicKey) || null);
        };
        req.onerror = () => { db.close(); ok(null); };
      } catch (_) {
        db.close();
        ok(null);
      }
    };
  });
}

async function main() {
  if (window.top !== window.self) return stop('framed');
  const app = $('app');
  const state = app.dataset.state;
  if (state !== 'ready') return stop(state);

  const pair = await storedKey();
  if (!pair) return stop('no_key');
  const did = await didOf(pair.publicKey);
  if (did !== app.dataset.did) return stop('did_mismatch');

  const redirectUri = app.dataset.redirect;
  const now = new Date();
  const message = buildContinueMessage({
    domain: location.host,
    alg: algOf(pair.publicKey),
    did,
    uri: location.origin,
    nonce: app.dataset.nonce,
    issuedAt: now,
    expiration: new Date(now.getTime() + 300 * 1000),
    redirectUri,
  });
  let res;
  try {
    res = await fetch('/guest/continue', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      body: JSON.stringify({ redirect_uri: redirectUri, message, signature: await sign(message, pair) }),
    });
  } catch (_) {
    return stop('network');
  }
  let json = {};
  try { json = await res.json(); } catch (_) { /* leave empty */ }
  if (res.status === 200 && json.next) {
    location.assign(json.next);
    return;
  }
  stop(json.error === 'no_session' ? 'no_guest' : json.error || 'other');
}

// Only in a browser: a Node test imports nothing from here, but keep the guard.
if (typeof document !== 'undefined') main().catch(() => stop('other'));
