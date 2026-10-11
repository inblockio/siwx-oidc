// The ended page: the guest account is gone, so this browser drops the key it made for it.
// Runs with no cookie and no record: it needs nothing from the server, except to tell a kept
// (claimed) account from an ended one for ten minutes after a claim (`resume` says `claimed`).
// The key is forgotten in both cases: a claimed account signs in with its passkey.
import { forgetKey } from '/guest/assets/guest-key.js';

async function claimed() {
  try {
    const r = await fetch('/guest/resume', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) return false;
    return (await r.json()).state === 'claimed';
  } catch (_) {
    return false;
  }
}

async function main() {
  const app = document.getElementById('app');
  if (await claimed()) {
    app.dataset.state = 'claimed';
    document.getElementById('title').textContent = 'Your account is kept';
    document.getElementById('status').textContent =
      'You saved this account with a passkey. Sign in with it any time; this browser forgets its guest key.';
  }
  try {
    await forgetKey();
    app.dataset.forgotten = 'true';
  } catch (_) {
    // Nothing to forget, or storage is blocked: the copy above stays true for the server.
    app.dataset.forgotten = 'false';
  }
}

if (typeof document !== 'undefined') main();
