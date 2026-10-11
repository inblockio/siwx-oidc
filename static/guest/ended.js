// The ended page: the guest account is gone, so this browser drops the key it made for it.
// Runs with no cookie and no record: it needs nothing from the server.
import { forgetKey } from '/guest/assets/guest-key.js';

async function main() {
  const app = document.getElementById('app');
  try {
    await forgetKey();
    app.dataset.forgotten = 'true';
  } catch (_) {
    // Nothing to forget, or storage is blocked: the copy above stays true for the server.
    app.dataset.forgotten = 'false';
  }
}

if (typeof document !== 'undefined') main();
