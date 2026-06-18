// PROBE (local stand-in for the real-authenticator test): does a passkey registered
// through THIS server's flow end up DISCOVERABLE (resident) on the authenticator, and
// can it be used with an EMPTY allowCredentials (the clean usernameless path)?
//
// The CDP virtual authenticator honours the registration's residentKey policy strictly,
// so it models a spec-compliant / Windows-Hello-class authenticator (the worst case for
// "is it already discoverable"). Real iOS/Android/macOS often store discoverable even
// when residentKey=discouraged — only a real device confirms that; this probe gives the
// deterministic lower bound and validates the fix.
import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator, registerPasskey } from './webauthn-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';

test('PROBE: server-registered passkey discoverability + empty-allow get', async ({ page }) => {
  const { client, authenticatorId } = await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'probe-disc-sess', url: BASE }]);
  await page.goto('/account');

  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);

  // (1) Did the authenticator store it as a resident (discoverable) credential?
  const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
  const resident = credentials.map((c) => c.isResidentCredential);
  console.log('PROBE/isResidentCredential=' + JSON.stringify(resident));
  // Crux of the fix: registration must yield a discoverable resident credential.
  expect(resident).toContain(true);

  // (2) Does an EMPTY-allowCredentials get() (discoverable flow) resolve the credential?
  //     Also report how many credentials the live server currently puts in the list.
  const result = await page.evaluate(async () => {
    const b64uToBuf = (s) => {
      const pad = '='.repeat((4 - (s.length % 4)) % 4);
      const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
      const r = atob(b); const u = new Uint8Array(r.length);
      for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
      return u.buffer;
    };
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    const opts = await sr.json();
    const serverAllowLen = (opts.publicKey.allowCredentials || []).length;
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    opts.publicKey.allowCredentials = []; // force the discoverable path
    try {
      const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
      return { serverAllowLen, discoverableGet: 'OK', credId: cred.id };
    } catch (e) {
      return { serverAllowLen, discoverableGet: e.name };
    }
  });
  console.log('PROBE/result=' + JSON.stringify(result));
  // The server no longer enumerates credentials, and the discoverable get resolves.
  expect(result.serverAllowLen).toBe(0);
  expect(result.discoverableGet).toBe('OK');
});
