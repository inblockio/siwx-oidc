// Reusable WebAuthn (passkey) primitives for the siwx-oidc browser E2E suite.
//
// Uses the CDP WebAuthn virtual authenticator (CTAP2, resident keys, UV) plus a
// per-page ceremony counter so a test can prove "exactly one navigator.credentials
// ceremony". The in-page register/authenticate ceremonies are extracted verbatim
// (behaviour-preserving) from account.spec.mjs.

// -- base64url <-> ArrayBuffer (in-page, so they are stringified into evaluate) --
// These are defined as plain functions and re-declared inside the page contexts
// where needed; exported here only for documentation/reuse from Node side.

// Instrument navigator.credentials.create / .get so a test can assert how many
// ceremonies happened. Sets window.__wa = { create, get }. Lifted verbatim from
// account.spec.mjs::instrumentCeremonyCounters.
export async function countCeremonies(page) {
  await page.addInitScript(() => {
    window.__wa = { create: 0, get: 0 };
    if (navigator.credentials) {
      const c = navigator.credentials;
      const oc = c.create && c.create.bind(c);
      const og = c.get && c.get.bind(c);
      if (oc) c.create = (...a) => { window.__wa.create++; return oc(...a); };
      if (og) c.get = (...a) => { window.__wa.get++; return og(...a); };
    }
  });
}

// Read the ceremony counters set up by countCeremonies.
export async function ceremonyCounts(page) {
  return page.evaluate(() => window.__wa || { create: 0, get: 0 });
}

// Attach a CDP WebAuthn virtual authenticator (internal/CTAP2, resident keys,
// UV always verified). Returns { client, authenticatorId } so a caller can later
// remove or inspect it. Lifted verbatim from account.spec.mjs.
export async function addVirtualAuthenticator(page) {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId };
}

// In-page WebAuthn REGISTRATION ceremony against /webauthn/register/{start,finish}.
// Uses the active virtual authenticator. Returns the derived did:key. This is the
// exact body of account.spec.mjs::registerPasskeyInPage, kept here as a single
// source of truth. It is a *function reference* that gets serialized into
// page.evaluate (so it must be self-contained — no closure over module scope).
export function registerPasskeyInPage() {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(b); const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  const bufToB64u = (buf) => {
    const by = new Uint8Array(buf); let s = '';
    by.forEach((x) => (s += String.fromCharCode(x)));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return (async () => {
    const sr = await fetch('/webauthn/register/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ display_name: null }),
    });
    if (!sr.ok) throw new Error('register start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    opts.publicKey.user.id = b64uToBuf(opts.publicKey.user.id);
    if (opts.publicKey.excludeCredentials)
      for (const c of opts.publicKey.excludeCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
    const att = cred.response;
    const fr = await fetch('/webauthn/register/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
        response: {
          attestationObject: bufToB64u(att.attestationObject),
          clientDataJSON: bufToB64u(att.clientDataJSON),
        },
      }),
    });
    if (!fr.ok) throw new Error('register finish ' + fr.status + ' ' + (await fr.text()));
    return (await fr.json()).did;
  })();
}

// Convenience wrapper: register a passkey and return its did:key.
export async function registerPasskey(page) {
  return page.evaluate(registerPasskeyInPage);
}

// In-page WebAuthn AUTHENTICATION ceremony for the *login* path:
//   POST /webauthn/authenticate/start  -> challenge (keyed to the `session` cookie)
//   navigator.credentials.get()
//   POST /webauthn/authenticate/finish -> stores verified_did in the Redis session
// Returns the server's authenticate/finish JSON ({ did, ... }) on success, or
// throws with the HTTP status+body on failure (so a replay test can assert the
// rejection). Self-contained for page.evaluate.
export function authenticatePasskeyInPage() {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(b); const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  const bufToB64u = (buf) => {
    const by = new Uint8Array(buf); let s = '';
    by.forEach((x) => (s += String.fromCharCode(x)));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return (async () => {
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!sr.ok) throw new Error('authenticate start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const r = cred.response;
    const body = {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        authenticatorData: bufToB64u(r.authenticatorData),
        clientDataJSON: bufToB64u(r.clientDataJSON),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
      },
    };
    const fr = await fetch('/webauthn/authenticate/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!fr.ok) throw new Error('authenticate finish ' + fr.status + ' ' + (await fr.text()));
    return await fr.json();
  })();
}

export async function authenticatePasskey(page) {
  return page.evaluate(authenticatePasskeyInPage);
}
