// The guest join page. The invite secret is in the URL fragment, so it never reached the
// server on the GET; it is read once, dropped from the address bar, and sent only in the
// body of POST /guest/peek and /guest/redeem. The private key stays in this browser.
import {
  buildRedeemMessage, capability, didOf, getOrCreateKey, rotateKey, sign,
} from '/guest/assets/guest-key.js';

const $ = (id) => document.getElementById(id);
const CONSENT_VARIANT = 'a';
const NONCE_FRESH_MS = 3 * 60 * 1000;

const MESSAGES = {
  invalid_link: 'This link is not valid. Check that you copied all of it, or ask the person who invited you for a new one.',
  ended: 'This invitation has already been used or has ended. If you joined from this browser, open the meeting link you were given. Otherwise ask the person who invited you for a new one.',
  bad_request: 'The form could not be read. Please check it and try again.',
  name_empty: 'Please enter your first name and your last name.',
  name_too_long: 'One of your names is too long.',
  name_chars: 'Names can contain letters, spaces, hyphens and apostrophes.',
  name_mixed_script: 'Please write each name in one alphabet.',
  name_reserved: 'That name is not available. Please use your own name.',
  email_required: 'Please enter your e-mail address.',
  email_invalid: 'That e-mail address does not look right.',
  email_not_allowed: 'Please use a different e-mail address.',
  consent_required: 'Please tick the box to agree before you join.',
  did_invalid: 'This browser could not make the key needed to join. Try another browser.',
  did_unsupported: 'This browser could not make the key needed to join. Try another browser.',
  did_unusable: 'This browser could not make a usable key. Please try again.',
  did_in_use: 'This browser has already been used to join with another invitation. Ask the person who invited you for help.',
  proof_invalid: 'Your request timed out. Please try again.',
  quota_exceeded: 'Too many guests have joined for now. Please try again later or ask the person who invited you.',
  disabled: 'Joining is not available right now. Please try again in a few minutes.',
  unavailable: 'Joining is not available right now. Please try again in a few minutes.',
  network: 'Could not reach the server. Check your connection and try again.',
  capability: 'This browser cannot create the key needed to join. Please open the link in a current version of Chrome, Firefox, Safari or Edge.',
  framed: 'This page cannot be shown inside another page. Open the link in its own tab.',
  other: 'Something went wrong. Please try again.',
};

/** Show a blocking message instead of the form. */
function block(key, title) {
  $('status').hidden = true;
  $('join-form').hidden = true;
  if (title) $('title').textContent = title;
  $('blocked-text').textContent = MESSAGES[key] || MESSAGES.other;
  $('blocked').hidden = false;
}

async function post(path, body) {
  let res;
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      body: JSON.stringify(body),
    });
  } catch (_) {
    return { status: 0, json: { error: 'network' } };
  }
  let json = {};
  try { json = await res.json(); } catch (_) { /* leave empty */ }
  return { status: res.status, json };
}

async function main() {
  if (window.top !== window.self) return block('framed'); // refuse to run framed

  const inviteId = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');
  const secret = decodeURIComponent(location.hash.replace(/^#/, ''));
  history.replaceState(null, '', location.pathname); // the secret leaves the address bar
  if (!inviteId || !secret) return block('invalid_link', 'Invitation');

  const cap = await capability();
  if (!cap.ok) return block('capability', 'Browser not supported');

  let peek = null;
  let peekedAt = 0;
  const doPeek = async () => {
    const r = await post('/guest/peek', { invite_id: inviteId, secret });
    if (r.status === 200) { peek = r.json; peekedAt = Date.now(); }
    return r;
  };
  const first = await doPeek();
  if (first.status === 404) return block('invalid_link', 'Invitation');
  if (first.status !== 200) return block(first.json.error || 'unavailable', 'Invitation');
  if (first.json.state !== 'active') return block('ended', 'Invitation ended');
  if (Array.isArray(peek.curves) && !peek.curves.includes(cap.alg)) return block('capability', 'Browser not supported');

  // The form, per the invite's policy.
  const policy = peek.email_policy;
  $('email-row').hidden = policy === 'off';
  $('email-opt').hidden = policy !== 'optional';
  $('recording').hidden = !peek.recording_expected;
  $('status').hidden = true;
  $('join-form').hidden = false;

  const fail = (key) => { $('error').textContent = MESSAGES[key] || MESSAGES.other; };

  $('join-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    fail('');
    const button = $('submit');
    button.disabled = true;
    try {
      if (!$('consent').checked) return fail('consent_required');
      if (Date.now() - peekedAt > NONCE_FRESH_MS) {
        const again = await doPeek();
        if (again.status === 404) return block('invalid_link', 'Invitation');
        if (again.status !== 200) return fail(again.json.error || 'unavailable');
        if (again.json.state !== 'active') return block('ended', 'Invitation ended');
      }
      let pair = await getOrCreateKey(cap.alg); // generated before redeem
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const did = await didOf(pair.publicKey);
        const now = new Date();
        const message = buildRedeemMessage({
          domain: location.host,
          alg: pair.publicKey.algorithm.name === 'Ed25519' ? 'Ed25519' : 'P-256',
          did,
          uri: location.origin,
          nonce: peek.nonce,
          issuedAt: now,
          expiration: new Date(now.getTime() + 300 * 1000),
          inviteId,
        });
        const body = {
          invite_id: inviteId,
          secret,
          first_name: $('first_name').value.trim(),
          second_name: $('second_name').value.trim(),
          consent: { version: peek.consent_version, variant: CONSENT_VARIANT },
          did,
          proof: { message, signature: await sign(message, pair) },
        };
        const email = $('email').value.trim();
        if (policy !== 'off' && email) body.email = email;
        const r = await post('/guest/redeem', body);
        if (r.status === 200 && r.json.guest_client_url) {
          location.assign(r.json.guest_client_url);
          return;
        }
        const code = r.json.error || (r.status === 0 ? 'network' : 'other');
        if (code === 'did_unusable' && attempt === 0) {
          pair = await rotateKey(cap.alg); // a new key, one retry
          continue;
        }
        if (r.status === 404) return block('invalid_link', 'Invitation');
        if (r.status === 410) return block('ended', 'Invitation ended');
        if (code === 'proof_invalid') await doPeek(); // a fresh nonce for the next try
        return fail(code);
      }
    } catch (_) {
      fail('other');
    } finally {
      button.disabled = false;
    }
  });
}

main().catch(() => block('other', 'Invitation'));
