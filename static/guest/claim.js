// The claim page (S7b): a guest keeps the account with a passkey. The state machine is
// design 05, section 6.2 (CL-01 .. CL-07, CL-E1 .. CL-E10). The cookie authorises every call;
// no Bearer token is used here. The page never sees or derives a private key: the passkey is
// made by the browser, and only its public attestation goes to /guest/claim/finish. After a
// commit or a lost race this browser forgets the guest key it made for the joined account.
import { base64url, forgetKey } from '/guest/assets/guest-key.js';

const $ = (id) => document.getElementById(id);
const CHALLENGE_MS = 120 * 1000; // the server keeps the creation challenge for 120 s

const ERRORS = {
  'CL-E1': { title: 'No guest session here', text: 'This browser does not hold your guest session. Claim in the browser you joined with.', action: 'close' },
  'CL-E2': { title: 'This session has ended', text: 'This session has ended, nothing was kept. If you just created a passkey, remove it from your device.', action: 'close' },
  'CL-E3': { title: 'You already keep this account', text: 'You already keep this account. Sign in with your passkey.', action: 'signin' },
  'CL-E4': { title: 'Not available', text: 'Keeping guest accounts is not available right now.', action: 'close' },
  'CL-E5': { title: 'This browser cannot create a passkey', text: 'This browser or device cannot create a passkey. Open this page in another browser, or choose a phone when the passkey prompt offers it. Your guest session stays as it is.', action: 'back' },
  'CL-E6': { title: 'Nothing was changed', text: 'Nothing was changed.', action: 'back' },
  'CL-E7': { title: 'It took too long', text: 'It took too long. A prompt on a phone can be slow. Nothing was changed.', action: 'back' },
  'CL-E8': { title: 'We could not verify the passkey', text: 'We could not verify the passkey. Nothing was kept. If this keeps happening, contact the person who runs this service.', action: 'back' },
  'CL-E9': { title: 'Try again in a moment', text: 'Try again in a moment. Nothing was kept yet.', action: 'back' },
  'CL-E10': { title: 'Too many attempts', text: 'Too many attempts. Wait a while, then try again.', action: 'back' },
};

let clientUrl = null;
let secondsLeft = 0;
let leftAt = 0;

function announce(text) {
  const live = $('live');
  live.textContent = '';
  // A new text node after a tick, so a screen reader reads a repeated message again.
  setTimeout(() => { live.textContent = text; }, 30);
}

/** Show one state, move focus to its heading and say it in the live region. */
function show(sectionId, code) {
  for (const s of document.querySelectorAll('#app > section')) s.hidden = s.id !== sectionId;
  const section = $(sectionId);
  $('app').dataset.state = code;
  const heading = section.querySelector('h2');
  heading.focus();
  announce(heading.textContent);
}

function fail(code, text) {
  const e = ERRORS[code];
  $('err-title').textContent = e.title;
  $('err-text').textContent = text || e.text;
  $('err-signin').hidden = !(e.action === 'signin' && clientUrl);
  if (clientUrl) $('err-signin').href = clientUrl;
  $('err-back').hidden = e.action !== 'back';
  $('err-close').hidden = e.action !== 'close';
  $('cl-err').dataset.code = code;
  show('cl-err', code);
}

function timeLeft(secs) {
  if (secs < 60) return 'less than a minute';
  const m = Math.round(secs / 60);
  if (m < 120) return `about ${m} minute${m === 1 ? '' : 's'}`;
  return `about ${Math.round(m / 60)} hours`;
}

function remaining() {
  return Math.max(0, secondsLeft - Math.floor((Date.now() - leftAt) / 1000));
}

async function call(method, path, body) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (_) {
    return { status: 0, json: {} };
  }
  let json = {};
  try { json = await res.json(); } catch (_) { /* leave empty */ }
  return { status: res.status, json };
}

function fromBase64url(s) {
  const b = (s + '='.repeat((4 - (s.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** The creation options as the server sends them (base64url strings) to what the browser takes. */
function creationOptions(ccr) {
  const pk = ccr.publicKey;
  pk.challenge = fromBase64url(pk.challenge);
  pk.user.id = fromBase64url(pk.user.id);
  for (const c of pk.excludeCredentials || []) c.id = fromBase64url(c.id);
  return pk;
}

async function forget() {
  try { await forgetKey(); } catch (_) { /* nothing to forget, or storage is blocked */ }
}

/** The error code of a claim route answer, mapped to its CL-E state (design table, section 6.2). */
function stateForClaimError(r) {
  const code = r.json && r.json.error;
  if (r.status === 0 || r.status >= 500) return 'CL-E9';
  if (r.status === 429) return 'CL-E10';
  switch (code) {
    case 'no_session': return 'CL-E1';
    case 'ended': case 'lost_race': return 'CL-E2';
    case 'already_claimed': return 'CL-E3';
    case 'claim_unavailable': return 'CL-E4';
    case 'verify_failed': case 'bad_request': return 'CL-E8';
    case 'claim_in_progress': case 'unavailable': return 'CL-E9';
    default: break;
  }
  if (r.status === 400) return 'CL-E8';
  if (r.status === 401) return 'CL-E1';
  if (r.status === 410) return 'CL-E2';
  return 'CL-E9';
}

/** Show a CL-E state; the ones that mean "this guest account is over" also drop the key. */
async function failWith(code) {
  if (code === 'CL-E2' || code === 'CL-E3') await forget();
  fail(code);
}

async function load() {
  show('cl-01', 'CL-01');
  const r = await call('GET', '/guest/resume');
  if (r.status === 429) return fail('CL-E10');
  if (r.status === 0 || r.status >= 500) return fail('CL-E9');
  if (r.status === 403) return fail('CL-E1');
  if (r.status !== 200) return fail('CL-E9');
  const v = r.json;
  clientUrl = typeof v.client_url === 'string' ? v.client_url : null;
  if (v.state === 'no_session') return fail('CL-E1');
  if (v.state === 'claimed') return failWith('CL-E3');
  if (v.state !== 'active' || v.claim_allowed !== true) return fail('CL-E4');
  secondsLeft = Number(v.seconds_left) || 0;
  leftAt = Date.now();
  if (secondsLeft <= 0) return failWith('CL-E2');
  $('who').textContent = [v.first_name, v.second_name].filter(Boolean).join(' ') || 'a guest';
  $('left').textContent = timeLeft(secondsLeft);
  $('email-choice').hidden = v.email_present !== true;
  $('email-remove').checked = true; // the default is always remove
  show('cl-02', 'CL-02');
}

async function create() {
  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
    return fail('CL-E5');
  }
  const keepEmail = !$('email-choice').hidden && $('email-keep').checked;
  show('cl-03', 'CL-03');
  const started = await call('POST', '/guest/claim/start', {});
  if (started.status !== 200) return failWith(stateForClaimError(started));
  const startedAt = Date.now();
  let options;
  try { options = creationOptions(started.json); } catch (_) { return fail('CL-E9'); }

  show('cl-04', 'CL-04');
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: options });
  } catch (err) {
    if (Date.now() - startedAt > CHALLENGE_MS) return fail('CL-E7');
    if (err && err.name === 'NotAllowedError') return fail('CL-E6');
    return fail('CL-E5'); // NotSupportedError, SecurityError, InvalidStateError ...
  }
  if (!cred || !cred.response) return fail('CL-E5');
  if (Date.now() - startedAt > CHALLENGE_MS) return fail('CL-E7');

  show('cl-05', 'CL-05');
  const att = cred.response;
  const body = {
    id: cred.id,
    rawId: base64url(new Uint8Array(cred.rawId)),
    type: cred.type,
    response: {
      attestationObject: base64url(new Uint8Array(att.attestationObject)),
      clientDataJSON: base64url(new Uint8Array(att.clientDataJSON)),
    },
    extensions: typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {},
    keep_email: keepEmail,
  };
  if (typeof att.getTransports === 'function') body.response.transports = att.getTransports();
  const done = await call('POST', '/guest/claim/finish', body); // once; the button is disabled
  if (done.status === 200 && done.json.state === 'claimed') {
    await forget(); // the guest key is of no use any more
    if (clientUrl) {
      $('back-to-call').href = clientUrl;
      $('back-to-call').hidden = false;
    }
    return show('cl-06', 'CL-06');
  }
  return failWith(stateForClaimError(done));
}

function decline() {
  $('left-decline').textContent = timeLeft(remaining());
  show('cl-07', 'CL-07');
}

async function deleteNow() {
  const button = $('delete-now');
  button.disabled = true;
  try {
    const r = await call('POST', '/guest/end', {});
    if (r.status === 200) {
      await forget();
      return show('cl-07-done', 'CL-07-DONE');
    }
    if (r.status === 409) return await failWith('CL-E3');
    if (r.status === 401) return fail('CL-E1');
    if (r.status === 429) return fail('CL-E10');
    return fail('CL-E9', 'Try again in a moment. Nothing was deleted yet.');
  } finally {
    button.disabled = false;
  }
}

function closeTab(ev) {
  window.close();
  // A browser refuses to close a tab the script did not open.
  setTimeout(() => {
    const note = ev.target.closest('section').querySelector('[data-closed]');
    if (note) note.hidden = false;
  }, 250);
}

function main() {
  if (window.top !== window.self) return; // framed: the CSP and X-Frame-Options already refuse
  const trust = $('trust-statement');
  for (const slot of document.querySelectorAll('[data-trust]')) slot.appendChild(trust.content.cloneNode(true));
  $('create').addEventListener('click', () => { create().catch(() => fail('CL-E9')); });
  $('decline').addEventListener('click', decline);
  $('delete-now').addEventListener('click', () => { deleteNow().catch(() => fail('CL-E9', 'Try again in a moment. Nothing was deleted yet.')); });
  $('err-back').addEventListener('click', () => { load().catch(() => fail('CL-E9')); });
  for (const b of document.querySelectorAll('[data-close]')) b.addEventListener('click', closeTab);
  load().catch(() => fail('CL-E9'));
}

if (typeof document !== 'undefined') main();
