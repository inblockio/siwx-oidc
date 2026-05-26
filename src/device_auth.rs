use axum::response::Html;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::introspect::generate_opaque_token;
use crate::oidc::{did_to_localpart, CustomError};
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::*;

/// Consonant alphabet for user codes (base-20, no vowels to avoid profanity).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Length of the user code in characters (excluding the separator).
const USER_CODE_LEN: usize = 6;

/// Generate a 6-character user code from consonants, formatted as XXX-XXX.
///
/// 6 consonants from a 20-character alphabet give log2(20^6) ≈ 25.9 bits of
/// entropy, which is comfortably above the ~20-bit minimum recommended by
/// RFC 8628 §6.1 for the lifetime of a device code (600s).
///
/// The shorter format ensures the code fits in narrow client display widgets
/// (notably the Element X mobile verification screen).
pub fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<u8> = (0..USER_CODE_LEN)
        .map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())])
        .collect();
    let mid = USER_CODE_LEN / 2;
    let left = std::str::from_utf8(&chars[..mid]).unwrap();
    let right = std::str::from_utf8(&chars[mid..]).unwrap();
    format!("{}-{}", left, right)
}

#[derive(Deserialize)]
pub struct DeviceAuthRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// RFC 8628 Device Authorization endpoint.
///
/// Validates the client, generates a device code and user code, stores both in
/// Redis, and returns the URIs the device should display to the user.
pub async fn device_authorization(
    config: &Config,
    db_client: &(dyn DBClient + Sync),
    form: DeviceAuthRequest,
) -> Result<DeviceAuthResponse, CustomError> {
    // 1. Validate client_id
    let _client = db_client
        .get_client(form.client_id.clone())
        .await?
        .ok_or_else(|| CustomError::BadRequest("Unknown client_id".to_string()))?;

    // 2. Generate codes
    let device_code = generate_opaque_token("dvc_");
    let user_code = generate_user_code();
    debug!(raw_scope = ?form.scope, "device_authorization: scope from client");
    let scope = form.scope.unwrap_or_else(|| "openid".to_string());

    // 3. Build entry
    let entry = DeviceCodeEntry {
        user_code: user_code.clone(),
        client_id: form.client_id,
        scope: scope.clone(),
        status: DeviceCodeStatus::Pending,
        did: None,
        device_id: None,
        last_poll: None,
        created_at: chrono::Utc::now().timestamp(),
    };

    // 4. Store device code and user_code -> device_code mapping
    db_client
        .set_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
        .await?;
    db_client
        .set_user_code_mapping(&user_code, &device_code, DEVICE_CODE_LIFETIME)
        .await?;

    // 5. Build verification URIs
    let base = config.base_url.as_str().trim_end_matches('/');
    let verification_uri = format!("{}/device", base);
    let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

    info!(
        device_code_prefix = &device_code[..8],
        user_code = %user_code,
        scope = %scope,
        "device_authorization issued"
    );

    Ok(DeviceAuthResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_LIFETIME,
        interval: DEVICE_CODE_INTERVAL,
    })
}

// -- Approval page (GET/POST /device) ----------------------------------------

#[derive(Deserialize)]
pub struct DevicePageQuery {
    pub user_code: Option<String>,
}

/// Sanitize a user-supplied code string for safe HTML interpolation.
///
/// The expected format is `[A-Z0-9-]` (consonant codes from `generate_user_code`
/// or any historic alphanumeric format). Any other character is dropped, and
/// the result is capped at 16 chars to bound memory.
fn sanitize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(16)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Serve the device approval HTML page.
///
/// Visual language mirrors the siwx-oidc landing page (`js/ui/src/App.svelte`):
/// Satoshi from fontshare, `#f5f5f5` background with an ambient orange glow,
/// white card on top, orange gradient primary button, ghost-styled "Deny".
pub fn device_page(query: DevicePageQuery, base_url: &str) -> Html<String> {
    let user_code = sanitize_user_code(query.user_code.as_deref().unwrap_or(""));
    let base = base_url.trim_end_matches('/');
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve device · inblock.io</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link href="https://api.fontshare.com/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body data-user-code="{user_code}" data-base="{base}">
<div class="login-page">
  <div class="ambient-glow"></div>
  <div class="login-card">
    <div class="card-inner">
      <div class="logo-area">
        <img src="/img/inblockio-logo.png" alt="inblock.io" class="logo logo-single">
      </div>

      <div id="code-section" class="auth-section">
        <h1 class="title">Verify device</h1>
        <p class="subtitle">Enter the code shown on your device to continue.</p>
        <input type="text" id="user_code" class="code-input" placeholder="XXX-XXX"
               value="{user_code}" maxlength="9"
               autocomplete="off" autocapitalize="characters" spellcheck="false">
        <button class="btn btn-primary" id="btn-verify" onclick="lookupCode()">
          <span>Verify code</span>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="btn-icon btn-icon-right">
            <path fill-rule="evenodd" d="M3 10a.75.75 0 0 1 .75-.75h10.638L10.23 5.29a.75.75 0 1 1 1.04-1.08l5.5 5.25a.75.75 0 0 1 0 1.08l-5.5 5.25a.75.75 0 1 1-1.04-1.08l4.158-3.96H3.75A.75.75 0 0 1 3 10Z" clip-rule="evenodd"/>
          </svg>
        </button>
      </div>

      <div id="auth-section" class="auth-section hidden">
        <h1 class="title">Approve device</h1>
        <p class="subtitle">Confirm this code matches what's shown on your device.</p>
        <div class="code-chip" id="display-code"></div>

        <button class="btn btn-primary" id="btn-wallet" onclick="approveWallet()">
          <svg xmlns="http://www.w3.org/2000/svg" clip-rule="evenodd" fill-rule="evenodd" viewBox="170 30 220 350" class="btn-icon eth-icon">
            <g fill-rule="nonzero" transform="matrix(.781253 0 0 .781253 180 37.1453)">
              <path d="m127.961 0-2.795 9.5v275.668l2.795 2.79 127.962-75.638z" fill="#343434"/>
              <path d="m127.962 0-127.962 212.32 127.962 75.639v-133.801z" fill="#8c8c8c"/>
              <path d="m127.961 312.187-1.575 1.92v98.199l1.575 4.601 128.038-180.32z" fill="#3c3c3b"/>
              <path d="m127.962 416.905v-104.72l-127.962-75.6z" fill="#8c8c8c"/>
              <path d="m127.961 287.958 127.96-75.637-127.96-58.162z" fill="#141414"/>
              <path d="m.001 212.321 127.96 75.637v-133.799z" fill="#393939"/>
            </g>
          </svg>
          <span>Sign with wallet</span>
        </button>

        <div class="divider">
          <div class="divider-line"></div>
          <span class="divider-text">or</span>
          <div class="divider-line"></div>
        </div>

        <button class="btn btn-secondary" id="btn-passkey" onclick="approvePasskey()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="btn-icon">
            <path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd"/>
          </svg>
          <span>Sign with passkey</span>
        </button>

        <button class="btn btn-ghost btn-deny" onclick="denyDevice()">
          <span>Deny request</span>
        </button>
      </div>

      <div id="terminal-section" class="auth-section hidden">
        <div class="success-badge" id="terminal-badge"></div>
        <h1 class="title" id="terminal-title"></h1>
        <p class="subtitle" id="terminal-subtitle">You can close this page.</p>
      </div>

      <div id="status" class="error-msg hidden">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="error-icon">
          <path fill-rule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 5Zm0 10a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clip-rule="evenodd"/>
        </svg>
        <span id="status-text"></span>
      </div>

      <div class="footer">
        <p>By continuing you agree to the
          <a href="/legal/terms-of-use.html">Terms of Use</a> and
          <a href="/legal/privacy-policy.html">Privacy Policy</a>.
        </p>
      </div>
    </div>
  </div>
</div>
<script>{js}</script>
</body>
</html>"##,
        css = DEVICE_PAGE_CSS,
        js = DEVICE_PAGE_JS,
        user_code = user_code,
        base = base,
    );
    Html(html)
}

/// CSS for the device approval page. Visual tokens mirror `js/ui/src/App.svelte`.
const DEVICE_PAGE_CSS: &str = r##"
:root {
  --bg: #f5f5f5;
  --card-bg: #ffffff;
  --text: #1a1a1a;
  --text-dim: rgba(0,0,0,0.4);
  --text-mute: rgba(0,0,0,0.3);
  --border: rgba(0,0,0,0.06);
  --border-strong: rgba(0,0,0,0.12);
  --accent: #E8611A;
  --accent-strong: #EF5402;
  --accent-deep: #D4570F;
  --danger: #dc2626;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  width: 100%;
  min-height: 100%;
  background: var(--bg);
  overflow-x: hidden;
  font-family: 'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: var(--text);
}
.hidden { display: none !important; }
.login-page {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
  animation: fadeIn 0.6s ease both;
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.ambient-glow {
  position: fixed;
  top: -30%;
  left: 50%;
  transform: translateX(-50%);
  width: 800px;
  height: 600px;
  background: radial-gradient(ellipse at center,
    rgba(232,97,26,0.06) 0%,
    rgba(232,97,26,0.02) 40%,
    transparent 70%);
  pointer-events: none;
  z-index: 0;
}
.login-card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 400px;
  border-radius: 20px;
  background: var(--card-bg);
  border: 1px solid var(--border);
  box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 32px -8px rgba(0,0,0,0.08);
}
.card-inner {
  padding: 40px 36px 32px;
  display: flex;
  flex-direction: column;
}
.logo-area { display: flex; justify-content: center; margin-bottom: 32px; }
.logo { width: 56px; height: 56px; object-fit: contain; border-radius: 12px; }
.auth-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}
.title {
  font-family: 'Satoshi', sans-serif;
  font-weight: 700;
  font-size: 22px;
  line-height: 1.3;
  color: var(--text);
  margin: 0 0 6px;
  letter-spacing: -0.3px;
}
.subtitle {
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-dim);
  margin: 0 0 24px;
  max-width: 300px;
}
.code-input {
  width: 100%;
  height: 56px;
  padding: 0 16px;
  font-family: 'Satoshi', sans-serif;
  font-weight: 700;
  font-size: 22px;
  letter-spacing: 0.2em;
  text-align: center;
  text-transform: uppercase;
  color: var(--text);
  background: rgba(0,0,0,0.025);
  border: 1px solid var(--border);
  border-radius: 12px;
  outline: none;
  margin-bottom: 14px;
  transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
}
.code-input::placeholder {
  color: var(--text-mute);
  letter-spacing: 0.2em;
  font-weight: 500;
}
.code-input:focus {
  background: #ffffff;
  border-color: rgba(232,97,26,0.45);
  box-shadow: 0 0 0 3px rgba(232,97,26,0.12);
}
.code-chip {
  font-family: 'Satoshi', sans-serif;
  font-weight: 900;
  font-size: 30px;
  letter-spacing: 0.22em;
  text-align: center;
  color: var(--text);
  background: rgba(232,97,26,0.06);
  border: 1px solid rgba(232,97,26,0.16);
  border-radius: 14px;
  padding: 18px 24px 18px 30px;
  margin: 0 0 24px;
  width: 100%;
  text-transform: uppercase;
}
.btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 48px;
  padding: 0 20px;
  border-radius: 12px;
  font-family: 'Satoshi', sans-serif;
  font-weight: 600;
  font-size: 14px;
  letter-spacing: 0.1px;
  cursor: pointer;
  transition: all 0.15s ease;
  border: none;
  outline: none;
  width: 100%;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn + .btn { margin-top: 10px; }
.btn-primary {
  background: linear-gradient(135deg, var(--accent-strong) 0%, var(--accent-deep) 100%);
  color: #fff;
  box-shadow: 0 1px 2px rgba(0,0,0,0.1), 0 0 0 1px rgba(232,97,26,0.12) inset;
}
.btn-primary:not(:disabled):hover {
  background: linear-gradient(135deg, #ff6a1a 0%, var(--accent-strong) 100%);
  box-shadow: 0 4px 16px rgba(232,97,26,0.25), 0 0 0 1px rgba(232,97,26,0.15) inset;
  transform: translateY(-1px);
}
.btn-primary:not(:disabled):active { transform: translateY(0); }
.btn-secondary {
  background: rgba(0,0,0,0.03);
  color: var(--text);
  border: 1px solid rgba(0,0,0,0.08);
}
.btn-secondary:not(:disabled):hover {
  background: rgba(0,0,0,0.06);
  border-color: rgba(0,0,0,0.12);
  transform: translateY(-1px);
}
.btn-ghost {
  background: transparent;
  color: var(--text-dim);
  border: 1px solid var(--border);
}
.btn-ghost:not(:disabled):hover {
  color: rgba(0,0,0,0.65);
  background: rgba(0,0,0,0.02);
  border-color: rgba(0,0,0,0.1);
}
.btn-deny { margin-top: 16px; }
.btn-icon { width: 18px; height: 18px; flex-shrink: 0; }
.btn-icon-right { width: 16px; height: 16px; margin-left: -2px; }
.eth-icon { width: 14px; height: 22px; }
.divider {
  display: flex;
  align-items: center;
  gap: 14px;
  margin: 14px 0;
  width: 100%;
}
.divider-line { flex: 1; height: 1px; background: rgba(0,0,0,0.07); }
.divider-text {
  font-size: 12px;
  color: rgba(0,0,0,0.25);
  text-transform: uppercase;
  letter-spacing: 1px;
  font-weight: 500;
}
.success-badge { margin-bottom: 16px; display: flex; justify-content: center; }
.success-icon { width: 44px; height: 44px; color: var(--accent); }
.denied-icon { width: 44px; height: 44px; color: rgba(0,0,0,0.35); }
.error-msg {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 16px;
  padding: 10px 14px;
  border-radius: 10px;
  background: rgba(239,68,68,0.05);
  border: 1px solid rgba(239,68,68,0.12);
}
.error-msg span {
  font-size: 13px;
  line-height: 1.4;
  color: var(--danger);
}
.error-icon {
  width: 16px;
  height: 16px;
  color: var(--danger);
  flex-shrink: 0;
  margin-top: 1px;
}
.error-msg.is-success {
  background: rgba(232,97,26,0.06);
  border-color: rgba(232,97,26,0.18);
}
.error-msg.is-success span { color: var(--accent-deep); }
.error-msg.is-success .error-icon { color: var(--accent-deep); }
.footer {
  margin-top: 28px;
  padding-top: 20px;
  border-top: 1px solid rgba(0,0,0,0.05);
  text-align: center;
}
.footer p {
  font-size: 11px;
  line-height: 1.5;
  color: rgba(0,0,0,0.3);
  margin: 0;
}
.footer a {
  color: rgba(0,0,0,0.45);
  text-decoration: none;
  transition: color 0.15s ease;
}
.footer a:hover { color: rgba(0,0,0,0.7); }
"##;

/// JavaScript for the device approval page.
///
/// Reads `user_code` and `base_url` from `<body data-*>` attributes (set by the
/// server) instead of interpolating them into JS string literals, which avoids
/// XSS via crafted query parameters.
const DEVICE_PAGE_JS: &str = r#"
const BASE = document.body.dataset.base;
let currentUserCode = document.body.dataset.userCode || '';

const $ = (id) => document.getElementById(id);

document.addEventListener('DOMContentLoaded', () => {
  const input = $('user_code');
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); lookupCode(); } });
  input.addEventListener('input', () => hideStatus());
  if (currentUserCode) {
    $('code-section').classList.add('hidden');
    lookupCode();
  } else {
    input.focus();
  }
});

async function lookupCode() {
  const raw = $('user_code').value;
  const code = (raw || currentUserCode || '').trim().toUpperCase();
  if (!code || code.length < 6) {
    showCodeSection();
    showStatus('Enter the code shown on your device.', true);
    return;
  }
  currentUserCode = code;
  setBusy('btn-verify', true);
  try {
    const r = await fetch(BASE + '/device/verify?user_code=' + encodeURIComponent(code));
    if (r.ok) {
      $('code-section').classList.add('hidden');
      $('auth-section').classList.remove('hidden');
      $('display-code').textContent = code;
      hideStatus();
    } else {
      const t = await r.text();
      showCodeSection();
      showStatus(t || 'Code not found or expired.', true);
    }
  } catch (e) {
    showCodeSection();
    showStatus('Network error. Try again.', true);
  } finally {
    setBusy('btn-verify', false);
  }
}

async function approveWallet() {
  hideStatus();
  setBusy('btn-wallet', true, 'Requesting signature...');
  try {
    if (!window.ethereum) { showStatus('No wallet detected. Install MetaMask or another EIP-1193 wallet.', true); return; }
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];
    const did = 'did:pkh:eip155:1:' + address;
    const domain = new URL(BASE).hostname;
    const nonce = Math.random().toString(36).substring(2, 18);
    const issuedAt = new Date().toISOString();
    const message = domain + ' wants you to sign in with your Ethereum account:\n' +
      address + '\n\nApprove device login.\n\nURI: ' + BASE + '\nVersion: 1\nChain ID: 1\n' +
      'Nonce: ' + nonce + '\nIssued At: ' + issuedAt;
    const signature = await window.ethereum.request({ method: 'personal_sign', params: [message, address] });
    const r = await fetch(BASE + '/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: currentUserCode, action: 'approve', did, message, signature })
    });
    if (r.ok) {
      const data = await r.json().catch(() => ({}));
      showTerminal(data.status || 'approved', data.warning);
    } else { const t = await r.text(); showStatus(t || 'Approval failed.', true); }
  } catch (e) {
    showStatus('Wallet error: ' + (e.message || e), true);
  } finally {
    setBusy('btn-wallet', false);
  }
}

async function approvePasskey() {
  hideStatus();
  setBusy('btn-passkey', true, 'Authenticating...');
  try {
    const startR = await fetch(BASE + '/device/passkey/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: currentUserCode })
    });
    if (!startR.ok) { showStatus('Failed to start passkey authentication.', true); return; }
    const options = await startR.json();
    options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      if (options.publicKey.allowCredentials.length === 0) {
        showStatus('No passkeys registered on this server. Register a passkey first.', true);
        return;
      }
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((c) => ({ ...c, id: base64ToBuffer(c.id) }));
    }
    const credential = await navigator.credentials.get({ publicKey: options.publicKey });
    const finishR = await fetch(BASE + '/device/passkey/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_code: currentUserCode,
        id: credential.id,
        rawId: bufferToBase64(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
          signature: bufferToBase64(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64(credential.response.userHandle) : null
        }
      })
    });
    if (finishR.ok) {
      const data = await finishR.json().catch(() => ({}));
      showTerminal(data.status || 'approved', data.warning);
    } else { const t = await finishR.text(); showStatus(t || 'Passkey authentication failed.', true); }
  } catch (e) {
    showStatus('Passkey error: ' + (e.message || e), true);
  } finally {
    setBusy('btn-passkey', false);
  }
}

async function denyDevice() {
  hideStatus();
  try {
    const r = await fetch(BASE + '/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: currentUserCode, action: 'deny' })
    });
    if (r.ok) { showTerminal('denied'); }
    else { showStatus('Failed to deny the request.', true); }
  } catch (e) {
    showStatus('Network error. Try again.', true);
  }
}

const CHECK_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon"><path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd"/></svg>';
const X_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="denied-icon"><path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25Zm-1.72 6.97a.75.75 0 1 0-1.06 1.06L10.94 12l-1.72 1.72a.75.75 0 1 0 1.06 1.06L12 13.06l1.72 1.72a.75.75 0 1 0 1.06-1.06L13.06 12l1.72-1.72a.75.75 0 1 0-1.06-1.06L12 10.94l-1.72-1.72Z" clip-rule="evenodd"/></svg>';

function showTerminal(kind, warning) {
  $('code-section').classList.add('hidden');
  $('auth-section').classList.add('hidden');
  hideStatus();
  const section = $('terminal-section');
  const badge = $('terminal-badge');
  const title = $('terminal-title');
  const subtitle = $('terminal-subtitle');
  if (kind === 'approved') {
    badge.innerHTML = CHECK_SVG;
    title.textContent = 'Device approved';
  } else {
    badge.innerHTML = X_SVG;
    title.textContent = 'Device denied';
  }
  if (warning) {
    subtitle.textContent = warning;
    subtitle.style.color = 'var(--accent-deep)';
  } else {
    subtitle.textContent = 'You can close this page.';
  }
  section.classList.remove('hidden');
}

function showCodeSection() {
  $('code-section').classList.remove('hidden');
  $('auth-section').classList.add('hidden');
}

function showStatus(msg, isError) {
  const el = $('status');
  $('status-text').textContent = msg;
  el.classList.toggle('is-success', !isError);
  el.classList.remove('hidden');
}

function hideStatus() { $('status').classList.add('hidden'); }

function setBusy(id, busy, label) {
  const el = $(id);
  if (!el) return;
  el.disabled = !!busy;
  if (label !== undefined) {
    if (busy) {
      if (!el.dataset.origLabel) el.dataset.origLabel = el.querySelector('span').textContent;
      el.querySelector('span').textContent = label;
    } else if (el.dataset.origLabel) {
      el.querySelector('span').textContent = el.dataset.origLabel;
      delete el.dataset.origLabel;
    }
  }
}

function base64ToBuffer(b64) {
  const padding = '='.repeat((4 - (b64.length % 4)) % 4);
  const s = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(s);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  bytes.forEach((b) => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
"#;

#[cfg(test)]
fn terminal_page(kind: TerminalKind) -> Html<String> {
    let (title, icon_svg) = match kind {
        TerminalKind::Approved => (
            "Device approved",
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon"><path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd"/></svg>"#,
        ),
        TerminalKind::Denied => (
            "Device denied",
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="denied-icon"><path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25Zm-1.72 6.97a.75.75 0 1 0-1.06 1.06L10.94 12l-1.72 1.72a.75.75 0 1 0 1.06 1.06L12 13.06l1.72 1.72a.75.75 0 1 0 1.06-1.06L13.06 12l1.72-1.72a.75.75 0 1 0-1.06-1.06L12 10.94l-1.72-1.72Z" clip-rule="evenodd"/></svg>"#,
        ),
    };
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · inblock.io</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link href="https://api.fontshare.com/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<div class="login-page">
  <div class="ambient-glow"></div>
  <div class="login-card">
    <div class="card-inner">
      <div class="logo-area">
        <img src="/img/inblockio-logo.png" alt="inblock.io" class="logo logo-single">
      </div>
      <div class="auth-section">
        <div class="success-badge">{icon}</div>
        <h1 class="title">{title}</h1>
        <p class="subtitle">You can close this page.</p>
      </div>
    </div>
  </div>
</div>
</body>
</html>"#,
        css = DEVICE_PAGE_CSS,
        title = title,
        icon = icon_svg,
    ))
}

#[derive(Copy, Clone)]
#[cfg(test)]
enum TerminalKind {
    Approved,
    Denied,
}

#[derive(Serialize)]
pub struct DeviceApproveResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

const CROSS_SIGNING_WARNING: &str = "Your account has no Secure Backup set up. \
     The QR code login will fail because encryption keys cannot be transferred. \
     Please set up Secure Backup in Element Web first, then retry the QR code flow.";

async fn check_cross_signing(
    did: &str,
    synapse_client: Option<&SynapseClient>,
    server_name: Option<&str>,
) -> Option<String> {
    let (synapse, sn) = match (synapse_client, server_name) {
        (Some(s), Some(n)) => (s, n),
        _ => return None,
    };
    let localpart = did_to_localpart(did);
    match synapse.has_cross_signing_keys(&localpart, sn).await {
        Ok(true) => None,
        Ok(false) => {
            warn!(did = %did, "device approval: user has no cross-signing keys");
            Some(CROSS_SIGNING_WARNING.to_string())
        }
        Err(e) => {
            debug!("cross-signing check failed (skipping warning): {}", e);
            None
        }
    }
}

/// Verify that a user code exists and is pending.
pub async fn device_verify(
    db_client: &(dyn DBClient + Sync),
    user_code: &str,
) -> Result<(), CustomError> {
    let (_dc, entry) = db_client
        .get_device_code_by_user_code(user_code)
        .await?
        .ok_or_else(|| CustomError::BadRequest("User code not found or expired".to_string()))?;
    if entry.status != DeviceCodeStatus::Pending {
        return Err(CustomError::BadRequest("Code already used".to_string()));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct DeviceApproveRequest {
    pub user_code: String,
    pub action: String,
    pub did: Option<String>,
    pub message: Option<String>,
    pub signature: Option<String>,
}

/// Process a device approval or denial via CAIP-122 wallet signature.
pub async fn device_approve(
    config: &Config,
    db_client: &(dyn DBClient + Sync),
    req: DeviceApproveRequest,
    synapse_client: Option<&SynapseClient>,
) -> Result<DeviceApproveResponse, CustomError> {
    let (device_code, mut entry) = db_client
        .get_device_code_by_user_code(&req.user_code)
        .await?
        .ok_or_else(|| CustomError::BadRequest("User code not found or expired".to_string()))?;

    if entry.status != DeviceCodeStatus::Pending {
        return Err(CustomError::BadRequest("Code already used".to_string()));
    }

    if req.action == "deny" {
        entry.status = DeviceCodeStatus::Denied;
        let _ = db_client
            .update_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
            .await;
        info!(user_code = %req.user_code, "device denied");
        return Ok(DeviceApproveResponse {
            status: "denied".to_string(),
            warning: None,
        });
    }

    // Approve: verify the wallet signature
    let did = req
        .did
        .as_ref()
        .ok_or_else(|| CustomError::BadRequest("Missing DID".to_string()))?;
    let message = req
        .message
        .as_ref()
        .ok_or_else(|| CustomError::BadRequest("Missing message".to_string()))?;
    let signature = req
        .signature
        .as_ref()
        .ok_or_else(|| CustomError::BadRequest("Missing signature".to_string()))?;

    let sig_hex = signature.strip_prefix("0x").unwrap_or(signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    let did_method = aqua_auth::find_did_method(did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", did)))?;

    if !config
        .supported_did_methods
        .iter()
        .any(|m| m == did_method.method_name())
    {
        return Err(CustomError::BadRequest(format!(
            "DID method '{}' is not enabled on this server",
            did_method.method_name()
        )));
    }

    let valid = did_method
        .verify(did, message, &sig_bytes)
        .map_err(|e| CustomError::BadRequest(format!("Verification error: {}", e)))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    let warning =
        check_cross_signing(did, synapse_client, config.matrix_server_name.as_deref()).await;

    entry.status = DeviceCodeStatus::Approved;
    entry.did = Some(did.clone());
    let _ = db_client
        .update_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
        .await;
    info!(user_code = %req.user_code, did = %did, "device approved");

    Ok(DeviceApproveResponse {
        status: "approved".to_string(),
        warning,
    })
}

/// Process a device approval via passkey (WebAuthn).
/// Called after the passkey ceremony verifies the DID server-side.
pub async fn device_approve_passkey(
    db_client: &(dyn DBClient + Sync),
    user_code: &str,
    verified_did: &str,
    synapse_client: Option<&SynapseClient>,
    matrix_server_name: Option<&str>,
) -> Result<DeviceApproveResponse, CustomError> {
    let (device_code, mut entry) = db_client
        .get_device_code_by_user_code(user_code)
        .await?
        .ok_or_else(|| CustomError::BadRequest("User code not found or expired".to_string()))?;

    if entry.status != DeviceCodeStatus::Pending {
        return Err(CustomError::BadRequest("Code already used".to_string()));
    }

    let warning = check_cross_signing(verified_did, synapse_client, matrix_server_name).await;

    entry.status = DeviceCodeStatus::Approved;
    entry.did = Some(verified_did.to_string());
    let _ = db_client
        .update_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
        .await;
    info!(user_code = %user_code, did = %verified_did, "device approved via passkey");

    Ok(DeviceApproveResponse {
        status: "approved".to_string(),
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_page_renders_landing_page_brand() {
        let html = device_page(
            DevicePageQuery {
                user_code: Some("JKQ-WZL".to_string()),
            },
            "https://siwx-oidc.example.com",
        )
        .0;
        // Brand markers from the landing page (App.svelte).
        assert!(
            html.contains("api.fontshare.com/css?f[]=satoshi"),
            "Satoshi font must be loaded"
        );
        assert!(
            html.contains("--accent: #E8611A"),
            "brand accent must be set"
        );
        assert!(
            html.contains("ambient-glow"),
            "ambient glow must be present"
        );
        assert!(html.contains("inblockio-logo.png"), "logo must be present");
        // Endpoint URLs must remain unchanged so existing flow works.
        assert!(html.contains("/device/verify?user_code="));
        assert!(html.contains("/device/passkey/start"));
        assert!(html.contains("/device/passkey/finish"));
        // User code and base must be injected via data-* (not JS literals).
        assert!(html.contains(r#"data-user-code="JKQ-WZL""#));
        assert!(html.contains(r#"data-base="https://siwx-oidc.example.com""#));
        // Placeholder reflects the new format.
        assert!(html.contains(r#"placeholder="XXX-XXX""#));
    }

    #[test]
    fn device_page_sanitizes_malicious_user_code() {
        let html = device_page(
            DevicePageQuery {
                user_code: Some("\"><script>alert(1)</script>".to_string()),
            },
            "https://siwx-oidc.example.com",
        )
        .0;
        // Raw script tag must not appear in the rendered HTML.
        assert!(!html.contains("<script>alert"));
        // The injected data attribute must contain only the sanitized residue
        // (alphanumeric + hyphen, uppercased, capped at 16 chars).
        assert!(html.contains(r#"data-user-code="SCRIPTALERT1SCRI""#));
    }

    /// Opt-in: write rendered HTML to /tmp for browser inspection.
    /// Run with: `WRITE_DEVICE_PREVIEWS=1 cargo test device_auth::tests::write_previews -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn write_previews() {
        if std::env::var("WRITE_DEVICE_PREVIEWS").is_err() {
            return;
        }
        let cases: [(&str, Option<String>); 2] = [
            ("verify-empty", None),
            ("verify-prefilled", Some("JKQ-WZL".to_string())),
        ];
        for (name, code) in cases {
            let html = device_page(
                DevicePageQuery { user_code: code },
                "https://siwx-oidc.example.com",
            )
            .0;
            let path = format!("/tmp/device-{name}.html");
            std::fs::write(&path, html).unwrap();
            println!("wrote {path}");
        }
        std::fs::write(
            "/tmp/device-approved.html",
            terminal_page(TerminalKind::Approved).0,
        )
        .unwrap();
        std::fs::write(
            "/tmp/device-denied.html",
            terminal_page(TerminalKind::Denied).0,
        )
        .unwrap();
        println!("wrote /tmp/device-approved.html and /tmp/device-denied.html");
    }

    #[test]
    fn terminal_pages_use_landing_brand() {
        let approved = terminal_page(TerminalKind::Approved).0;
        assert!(approved.contains("Device approved"));
        assert!(approved.contains("api.fontshare.com/css?f[]=satoshi"));
        assert!(approved.contains("inblockio-logo.png"));

        let denied = terminal_page(TerminalKind::Denied).0;
        assert!(denied.contains("Device denied"));
        assert!(denied.contains("--accent: #E8611A"));
    }

    #[test]
    fn sanitize_user_code_strips_unsafe_chars() {
        assert_eq!(sanitize_user_code(""), "");
        assert_eq!(sanitize_user_code("abc-def"), "ABC-DEF");
        assert_eq!(sanitize_user_code("JKQ-WZL"), "JKQ-WZL");
        // HTML/JS injection chars must be removed.
        assert_eq!(sanitize_user_code("\"><script>"), "SCRIPT");
        assert_eq!(sanitize_user_code("';alert(1);//"), "ALERT1");
        // Length is capped at 16.
        assert_eq!(sanitize_user_code(&"A".repeat(100)).len(), 16);
    }

    #[test]
    fn user_code_format() {
        for _ in 0..1000 {
            let code = generate_user_code();
            assert_eq!(code.len(), 7, "expected 7 chars (XXX-XXX), got {code:?}");
            assert_eq!(
                code.as_bytes()[3],
                b'-',
                "separator must be at index 3: {code:?}"
            );
            let body = code.replace('-', "");
            assert_eq!(body.len(), USER_CODE_LEN);
            for b in body.as_bytes() {
                assert!(
                    USER_CODE_ALPHABET.contains(b),
                    "char {:?} not in consonant alphabet (code {code:?})",
                    *b as char
                );
            }
        }
    }
}
