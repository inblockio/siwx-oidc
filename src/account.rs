//! MSC4191 account management page and MSC4312 cross-signing reset flow.
//!
//! Provides:
//! - `GET /account` — renders the account management page
//! - `POST /account/wallet` — wallet (CAIP-122) re-auth + action execution
//! - `POST /account/passkey/start` — start passkey authentication
//! - `POST /account/passkey/finish` — finish passkey auth + action execution

use axum::response::Html;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::Config;
use crate::oidc::{did_to_localpart, CustomError};
use crate::synapse_client::SynapseClient;
use crate::webauthn as wa;
use siwx_oidc::db::RedisClient;

// -- Request/response types ---------------------------------------------------

#[derive(Deserialize)]
pub struct AccountPageQuery {
    pub action: Option<String>,
    #[allow(dead_code)]
    pub id_token_hint: Option<String>,
}

#[derive(Deserialize)]
pub struct AccountWalletRequest {
    pub action: String,
    pub did: String,
    pub message: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct AccountPasskeyFinishRequest {
    pub action: String,
    #[serde(flatten)]
    pub credential: serde_json::Value,
}

#[derive(Serialize)]
pub struct AccountActionResponse {
    pub status: String,
    pub action: String,
}

// -- Supported actions --------------------------------------------------------

const ACTION_CROSS_SIGNING_RESET: &str = "org.matrix.cross_signing_reset";

/// A normalized MSC4191 account-management action.
///
/// The wire protocol has two generations of action strings: the stable
/// `device_*` set (Matrix v1.18) and the older `session_*` aliases. Both are
/// accepted on input (see [`canonical_action`]) and collapse onto these
/// variants, so the rest of the code only ever reasons about one set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// `org.matrix.profile` — view the account profile/identity.
    Profile,
    /// `org.matrix.devices_list` / `org.matrix.sessions_list`.
    DevicesList,
    /// `org.matrix.device_view` / `org.matrix.session_view` (needs `device_id`).
    DeviceView,
    /// `org.matrix.device_delete` / `org.matrix.session_end` (needs `device_id`).
    DeviceDelete,
    /// `org.matrix.cross_signing_reset` (MSC4312).
    CrossSigningReset,
}

impl Action {
    /// Whether this action requires a `device_id` query parameter.
    pub fn requires_device_id(self) -> bool {
        matches!(self, Action::DeviceView | Action::DeviceDelete)
    }
}

/// The full superset of MSC4191 action strings this server advertises in
/// `account_management_actions_supported`, in stable-then-alias order.
///
/// This is the single source of truth: it drives the discovery metadata
/// (`oidc::provider_metadata_value`), page validation, and dispatch
/// ([`canonical_action`]). matrix.org advertises both naming generations and
/// different client versions emit different ones, so we advertise the superset.
pub const SUPPORTED_ACTIONS: &[&str] = &[
    "org.matrix.profile",
    "org.matrix.devices_list",
    "org.matrix.device_view",
    "org.matrix.device_delete",
    ACTION_CROSS_SIGNING_RESET,
    // session_* aliases (older naming — accepted for compatibility):
    "org.matrix.sessions_list",
    "org.matrix.session_view",
    "org.matrix.session_end",
];

/// Map an action string (stable `device_*` or legacy `session_*`) to its
/// canonical [`Action`]. Returns `None` for unknown/unsupported actions.
pub fn canonical_action(action: &str) -> Option<Action> {
    match action {
        "org.matrix.profile" => Some(Action::Profile),
        "org.matrix.devices_list" | "org.matrix.sessions_list" => Some(Action::DevicesList),
        "org.matrix.device_view" | "org.matrix.session_view" => Some(Action::DeviceView),
        "org.matrix.device_delete" | "org.matrix.session_end" => Some(Action::DeviceDelete),
        ACTION_CROSS_SIGNING_RESET => Some(Action::CrossSigningReset),
        _ => None,
    }
}

fn is_supported_action(action: &str) -> bool {
    action == ACTION_CROSS_SIGNING_RESET
}

/// Sanitize a user-supplied action string for safe HTML interpolation.
fn sanitize_action(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
        .take(64)
        .collect()
}

// -- Action execution ---------------------------------------------------------

async fn execute_action(
    action: &str,
    did: &str,
    synapse_client: Option<&SynapseClient>,
) -> Result<(), CustomError> {
    match action {
        ACTION_CROSS_SIGNING_RESET => {
            let synapse = synapse_client.ok_or_else(|| {
                CustomError::BadRequest(
                    "Cross-signing reset requires Synapse integration".to_string(),
                )
            })?;
            let localpart = did_to_localpart(did);
            synapse
                .allow_cross_signing_reset(&localpart)
                .await
                .map_err(|e| {
                    warn!(error = %e, "allow_cross_signing_reset failed during account action");
                    CustomError::BadRequest("Failed to reset cross-signing keys".to_string())
                })?;
            info!(did = %did, "cross-signing reset allowed via account management page");
            Ok(())
        }
        _ => Err(CustomError::BadRequest(format!(
            "Unsupported action: {}",
            action
        ))),
    }
}

// -- Wallet re-authentication -------------------------------------------------

pub async fn account_wallet(
    config: &Config,
    req: AccountWalletRequest,
    synapse_client: Option<&SynapseClient>,
) -> Result<AccountActionResponse, CustomError> {
    if !is_supported_action(&req.action) {
        return Err(CustomError::BadRequest(format!(
            "Unsupported action: {}",
            req.action
        )));
    }

    let sig_hex = req.signature.strip_prefix("0x").unwrap_or(&req.signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    let did_method = aqua_auth::find_did_method(&req.did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", req.did)))?;

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
        .verify(&req.did, &req.message, &sig_bytes)
        .map_err(|e| CustomError::BadRequest(format!("Verification error: {}", e)))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    execute_action(&req.action, &req.did, synapse_client).await?;

    Ok(AccountActionResponse {
        status: "completed".to_string(),
        action: req.action,
    })
}

// -- Passkey re-authentication ------------------------------------------------

pub async fn account_passkey_finish(
    db_client: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    req: AccountPasskeyFinishRequest,
    synapse_client: Option<&SynapseClient>,
) -> Result<AccountActionResponse, CustomError> {
    if !is_supported_action(&req.action) {
        return Err(CustomError::BadRequest(format!(
            "Unsupported action: {}",
            req.action
        )));
    }

    let auth_response: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(req.credential)
            .map_err(|e| CustomError::BadRequest(format!("Invalid credential: {}", e)))?;

    let resp = wa::verify_credential(db_client, session_id, rp_id, rp_origin, &auth_response)
        .await
        .map_err(|e| CustomError::BadRequest(e.to_string()))?;

    execute_action(&req.action, &resp.did, synapse_client).await?;

    Ok(AccountActionResponse {
        status: "completed".to_string(),
        action: req.action,
    })
}

// -- Account management page --------------------------------------------------

pub fn account_page(query: AccountPageQuery, base_url: &str) -> Html<String> {
    let action = query
        .action
        .as_deref()
        .map(sanitize_action)
        .unwrap_or_default();
    let base = base_url.trim_end_matches('/');

    let (title, subtitle) = if action == ACTION_CROSS_SIGNING_RESET {
        (
            "Reset encryption keys",
            "Authenticate to confirm resetting your cross-signing keys. \
             This allows your client to set up new encryption keys.",
        )
    } else if action.is_empty() {
        ("Account", "Manage your account settings.")
    } else {
        ("Account action", "Authenticate to continue.")
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · inblock.io</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link href="https://api.fontshare.com/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body data-action="{action}" data-base="{base}">
<div class="login-page">
  <div class="ambient-glow"></div>
  <div class="login-card">
    <div class="card-inner">
      <div class="logo-area">
        <img src="/img/inblockio-logo.png" alt="inblock.io" class="logo logo-single">
      </div>

      <div id="auth-section" class="auth-section">
        <div class="action-badge">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="action-icon">
            <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 0 0-5.25 5.25v3a3 3 0 0 0-3 3v6.75a3 3 0 0 0 3 3h10.5a3 3 0 0 0 3-3v-6.75a3 3 0 0 0-3-3v-3c0-2.9-2.35-5.25-5.25-5.25Zm3.75 8.25v-3a3.75 3.75 0 1 0-7.5 0v3h7.5Z" clip-rule="evenodd"/>
          </svg>
        </div>
        <h1 class="title">{title}</h1>
        <p class="subtitle">{subtitle}</p>

        <button class="btn btn-primary" id="btn-wallet" onclick="authWallet()">
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

        <button class="btn btn-secondary" id="btn-passkey" onclick="authPasskey()">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="btn-icon">
            <path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd"/>
          </svg>
          <span>Sign with passkey</span>
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
        css = ACCOUNT_PAGE_CSS,
        js = ACCOUNT_PAGE_JS,
        title = title,
        subtitle = subtitle,
        action = action,
        base = base,
    );
    Html(html)
}

const ACCOUNT_PAGE_CSS: &str = r##"
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
.action-badge {
  margin-bottom: 16px;
  display: flex;
  justify-content: center;
}
.action-icon {
  width: 44px;
  height: 44px;
  color: var(--accent);
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
.btn-icon { width: 18px; height: 18px; flex-shrink: 0; }
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

const ACCOUNT_PAGE_JS: &str = r#"
const BASE = document.body.dataset.base;
const ACTION = document.body.dataset.action;
const $ = (id) => document.getElementById(id);

const CHECK_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon"><path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd"/></svg>';

async function authWallet() {
  hideStatus();
  setBusy('btn-wallet', true, 'Requesting signature...');
  try {
    if (!window.ethereum) { showStatus('No wallet detected. Install MetaMask or another EIP-1193 wallet.'); return; }
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];
    const did = 'did:pkh:eip155:1:' + address;
    const domain = new URL(BASE).hostname;
    const nonce = Math.random().toString(36).substring(2, 18);
    const issuedAt = new Date().toISOString();
    const message = domain + ' wants you to sign in with your Ethereum account:\n' +
      address + '\n\nConfirm account action.\n\nURI: ' + BASE + '\nVersion: 1\nChain ID: 1\n' +
      'Nonce: ' + nonce + '\nIssued At: ' + issuedAt;
    const signature = await window.ethereum.request({ method: 'personal_sign', params: [message, address] });
    const r = await fetch(BASE + '/account/wallet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: ACTION, did, message, signature })
    });
    if (r.ok) {
      showTerminal('Encryption keys reset', 'Your client can now set up new encryption keys. You can close this page.');
    } else {
      const t = await r.text();
      showStatus(t || 'Action failed.');
    }
  } catch (e) {
    showStatus('Wallet error: ' + (e.message || e));
  } finally {
    setBusy('btn-wallet', false);
  }
}

async function authPasskey() {
  hideStatus();
  setBusy('btn-passkey', true, 'Authenticating...');
  try {
    const startR = await fetch(BASE + '/account/passkey/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: ACTION })
    });
    if (!startR.ok) { showStatus('Failed to start passkey authentication.'); return; }
    const startData = await startR.json();
    const sessionId = startData.session_id;
    const options = startData;
    options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      if (options.publicKey.allowCredentials.length === 0) {
        showStatus('No passkeys registered on this server. Register a passkey first.');
        return;
      }
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((c) => ({ ...c, id: base64ToBuffer(c.id) }));
    }
    const credential = await navigator.credentials.get({ publicKey: options.publicKey });
    const finishR = await fetch(BASE + '/account/passkey/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: ACTION,
        session_id: sessionId,
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
      showTerminal('Encryption keys reset', 'Your client can now set up new encryption keys. You can close this page.');
    } else {
      const t = await finishR.text();
      showStatus(t || 'Passkey authentication failed.');
    }
  } catch (e) {
    showStatus('Passkey error: ' + (e.message || e));
  } finally {
    setBusy('btn-passkey', false);
  }
}

function showTerminal(title, subtitle) {
  $('auth-section').classList.add('hidden');
  hideStatus();
  const section = $('terminal-section');
  $('terminal-badge').innerHTML = CHECK_SVG;
  $('terminal-title').textContent = title;
  $('terminal-subtitle').textContent = subtitle || 'You can close this page.';
  section.classList.remove('hidden');
  // Try to close the window after a short delay (works when opened by window.open).
  setTimeout(() => { try { window.close(); } catch (_) {} }, 3000);
}

function showStatus(msg) {
  const el = $('status');
  $('status-text').textContent = msg;
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
mod tests {
    use super::*;

    #[test]
    fn account_page_renders_cross_signing_reset() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Reset encryption keys"));
        assert!(html.contains("cross-signing keys"));
        assert!(html.contains(r#"data-action="org.matrix.cross_signing_reset""#));
        assert!(html.contains(r#"data-base="https://siwx.example.com""#));
    }

    #[test]
    fn account_page_renders_without_action() {
        let html = account_page(
            AccountPageQuery {
                action: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Account"));
        assert!(html.contains("Manage your account"));
        assert!(html.contains(r#"data-action="""#));
    }

    #[test]
    fn account_page_sanitizes_action() {
        let html = account_page(
            AccountPageQuery {
                action: Some("<script>alert(1)</script>".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("data-action=\"scriptalert1script\""));
    }

    #[test]
    fn account_page_uses_brand_styling() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
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
    }

    #[test]
    fn account_page_has_wallet_and_passkey_buttons() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Sign with wallet"));
        assert!(html.contains("Sign with passkey"));
        assert!(html.contains("/account/wallet"));
        assert!(html.contains("/account/passkey/start"));
        assert!(html.contains("/account/passkey/finish"));
    }

    #[test]
    fn sanitize_action_strips_unsafe_chars() {
        assert_eq!(sanitize_action(""), "");
        assert_eq!(
            sanitize_action("org.matrix.cross_signing_reset"),
            "org.matrix.cross_signing_reset"
        );
        assert_eq!(
            sanitize_action("<script>alert(1)</script>"),
            "scriptalert1script"
        );
        assert_eq!(sanitize_action("'; DROP TABLE--"), "DROPTABLE");
        assert_eq!(sanitize_action(&"A".repeat(100)).len(), 64);
    }

    #[test]
    fn is_supported_action_works() {
        assert!(is_supported_action("org.matrix.cross_signing_reset"));
        assert!(!is_supported_action("org.matrix.unknown"));
        assert!(!is_supported_action(""));
    }

    #[test]
    fn canonical_action_maps_stable_names() {
        assert_eq!(
            canonical_action("org.matrix.profile"),
            Some(Action::Profile)
        );
        assert_eq!(
            canonical_action("org.matrix.devices_list"),
            Some(Action::DevicesList)
        );
        assert_eq!(
            canonical_action("org.matrix.device_view"),
            Some(Action::DeviceView)
        );
        assert_eq!(
            canonical_action("org.matrix.device_delete"),
            Some(Action::DeviceDelete)
        );
        assert_eq!(
            canonical_action("org.matrix.cross_signing_reset"),
            Some(Action::CrossSigningReset)
        );
    }

    #[test]
    fn canonical_action_collapses_session_aliases() {
        // session_* aliases must behave identically to their device_* form.
        assert_eq!(
            canonical_action("org.matrix.sessions_list"),
            canonical_action("org.matrix.devices_list")
        );
        assert_eq!(
            canonical_action("org.matrix.session_view"),
            canonical_action("org.matrix.device_view")
        );
        assert_eq!(
            canonical_action("org.matrix.session_end"),
            canonical_action("org.matrix.device_delete")
        );
    }

    #[test]
    fn canonical_action_rejects_unknown() {
        assert_eq!(canonical_action("org.matrix.unknown"), None);
        assert_eq!(canonical_action(""), None);
        assert_eq!(canonical_action("device_view"), None); // missing namespace
    }

    #[test]
    fn requires_device_id_only_for_single_device_actions() {
        assert!(Action::DeviceView.requires_device_id());
        assert!(Action::DeviceDelete.requires_device_id());
        assert!(!Action::DevicesList.requires_device_id());
        assert!(!Action::Profile.requires_device_id());
        assert!(!Action::CrossSigningReset.requires_device_id());
    }

    #[test]
    fn supported_actions_cover_acceptance_criteria() {
        // AC1: the advertised set must contain at least these four real actions
        // plus their session_* aliases, plus cross_signing_reset.
        for required in [
            "org.matrix.profile",
            "org.matrix.devices_list",
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.cross_signing_reset",
            "org.matrix.sessions_list",
            "org.matrix.session_view",
            "org.matrix.session_end",
        ] {
            assert!(
                SUPPORTED_ACTIONS.contains(&required),
                "SUPPORTED_ACTIONS missing {required}"
            );
        }
        // Every advertised action must be dispatchable (no advertised-but-unhandled drift).
        for action in SUPPORTED_ACTIONS {
            assert!(
                canonical_action(action).is_some(),
                "advertised action {action} has no canonical mapping"
            );
        }
    }
}
