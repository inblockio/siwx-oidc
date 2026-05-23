use axum::response::Html;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::config::Config;
use crate::introspect::generate_opaque_token;
use crate::oidc::CustomError;
use siwx_oidc::db::*;

/// Consonant alphabet for user codes (base-20, no vowels to avoid profanity).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Generate an 8-character user code from consonants, formatted as XXXX-XXXX.
pub fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<u8> = (0..8)
        .map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())])
        .collect();
    let left = std::str::from_utf8(&chars[..4]).unwrap();
    let right = std::str::from_utf8(&chars[4..]).unwrap();
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

/// Serve the device approval HTML page.
pub fn device_page(query: DevicePageQuery, base_url: &str) -> Html<String> {
    let user_code_value = query.user_code.as_deref().unwrap_or("");
    let base = base_url.trim_end_matches('/');
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve Device Login</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 420px; margin: 60px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }}
  h1 {{ font-size: 1.4em; text-align: center; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin: 20px 0; }}
  .code-display {{ font-size: 2em; font-weight: bold; text-align: center; letter-spacing: 0.15em; color: #58a6ff; margin: 16px 0; }}
  input[type=text] {{ width: 100%; padding: 10px; font-size: 1.2em; text-align: center; letter-spacing: 0.1em; background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; box-sizing: border-box; }}
  .btn {{ display: block; width: 100%; padding: 12px; font-size: 1em; border: none; border-radius: 6px; cursor: pointer; margin: 8px 0; font-weight: 600; }}
  .btn-approve {{ background: #238636; color: #fff; }}
  .btn-approve:hover {{ background: #2ea043; }}
  .btn-deny {{ background: #21262d; color: #f85149; border: 1px solid #30363d; }}
  .btn-deny:hover {{ background: #30363d; }}
  .btn-wallet {{ background: #3b82f6; color: #fff; }}
  .btn-wallet:hover {{ background: #2563eb; }}
  .btn-passkey {{ background: #8b5cf6; color: #fff; }}
  .btn-passkey:hover {{ background: #7c3aed; }}
  .status {{ text-align: center; padding: 20px; font-size: 1.1em; }}
  .error {{ color: #f85149; }}
  .success {{ color: #3fb950; }}
  #auth-section {{ display: none; }}
  p {{ line-height: 1.5; color: #8b949e; text-align: center; }}
</style>
</head>
<body>
<h1>Approve Device Login</h1>
<div class="card">
  <p>A new device wants to sign in to your account. Verify the code below matches what's shown on the device, then approve with your wallet or passkey.</p>
  <div id="code-section">
    <input type="text" id="user_code" placeholder="XXXX-XXXX" value="{user_code_value}" maxlength="9"
           style="{}" >
    <button class="btn btn-approve" onclick="lookupCode()" style="margin-top: 12px;">Verify Code</button>
  </div>
  <div id="auth-section">
    <div class="code-display" id="display-code"></div>
    <p>Authenticate to approve this device:</p>
    <button class="btn btn-wallet" onclick="approveWallet()">Sign with Wallet</button>
    <button class="btn btn-passkey" onclick="approvePasskey()">Sign with Passkey</button>
    <button class="btn btn-deny" onclick="denyDevice()">Deny</button>
  </div>
  <div id="status" class="status" style="display:none;"></div>
</div>
<script>
let currentUserCode = '{user_code_value}';
const BASE = '{base}';

if (currentUserCode) {{
  lookupCode();
}}

async function lookupCode() {{
  const code = document.getElementById('user_code').value.trim().toUpperCase();
  if (!code || code.length < 8) {{ showStatus('Enter a valid code (XXXX-XXXX)', true); return; }}
  currentUserCode = code;
  try {{
    const r = await fetch(BASE + '/device/verify?user_code=' + encodeURIComponent(code));
    if (r.ok) {{
      document.getElementById('code-section').style.display = 'none';
      document.getElementById('auth-section').style.display = 'block';
      document.getElementById('display-code').textContent = code;
      document.getElementById('status').style.display = 'none';
    }} else {{
      const t = await r.text();
      showStatus(t || 'Code not found or expired', true);
    }}
  }} catch(e) {{ showStatus('Network error', true); }}
}}

async function approveWallet() {{
  showStatus('Requesting wallet signature...', false);
  try {{
    if (!window.ethereum) {{ showStatus('No wallet detected. Install MetaMask.', true); return; }}
    const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
    const address = accounts[0];
    const did = 'did:pkh:eip155:1:' + address;
    const domain = new URL(BASE).hostname;
    const nonce = Math.random().toString(36).substring(2, 18);
    const issuedAt = new Date().toISOString();
    const message = domain + ' wants you to sign in with your Ethereum account:\\n' +
      address + '\\n\\nApprove device login.\\n\\nURI: ' + BASE + '\\nVersion: 1\\nChain ID: 1\\n' +
      'Nonce: ' + nonce + '\\nIssued At: ' + issuedAt;
    const signature = await window.ethereum.request({{
      method: 'personal_sign', params: [message, address]
    }});
    const r = await fetch(BASE + '/device', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ user_code: currentUserCode, action: 'approve', did, message, signature }})
    }});
    if (r.ok) {{ showStatus('Device approved! You can close this page.', false, true); }}
    else {{ const t = await r.text(); showStatus(t || 'Approval failed', true); }}
  }} catch(e) {{ showStatus('Wallet error: ' + e.message, true); }}
}}

async function approvePasskey() {{
  showStatus('Starting passkey authentication...', false);
  try {{
    const startR = await fetch(BASE + '/device/passkey/start', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ user_code: currentUserCode }})
    }});
    if (!startR.ok) {{ showStatus('Failed to start passkey auth', true); return; }}
    const options = await startR.json();
    options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {{
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({{
        ...c, id: base64ToBuffer(c.id)
      }}));
    }}
    const credential = await navigator.credentials.get(options);
    const finishR = await fetch(BASE + '/device/passkey/finish', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        user_code: currentUserCode,
        id: credential.id,
        rawId: bufferToBase64(credential.rawId),
        type: credential.type,
        response: {{
          authenticatorData: bufferToBase64(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
          signature: bufferToBase64(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64(credential.response.userHandle) : null
        }}
      }})
    }});
    if (finishR.ok) {{ showStatus('Device approved! You can close this page.', false, true); }}
    else {{ const t = await finishR.text(); showStatus(t || 'Passkey auth failed', true); }}
  }} catch(e) {{ showStatus('Passkey error: ' + e.message, true); }}
}}

async function denyDevice() {{
  try {{
    const r = await fetch(BASE + '/device', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ user_code: currentUserCode, action: 'deny' }})
    }});
    if (r.ok) {{ showStatus('Device denied.', false, true); }}
    else {{ showStatus('Failed to deny', true); }}
  }} catch(e) {{ showStatus('Network error', true); }}
}}

function showStatus(msg, isError, hideAuth) {{
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = 'status ' + (isError ? 'error' : 'success');
  el.style.display = 'block';
  if (hideAuth) {{ document.getElementById('auth-section').style.display = 'none'; }}
}}

function base64ToBuffer(b64) {{
  const s = b64.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(s);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}}
function bufferToBase64(buf) {{
  const bytes = new Uint8Array(buf);
  let s = '';
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}}
</script>
</body>
</html>"#,
        if user_code_value.is_empty() {
            ""
        } else {
            "display:none;"
        }
    ))
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
) -> Result<Html<String>, CustomError> {
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
        return Ok(Html("<html><body style='background:#0d1117;color:#f85149;text-align:center;padding:60px;font-family:sans-serif'><h2>Device denied</h2></body></html>".to_string()));
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

    entry.status = DeviceCodeStatus::Approved;
    entry.did = Some(did.clone());
    let _ = db_client
        .update_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
        .await;
    info!(user_code = %req.user_code, did = %did, "device approved");

    Ok(Html("<html><body style='background:#0d1117;color:#3fb950;text-align:center;padding:60px;font-family:sans-serif'><h2>Device approved!</h2><p>You can close this page.</p></body></html>".to_string()))
}

/// Process a device approval via passkey (WebAuthn).
/// Called after the passkey ceremony verifies the DID server-side.
pub async fn device_approve_passkey(
    db_client: &(dyn DBClient + Sync),
    user_code: &str,
    verified_did: &str,
) -> Result<Html<String>, CustomError> {
    let (device_code, mut entry) = db_client
        .get_device_code_by_user_code(user_code)
        .await?
        .ok_or_else(|| CustomError::BadRequest("User code not found or expired".to_string()))?;

    if entry.status != DeviceCodeStatus::Pending {
        return Err(CustomError::BadRequest("Code already used".to_string()));
    }

    entry.status = DeviceCodeStatus::Approved;
    entry.did = Some(verified_did.to_string());
    let _ = db_client
        .update_device_code(&device_code, &entry, DEVICE_CODE_LIFETIME)
        .await;
    info!(user_code = %user_code, did = %verified_did, "device approved via passkey");

    Ok(Html("<html><body style='background:#0d1117;color:#3fb950;text-align:center;padding:60px;font-family:sans-serif'><h2>Device approved!</h2><p>You can close this page.</p></body></html>".to_string()))
}
