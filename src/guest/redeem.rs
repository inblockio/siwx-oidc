//! `POST /guest/peek` and `POST /guest/redeem` (work package S3b): the guest's side of
//! an invitation, authorised by the invite secret in the body and by nothing else.
//! They sit in the cookie group of the guest router, so [`super::layers`] has already
//! applied the origin check, JSON only and the 4 KiB cap.
//!
//! - **peek** reads, never writes. After the secret verifies it returns the invite's
//!   state and, when it is active, what the join page needs plus a stateless nonce.
//! - **redeem** binds the guest's browser-made `did:key` to the invite with a proof of
//!   possession over that nonce, then mints the record in one Redis script. It makes
//!   no Synapse write: the account is created later by the `sign_in` fence (S4).
//!
//! Order on redeem: secret, invite state, input validation, proof, DID in use, script.
//! The secret failure is one fixed answer for an unknown id, a wrong secret and a body
//! that does not parse, so none of the three is an oracle. The proof comes before the
//! DID-in-use check so that only the holder of a key learns whether its DID is taken.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;

use super::invite::GuestState;
use super::layers::error;
use siwx_oidc::db::guest_records::{
    InviteGate, InviteState, NewGuest, RedeemLimits, RedeemOutcome, RedeemRefusal,
};
use siwx_oidc::guest_admission::{
    admit_did, check_consent, did_sha256_hex, mint_nonce, validate_email, validate_names,
    verify_redeem_proof, Consent, EmailPolicy, NameRules, GUEST_CONSENT_VERSION,
};
use siwx_oidc::guest_invite::secret_hash;
use siwx_oidc::mxid::legacy_localpart;

/// What a secret hash is compared with when no invite exists, so the work is the same.
const DUMMY_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The curves a join page may generate a key on.
const CURVES: [&str; 2] = ["Ed25519", "P-256"];
/// The DID methods accepted.
const DID_METHODS: [&str; 1] = ["key"];

/// The one answer to a link that is not valid, whatever the reason.
fn invalid_link() -> Response {
    error(StatusCode::NOT_FOUND, "invalid_link")
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

/// The part of a body both routes read first. Anything that does not parse reads as
/// empty, which then fails like an unknown id.
#[derive(Deserialize, Default)]
struct Credentials {
    #[serde(default)]
    invite_id: String,
    #[serde(default)]
    secret: String,
}

/// Look the invite up once and compare the secret in constant time. `Ok(gate)` only
/// when the invite exists and the secret matches; every other input is [`invalid_link`].
///
/// A refusal is counted (`route` is `"peek"` or `"redeem"`, the reason `invalid_link`) for
/// the refusal-burst alert; the event carries neither id nor secret, and the answer is
/// the same bytes with or without the count.
async fn verify_secret(
    state: &GuestState,
    body: &[u8],
    route: &'static str,
) -> Result<InviteGate, Response> {
    let creds: Credentials = serde_json::from_slice(body).unwrap_or_default();
    let gate = match state.redis.read_invite_gate(&creds.invite_id).await {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "guest link: invite store unavailable");
            return Err(unavailable());
        }
    };
    let given = secret_hash(&creds.secret);
    let expected = gate.as_ref().map_or(DUMMY_HASH, |g| g.secret_hash.as_str());
    let matches: bool = given.as_bytes().ct_eq(expected.as_bytes()).into();
    match gate {
        Some(g) if matches => Ok(g),
        _ => {
            super::audit::refused(&state.redis, route, "invalid_link").await;
            Err(invalid_link())
        }
    }
}

fn email_policy(state: &GuestState) -> EmailPolicy {
    match state.config.guest_email_policy.as_str() {
        "optional" => EmailPolicy::Optional,
        "required" => EmailPolicy::Required,
        _ => EmailPolicy::Off,
    }
}

/// `POST /guest/peek` `{invite_id, secret}`. Changes no state.
pub async fn peek(State(state): State<GuestState>, body: Bytes) -> Response {
    let gate = match verify_secret(&state, &body, "peek").await {
        Ok(g) => g,
        Err(r) => return r,
    };
    match state.redis.guest_control().await {
        Ok(c) if !c.disabled => {}
        Ok(_) => {
            super::audit::refused(&state.redis, "peek", "disabled").await;
            return error(StatusCode::SERVICE_UNAVAILABLE, "disabled");
        }
        Err(e) => {
            warn!(error = %e, "guest peek: control read failed");
            return unavailable();
        }
    }
    if gate.state != InviteState::Active {
        return Json(json!({ "state": gate.state.as_str() })).into_response();
    }
    let creds: Credentials = serde_json::from_slice(&body).unwrap_or_default();
    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    Json(json!({
        "state": "active",
        "email_policy": email_policy(&state).as_str(),
        "session_secs": gate.session_secs,
        "consent_version": GUEST_CONSENT_VERSION,
        "recording_expected": gate.recording_expected,
        "nonce": mint_nonce(&state.nonce_key, &creds.invite_id, now),
        "did_methods": DID_METHODS,
        "curves": CURVES,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct RedeemBody {
    first_name: String,
    second_name: String,
    #[serde(default)]
    email: Option<String>,
    consent: Consent,
    did: String,
    proof: Proof,
}

#[derive(Deserialize)]
struct Proof {
    message: String,
    signature: String,
}

/// The signature is base64url without padding (what the join page sends). Standard
/// base64, padded or not, is accepted too.
fn decode_signature(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| STANDARD.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .ok()
}

fn unprocessable(code: &'static str) -> Response {
    error(StatusCode::UNPROCESSABLE_ENTITY, code)
}

/// The host's display name, for the "looks like the host" name rule. Best effort: any
/// failure skips that one rule.
async fn host_display_name(state: &GuestState, host: &str) -> Option<String> {
    let synapse = state.synapse.as_ref()?;
    let server = state.config.matrix_server_name.as_deref()?;
    match synapse.read_profile(host, server).await {
        Ok(profile) => profile.displayname,
        Err(e) => {
            warn!(error = %e, "guest redeem: host profile read failed, skipping that name rule");
            None
        }
    }
}

/// The session cookie. `__Host-` and `Secure` on https; on plain-http development
/// (`base_url` is http, which start-up allows only for localhost) the unprefixed name
/// without `Secure`, since a browser would not store the other.
pub(super) fn session_cookie(base_url: &url::Url, handle: &str, max_age: i64) -> String {
    if base_url.scheme() == "https" {
        format!(
            "__Host-guest_session={handle}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"
        )
    } else {
        format!("guest_session={handle}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}")
    }
}

/// `POST /guest/redeem`.
pub async fn redeem(State(state): State<GuestState>, body: Bytes) -> Response {
    // 1. The secret.
    let gate = match verify_secret(&state, &body, "redeem").await {
        Ok(g) => g,
        Err(r) => return r,
    };
    // 2. The invite state, before any input is judged.
    match gate.state {
        InviteState::Active => {}
        other => return error(StatusCode::GONE, other.as_str()),
    }
    // 3. The rest of the body, then the inputs.
    let creds: Credentials = serde_json::from_slice(&body).unwrap_or_default();
    let Ok(req) = serde_json::from_slice::<RedeemBody>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Some(client_url) = state.config.guest_client_url.as_ref() else {
        return unavailable();
    };
    let host_name = host_display_name(&state, &gate.host).await;
    let names = match validate_names(
        &req.first_name,
        &req.second_name,
        &NameRules {
            name_suffix: &state.config.guest_name_suffix,
            host_display_name: host_name.as_deref(),
        },
    ) {
        Ok(n) => n,
        Err(e) => return unprocessable(e.reason()),
    };
    let email = match validate_email(email_policy(&state), req.email.as_deref()) {
        Ok(e) => e,
        Err(e) => return unprocessable(e.reason()),
    };
    if let Err(e) = check_consent(&req.consent, GUEST_CONSENT_VERSION) {
        return unprocessable(e.reason());
    }
    let admitted = match admit_did(&req.did) {
        Ok(a) => a,
        Err(e) => return unprocessable(e.reason()),
    };
    // 4. The proof of possession.
    let Some(signature) = decode_signature(&req.proof.signature) else {
        return unprocessable("proof_invalid");
    };
    if let Err(e) = verify_redeem_proof(
        &state.config.base_url,
        &creds.invite_id,
        &admitted.did,
        &req.proof.message,
        &signature,
        &state.nonce_key,
        Utc::now(),
    ) {
        return unprocessable(e.reason());
    }
    // 5. A DID this server already knows is refused before the script (the script
    //    repeats the record and erasure checks atomically).
    let did_hash = did_sha256_hex(&admitted.did);
    let legacy = legacy_localpart(&admitted.did);
    let mut localparts = vec![admitted.localpart.as_str()];
    if legacy != admitted.localpart {
        localparts.push(legacy.as_str());
    }
    match state
        .redis
        .guest_did_known(&admitted.did, &did_hash, &localparts)
        .await
    {
        Ok(false) => {}
        Ok(true) => return error(StatusCode::CONFLICT, "did_in_use"),
        Err(e) => {
            warn!(error = %e, "guest redeem: account lookup failed");
            return unavailable();
        }
    }
    // 6. The script.
    let mut handle_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut handle_bytes);
    let handle = URL_SAFE_NO_PAD.encode(handle_bytes);
    let handle_hash = hex::encode(Sha256::digest(handle.as_bytes()));
    let c = &state.config;
    let outcome = state
        .redis
        .redeem_guest(
            &gate.host,
            &NewGuest {
                invite_id: &creds.invite_id,
                secret_hash: &gate.secret_hash,
                localpart: &admitted.localpart,
                legacy_localpart: &legacy,
                did: &admitted.did,
                did_sha256_hex: &did_hash,
                first_name: &names.first,
                second_name: &names.second,
                email: email.as_deref(),
                consent_version: &req.consent.version,
                consent_variant: &req.consent.variant,
                handle_sha256_hex: &handle_hash,
            },
            &RedeemLimits {
                global_active: c.guest_global_max_active,
                daily_mint: c.guest_daily_mint_max,
                host_live_guests: c.guest_host_max_live_guests,
            },
        )
        .await;
    match outcome {
        Ok(RedeemOutcome::Minted { deadline, now }) => {
            super::audit::minted();
            let seconds_left = (deadline - now).max(0);
            let mut response = Json(json!({
                "guest_client_url": client_url.as_str(),
                "deadline": deadline,
                "seconds_left": seconds_left,
            }))
            .into_response();
            let cookie = session_cookie(&c.base_url, &handle, seconds_left);
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(header::SET_COOKIE, v);
            }
            response
        }
        Ok(RedeemOutcome::Refused(why)) => {
            super::audit::refused(&state.redis, "redeem", refusal_class(why)).await;
            refusal(why)
        }
        Err(e) => {
            warn!(error = %e, "guest redeem: store write failed");
            unavailable()
        }
    }
}

/// The reason class of a refusal, for the audit event.
fn refusal_class(why: RedeemRefusal) -> &'static str {
    match why {
        RedeemRefusal::Disabled => "disabled",
        RedeemRefusal::InvalidLink => "invalid_link",
        RedeemRefusal::Expired => "expired",
        RedeemRefusal::Exhausted => "exhausted",
        RedeemRefusal::Revoked => "revoked",
        RedeemRefusal::DidInUse => "did_in_use",
        RedeemRefusal::Quota(class) => class,
    }
}

fn refusal(why: RedeemRefusal) -> Response {
    match why {
        RedeemRefusal::Disabled => error(StatusCode::SERVICE_UNAVAILABLE, "disabled"),
        RedeemRefusal::InvalidLink => invalid_link(),
        RedeemRefusal::Expired => error(StatusCode::GONE, "expired"),
        RedeemRefusal::Exhausted => error(StatusCode::GONE, "exhausted"),
        RedeemRefusal::Revoked => error(StatusCode::GONE, "revoked"),
        RedeemRefusal::DidInUse => error(StatusCode::CONFLICT, "did_in_use"),
        RedeemRefusal::Quota(class) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "quota_exceeded", "quota": class })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    //! Driven over a real socket against a real Redis, through the whole guest stack
    //! (origin check, JSON only, headers), with keys made by the dalek and p256 crates.
    use super::*;
    use crate::config::Config;
    use crate::synapse_client::SynapseClient;
    use chrono::Duration;
    use ed25519_dalek::Signer as _;
    use reqwest::header::HeaderMap;
    use serde_json::Value;
    use siwx_oidc::db::guest_invites::{
        by_host_key, guest_account_key, invite_key, NewBatch, NewInvite, QuotaLimits, CONTROL_KEY,
    };
    use siwx_oidc::db::guest_records::{by_invite_key, handle_key, DUE_KEY};
    use siwx_oidc::db::{DBClient, RedisClient, TokenKind, TokenMetadata};
    use siwx_oidc::guest_admission::build_redeem_message;
    use siwx_oidc::guest_invite::{new_invite_id, Kind};
    use siwx_oidc::mxid::localpart_for;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    const ISSUER: &str = "https://id.example.org";
    const SESSION: u64 = 7200;

    fn uniq() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    struct Resp {
        status: u16,
        headers: HeaderMap,
        bytes: Vec<u8>,
    }

    impl Resp {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
        }
        fn error(&self) -> String {
            self.json()["error"].as_str().unwrap_or("").to_string()
        }
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.bytes).into_owned()
        }
    }

    struct Guest {
        sk: ed25519_dalek::SigningKey,
        did: String,
    }

    impl Guest {
        fn new() -> Self {
            let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let mut b = vec![0xed, 0x01];
            b.extend_from_slice(sk.verifying_key().as_bytes());
            let did = format!("did:key:z{}", bs58::encode(b).into_string());
            Guest { sk, did }
        }
    }

    #[derive(Clone)]
    struct Invite {
        id: String,
        secret: String,
        host: String,
    }

    #[derive(Clone)]
    struct Env {
        base: String,
        redis: RedisClient,
        client: reqwest::Client,
        config: Config,
    }

    /// `db` picks the Redis database (a test that counts keys or sets the kill switch
    /// owns one); `edit` adjusts the configuration. Quotas are large unless edited.
    async fn env_in(
        db: Option<u8>,
        synapse: Option<&str>,
        edit: impl Fn(&mut Config),
    ) -> Option<Env> {
        let redis = match db {
            None => siwx_oidc::test_support::redis().await?,
            Some(n) => siwx_oidc::test_support::redis_db(n).await?,
        };
        let mut config = Config {
            guest_enabled: true,
            base_url: url::Url::parse(ISSUER).unwrap(),
            matrix_server_name: Some("example.org".into()),
            guest_client_url: Some(url::Url::parse("https://meet.example.org/start").unwrap()),
            guest_global_max_active: 1_000_000,
            guest_daily_mint_max: 1_000_000,
            guest_host_max_live_guests: 1_000_000,
            ..Config::default()
        };
        edit(&mut config);
        let synapse = synapse.map(|u| Arc::new(SynapseClient::new(u, "secret")));
        let app = super::super::routes::router(&config, redis.clone(), synapse);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Some(Env {
            base: format!("http://{addr}"),
            redis,
            client: reqwest::Client::new(),
            config,
        })
    }

    async fn env(edit: impl Fn(&mut Config)) -> Option<Env> {
        env_in(None, None, edit).await
    }

    impl Env {
        async fn invite_of(&self, host: &str, kind: Kind, max: u64) -> Invite {
            let (id, secret) = (new_invite_id(), format!("gi_{}", uniq()));
            let list = [NewInvite {
                id: id.clone(),
                secret_hash: secret_hash(&secret),
                label: "t".into(),
            }];
            self.redis
                .create_guest_invites(
                    &NewBatch {
                        host,
                        host_did: "did:key:zHost",
                        room_id: "!room:example.org",
                        kind,
                        max_guests: max,
                        expires_in: 3600,
                        session_secs: SESSION,
                        recording_expected: true,
                        invites: &list,
                    },
                    &QuotaLimits {
                        max_invites: 1000,
                        max_open_invites: 1000,
                        per_hour: 1_000_000,
                        session_max_secs: SESSION,
                    },
                )
                .await
                .unwrap();
            Invite {
                id,
                secret,
                host: host.into(),
            }
        }

        async fn invite(&self, kind: Kind, max: u64) -> Invite {
            self.invite_of(&format!("host{}", uniq()), kind, max).await
        }

        async fn post_with(&self, path: &str, body: String, origin: Option<&str>) -> Resp {
            let mut req = self
                .client
                .post(format!("{}{path}", self.base))
                .header("content-type", "application/json")
                .body(body);
            if let Some(o) = origin {
                req = req.header("origin", o);
            }
            let r = req.send().await.unwrap();
            Resp {
                status: r.status().as_u16(),
                headers: r.headers().clone(),
                bytes: r.bytes().await.unwrap().to_vec(),
            }
        }

        async fn post(&self, path: &str, body: Value) -> Resp {
            let origin = self.config.base_url.origin().ascii_serialization();
            self.post_with(path, body.to_string(), Some(&origin)).await
        }

        async fn peek(&self, inv: &Invite) -> Resp {
            self.post(
                "/guest/peek",
                json!({"invite_id": inv.id, "secret": inv.secret}),
            )
            .await
        }

        async fn nonce(&self, inv: &Invite) -> String {
            self.peek(inv).await.json()["nonce"]
                .as_str()
                .unwrap()
                .to_string()
        }

        fn body(&self, inv: &Invite, g: &Guest, nonce: &str) -> Value {
            let now = Utc::now();
            let msg = build_redeem_message(
                &self.config.base_url,
                &g.did,
                &inv.id,
                nonce,
                now,
                now + Duration::minutes(5),
            )
            .unwrap();
            let sig = g.sk.sign(msg.as_bytes());
            json!({
                "invite_id": inv.id,
                "secret": inv.secret,
                "first_name": "Ada",
                "second_name": "Lovelace",
                "consent": {"version": "1", "variant": "a"},
                "did": g.did,
                "proof": {"message": msg, "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes())},
            })
        }

        async fn redeem(&self, inv: &Invite, g: &Guest) -> Resp {
            let nonce = self.nonce(inv).await;
            self.post("/guest/redeem", self.body(inv, g, &nonce)).await
        }

        async fn used(&self, inv: &Invite) -> String {
            self.redis
                .get_hash_field_for_test(&invite_key(&inv.id), "used")
                .await
                .unwrap()
        }

        async fn record(&self, g: &Guest) -> std::collections::HashMap<String, String> {
            self.redis
                .hgetall_for_test(&guest_account_key(&localpart_for(&g.did)))
                .await
        }
    }

    fn cookie_value(r: &Resp) -> String {
        let c = r.headers[header::SET_COOKIE].to_str().unwrap();
        c.split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_string()
    }

    /// ST-08: an unknown id, a wrong secret and a malformed body give the same bytes on
    /// both routes, and peek changes no state.
    #[tokio::test]
    async fn st08_the_generic_failures_are_byte_identical_and_peek_writes_nothing() {
        let Some(e) = env_in(Some(13), None, |_| {}).await else {
            return;
        };
        e.redis.flush_db_for_test().await;
        let inv = e.invite(Kind::Single, 1).await;
        let g = Guest::new();
        let nonce = e.nonce(&inv).await;
        let good = e.body(&inv, &g, &nonce);
        let bad_bodies = [
            json!({"invite_id": new_invite_id(), "secret": inv.secret}),
            json!({"invite_id": inv.id, "secret": "gi_wrong"}),
            json!({"invite_id": "x", "secret": inv.secret}),
            json!({"invite_id": "../../acct", "secret": ""}),
            json!({"invite_id": 7, "secret": [1]}),
            json!({}),
            Value::Null,
        ];
        for path in ["/guest/peek", "/guest/redeem"] {
            let mut seen = BTreeSet::new();
            for b in &bad_bodies {
                let mut b = b.clone();
                if path == "/guest/redeem" && b.is_object() {
                    for k in ["first_name", "second_name", "consent", "did", "proof"] {
                        b[k] = good[k].clone();
                    }
                }
                let r = e.post(path, b).await;
                seen.insert((r.status, r.bytes.clone()));
            }
            let r = e
                .post_with(path, "not json at all".into(), Some(ISSUER))
                .await;
            seen.insert((r.status, r.bytes));
            assert_eq!(seen.len(), 1, "{path}: {seen:?}");
            let (status, bytes) = seen.into_iter().next().unwrap();
            assert_eq!(status, 404);
            assert_eq!(bytes, br#"{"error":"invalid_link"}"#);
        }
        // Peek with the right secret: the join page's inputs, nothing of the host's.
        let before = e.redis.dbsize_for_test().await;
        let r = e.peek(&inv).await;
        assert_eq!(r.status, 200);
        let v = r.json();
        assert_eq!(v["state"], "active");
        assert_eq!(v["email_policy"], "off");
        assert_eq!(v["session_secs"], SESSION);
        assert_eq!(v["consent_version"], "1");
        assert_eq!(v["recording_expected"], true);
        assert_eq!(v["did_methods"], json!(["key"]));
        assert_eq!(v["curves"], json!(["Ed25519", "P-256"]));
        assert!(v["nonce"].as_str().unwrap().contains('.'));
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "consent_version",
                "curves",
                "did_methods",
                "email_policy",
                "nonce",
                "recording_expected",
                "session_secs",
                "state"
            ]
        );
        assert!(!r.text().contains(&inv.host) && !r.text().contains(&inv.secret));
        for _ in 0..3 {
            e.peek(&inv).await;
            e.post("/guest/peek", json!({"invite_id": inv.id, "secret": "no"}))
                .await;
        }
        assert_eq!(e.redis.dbsize_for_test().await, before, "peek wrote");
        assert_eq!(e.used(&inv).await, "0");
    }

    /// Peek answers an ended invite's state only to the holder of the secret.
    #[tokio::test]
    async fn peek_states_come_after_the_secret() {
        let Some(e) = env(|_| {}).await else { return };
        for (what, expect) in [
            ("revoked", "revoked"),
            ("expires", "expired"),
            ("used", "exhausted"),
        ] {
            let inv = e.invite(Kind::Single, 1).await;
            match what {
                "revoked" => assert!(e
                    .redis
                    .revoke_guest_invite(&inv.host, &inv.id)
                    .await
                    .unwrap()),
                "expires" => {
                    e.redis
                        .hset_raw_for_test(&invite_key(&inv.id), "expires_at", "1")
                        .await
                }
                _ => {
                    e.redis
                        .hset_raw_for_test(&invite_key(&inv.id), "used", "1")
                        .await
                }
            }
            let r = e.peek(&inv).await;
            assert_eq!((r.status, r.json()), (200, json!({"state": expect})));
            let wrong = e
                .post(
                    "/guest/peek",
                    json!({"invite_id": inv.id, "secret": "gi_no"}),
                )
                .await;
            assert_eq!((wrong.status, wrong.error()), (404, "invalid_link".into()));
        }
    }

    /// ST-02: N = 3 x max_guests concurrent redeems of one link mint exactly max_guests.
    #[tokio::test]
    async fn st02_concurrent_redeems_mint_exactly_max_guests() {
        let Some(e) = env(|_| {}).await else { return };
        let max = 4u64;
        let inv = e.invite(Kind::Open, max).await;
        let nonce = e.nonce(&inv).await;
        let mut tasks = Vec::new();
        for _ in 0..3 * max {
            let (e, inv, nonce) = (e.clone(), inv.clone(), nonce.clone());
            tasks.push(tokio::spawn(async move {
                let g = Guest::new();
                let body = e.body(&inv, &g, &nonce);
                let r = e.post("/guest/redeem", body).await;
                (r.status, r.error())
            }));
        }
        let (mut minted, mut exhausted) = (0, 0);
        for t in tasks {
            match t.await.unwrap() {
                (200, _) => minted += 1,
                (410, c) if c == "exhausted" => exhausted += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!((minted, exhausted), (max, 2 * max));
        assert_eq!(e.used(&inv).await, max.to_string());
        let members = e.redis.smembers_raw(&by_invite_key(&inv.id)).await.unwrap();
        assert_eq!(members.len() as u64, max);
        for lp in &members {
            assert!(e.redis.zscore_for_test(DUE_KEY, lp).await.is_some());
        }
    }

    /// The `SET NX` on the record: one DID redeemed concurrently mints once.
    #[tokio::test]
    async fn the_same_did_redeemed_concurrently_mints_once() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Open, 10).await;
        let nonce = e.nonce(&inv).await;
        let g = Arc::new(Guest::new());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (e, inv, nonce, g) = (e.clone(), inv.clone(), nonce.clone(), g.clone());
            tasks.push(tokio::spawn(async move {
                let r = e.post("/guest/redeem", e.body(&inv, &g, &nonce)).await;
                (r.status, r.error())
            }));
        }
        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap());
        }
        assert_eq!(
            results.iter().filter(|r| r.0 == 200).count(),
            1,
            "{results:?}"
        );
        assert!(results
            .iter()
            .filter(|r| r.0 != 200)
            .all(|r| r.0 == 409 && r.1 == "did_in_use"));
        assert_eq!(e.used(&inv).await, "1");
    }

    /// A second redeem of a single-use link is refused whatever DID it carries; the
    /// first guest's record is untouched.
    #[tokio::test]
    async fn a_single_use_link_burns_on_the_first_redeem() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Single, 1).await;
        let (first, other) = (Guest::new(), Guest::new());
        let nonce = e.nonce(&inv).await;
        let ok = e.post("/guest/redeem", e.body(&inv, &first, &nonce)).await;
        assert_eq!(ok.status, 200, "{}", ok.text());
        for g in [&other, &first] {
            let r = e.post("/guest/redeem", e.body(&inv, g, &nonce)).await;
            assert_eq!((r.status, r.error()), (410, "exhausted".into()));
        }
        assert!(e.record(&other).await.is_empty());
        assert_eq!(e.record(&first).await["state"], "minted");
        let p = e.peek(&inv).await;
        assert_eq!(p.json(), json!({"state": "exhausted"}));
    }

    /// A victim's public DID with a proof signed by another key is `proof_invalid`, and
    /// nothing is written; so is a replayed proof on another invite and a stale nonce.
    #[tokio::test]
    async fn a_victims_did_without_the_key_is_refused() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Open, 5).await;
        let (victim, attacker) = (Guest::new(), Guest::new());
        let nonce = e.nonce(&inv).await;
        // The message names the victim's DID but is signed by the attacker's key.
        let mut body = e.body(&inv, &victim, &nonce);
        let forged = e.body(&inv, &attacker, &nonce);
        let msg = body["proof"]["message"].as_str().unwrap().to_string();
        let sig = attacker.sk.sign(msg.as_bytes());
        body["proof"]["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let r = e.post("/guest/redeem", body).await;
        assert_eq!((r.status, r.error()), (422, "proof_invalid".into()));
        // The attacker's own message with the victim's DID swapped in.
        let mut body = forged.clone();
        body["did"] = json!(victim.did);
        let r = e.post("/guest/redeem", body).await;
        assert_eq!((r.status, r.error()), (422, "proof_invalid".into()));
        // A nonce minted for another invite.
        let inv2 = e.invite(Kind::Open, 5).await;
        let r = e
            .post(
                "/guest/redeem",
                e.body(&inv, &attacker, &e.nonce(&inv2).await),
            )
            .await;
        assert_eq!((r.status, r.error()), (422, "proof_invalid".into()));
        // A signature that is not base64.
        let mut body = e.body(&inv, &victim, &nonce);
        body["proof"]["signature"] = json!("!!not base64!!");
        let r = e.post("/guest/redeem", body).await;
        assert_eq!((r.status, r.error()), (422, "proof_invalid".into()));
        assert!(e.record(&victim).await.is_empty());
        assert!(e.record(&attacker).await.is_empty());
        assert_eq!(e.used(&inv).await, "0");
        // The honest holder still gets in; standard base64 is accepted too.
        let mut body = e.body(&inv, &victim, &nonce);
        let sig = URL_SAFE_NO_PAD
            .decode(body["proof"]["signature"].as_str().unwrap())
            .unwrap();
        body["proof"]["signature"] = json!(STANDARD.encode(sig));
        assert_eq!(e.post("/guest/redeem", body).await.status, 200);
    }

    /// ST-02 / ST-10-ish: the same DID on a second invite, an `erased:did` marker and a
    /// known account (under either localpart) are `did_in_use`, with nothing written.
    #[tokio::test]
    async fn a_did_in_use_is_refused_before_the_script() {
        let Some(e) = env(|_| {}).await else { return };
        let (a, b) = (
            e.invite(Kind::Single, 1).await,
            e.invite(Kind::Single, 1).await,
        );
        let g = Guest::new();
        assert_eq!(e.redeem(&a, &g).await.status, 200);
        let r = e.redeem(&b, &g).await;
        assert_eq!((r.status, r.error()), (409, "did_in_use".into()));
        assert_eq!(e.used(&b).await, "0");

        let erased = Guest::new();
        e.redis
            .set_raw(&format!("erased:did/{}", did_sha256_hex(&erased.did)), "t")
            .await
            .unwrap();
        let r = e.redeem(&b, &erased).await;
        assert_eq!((r.status, r.error()), (409, "did_in_use".into()));

        let known = Guest::new();
        let legacy = Guest::new();
        assert_ne!(legacy_localpart(&known.did), localpart_for(&known.did));
        e.redis
            .set_raw(
                &format!("idx:grants:user/{}", localpart_for(&known.did)),
                "x",
            )
            .await
            .unwrap();
        e.redis
            .set_raw(
                &format!("tombstone:user/{}", legacy_localpart(&legacy.did)),
                "x",
            )
            .await
            .unwrap();
        for g in [&known, &legacy] {
            let r = e.redeem(&b, g).await;
            assert_eq!((r.status, r.error()), (409, "did_in_use".into()));
            assert!(e.record(g).await.is_empty());
        }
        assert_eq!(e.used(&b).await, "0");
    }

    /// S5: the tombstone a guest teardown writes (`mark_guest_erased`) makes the DID's
    /// redeem `did_in_use`, and nothing is written.
    #[tokio::test]
    async fn st22_a_reaped_dids_redeem_is_did_in_use() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Open, 5).await;
        let reaped = Guest::new();
        e.redis
            .mark_guest_erased(&localpart_for(&reaped.did), &reaped.did)
            .await
            .unwrap();
        let r = e.redeem(&inv, &reaped).await;
        assert_eq!((r.status, r.error()), (409, "did_in_use".into()));
        assert_eq!(e.used(&inv).await, "0");
        assert!(e.record(&reaped).await.is_empty());
    }

    /// The order is secret, state, validation, proof; every input refusal writes nothing.
    #[tokio::test]
    async fn st13_st15_input_refusals_have_their_classes_and_write_nothing() {
        let Some(e) = env(|c| c.guest_email_policy = "required".into()).await else {
            return;
        };
        let inv = e.invite(Kind::Open, 50).await;
        let nonce = e.nonce(&inv).await;
        let g = Guest::new();
        let base = {
            let mut b = e.body(&inv, &g, &nonce);
            b["email"] = json!("ada@example.org");
            b
        };
        type Mutation = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "name_chars",
                Box::new(|b| b["first_name"] = json!("<b>Ada</b>")),
            ),
            (
                "name_chars",
                Box::new(|b| b["second_name"] = json!("Lovelace 2")),
            ),
            ("name_empty", Box::new(|b| b["first_name"] = json!("   "))),
            (
                "name_mixed_script",
                Box::new(|b| b["first_name"] = json!("Аda")),
            ),
            (
                "name_reserved",
                Box::new(|b| {
                    b["first_name"] = json!("Admin");
                    b["second_name"] = json!("Admin");
                }),
            ),
            (
                "email_required",
                Box::new(|b| {
                    b.as_object_mut().unwrap().remove("email");
                }),
            ),
            (
                "email_invalid",
                Box::new(|b| b["email"] = json!("not-an-address")),
            ),
            (
                "consent_required",
                Box::new(|b| b["consent"]["version"] = json!("0")),
            ),
            ("did_invalid", Box::new(|b| b["did"] = json!("did:key:abc"))),
            (
                "did_unsupported",
                Box::new(|b| b["did"] = json!("did:web:example.org")),
            ),
        ];
        for (class, mutate) in cases {
            let mut b = base.clone();
            mutate(&mut b);
            let r = e.post("/guest/redeem", b).await;
            assert_eq!((r.status, r.error()), (422, class.into()), "{class}");
        }
        // Not a JSON object after the credentials: 400, still after the secret.
        let mut b = base.clone();
        b["consent"] = json!("yes");
        assert_eq!(e.post("/guest/redeem", b).await.status, 400);
        assert_eq!(e.used(&inv).await, "0");
        assert!(e.record(&g).await.is_empty());

        // Order: a wrong secret beats everything, an ended invite beats validation.
        let mut b = base.clone();
        b["secret"] = json!("gi_wrong");
        b["first_name"] = json!("<b>");
        assert_eq!(e.post("/guest/redeem", b).await.status, 404);
        e.redis
            .revoke_guest_invite(&inv.host, &inv.id)
            .await
            .unwrap();
        let mut b = base.clone();
        b["first_name"] = json!("<b>");
        let r = e.post("/guest/redeem", b).await;
        assert_eq!((r.status, r.error()), (410, "revoked".into()));

        // The policy `off` refuses an address; `optional` takes one and none.
        let off = env(|_| {}).await.unwrap();
        let inv = off.invite(Kind::Open, 5).await;
        let r = off
            .post("/guest/redeem", {
                let mut b = off.body(&inv, &g, &off.nonce(&inv).await);
                b["email"] = json!("ada@example.org");
                b
            })
            .await;
        assert_eq!((r.status, r.error()), (422, "email_not_allowed".into()));
        let opt = env(|c| c.guest_email_policy = "optional".into())
            .await
            .unwrap();
        let inv = opt.invite(Kind::Open, 5).await;
        assert_eq!(opt.redeem(&inv, &Guest::new()).await.status, 200);
    }

    /// ST-13: the host's display name is a reserved name when Synapse answers, and the
    /// rule alone is skipped when it does not.
    #[tokio::test]
    async fn st13_a_lookalike_of_the_host_is_refused_and_a_profile_failure_skips_only_that() {
        let status = Arc::new(AtomicU16::new(200));
        let s = status.clone();
        let app = axum::Router::new().fallback(move || {
            let s = s.clone();
            async move {
                (
                    StatusCode::from_u16(s.load(Ordering::SeqCst)).unwrap(),
                    Json(json!({"displayname": "Erika Muster"})),
                )
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let Some(e) = env_in(None, Some(&url), |_| {}).await else {
            return;
        };
        let inv = e.invite(Kind::Open, 5).await;
        let nonce = e.nonce(&inv).await;
        let mut b = e.body(&inv, &Guest::new(), &nonce);
        b["first_name"] = json!("Erika");
        b["second_name"] = json!("Muster");
        let r = e.post("/guest/redeem", b.clone()).await;
        assert_eq!((r.status, r.error()), (422, "name_reserved".into()));
        status.store(500, Ordering::SeqCst);
        let r = e.post("/guest/redeem", b).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }

    /// ST-02, ST-03-ish: a refusal by a quota or the kill switch writes nothing and
    /// changes no invite state. One test owns its database because the kill switch and
    /// the global counters are global.
    #[tokio::test]
    async fn st02_a_quota_or_kill_switch_refusal_writes_nothing() {
        let Some(db) = siwx_oidc::test_support::redis_db(14).await else {
            return;
        };
        type Edit = Box<dyn Fn(&mut Config)>;
        let scenarios: [(&str, Edit); 3] = [
            ("global_active", Box::new(|c| c.guest_global_max_active = 1)),
            ("daily_mint", Box::new(|c| c.guest_daily_mint_max = 1)),
            (
                "host_live_guests",
                Box::new(|c| c.guest_host_max_live_guests = 1),
            ),
        ];
        for (class, edit) in scenarios {
            db.flush_db_for_test().await;
            let e = env_in(Some(14), None, edit).await.unwrap();
            let inv = e.invite(Kind::Open, 5).await;
            assert_eq!(e.redeem(&inv, &Guest::new()).await.status, 200, "{class}");
            let nonce = e.nonce(&inv).await;
            let body = e.body(&inv, &Guest::new(), &nonce);
            let before = e.redis.dbsize_for_test().await;
            let r = e.post("/guest/redeem", body).await;
            assert_eq!(r.status, 429, "{class}: {}", r.text());
            assert_eq!(r.json(), json!({"error": "quota_exceeded", "quota": class}));
            assert_eq!(
                e.redis.dbsize_for_test().await,
                before,
                "{class}: a refusal wrote"
            );
            assert_eq!(e.used(&inv).await, "1", "{class}");
        }
        // The kill switch.
        db.flush_db_for_test().await;
        let e = env_in(Some(14), None, |_| {}).await.unwrap();
        let inv = e.invite(Kind::Single, 1).await;
        let nonce = e.nonce(&inv).await;
        let body = e.body(&inv, &Guest::new(), &nonce);
        e.redis
            .hset_raw_for_test(CONTROL_KEY, "disabled", "1")
            .await;
        let before = e.redis.dbsize_for_test().await;
        let r = e.post("/guest/redeem", body.clone()).await;
        assert_eq!((r.status, r.error()), (503, "disabled".into()));
        let p = e.peek(&inv).await;
        assert_eq!((p.status, p.error()), (503, "disabled".into()));
        assert_eq!(e.redis.dbsize_for_test().await, before);
        assert_eq!(e.used(&inv).await, "0");
        // Switched off again: the same link still works (the refusal burned nothing).
        e.redis.del_raw(CONTROL_KEY).await.unwrap();
        assert_eq!(e.post("/guest/redeem", body).await.status, 200);
        db.flush_db_for_test().await;
    }

    /// S6: a banned host's invite answers as an ended one at peek and redeem and burns
    /// nothing; lifting the ban restores it. Own database: the key is global.
    #[tokio::test]
    async fn a_banned_hosts_invite_is_refused_as_revoked() {
        let Some(db) = siwx_oidc::test_support::redis_db(7).await else {
            return;
        };
        db.flush_db_for_test().await;
        let e = env_in(Some(7), None, |_| {}).await.unwrap();
        let inv = e.invite(Kind::Single, 1).await;
        let nonce = e.nonce(&inv).await;
        let body = e.body(&inv, &Guest::new(), &nonce);
        e.redis
            .sadd_raw(siwx_oidc::db::guest_invites::BANNED_HOSTS_KEY, &inv.host)
            .await
            .unwrap();
        let p = e.peek(&inv).await;
        assert_eq!(
            (p.status, p.json()["state"].clone()),
            (200, json!("revoked"))
        );
        let r = e.post("/guest/redeem", body.clone()).await;
        assert_eq!((r.status, r.error()), (410, "revoked".into()));
        assert_eq!(e.used(&inv).await, "0");
        e.redis
            .del_raw(siwx_oidc::db::guest_invites::BANNED_HOSTS_KEY)
            .await
            .unwrap();
        assert_eq!(e.post("/guest/redeem", body).await.status, 200);
        db.flush_db_for_test().await;
    }

    /// The invalid-link answer of peek and redeem is counted for the refusal-burst alert
    /// (one per refused request, whatever made the link invalid), while a valid link and
    /// the answer's bytes stay as they were.
    #[tokio::test]
    async fn an_invalid_link_is_counted_on_peek_and_redeem_and_answers_the_same() {
        let Some(db) = siwx_oidc::test_support::redis_db(6).await else {
            return;
        };
        db.flush_db_for_test().await;
        let e = env_in(Some(6), None, |_| {}).await.unwrap();
        let inv = e.invite(Kind::Open, 5).await;
        // A valid peek is no refusal.
        assert_eq!(e.peek(&inv).await.status, 200);
        assert_eq!(db.guest_refusal_total_for_test().await, 0);
        let origin = e.config.base_url.origin().ascii_serialization();
        let mut answers = Vec::new();
        let mut expect = 0;
        for route in ["/guest/peek", "/guest/redeem"] {
            for body in [
                // an unknown id
                json!({"invite_id": "gv_unknown", "secret": inv.secret}).to_string(),
                // the right id, a wrong secret
                json!({"invite_id": inv.id, "secret": "gi_wrong"}).to_string(),
                // a body that does not parse
                "not json".to_string(),
            ] {
                let r = e.post_with(route, body, Some(&origin)).await;
                assert_eq!(
                    (r.status, r.error()),
                    (404, "invalid_link".into()),
                    "{route}"
                );
                answers.push(r.bytes.clone());
                expect += 1;
                assert_eq!(
                    db.guest_refusal_total_for_test().await,
                    expect,
                    "{route}: one count per refused request"
                );
            }
        }
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "the same bytes for every reason and both routes"
        );
        // The valid link still works after the refusals.
        assert_eq!(e.peek(&inv).await.status, 200);
        assert_eq!(db.guest_refusal_total_for_test().await, expect);
        db.flush_db_for_test().await;
    }

    /// ST-29: the cookie, https and plain-http development.
    #[tokio::test]
    async fn st29_the_session_cookie_has_its_flags() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Single, 1).await;
        let g = Guest::new();
        let r = e.redeem(&inv, &g).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let cookie = r.headers[header::SET_COOKIE].to_str().unwrap().to_string();
        let handle = cookie_value(&r);
        let max_age: i64 = cookie.rsplit("Max-Age=").next().unwrap().parse().unwrap();
        assert!(
            (SESSION as i64 - 5..=SESSION as i64).contains(&max_age),
            "{cookie}"
        );
        assert_eq!(
            cookie,
            format!(
                "__Host-guest_session={handle}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"
            )
        );
        assert!(!cookie.contains("Domain"));
        // The body: the configured URL, the deadline, the seconds left.
        let v = r.json();
        assert_eq!(v["guest_client_url"], "https://meet.example.org/start");
        assert_eq!(v["seconds_left"], max_age);
        let rec = e.record(&g).await;
        assert_eq!(v["deadline"].as_i64().unwrap().to_string(), rec["deadline"]);
        // Redis holds only the hash of the handle, with a TTL to the deadline.
        let key = handle_key(&hex::encode(Sha256::digest(handle.as_bytes())));
        assert_eq!(
            e.redis.get_raw(&key).await.unwrap().as_deref(),
            Some(localpart_for(&g.did).as_str())
        );
        assert!(e.redis.ttl_for_test(&key).await > 0);
        assert_eq!(
            e.redis
                .get_raw(&format!("guest:handle/{handle}"))
                .await
                .unwrap(),
            None
        );
        let all = e.redis.keys_raw("*").await.unwrap();
        assert!(
            all.iter().all(|k| !k.contains(&handle)),
            "a key names the handle"
        );
        assert_eq!(handle.len(), 43, "32 random bytes, base64url");
        // ST-27: the guest headers are on the success too.
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["referrer-policy"], "no-referrer");

        // Plain-http development.
        let local = env(|c| {
            c.base_url = url::Url::parse("http://localhost:18080").unwrap();
            c.guest_client_url = Some(url::Url::parse("http://localhost:5173/start").unwrap());
        })
        .await
        .unwrap();
        let inv = local.invite(Kind::Single, 1).await;
        let nonce = local.nonce(&inv).await;
        let r = local
            .post_with(
                "/guest/redeem",
                local.body(&inv, &Guest::new(), &nonce).to_string(),
                Some("http://localhost:18080"),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let cookie = r.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.starts_with("guest_session="), "{cookie}");
        assert!(
            !cookie.contains("Secure") && !cookie.contains("__Host-"),
            "{cookie}"
        );
        assert!(
            cookie.contains("HttpOnly; SameSite=Lax; Path=/; Max-Age="),
            "{cookie}"
        );
    }

    /// ST-41 / ST-07 / ST-17: the record holds the closed field list, the deadline is
    /// Redis TIME plus the session length, the secret is nowhere, and the same address
    /// twice gives the same answer.
    #[tokio::test]
    async fn st41_the_record_holds_the_closed_field_list_and_no_secret() {
        let Some(e) = env(|c| c.guest_email_policy = "optional".into()).await else {
            return;
        };
        let inv = e.invite(Kind::Open, 5).await;
        let g = Guest::new();
        let nonce = e.nonce(&inv).await;
        let mut body = e.body(&inv, &g, &nonce);
        body["first_name"] = json!("  Zoe\u{0301}  ");
        body["email"] = json!(" Ada@Example.ORG ");
        let r = e.post("/guest/redeem", body).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let rec = e.record(&g).await;
        let fields: BTreeSet<&str> = rec.keys().map(String::as_str).collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "state",
                "did",
                "invite_id",
                "host",
                "room_id",
                "first_name",
                "second_name",
                "email",
                "consent_version",
                "consent_variant",
                "created_at",
                "deadline"
            ])
        );
        assert_eq!(rec["state"], "minted");
        assert_eq!(rec["did"], g.did);
        assert_eq!(rec["invite_id"], inv.id);
        assert_eq!(rec["host"], inv.host);
        assert_eq!(rec["first_name"], "Zo\u{e9}", "NFC, trimmed");
        assert_eq!(rec["email"], "Ada@example.org");
        assert_eq!(
            (&rec["consent_version"][..], &rec["consent_variant"][..]),
            ("1", "a")
        );
        let (created, deadline): (i64, i64) = (
            rec["created_at"].parse().unwrap(),
            rec["deadline"].parse().unwrap(),
        );
        assert_eq!(
            deadline - created,
            SESSION as i64,
            "Redis TIME + session_secs"
        );
        assert_eq!(
            e.redis
                .zscore_for_test(DUE_KEY, &localpart_for(&g.did))
                .await,
            Some(deadline as f64)
        );
        let blob = format!("{rec:?}{}", r.text());
        assert!(
            !blob.contains(&inv.secret),
            "the secret is in the record or the answer"
        );
        // Without an address the field is absent; the same address twice is accepted alike.
        let g2 = Guest::new();
        let mut body = e.body(&inv, &g2, &nonce);
        body["email"] = json!("ada@example.org");
        assert_eq!(e.post("/guest/redeem", body).await.status, 200);
        let g3 = Guest::new();
        assert_eq!(e.redeem(&inv, &g3).await.status, 200);
        assert!(!e.record(&g3).await.contains_key("email"));
        // The record is a guest: no promotion, so it is refused as a host.
        assert!(e
            .redis
            .is_unpromoted_guest(&localpart_for(&g.did))
            .await
            .unwrap());
    }

    /// The seams: the host's list shows the guests and counts, and ending an invite or a
    /// meeting moves unclaimed deadlines to now, never later, and skips `claimed`.
    #[tokio::test]
    async fn the_host_list_and_the_end_routes_use_the_real_records() {
        let host = format!("host{}", uniq());
        let hosts = host.clone();
        let Some(e) = env(move |c| c.guest_hosts = vec![hosts.clone()]).await else {
            return;
        };
        let token = format!("mat_{}", uniq());
        e.redis
            .set_token(
                &token,
                &TokenMetadata {
                    username: host.clone(),
                    device_id: String::new(),
                    scope: "openid".into(),
                    client_id: "c".into(),
                    iat: 0,
                    exp: i64::MAX,
                    did: "did:key:zHost".into(),
                    name: "n".into(),
                    kind: Some(TokenKind::Access),
                    grant_kind: None,
                },
                300,
            )
            .await
            .unwrap();
        let inv = e.invite_of(&host, Kind::Open, 5).await;
        let (a, b, c) = (Guest::new(), Guest::new(), Guest::new());
        for g in [&a, &b, &c] {
            assert_eq!(e.redeem(&inv, g).await.status, 200);
        }
        let key_of = |g: &Guest| guest_account_key(&localpart_for(&g.did));
        e.redis
            .hset_raw_for_test(&key_of(&a), "state", "active")
            .await;
        e.redis
            .hset_raw_for_test(&key_of(&b), "state", "claimed")
            .await;
        let list = |token: String| {
            let (client, url) = (e.client.clone(), format!("{}/guest/invites", e.base));
            async move {
                let r = client.get(url).bearer_auth(token).send().await.unwrap();
                (r.status().as_u16(), r.json::<Value>().await.unwrap())
            }
        };
        let (status, v) = list(token.clone()).await;
        assert_eq!(status, 200);
        let item = &v["invites"][0];
        assert_eq!(
            item["counts"],
            json!({"redeemed": 3, "active": 3, "ended": 0, "reaped": 0})
        );
        let guests = item["guests"].as_array().unwrap();
        assert_eq!(guests.len(), 3);
        assert!(guests
            .iter()
            .all(|g| g["first_name"] == "Ada" && g.get("email").is_none()));
        let mut states: Vec<_> = guests
            .iter()
            .map(|g| g["state"].as_str().unwrap())
            .collect();
        states.sort();
        assert_eq!(states, ["active", "claimed", "minted"]);
        assert!(!v.to_string().contains(&inv.secret));

        // c has an earlier deadline than "now" would give; it must not move later.
        let early = Utc::now().timestamp() + 5;
        e.redis
            .hset_raw_for_test(&key_of(&c), "deadline", &early.to_string())
            .await;
        let claimed_before = e.record(&b).await["deadline"].clone();
        let end = e
            .client
            .post(format!("{}/guest/invites/{}/end", e.base, inv.id))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(end.status(), 200);
        let now = Utc::now().timestamp();
        let moved = |g: &Guest| {
            let (e, k) = (e.clone(), key_of(g));
            async move {
                e.redis.hgetall_for_test(&k).await["deadline"]
                    .parse::<i64>()
                    .unwrap()
            }
        };
        assert!(
            (now - 5..=now + 1).contains(&moved(&a).await),
            "a moved to now"
        );
        assert!(
            (now - 5..=now + 1).contains(&moved(&c).await),
            "c moved to now"
        );
        assert_eq!(
            e.record(&b).await["deadline"],
            claimed_before,
            "claimed is not moved"
        );
        assert_eq!(
            e.redis
                .zscore_for_test(DUE_KEY, &localpart_for(&a.did))
                .await,
            Some(moved(&a).await as f64)
        );
        // Never later: an already-due guest keeps its earlier deadline.
        e.redis
            .hset_raw_for_test(&key_of(&a), "deadline", "5")
            .await;
        e.redis
            .move_guest_deadlines_to_now(std::slice::from_ref(&inv.id))
            .await
            .unwrap();
        assert_eq!(moved(&a).await, 5);
        // The list shows the guests of a revoked invite as well.
        let (_, v) = list(token.clone()).await;
        assert_eq!(v["invites"][0]["state"], "revoked");
        assert_eq!(v["invites"][0]["guests"].as_array().unwrap().len(), 3);

        // The meeting route moves the deadlines of its room's invites.
        let inv2 = e.invite_of(&host, Kind::Open, 5).await;
        let d = Guest::new();
        assert_eq!(e.redeem(&inv2, &d).await.status, 200);
        let r = e
            .client
            .post(format!("{}/guest/meetings/end", e.base))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(json!({"room_id": "!room:example.org"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let now = Utc::now().timestamp();
        assert!(
            (now - 5..=now + 1).contains(&moved(&d).await),
            "d moved to now"
        );
        let _ = by_host_key(&host);
    }

    /// S5b: the host's "End meeting" and "End link" are fail-closed. When the deadline move
    /// fails (here: the invite's guest set is not a set), the answer is 503 `unavailable`
    /// and never 200 while a guest stays live; after the fault is gone a retry succeeds
    /// (the revoke is idempotent) and the guest is due.
    #[tokio::test]
    async fn the_host_end_routes_answer_503_when_the_deadline_move_fails() {
        let host = format!("host{}", uniq());
        let hosts = host.clone();
        let Some(e) = env(move |c| c.guest_hosts = vec![hosts.clone()]).await else {
            return;
        };
        let token = format!("mat_{}", uniq());
        e.redis
            .set_token(
                &token,
                &TokenMetadata {
                    username: host.clone(),
                    device_id: String::new(),
                    scope: "openid".into(),
                    client_id: "c".into(),
                    iat: 0,
                    exp: i64::MAX,
                    did: "did:key:zHost".into(),
                    name: "n".into(),
                    kind: Some(TokenKind::Access),
                    grant_kind: None,
                },
                300,
            )
            .await
            .unwrap();
        let inv = e.invite_of(&host, Kind::Open, 5).await;
        let g = Guest::new();
        assert_eq!(e.redeem(&inv, &g).await.status, 200);
        let lp = localpart_for(&g.did);
        let members = by_invite_key(&inv.id);
        let post = |path: String, body: String| {
            let (client, url, token) =
                (e.client.clone(), format!("{}{path}", e.base), token.clone());
            async move {
                let r = client
                    .post(url)
                    .bearer_auth(token)
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .unwrap();
                (r.status().as_u16(), r.json::<Value>().await.unwrap())
            }
        };
        let end_invite = format!("/guest/invites/{}/end", inv.id);
        let meeting = json!({"room_id": "!room:example.org"}).to_string();
        // The fault: the member set of the invite is a string, so the script errors.
        e.redis.del_raw(&members).await.unwrap();
        e.redis.set_raw(&members, "broken").await.unwrap();
        for (path, body) in [
            (end_invite.clone(), "{}".to_string()),
            ("/guest/meetings/end".to_string(), meeting.clone()),
        ] {
            let (status, v) = post(path.clone(), body).await;
            assert_eq!(
                (status, v),
                (503, json!({"error": "unavailable"})),
                "{path}"
            );
        }
        // Healed: the set is back, both routes answer 200 and the guest is due.
        e.redis.del_raw(&members).await.unwrap();
        e.redis.sadd_raw_for_test(&members, &lp).await;
        let (status, _) = post(end_invite, "{}".to_string()).await;
        assert_eq!(status, 200);
        let now = Utc::now().timestamp();
        let due = e.redis.zscore_for_test(DUE_KEY, &lp).await.unwrap() as i64;
        assert!((now - 5..=now + 1).contains(&due), "the guest is due now");
        let (status, _) = post("/guest/meetings/end".to_string(), meeting).await;
        assert_eq!(status, 200);
    }

    /// A guest's record makes its token a guest token on the host routes.
    #[tokio::test]
    async fn a_minted_guest_is_refused_as_a_host() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Single, 1).await;
        let g = Guest::new();
        assert_eq!(e.redeem(&inv, &g).await.status, 200);
        let lp = localpart_for(&g.did);
        let token = format!("mat_{}", uniq());
        let mut conf = e.config.clone();
        conf.guest_hosts = vec![lp.clone()];
        let app = super::super::routes::router(&conf, e.redis.clone(), None);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        e.redis
            .set_token(
                &token,
                &TokenMetadata {
                    username: lp,
                    device_id: String::new(),
                    scope: "openid".into(),
                    client_id: "c".into(),
                    iat: 0,
                    exp: i64::MAX,
                    did: g.did.clone(),
                    name: "n".into(),
                    kind: Some(TokenKind::Access),
                    grant_kind: None,
                },
                300,
            )
            .await
            .unwrap();
        let r = e
            .client
            .get(format!("http://{addr}/guest/invites"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(
            r.json::<Value>().await.unwrap(),
            json!({"error": "guest_token"})
        );
    }

    /// A P-256 key works too: the WebCrypto `r || s` signature over SHA-256.
    #[tokio::test]
    async fn a_p256_guest_redeems_with_a_webcrypto_signature() {
        use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Single, 1).await;
        let sk = SigningKey::random(&mut OsRng);
        let mut bytes = vec![0x80, 0x24];
        bytes.extend_from_slice(sk.verifying_key().to_encoded_point(true).as_bytes());
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        let nonce = e.nonce(&inv).await;
        let now = Utc::now();
        let msg = build_redeem_message(
            &e.config.base_url,
            &did,
            &inv.id,
            &nonce,
            now,
            now + Duration::minutes(5),
        )
        .unwrap();
        let sig: Signature = sk.sign(msg.as_bytes());
        let body = json!({
            "invite_id": inv.id, "secret": inv.secret, "first_name": "Ada", "second_name": "Lovelace",
            "consent": {"version": "1", "variant": "a"}, "did": did,
            "proof": {"message": msg, "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes())},
        });
        let r = e.post("/guest/redeem", body).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let rec = e
            .redis
            .hgetall_for_test(&guest_account_key(&localpart_for(&did)))
            .await;
        assert_eq!(rec["did"], did);
    }

    /// The origin check applies: a cross-site POST never reaches the handler.
    #[tokio::test]
    async fn peek_and_redeem_are_origin_checked() {
        let Some(e) = env(|_| {}).await else { return };
        let inv = e.invite(Kind::Single, 1).await;
        for path in ["/guest/peek", "/guest/redeem"] {
            let body = json!({"invite_id": inv.id, "secret": inv.secret}).to_string();
            for origin in [None, Some("https://evil.example.org")] {
                let r = e.post_with(path, body.clone(), origin).await;
                assert_eq!((r.status, r.error()), (403, "forbidden_origin".into()));
            }
        }
        assert_eq!(e.used(&inv).await, "0");
    }

    // ---- the join page and its assets (S3c) ----

    async fn get(e: &Env, path: &str) -> Resp {
        let r = e
            .client
            .get(format!("{}{path}", e.base))
            .header("sec-fetch-site", "none")
            .send()
            .await
            .unwrap();
        Resp {
            status: r.status().as_u16(),
            headers: r.headers().clone(),
            bytes: r.bytes().await.unwrap().to_vec(),
        }
    }

    fn assert_gp_sec_39(r: &Resp) {
        let h = |n: &str| r.headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
        assert_eq!(
            h("content-security-policy"),
            "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; \
             form-action 'self'; frame-ancestors 'none'"
        );
        assert_eq!(h("x-frame-options"), "DENY");
        assert_eq!(h("referrer-policy"), "no-referrer");
        assert_eq!(h("x-content-type-options"), "nosniff");
        assert_eq!(h("cache-control"), "no-store");
    }

    #[tokio::test]
    async fn join_page_is_the_same_html_for_every_id_with_the_headers() {
        let Some(e) = env(|_| {}).await else { return };
        let a = get(&e, "/guest/join/inv_known_or_not").await;
        let b = get(&e, "/guest/join/zzz").await;
        for r in [&a, &b] {
            assert_eq!(r.status, 200);
            assert!(r.headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html"));
            assert_gp_sec_39(r);
        }
        assert_eq!(a.bytes, b.bytes, "the id must not change a byte");
        let html = a.text();
        // CSP: nothing inline, so the page may only name its own scripts and styles.
        assert!(!html.contains("<style"), "no inline style");
        assert!(!html.contains(" style="), "no style attribute");
        assert!(!html.contains(" onclick=") && !html.contains(" onsubmit="));
        assert!(!html
            .replace("<script type=\"module\" src=", "")
            .contains("<script>"));
    }

    #[tokio::test]
    async fn assets_are_a_fixed_allow_list() {
        let Some(e) = env(|_| {}).await else { return };
        for (file, ct) in [
            ("join.js", "text/javascript"),
            ("guest-key.js", "text/javascript"),
            ("guest.css", "text/css"),
        ] {
            let r = get(&e, &format!("/guest/assets/{file}")).await;
            assert_eq!(r.status, 200, "{file}");
            assert!(
                r.headers[header::CONTENT_TYPE]
                    .to_str()
                    .unwrap()
                    .starts_with(ct),
                "{file}"
            );
            assert!(!r.bytes.is_empty());
            assert_gp_sec_39(&r);
        }
        for bad in [
            "guest-key.test.mjs",
            "join.html",
            "nope.js",
            "..%2F..%2FCargo.toml",
            "%2e%2e%2fCargo.toml",
            "..",
            "join.js%00",
            "JOIN.JS",
        ] {
            let r = get(&e, &format!("/guest/assets/{bad}")).await;
            assert_eq!(r.status, 404, "{bad}");
            assert_eq!(r.error(), "not_found", "{bad}");
            assert_gp_sec_39(&r);
        }
        assert_eq!(get(&e, "/guest/assets/a/b").await.status, 404);
    }

    #[tokio::test]
    async fn join_page_and_assets_give_the_503_shell_with_guest_mode_off() {
        let Some(e) = env(|c| c.guest_enabled = false).await else {
            return;
        };
        for path in ["/guest/join/abc", "/guest/assets/join.js"] {
            let r = get(&e, path).await;
            assert_eq!(r.status, 503, "{path}");
            assert_eq!(r.error(), "guest_unavailable", "{path}");
            assert_gp_sec_39(&r);
        }
    }
}
