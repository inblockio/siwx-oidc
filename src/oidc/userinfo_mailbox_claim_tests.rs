//! Tests for what `/userinfo` says about a mail client's token: the `io.inblock.mailbox` claim,
//! the answer to a token it cannot use, and the rule that it never carries an `email`.
//!
//! The claim is what lets a mail server create a mailbox, so every condition that gates it has
//! a case that goes wrong when only that condition is dropped, and the case that meets them all
//! is asserted too: a claim that is never emitted would pass every absence check. Redis-backed
//! like the `io.inblock.mxid` tests, for the same reason: `userinfo` resolves its caller through
//! the real access check, so every token here belongs to a real grant.

use super::*;
use crate::config::Config;
use crate::localpart::{legacy_localpart, localpart_for};

/// A `did:key`, so no ENS lookup can happen. Mixed case: `sub` must come back exact.
const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
const MAIL_DOMAIN: &str = "matrix.example.org";
const GENERIC_MAIL: &[&str] = &["openid", "io.inblock.mail"];
const MAIL_SCOPES: &str = "openid io.inblock.mail";
/// Spelled out by hand: a test that read the name from the code would agree with any rename.
const CLAIM: &str = "io.inblock.mailbox";

fn nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

fn config(mail_domain: Option<&str>) -> Config {
    Config {
        ens_api_url: None,
        eth_provider: None,
        matrix_server_name: Some(MAIL_DOMAIN.to_string()),
        mail_domain: mail_domain.map(str::to_string),
        ..Config::default()
    }
}

fn client(class: ClientClass, allowed: Option<&[&str]>, signed: bool) -> ClientEntry {
    let mut metadata = SiwxClientMetadata::new(
        vec![RedirectUrl::new("https://mail.example.org/cb".into()).unwrap()],
        LogoutClientMetadata::default(),
    );
    if signed {
        metadata = metadata
            .set_userinfo_signed_response_alg(Some(CoreJwsSigningAlgorithm::EcdsaP256Sha256));
    }
    ClientEntry {
        class,
        allowed_scopes: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
        ..ClientEntry::new("s", metadata, None)
    }
}

async fn store_client(db: &RedisClient, entry: ClientEntry) -> String {
    let client_id = format!("mailbox-{}", nonce());
    db.set_client(client_id.clone(), entry).await.unwrap();
    client_id
}

/// A grant of `kind` for [`DID`], recording `username` as its localpart.
async fn issue(
    db: &RedisClient,
    kind: GrantKind,
    client_id: &str,
    username: &str,
    scope: &str,
) -> siwx_oidc::db::grant::IssuedGrant {
    db.issue_grant(&NewGrant {
        kind,
        username: username.to_string(),
        did: DID.to_string(),
        client_id: client_id.to_string(),
        confidential_client: false,
        device_id: if kind == GrantKind::MatrixDevice {
            format!("SIWX_{}", nonce())
        } else {
            String::new()
        },
        scope: scope.to_string(),
        name: DID.to_string(),
        auth_ms: None,
        access_ttl: ACCESS_TOKEN_TTL,
        refresh_inactivity_secs: (kind != GrantKind::Service).then_some(REFRESH_TOKEN_TTL),
    })
    .await
    .unwrap()
}

/// The access token of an `oidc` grant: what a code exchange gives a generic mail client.
async fn oidc_token(db: &RedisClient, client_id: &str, username: &str, scope: &str) -> String {
    issue(db, GrantKind::Oidc, client_id, username, scope)
        .await
        .access_token
}

async fn userinfo_of(
    config: &Config,
    db: &RedisClient,
    token: Option<String>,
) -> Result<UserInfoResponse, CustomError> {
    userinfo(
        config,
        &EcdsaSigningKey::generate(),
        None,
        UserInfoPayload {
            access_token: token,
        },
        db,
    )
    .await
}

/// The payload of the compact JWS a client that registered a signed response receives.
fn jwt_payload(jwt: SiwxUserInfoJsonWebToken) -> serde_json::Value {
    let compact = serde_json::to_value(jwt)
        .unwrap()
        .as_str()
        .expect("the compact JWS string")
        .to_string();
    let payload = compact
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// The claims a client reads: the JSON body, or the payload of the signed response when the
/// client registered for one.
async fn claims(config: &Config, db: &RedisClient, token: &str) -> serde_json::Value {
    match userinfo_of(config, db, Some(token.to_string()))
        .await
        .expect("userinfo succeeds for a live access token")
    {
        UserInfoResponse::Json(c) => serde_json::to_value(c).unwrap(),
        UserInfoResponse::Jwt(jwt) => jwt_payload(jwt),
    }
}

#[tokio::test]
async fn mailbox_claim_opaque_only() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    assert_eq!(
        client_policy::MAILBOX_CLAIM,
        CLAIM,
        "the constant and the serde rename must agree"
    );
    let config = config(Some(MAIL_DOMAIN));
    let opaque = localpart_for(DID);
    let client_id =
        store_client(&db, client(ClientClass::Generic, Some(GENERIC_MAIL), false)).await;

    let token = oidc_token(&db, &client_id, &opaque, MAIL_SCOPES).await;
    let body = claims(&config, &db, &token).await;
    assert_eq!(body[CLAIM], format!("{opaque}@{MAIL_DOMAIN}"), "{body}");
    assert_eq!(body["sub"], DID, "sub stays the exact-case DID");
    assert_eq!(
        body["preferred_username"], DID,
        "preferred_username stays the DID"
    );

    let legacy = oidc_token(&db, &client_id, &legacy_localpart(DID), MAIL_SCOPES).await;
    let body = claims(&config, &db, &legacy).await;
    assert!(
        body.get(CLAIM).is_none(),
        "a legacy localpart gets no mailbox: {body}"
    );
}

#[tokio::test]
async fn the_mailbox_claim_needs_every_condition() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let opaque = localpart_for(DID);
    let generic_id =
        store_client(&db, client(ClientClass::Generic, Some(GENERIC_MAIL), false)).await;
    let narrowed_id =
        store_client(&db, client(ClientClass::Generic, Some(&["openid"]), false)).await;
    let matrix_id = store_client(&db, client(ClientClass::Matrix, None, false)).await;

    let token = oidc_token(&db, &generic_id, &opaque, MAIL_SCOPES).await;
    let body = claims(&config(Some(MAIL_DOMAIN)), &db, &token).await;
    assert_eq!(
        body[CLAIM],
        format!("{opaque}@{MAIL_DOMAIN}"),
        "every condition met: the claim is there, so the absences below mean something: {body}"
    );

    let legacy = format!("tok_{}", nonce());
    db.set_token(
        &legacy,
        &TokenMetadata {
            username: opaque.clone(),
            device_id: String::new(),
            scope: MAIL_SCOPES.to_string(),
            client_id: generic_id.clone(),
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 300,
            did: DID.to_string(),
            name: DID.to_string(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        },
        300,
    )
    .await
    .unwrap();

    let cases = [
        (
            "no mail scope",
            oidc_token(&db, &generic_id, &opaque, "openid").await,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "a scope that only starts with the mail scope",
            oidc_token(&db, &generic_id, &opaque, "openid io.inblock.mailx").await,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "the client is no longer allowed the scope",
            oidc_token(&db, &narrowed_id, &opaque, MAIL_SCOPES).await,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "a Matrix device grant, whatever its scope string",
            issue(
                &db,
                GrantKind::MatrixDevice,
                &matrix_id,
                &opaque,
                MAIL_SCOPES,
            )
            .await
            .access_token,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "a Matrix device grant of a client that is generic-class now",
            issue(
                &db,
                GrantKind::MatrixDevice,
                &generic_id,
                &opaque,
                MAIL_SCOPES,
            )
            .await
            .access_token,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "an oidc grant whose client is Matrix-class now",
            oidc_token(&db, &matrix_id, &opaque, MAIL_SCOPES).await,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "a service grant",
            issue(&db, GrantKind::Service, &generic_id, &opaque, MAIL_SCOPES)
                .await
                .access_token,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "a legacy token with no grant behind it",
            legacy,
            config(Some(MAIL_DOMAIN)),
        ),
        (
            "no mail domain configured",
            oidc_token(&db, &generic_id, &opaque, MAIL_SCOPES).await,
            config(None),
        ),
    ];
    for (why, token, cfg) in cases {
        let body = claims(&cfg, &db, &token).await;
        assert!(body.get(CLAIM).is_none(), "{why}: {body}");
    }
}

#[tokio::test]
async fn the_signed_jwt_variant_carries_the_mailbox_claim() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let opaque = localpart_for(DID);
    let client_id = store_client(&db, client(ClientClass::Generic, Some(GENERIC_MAIL), true)).await;
    let token = oidc_token(&db, &client_id, &opaque, MAIL_SCOPES).await;
    let response = userinfo_of(&config(Some(MAIL_DOMAIN)), &db, Some(token))
        .await
        .expect("userinfo succeeds");
    let payload = match response {
        UserInfoResponse::Jwt(jwt) => jwt_payload(jwt),
        UserInfoResponse::Json(_) => panic!("a signed response was registered"),
    };
    assert_eq!(payload[CLAIM], format!("{opaque}@{MAIL_DOMAIN}"));
}

// -- The shape of the localpart -------------------------------------------------------------

/// The mailbox claim userinfo carries for a mail-scoped token of a generic client that records
/// `username`, or `None` when the claim is absent.
async fn mailbox_recorded_as(db: &RedisClient, username: &str) -> Option<String> {
    let client_id = store_client(db, client(ClientClass::Generic, Some(GENERIC_MAIL), false)).await;
    let token = oidc_token(db, &client_id, username, MAIL_SCOPES).await;
    let body = claims(&config(Some(MAIL_DOMAIN)), db, &token).await;
    body.get(CLAIM)
        .map(|claim| claim.as_str().expect("the claim is a string").to_string())
}

/// The claim carries only a 16-character lowercase base36 localpart: a mail server takes a
/// mailbox name of any case and length, so this provider is the only gate on the shape. Each
/// malformed spelling below is also refused by the check against the token's DID; the shape
/// gate is pinned on its own in `client_policy`.
async fn assert_mailbox_only_for_the_opaque_localpart(malformed: &str, what: &str) {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let opaque = localpart_for(DID);
    assert_eq!(
        mailbox_recorded_as(&db, &opaque).await,
        Some(format!("{opaque}@{MAIL_DOMAIN}")),
        "control: the opaque localpart of the same DID gets its address"
    );
    assert_eq!(
        mailbox_recorded_as(&db, malformed).await,
        None,
        "{what}: {malformed:?} gets no mailbox claim"
    );
}

#[tokio::test]
async fn an_upper_case_localpart_gets_no_mailbox_claim() {
    let upper = localpart_for(DID).to_uppercase();
    assert_mailbox_only_for_the_opaque_localpart(&upper, "upper case").await;
}

#[tokio::test]
async fn a_15_character_localpart_gets_no_mailbox_claim() {
    let short = localpart_for(DID)[..15].to_string();
    assert_mailbox_only_for_the_opaque_localpart(&short, "15 characters").await;
}

#[tokio::test]
async fn a_17_character_localpart_gets_no_mailbox_claim() {
    let long = format!("{}a", localpart_for(DID));
    assert_mailbox_only_for_the_opaque_localpart(&long, "17 characters").await;
}

#[tokio::test]
async fn the_legacy_localpart_gets_no_mailbox_claim() {
    assert_mailbox_only_for_the_opaque_localpart(&legacy_localpart(DID), "the legacy form").await;
}

#[tokio::test]
async fn a_localpart_with_non_base36_characters_gets_no_mailbox_claim() {
    let opaque = localpart_for(DID);
    for replacement in ["-", "_", ".", ":", "@", "/", " ", "\u{e9}"] {
        let mut malformed = opaque.clone();
        malformed.replace_range(7..8, replacement);
        assert_mailbox_only_for_the_opaque_localpart(
            &malformed,
            &format!("{replacement:?} in place of one character"),
        )
        .await;
    }
}

// -- No email claim -------------------------------------------------------------------------

/// Every scope string a token could record: all 64 subsets of the scopes a client of this
/// server can see, the empty one included.
fn every_scope_combination() -> Vec<String> {
    const SCOPES: [&str; 6] = [
        "openid",
        "profile",
        "email",
        "io.inblock.mail",
        "urn:matrix:client:api:*",
        "urn:matrix:client:device:SIWX_NOEMAIL",
    ];
    (0u32..1 << SCOPES.len())
        .map(|mask| {
            SCOPES
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, scope)| *scope)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// Whether `value` holds a key named `email` anywhere in it.
fn holds_an_email_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .any(|(key, inner)| key == "email" || holds_an_email_key(inner)),
        serde_json::Value::Array(items) => items.iter().any(holds_an_email_key),
        _ => false,
    }
}

/// A mail server that finds no mailbox claim may fall back to the standard `email` claim, so
/// an `email` in any userinfo response would let a token open that mailbox. Userinfo carries
/// none, for either class of client, in the JSON and the signed response, whatever scope the
/// token records (`email` and the Matrix scopes included).
#[tokio::test]
async fn userinfo_never_carries_an_email_claim() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let config = config(Some(MAIL_DOMAIN));
    let opaque = localpart_for(DID);
    let generic_scopes: &[&str] = &["openid", "profile", "email", "io.inblock.mail"];
    let mut clients = Vec::new();
    for class in [ClientClass::Matrix, ClientClass::Generic] {
        for signed in [false, true] {
            let allowed = (class == ClientClass::Generic).then_some(generic_scopes);
            let client_id = store_client(&db, client(class, allowed, signed)).await;
            let kind = match class {
                ClientClass::Matrix => GrantKind::MatrixDevice,
                ClientClass::Generic => GrantKind::Oidc,
            };
            clients.push((client_id, class, kind));
        }
    }

    let mut asked = 0;
    for (client_id, class, kind) in &clients {
        for scope in every_scope_combination() {
            let token = issue(&db, *kind, client_id, &opaque, &scope)
                .await
                .access_token;
            let body = claims(&config, &db, &token).await;
            assert!(
                !holds_an_email_key(&body),
                "userinfo must never carry `email` ({class:?} client, scope {scope:?}): {body}"
            );
            asked += 1;
        }
    }
    assert_eq!(
        asked,
        4 * 64,
        "every class, response variant and scope combination was asked"
    );
}

// -- A token userinfo cannot use ------------------------------------------------------------

/// RFC 6750 section 3.1: a token that cannot be used is `invalid_token`, rendered as a 401
/// with a challenge. A 400 reads as a fault in the request itself, which a resource server may
/// treat as temporary and retry, for a credential that can never work again.
#[tokio::test]
async fn an_unknown_token_is_an_invalid_token() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let result = userinfo_of(
        &config(Some(MAIL_DOMAIN)),
        &db,
        Some(format!("tok_{}", nonce())),
    )
    .await;
    assert!(
        matches!(result, Err(CustomError::InvalidToken(ref m)) if m == "Unknown token."),
        "an unknown token"
    );
}

#[tokio::test]
async fn an_expired_token_is_an_invalid_token() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let client_id = store_client(&db, client(ClientClass::Matrix, None, false)).await;
    let token = format!("tok_{}", nonce());
    db.set_token(
        &token,
        &TokenMetadata {
            username: localpart_for(DID),
            device_id: String::new(),
            scope: "openid".to_string(),
            client_id,
            iat: 0,
            exp: Utc::now().timestamp() - 1,
            did: DID.to_string(),
            name: DID.to_string(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        },
        120,
    )
    .await
    .unwrap();

    let result = userinfo_of(&config(Some(MAIL_DOMAIN)), &db, Some(token)).await;

    assert!(
        matches!(result, Err(CustomError::InvalidToken(_))),
        "an expired token"
    );
}

/// A refresh token goes to the refresh grants and to revocation, never to a resource server.
#[tokio::test]
async fn a_refresh_token_is_an_invalid_token() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let client_id =
        store_client(&db, client(ClientClass::Generic, Some(GENERIC_MAIL), false)).await;
    let issued = issue(
        &db,
        GrantKind::Oidc,
        &client_id,
        &localpart_for(DID),
        MAIL_SCOPES,
    )
    .await;
    let refresh = issued
        .refresh_token
        .expect("the grant carries a refresh token");

    let result = userinfo_of(&config(Some(MAIL_DOMAIN)), &db, Some(refresh)).await;

    assert!(
        matches!(result, Err(CustomError::InvalidToken(ref m)) if m == "Unknown token."),
        "a refresh token presented as a bearer token"
    );
    userinfo_of(&config(Some(MAIL_DOMAIN)), &db, Some(issued.access_token))
        .await
        .map(|_| ())
        .expect("the access token of the same grant still works");
}

/// A token whose client is gone (a static client removed from the configuration, a dynamic one
/// that expired) is dead for good, so it is answered like any other dead token.
#[tokio::test]
async fn a_token_whose_client_is_gone_is_an_invalid_token() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let token = oidc_token(
        &db,
        &format!("no-such-client-{}", nonce()),
        &localpart_for(DID),
        MAIL_SCOPES,
    )
    .await;

    let result = userinfo_of(&config(Some(MAIL_DOMAIN)), &db, Some(token)).await;

    assert!(
        matches!(result, Err(CustomError::InvalidToken(ref m)) if m == "Unknown client."),
        "a token of a client that no longer exists"
    );
}

/// A request that presents no token at all is a malformed request, not a rejected credential,
/// and keeps its 400.
#[tokio::test]
async fn a_request_without_a_token_is_still_a_bad_request() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let result = userinfo_of(&config(Some(MAIL_DOMAIN)), &db, None).await;
    assert!(
        matches!(result, Err(CustomError::BadRequest(ref m)) if m == "Missing access token."),
        "no token"
    );
}
