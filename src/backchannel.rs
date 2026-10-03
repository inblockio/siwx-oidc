//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0; design 5.6,
//! D3, D4): the logout token, the SSRF guard on `backchannel_logout_uri`, and
//! the worker that delivers the outbox ([`siwx_oidc::db::outbox`]).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siwx_oidc::db::outbox::{ClaimedEntry, LogoutEntry};
use siwx_oidc::db::RedisClient;
use url::Url;

use crate::oidc::EcdsaSigningKey;

/// The one event a logout token carries (§2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// The JWS `typ` of a logout token (§2.4).
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";
/// A logout token's lifetime: `exp` = `iat` + this.
pub const LOGOUT_TOKEN_LIFETIME_SECS: i64 = 120;

/// The logout token for `entry`, signed now.
pub fn mint_logout_token(
    key: &EcdsaSigningKey,
    issuer: &str,
    entry: &LogoutEntry,
    now: i64,
) -> String {
    let _ = (key, issuer, entry, now);
    String::new()
}

/// An address class delivery never connects to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    Unspecified,
    Loopback,
    Private,
    SharedCgnat,
    LinkLocal,
    Multicast,
    Reserved,
}

/// The class `ip` belongs to when delivery must refuse it, else `None`.
pub fn refused_class(ip: IpAddr) -> Option<AddressClass> {
    let _ = ip;
    None
}

/// Why a `backchannel_logout_uri` is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UriRefusal {
    NoHost,
    Fragment,
    NotHttps,
    Unresolvable,
    Address(AddressClass),
}

/// The SSRF guard: the operator's host allowlist plus the address check.
#[derive(Clone, Debug, Default)]
pub struct UriGuard {
    allowed_hosts: Arc<Vec<String>>,
}

impl UriGuard {
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            allowed_hosts: Arc::new(
                allowed_hosts
                    .iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect(),
            ),
        }
    }

    /// `Ok(None)` for an allowlisted host (no address check), `Ok(Some(addrs))`
    /// with every address the host resolved to, all checked.
    pub async fn check(&self, uri: &Url) -> Result<Option<Vec<SocketAddr>>, UriRefusal> {
        let _ = uri;
        Ok(None)
    }
}

/// Why a delivery did not succeed.
#[derive(Debug)]
pub enum DeliveryError {
    /// The URI is refused; nothing was sent.
    Refused(UriRefusal),
    /// The RP did not answer 200 or 204.
    Failed(String),
}

/// POST `logout_token` to `uri`.
pub async fn deliver(guard: &UriGuard, uri: &Url, token: &str) -> Result<(), DeliveryError> {
    let _ = (guard, uri, token);
    Ok(())
}

/// The retry schedule.
#[derive(Clone, Debug)]
pub struct OutboxPolicy {
    pub max_attempts: u32,
    pub backoff_base: Duration,
    pub lease: Duration,
    pub poll: Duration,
    pub batch: usize,
}

impl Default for OutboxPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            backoff_base: Duration::from_secs(2),
            lease: Duration::from_secs(30),
            poll: Duration::from_secs(1),
            batch: 16,
        }
    }
}

/// The outbox worker.
pub struct Worker {
    pub redis: RedisClient,
    pub signing_key: Arc<EcdsaSigningKey>,
    pub issuer: String,
    pub guard: UriGuard,
    pub policy: OutboxPolicy,
}

impl Worker {
    /// Claim and handle due entries once; returns how many were claimed.
    pub async fn tick(&self) -> usize {
        let _ = self.handle(None).await;
        0
    }

    async fn handle(&self, claimed: Option<ClaimedEntry>) {
        let _ = claimed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use siwx_oidc::db::grant::{GrantKind, NewGrant};
    use siwx_oidc::db::{ClientEntry, DBClient, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Mutex;

    fn entry(sid: &str) -> LogoutEntry {
        LogoutEntry {
            client_id: "rp-1".into(),
            sub: "did:key:z6MkCaseMatters".into(),
            sid: sid.into(),
            grant: "0123456789abcdef".into(),
            attempt: 0,
        }
    }

    fn decode(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
    }

    /// Verify a compact JWS with `key` over the received bytes; returns
    /// header and claims.
    fn verified(token: &str, key: &VerifyingKey) -> (serde_json::Value, serde_json::Value) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS: {token:?}");
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig.len(), 64, "ES256 is raw r||s, never DER");
        let sig = Signature::from_slice(&sig).unwrap();
        key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("the signature verifies over the received bytes");
        (decode(parts[0]), decode(parts[1]))
    }

    fn verifying_key(key: &EcdsaSigningKey) -> VerifyingKey {
        use openidconnect::PrivateSigningKey;
        let jwk = serde_json::to_value(key.as_verification_key()).unwrap();
        let coord = |c: &str| URL_SAFE_NO_PAD.decode(jwk[c].as_str().unwrap()).unwrap();
        let mut sec1 = vec![4u8];
        sec1.extend(coord("x"));
        sec1.extend(coord("y"));
        VerifyingKey::from_sec1_bytes(&sec1).unwrap()
    }

    #[test]
    fn the_logout_token_has_the_spec_header_claims_and_a_raw_signature() {
        let key = EcdsaSigningKey::generate();
        let token = mint_logout_token(&key, "https://op.example.org/", &entry("sid-1"), 1_000);
        let (header, claims) = verified(&token, &verifying_key(&key));
        assert_eq!(
            header,
            serde_json::json!({"alg": "ES256", "typ": "logout+jwt", "kid": key.kid()})
        );
        let mut keys: Vec<&str> = claims
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"],
            "exactly the spec claims, never a nonce: {claims}"
        );
        assert_eq!(claims["iss"], "https://op.example.org/");
        assert_eq!(claims["aud"], "rp-1");
        assert_eq!(
            claims["sub"], "did:key:z6MkCaseMatters",
            "the DID keeps its case"
        );
        assert_eq!(claims["sid"], "sid-1");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_000 + LOGOUT_TOKEN_LIFETIME_SECS);
        assert_eq!(
            claims["events"],
            serde_json::json!({ BACKCHANNEL_LOGOUT_EVENT: {} })
        );
        let jti = claims["jti"].as_str().unwrap();
        assert!(jti.len() >= 22, "a random jti: {jti}");
        let other = mint_logout_token(&key, "https://op.example.org/", &entry("sid-1"), 1_000);
        let (_, other) = verified(&other, &verifying_key(&key));
        assert_ne!(other["jti"], claims["jti"], "every token has its own jti");

        let (_, no_sid) = verified(
            &mint_logout_token(&key, "https://op.example.org/", &entry(""), 1_000),
            &verifying_key(&key),
        );
        assert!(
            no_sid.get("sid").is_none(),
            "no sid is omitted, never empty: {no_sid}"
        );
    }

    #[test]
    fn the_address_classifier_refuses_every_internal_class() {
        use AddressClass::*;
        let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
        let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
        let table = [
            (v4("0.0.0.0"), Some(Unspecified)),
            (v4("0.1.2.3"), Some(Unspecified)),
            (v4("127.0.0.1"), Some(Loopback)),
            (v4("127.255.255.254"), Some(Loopback)),
            (v4("10.0.0.1"), Some(Private)),
            (v4("172.16.0.1"), Some(Private)),
            (v4("172.31.255.255"), Some(Private)),
            (v4("172.32.0.1"), None),
            (v4("192.168.1.1"), Some(Private)),
            (v4("100.64.0.1"), Some(SharedCgnat)),
            (v4("100.127.255.255"), Some(SharedCgnat)),
            (v4("100.128.0.1"), None),
            (v4("169.254.169.254"), Some(LinkLocal)),
            (v4("169.254.0.1"), Some(LinkLocal)),
            (v4("224.0.0.1"), Some(Multicast)),
            (v4("239.255.255.250"), Some(Multicast)),
            (v4("240.0.0.1"), Some(Reserved)),
            (v4("255.255.255.255"), Some(Reserved)),
            (v4("192.0.2.10"), None),
            (v4("198.51.100.7"), None),
            (v4("203.0.113.200"), None),
            (v6("::"), Some(Unspecified)),
            (v6("::1"), Some(Loopback)),
            (v6("fe80::1"), Some(LinkLocal)),
            (v6("febf::1"), Some(LinkLocal)),
            (v6("fc00::1"), Some(Private)),
            (v6("fd12:3456::1"), Some(Private)),
            (v6("ff02::1"), Some(Multicast)),
            (v6("::ffff:127.0.0.1"), Some(Loopback)),
            (v6("::ffff:169.254.169.254"), Some(LinkLocal)),
            (v6("::ffff:10.1.2.3"), Some(Private)),
            (v6("::ffff:100.64.0.1"), Some(SharedCgnat)),
            (v6("::ffff:192.0.2.10"), None),
            (v6("64:ff9b::a9fe:a9fe"), Some(LinkLocal)),
            (v6("64:ff9b::c000:20a"), None),
            (v6("2001:db8::1"), None),
        ];
        for (ip, expected) in table {
            assert_eq!(refused_class(ip), expected, "{ip}");
        }
    }

    #[tokio::test]
    async fn the_uri_guard_checks_scheme_fragment_and_every_resolved_address() {
        let open = UriGuard::default();
        let listed = UriGuard::new(&["LocalHost".to_string(), "127.0.0.1".to_string()]);
        let url = |s: &str| Url::parse(s).unwrap();
        let ok = open.check(&url("https://192.0.2.10/bcl")).await;
        assert_eq!(ok, Ok(Some(vec!["192.0.2.10:443".parse().unwrap()])));
        let ok6 = open.check(&url("https://[2001:db8::5]:8443/bcl?x=1")).await;
        assert_eq!(ok6, Ok(Some(vec!["[2001:db8::5]:8443".parse().unwrap()])));
        for (uri, refusal) in [
            ("http://192.0.2.10/bcl", UriRefusal::NotHttps),
            ("https://192.0.2.10/bcl#frag", UriRefusal::Fragment),
            (
                "https://127.0.0.1/bcl",
                UriRefusal::Address(AddressClass::Loopback),
            ),
            (
                "https://[::1]/bcl",
                UriRefusal::Address(AddressClass::Loopback),
            ),
            (
                "https://169.254.169.254/latest",
                UriRefusal::Address(AddressClass::LinkLocal),
            ),
            (
                "https://[::ffff:10.0.0.1]/",
                UriRefusal::Address(AddressClass::Private),
            ),
            (
                "https://100.100.100.100/",
                UriRefusal::Address(AddressClass::SharedCgnat),
            ),
            (
                "https://localhost/bcl",
                UriRefusal::Address(AddressClass::Loopback),
            ),
            ("mailto:rp@example.org", UriRefusal::NotHttps),
        ] {
            assert_eq!(open.check(&url(uri)).await, Err(refusal), "{uri}");
        }
        assert_eq!(listed.check(&url("http://localhost:9/bcl")).await, Ok(None));
        assert_eq!(listed.check(&url("https://127.0.0.1/bcl")).await, Ok(None));
        assert_eq!(
            listed.check(&url("http://localhost:9/bcl#f")).await,
            Err(UriRefusal::Fragment),
            "the allowlist bypasses the address check, never the fragment rule"
        );
        assert_eq!(
            listed.check(&url("https://[::1]/bcl")).await,
            Err(UriRefusal::Address(AddressClass::Loopback)),
            "only a listed host is exempt"
        );
    }

    /// A stub relying party on loopback: records every POST body and its
    /// content type, answers with the status set in `status` (303 with a
    /// `Location` pointing at `/elsewhere`, which records into `elsewhere`).
    #[derive(Clone, Default)]
    struct Stub {
        hits: Arc<Mutex<Vec<(String, String)>>>,
        elsewhere: Arc<Mutex<usize>>,
        status: Arc<AtomicU16>,
    }

    impl Stub {
        fn hits(&self) -> Vec<(String, String)> {
            self.hits.lock().unwrap().clone()
        }
    }

    async fn stub_rp() -> (Stub, SocketAddr) {
        async fn bcl(
            State(s): State<Stub>,
            headers: HeaderMap,
            body: String,
        ) -> (StatusCode, HeaderMap) {
            let ct = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            s.hits.lock().unwrap().push((ct, body));
            let status = StatusCode::from_u16(s.status.load(Ordering::SeqCst)).unwrap();
            let mut out = HeaderMap::new();
            if status.is_redirection() {
                out.insert(header::LOCATION, "/elsewhere".parse().unwrap());
            }
            (status, out)
        }
        async fn elsewhere(State(s): State<Stub>) -> StatusCode {
            *s.elsewhere.lock().unwrap() += 1;
            StatusCode::OK
        }
        let stub = Stub::default();
        stub.status.store(200, Ordering::SeqCst);
        let app = Router::new()
            .route("/bcl", post(bcl))
            .route("/elsewhere", post(elsewhere).get(elsewhere))
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (stub, addr)
    }

    #[tokio::test]
    async fn delivery_connects_only_to_a_checked_or_listed_host_and_follows_no_redirect() {
        let (stub, addr) = stub_rp().await;
        let http = Url::parse(&format!("http://127.0.0.1:{}/bcl", addr.port())).unwrap();
        let https = Url::parse(&format!("https://127.0.0.1:{}/bcl", addr.port())).unwrap();
        let open = UriGuard::default();
        for uri in [&http, &https] {
            match deliver(&open, uri, "t").await {
                Err(DeliveryError::Refused(_)) => {}
                other => panic!("a loopback URI must be refused, got {other:?}"),
            }
        }
        assert!(
            stub.hits().is_empty(),
            "a refused URI is never connected to"
        );

        let listed = UriGuard::new(&["127.0.0.1".to_string()]);
        deliver(&listed, &http, "a.b.c")
            .await
            .expect("a listed host is delivered to");
        let hits = stub.hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "application/x-www-form-urlencoded");
        assert_eq!(hits[0].1, "logout_token=a.b.c");

        stub.status.store(204, Ordering::SeqCst);
        deliver(&listed, &http, "t")
            .await
            .expect("204 is success too");
        stub.status.store(303, Ordering::SeqCst);
        match deliver(&listed, &http, "t").await {
            Err(DeliveryError::Failed(_)) => {}
            other => panic!("a redirect is a failure, got {other:?}"),
        }
        stub.status.store(500, Ordering::SeqCst);
        assert!(matches!(
            deliver(&listed, &http, "t").await,
            Err(DeliveryError::Failed(_))
        ));
        assert_eq!(
            *stub.elsewhere.lock().unwrap(),
            0,
            "a redirect is never followed"
        );
    }

    async fn register_rp(db: &RedisClient, client_id: &str, uri: &str) {
        let metadata: siwx_oidc::db::SiwxClientMetadata =
            serde_json::from_value(serde_json::json!({
                "redirect_uris": ["https://rp.example.org/cb"],
                "backchannel_logout_uri": uri,
            }))
            .unwrap();
        db.set_client(client_id.to_string(), ClientEntry::new("s", metadata, None))
            .await
            .unwrap();
    }

    async fn end_oidc_grant(db: &RedisClient, client_id: &str) -> Option<String> {
        let user = format!("u{}", siwx_oidc::db::tokens::new_session_id());
        let g = db
            .issue_grant(&NewGrant {
                kind: GrantKind::Oidc,
                username: user.clone(),
                did: format!("did:key:z6Mk{user}"),
                client_id: client_id.to_string(),
                confidential_client: false,
                device_id: String::new(),
                scope: "openid offline_access".into(),
                name: "n".into(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
            })
            .await
            .unwrap();
        db.revoke_grants_for_user(&user).await.unwrap();
        g.sid
    }

    /// In-process H7: the worker sends a logout token the RP can verify with
    /// our key, naming the ended grant's `sid`; a failing RP is retried
    /// `max_attempts` times in all and then dropped with a warning that names
    /// fingerprints only; an RP without a URI is never contacted.
    #[tokio::test]
    async fn the_worker_delivers_retries_a_failing_rp_then_drops_it_with_a_warning() {
        let Some(db) = siwx_oidc::test_support::redis_db(10).await else {
            return;
        };
        let mut url = siwx_oidc::test_support::redis_url();
        url.set_path("/10");
        let raw = bb8_redis::redis::Client::open(url.as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: i64 = bb8_redis::redis::cmd("DEL")
            .arg(siwx_oidc::db::outbox::KV_BACKCHANNEL_OUTBOX)
            .query_async(&mut conn)
            .await
            .unwrap();
        let (stub, addr) = stub_rp().await;
        let uri = format!("http://127.0.0.1:{}/bcl", addr.port());
        register_rp(&db, "rp-ok", &uri).await;
        let key = Arc::new(EcdsaSigningKey::generate());
        let worker = Worker {
            redis: db.clone(),
            signing_key: key.clone(),
            issuer: "https://op.example.org/".into(),
            guard: UriGuard::new(&["127.0.0.1".to_string()]),
            policy: OutboxPolicy {
                max_attempts: 3,
                backoff_base: Duration::from_millis(20),
                lease: Duration::from_secs(30),
                poll: Duration::from_millis(10),
                batch: 8,
            },
        };

        let sid = end_oidc_grant(&db, "rp-ok").await.expect("a sid");
        assert_eq!(worker.tick().await, 1, "the queued entry is claimed");
        let hits = stub.hits();
        assert_eq!(hits.len(), 1, "one logout token delivered");
        let token = hits[0]
            .1
            .strip_prefix("logout_token=")
            .expect("a form body");
        let (header, claims) = verified(token, &verifying_key(&key));
        assert_eq!(header["typ"], "logout+jwt");
        assert_eq!(claims["aud"], "rp-ok");
        assert_eq!(claims["sid"], sid.as_str());
        assert!(
            db.pending_logout_entries().await.unwrap().is_empty(),
            "delivered = removed"
        );

        // A failing RP: three attempts in all, then the entry is dropped.
        stub.status.store(500, Ordering::SeqCst);
        let log = siwx_oidc::test_support::LogCapture::start();
        end_oidc_grant(&db, "rp-ok").await;
        for _ in 0..100 {
            worker.tick().await;
            if db.pending_logout_entries().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            db.pending_logout_entries().await.unwrap().is_empty(),
            "dropped at last"
        );
        assert_eq!(stub.hits().len(), 1 + 3, "exactly max_attempts attempts");
        let out = log.output();
        assert!(
            out.contains("back-channel logout dropped") && out.contains("WARN"),
            "the drop is a warning: {out}"
        );
        assert!(
            !out.contains(&uri) && !out.contains("logout_token="),
            "no URI, no token: {out}"
        );

        // An RP that registered no URI is never contacted; its entry goes.
        db.set_client(
            "rp-none".into(),
            ClientEntry::new(
                "s",
                serde_json::from_value(
                    serde_json::json!({"redirect_uris": ["https://rp.example.org/cb"]}),
                )
                .unwrap(),
                None,
            ),
        )
        .await
        .unwrap();
        end_oidc_grant(&db, "rp-none").await;
        assert_eq!(worker.tick().await, 1);
        assert_eq!(stub.hits().len(), 4, "no URI, no delivery");
        assert!(db.pending_logout_entries().await.unwrap().is_empty());
    }
}
