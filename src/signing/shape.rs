//! What a message may look like, per purpose, before `siwx-signer` signs it.
//!
//! The signer signs only JWS signing inputs (`BASE64URL(header).BASE64URL(payload)`,
//! unpadded) whose header and payload are JSON objects, and only in the shapes
//! siwx-oidc emits:
//!
//! | Purpose | Header | Payload |
//! |---|---|---|
//! | `id_token` | `alg` ES256, `kid` the signer's, `typ` absent or `JWT` | `iss`, `sub`, `aud`, `iat` and `exp` bounded; no `events`, no `mxid` |
//! | `userinfo` | as `id_token` | `iss`, `sub`, `aud`; none of `exp`, `iat`, `nonce`, `at_hash`, `c_hash`, `auth_time`, `sid`, `mxid`, `events` |
//! | `logout_token` | as `id_token`, `typ` `logout+jwt` | `iss`, `sub`, `aud`, `jti`, the back-channel `events` member, `iat` and `exp` bounded; no `nonce`, no `mxid` |
//! | `did_proof` | as `id_token`, `typ` `JWT` | exactly `iss`, `sub` (a DID), `mxid`, `iat` bounded; no `exp` |
//!
//! "Bounded": `iat` within the clock skew of the signer's clock, and `exp`
//! after `iat` by at most the maximum token lifetime. `iss` is the issuer the
//! signer was started with. A header holds no member beyond `alg`, `kid` and
//! `typ`, so no `crit`, `jku` or `x5u` can be smuggled in. No object in the
//! header or the payload names a member twice: a verifier that keeps the first
//! of two `iss` would read another token than the one checked here.
//!
//! The purposes do not overlap: no message passes the check of two of them.
//! A userinfo response carries no time and none of the members that make an
//! ID token (its lifetime, `nonce`, the hashes, `sid`) or a DID proof (`mxid`,
//! `iat`), so a userinfo signature is never an ID token without an end and
//! never a DID binding; an ID token and a logout token carry no `mxid`, which
//! the DID verifier requires. Honest userinfo names the Matrix ID
//! `io.inblock.mxid`, never `mxid`.
//!
//! These checks narrow what a compromised siwx-oidc can get signed (no foreign
//! issuer, no unbounded lifetime, no other key's `kid`, no non-JWS bytes, no
//! signature for one purpose that serves another). They do not stop it from
//! getting a well-formed token for any subject signed: that residual is the
//! reason the key can be rotated.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::Purpose;

/// The `events` member a back-channel logout token carries (OpenID Connect
/// Back-Channel Logout 1.0, §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The bounds a message is checked against.
#[derive(Clone, Debug)]
pub struct ShapePolicy {
    /// The signer's own `kid`.
    pub kid: String,
    /// The issuer, exactly as siwx-oidc writes `iss` (its `base_url`, parsed
    /// as a URL, so `https://example.org` reads `https://example.org/`).
    pub issuer: String,
    /// The longest `exp - iat`, in seconds.
    pub max_token_lifetime_secs: i64,
    /// How far `iat` may be from the signer's clock, in seconds, either way.
    pub max_clock_skew_secs: i64,
}

/// Why a message was refused. Logged by the signer as a fixed reason; never
/// carries a byte of the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeError {
    /// Not two unpadded base64url segments of JSON objects.
    NotJws,
    /// An object in the header or the payload names a member twice.
    Duplicate,
    /// A header member other than `alg`, `kid`, `typ`.
    HeaderMember,
    /// `alg` is not `ES256`.
    Alg,
    /// `kid` is not the signer's.
    Kid,
    /// `typ` is not the purpose's.
    Typ,
    /// `iss` is not the configured issuer.
    Iss,
    /// A claim the purpose requires is missing or of the wrong type.
    Claim,
    /// A claim the purpose forbids is present.
    Forbidden,
    /// `iat` is too far from the signer's clock.
    Iat,
    /// `exp` is missing where required, not after `iat`, or too far after it.
    Exp,
}

impl ShapeError {
    /// The fixed reason the signer logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ShapeError::NotJws => "not_jws",
            ShapeError::Duplicate => "duplicate_member",
            ShapeError::HeaderMember => "header_member",
            ShapeError::Alg => "alg",
            ShapeError::Kid => "kid",
            ShapeError::Typ => "typ",
            ShapeError::Iss => "iss",
            ShapeError::Claim => "claim",
            ShapeError::Forbidden => "forbidden",
            ShapeError::Iat => "iat",
            ShapeError::Exp => "exp",
        }
    }
}

/// What a userinfo payload never carries: siwx-oidc's userinfo has no time and
/// none of an ID token's session members, and names the Matrix ID
/// `io.inblock.mxid`. Each of them would let a userinfo signature serve as an
/// ID token (one without an end) or as a DID proof.
const USERINFO_FORBIDS: &[&str] = &[
    "exp",
    "iat",
    "nonce",
    "at_hash",
    "c_hash",
    "auth_time",
    "sid",
    "mxid",
    "events",
];

/// Check `msg` against the shape `purpose` allows, at `now` (Unix seconds).
pub fn check(
    policy: &ShapePolicy,
    purpose: Purpose,
    msg: &[u8],
    now: i64,
) -> Result<(), ShapeError> {
    let (header, payload) = split(msg)?;

    if header
        .keys()
        .any(|k| !matches!(k.as_str(), "alg" | "kid" | "typ"))
    {
        return Err(ShapeError::HeaderMember);
    }
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(ShapeError::Alg);
    }
    if header.get("kid").and_then(Value::as_str) != Some(policy.kid.as_str()) {
        return Err(ShapeError::Kid);
    }
    let typ = header.get("typ");
    let typ_ok = match purpose {
        Purpose::IdToken | Purpose::Userinfo => {
            typ.is_none() || typ.and_then(Value::as_str) == Some("JWT")
        }
        Purpose::LogoutToken => typ.and_then(Value::as_str) == Some("logout+jwt"),
        Purpose::DidProof => typ.and_then(Value::as_str) == Some("JWT"),
    };
    if !typ_ok {
        return Err(ShapeError::Typ);
    }

    if payload.get("iss").and_then(Value::as_str) != Some(policy.issuer.as_str()) {
        return Err(ShapeError::Iss);
    }
    if payload
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ShapeError::Claim);
    }

    match purpose {
        Purpose::IdToken => {
            require_audience(&payload)?;
            forbid(&payload, &["events", "mxid"])?;
            check_times(policy, &payload, now)
        }
        Purpose::Userinfo => {
            require_audience(&payload)?;
            forbid(&payload, USERINFO_FORBIDS)
        }
        Purpose::LogoutToken => {
            require_audience(&payload)?;
            forbid(&payload, &["nonce", "mxid"])?;
            if !payload.get("jti").is_some_and(Value::is_string) {
                return Err(ShapeError::Claim);
            }
            let events = payload
                .get("events")
                .and_then(Value::as_object)
                .ok_or(ShapeError::Claim)?;
            if !events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
                return Err(ShapeError::Claim);
            }
            check_times(policy, &payload, now)
        }
        Purpose::DidProof => {
            if payload
                .keys()
                .any(|k| !matches!(k.as_str(), "iss" | "sub" | "mxid" | "iat"))
            {
                return Err(ShapeError::Forbidden);
            }
            let did = payload
                .get("sub")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !did.starts_with("did:") {
                return Err(ShapeError::Claim);
            }
            if !payload
                .get("mxid")
                .and_then(Value::as_str)
                .is_some_and(|m| m.starts_with('@') && m.contains(':'))
            {
                return Err(ShapeError::Claim);
            }
            let iat = payload
                .get("iat")
                .and_then(Value::as_i64)
                .ok_or(ShapeError::Iat)?;
            check_iat(policy, iat, now)
        }
    }
}

/// Split and decode `BASE64URL(header).BASE64URL(payload)`.
/// A decoded JWS segment.
type Object = Map<String, Value>;

fn split(msg: &[u8]) -> Result<(Object, Object), ShapeError> {
    let text = std::str::from_utf8(msg).map_err(|_| ShapeError::NotJws)?;
    let mut parts = text.split('.');
    let (Some(header), Some(payload), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ShapeError::NotJws);
    };
    Ok((object(header)?, object(payload)?))
}

fn object(segment: &str) -> Result<Object, ShapeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ShapeError::NotJws)?;
    match serde_json::from_slice::<Strict>(&bytes) {
        Ok(Strict(Value::Object(map))) => Ok(map),
        Ok(_) => Err(ShapeError::NotJws),
        Err(e) if e.to_string().starts_with(DUPLICATE_MEMBER) => Err(ShapeError::Duplicate),
        Err(_) => Err(ShapeError::NotJws),
    }
}

/// The error text [`Strict`] fails with on a member named twice.
const DUPLICATE_MEMBER: &str = "duplicate member";

/// A JSON value read with every object checked for a member named twice, at
/// any depth. `serde_json::Value` keeps the last of two, so a check over it
/// would judge a token by a value another reader may never see. Names are
/// compared after unescaping (`"i\u0073s"` is `iss`).
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(de::Error::custom(DUPLICATE_MEMBER));
            }
            let Strict(value) = map.next_value()?;
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}

fn require_audience(payload: &Map<String, Value>) -> Result<(), ShapeError> {
    let ok = match payload.get("aud") {
        Some(Value::String(aud)) => !aud.is_empty(),
        Some(Value::Array(auds)) => {
            !auds.is_empty()
                && auds
                    .iter()
                    .all(|a| a.as_str().is_some_and(|a| !a.is_empty()))
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ShapeError::Claim)
    }
}

fn forbid(payload: &Map<String, Value>, names: &[&str]) -> Result<(), ShapeError> {
    if names.iter().any(|n| payload.contains_key(*n)) {
        Err(ShapeError::Forbidden)
    } else {
        Ok(())
    }
}

fn check_iat(policy: &ShapePolicy, iat: i64, now: i64) -> Result<(), ShapeError> {
    if iat.abs_diff(now) > policy.max_clock_skew_secs.unsigned_abs() {
        Err(ShapeError::Iat)
    } else {
        Ok(())
    }
}

/// `iat` and `exp`, both required: `iat` within the clock skew, `exp` after
/// `iat` by at most the maximum token lifetime.
fn check_times(
    policy: &ShapePolicy,
    payload: &Map<String, Value>,
    now: i64,
) -> Result<(), ShapeError> {
    let iat = payload
        .get("iat")
        .ok_or(ShapeError::Iat)?
        .as_i64()
        .ok_or(ShapeError::Iat)?;
    check_iat(policy, iat, now)?;
    let exp = payload
        .get("exp")
        .ok_or(ShapeError::Exp)?
        .as_i64()
        .ok_or(ShapeError::Exp)?;
    if exp <= iat || exp - iat > policy.max_token_lifetime_secs {
        return Err(ShapeError::Exp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn policy() -> ShapePolicy {
        ShapePolicy {
            kid: "0123456789abcdef".to_string(),
            issuer: "https://example.org/".to_string(),
            max_token_lifetime_secs: 3600,
            max_clock_skew_secs: 300,
        }
    }

    fn jws(header: Value, payload: Value) -> Vec<u8> {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        )
        .into_bytes()
    }

    fn id_token() -> (Value, Value) {
        (
            json!({"alg": "ES256", "kid": "0123456789abcdef"}),
            json!({"iss": "https://example.org/", "aud": ["client"], "exp": NOW + 300,
                   "iat": NOW, "sub": "did:key:zExample", "nonce": "n"}),
        )
    }

    fn logout_token() -> (Value, Value) {
        (
            json!({"alg": "ES256", "typ": "logout+jwt", "kid": "0123456789abcdef"}),
            json!({"iss": "https://example.org/", "aud": "client", "iat": NOW, "exp": NOW + 120,
                   "jti": "j", "sub": "did:key:zExample", "sid": "s",
                   "events": {BACKCHANNEL_LOGOUT_EVENT: {}}}),
        )
    }

    fn did_proof() -> (Value, Value) {
        (
            json!({"alg": "ES256", "typ": "JWT", "kid": "0123456789abcdef"}),
            json!({"iss": "https://example.org/", "sub": "did:key:zExample",
                   "mxid": "@u:example.org", "iat": NOW}),
        )
    }

    fn userinfo() -> (Value, Value) {
        (
            json!({"alg": "ES256", "kid": "0123456789abcdef"}),
            json!({"iss": "https://example.org/", "aud": ["client"], "sub": "did:key:zExample"}),
        )
    }

    fn base(purpose: Purpose) -> (Value, Value) {
        match purpose {
            Purpose::IdToken => id_token(),
            Purpose::Userinfo => userinfo(),
            Purpose::LogoutToken => logout_token(),
            Purpose::DidProof => did_proof(),
        }
    }

    fn verdict(purpose: Purpose, header: &Value, payload: &Value) -> Result<(), ShapeError> {
        check(
            &policy(),
            purpose,
            &jws(header.clone(), payload.clone()),
            NOW,
        )
    }

    #[test]
    fn the_shapes_siwx_oidc_emits_pass() {
        for purpose in Purpose::ALL {
            let (h, p) = base(purpose);
            assert_eq!(verdict(purpose, &h, &p), Ok(()), "{purpose}");
        }
    }

    #[test]
    fn a_foreign_alg_kid_or_issuer_is_refused_for_every_purpose() {
        for purpose in Purpose::ALL {
            let (h, p) = base(purpose);
            let mut bad = h.clone();
            bad["alg"] = json!("HS256");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::Alg),
                "{purpose}"
            );
            let mut bad = h.clone();
            bad["alg"] = json!("none");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::Alg),
                "{purpose}"
            );
            let mut bad = h.clone();
            bad["kid"] = json!("fedcba9876543210");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::Kid),
                "{purpose}"
            );
            let mut bad = h.clone();
            bad.as_object_mut().unwrap().remove("kid");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::Kid),
                "{purpose}"
            );
            let mut bad = h.clone();
            bad["jku"] = json!("https://attacker.example/jwks");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::HeaderMember),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["iss"] = json!("https://attacker.example/");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Iss),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["iss"] = json!("https://example.org");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Iss),
                "{purpose}: the issuer is compared exactly"
            );
            let mut bad = p.clone();
            bad.as_object_mut().unwrap().remove("sub");
            assert!(verdict(purpose, &h, &bad).is_err(), "{purpose}: no sub");
        }
    }

    #[test]
    fn an_unbounded_or_stale_lifetime_is_refused() {
        for purpose in [Purpose::IdToken, Purpose::LogoutToken] {
            let (h, p) = base(purpose);
            let mut bad = p.clone();
            bad["exp"] = json!(NOW + 3601);
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Exp),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["exp"] = json!(NOW);
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Exp),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad.as_object_mut().unwrap().remove("exp");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Exp),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["exp"] = json!("tomorrow");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Exp),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad.as_object_mut().unwrap().remove("iat");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Iat),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["iat"] = json!(NOW - 301);
            bad["exp"] = json!(NOW - 1);
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Iat),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad["iat"] = json!(NOW + 301);
            bad["exp"] = json!(NOW + 400);
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Iat),
                "{purpose}"
            );
        }
        // Userinfo carries no times at all: neither a bounded nor an endless one.
        let (h, p) = userinfo();
        for (name, value) in [
            ("exp", json!(NOW + 10 * 365 * 86_400)),
            ("exp", json!(NOW + 60)),
            ("iat", json!(NOW)),
        ] {
            let mut bad = p.clone();
            bad[name] = value;
            assert_eq!(
                verdict(Purpose::Userinfo, &h, &bad),
                Err(ShapeError::Forbidden),
                "{name}"
            );
        }
        // A DID proof is permanent: it never carries `exp`, and its `iat` is now.
        let (h, p) = did_proof();
        let mut bad = p.clone();
        bad["exp"] = json!(NOW + 60);
        assert_eq!(
            verdict(Purpose::DidProof, &h, &bad),
            Err(ShapeError::Forbidden)
        );
        let mut bad = p.clone();
        bad["iat"] = json!(NOW - 3600);
        assert_eq!(verdict(Purpose::DidProof, &h, &bad), Err(ShapeError::Iat));
    }

    #[test]
    fn each_purpose_keeps_its_own_typ_and_members() {
        // A logout token is explicitly typed, and an ID token or userinfo is not
        // one: no `events`, so neither can be replayed as a logout token.
        let (h, p) = logout_token();
        let mut bad = h.clone();
        bad.as_object_mut().unwrap().remove("typ");
        assert_eq!(
            verdict(Purpose::LogoutToken, &bad, &p),
            Err(ShapeError::Typ)
        );
        let mut bad = p.clone();
        bad["nonce"] = json!("n");
        assert_eq!(
            verdict(Purpose::LogoutToken, &h, &bad),
            Err(ShapeError::Forbidden)
        );
        let mut bad = p.clone();
        bad["events"] = json!({"http://example.org/other": {}});
        assert_eq!(
            verdict(Purpose::LogoutToken, &h, &bad),
            Err(ShapeError::Claim)
        );
        let mut bad = p.clone();
        bad.as_object_mut().unwrap().remove("jti");
        assert_eq!(
            verdict(Purpose::LogoutToken, &h, &bad),
            Err(ShapeError::Claim)
        );
        assert_eq!(verdict(Purpose::IdToken, &h, &p), Err(ShapeError::Typ));

        for purpose in [Purpose::IdToken, Purpose::Userinfo] {
            let (h, p) = base(purpose);
            let mut bad = p.clone();
            bad["events"] = json!({BACKCHANNEL_LOGOUT_EVENT: {}});
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Forbidden),
                "{purpose}"
            );
            let mut bad = h.clone();
            bad["typ"] = json!("logout+jwt");
            assert_eq!(
                verdict(purpose, &bad, &p),
                Err(ShapeError::Typ),
                "{purpose}"
            );
            let mut bad = p.clone();
            bad.as_object_mut().unwrap().remove("aud");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Claim),
                "{purpose}"
            );
            let mut ok = h.clone();
            ok["typ"] = json!("JWT");
            assert_eq!(verdict(purpose, &ok, &p), Ok(()), "{purpose}");
        }

        let (h, p) = did_proof();
        let mut bad = h.clone();
        bad.as_object_mut().unwrap().remove("typ");
        assert_eq!(verdict(Purpose::DidProof, &bad, &p), Err(ShapeError::Typ));
        let mut bad = p.clone();
        bad["aud"] = json!("client");
        assert_eq!(
            verdict(Purpose::DidProof, &h, &bad),
            Err(ShapeError::Forbidden)
        );
        let mut bad = p.clone();
        bad["sub"] = json!("not-a-did");
        assert_eq!(verdict(Purpose::DidProof, &h, &bad), Err(ShapeError::Claim));
        let mut bad = p.clone();
        bad["mxid"] = json!("u");
        assert_eq!(verdict(Purpose::DidProof, &h, &bad), Err(ShapeError::Claim));
    }

    /// No message passes two purposes: the emission of each purpose, under the
    /// header of every other one, is refused. A signature asked for one purpose
    /// therefore never serves as another (a userinfo response as an ID token or
    /// a DID proof, an ID token as a DID proof).
    #[test]
    fn no_purpose_signs_what_another_purpose_emits() {
        for emitted in Purpose::ALL {
            let (_, payload) = base(emitted);
            for asked in Purpose::ALL.into_iter().filter(|p| *p != emitted) {
                let (header, _) = base(asked);
                assert_ne!(
                    verdict(asked, &header, &payload),
                    Ok(()),
                    "a {emitted} payload signed as {asked}"
                );
            }
        }
        // The members that tell them apart, one at a time on an honest payload.
        let (h, p) = userinfo();
        for name in USERINFO_FORBIDS {
            let mut bad = p.clone();
            bad[*name] = json!("x");
            assert_eq!(
                verdict(Purpose::Userinfo, &h, &bad),
                Err(ShapeError::Forbidden),
                "userinfo with {name}"
            );
        }
        let mut ok = p.clone();
        ok["io.inblock.mxid"] = json!("@u:example.org");
        assert_eq!(
            verdict(Purpose::Userinfo, &h, &ok),
            Ok(()),
            "honest userinfo names the Matrix ID io.inblock.mxid"
        );
        for purpose in [Purpose::IdToken, Purpose::LogoutToken] {
            let (h, p) = base(purpose);
            let mut bad = p.clone();
            bad["mxid"] = json!("@u:example.org");
            assert_eq!(
                verdict(purpose, &h, &bad),
                Err(ShapeError::Forbidden),
                "{purpose} with mxid"
            );
        }
    }

    /// A member named twice is refused at any depth and however its name is
    /// escaped, in the header and in the payload.
    #[test]
    fn a_member_named_twice_is_refused_nested_and_escaped() {
        let header = r#"{"alg":"ES256","kid":"0123456789abcdef","typ":"logout+jwt"}"#;
        let payload = format!(
            r#"{{"iss":"https://example.org/","aud":"client","iat":{NOW},"exp":{},"jti":"j","sub":"did:key:zExample","events":{{"{BACKCHANNEL_LOGOUT_EVENT}":{{}},"{BACKCHANNEL_LOGOUT_EVENT}":{{}}}}}}"#,
            NOW + 120
        );
        assert_eq!(
            check(
                &policy(),
                Purpose::LogoutToken,
                &raw_jws(header, &payload),
                NOW
            ),
            Err(ShapeError::Duplicate)
        );
        let payload = format!(
            r#"{{"iss":"https://example.org/","aud":["client"],"sub":"did:key:zExample","iat":{NOW},"exp":{},"i\u0073s":"https://example.org/"}}"#,
            NOW + 300
        );
        assert_eq!(
            check(
                &policy(),
                Purpose::IdToken,
                &raw_jws(r#"{"alg":"ES256","kid":"0123456789abcdef"}"#, &payload),
                NOW
            ),
            Err(ShapeError::Duplicate)
        );
        let header = r#"{"alg":"ES256","kid":"0123456789abcdef","kid":"0123456789abcdef"}"#;
        let payload = r#"{"iss":"https://example.org/","aud":["client"],"sub":"did:key:zExample"}"#;
        assert_eq!(
            check(&policy(), Purpose::Userinfo, &raw_jws(header, payload), NOW),
            Err(ShapeError::Duplicate),
            "even a duplicate with the same value"
        );
    }

    #[test]
    fn anything_but_a_two_segment_jws_of_objects_is_refused() {
        let p = policy();
        for msg in [
            &b""[..],
            b"plain bytes",
            b"e30",
            b"e30.e30.e30",
            b"e30=.e30",
            b"W10.e30",
            b"\xff\xfe.e30",
        ] {
            assert_eq!(
                check(&p, Purpose::IdToken, msg, NOW),
                Err(ShapeError::NotJws),
                "{:?}",
                String::from_utf8_lossy(msg)
            );
        }
    }

    /// The raw JWS signing input of a header and payload given as JSON text,
    /// so a test can write what `serde_json::json!` cannot (duplicate members).
    fn raw_jws(header: &str, payload: &str) -> Vec<u8> {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        )
        .into_bytes()
    }

    /// AUDIT PR83 F4: a member named twice is judged by its LAST value (the
    /// `serde_json::Map` keeps the last), so a payload whose first `iss` is a
    /// foreign issuer and whose first `exp` is ten years out passes. A verifier
    /// that keeps the first value (or reads the text differently) sees a token
    /// the signer would never have signed. RFC 7515 section 5.2 and RFC 7519
    /// section 4 let a producer emit no duplicates; the signer should refuse them.
    #[test]
    fn audit_pr83_a_member_named_twice_is_refused() {
        let header = r#"{"alg":"ES256","kid":"0123456789abcdef"}"#;
        let payload = format!(
            r#"{{"iss":"https://attacker.example/","iss":"https://example.org/","aud":["client"],"sub":"did:key:zExample","iat":{NOW},"exp":{},"exp":{}}}"#,
            NOW + 10 * 365 * 86_400,
            NOW + 300
        );
        assert_ne!(
            check(&policy(), Purpose::IdToken, &raw_jws(header, &payload), NOW),
            Ok(()),
            "a duplicate iss / exp is refused, not judged by its last value"
        );
        let header = r#"{"alg":"none","alg":"ES256","kid":"0123456789abcdef"}"#;
        let payload = format!(
            r#"{{"iss":"https://example.org/","aud":["client"],"sub":"did:key:zExample","iat":{NOW},"exp":{}}}"#,
            NOW + 300
        );
        assert_ne!(
            check(&policy(), Purpose::IdToken, &raw_jws(header, &payload), NOW),
            Ok(()),
            "a duplicate alg is refused"
        );
    }

    /// AUDIT PR83 F3: the `userinfo` purpose is a superset of the others. It
    /// signs an ID token's payload with no `exp` and no `iat` (a token with no
    /// end), and it signs a DID proof's payload (plus an `aud`), which the
    /// shipped DID verifier (`siwx_oidc_auth::did_assertion`) accepts: it reads
    /// only `iss`, `sub`, `mxid`, `iat` and allows `typ` JWT. The per-purpose
    /// shapes therefore separate nothing, and the documented "no unbounded
    /// lifetime" does not hold for this purpose.
    #[test]
    fn audit_pr83_userinfo_signs_neither_an_endless_id_token_nor_a_did_proof() {
        let header = json!({"alg": "ES256", "kid": "0123456789abcdef"});
        let endless_id_token = json!({"iss": "https://example.org/", "aud": ["client"],
            "sub": "did:key:zExample", "nonce": "n", "auth_time": NOW});
        assert_ne!(
            check(
                &policy(),
                Purpose::Userinfo,
                &jws(header.clone(), endless_id_token),
                NOW
            ),
            Ok(()),
            "userinfo does not sign an ID token payload without exp"
        );
        let did_proof_header = json!({"alg": "ES256", "typ": "JWT", "kid": "0123456789abcdef"});
        let did_proof = json!({"iss": "https://example.org/", "aud": "x",
            "sub": "did:key:zExample", "mxid": "@victim:example.org", "iat": NOW});
        assert_ne!(
            check(
                &policy(),
                Purpose::Userinfo,
                &jws(did_proof_header, did_proof),
                NOW
            ),
            Ok(()),
            "userinfo does not sign a DID proof payload"
        );
    }
}
