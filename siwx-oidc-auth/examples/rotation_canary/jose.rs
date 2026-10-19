//! JOSE and JWKS logic: the hand-written ES256 verification of the ID token
//! against the `/jwk` entry for its `kid`, kid derivation, the exact-set JWKS
//! comparison, issuer normalization and the server-clock rules.
//!
//! No library verifier is used for the ID token: `siwx_oidc_auth` ships none
//! (its DID-assertion verifier is the only JWS check it has, and it fixes its
//! own claims). Everything here is pure and tested without a network.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::report::Reason;

/// Exactly one trailing slash is trimmed: the server's `IssuerUrl` renders its
/// base URL with one (`did_assertion.rs` `normalize_issuer` trims every slash,
/// which is the looser of the two; `--issuer` is held to the stricter rule).
pub fn normalize_issuer(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

pub fn issuers_match(a: &str, b: &str) -> bool {
    normalize_issuer(a) == normalize_issuer(b)
}

/// The `kid` of a P-256 key: the first 16 hex characters of the SHA-256 of the
/// 65-byte uncompressed point (`04 || x || y`). This is `fingerprint_of_public`
/// in the server's `src/oidc.rs`, the one place the server computes a kid for
/// the live key and for retired keys alike.
pub fn kid_from_xy(x: &[u8], y: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update([0x04]);
    hash.update(x);
    hash.update(y);
    hex::encode(&hash.finalize()[..8])
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// One entry of the published JWKS: its `kid` as published and, when it is a
/// usable ES256 verification key, its affine point.
#[derive(Clone, Debug)]
pub struct JwkEntry {
    pub kid: String,
    pub point: Option<([u8; 32], [u8; 32])>,
}

fn entry_of(key: &Value) -> JwkEntry {
    let text = |name: &str| key.get(name).and_then(Value::as_str);
    let kid = text("kid").unwrap_or_default().to_string();
    // A key published for anything but ES256 signatures cannot verify an ID token.
    let usable = text("kty") == Some("EC")
        && text("crv") == Some("P-256")
        && text("use").is_none_or(|u| u == "sig")
        && text("alg").is_none_or(|a| a == "ES256");
    let coordinate =
        |name: &str| -> Option<[u8; 32]> { b64d(text(name)?)?.as_slice().try_into().ok() };
    let point = if usable {
        coordinate("x").zip(coordinate("y")).filter(|(x, y)| {
            let ep = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
            VerifyingKey::from_encoded_point(&ep).is_ok()
        })
    } else {
        None
    };
    JwkEntry { kid, point }
}

/// The entries of a JWKS body, `None` when it has no `keys` array.
pub fn parse_jwks(body: &Value) -> Option<Vec<JwkEntry>> {
    Some(body.get("keys")?.as_array()?.iter().map(entry_of).collect())
}

/// What C2 found. Every list is of public kids.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct JwksVerdict {
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub dropped_present: Vec<String>,
    pub not_derived: Vec<String>,
    pub duplicates: Vec<String>,
}

impl JwksVerdict {
    /// The first rule broken, most serious first: a dropped (exposed) kid that
    /// is still published outranks every other difference.
    pub fn reason(&self) -> Reason {
        if !self.dropped_present.is_empty() {
            Reason::DroppedKidPresent
        } else if !self.duplicates.is_empty() {
            Reason::KidDuplicate
        } else if !self.missing.is_empty() || !self.extra.is_empty() {
            Reason::KidSetDiffers
        } else if !self.not_derived.is_empty() {
            Reason::KidNotDerived
        } else {
            Reason::Ok
        }
    }
}

/// C2: the published kid set equals `expect` exactly, no `dropped` kid is in it,
/// and every entry's kid is the one derived from its own `x`,`y`.
pub fn judge_jwks(
    entries: &[JwkEntry],
    expect: &BTreeSet<String>,
    dropped: &BTreeSet<String>,
) -> JwksVerdict {
    let mut verdict = JwksVerdict::default();
    let mut seen = BTreeSet::new();
    for entry in entries {
        if !seen.insert(entry.kid.clone()) && !verdict.duplicates.contains(&entry.kid) {
            verdict.duplicates.push(entry.kid.clone());
        }
        let derived_ok = entry
            .point
            .as_ref()
            .is_some_and(|(x, y)| kid_from_xy(x, y) == entry.kid);
        if !derived_ok {
            verdict.not_derived.push(entry.kid.clone());
        }
        if dropped.contains(&entry.kid) && !verdict.dropped_present.contains(&entry.kid) {
            verdict.dropped_present.push(entry.kid.clone());
        }
    }
    verdict.missing = expect.difference(&seen).cloned().collect();
    verdict.extra = seen.difference(expect).cloned().collect();
    verdict
}

/// What the ID token must say.
pub struct Expect<'a> {
    pub live_kid: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub did: &'a str,
}

#[derive(Debug)]
pub struct IdTokenFacts {
    pub kid: String,
    pub iat: i64,
    pub exp: i64,
}

fn verify_es256(signing_input: &[u8], signature: &[u8], point: &([u8; 32], [u8; 32])) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    let ep = EncodedPoint::from_affine_coordinates((&point.0).into(), (&point.1).into(), false);
    let Ok(key) = VerifyingKey::from_encoded_point(&ep) else {
        return false;
    };
    key.verify(signing_input, &signature).is_ok()
}

/// The `kid` in an ID token's header, unverified, for a report that names the
/// kid a wrong-key token carried.
pub fn header_kid(jws: &str) -> Option<String> {
    let header: Value = serde_json::from_slice(&b64d(jws.split('.').next()?)?).ok()?;
    header.get("kid")?.as_str().map(str::to_string)
}

/// C3's token check, in the order that never trusts the token before the key
/// says so: three parts; `alg` is ES256 (decided before any key is looked up,
/// so `none` and `HS*` are rejected by name); the header `kid` is the live kid
/// and is in the JWKS; the raw `r||s` signature (64 bytes, never DER) verifies
/// over the received `header.payload` bytes against that entry; then `iss`
/// (one trailing slash normalized), `aud` (string or array) and `sub`.
/// Times are judged separately by [`check_times`], against the server's clock.
pub fn verify_id_token(
    token: &str,
    jwks: &[JwkEntry],
    want: &Expect<'_>,
) -> Result<IdTokenFacts, Reason> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = parts[..] else {
        return Err(Reason::IdTokenMalformed);
    };
    let header: Value = b64d(header_b64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(Reason::IdTokenMalformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(Reason::AlgMismatch);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(Reason::KidMismatch)?;
    if kid != want.live_kid {
        return Err(Reason::KidMismatch);
    }
    let entry = jwks
        .iter()
        .find(|e| e.kid == kid)
        .ok_or(Reason::KidNotInJwks)?;
    let point = entry.point.as_ref().ok_or(Reason::JwkUnusable)?;
    let signature = b64d(signature_b64).ok_or(Reason::SignatureInvalid)?;
    if !verify_es256(
        format!("{header_b64}.{payload_b64}").as_bytes(),
        &signature,
        point,
    ) {
        return Err(Reason::SignatureInvalid);
    }
    let claims: Value = b64d(payload_b64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(Reason::IdTokenMalformed)?;
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !issuers_match(iss, want.issuer) {
        return Err(Reason::IssClaimMismatch);
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == want.client_id,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(want.client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(Reason::AudMismatch);
    }
    if claims.get("sub").and_then(Value::as_str) != Some(want.did) {
        return Err(Reason::SubMismatch);
    }
    let iat = claims.get("iat").and_then(Value::as_i64);
    let exp = claims.get("exp").and_then(Value::as_i64);
    let (Some(iat), Some(exp)) = (iat, exp) else {
        return Err(Reason::IdTokenMalformed);
    };
    Ok(IdTokenFacts {
        kid: kid.to_string(),
        iat,
        exp,
    })
}

/// `iat` and `exp` against the SERVER's clock: `server_date` is the `Date` of a
/// response the server sent just before the token was minted, `elapsed` the
/// seconds that passed on this host's monotonic clock since. This host's wall
/// clock is not used (a skewed WSL clock must not fail a healthy server). The
/// signed `iat - server_date` is returned as the skew.
pub fn check_times(
    iat: i64,
    exp: i64,
    server_date: i64,
    elapsed: i64,
    max_skew: i64,
) -> Result<i64, Reason> {
    let skew = iat - server_date;
    if skew < -max_skew || iat > server_date + elapsed + max_skew {
        return Err(Reason::ClockSkew);
    }
    if exp <= iat || exp <= server_date + elapsed - max_skew {
        return Err(Reason::TokenExpired);
    }
    Ok(skew)
}

/// An HTTP `Date` header (RFC 9110 IMF-fixdate) as unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|d| d.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // A P-256 point and the kid computed for it outside this code with
    // `sha256sum` over the 65-byte uncompressed point (04 || x || y), the first
    // 16 hex characters: the derivation `fingerprint_of_public` in the server's
    // `src/oidc.rs` performs for every key it publishes.
    const VEC_X: &str = "cb80236d22e922dd25cf16d3ebb5e8216da3ff35343f29cfb035d1210598d1e0";
    const VEC_Y: &str = "81f5dc02c4c40c5ce954915ee115d3508c263d7d2f41a8ead0f9294983dd1d6f";
    const VEC_KID: &str = "7588bd62dc96c065";

    const ISSUER: &str = "https://siwx.example.org";
    const CLIENT: &str = "client-123";
    const DID: &str = "did:key:z6MkTestCanaryIdentity";

    fn entry_for(key: &SigningKey) -> JwkEntry {
        let point = key.verifying_key().to_encoded_point(false);
        let x: [u8; 32] = point.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = point.y().unwrap().as_slice().try_into().unwrap();
        JwkEntry {
            kid: kid_from_xy(&x, &y),
            point: Some((x, y)),
        }
    }

    fn mint(key: &SigningKey, header: Value, claims: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn claims() -> Value {
        serde_json::json!({
            "iss": format!("{ISSUER}/"), "aud": [CLIENT], "sub": DID, "iat": 1000, "exp": 4600
        })
    }

    fn want<'a>(kid: &'a str) -> Expect<'a> {
        Expect {
            live_kid: kid,
            issuer: ISSUER,
            client_id: CLIENT,
            did: DID,
        }
    }

    #[test]
    fn es256_accepts_a_token_signed_by_the_published_key() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&key);
        let token = mint(
            &key,
            serde_json::json!({"alg": "ES256", "kid": entry.kid}),
            claims(),
        );
        let facts = verify_id_token(&token, std::slice::from_ref(&entry), &want(&entry.kid))
            .expect("valid token");
        assert_eq!(
            (facts.kid.as_str(), facts.iat, facts.exp),
            (entry.kid.as_str(), 1000, 4600)
        );
    }

    #[test]
    fn es256_rejects_a_token_signed_by_another_key() {
        let published = SigningKey::random(&mut rand::rngs::OsRng);
        let attacker = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&published);
        // The header names the live kid, the signature is not the live key's.
        let token = mint(
            &attacker,
            serde_json::json!({"alg": "ES256", "kid": entry.kid}),
            claims(),
        );
        assert_eq!(
            verify_id_token(&token, std::slice::from_ref(&entry), &want(&entry.kid)).unwrap_err(),
            Reason::SignatureInvalid
        );
    }

    #[test]
    fn es256_rejects_a_token_whose_signature_was_cut_or_flipped() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&key);
        let token = mint(
            &key,
            serde_json::json!({"alg": "ES256", "kid": entry.kid}),
            claims(),
        );
        let (head, sig) = token.rsplit_once('.').unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
        raw[10] ^= 0x01;
        let flipped = format!("{head}.{}", URL_SAFE_NO_PAD.encode(&raw));
        assert_eq!(
            verify_id_token(&flipped, std::slice::from_ref(&entry), &want(&entry.kid)).unwrap_err(),
            Reason::SignatureInvalid
        );
        let cut = format!("{head}.{}", URL_SAFE_NO_PAD.encode(&raw[..63]));
        assert_eq!(
            verify_id_token(&cut, std::slice::from_ref(&entry), &want(&entry.kid)).unwrap_err(),
            Reason::SignatureInvalid
        );
    }

    #[test]
    fn es256_rejects_a_mismatched_kid() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&key);
        // Validly signed by a published key, but not the key the operator says is live.
        let token = mint(
            &key,
            serde_json::json!({"alg": "ES256", "kid": entry.kid}),
            claims(),
        );
        assert_eq!(
            verify_id_token(
                &token,
                std::slice::from_ref(&entry),
                &want("0123456789abcdef")
            )
            .unwrap_err(),
            Reason::KidMismatch
        );
        // A header kid that is not in the JWKS at all.
        let token = mint(
            &key,
            serde_json::json!({"alg": "ES256", "kid": "0123456789abcdef"}),
            claims(),
        );
        assert_eq!(
            verify_id_token(&token, &[entry], &want("0123456789abcdef")).unwrap_err(),
            Reason::KidNotInJwks
        );
    }

    #[test]
    fn es256_rejects_other_algorithms_by_name() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&key);
        for alg in ["none", "HS256", "RS256", "ES384"] {
            let token = mint(
                &key,
                serde_json::json!({"alg": alg, "kid": entry.kid}),
                claims(),
            );
            assert_eq!(
                verify_id_token(&token, std::slice::from_ref(&entry), &want(&entry.kid))
                    .unwrap_err(),
                Reason::AlgMismatch,
                "{alg}"
            );
        }
    }

    #[test]
    fn id_token_claims_are_bound_to_issuer_client_and_did() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entry = entry_for(&key);
        let header = serde_json::json!({"alg": "ES256", "kid": entry.kid});
        let case = |claims: Value| {
            let token = mint(&key, header.clone(), claims);
            verify_id_token(&token, std::slice::from_ref(&entry), &want(&entry.kid))
        };
        let mut c = claims();
        c["iss"] = "https://other.example.org/".into();
        assert_eq!(case(c).unwrap_err(), Reason::IssClaimMismatch);
        let mut c = claims();
        c["aud"] = serde_json::json!(["someone-else"]);
        assert_eq!(case(c).unwrap_err(), Reason::AudMismatch);
        let mut c = claims();
        c["aud"] = serde_json::json!(CLIENT);
        assert!(
            case(c).is_ok(),
            "a string aud is as good as a one-element array"
        );
        let mut c = claims();
        c["sub"] = "did:key:zSomeoneElse".into();
        assert_eq!(case(c).unwrap_err(), Reason::SubMismatch);
        let mut c = claims();
        c["iss"] = ISSUER.into();
        assert!(
            case(c).is_ok(),
            "an issuer without the slash is the same issuer"
        );
    }

    #[test]
    fn issuer_normalization_trims_exactly_one_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://siwx.example.org/"),
            "https://siwx.example.org"
        );
        assert_eq!(
            normalize_issuer("https://siwx.example.org"),
            "https://siwx.example.org"
        );
        assert_eq!(
            normalize_issuer("https://siwx.example.org//"),
            "https://siwx.example.org/"
        );
        assert!(issuers_match(
            "https://siwx.example.org/",
            "https://siwx.example.org"
        ));
        assert!(!issuers_match(
            "https://siwx.example.org//",
            "https://siwx.example.org"
        ));
        assert!(!issuers_match(
            "https://siwx.example.org",
            "https://siwx.example.com"
        ));
        assert!(!issuers_match(
            "http://siwx.example.org",
            "https://siwx.example.org"
        ));
    }

    #[test]
    fn kid_derivation_matches_the_servers_for_a_pinned_point() {
        let x = hex::decode(VEC_X).unwrap();
        let y = hex::decode(VEC_Y).unwrap();
        assert_eq!(kid_from_xy(&x, &y), VEC_KID);
    }

    #[test]
    fn kid_derivation_matches_a_jwk_the_running_server_published() {
        // `x`, `y` and `kid` of the live key as `GET /jwk` of the siwx-oidc
        // built from this tree served them (a throwaway key of a local stack).
        let x = URL_SAFE_NO_PAD
            .decode("adRX-9KLo8rWCqDgEK0KY-v3_65dQNVfeZyNC0AFdkg")
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode("1PbGmkETBlg5BQnwbRJrM4H0CH0lfQV6ueLmFpFhzV0")
            .unwrap();
        assert_eq!(kid_from_xy(&x, &y), "ac75b6ec9e53d7ad");
        let body = serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "ac75b6ec9e53d7ad",
            "x": "adRX-9KLo8rWCqDgEK0KY-v3_65dQNVfeZyNC0AFdkg",
            "y": "1PbGmkETBlg5BQnwbRJrM4H0CH0lfQV6ueLmFpFhzV0",
        }]});
        let entries = parse_jwks(&body).unwrap();
        let expect = BTreeSet::from(["ac75b6ec9e53d7ad".to_string()]);
        assert_eq!(
            judge_jwks(&entries, &expect, &BTreeSet::new()),
            JwksVerdict::default()
        );
    }

    #[test]
    fn kid_derivation_equals_the_servers_formula_for_random_keys() {
        use sha2::{Digest, Sha256};
        for _ in 0..8 {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            // `fingerprint_of_public`: sha256 over `to_encoded_point(false)`, 16 hex.
            let server = hex::encode(Sha256::digest(
                key.verifying_key().to_encoded_point(false).as_bytes(),
            ))[..16]
                .to_string();
            assert_eq!(entry_for(&key).kid, server);
        }
    }

    fn set(kids: &[&str]) -> BTreeSet<String> {
        kids.iter().map(|k| k.to_string()).collect()
    }

    fn jwks_of(keys: &[&SigningKey]) -> Vec<JwkEntry> {
        keys.iter().map(|k| entry_for(k)).collect()
    }

    #[test]
    fn jwks_exact_set_passes_when_the_sets_are_equal() {
        let (a, b) = (
            SigningKey::random(&mut rand::rngs::OsRng),
            SigningKey::random(&mut rand::rngs::OsRng),
        );
        let entries = jwks_of(&[&a, &b]);
        let expect = set(&[&entries[0].kid, &entries[1].kid]);
        let v = judge_jwks(&entries, &expect, &BTreeSet::new());
        assert_eq!(v, JwksVerdict::default());
        assert_eq!(v.reason(), Reason::Ok);
    }

    #[test]
    fn jwks_exact_set_fails_when_a_dropped_kid_is_still_listed() {
        let (live, old) = (
            SigningKey::random(&mut rand::rngs::OsRng),
            SigningKey::random(&mut rand::rngs::OsRng),
        );
        let entries = jwks_of(&[&live, &old]);
        let expect = set(&[&entries[0].kid]);
        let dropped = set(&[&entries[1].kid]);
        let v = judge_jwks(&entries, &expect, &dropped);
        assert_eq!(v.dropped_present, vec![entries[1].kid.clone()]);
        assert_eq!(v.extra, vec![entries[1].kid.clone()]);
        assert_eq!(v.reason(), Reason::DroppedKidPresent);
    }

    #[test]
    fn jwks_exact_set_fails_on_a_missing_or_an_extra_kid() {
        let (a, b) = (
            SigningKey::random(&mut rand::rngs::OsRng),
            SigningKey::random(&mut rand::rngs::OsRng),
        );
        let entries = jwks_of(&[&a]);
        let expect = set(&[&entries[0].kid, &jwks_of(&[&b])[0].kid]);
        let v = judge_jwks(&entries, &expect, &BTreeSet::new());
        assert_eq!(v.missing.len(), 1);
        assert_eq!(v.reason(), Reason::KidSetDiffers);
        let v = judge_jwks(
            &jwks_of(&[&a, &b]),
            &set(&[&entries[0].kid]),
            &BTreeSet::new(),
        );
        assert_eq!(v.extra.len(), 1);
        assert_eq!(v.reason(), Reason::KidSetDiffers);
    }

    #[test]
    fn jwks_entry_whose_kid_is_not_derived_from_its_point_fails() {
        let a = SigningKey::random(&mut rand::rngs::OsRng);
        let mut entries = jwks_of(&[&a]);
        entries[0].kid = "0123456789abcdef".to_string();
        let v = judge_jwks(&entries, &set(&["0123456789abcdef"]), &BTreeSet::new());
        assert_eq!(v.not_derived, vec!["0123456789abcdef".to_string()]);
        assert_eq!(v.reason(), Reason::KidNotDerived);
        // A key that is not a usable point has no derivable kid either.
        entries[0].point = None;
        assert_eq!(
            judge_jwks(&entries, &set(&["0123456789abcdef"]), &BTreeSet::new()).reason(),
            Reason::KidNotDerived
        );
    }

    #[test]
    fn jwks_duplicate_kid_fails() {
        let a = SigningKey::random(&mut rand::rngs::OsRng);
        let mut entries = jwks_of(&[&a]);
        entries.push(entries[0].clone());
        let expect = set(&[&entries[0].kid]);
        assert_eq!(
            judge_jwks(&entries, &expect, &BTreeSet::new()).reason(),
            Reason::KidDuplicate
        );
    }

    #[test]
    fn parse_jwks_reads_x_and_y_and_refuses_a_non_p256_entry() {
        let x = URL_SAFE_NO_PAD.encode(hex::decode(VEC_X).unwrap());
        let y = URL_SAFE_NO_PAD.encode(hex::decode(VEC_Y).unwrap());
        let body = serde_json::json!({"keys": [
            {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": VEC_KID, "use": "sig", "alg": "ES256"},
            {"kty": "EC", "crv": "P-384", "x": x, "y": y, "kid": "aaaaaaaaaaaaaaaa"},
            {"kty": "RSA", "kid": "bbbbbbbbbbbbbbbb"},
            {"kid": "cccccccccccccccc", "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
        ]});
        let entries = parse_jwks(&body).expect("keys array");
        assert_eq!(entries.len(), 4);
        assert!(entries[0].point.is_some());
        assert!(entries[1..].iter().all(|e| e.point.is_none()));
        assert!(parse_jwks(&serde_json::json!({"nokeys": []})).is_none());
    }

    #[test]
    fn times_are_judged_against_the_servers_clock_not_the_local_one() {
        // iat on the server's Date, 2 s elapsed since: fine, skew 0.
        assert_eq!(check_times(5_000, 8_600, 5_000, 2, 30), Ok(0));
        assert_eq!(check_times(5_001, 8_600, 5_000, 2, 30), Ok(1));
        // A token minted before the Date we read, within the stated skew.
        assert_eq!(check_times(4_980, 8_600, 5_000, 2, 30), Ok(-20));
        // Beyond the skew either way.
        assert_eq!(
            check_times(4_960, 8_600, 5_000, 2, 30),
            Err(Reason::ClockSkew)
        );
        assert_eq!(
            check_times(5_100, 8_600, 5_000, 2, 30),
            Err(Reason::ClockSkew)
        );
        // Already expired by the server's clock.
        assert_eq!(
            check_times(5_000, 5_010, 5_000, 40, 30),
            Err(Reason::TokenExpired)
        );
        assert_eq!(
            check_times(5_000, 4_999, 5_000, 0, 30),
            Err(Reason::TokenExpired)
        );
    }

    #[test]
    fn http_dates_parse_to_unix_seconds() {
        assert_eq!(
            parse_http_date("Tue, 15 Nov 1994 08:12:31 GMT"),
            Some(784_887_151)
        );
        assert_eq!(parse_http_date("not a date"), None);
    }
}
