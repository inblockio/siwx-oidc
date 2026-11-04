//! RFC 9068 JWT access tokens, issued for a resource (RFC 8707).
//!
//! An ordinary access token is opaque: a random `mat_…` string whose digest
//! keys the grant it belongs to, judged by introspection or `/userinfo`. A
//! token issued for a resource is instead a JWT the resource server verifies
//! offline against `/jwk`, because the resource server (an MCP server) holds
//! no credential of this provider's and must not be handed one.
//!
//! The grant behind it is the same record as for an opaque token, and keeps
//! its opaque access token, which nobody is handed: it is the grant's entry
//! (`at/{digest}`), what the rotation script writes and what revocation
//! deletes. The JWT carries the grant's `did`, `client_id` and `scope`, the
//! resource as `aud`, the issue and expiry instants the store decided (Redis
//! `TIME`, never an instance clock) and a random `jti`. Its lifetime is the
//! access token's (300 s), which bounds how long a revoked grant's JWT is
//! still accepted by a resource server: there is no introspection for it.
//!
//! Header: `{"alg":"ES256","typ":"at+jwt","kid":<the signer's>}`, signed
//! through [`ProviderSigner`] under [`Purpose::AccessToken`], so the `socket`
//! backend checks the shape ([`crate::signing::shape`]) like every other
//! signature of this provider. Claim and header order is struct declaration
//! order; those bytes are signed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

use crate::signing::shape::ACCESS_TOKEN_TYP;
use crate::signing::{ProviderSigner, Purpose, SignError};

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

/// What a token says (RFC 9068 section 2.2), in the order it is written.
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    client_id: &'a str,
    scope: &'a str,
    iat: i64,
    exp: i64,
    jti: &'a str,
}

/// The inputs of one token. Every string is written as given: the DID keeps
/// its exact case, the resource is the configured URI byte for byte.
#[derive(Clone, Debug)]
pub struct AccessTokenClaims<'a> {
    /// The issuer, as discovery's `issuer` (the configured `base_url`).
    pub issuer: &'a str,
    /// The authenticated DID, the grant's `did`.
    pub subject: &'a str,
    /// The resource the grant is for.
    pub resource: &'a str,
    /// The client the grant was issued to.
    pub client_id: &'a str,
    /// The grant's scope.
    pub scope: &'a str,
    /// Issue and expiry instants (Unix seconds) from the store.
    pub iat: i64,
    pub exp: i64,
}

/// Mint one token for `claims`, signed by `signer`. The `jti` is random and
/// never reused; a replayed rotation answer gets a token of its own.
pub async fn mint(
    signer: &dyn ProviderSigner,
    claims: &AccessTokenClaims<'_>,
) -> Result<String, SignError> {
    let header = Header {
        alg: "ES256",
        typ: ACCESS_TOKEN_TYP,
        kid: signer.kid(),
    };
    let jti = crate::db::tokens::new_session_id();
    let payload = Claims {
        iss: claims.issuer,
        sub: claims.subject,
        aud: claims.resource,
        client_id: claims.client_id,
        scope: claims.scope,
        iat: claims.iat,
        exp: claims.exp,
        jti: &jti,
    };
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("encodable header")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("encodable claims"))
    );
    let signature = signer.sign(Purpose::AccessToken, input.as_bytes()).await?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::EcdsaSigningKey;
    use p256::ecdsa::signature::Verifier;
    use serde_json::Value;

    fn claims() -> AccessTokenClaims<'static> {
        AccessTokenClaims {
            issuer: "https://id.example.org/",
            subject: "did:key:zDnaExactCase",
            resource: "https://mcp.example.org/mcp",
            client_id: "client-1",
            scope: "aqua:read aqua:write",
            iat: 1_800_000_000,
            exp: 1_800_000_300,
        }
    }

    fn decode(segment: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_token_carries_the_rfc_9068_claims_in_order_and_verifies_with_the_published_key() {
        let key = EcdsaSigningKey::generate();
        let token = mint(&key, &claims()).await.unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = decode(parts[0]);
        assert_eq!(
            header,
            serde_json::json!({"alg": "ES256", "typ": "at+jwt", "kid": key.kid()})
        );
        let payload = decode(parts[1]);
        // The order the bytes were signed in: declaration order (a parsed
        // `Value` sorts its keys, so the raw text is read).
        let raw_payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let positions: Vec<usize> = [
            "iss",
            "sub",
            "aud",
            "client_id",
            "scope",
            "iat",
            "exp",
            "jti",
        ]
        .iter()
        .map(|k| raw_payload.find(&format!("\"{k}\":")).unwrap())
        .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{raw_payload}");
        assert_eq!(payload.as_object().unwrap().len(), 8);
        assert_eq!(payload["iss"], "https://id.example.org/");
        assert_eq!(payload["sub"], "did:key:zDnaExactCase");
        assert_eq!(payload["aud"], "https://mcp.example.org/mcp");
        assert_eq!(payload["client_id"], "client-1");
        assert_eq!(payload["scope"], "aqua:read aqua:write");
        assert_eq!(payload["iat"], 1_800_000_000);
        assert_eq!(payload["exp"], 1_800_000_300);
        assert!(payload["jti"].as_str().is_some_and(|j| !j.is_empty()));

        let raw = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(raw.len(), 64, "raw r||s, never DER");
        let signature = p256::ecdsa::Signature::from_slice(&raw).unwrap();
        key.verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("verifies with the signer's public key");

        let again = mint(&key, &claims()).await.unwrap();
        assert_ne!(
            decode(again.split('.').nth(1).unwrap())["jti"],
            payload["jti"],
            "every token has its own jti"
        );
    }

    /// The shape the socket signer checks is the shape this module emits.
    #[test]
    fn the_emitted_shape_passes_the_signers_check() {
        use crate::signing::shape::{check, ShapePolicy};
        let key = EcdsaSigningKey::generate();
        let header = Header {
            alg: "ES256",
            typ: ACCESS_TOKEN_TYP,
            kid: key.kid(),
        };
        let c = claims();
        let payload = Claims {
            iss: c.issuer,
            sub: c.subject,
            aud: c.resource,
            client_id: c.client_id,
            scope: c.scope,
            iat: c.iat,
            exp: c.exp,
            jti: "j",
        };
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let policy = ShapePolicy {
            kid: key.kid().to_string(),
            issuer: c.issuer.to_string(),
            max_token_lifetime_secs: 300,
            max_clock_skew_secs: 300,
        };
        assert_eq!(
            check(&policy, Purpose::AccessToken, input.as_bytes(), c.iat),
            Ok(())
        );
    }
}
