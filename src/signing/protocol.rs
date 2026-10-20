//! The `siwx-signer` wire protocol, version 1.
//!
//! A Unix stream socket, one request per connection. The client writes one
//! JSON object (it holds no newline) followed by `\n`; the signer answers with
//! one JSON object and `\n`, then closes. A request is at most
//! [`MAX_REQUEST_BYTES`] including the newline. Every request and answer
//! carries `"v": 1`.
//!
//! | Request | Answer |
//! |---|---|
//! | `{"v":1,"op":"public"}` | `{"v":1,"kid":"…","jwk":{…},"alg":"ES256"}` |
//! | `{"v":1,"op":"sign","purpose":"id_token","msg":"<base64url>"}` | `{"v":1,"kid":"…","sig":"<base64url r‖s>"}` |
//! | anything refused | `{"v":1,"error":"<code>"}` with a code of [`ErrorCode`] |
//!
//! `purpose` is one of [`Purpose`]; `msg` is the JWS signing input
//! (`BASE64URL(header).BASE64URL(payload)`) in unpadded base64url. An error
//! answer never echoes the request.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The protocol version this build speaks.
pub const VERSION: u64 = 1;

/// The largest request the signer reads, newline included.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// The largest answer a client reads. The longest answer is `public` (a JWK),
/// well under this.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024;

/// What a signature is for. The signer checks the message's shape per purpose
/// ([`super::shape`]) and counts signatures per purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// An ID token from the token endpoint.
    IdToken,
    /// The DID assertion published in the `io.inblock.did` profile field.
    DidProof,
    /// A back-channel logout token.
    LogoutToken,
    /// A signed userinfo response.
    Userinfo,
}

impl Purpose {
    /// Every purpose, in a fixed order (the order of the signer's count line).
    pub const ALL: [Purpose; 4] = [
        Purpose::IdToken,
        Purpose::DidProof,
        Purpose::LogoutToken,
        Purpose::Userinfo,
    ];

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::IdToken => "id_token",
            Purpose::DidProof => "did_proof",
            Purpose::LogoutToken => "logout_token",
            Purpose::Userinfo => "userinfo",
        }
    }

    fn from_wire(name: &str) -> Option<Self> {
        Purpose::ALL.into_iter().find(|p| p.as_str() == name)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The fixed set of error codes the signer answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Not JSON, not an object, an unknown `op` or `purpose`, a field that does
    /// not belong, or a `msg` that is not unpadded base64url.
    BadRequest,
    /// More than [`MAX_REQUEST_BYTES`] before the newline.
    TooLarge,
    /// `v` missing, or not [`VERSION`].
    BadVersion,
    /// The message is not the shape the purpose allows ([`super::shape`]).
    Shape,
    /// The signer failed on its own side.
    Internal,
}

impl ErrorCode {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::BadVersion => "bad_version",
            ErrorCode::Shape => "shape",
            ErrorCode::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request as the signer reads it.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// `op: public`: the signer's `kid` and public JWK.
    Public,
    /// `op: sign`: a signature over `msg` (decoded) for `purpose`.
    Sign { purpose: Purpose, msg: Vec<u8> },
}

/// One message on the wire, members in the documented order (`v` first).
#[derive(Serialize)]
#[serde(untagged)]
enum Wire<'a> {
    PublicRequest {
        v: u64,
        op: &'static str,
    },
    SignRequest {
        v: u64,
        op: &'static str,
        purpose: Purpose,
        msg: String,
    },
    PublicAnswer {
        v: u64,
        kid: &'a str,
        jwk: Value,
        alg: &'static str,
    },
    SignAnswer {
        v: u64,
        kid: &'a str,
        sig: String,
    },
    Error {
        v: u64,
        error: ErrorCode,
    },
}

/// The `public` request line, newline included.
pub fn public_request() -> Vec<u8> {
    line(Wire::PublicRequest {
        v: VERSION,
        op: "public",
    })
}

/// The `sign` request line for `msg`, newline included.
pub fn sign_request(purpose: Purpose, msg: &[u8]) -> Vec<u8> {
    line(Wire::SignRequest {
        v: VERSION,
        op: "sign",
        purpose,
        msg: URL_SAFE_NO_PAD.encode(msg),
    })
}

/// Parse one request (without its newline). The version is checked before the
/// operation, so a request from a later protocol is `bad_version`, never a
/// misread `bad_request`.
pub fn parse_request(bytes: &[u8]) -> Result<Request, ErrorCode> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ErrorCode::BadRequest)?;
    let object = value.as_object().ok_or(ErrorCode::BadRequest)?;
    match object.get("v").and_then(Value::as_u64) {
        Some(VERSION) => {}
        _ => return Err(ErrorCode::BadVersion),
    }
    match object.get("op").and_then(Value::as_str) {
        Some("public") => {
            only_fields(object, &["v", "op"])?;
            Ok(Request::Public)
        }
        Some("sign") => {
            only_fields(object, &["v", "op", "purpose", "msg"])?;
            let purpose = object
                .get("purpose")
                .and_then(Value::as_str)
                .and_then(Purpose::from_wire)
                .ok_or(ErrorCode::BadRequest)?;
            let msg = object
                .get("msg")
                .and_then(Value::as_str)
                .and_then(|m| URL_SAFE_NO_PAD.decode(m).ok())
                .ok_or(ErrorCode::BadRequest)?;
            Ok(Request::Sign { purpose, msg })
        }
        _ => Err(ErrorCode::BadRequest),
    }
}

fn only_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), ErrorCode> {
    if object.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(ErrorCode::BadRequest)
    }
}

/// The `public` answer line.
pub fn public_answer(kid: &str, jwk: Value) -> Vec<u8> {
    line(Wire::PublicAnswer {
        v: VERSION,
        kid,
        jwk,
        alg: "ES256",
    })
}

/// The `sign` answer line.
pub fn sign_answer(kid: &str, signature: &[u8]) -> Vec<u8> {
    line(Wire::SignAnswer {
        v: VERSION,
        kid,
        sig: URL_SAFE_NO_PAD.encode(signature),
    })
}

/// The error answer line.
pub fn error_answer(code: ErrorCode) -> Vec<u8> {
    line(Wire::Error {
        v: VERSION,
        error: code,
    })
}

fn line(message: Wire<'_>) -> Vec<u8> {
    // serde_json's compact form escapes control characters, so it holds no
    // newline and the one appended here ends the message.
    let mut bytes = serde_json::to_vec(&message).expect("a wire message always encodes");
    bytes.push(b'\n');
    bytes
}

/// The answer to `public`, as a client reads it.
#[derive(Debug, Deserialize)]
pub struct PublicAnswer {
    pub kid: String,
    pub jwk: Value,
    pub alg: String,
}

/// The answer to `sign`, as a client reads it.
#[derive(Debug, Deserialize)]
pub struct SignAnswer {
    pub kid: String,
    pub sig: String,
}

/// An answer as a client reads it: the expected success shape `T`, or an
/// error code. `None` for anything else (wrong version, unknown code, neither
/// shape).
pub fn parse_answer<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<Result<T, ErrorCode>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let value: Value = serde_json::from_str(text.strip_suffix('\n').unwrap_or(text)).ok()?;
    if value.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return None;
    }
    if let Some(code) = value.get("error") {
        return serde_json::from_value::<ErrorCode>(code.clone())
            .ok()
            .map(Err);
    }
    serde_json::from_value::<T>(value).ok().map(Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Request, ErrorCode> {
        parse_request(text.as_bytes())
    }

    #[test]
    fn the_request_lines_parse_back_and_end_in_one_newline() {
        let public = public_request();
        assert_eq!(public.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(public.last(), Some(&b'\n'));
        assert_eq!(
            parse_request(&public[..public.len() - 1]),
            Ok(Request::Public)
        );

        let msg = b"eyJhbGciOiJFUzI1NiJ9.e30".to_vec();
        let sign = sign_request(Purpose::LogoutToken, &msg);
        assert_eq!(sign.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(
            parse_request(&sign[..sign.len() - 1]),
            Ok(Request::Sign {
                purpose: Purpose::LogoutToken,
                msg
            })
        );
    }

    #[test]
    fn every_purpose_has_its_wire_name() {
        for purpose in Purpose::ALL {
            let wire = serde_json::to_value(purpose).unwrap();
            assert_eq!(wire, Value::String(purpose.as_str().to_string()));
            assert_eq!(Purpose::from_wire(purpose.as_str()), Some(purpose));
        }
        assert_eq!(
            Purpose::ALL.map(Purpose::as_str),
            ["id_token", "did_proof", "logout_token", "userinfo"]
        );
    }

    #[test]
    fn bad_json_and_non_objects_are_bad_request() {
        assert_eq!(parse("not json"), Err(ErrorCode::BadRequest));
        assert_eq!(parse("[1]"), Err(ErrorCode::BadRequest));
        assert_eq!(parse("\"public\""), Err(ErrorCode::BadRequest));
        assert_eq!(parse(""), Err(ErrorCode::BadRequest));
    }

    #[test]
    fn a_missing_or_other_version_is_bad_version_before_anything_else() {
        assert_eq!(parse(r#"{"op":"public"}"#), Err(ErrorCode::BadVersion));
        assert_eq!(
            parse(r#"{"v":2,"op":"public"}"#),
            Err(ErrorCode::BadVersion)
        );
        assert_eq!(
            parse(r#"{"v":"1","op":"public"}"#),
            Err(ErrorCode::BadVersion)
        );
        assert_eq!(
            parse(r#"{"v":0,"op":"nonsense"}"#),
            Err(ErrorCode::BadVersion)
        );
    }

    #[test]
    fn unknown_ops_purposes_fields_and_bad_base64_are_bad_request() {
        assert_eq!(
            parse(r#"{"v":1,"op":"export"}"#),
            Err(ErrorCode::BadRequest)
        );
        assert_eq!(parse(r#"{"v":1}"#), Err(ErrorCode::BadRequest));
        assert_eq!(
            parse(r#"{"v":1,"op":"public","extra":1}"#),
            Err(ErrorCode::BadRequest)
        );
        assert_eq!(
            parse(r#"{"v":1,"op":"sign","purpose":"access_token","msg":"e30"}"#),
            Err(ErrorCode::BadRequest)
        );
        assert_eq!(
            parse(r#"{"v":1,"op":"sign","purpose":"id_token","msg":"e30="}"#),
            Err(ErrorCode::BadRequest),
            "padding is not unpadded base64url"
        );
        assert_eq!(
            parse(r#"{"v":1,"op":"sign","purpose":"id_token","msg":"e3+/"}"#),
            Err(ErrorCode::BadRequest),
            "the standard alphabet is not base64url"
        );
        assert_eq!(
            parse(r#"{"v":1,"op":"sign","purpose":"id_token"}"#),
            Err(ErrorCode::BadRequest)
        );
        assert_eq!(
            parse(r#"{"v":1,"op":"sign","purpose":"id_token","msg":"e30","kid":"x"}"#),
            Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn answers_parse_on_the_client_side() {
        let jwk = serde_json::json!({"kty": "EC"});
        let public = public_answer("0123456789abcdef", jwk.clone());
        let parsed: PublicAnswer = parse_answer(&public).unwrap().unwrap();
        assert_eq!(parsed.kid, "0123456789abcdef");
        assert_eq!(parsed.jwk, jwk);
        assert_eq!(parsed.alg, "ES256");

        let sign = sign_answer("0123456789abcdef", &[1, 2, 3]);
        let parsed: SignAnswer = parse_answer(&sign).unwrap().unwrap();
        assert_eq!(parsed.sig, "AQID");

        for code in [
            ErrorCode::BadRequest,
            ErrorCode::TooLarge,
            ErrorCode::BadVersion,
            ErrorCode::Shape,
            ErrorCode::Internal,
        ] {
            let answer = error_answer(code);
            assert_eq!(
                String::from_utf8(answer.clone()).unwrap(),
                format!("{{\"v\":1,\"error\":\"{code}\"}}\n")
            );
            assert_eq!(
                parse_answer::<SignAnswer>(&answer).unwrap().unwrap_err(),
                code
            );
        }

        assert!(parse_answer::<SignAnswer>(br#"{"v":2,"kid":"k","sig":"AQID"}"#).is_none());
        assert!(parse_answer::<SignAnswer>(br#"{"v":1,"error":"surprise"}"#).is_none());
        assert!(parse_answer::<SignAnswer>(br#"{"v":1,"kid":"k"}"#).is_none());
        assert!(parse_answer::<SignAnswer>(b"garbage").is_none());
    }
}
