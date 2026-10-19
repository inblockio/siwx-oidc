//! HTTP: one client, replies reduced to what the checks decide on. A reply
//! never carries a body into output: the JSON stays in memory for the decision
//! and `Debug` shows the status only.

use std::fmt;
use std::time::Duration;

use serde_json::Value;

use crate::jose::parse_http_date;
use crate::report::Reason;

pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// A larger body is treated as unreadable.
const MAX_BODY: usize = 2 * 1024 * 1024;

/// Why a request got no answer. The transport error's own text carries URLs
/// and is dropped here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetErr {
    Timeout,
    Connect,
    Other,
}

pub struct Reply {
    pub status: u16,
    pub json: Option<Value>,
    /// The server's `Date`, unix seconds.
    pub date: Option<i64>,
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reply {{ status: {} }}", self.status)
    }
}

impl Reply {
    /// 502, 503 or 504: an edge in front of a server that is being recreated, or a store fault.
    pub fn is_unavailable(&self) -> bool {
        matches!(self.status, 502..=504)
    }

    pub fn str_field(&self, name: &str) -> Option<&str> {
        self.json.as_ref()?.get(name)?.as_str()
    }

    /// The OAuth `error` or Matrix `errcode` of an error body, for deciding on, never for printing.
    pub fn error_code(&self) -> Option<&str> {
        self.str_field("error")
            .or_else(|| self.str_field("errcode"))
    }
}

pub fn client() -> Result<reqwest::Client, Reason> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        // The sign-in reads `Location` headers itself.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("rotation-canary/1")
        .build()
        .map_err(|_| Reason::Internal)
}

fn net_err(e: reqwest::Error) -> NetErr {
    if e.is_timeout() {
        NetErr::Timeout
    } else if e.is_connect() {
        NetErr::Connect
    } else {
        NetErr::Other
    }
}

pub async fn send(request: reqwest::RequestBuilder) -> Result<Reply, NetErr> {
    let response = request.send().await.map_err(net_err)?;
    let status = response.status().as_u16();
    let date = response
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date);
    let body = response.bytes().await.map_err(net_err)?;
    let json = if body.len() <= MAX_BODY {
        serde_json::from_slice(&body).ok()
    } else {
        None
    };
    Ok(Reply { status, json, date })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_prints_its_status_and_never_its_body() {
        let reply = Reply {
            status: 200,
            json: Some(serde_json::json!({"access_token": "mat_SecretSecretSecretSecretSecret12"})),
            date: None,
        };
        let shown = format!("{reply:?} {reply:#?}");
        assert!(shown.contains("status: 200"));
        assert!(!shown.contains("mat_Secret"), "{shown}");
        assert_eq!(
            reply.str_field("access_token"),
            Some("mat_SecretSecretSecretSecretSecret12")
        );
    }

    #[test]
    fn error_codes_come_from_error_or_errcode() {
        let oauth = Reply {
            status: 400,
            json: Some(serde_json::json!({"error": "invalid_grant"})),
            date: None,
        };
        let matrix = Reply {
            status: 401,
            json: Some(serde_json::json!({"errcode": "M_UNKNOWN_TOKEN"})),
            date: None,
        };
        let none = Reply {
            status: 500,
            json: None,
            date: None,
        };
        assert_eq!(oauth.error_code(), Some("invalid_grant"));
        assert_eq!(matrix.error_code(), Some("M_UNKNOWN_TOKEN"));
        assert_eq!(none.error_code(), None);
        assert!(Reply {
            status: 503,
            json: None,
            date: None
        }
        .is_unavailable());
        assert!(!Reply {
            status: 500,
            json: None,
            date: None
        }
        .is_unavailable());
    }
}
