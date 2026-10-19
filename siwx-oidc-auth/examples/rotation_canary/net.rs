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
    /// The `Set-Cookie` headers as received. Credentials: callers wrap them.
    pub set_cookies: Vec<String>,
    /// The body as text, for deciding on (a plain-text refusal is not JSON).
    /// Never printed.
    text: String,
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

    /// Whether the body, read as text, contains `needle`.
    pub fn body_contains(&self, needle: &str) -> bool {
        self.text.contains(needle)
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
        // The canary talks to the hosts it was told to, never through a proxy
        // an environment variable names: a proxy would see every credential.
        .no_proxy()
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
    let set_cookies = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    let body = response.bytes().await.map_err(net_err)?;
    let (json, text) = if body.len() <= MAX_BODY {
        (
            serde_json::from_slice(&body).ok(),
            String::from_utf8_lossy(&body).into_owned(),
        )
    } else {
        (None, String::new())
    };
    Ok(Reply {
        status,
        json,
        date,
        set_cookies,
        text,
    })
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
            set_cookies: vec![],
            text: String::new(),
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
            set_cookies: vec![],
            text: String::new(),
        };
        let matrix = Reply {
            status: 401,
            json: Some(serde_json::json!({"errcode": "M_UNKNOWN_TOKEN"})),
            date: None,
            set_cookies: vec![],
            text: String::new(),
        };
        let none = Reply {
            status: 500,
            json: None,
            date: None,
            set_cookies: vec![],
            text: String::new(),
        };
        assert_eq!(oauth.error_code(), Some("invalid_grant"));
        assert_eq!(matrix.error_code(), Some("M_UNKNOWN_TOKEN"));
        assert_eq!(none.error_code(), None);
        assert!(Reply {
            status: 503,
            json: None,
            date: None,
            set_cookies: vec![],
            text: String::new(),
        }
        .is_unavailable());
        assert!(!Reply {
            status: 500,
            json: None,
            date: None,
            set_cookies: vec![],
            text: String::new(),
        }
        .is_unavailable());
    }
}
