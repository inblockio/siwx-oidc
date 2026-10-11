//! The pure rules of a guest invitation (work package S2b, design 01 §4 A2, 04
//! GP-SEC-09/10/11): what a create request may ask for, how an invite id and its
//! secret are made, and who counts as a host. No Redis, no Synapse, no axum, so
//! every limit is tested without them. The store is [`crate::db`]'s `guest` module;
//! the HTTP side is `src/guest/invite.rs` in the binary.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::guest_room_audit::valid_room_id;

/// `expires_in` when the request names none (24 h, GP-SEC-11).
pub const DEFAULT_EXPIRES_IN: u64 = 86_400;
/// The longest `expires_in` accepted (72 h, GP-SEC-11). Over it is refused, not clamped.
pub const MAX_EXPIRES_IN: u64 = 259_200;
/// `session_secs` bounds and default (GP-SEC-33). Outside them is refused, not clamped.
pub const MIN_SESSION_SECS: u64 = 600;
pub const DEFAULT_SESSION_SECS: u64 = 7_200;
pub const MAX_SESSION_SECS: u64 = 14_400;
/// The longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 40;
/// The service subject of a minted admin token: it can never be a host.
pub const ADMIN_SUBJECT: &str = "urn:siwx:service:admin";

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// What an invitation lets in: one guest, or up to `max_guests` through one link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Single,
    Open,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Single => "single",
            Kind::Open => "open",
        }
    }
}

/// The body of `POST /guest/invites`. Unknown fields are refused: a typo in a
/// limit must not silently fall back to its default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub room_id: String,
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub max_guests: Option<u64>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub session_secs: Option<u64>,
    #[serde(default)]
    pub recording_expected: Option<bool>,
}

/// The configuration a request is judged against.
pub struct Limits<'a> {
    pub server_name: &'a str,
    pub max_guests: u64,
    pub allow_open_links: bool,
    pub open_link_max_uses: u64,
    pub open_link_max_ttl_secs: u64,
}

/// A request that passed [`validate`], with every default filled in.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidCreate {
    pub room_id: String,
    pub count: u64,
    /// Exactly `count` entries, empty where the host gave none.
    pub labels: Vec<String>,
    pub kind: Kind,
    /// Uses of one link: always 1 for a single-use link.
    pub max_guests: u64,
    pub expires_in: u64,
    pub session_secs: u64,
    pub recording_expected: bool,
}

/// Check a create request. The error is a fixed code, never an echo of the input.
///
/// - `room_id` follows the GP-SEC-07 grammar (checked before anything else, so a
///   hostile id never reaches Synapse).
/// - `count` is 1 to `max_guests` (default 1); `labels`, when given, has exactly
///   `count` entries of at most 40 characters and no control character.
/// - `kind` is `single` (default) or `open`; `open` needs `allow_open_links`, and
///   then `max_guests` (default: the cap) is at most `open_link_max_uses` and
///   `expires_in` at most `open_link_max_ttl_secs`. A single-use link takes
///   `max_guests` of 1 or none.
/// - `expires_in` defaults to 86400 and is at most 259200; `session_secs` defaults
///   to 7200 and lies in 600..=14400. Over a ceiling is refused, never clamped.
pub fn validate(req: CreateRequest, limits: &Limits<'_>) -> Result<ValidCreate, &'static str> {
    if !valid_room_id(&req.room_id, limits.server_name) {
        return Err("bad_room_id");
    }
    let count = req.count.unwrap_or(1);
    if count == 0 || count > limits.max_guests {
        return Err("bad_count");
    }
    let labels = match req.labels {
        None => vec![String::new(); count as usize],
        Some(labels) => {
            if labels.len() as u64 != count
                || labels
                    .iter()
                    .any(|l| l.chars().count() > MAX_LABEL_CHARS || l.chars().any(char::is_control))
            {
                return Err("bad_labels");
            }
            labels
        }
    };
    let kind = match req.kind.as_deref() {
        None | Some("single") => Kind::Single,
        Some("open") => Kind::Open,
        Some(_) => return Err("bad_kind"),
    };
    let max_guests = match kind {
        Kind::Single => match req.max_guests {
            None | Some(1) => 1,
            Some(_) => return Err("bad_max_guests"),
        },
        Kind::Open => {
            if !limits.allow_open_links {
                return Err("open_links_disabled");
            }
            let uses = req.max_guests.unwrap_or(limits.open_link_max_uses);
            if uses == 0 || uses > limits.open_link_max_uses {
                return Err("bad_max_guests");
            }
            uses
        }
    };
    let expires_in = req.expires_in.unwrap_or(DEFAULT_EXPIRES_IN);
    let ceiling = match kind {
        Kind::Single => MAX_EXPIRES_IN,
        Kind::Open => MAX_EXPIRES_IN.min(limits.open_link_max_ttl_secs),
    };
    if expires_in == 0 || expires_in > ceiling {
        return Err("bad_expires_in");
    }
    let session_secs = req.session_secs.unwrap_or(DEFAULT_SESSION_SECS);
    if !(MIN_SESSION_SECS..=MAX_SESSION_SECS).contains(&session_secs) {
        return Err("bad_session_secs");
    }
    Ok(ValidCreate {
        room_id: req.room_id,
        count,
        labels,
        kind,
        max_guests,
        expires_in,
        session_secs,
        recording_expected: req.recording_expected.unwrap_or(false),
    })
}

/// A fresh invite id: 96 random bits from the operating system, as 16 characters
/// of unpadded base64url. It is a handle in a URL path, not a credential.
pub fn new_invite_id() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Whether `id` has the shape [`new_invite_id`] makes. Checked on a path segment
/// before it becomes part of a Redis key.
pub fn valid_invite_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A fresh invite secret: `gi_` and 32 base62 characters (about 190 bits) from
/// the operating system. Shown once; only [`secret_hash`] is stored.
pub fn new_secret() -> String {
    let random: String = (0..32)
        .map(|_| BASE62[OsRng.gen_range(0..BASE62.len())] as char)
        .collect();
    format!("gi_{random}")
}

/// Lowercase hex SHA-256 of a secret: the only form of it that is stored.
pub fn secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// The link a host hands a guest. The secret rides in the fragment, which a
/// browser never sends to a server.
pub fn join_link(issuer: &str, id: &str, secret: &str) -> String {
    format!("{}/guest/join/{id}#{secret}", issuer.trim_end_matches('/'))
}

/// Whether a `guest_hosts` entry names this caller. An entry that starts with
/// `did:` is a DID and matches `did` byte for byte; anything else is a localpart
/// and matches `username` (`TokenMetadata.username`, already lowercase) exactly.
pub fn host_entry_matches(entry: &str, username: &str, did: &str) -> bool {
    if entry.starts_with("did:") {
        entry == did
    } else {
        entry == username
    }
}

/// Whether the caller is in `guest_hosts`.
pub fn is_host(hosts: &[String], username: &str, did: &str) -> bool {
    hosts
        .iter()
        .any(|entry| host_entry_matches(entry, username, did))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits<'static> {
        Limits {
            server_name: "example.org",
            max_guests: 10,
            allow_open_links: false,
            open_link_max_uses: 10,
            open_link_max_ttl_secs: 86_400,
        }
    }

    fn req(json: serde_json::Value) -> CreateRequest {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn defaults_fill_in() {
        let v = validate(
            req(serde_json::json!({"room_id": "!abc:example.org"})),
            &limits(),
        )
        .unwrap();
        assert_eq!(v.count, 1);
        assert_eq!(v.labels, vec![String::new()]);
        assert_eq!(v.kind, Kind::Single);
        assert_eq!(v.max_guests, 1);
        assert_eq!(v.expires_in, 86_400);
        assert_eq!(v.session_secs, 7_200);
        assert!(!v.recording_expected);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let r: Result<CreateRequest, _> =
            serde_json::from_value(serde_json::json!({"room_id": "!a", "expires": 5}));
        assert!(r.is_err());
    }

    #[test]
    fn ids_and_secrets_have_their_shape() {
        let id = new_invite_id();
        assert_eq!(id.len(), 16);
        assert!(valid_invite_id(&id));
        assert_ne!(id, new_invite_id());
        let s = new_secret();
        assert!(s.starts_with("gi_") && s.len() == 35);
        assert!(s[3..].bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(secret_hash("gi_x").len(), 64);
        assert!(!valid_invite_id("short") && !valid_invite_id("a/b/c/d/e/f/g/h/i"));
        assert!(!valid_invite_id("0123456789abcde%"));
    }

    #[test]
    fn the_link_keeps_the_secret_in_the_fragment() {
        assert_eq!(
            join_link("https://id.example.org/", "AbC", "gi_s"),
            "https://id.example.org/guest/join/AbC#gi_s"
        );
    }

    #[test]
    fn host_entries_match_localparts_on_the_username_and_dids_byte_for_byte() {
        assert!(host_entry_matches("alice", "alice", "did:key:zAbC"));
        assert!(!host_entry_matches("Alice", "alice", "did:key:zAbC"));
        assert!(host_entry_matches("did:key:zAbC", "x", "did:key:zAbC"));
        assert!(!host_entry_matches("did:key:zabc", "x", "did:key:zAbC"));
        // A DID entry never matches on the username, nor a localpart on the DID.
        assert!(!host_entry_matches("did:key:zAbC", "did:key:zAbC", "other"));
        assert!(!host_entry_matches("alice", "x", "alice"));
        assert!(is_host(&["bob".into(), "alice".into()], "alice", "d"));
        assert!(!is_host(&[], "alice", "d"));
    }
}
