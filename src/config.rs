use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub base_url: Url,
    /// PKCS#8 PEM for the ES256 (P-256 ECDSA) signing key.
    /// If absent, a random key is generated on startup.
    pub signing_key_pem: Option<String>,
    pub redis_url: Url,
    pub default_clients: HashMap<String, String>,
    pub require_secret: bool,
    /// ID token lifetime in seconds. Default: 300 (5 minutes).
    pub id_token_ttl_secs: u64,
    pub eth_provider: Option<Url>,
    /// ENS reverse-lookup API URL. Appended with `/{address}` and must return
    /// JSON with an `ens_primary` field. Default: `https://api.ensdata.net`.
    /// Set to empty string to disable ENS resolution entirely.
    pub ens_api_url: Option<Url>,
    /// DID method names accepted at sign-in (e.g. ["pkh"]).
    /// Must be a subset of the methods registered in aqua-auth.
    pub supported_did_methods: Vec<String>,
    /// did:pkh namespaces accepted at sign-in (e.g. ["eip155", "ed25519", "p256"]).
    /// Must be a subset of the cipher suites registered in aqua-auth.
    pub supported_pkh_namespaces: Vec<String>,
    /// WebAuthn Relying Party ID (domain). Defaults to the hostname of `base_url`.
    pub rp_id: Option<String>,
    /// WebAuthn expected origin. Defaults to `base_url` (scheme + host + port).
    pub rp_origin: Option<String>,
    /// Shared secret for MSC3861 token introspection (Synapse delegates auth).
    /// When set, the token endpoint issues opaque tokens stored in Redis instead
    /// of JWTs, and the `/oauth2/introspect` endpoint becomes active.
    /// Env: `SIWEOIDC_MAS_SHARED_SECRET`
    pub mas_shared_secret: Option<String>,
    /// Synapse homeserver endpoint for provisioning calls (MSC3861 Agent C).
    /// Example: `http://matrix_synapse:8080`
    /// Env: `SIWEOIDC_SYNAPSE_ENDPOINT`
    pub synapse_endpoint: Option<Url>,
    /// Log output format: "pretty" (default, human-readable) or "json" (structured).
    /// Env: `SIWEOIDC_LOG_FORMAT`
    pub log_format: String,
    /// Matrix homeserver server_name (e.g. `matrix.inblock.io`).
    /// Used for cross-signing pre-flight checks during device approval.
    /// Env: `SIWEOIDC_MATRIX_SERVER_NAME`
    pub matrix_server_name: Option<String>,
    /// MSC4191: Account management URI advertised in OIDC discovery.
    /// When absent, defaults to `{base_url}/account`.
    /// Env: `SIWEOIDC_ACCOUNT_MANAGEMENT_URI`
    pub account_management_uri: Option<Url>,
    /// Lifetime, in seconds, of an admin-scoped token minted at
    /// `POST /oauth2/admin_token`.
    ///
    /// Clamped in code to `admin_token::ADMIN_TOKEN_TTL_MIN..=ADMIN_TOKEN_TTL_MAX`
    /// — the configured value cannot promote the mint into a long-lived standing
    /// admin credential. Default: 300 (5 minutes).
    /// Env: `SIWEOIDC_ADMIN_TOKEN_TTL_SECS`
    pub admin_token_ttl_secs: u64,
    /// Localpart of the Synapse service user that admin-scoped tokens are bound
    /// to. Synapse 1.159 resolves the introspected `username` against its own
    /// `users` table, so this account is auto-provisioned (idempotently) on the
    /// first mint. Default: `siwx-admin`.
    /// Env: `SIWEOIDC_ADMIN_TOKEN_LOCALPART`
    pub admin_token_localpart: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(127, 0, 0, 1).into(),
            port: 8000,
            base_url: Url::parse("http://127.0.0.1:8000").unwrap(),
            signing_key_pem: None,
            redis_url: Url::parse("redis://localhost").unwrap(),
            default_clients: HashMap::default(),
            require_secret: true,
            id_token_ttl_secs: 300,
            eth_provider: None,
            ens_api_url: Some(Url::parse("https://api.ensdata.net").unwrap()),
            supported_did_methods: vec!["pkh".to_string(), "key".to_string()],
            supported_pkh_namespaces: vec![
                "eip155".to_string(),
                "ed25519".to_string(),
                "p256".to_string(),
            ],
            rp_id: None,
            rp_origin: None,
            mas_shared_secret: None,
            synapse_endpoint: None,
            log_format: "pretty".to_string(),
            matrix_server_name: None,
            account_management_uri: None,
            admin_token_ttl_secs: 300,
            admin_token_localpart: "siwx-admin".to_string(),
        }
    }
}
