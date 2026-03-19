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
    pub eth_provider: Option<Url>,
    /// DID method names accepted at sign-in (e.g. ["pkh"]).
    /// Must be a subset of the methods registered in siwx-core.
    pub supported_did_methods: Vec<String>,
    /// did:pkh namespaces accepted at sign-in (e.g. ["eip155", "ed25519", "p256"]).
    /// Must be a subset of the cipher suites registered in siwx-core.
    pub supported_pkh_namespaces: Vec<String>,
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
            require_secret: false,
            eth_provider: None,
            supported_did_methods: vec!["pkh".to_string()],
            supported_pkh_namespaces: vec![
                "eip155".to_string(),
                "ed25519".to_string(),
                "p256".to_string(),
            ],
        }
    }
}
