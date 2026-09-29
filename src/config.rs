// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};
use url::Url;

/// The documented environment prefix: `SIWXOIDC_PORT`, `SIWXOIDC_BASE_URL`, …
pub const ENV_PREFIX: &str = "SIWXOIDC_";
/// The prefix inherited from siwe-oidc. Still read, with no removal scheduled,
/// because live deployments set it. It ranks below [`ENV_PREFIX`].
pub const LEGACY_ENV_PREFIX: &str = "SIWEOIDC_";
/// The documented config file, looked up in the working directory and then in
/// each parent directory (figment's `Toml::file` search).
pub const CONFIG_FILE: &str = "siwx-oidc.toml";
/// The config file name inherited from siwe-oidc. Still read, below
/// [`CONFIG_FILE`].
pub const LEGACY_CONFIG_FILE: &str = "siwe-oidc.toml";

/// The layered configuration source. Precedence, lowest to highest:
///
/// 1. [`Config::default`]
/// 2. [`LEGACY_CONFIG_FILE`] (`siwe-oidc.toml`)
/// 3. [`CONFIG_FILE`] (`siwx-oidc.toml`)
/// 4. [`LEGACY_ENV_PREFIX`] variables (`SIWEOIDC_*`)
/// 5. [`ENV_PREFIX`] variables (`SIWXOIDC_*`)
///
/// So a key set under both names takes the new name's value, and a deployment
/// that sets only the legacy names keeps working unchanged. Every layer is
/// optional: a missing file contributes nothing, which is how the container
/// image runs (it ships no config file).
///
/// The files are `nested()`: their top-level tables are figment profiles
/// (`[default]`, `[global]`). Both env prefixes are `global()` and split on
/// `__`, so `SIWXOIDC_DEFAULT_CLIENTS__MYCLIENT=…` sets
/// `default_clients.myclient`. Prefix matching is case-insensitive, as in
/// figment itself.
///
/// Figment ranks profiles before merge order: anything in the `global`
/// profile beats anything in `default`. The ladder above therefore holds
/// between layers that write the same profile, and a file's `[default]`
/// table always ranks below the environment.
pub fn figment() -> Figment {
    Figment::from(Serialized::defaults(Config::default()))
        .merge(Toml::file(LEGACY_CONFIG_FILE).nested())
        .merge(Toml::file(CONFIG_FILE).nested())
        .merge(Env::prefixed(LEGACY_ENV_PREFIX).split("__").global())
        .merge(Env::prefixed(ENV_PREFIX).split("__").global())
}

/// The legacy configuration names a figment actually draws on, for the startup
/// deprecation warning. It holds variable NAMES and a file path only, never a
/// value: several of these variables carry secrets (`…_SIGNING_KEY_PEM`,
/// `…_MAS_SHARED_SECRET`).
#[derive(Debug, Default, PartialEq)]
pub struct LegacyNames {
    /// `SIWEOIDC_*` variables present in the process environment, sorted.
    pub env_vars: Vec<String>,
    /// The `siwe-oidc.toml` the figment found and read, if any.
    pub file: Option<PathBuf>,
}

impl LegacyNames {
    /// Inspects the process environment and the files `figment` resolved.
    pub fn detect(figment: &Figment) -> Self {
        LegacyNames {
            env_vars: legacy_env_var_names(std::env::vars_os().map(|(key, _)| key)),
            file: figment.metadata().find_map(|md| {
                let path = md.source.as_ref()?.file_path()?;
                (path.file_name()? == LEGACY_CONFIG_FILE).then(|| path.to_path_buf())
            }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.env_vars.is_empty() && self.file.is_none()
    }
}

/// The keys among `keys` that the legacy env provider would read, sorted.
/// Takes the keys alone, so no value can reach the caller.
fn legacy_env_var_names(keys: impl IntoIterator<Item = std::ffi::OsString>) -> Vec<String> {
    let mut names: Vec<String> = keys
        .into_iter()
        .map(|key| key.to_string_lossy().into_owned())
        .filter(|key| has_prefix(key, LEGACY_ENV_PREFIX))
        .collect();
    names.sort();
    names
}

/// ASCII case-insensitive prefix test, matching how figment's
/// `Env::prefixed` selects variables.
fn has_prefix(key: &str, prefix: &str) -> bool {
    key.len() >= prefix.len()
        && key.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Deserializes an optional URL, treating an empty (or all-whitespace) string
/// as `None`. Environment variables cannot express "unset" once a default
/// exists, so an empty value is how an operator switches an optional URL off.
fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<Url>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(raw) if raw.trim().is_empty() => Ok(None),
        Some(raw) => Url::parse(raw.trim())
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Deserializes an optional absolute `http`/`https` URL, treating an empty
/// string as `None` like [`empty_string_as_none`]. Anything else, a relative
/// path or another scheme, is an error, so a bad value stops the server at
/// startup instead of being published in discovery.
fn http_url_or_none<'de, D>(deserializer: D) -> Result<Option<Url>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(url) = empty_string_as_none(deserializer)? else {
        return Ok(None);
    };
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(serde::de::Error::custom(format!(
            "expected an absolute http(s) URL, got {url}"
        )));
    }
    Ok(Some(url))
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub base_url: Url,
    /// PKCS#8 PEM for the ES256 (P-256 ECDSA) signing key.
    /// If absent, a random key is generated on startup.
    pub signing_key_pem: Option<String>,
    /// One or more **public** (SPKI `-----BEGIN PUBLIC KEY-----`) P-256 PEM
    /// blocks, concatenated, for signing keys this provider has RETIRED.
    ///
    /// They are appended to the published JWKS with their own derived `kid`s so
    /// that DID assertions minted before a rotation stay verifiable. Signing
    /// always uses `signing_key_pem` alone. A **private** key here is a hard
    /// startup error — see `oidc::parse_retired_verification_keys` for why the
    /// public-only restriction is load-bearing rather than fussy.
    ///
    /// Env: `SIWEOIDC_RETIRED_SIGNING_KEYS_PEM`
    pub retired_signing_keys_pem: Option<String>,
    pub redis_url: Url,
    pub default_clients: HashMap<String, String>,
    pub require_secret: bool,
    /// ID token lifetime in seconds. Default: 300 (5 minutes).
    pub id_token_ttl_secs: u64,
    pub eth_provider: Option<Url>,
    /// ENS reverse-lookup API URL. Appended with `/{address}` and must return
    /// JSON with an `ens_primary` field. Opt-in, no default: the API receives
    /// the Ethereum address of every `did:pkh:eip155` sign-in, and a default
    /// deployment must not send that to a third party. Setting it (for
    /// example `https://api.ensdata.net`) enables the HTTP lookup; an empty
    /// string (`SIWXOIDC_ENS_API_URL=`) disables it again.
    #[serde(default, deserialize_with = "empty_string_as_none")]
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
    /// The MAS shared secret (MSC3861 mode); must equal Synapse's
    /// `matrix_authentication_service.secret`. It authenticates Synapse to
    /// `/oauth2/introspect` and `/oauth2/admin_token`, and this provider to
    /// Synapse's `/_synapse/mas/*`. When set, issued tokens carry the Matrix
    /// `mat_`/`mcr_` prefixes and scopes (tokens are opaque and stored in Redis
    /// in both modes) and those two endpoints become active.
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
    /// Needed wherever a full mxid is built: account and device actions,
    /// session teardown, `io.inblock.did` publication, the `io.inblock.mxid`
    /// userinfo claim and `GET /resolve`. Without it those degrade or are skipped.
    /// Env: `SIWEOIDC_MATRIX_SERVER_NAME`
    pub matrix_server_name: Option<String>,
    /// This deployment's terms of service, advertised as `op_tos_uri` in
    /// discovery. Unset or empty (the default): the field is omitted, because
    /// no deployment should advertise terms it did not write. An absolute
    /// http(s) URL, checked at startup.
    /// Env: `SIWXOIDC_OP_TOS_URI`
    #[serde(default, deserialize_with = "http_url_or_none")]
    pub op_tos_uri: Option<Url>,
    /// This deployment's privacy policy, advertised as `op_policy_uri` in
    /// discovery. Same rules as [`Config::op_tos_uri`].
    /// Env: `SIWXOIDC_OP_POLICY_URI`
    #[serde(default, deserialize_with = "http_url_or_none")]
    pub op_policy_uri: Option<Url>,
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
            retired_signing_keys_pem: None,
            redis_url: Url::parse("redis://localhost").unwrap(),
            default_clients: HashMap::default(),
            require_secret: true,
            id_token_ttl_secs: 300,
            eth_provider: None,
            ens_api_url: None,
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
            op_tos_uri: None,
            op_policy_uri: None,
            account_management_uri: None,
            admin_token_ttl_secs: 300,
            admin_token_localpart: "siwx-admin".to_string(),
        }
    }
}

#[cfg(test)]
// `figment::Jail::expect_with` fixes the closure's return type to
// `figment::Result<()>`; its error type is figment's, not ours to shrink.
#[allow(clippy::result_large_err)]
mod tests {
    //! The naming contract for configuration sources. Each test runs in a
    //! `figment::Jail`: a fresh temporary working directory (so no real
    //! `siwe-oidc.toml` / `siwx-oidc.toml` is in reach) and env vars that are
    //! restored when the jail drops.

    use super::*;
    use figment::Jail;

    /// Removes every `SIWXOIDC_*` / `SIWEOIDC_*` variable the ambient
    /// environment carries (a shell that sourced `e2e/env.sh` has a dozen),
    /// so each test sees only the layers it sets up. Each variable is first
    /// registered with the jail, which records the original value and
    /// restores it on drop.
    fn scrub_config_env(jail: &mut Jail) {
        let ambient: Vec<String> = std::env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .filter(|key| has_prefix(key, ENV_PREFIX) || has_prefix(key, LEGACY_ENV_PREFIX))
            .collect();
        for key in ambient {
            jail.set_env(&key, "");
            std::env::remove_var(&key);
        }
    }

    #[test]
    fn new_env_prefix_is_read() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWXOIDC_PORT", 4101);
            assert_eq!(figment().extract::<Config>()?.port, 4101);
            Ok(())
        });
    }

    #[test]
    fn legacy_env_prefix_is_still_read() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWEOIDC_PORT", 4102);
            assert_eq!(figment().extract::<Config>()?.port, 4102);
            Ok(())
        });
    }

    #[test]
    fn new_env_prefix_beats_legacy_when_both_are_set() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWEOIDC_PORT", 4103);
            jail.set_env("SIWXOIDC_PORT", 4104);
            assert_eq!(figment().extract::<Config>()?.port, 4104);
            Ok(())
        });
    }

    #[test]
    fn both_env_prefixes_keep_the_double_underscore_split() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWEOIDC_DEFAULT_CLIENTS__ALPHA", "from-legacy");
            jail.set_env("SIWXOIDC_DEFAULT_CLIENTS__BETA", "from-new");
            let clients = figment().extract::<Config>()?.default_clients;
            assert_eq!(
                clients.get("alpha").map(String::as_str),
                Some("from-legacy")
            );
            assert_eq!(clients.get("beta").map(String::as_str), Some("from-new"));
            Ok(())
        });
    }

    #[test]
    fn legacy_file_is_still_read() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.create_file(LEGACY_CONFIG_FILE, "[default]\nport = 4105\n")?;
            assert_eq!(figment().extract::<Config>()?.port, 4105);
            Ok(())
        });
    }

    #[test]
    fn new_file_overrides_legacy_file() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.create_file(LEGACY_CONFIG_FILE, "[default]\nport = 4106\n")?;
            jail.create_file(CONFIG_FILE, "[default]\nport = 4107\n")?;
            assert_eq!(figment().extract::<Config>()?.port, 4107);
            Ok(())
        });
    }

    #[test]
    fn missing_config_files_are_fine() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            let figment = figment();
            let config = figment.extract::<Config>()?;
            assert_eq!(config.port, Config::default().port);
            assert!(
                figment.metadata().all(|md| md
                    .source
                    .as_ref()
                    .and_then(|s| s.file_path())
                    .is_none()),
                "no provider may report a file source when no file exists"
            );
            Ok(())
        });
    }

    /// All five layers at once. Key `k` is written by every layer up to and
    /// including the one it is named for, so its value can only come from that
    /// layer if the order is exactly defaults < legacy file < new file <
    /// legacy env < new env.
    #[test]
    fn full_precedence_ladder() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.create_file(
                LEGACY_CONFIG_FILE,
                "[default]\nport = 1001\nid_token_ttl_secs = 1001\n\
                 admin_token_ttl_secs = 1001\nadmin_token_localpart = \"legacy-file\"\n",
            )?;
            jail.create_file(
                CONFIG_FILE,
                "[default]\nid_token_ttl_secs = 2002\n\
                 admin_token_ttl_secs = 2002\nadmin_token_localpart = \"new-file\"\n",
            )?;
            jail.set_env("SIWEOIDC_ADMIN_TOKEN_TTL_SECS", 3003);
            jail.set_env("SIWEOIDC_ADMIN_TOKEN_LOCALPART", "legacy-env");
            jail.set_env("SIWXOIDC_ADMIN_TOKEN_LOCALPART", "new-env");

            let config = figment().extract::<Config>()?;
            assert_eq!(
                config.log_format, "pretty",
                "untouched key keeps its default"
            );
            assert_eq!(config.port, 1001, "legacy file beats defaults");
            assert_eq!(config.id_token_ttl_secs, 2002, "new file beats legacy file");
            assert_eq!(
                config.admin_token_ttl_secs, 3003,
                "legacy env beats new file"
            );
            assert_eq!(
                config.admin_token_localpart, "new-env",
                "new env beats legacy env"
            );
            Ok(())
        });
    }

    #[test]
    fn client_key_file_var_is_not_server_config() {
        // `siwx-oidc-auth` reads `SIWX_KEY_FILE`. The server prefix is
        // `SIWXOIDC_`, so the two must never meet.
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWX_KEY_FILE", "/nonexistent/identity.pem");
            assert_eq!(Env::prefixed(ENV_PREFIX).iter().count(), 0);
            assert_eq!(Env::prefixed(LEGACY_ENV_PREFIX).iter().count(), 0);
            figment().extract::<Config>()?;
            Ok(())
        });
    }

    #[test]
    fn legacy_env_names_are_matched_like_figment_and_reported_by_name() {
        let keys = [
            "SIWXOIDC_PORT",
            "SIWEOIDC_SIGNING_KEY_PEM",
            "PATH",
            "siweoidc_base_url",
            "SIWX_KEY_FILE",
            "SIWEOIDC",
        ]
        .map(std::ffi::OsString::from);
        assert_eq!(
            legacy_env_var_names(keys),
            vec!["SIWEOIDC_SIGNING_KEY_PEM", "siweoidc_base_url"]
        );
    }

    #[test]
    fn deprecation_reports_legacy_env_and_file() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWEOIDC_PORT", 4108);
            jail.create_file(LEGACY_CONFIG_FILE, "")?;
            let legacy = LegacyNames::detect(&figment());
            assert_eq!(legacy.env_vars, vec!["SIWEOIDC_PORT"]);
            let file = legacy.file.expect("the legacy file must be reported");
            assert_eq!(file.file_name().unwrap(), LEGACY_CONFIG_FILE);
            Ok(())
        });
    }

    #[test]
    fn deprecation_is_silent_when_only_new_names_are_used() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWXOIDC_PORT", 4109);
            jail.create_file(CONFIG_FILE, "[default]\nport = 4110\n")?;
            assert!(LegacyNames::detect(&figment()).is_empty());
            Ok(())
        });
    }

    #[test]
    fn legal_uris_are_unset_by_default() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            let config: Config = figment().extract()?;
            assert!(config.op_tos_uri.is_none());
            assert!(config.op_policy_uri.is_none());
            Ok(())
        });
    }

    #[test]
    fn legal_uris_are_read_under_both_prefixes_and_from_the_file() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.set_env("SIWXOIDC_OP_TOS_URI", "https://id.example.org/terms");
            jail.set_env("SIWEOIDC_OP_POLICY_URI", "https://id.example.org/privacy");
            let config: Config = figment().extract()?;
            assert_eq!(
                config.op_tos_uri.as_ref().map(Url::as_str),
                Some("https://id.example.org/terms")
            );
            assert_eq!(
                config.op_policy_uri.as_ref().map(Url::as_str),
                Some("https://id.example.org/privacy")
            );

            scrub_config_env(jail);
            jail.create_file(
                CONFIG_FILE,
                "[default]\nop_tos_uri = \"https://id.example.org/file-terms\"\n",
            )?;
            let config: Config = figment().extract()?;
            assert_eq!(
                config.op_tos_uri.as_ref().map(Url::as_str),
                Some("https://id.example.org/file-terms")
            );
            // An empty value unsets it again, as for every optional URL.
            jail.set_env("SIWXOIDC_OP_TOS_URI", "");
            let config: Config = figment().extract()?;
            assert!(config.op_tos_uri.is_none());
            Ok(())
        });
    }

    /// A value that is not an absolute http(s) URL fails extraction, which is
    /// the startup `unwrap` in `axum_lib::main`: the server refuses to start
    /// rather than advertise it. The error names the key.
    #[test]
    fn a_legal_uri_that_is_not_an_absolute_http_url_fails_startup() {
        for bad in [
            "/legal/terms-of-use.html",
            "javascript:alert(1)",
            "mailto:legal@example.org",
            "not a url",
        ] {
            Jail::expect_with(|jail| {
                scrub_config_env(jail);
                jail.set_env("SIWXOIDC_OP_POLICY_URI", bad);
                let err = match figment().extract::<Config>() {
                    Ok(_) => panic!("{bad:?} must be refused"),
                    Err(e) => e.to_string(),
                };
                assert!(
                    err.to_ascii_lowercase().contains("op_policy_uri"),
                    "the error must name the key, got: {err}"
                );
                Ok(())
            });
        }
    }

    /// An empty value switches the lookup off even over a configured one, so
    /// an operator can disable ENS from the environment without editing the
    /// file.
    #[test]
    fn empty_ens_api_url_disables_the_lookup() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            jail.create_file(
                CONFIG_FILE,
                "[default]\nens_api_url = \"https://ens.example.org\"\n",
            )?;
            jail.set_env("SIWXOIDC_ENS_API_URL", "");
            let config: Config = figment().extract()?;
            assert!(config.ens_api_url.is_none());
            Ok(())
        });
    }

    /// ENS is opt-in: a default deployment sends no Ethereum address to a
    /// third-party API. Setting the variable, under either prefix, enables it.
    #[test]
    fn ens_api_url_is_off_by_default_and_enabled_by_setting_it() {
        Jail::expect_with(|jail| {
            scrub_config_env(jail);
            let config: Config = figment().extract()?;
            assert!(
                config.ens_api_url.is_none(),
                "a default deployment must make no third-party ENS call"
            );
            jail.set_env("SIWEOIDC_ENS_API_URL", "https://api.ensdata.net");
            let config: Config = figment().extract()?;
            assert_eq!(
                config.ens_api_url.as_ref().map(Url::as_str),
                Some("https://api.ensdata.net/")
            );
            jail.set_env("SIWXOIDC_ENS_API_URL", "https://ens.example.org");
            let config: Config = figment().extract()?;
            assert_eq!(
                config.ens_api_url.as_ref().map(Url::as_str),
                Some("https://ens.example.org/")
            );
            Ok(())
        });
    }
}
