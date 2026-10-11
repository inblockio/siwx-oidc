//! The guest server path (work package S1). Slice A holds the start-up check of
//! its configuration, slice B the `/guest` router and its shared layers; the
//! endpoints arrive in later slices.
//!
//! There is deliberately no `guest_key_secret`: a guest's identity is a
//! `did:key` the browser makes, so the server never holds or derives a guest key.

use crate::config::Config;
use url::Url;

pub mod handoff;
pub mod invite;
pub mod layers;
pub mod redeem;
pub mod routes;
pub mod teardown;

/// The values `guest_client_topology` may take.
pub const TOPOLOGIES: [&str; 2] = ["same-site", "cross-site"];

/// The guest client as the static public client it is (S4b): `guest_client_id`, exactly
/// `guest_client_redirect_uris`, `token_endpoint_auth_method = none` (PKCE S256 is
/// mandatory on the guest path), the authorization-code and refresh grants, no expiry and
/// no `/register`. Its secret is random and thrown away: nobody can authenticate with it.
/// `None` with guest mode off.
pub fn guest_client_entry(
    config: &Config,
) -> Result<Option<(String, siwx_oidc::db::ClientEntry)>, String> {
    use openidconnect::core::{CoreClientAuthMethod, CoreGrantType};
    use openidconnect::RedirectUrl;
    use rand::RngCore as _;
    if !config.guest_enabled {
        return Ok(None);
    }
    let id = config
        .guest_client_id
        .clone()
        .filter(|i| !i.is_empty())
        .ok_or("guest_client_id is required when guest_enabled is true")?;
    let redirects = config
        .guest_client_redirect_uris
        .iter()
        .map(|u| RedirectUrl::new(u.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("guest_client_redirect_uris: {e}"))?;
    if redirects.is_empty() {
        return Err("guest_client_redirect_uris must name at least one URI".into());
    }
    let metadata = siwx_oidc::db::SiwxClientMetadata::new(
        redirects,
        siwx_oidc::db::LogoutClientMetadata::default(),
    )
    .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None))
    .set_grant_types(Some(vec![
        CoreGrantType::AuthorizationCode,
        CoreGrantType::RefreshToken,
    ]));
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let secret = hex::encode(secret);
    Ok(Some((
        id,
        siwx_oidc::db::ClientEntry::new(&secret, metadata, None),
    )))
}

/// Whether `url`'s host is a local-development host (`localhost`, `127.0.0.1`, `[::1]`).
fn is_local_host(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("::1")
    )
}

/// Refuse a misconfigured guest mode (GP-SEC-51, adapted).
///
/// Disabled (`guest_enabled = false`): `Ok`, nothing else is looked at. Enabled: every
/// problem found is listed, each naming the key, joined by `; `. Start-up turns an `Err`
/// into a `FATAL` panic before anything binds.
///
/// Rules: `mas_shared_secret`, `synapse_endpoint`, `matrix_server_name`, `guest_client_url`
/// and `guest_client_id` are set; `guest_client_redirect_uris` and `guest_hosts` are not
/// empty; `"key"` is in `supported_did_methods`; `guest_client_topology` is `same-site` or
/// `cross-site`; every quota and `guest_session_max_secs` is non-zero; `base_url`,
/// `guest_client_url` and every redirect URI are https. When `base_url`'s host is
/// `localhost`, `127.0.0.1` or `[::1]` (local development) http is allowed for all of them.
/// `synapse_endpoint` is exempt from the https rule: it is an internal admin endpoint
/// (typically `http://synapse:8008` on a private network).
pub fn validate_guest_config(config: &Config) -> Result<(), String> {
    if !config.guest_enabled {
        return Ok(());
    }
    let mut problems: Vec<String> = Vec::new();

    if config
        .mas_shared_secret
        .as_deref()
        .is_none_or(str::is_empty)
    {
        problems.push("mas_shared_secret is required when guest_enabled is true".into());
    }
    if config.synapse_endpoint.is_none() {
        problems.push("synapse_endpoint is required when guest_enabled is true".into());
    }
    if config
        .matrix_server_name
        .as_deref()
        .is_none_or(str::is_empty)
    {
        problems.push("matrix_server_name is required when guest_enabled is true".into());
    }
    if config.guest_client_url.is_none() {
        problems.push("guest_client_url is required when guest_enabled is true".into());
    }
    if config.guest_client_id.as_deref().is_none_or(str::is_empty) {
        problems.push("guest_client_id is required when guest_enabled is true".into());
    }
    if config.guest_client_redirect_uris.is_empty() {
        problems.push("guest_client_redirect_uris must name at least one URI".into());
    }
    if config.guest_hosts.iter().all(|h| h.trim().is_empty()) {
        problems.push("guest_hosts must name at least one host".into());
    }
    if !config.supported_did_methods.iter().any(|m| m == "key") {
        problems.push(
            "supported_did_methods must include \"key\" (a guest is a browser-made did:key)".into(),
        );
    }
    if !TOPOLOGIES.contains(&config.guest_client_topology.as_str()) {
        problems.push(format!(
            "guest_client_topology = {:?}: must be one of {}",
            config.guest_client_topology,
            TOPOLOGIES.join(", ")
        ));
    }

    if !["off", "optional", "required"].contains(&config.guest_email_policy.as_str()) {
        problems.push(format!(
            "guest_email_policy = {:?}: must be one of off, optional, required",
            config.guest_email_policy
        ));
    }

    let numbers: [(&str, u64); 15] = [
        ("guest_session_max_secs", config.guest_session_max_secs),
        ("guest_max_guests", config.guest_max_guests),
        ("guest_host_max_invites", config.guest_host_max_invites),
        (
            "guest_host_max_live_guests",
            config.guest_host_max_live_guests,
        ),
        (
            "guest_host_invites_per_hour",
            config.guest_host_invites_per_hour,
        ),
        ("guest_global_max_active", config.guest_global_max_active),
        ("guest_daily_mint_max", config.guest_daily_mint_max),
        ("guest_max_claimed", config.guest_max_claimed),
        ("guest_max_devices", config.guest_max_devices),
        ("guest_handoff_per_minute", config.guest_handoff_per_minute),
        ("guest_open_link_max_uses", config.guest_open_link_max_uses),
        (
            "guest_open_link_max_ttl_secs",
            config.guest_open_link_max_ttl_secs,
        ),
        (
            "guest_host_max_open_invites",
            config.guest_host_max_open_invites,
        ),
        (
            "guest_brake_reaping_count",
            config.guest_brake_reaping_count,
        ),
        ("guest_brake_reaping_secs", config.guest_brake_reaping_secs),
    ];
    for (key, value) in numbers {
        if value == 0 {
            problems.push(format!("{key} must be greater than zero"));
        }
    }

    let local = is_local_host(&config.base_url);
    let mut need_https = |key: String, url: &Url| {
        if url.scheme() != "https" && !(local && url.scheme() == "http") {
            problems.push(format!(
                "{key} = {url}: must be https (http is allowed only when base_url is localhost, 127.0.0.1 or [::1])"
            ));
        }
    };
    need_https("base_url".into(), &config.base_url);
    if let Some(url) = &config.guest_client_url {
        need_https("guest_client_url".into(), url);
    }
    for (i, url) in config.guest_client_redirect_uris.iter().enumerate() {
        need_https(format!("guest_client_redirect_uris[{i}]"), url);
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "invalid guest configuration: {}",
            problems.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration that passes with guest mode on.
    fn valid() -> Config {
        Config {
            guest_enabled: true,
            base_url: Url::parse("https://id.example.org").unwrap(),
            mas_shared_secret: Some("s3cret".into()),
            synapse_endpoint: Some(Url::parse("http://synapse:8008").unwrap()),
            matrix_server_name: Some("matrix.example.org".into()),
            guest_client_url: Some(Url::parse("https://meet.example.org/start").unwrap()),
            guest_client_id: Some("meet".into()),
            guest_client_redirect_uris: vec![Url::parse("https://meet.example.org/cb").unwrap()],
            guest_hosts: vec!["alice".into()],
            ..Config::default()
        }
    }

    fn refused(config: &Config, key: &str) {
        let err = validate_guest_config(config).expect_err(key);
        assert!(err.contains(key), "{key} not named in: {err}");
    }

    #[test]
    fn the_valid_baseline_passes() {
        validate_guest_config(&valid()).unwrap();
    }

    #[test]
    fn disabled_ignores_everything() {
        let c = Config {
            guest_enabled: false,
            mas_shared_secret: None,
            guest_hosts: vec![],
            guest_client_topology: "bogus".into(),
            guest_max_guests: 0,
            base_url: Url::parse("http://example.org").unwrap(),
            supported_did_methods: vec![],
            ..valid()
        };
        validate_guest_config(&c).unwrap();
        validate_guest_config(&Config::default()).unwrap();
    }

    #[test]
    fn each_refusal_names_its_key() {
        type Case = (&'static str, Box<dyn Fn(&mut Config)>);
        let cases: Vec<Case> = vec![
            (
                "mas_shared_secret",
                Box::new(|c| c.mas_shared_secret = None),
            ),
            (
                "mas_shared_secret",
                Box::new(|c| c.mas_shared_secret = Some(String::new())),
            ),
            ("synapse_endpoint", Box::new(|c| c.synapse_endpoint = None)),
            (
                "matrix_server_name",
                Box::new(|c| c.matrix_server_name = None),
            ),
            ("guest_client_url", Box::new(|c| c.guest_client_url = None)),
            ("guest_client_id", Box::new(|c| c.guest_client_id = None)),
            (
                "guest_client_redirect_uris",
                Box::new(|c| c.guest_client_redirect_uris.clear()),
            ),
            ("guest_hosts", Box::new(|c| c.guest_hosts.clear())),
            (
                "supported_did_methods",
                Box::new(|c| c.supported_did_methods = vec!["pkh".into()]),
            ),
            (
                "guest_client_topology",
                Box::new(|c| c.guest_client_topology = "sideways".into()),
            ),
            (
                "guest_email_policy",
                Box::new(|c| c.guest_email_policy = "maybe".into()),
            ),
            (
                "guest_session_max_secs",
                Box::new(|c| c.guest_session_max_secs = 0),
            ),
            ("guest_max_guests", Box::new(|c| c.guest_max_guests = 0)),
            (
                "guest_host_max_invites",
                Box::new(|c| c.guest_host_max_invites = 0),
            ),
            (
                "guest_host_max_live_guests",
                Box::new(|c| c.guest_host_max_live_guests = 0),
            ),
            (
                "guest_host_invites_per_hour",
                Box::new(|c| c.guest_host_invites_per_hour = 0),
            ),
            (
                "guest_global_max_active",
                Box::new(|c| c.guest_global_max_active = 0),
            ),
            (
                "guest_daily_mint_max",
                Box::new(|c| c.guest_daily_mint_max = 0),
            ),
            ("guest_max_claimed", Box::new(|c| c.guest_max_claimed = 0)),
            ("guest_max_devices", Box::new(|c| c.guest_max_devices = 0)),
            (
                "guest_handoff_per_minute",
                Box::new(|c| c.guest_handoff_per_minute = 0),
            ),
            (
                "guest_open_link_max_uses",
                Box::new(|c| c.guest_open_link_max_uses = 0),
            ),
            (
                "guest_open_link_max_ttl_secs",
                Box::new(|c| c.guest_open_link_max_ttl_secs = 0),
            ),
            (
                "guest_host_max_open_invites",
                Box::new(|c| c.guest_host_max_open_invites = 0),
            ),
            (
                "guest_brake_reaping_count",
                Box::new(|c| c.guest_brake_reaping_count = 0),
            ),
            (
                "guest_brake_reaping_secs",
                Box::new(|c| c.guest_brake_reaping_secs = 0),
            ),
            (
                "base_url",
                Box::new(|c| c.base_url = Url::parse("http://id.example.org").unwrap()),
            ),
            (
                "guest_client_url",
                Box::new(|c| {
                    c.guest_client_url = Some(Url::parse("http://meet.example.org/").unwrap())
                }),
            ),
            (
                "guest_client_redirect_uris[1]",
                Box::new(|c| {
                    c.guest_client_redirect_uris
                        .push(Url::parse("http://meet.example.org/cb2").unwrap())
                }),
            ),
        ];
        for (key, mutate) in cases {
            let mut c = valid();
            mutate(&mut c);
            refused(&c, key);
        }
    }

    #[test]
    fn the_topology_accepts_exactly_its_two_values() {
        for ok in ["same-site", "cross-site"] {
            let c = Config {
                guest_client_topology: ok.into(),
                ..valid()
            };
            validate_guest_config(&c).unwrap();
        }
    }

    #[test]
    fn synapse_endpoint_may_be_plain_http() {
        let c = Config {
            synapse_endpoint: Some(Url::parse("http://10.0.0.5:8008").unwrap()),
            ..valid()
        };
        validate_guest_config(&c).unwrap();
    }

    #[test]
    fn http_is_allowed_everywhere_when_base_url_is_local() {
        for base in [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            let c = Config {
                base_url: Url::parse(base).unwrap(),
                guest_client_url: Some(Url::parse("http://localhost:5173/start").unwrap()),
                guest_client_redirect_uris: vec![Url::parse("http://localhost:5173/cb").unwrap()],
                ..valid()
            };
            validate_guest_config(&c).unwrap_or_else(|e| panic!("{base}: {e}"));
        }
    }

    #[test]
    fn a_local_client_url_does_not_excuse_a_public_base_url() {
        let c = Config {
            guest_client_url: Some(Url::parse("http://localhost:5173/start").unwrap()),
            ..valid()
        };
        refused(&c, "guest_client_url");
    }

    #[test]
    fn every_problem_is_listed_at_once() {
        let c = Config {
            guest_client_id: None,
            guest_hosts: vec![],
            ..valid()
        };
        let err = validate_guest_config(&c).unwrap_err();
        assert!(
            err.contains("guest_client_id") && err.contains("guest_hosts"),
            "{err}"
        );
    }
}
