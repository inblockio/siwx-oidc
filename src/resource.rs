//! Resource indicators (RFC 8707): the resource servers this provider issues
//! access tokens for, and what a request bound to one of them is granted.
//!
//! A resource is a protected resource server (an MCP server, per the MCP
//! authorization specification of 2026-07-28) that validates this provider's
//! access tokens offline against `/jwk`. The operator names each one in
//! `resources` (`docs/configuration.md`): its canonical URI, exactly as the
//! resource server names itself in its protected-resource metadata and as a
//! client sends it in `resource`, and the scopes the resource understands.
//!
//! A request that names a `resource` is bound to it for its whole flow
//! (`/authorize`, the code, `/token`, the grant, every rotation), and its access
//! tokens are RFC 9068 JWTs whose `aud` is that URI, so a token issued for one
//! resource is refused by every other ([`crate::access_token`]). Its grant is
//! the requested scopes the resource lists, plus `offline_access` when it was
//! asked for and the client may refresh; nothing else. In particular `openid`
//! is not granted (no ID token is issued) and no Matrix scope is: the token is
//! for the resource, not for this provider or the homeserver.
//!
//! Pure: no I/O, so the binary and the tests read one set of rules.

use std::collections::HashMap;

use serde::Deserialize;
use url::Url;

/// One configured resource server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    /// The canonical URI (RFC 8707 section 2): absolute, `http` or `https`,
    /// no query, no fragment. Compared with a request's `resource` and
    /// written into `aud` byte for byte.
    pub uri: String,
    /// The scopes the resource understands, each one word (RFC 6749 section
    /// 3.3), in the configured order.
    pub scopes: Vec<String>,
}

/// The JSON form of a `resources` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    uri: String,
    scopes: Vec<String>,
}

/// The configured resources, validated at start-up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    resources: Vec<Resource>,
}

/// What a request bound to a resource is granted, decided once for the whole
/// flow and recomputed at the exchange from the same inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceGrant {
    /// The scope recorded on the grant and written into the token's `scope`:
    /// the requested scopes the resource lists, in the resource's order, then
    /// `offline_access` when granted.
    pub scope: String,
    /// Whether a refresh token is issued (`offline_access` requested and the
    /// client may refresh).
    pub refresh_token: bool,
    /// Whether the token response must name the scope, because it differs
    /// from the request (RFC 6749 section 5.1).
    pub report_scope: bool,
}

/// The scope words a resource may not list: each means something to this
/// provider or to the homeserver, never to a resource server.
const RESERVED_SCOPES: [&str; 3] = ["openid", "profile", "offline_access"];
const RESERVED_SCOPE_PREFIXES: [&str; 2] = ["urn:matrix:", "urn:synapse:"];

/// RFC 6749 section 3.3: a scope is a non-empty run of printable ASCII
/// without `"` and `\`.
fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// The refusals of a resource URI. Fixed texts that never quote the value.
fn check_uri(raw: &str) -> Result<(), &'static str> {
    let url = Url::parse(raw).map_err(|_| "`uri` is not an absolute URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("`uri` must be an http or https URL");
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("`uri` has no host");
    }
    if url.query().is_some() {
        return Err("`uri` must carry no query (RFC 8707 section 2)");
    }
    if url.fragment().is_some() {
        return Err("`uri` must carry no fragment (RFC 8707 section 2)");
    }
    if url.username() != "" || url.password().is_some() {
        return Err("`uri` must carry no user information");
    }
    // The string is compared byte for byte with what clients send and what the
    // resource server publishes, so it must already be in the form a parser
    // would write back: a lowercase scheme and host, no default port, and no
    // trailing slash on a bare origin or a path (`/mcp/` and `/mcp` would be
    // two resources).
    let canonical = url.as_str().trim_end_matches('/');
    let given = raw.trim_end_matches('/');
    if canonical != given {
        return Err("`uri` is not in canonical form: lowercase scheme and host, no default port");
    }
    if raw.ends_with('/') {
        return Err("`uri` must not end in a slash");
    }
    Ok(())
}

impl Registry {
    /// The configured `resources`, each a JSON `{"uri": …, "scopes": […]}`,
    /// validated. The error names the entry and the rule, never the value of
    /// a field (an operator's typo is still theirs to read in the file).
    pub fn parse(configured: &HashMap<String, String>) -> Result<Self, String> {
        let mut names: Vec<&String> = configured.keys().collect();
        names.sort();
        let mut resources: Vec<Resource> = Vec::with_capacity(names.len());
        for name in names {
            let refuse = |rule: &str| Err(format!("resources.{name}: {rule}"));
            let entry: Entry = match serde_json::from_str(&configured[name]) {
                Ok(entry) => entry,
                Err(_) => {
                    return refuse(
                        "not a valid resource entry: a JSON object with `uri` (a string) and \
                         `scopes` (an array of strings), and nothing else",
                    )
                }
            };
            if let Err(rule) = check_uri(&entry.uri) {
                return refuse(rule);
            }
            if resources.iter().any(|r| r.uri == entry.uri) {
                return refuse("`uri` is already named by another resource");
            }
            if entry.scopes.is_empty() {
                return refuse("`scopes` must list at least one scope");
            }
            for scope in &entry.scopes {
                if !is_scope_token(scope) {
                    return refuse(
                        "a scope is one word of printable characters (RFC 6749 section 3.3)",
                    );
                }
                if RESERVED_SCOPES.contains(&scope.as_str())
                    || RESERVED_SCOPE_PREFIXES.iter().any(|p| scope.starts_with(p))
                {
                    return refuse(
                        "`scopes` may not list `openid`, `profile`, `offline_access` or a \
                         `urn:matrix:` or `urn:synapse:` scope: those belong to this provider \
                         and the homeserver, not to a resource",
                    );
                }
                if entry.scopes.iter().filter(|s| *s == scope).count() > 1 {
                    return refuse("`scopes` lists a scope twice");
                }
            }
            resources.push(Resource {
                uri: entry.uri,
                scopes: entry.scopes,
            });
        }
        Ok(Registry { resources })
    }

    /// Whether any resource is configured.
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// The resource named exactly by `uri`, if configured.
    pub fn find(&self, uri: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| r.uri == uri)
    }

    /// Every scope any resource lists, each once, in configuration order; for
    /// discovery's `scopes_supported`.
    pub fn scopes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for scope in self.resources.iter().flat_map(|r| r.scopes.iter()) {
            if !out.contains(scope) {
                out.push(scope.clone());
            }
        }
        out
    }

    /// What a request for `resource` that asked for `requested` is granted:
    /// `None` when the resource is not configured or the request asks for
    /// none of its scopes (there is nothing to issue a token for). Otherwise
    /// the requested scopes the resource lists, in the resource's order, and
    /// `offline_access` when requested and `may_refresh`.
    pub fn grant(
        &self,
        resource: &str,
        requested: &str,
        may_refresh: bool,
    ) -> Option<ResourceGrant> {
        let entry = self.find(resource)?;
        let asked: Vec<&str> = requested.split_whitespace().collect();
        let mut granted: Vec<&str> = entry
            .scopes
            .iter()
            .map(String::as_str)
            .filter(|scope| asked.contains(scope))
            .collect();
        if granted.is_empty() {
            return None;
        }
        let refresh_token = may_refresh && asked.contains(&"offline_access");
        if refresh_token {
            granted.push("offline_access");
        }
        let mut requested_set = asked.clone();
        requested_set.sort_unstable();
        requested_set.dedup();
        let mut granted_set = granted.clone();
        granted_set.sort_unstable();
        Some(ResourceGrant {
            scope: granted.join(" "),
            refresh_token,
            report_scope: requested_set != granted_set,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const MCP: &str =
        r#"{"uri":"https://mcp.example.org/mcp","scopes":["aqua:read","aqua:write"]}"#;

    #[test]
    fn a_well_formed_registry_parses_in_name_order() {
        let registry = Registry::parse(&configured(&[
            (
                "zeta",
                r#"{"uri":"https://z.example.org","scopes":["z:read"]}"#,
            ),
            ("mcp", MCP),
        ]))
        .unwrap();
        assert_eq!(
            registry
                .find("https://mcp.example.org/mcp")
                .map(|r| r.scopes.clone()),
            Some(vec!["aqua:read".to_string(), "aqua:write".to_string()])
        );
        assert_eq!(registry.scopes(), vec!["aqua:read", "aqua:write", "z:read"]);
        assert!(
            registry.find("https://mcp.example.org/mcp/").is_none(),
            "exact match"
        );
        assert!(registry.find("https://mcp.example.org").is_none());
        assert!(Registry::parse(&HashMap::new()).unwrap().is_empty());
    }

    #[test]
    fn every_malformed_entry_is_refused_by_name_and_rule_without_its_value() {
        let cases: [(&str, &str); 14] = [
            ("not json", "not a valid resource entry"),
            (
                r#"{"uri":"https://a.example.org"}"#,
                "not a valid resource entry",
            ),
            (
                r#"{"uri":"https://a.example.org","scopes":["x"],"extra":1}"#,
                "not a valid resource entry",
            ),
            (
                r#"{"uri":"mcp.example.org/mcp","scopes":["x"]}"#,
                "not an absolute URL",
            ),
            (
                r#"{"uri":"ftp://a.example.org","scopes":["x"]}"#,
                "http or https",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp?x=1","scopes":["x"]}"#,
                "no query",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp#f","scopes":["x"]}"#,
                "no fragment",
            ),
            (
                r#"{"uri":"https://u:p@a.example.org/mcp","scopes":["x"]}"#,
                "user information",
            ),
            (
                r#"{"uri":"HTTPS://A.example.org/mcp","scopes":["x"]}"#,
                "canonical form",
            ),
            (
                r#"{"uri":"https://a.example.org:443/mcp","scopes":["x"]}"#,
                "canonical form",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp/","scopes":["x"]}"#,
                "end in a slash",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp","scopes":[]}"#,
                "at least one scope",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp","scopes":["a b"]}"#,
                "one word",
            ),
            (
                r#"{"uri":"https://a.example.org/mcp","scopes":["x","x"]}"#,
                "twice",
            ),
        ];
        for (entry, rule) in cases {
            let err = Registry::parse(&configured(&[("bad", entry)])).unwrap_err();
            assert!(err.starts_with("resources.bad: "), "{entry}: {err}");
            assert!(err.contains(rule), "{entry}: {err}");
            assert!(
                !err.contains("example.org"),
                "the value is not quoted: {err}"
            );
        }
        for reserved in [
            "openid",
            "profile",
            "offline_access",
            "urn:matrix:client:api:*",
            "urn:synapse:admin:*",
        ] {
            let entry = format!(r#"{{"uri":"https://a.example.org/mcp","scopes":["{reserved}"]}}"#);
            let err = Registry::parse(&configured(&[("bad", &entry)])).unwrap_err();
            assert!(err.contains("belong to this provider"), "{reserved}: {err}");
        }
        let err = Registry::parse(&configured(&[
            ("a", r#"{"uri":"https://a.example.org","scopes":["x"]}"#),
            ("b", r#"{"uri":"https://a.example.org","scopes":["y"]}"#),
        ]))
        .unwrap_err();
        assert_eq!(
            err,
            "resources.b: `uri` is already named by another resource"
        );
    }

    #[test]
    fn the_grant_is_the_requested_scopes_the_resource_lists_and_nothing_else() {
        let registry = Registry::parse(&configured(&[("mcp", MCP)])).unwrap();
        let uri = "https://mcp.example.org/mcp";
        let read = registry.grant(uri, "aqua:read", true).unwrap();
        assert_eq!(
            read,
            ResourceGrant {
                scope: "aqua:read".into(),
                refresh_token: false,
                report_scope: false
            }
        );
        // The resource's order, not the request's; `openid` and foreign scopes
        // are dropped and the response says so.
        let both = registry
            .grant(
                uri,
                "openid aqua:write aqua:read urn:matrix:client:api:*",
                true,
            )
            .unwrap();
        assert_eq!(both.scope, "aqua:read aqua:write");
        assert!(both.report_scope);
        assert!(!both.refresh_token);
        // offline_access needs the request and the registration.
        let refresh = registry
            .grant(uri, "aqua:read offline_access", true)
            .unwrap();
        assert_eq!(refresh.scope, "aqua:read offline_access");
        assert!(refresh.refresh_token);
        assert!(!refresh.report_scope);
        let no_refresh = registry
            .grant(uri, "aqua:read offline_access", false)
            .unwrap();
        assert_eq!(no_refresh.scope, "aqua:read");
        assert!(!no_refresh.refresh_token);
        assert!(no_refresh.report_scope);
        // Nothing of the resource's: nothing to issue.
        assert!(registry.grant(uri, "openid offline_access", true).is_none());
        assert!(registry.grant(uri, "", true).is_none());
        // Not a configured resource.
        assert!(registry
            .grant("https://other.example.org", "aqua:read", true)
            .is_none());
    }
}
