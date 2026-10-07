//! Policy for generic-class clients: which scopes they are granted, which static entries
//! start-up refuses, and which accounts get a mailbox address. Pure functions, so every
//! rule is unit-tested here and read the same way by `oidc.rs` and `axum_lib.rs`.

use std::collections::HashMap;

use crate::db::{ClientClass, ClientEntry};
use crate::mxid::localpart_for;

/// The scope that unlocks the mailbox claim.
pub const MAIL_SCOPE: &str = "io.inblock.mail";
/// The userinfo claim that carries the mailbox address.
pub const MAILBOX_CLAIM: &str = "io.inblock.mailbox";

/// Scope prefixes that open a Matrix or Synapse session. A generic client is never
/// granted one, whatever its configuration says.
const MATRIX_SESSION_SCOPE_PREFIXES: [&str; 2] = ["urn:matrix:", "urn:synapse:"];

/// The deployment settings the static-client rules read besides the entry itself.
#[derive(Clone, Copy, Debug)]
pub struct Deployment<'a> {
    /// `mail_domain`, which start-up has already passed to [`validate_mail_domain`].
    pub mail_domain: Option<&'a str>,
    /// Whether `mas_shared_secret` is set (delegated-auth mode): the deployment has a
    /// Synapse that supplies the account and the localpart of a signed-in user.
    pub delegated_auth: bool,
}

/// What a generic client is granted: every requested scope that is in `allowed`, in
/// request order and without duplicates, or `None` when `openid` is not among them. A
/// scope the client may not have is dropped rather than refused (OpenID Connect Core 1.0
/// section 5.4), so the result is always a subset of `allowed`.
fn granted_scope(requested: &str, allowed: &[String]) -> Option<String> {
    let mut granted: Vec<&str> = Vec::new();
    for scope in requested.split(' ').filter(|s| !s.is_empty()) {
        if allowed.iter().any(|a| a == scope) && !granted.contains(&scope) {
            granted.push(scope);
        }
    }
    granted.contains(&"openid").then(|| granted.join(" "))
}

/// `granted` (the result of [`granted_scope`]) plus every scope of `always_granted` it does
/// not contain yet, appended in configuration order. Start-up keeps `always_granted` inside
/// the client's allowed scopes, so the merged scope stays a subset of them too.
fn with_always_granted(granted: &str, always_granted: &[String]) -> String {
    let mut scopes: Vec<&str> = granted.split(' ').filter(|s| !s.is_empty()).collect();
    for scope in always_granted {
        if !scopes.contains(&scope.as_str()) {
            scopes.push(scope);
        }
    }
    scopes.join(" ")
}

/// What `client` is granted for a request for `requested`: the requested scopes it may have
/// (which must include `openid`) plus the scopes its configuration always grants.
///
/// `None` means the request grants no `openid`, and also covers a Matrix-class client,
/// whose scope this function does not decide. A caller that refuses a request at
/// `/authorize` and one that issues the grant at the token endpoint both ask this function
/// about the same scope string, so the request one refuses is the request the other
/// refuses, and the grant issued is the one that was checked.
pub fn grant_for(client: &ClientEntry, requested: &str) -> Option<String> {
    match client.class {
        ClientClass::Matrix => None,
        ClientClass::Generic => {
            let allowed = client.allowed_scopes.as_deref().unwrap_or(&[]);
            let granted = granted_scope(requested, allowed)?;
            Some(with_always_granted(&granted, &client.always_granted_scopes))
        }
    }
}

/// Whether a space-separated scope string contains `scope` as a whole word.
pub fn has_scope(scopes: &str, scope: &str) -> bool {
    scopes.split(' ').any(|s| s == scope)
}

/// The width of an opaque localpart, in characters.
const OPAQUE_LOCALPART_WIDTH: usize = 16;

/// Whether `localpart` has the shape of an opaque localpart: exactly 16 characters, each a
/// lowercase base36 digit (`0-9`, `a-z`).
///
/// A mail server takes a mailbox name of any case and length, so this provider is the only
/// gate on what the mailbox claim can carry. The shape is stated here, apart from the
/// derivation in [`crate::mxid::localpart_for`], on purpose: changing the derivation without
/// changing this makes the claim vanish instead of silently changing the shape of every
/// address. `every_localpart_the_derivation_produces_passes_the_mailbox_gate` fails first.
pub fn is_opaque_localpart(localpart: &str) -> bool {
    localpart.len() == OPAQUE_LOCALPART_WIDTH
        && localpart
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

/// The mailbox address of an account, or `None`. This is the one place the value of the
/// mailbox claim is built.
///
/// Only an account whose RECORDED localpart (`TokenMetadata::username`, set at sign-in) is
/// an opaque localpart ([`is_opaque_localpart`]) and is the one derived from its DID gets
/// one; a grandfathered legacy localpart never does. The two checks answer different
/// questions, the shape of the name and whose name it is. Today the derivation implies the
/// shape, so the shape check changes no outcome; it is kept so that the address format does
/// not depend on how the derivation happens to be written. They only check the recorded
/// value: the address is always built from `username` as recorded, never from a recomputed
/// localpart. `mail_domain` is the configured value, which start-up has already passed to
/// [`validate_mail_domain`].
pub fn mailbox_for(username: &str, did: &str, mail_domain: Option<&str>) -> Option<String> {
    let domain = mail_domain?;
    (is_opaque_localpart(username) && username == localpart_for(did))
        .then(|| format!("{username}@{domain}"))
}

/// The longest DNS name, and the longest label in one, in characters (RFC 1035 section
/// 2.3.4, without the trailing dot).
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Refuse a `mail_domain` that would mint malformed or ambiguous addresses: it must be a
/// lowercase DNS name (labels of `a-z`, `0-9` and inner `-`, joined by single dots, at most
/// 63 characters per label and 253 in all) whose last label is not all digits. The last
/// rule is RFC 1123 section 2.1 and RFC 3696 section 2: a top-level label is never numeric,
/// which is what keeps an IP address (`127.0.0.1`, `127.1`, `2130706433`) from passing for
/// a name.
pub fn validate_mail_domain(mail_domain: Option<&str>) -> Result<(), String> {
    let Some(domain) = mail_domain else {
        return Ok(());
    };
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let last_label_is_numeric = domain
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()));
    if domain.len() <= MAX_DOMAIN_LEN && domain.split('.').all(label_ok) && !last_label_is_numeric {
        Ok(())
    } else {
        Err(format!(
            "mail_domain `{domain}` is not a lowercase DNS name: labels of a-z, 0-9 and inner \
             hyphens of at most {MAX_LABEL_LEN} characters, at most {MAX_DOMAIN_LEN} in all, \
             and a last label that is not all digits (an IP address is not a mail domain)"
        ))
    }
}

/// RFC 6749 section 3.3: a scope is a non-empty run of printable ASCII without `"` and `\`.
/// That is also what keeps a space-separated scope string unambiguous.
fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// Refuse a static client entry this server could not honour safely. Start-up runs it for
/// every `default_clients` entry; the error names the client and the rule.
pub fn validate_static_client(
    id: &str,
    entry: &ClientEntry,
    deployment: Deployment<'_>,
) -> Result<(), String> {
    let refuse = |rule: String| Err(format!("default_clients.{id}: {rule}"));
    if let Some(scope) = entry
        .allowed_scopes
        .iter()
        .flatten()
        .chain(&entry.always_granted_scopes)
        .find(|s| !is_scope_token(s))
    {
        return refuse(format!(
            "`{scope}` is not a scope: a scope is one word of printable characters (RFC 6749 section 3.3)"
        ));
    }
    match entry.class {
        ClientClass::Matrix => {
            if entry.allowed_scopes.is_some() {
                return refuse(
                    "`allowed_scopes` applies only to class \"generic\"; \
                     a Matrix-class client always gets the Matrix scope"
                        .into(),
                );
            }
            if !entry.always_granted_scopes.is_empty() {
                return refuse("`always_granted_scopes` applies only to class \"generic\"".into());
            }
        }
        ClientClass::Generic => {
            if !deployment.delegated_auth {
                return refuse(
                    "a generic client needs `mas_shared_secret` (SIWXOIDC_MAS_SHARED_SECRET): \
                     its account and localpart come from Synapse"
                        .into(),
                );
            }
            let Some(allowed) = entry.allowed_scopes.as_deref() else {
                return refuse("a generic client needs `allowed_scopes`".into());
            };
            if !allowed.iter().any(|s| s == "openid") {
                return refuse("`allowed_scopes` must include \"openid\"".into());
            }
            if let Some(scope) = allowed.iter().find(|s| {
                MATRIX_SESSION_SCOPE_PREFIXES
                    .iter()
                    .any(|prefix| s.starts_with(prefix))
            }) {
                return refuse(format!(
                    "a generic client can never be granted `{scope}`: scopes starting with \
                     `urn:matrix:` or `urn:synapse:` open a Matrix or Synapse session"
                ));
            }
            if entry.always_granted_scopes.iter().any(|s| s == "openid") {
                return refuse(
                    "`always_granted_scopes` must not include \"openid\": a client requests it, \
                     and it is never implied"
                        .into(),
                );
            }
            if let Some(scope) = entry
                .always_granted_scopes
                .iter()
                .find(|s| !allowed.contains(s))
            {
                return refuse(format!(
                    "`always_granted_scopes` must be a subset of `allowed_scopes`, \
                     and `{scope}` is not in it"
                ));
            }
            if allowed.iter().any(|s| s == MAIL_SCOPE) && deployment.mail_domain.is_none() {
                return refuse(format!(
                    "`{MAIL_SCOPE}` needs `mail_domain` (SIWXOIDC_MAIL_DOMAIN)"
                ));
            }
            if entry.access_token_digest.is_some() {
                return refuse("a generic client cannot carry a registration access token".into());
            }
        }
    }
    Ok(())
}

/// Parse and validate every `default_clients` entry, in id order so that a configuration
/// with several faults reports the same one on every start. Start-up calls it before
/// anything is written, and it needs no Redis.
pub fn parse_static_clients(
    configured: &HashMap<String, String>,
    deployment: Deployment<'_>,
) -> Result<Vec<(String, ClientEntry)>, String> {
    let mut ids: Vec<&String> = configured.keys().collect();
    ids.sort();
    ids.into_iter()
        .map(|id| {
            let entry: ClientEntry = serde_json::from_str(&configured[id])
                .map_err(|e| format!("default_clients.{id}: not a valid client entry: {e}"))?;
            validate_static_client(id, &entry, deployment)?;
            Ok((id.clone(), entry))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SiwxClientMetadata;
    use openidconnect::RedirectUrl;

    fn allowed(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|s| s.to_string()).collect()
    }

    /// A deployment with a Synapse (delegated-auth mode) and the given mail domain.
    fn deployment(mail_domain: Option<&str>) -> Deployment<'_> {
        Deployment {
            mail_domain,
            delegated_auth: true,
        }
    }

    fn metadata() -> SiwxClientMetadata {
        SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://mail.example.org/cb".into()).unwrap()],
            Default::default(),
        )
    }

    fn entry(class: ClientClass, scopes: Option<&[&str]>) -> ClientEntry {
        ClientEntry {
            class,
            allowed_scopes: scopes.map(allowed),
            ..ClientEntry::new("s", metadata(), None)
        }
    }

    fn always(mut entry: ClientEntry, scopes: &[&str]) -> ClientEntry {
        entry.always_granted_scopes = allowed(scopes);
        entry
    }

    #[test]
    fn granted_scope_keeps_only_allowed_scopes_and_needs_openid() {
        let mail = allowed(&["openid", "profile", MAIL_SCOPE]);
        assert_eq!(
            granted_scope("openid io.inblock.mail urn:matrix:client:api:*", &mail).as_deref(),
            Some("openid io.inblock.mail")
        );
        assert_eq!(
            granted_scope("io.inblock.mail openid openid", &mail).as_deref(),
            Some("io.inblock.mail openid"),
            "request order, no duplicates"
        );
        assert_eq!(
            granted_scope("io.inblock.mail", &mail),
            None,
            "openid is required"
        );
        assert_eq!(
            granted_scope("openid io.inblock.mail", &allowed(&["openid"])).as_deref(),
            Some("openid"),
            "a scope the client may not have is dropped, never granted"
        );
        assert_eq!(granted_scope("", &mail), None);
    }

    #[test]
    fn has_scope_matches_whole_words_only() {
        assert!(has_scope("openid io.inblock.mail", MAIL_SCOPE));
        assert!(!has_scope("openid io.inblock.mailx", MAIL_SCOPE));
        assert!(!has_scope("openid", MAIL_SCOPE));
    }

    #[test]
    fn always_granted_scopes_are_appended_without_duplicates() {
        let mail = allowed(&[MAIL_SCOPE]);
        assert_eq!(
            with_always_granted("openid profile", &mail),
            "openid profile io.inblock.mail"
        );
        assert_eq!(
            with_always_granted("openid io.inblock.mail", &mail),
            "openid io.inblock.mail",
            "a scope the client did request is not repeated"
        );
        assert_eq!(with_always_granted("openid", &[]), "openid");
        assert_eq!(
            with_always_granted("openid", &allowed(&["b", "a", "b"])),
            "openid b a",
            "configuration order, no duplicates"
        );
    }

    #[test]
    fn a_client_that_requests_only_openid_and_profile_still_gets_the_mail_scope() {
        let may_have = allowed(&["openid", "profile", MAIL_SCOPE]);
        let granted = granted_scope("openid profile", &may_have).unwrap();
        let merged = with_always_granted(&granted, &allowed(&[MAIL_SCOPE]));
        assert_eq!(merged, "openid profile io.inblock.mail");
        assert!(has_scope(&merged, MAIL_SCOPE));
        assert!(
            merged.split(' ').all(|s| may_have.iter().any(|a| a == s)),
            "the merged scope stays inside the allowed scopes"
        );
    }

    #[test]
    fn a_generic_client_is_granted_what_it_may_have_plus_what_is_always_granted() {
        let client = always(
            entry(
                ClientClass::Generic,
                Some(&["openid", "profile", MAIL_SCOPE]),
            ),
            &[MAIL_SCOPE],
        );
        assert_eq!(
            grant_for(&client, "openid profile urn:matrix:client:api:*").as_deref(),
            Some("openid profile io.inblock.mail")
        );
        assert_eq!(
            grant_for(&client, "openid io.inblock.mail").as_deref(),
            Some("openid io.inblock.mail"),
            "a scope the client did request is not repeated"
        );
        assert_eq!(
            grant_for(
                &entry(ClientClass::Generic, Some(&["openid"])),
                "openid profile"
            )
            .as_deref(),
            Some("openid"),
            "without always-granted scopes the grant is the allowed part of the request"
        );
    }

    #[test]
    fn a_request_without_openid_is_refused_whatever_is_always_granted() {
        let client = always(
            entry(ClientClass::Generic, Some(&["openid", MAIL_SCOPE])),
            &[MAIL_SCOPE],
        );
        assert_eq!(grant_for(&client, MAIL_SCOPE), None);
        assert_eq!(grant_for(&client, "profile"), None);
        assert_eq!(grant_for(&client, ""), None);
    }

    #[test]
    fn a_generic_client_without_a_scope_policy_is_granted_nothing() {
        assert_eq!(
            grant_for(&entry(ClientClass::Generic, None), "openid"),
            None
        );
    }

    #[test]
    fn only_a_generic_client_is_granted_a_scope_here() {
        let matrix = entry(ClientClass::Matrix, Some(&["openid"]));
        assert_eq!(
            grant_for(&matrix, "openid"),
            None,
            "a Matrix-class client's scope is fixed at the token endpoint"
        );
    }

    #[test]
    fn only_the_opaque_localpart_gets_a_mailbox() {
        let did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
        let opaque = crate::mxid::localpart_for(did);
        assert_eq!(
            mailbox_for(&opaque, did, Some("matrix.example.org")),
            Some(format!("{opaque}@matrix.example.org"))
        );
        assert_eq!(
            mailbox_for(
                &crate::mxid::legacy_localpart(did),
                did,
                Some("matrix.example.org")
            ),
            None,
            "a legacy localpart gets no mailbox"
        );
        assert_eq!(
            mailbox_for(
                &opaque,
                "did:key:z6MkpFemPtmjvPZ1gFYM6d68tuwxxrcec4H2Ck23FRchU9ue",
                Some("matrix.example.org")
            ),
            None,
            "a localpart that is not this DID's own gets no mailbox"
        );
        assert_eq!(mailbox_for(&opaque, did, None), None);
    }

    #[test]
    fn only_sixteen_lowercase_base36_characters_are_an_opaque_localpart() {
        for opaque in [
            "k3f9x2q7ab4d8m1p",
            "1vo8g4vofiha69ua",
            "0000000000000000",
            "zzzzzzzzzzzzzzzz",
        ] {
            assert!(is_opaque_localpart(opaque), "{opaque:?} is opaque");
        }
        let malformed = [
            ("upper case", "K3F9X2Q7AB4D8M1P"),
            ("one upper case letter", "k3f9x2q7ab4d8m1P"),
            ("15 characters", "k3f9x2q7ab4d8m1"),
            ("17 characters", "k3f9x2q7ab4d8m1pa"),
            ("empty", ""),
            (
                "the legacy form",
                "did-key-z6mkmwzijj2k3ckqvqnmmgvkefmhdse4zxrfvqksxdmgba4v",
            ),
            ("a hyphen", "k3f9x2q7-b4d8m1p"),
            ("an underscore", "k3f9x2q7_b4d8m1p"),
            ("a dot", "k3f9x2q7.b4d8m1p"),
            ("a colon", "k3f9x2q7:b4d8m1p"),
            ("an at sign", "k3f9x2q7@b4d8m1p"),
            ("a space", "k3f9x2q7 b4d8m1p"),
            ("a trailing newline", "k3f9x2q7ab4d8m1\n"),
            (
                "a multi-byte letter that makes it 16 bytes",
                "k3f9x2q7ab4d8m\u{e9}",
            ),
            (
                "a multi-byte letter on top of 15 characters",
                "k3f9x2q7ab4d8m1\u{e9}",
            ),
        ];
        for (what, localpart) in malformed {
            assert!(
                !is_opaque_localpart(localpart),
                "{what}: {localpart:?} is not opaque"
            );
        }
    }

    /// The gate and the derivation are stated apart, so that changing the derivation without
    /// changing the gate makes the claim vanish instead of silently changing the address.
    /// This is the test that fails first when only one of them is changed.
    #[test]
    fn every_localpart_the_derivation_produces_passes_the_mailbox_gate() {
        let spellings = [
            "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "did:pkh:eip155:1:0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
            "did:pkh:ed25519:0xabcdef1234567890",
            "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB",
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "",
        ];
        let generated = (0..1000).map(|i| format!("did:key:zDerive{i}"));
        for did in spellings.iter().map(|s| s.to_string()).chain(generated) {
            let localpart = crate::mxid::localpart_for(&did);
            assert!(
                is_opaque_localpart(&localpart),
                "the localpart derived for {did:?} fails the gate: {localpart:?}"
            );
        }
    }

    #[test]
    fn a_mail_domain_must_be_a_lowercase_dns_name() {
        assert!(validate_mail_domain(None).is_ok());
        assert!(validate_mail_domain(Some("matrix.example.org")).is_ok());
        assert!(validate_mail_domain(Some("matrix.test")).is_ok());
        assert!(validate_mail_domain(Some("1password.example.com")).is_ok());
        assert!(validate_mail_domain(Some("host.123abc")).is_ok());
        assert!(validate_mail_domain(Some("localhost")).is_ok());
        for bad in [
            "",
            "Matrix.example.org",
            "user@example.org",
            "example..org",
            "-x.example.org",
            "exa mple.org",
            ".example.org",
            "example.org.",
            "  ",
            " example.org",
        ] {
            assert!(
                validate_mail_domain(Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_mail_domain_is_bounded_in_length() {
        let label_63 = "a".repeat(63);
        assert!(validate_mail_domain(Some(&format!("{label_63}.example.org"))).is_ok());
        assert!(
            validate_mail_domain(Some(&format!("{}.example.org", "a".repeat(64)))).is_err(),
            "a label of 64 characters"
        );
        let name_253 = format!("{label_63}.{label_63}.{label_63}.{}", "a".repeat(61));
        assert_eq!(name_253.len(), 253);
        assert!(validate_mail_domain(Some(&name_253)).is_ok());
        assert!(
            validate_mail_domain(Some(&format!("{name_253}a"))).is_err(),
            "a name of 254 characters"
        );
    }

    #[test]
    fn a_mail_domain_is_never_an_ip_address() {
        for ip in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "10.0.0.1",
            "mail.example.org.1",
            "1.2.3.4",
        ] {
            assert!(
                validate_mail_domain(Some(ip)).is_err(),
                "{ip:?} must be refused"
            );
        }
    }

    #[test]
    fn static_client_validation_refuses_what_it_cannot_honour_safely() {
        let domain = Some("matrix.example.org");
        let served = deployment(domain);
        assert!(
            validate_static_client("element", &entry(ClientClass::Matrix, None), served).is_ok()
        );
        assert!(validate_static_client(
            "mail",
            &entry(ClientClass::Generic, Some(&["openid", MAIL_SCOPE])),
            served
        )
        .is_ok());
        let without_domain = deployment(None);
        let without_synapse = Deployment {
            mail_domain: domain,
            delegated_auth: false,
        };
        let refused = [
            (
                "matrix-with-scopes",
                entry(ClientClass::Matrix, Some(&["openid"])),
                served,
                "applies only to class",
            ),
            (
                "generic-without-scopes",
                entry(ClientClass::Generic, None),
                served,
                "needs `allowed_scopes`",
            ),
            (
                "generic-without-openid",
                entry(ClientClass::Generic, Some(&[MAIL_SCOPE])),
                served,
                "must include \"openid\"",
            ),
            (
                "generic-with-matrix-scope",
                entry(
                    ClientClass::Generic,
                    Some(&["openid", "urn:matrix:client:api:*"]),
                ),
                served,
                "urn:matrix:client:api:*",
            ),
            (
                "generic-with-synapse-scope",
                entry(
                    ClientClass::Generic,
                    Some(&["openid", "urn:synapse:admin:*"]),
                ),
                served,
                "urn:synapse:admin:*",
            ),
            (
                "mail-without-domain",
                entry(ClientClass::Generic, Some(&["openid", MAIL_SCOPE])),
                without_domain,
                "needs `mail_domain`",
            ),
            (
                "scope-with-a-space",
                entry(ClientClass::Generic, Some(&["openid", "profile email"])),
                served,
                "`profile email` is not a scope",
            ),
            (
                "empty-scope",
                entry(ClientClass::Generic, Some(&["openid", ""])),
                served,
                "`` is not a scope",
            ),
            (
                "generic-without-a-synapse",
                entry(ClientClass::Generic, Some(&["openid"])),
                without_synapse,
                "needs `mas_shared_secret`",
            ),
        ];
        for (id, e, d, rule) in refused {
            let err = validate_static_client(id, &e, d).expect_err(id);
            assert!(
                err.starts_with(&format!("default_clients.{id}:")),
                "the error names the client: {err}"
            );
            assert!(
                err.contains(rule),
                "the error names the rule {rule:?}: {err}"
            );
        }
        let managed = ClientEntry {
            class: ClientClass::Generic,
            allowed_scopes: Some(allowed(&["openid"])),
            ..ClientEntry::new("s", metadata(), Some("t"))
        };
        assert!(
            validate_static_client("managed", &managed, served).is_err(),
            "a generic client cannot be managed through /client/{{id}}"
        );
    }

    /// A Matrix-class client is the same in either deployment mode; only the generic
    /// class needs a Synapse.
    #[test]
    fn a_matrix_class_client_is_valid_without_a_synapse() {
        let without_synapse = Deployment {
            mail_domain: None,
            delegated_auth: false,
        };
        assert!(validate_static_client(
            "element",
            &entry(ClientClass::Matrix, None),
            without_synapse
        )
        .is_ok());
    }

    #[test]
    fn always_granted_scopes_must_be_allowed_and_never_openid() {
        let served = deployment(Some("matrix.example.org"));
        let generic = |extra: &[&str]| {
            always(
                entry(
                    ClientClass::Generic,
                    Some(&["openid", "profile", MAIL_SCOPE]),
                ),
                extra,
            )
        };
        assert!(validate_static_client("none", &generic(&[]), served).is_ok());
        assert!(validate_static_client("mail", &generic(&[MAIL_SCOPE]), served).is_ok());
        assert!(validate_static_client("two", &generic(&["profile", MAIL_SCOPE]), served).is_ok());

        let refused = [
            (
                "not-allowed",
                generic(&["urn:example:other"]),
                "`urn:example:other` is not in it",
            ),
            (
                "partly-allowed",
                generic(&[MAIL_SCOPE, "urn:example:other"]),
                "`urn:example:other` is not in it",
            ),
            (
                "openid",
                generic(&["openid"]),
                "must not include \"openid\"",
            ),
            (
                "matrix-class",
                always(entry(ClientClass::Matrix, None), &[MAIL_SCOPE]),
                "`always_granted_scopes` applies only to class",
            ),
            ("empty-scope", generic(&[""]), "`` is not a scope"),
            (
                "scope-with-a-space",
                generic(&["profile io.inblock.mail"]),
                "is not a scope",
            ),
        ];
        for (id, e, rule) in refused {
            let err = validate_static_client(id, &e, served).expect_err(id);
            assert!(
                err.starts_with(&format!("default_clients.{id}:")),
                "the error names the client: {err}"
            );
            assert!(
                err.contains(rule),
                "the error names the rule {rule:?}: {err}"
            );
        }
    }

    const MATRIX_ENTRY: &str =
        r#"{"secret":"s","metadata":{"redirect_uris":["https://app.example.org/cb"]}}"#;
    const MAIL_ENTRY: &str = r#"{"secret":"s","metadata":{"redirect_uris":["https://mail.example.org/cb"]},"class":"generic","allowed_scopes":["openid","profile","io.inblock.mail"],"always_granted_scopes":["io.inblock.mail"]}"#;

    fn configured(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(id, raw)| (id.to_string(), raw.to_string()))
            .collect()
    }

    #[test]
    fn start_up_parses_every_static_client_in_id_order() {
        let clients = parse_static_clients(
            &configured(&[("mail", MAIL_ENTRY), ("element", MATRIX_ENTRY)]),
            deployment(Some("matrix.example.org")),
        )
        .unwrap();
        let ids: Vec<&str> = clients.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["element", "mail"]);
        assert_eq!(clients[0].1.class, ClientClass::Matrix);
        assert_eq!(clients[1].1.class, ClientClass::Generic);
        assert_eq!(
            clients[1].1.always_granted_scopes,
            vec![MAIL_SCOPE.to_string()]
        );
        assert!(parse_static_clients(&HashMap::new(), deployment(None))
            .unwrap()
            .is_empty());
    }

    /// The refusal for `entries`; `ClientEntry` has no `Debug`, so `Result::unwrap_err` is
    /// not available.
    fn refusal(entries: &[(&str, &str)], deployment: Deployment<'_>) -> String {
        match parse_static_clients(&configured(entries), deployment) {
            Ok(_) => panic!("the configuration must be refused"),
            Err(refusal) => refusal,
        }
    }

    #[test]
    fn start_up_names_the_client_whose_entry_cannot_be_used() {
        let served = deployment(Some("matrix.example.org"));
        let unreadable = refusal(&[("broken", "{not json")], served);
        assert!(
            unreadable.starts_with("default_clients.broken:"),
            "{unreadable}"
        );

        let no_domain = refusal(&[("mail", MAIL_ENTRY)], deployment(None));
        assert!(
            no_domain.starts_with("default_clients.mail:"),
            "{no_domain}"
        );
        assert!(no_domain.contains("SIWXOIDC_MAIL_DOMAIN"), "{no_domain}");

        let no_synapse = refusal(
            &[("mail", MAIL_ENTRY)],
            Deployment {
                mail_domain: Some("matrix.example.org"),
                delegated_auth: false,
            },
        );
        assert!(
            no_synapse.starts_with("default_clients.mail:"),
            "{no_synapse}"
        );
        assert!(
            no_synapse.contains("SIWXOIDC_MAS_SHARED_SECRET"),
            "{no_synapse}"
        );

        let both = refusal(&[("zeta", "{}"), ("alpha", "{}")], served);
        assert!(
            both.starts_with("default_clients.alpha:"),
            "the first id in order is reported, so the message is stable: {both}"
        );
    }
}
