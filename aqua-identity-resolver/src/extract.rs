use aqua_rs_sdk::{
    core::VerificationResult,
    primitives::RevisionLink,
    schema::{
        template::BuiltInTemplate,
        templates::{EmailClaim, NameClaim},
        tree::Tree,
        AnyRevision,
    },
};

use crate::profile::{ClaimData, ClaimProvenance, ClaimState, ClaimType, ExtractedClaim};

struct KnownTemplates {
    name_claim: RevisionLink,
    email_claim: RevisionLink,
}

impl KnownTemplates {
    fn new() -> Self {
        Self {
            name_claim: RevisionLink::from_bytes(NameClaim::TEMPLATE_LINK),
            email_claim: RevisionLink::from_bytes(EmailClaim::TEMPLATE_LINK),
        }
    }
}

pub fn extract_claims(tree: &Tree, result: &VerificationResult) -> Vec<ExtractedClaim> {
    if !result.is_valid {
        return Vec::new();
    }

    let known = KnownTemplates::new();
    let mut claims = Vec::new();

    for (rev_link, revision) in &tree.revisions {
        let obj = match revision {
            AnyRevision::Typed(o) => o,
            _ => continue,
        };

        let rev_type = obj.revision_type();

        let claim_type = if *rev_type == known.name_claim {
            ClaimType::Name
        } else if *rev_type == known.email_claim {
            ClaimType::Email
        } else {
            continue;
        };

        let rev_hash_str = rev_link.to_string();

        let wasm_output = match result.wasm_outputs.get(&rev_hash_str) {
            Some(v) => v,
            None => continue,
        };

        let state_name = match wasm_output.get("state").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let claim_state = match ClaimState::from_wasm_state(state_name) {
            Some(s) => s,
            None => continue,
        };

        let payloads = obj.payloads();

        match claim_type {
            ClaimType::Name => {
                if let Ok(nc) = serde_json::from_value::<NameClaim>(payloads.clone()) {
                    claims.push(ExtractedClaim {
                        signer_did: nc.signer_did,
                        claim_type: ClaimType::Name,
                        data: ClaimData::Name {
                            given_name: nc.given_name,
                            family_name: nc.family_name,
                            middle_name: nc.middle_name,
                            name_prefix: nc.name_prefix,
                            name_suffix: nc.name_suffix,
                            nickname: nc.nickname,
                            preferred_username: nc.preferred_username,
                        },
                        provenance: ClaimProvenance {
                            revision_hash: rev_hash_str,
                            state: claim_state,
                            valid_from: nc.valid_from,
                            valid_until: nc.valid_until,
                        },
                    });
                }
            }
            ClaimType::Email => {
                if let Ok(ec) = serde_json::from_value::<EmailClaim>(payloads.clone()) {
                    claims.push(ExtractedClaim {
                        signer_did: ec.signer_did,
                        claim_type: ClaimType::Email,
                        data: ClaimData::Email {
                            email: ec.email,
                            display_name: ec.display_name,
                        },
                        provenance: ClaimProvenance {
                            revision_hash: rev_hash_str,
                            state: claim_state,
                            valid_from: ec.valid_from,
                            valid_until: ec.valid_until,
                        },
                    });
                }
            }
        }
    }

    claims
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    fn make_verification_result(
        rev_hash: &str,
        state: &str,
    ) -> VerificationResult {
        let mut wasm_outputs = HashMap::new();
        wasm_outputs.insert(
            rev_hash.to_string(),
            serde_json::json!({ "state": state, "state_index": 1 }),
        );
        VerificationResult {
            is_valid: true,
            status: "VERIFIED".into(),
            logs: vec![],
            wasm_outputs,
        }
    }

    #[test]
    fn rejects_invalid_verification() {
        let tree = Tree {
            revisions: BTreeMap::new(),
            file_index: BTreeMap::new(),
        };
        let result = VerificationResult {
            is_valid: false,
            status: "FAILED".into(),
            logs: vec![],
            wasm_outputs: HashMap::new(),
        };
        assert!(extract_claims(&tree, &result).is_empty());
    }

    #[test]
    fn skips_unsigned_claims() {
        use aqua_rs_sdk::schema::Object;
        use aqua_rs_sdk::primitives::{Method, HashType};

        let nc = NameClaim {
            signer_did: "did:key:z6MkTest".into(),
            given_name: "Alice".into(),
            family_name: "Smith".into(),
            middle_name: None,
            name_prefix: None,
            name_suffix: None,
            nickname: None,
            preferred_username: None,
            valid_from: None,
            valid_until: None,
        };

        let obj = Object::genesis_with_template(Method::Scalar, HashType::Sha3_256, nc);
        let obj_value = obj.genericize().unwrap();
        let rev_link = RevisionLink::from_bytes([0xAA; 32]);

        let mut revisions = BTreeMap::new();
        revisions.insert(rev_link.clone(), AnyRevision::Typed(obj_value));

        let tree = Tree {
            revisions,
            file_index: BTreeMap::new(),
        };

        let result = make_verification_result(&rev_link.to_string(), "unsigned");
        let claims = extract_claims(&tree, &result);
        assert!(claims.is_empty(), "unsigned claims should be skipped");
    }

    #[test]
    fn extracts_self_signed_name_claim() {
        use aqua_rs_sdk::schema::Object;
        use aqua_rs_sdk::primitives::{Method, HashType};

        let nc = NameClaim {
            signer_did: "did:key:z6MkTest".into(),
            given_name: "Alice".into(),
            family_name: "Smith".into(),
            middle_name: None,
            name_prefix: None,
            name_suffix: None,
            nickname: Some("ally".into()),
            preferred_username: None,
            valid_from: None,
            valid_until: None,
        };

        let obj = Object::genesis_with_template(Method::Scalar, HashType::Sha3_256, nc);
        let obj_value = obj.genericize().unwrap();
        let rev_link = RevisionLink::from_bytes([0xBB; 32]);

        let mut revisions = BTreeMap::new();
        revisions.insert(rev_link.clone(), AnyRevision::Typed(obj_value));

        let tree = Tree {
            revisions,
            file_index: BTreeMap::new(),
        };

        let result = make_verification_result(&rev_link.to_string(), "self_signed");
        let claims = extract_claims(&tree, &result);

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].signer_did, "did:key:z6MkTest");
        assert_eq!(claims[0].claim_type, ClaimType::Name);
        assert_eq!(claims[0].provenance.state, ClaimState::SelfSigned);

        match &claims[0].data {
            ClaimData::Name { given_name, family_name, nickname, .. } => {
                assert_eq!(given_name, "Alice");
                assert_eq!(family_name, "Smith");
                assert_eq!(nickname.as_deref(), Some("ally"));
            }
            _ => panic!("expected Name claim"),
        }
    }

    #[test]
    fn extracts_email_claim() {
        use aqua_rs_sdk::schema::Object;
        use aqua_rs_sdk::primitives::{Method, HashType};

        let ec = EmailClaim {
            signer_did: "did:key:z6MkTest".into(),
            email: "alice@example.com".into(),
            display_name: Some("Alice".into()),
            valid_from: None,
            valid_until: None,
        };

        let obj = Object::genesis_with_template(Method::Scalar, HashType::Sha3_256, ec);
        let obj_value = obj.genericize().unwrap();
        let rev_link = RevisionLink::from_bytes([0xCC; 32]);

        let mut revisions = BTreeMap::new();
        revisions.insert(rev_link.clone(), AnyRevision::Typed(obj_value));

        let tree = Tree {
            revisions,
            file_index: BTreeMap::new(),
        };

        let result = make_verification_result(&rev_link.to_string(), "attested");
        let claims = extract_claims(&tree, &result);

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim_type, ClaimType::Email);
        assert_eq!(claims[0].provenance.state, ClaimState::Attested);

        match &claims[0].data {
            ClaimData::Email { email, display_name } => {
                assert_eq!(email, "alice@example.com");
                assert_eq!(display_name.as_deref(), Some("Alice"));
            }
            _ => panic!("expected Email claim"),
        }
    }
}
