use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimState {
    SelfSigned,
    Attested,
}

impl ClaimState {
    pub fn from_wasm_state(state_name: &str) -> Option<Self> {
        match state_name {
            "self_signed" => Some(Self::SelfSigned),
            "attested" => Some(Self::Attested),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimType {
    Name,
    Email,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClaimData {
    Name {
        given_name: String,
        family_name: String,
        middle_name: Option<String>,
        name_prefix: Option<String>,
        name_suffix: Option<String>,
        nickname: Option<String>,
        preferred_username: Option<String>,
    },
    Email {
        email: String,
        display_name: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimProvenance {
    pub revision_hash: String,
    pub state: ClaimState,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractedClaim {
    pub signer_did: String,
    pub claim_type: ClaimType,
    pub data: ClaimData,
    pub provenance: ClaimProvenance,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerifiedProfile {
    pub did: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub claims: Vec<ExtractedClaim>,
}

impl VerifiedProfile {
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            ..Default::default()
        }
    }

    pub fn apply_claim(&mut self, claim: ExtractedClaim) {
        match &claim.data {
            ClaimData::Name {
                given_name,
                family_name,
                nickname,
                preferred_username,
                ..
            } => {
                let name = preferred_username
                    .as_deref()
                    .or(nickname.as_deref())
                    .map(String::from)
                    .unwrap_or_else(|| {
                        format!("{} {}", given_name, family_name).trim().to_string()
                    });
                if !name.is_empty() {
                    self.display_name = Some(name);
                }
            }
            ClaimData::Email { email, .. } => {
                self.email = Some(email.clone());
            }
        }
        self.claims.push(claim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_name_claim(given: &str, family: &str, nick: Option<&str>) -> ExtractedClaim {
        ExtractedClaim {
            signer_did: "did:key:z6MkTest".into(),
            claim_type: ClaimType::Name,
            data: ClaimData::Name {
                given_name: given.into(),
                family_name: family.into(),
                middle_name: None,
                name_prefix: None,
                name_suffix: None,
                nickname: nick.map(Into::into),
                preferred_username: None,
            },
            provenance: ClaimProvenance {
                revision_hash: "0xabc".into(),
                state: ClaimState::SelfSigned,
                valid_from: None,
                valid_until: None,
            },
        }
    }

    #[test]
    fn apply_name_claim_given_family() {
        let mut profile = VerifiedProfile::new("did:key:z6MkTest");
        profile.apply_claim(make_name_claim("Alice", "Smith", None));
        assert_eq!(profile.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(profile.claims.len(), 1);
    }

    #[test]
    fn apply_name_claim_nickname_preferred() {
        let mut profile = VerifiedProfile::new("did:key:z6MkTest");
        profile.apply_claim(make_name_claim("Alice", "Smith", Some("ally")));
        assert_eq!(profile.display_name.as_deref(), Some("ally"));
    }

    #[test]
    fn apply_email_claim() {
        let mut profile = VerifiedProfile::new("did:key:z6MkTest");
        profile.apply_claim(ExtractedClaim {
            signer_did: "did:key:z6MkTest".into(),
            claim_type: ClaimType::Email,
            data: ClaimData::Email {
                email: "alice@example.com".into(),
                display_name: None,
            },
            provenance: ClaimProvenance {
                revision_hash: "0xdef".into(),
                state: ClaimState::SelfSigned,
                valid_from: None,
                valid_until: None,
            },
        });
        assert_eq!(profile.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn preferred_username_takes_priority() {
        let mut profile = VerifiedProfile::new("did:key:z6MkTest");
        profile.apply_claim(ExtractedClaim {
            signer_did: "did:key:z6MkTest".into(),
            claim_type: ClaimType::Name,
            data: ClaimData::Name {
                given_name: "Alice".into(),
                family_name: "Smith".into(),
                middle_name: None,
                name_prefix: None,
                name_suffix: None,
                nickname: Some("ally".into()),
                preferred_username: Some("alice_s".into()),
            },
            provenance: ClaimProvenance {
                revision_hash: "0xabc".into(),
                state: ClaimState::SelfSigned,
                valid_from: None,
                valid_until: None,
            },
        });
        assert_eq!(profile.display_name.as_deref(), Some("alice_s"));
    }
}
