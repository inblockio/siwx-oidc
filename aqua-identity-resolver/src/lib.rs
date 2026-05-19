pub mod error;
pub mod extract;
pub mod profile;
pub mod resolver;
pub mod store;

pub use error::ResolverError;
pub use extract::extract_claims;
pub use profile::{
    ClaimData, ClaimProvenance, ClaimState, ClaimType, ExtractedClaim, VerifiedProfile,
};
pub use resolver::AquaIdentityResolver;
pub use store::{ClaimStore, InMemoryClaimStore};

pub use aqua_rs_sdk::schema::tree::Tree;
pub use aqua_rs_sdk::core::VerificationResult;
