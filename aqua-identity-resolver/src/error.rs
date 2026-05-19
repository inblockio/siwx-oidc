use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("verification failed: {status}")]
    VerificationFailed { status: String },

    #[error("SDK error: {0}")]
    SdkError(#[from] aqua_rs_sdk::primitives::MethodError),

    #[error("store error: {0}")]
    StoreError(String),

    #[error("deserialization error: {0}")]
    DeserializationError(#[from] serde_json::Error),
}
