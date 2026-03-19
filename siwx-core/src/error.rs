use thiserror::Error;

#[derive(Debug, Error)]
pub enum SiwxError {
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
