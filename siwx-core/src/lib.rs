// siwx-core: traits and cipher suites for CAIP-122 DID-method dispatch.
// No async — all verification is pure crypto.

pub mod cipher_suite;
pub mod did_method;
pub mod error;

pub use cipher_suite::{all_cipher_suites, find_cipher_suite, CipherSuite};
pub use did_method::{all_did_methods, find_did_method, DIDMethod};
pub use error::SiwxError;
