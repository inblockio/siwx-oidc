pub mod db;

/// Pure, dependency-light Matrix localpart derivation from a DID (opaque
/// base36 hash + the legacy grandfathering shape). No Synapse, no axum, no
/// tokio — safe to declare here (unlike `synapse_client`, see the note
/// below) and to link against from `tests/*.rs` integration tests, which is
/// the whole reason it lives in the library crate rather than only in the
/// binary's `src/localpart.rs`.
pub mod mxid;

/// Tier 1 of the identity model: the human-readable alias a new account is
/// seeded with, derived deterministically from the DID. Pure (`sha2` only),
/// and in the library crate for the same reason as `mxid` — `tests/*.rs` link
/// this crate, and a hand-copied derivation is a derivation that drifts.
pub mod alias;

/// The link-aware rule for which identity a stored passkey authenticates. Shared
/// by the login path and the credential-store backfill.
pub mod credential_identity;

/// Additive backfill of the passkey credentials into aqua-auth's credential
/// store.
pub mod credential_migration;

/// The optional aqua-auth credential store: dual-write and read-through, off by
/// default, selected by `AQUA_WEBAUTHN_REDIS_URL`.
pub mod credential_store;

// `synapse_client` is DELIBERATELY not re-exposed here.
//
// It used to be `pub mod synapse_client;`, which compiled the same file into
// both this library crate and the binary crate, producing two distinct types
// with one name — the footgun documented at the top of `src/compat.rs`. Nothing
// outside `src/` ever consumed the library copy.
//
// It also became impossible as of the 1.159 admin-token port: the client now
// mints its own admin-scoped credential and therefore depends on
// `crate::admin_token` and `crate::introspect`, which exist only in the binary
// crate. The binary's `mod synapse_client;` is the single definition.
