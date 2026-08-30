pub mod db;

/// The link-aware rule for which identity a stored passkey authenticates. Shared
/// by the login path and the credential-store backfill.
pub mod credential_identity;

/// Additive backfill of the passkey credentials into aqua-auth's credential
/// store.
pub mod credential_migration;

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
