# Security exceptions register

Accepted security-advisory exceptions for siwx-oidc. Machine-readable twins:
`.cargo/audit.toml` (what `cargo audit` ignores) and
`security/vex/siwx-oidc.openvex.json` (OpenVEX v0.2.0 statements).

**Rule:** every id in `.cargo/audit.toml` `ignore` must have a row here AND a VEX
statement. Adding an ignore without both is not allowed; when a review trigger fires,
re-verify or remove the exception (all three places together).

| ID | Crate@version | Status | Justification | Evidence | Decided | Review trigger (first of) |
|---|---|---|---|---|---|---|
| RUSTSEC-2023-0071 (CVE-2023-49092, GHSA-c38w-74pg-36hr, GHSA-4grx-2x9w-596c) | rsa@0.9.10 | not_affected | vulnerable_code_not_in_execute_path: Marvin needs RSA private-key ops (decrypt/sign); siwx-oidc holds no RSA private key and signs only with ES256 | `src/oidc.rs` signing key is `p256::ecdsa::SigningKey` (`EcdsaSigningKey::from_pem` / `generate`), `SIGNING_ALG = [EcdsaP256Sha256]`; retired keys parsed as P-256 public keys, PEMs containing `PRIVATE KEY` rejected; no `rsa` reference in `src/` or aqua-auth v0.7.0; `cargo tree -i rsa`: only openidconnect 4.0.1 and crypto-glue 0.1.16 (webauthn-rs-core / webauthn-attestation-ca), both using RS256 public-key verification only; dev + prod discovery advertise only ES256 signing and no JWE algs, `/jwk` holds only EC P-256 keys (checked 2026-09-29) | Tim Bansemer, 2026-09-29 | an rsa release fixing Marvin (0.10 line); siwx-oidc starting to hold RSA private keys (e.g. RS256 signing or RSA JWE); 2027-03-29 |

## Guest mode: residual risks

Accepted residual risks and deviations of the guest mode (`docs/guest-portal.md`; the guest-portal
design set, which is not published in this repository, section 6.2 of its security document). These are not advisory
exceptions: they have no `.cargo/audit.toml` ignore and no VEX statement. Each row is reviewable;
when its trigger fires, re-decide it and update this table.

### Deviations from the design, accepted

| ID | Deviation | Reason | Review trigger |
|---|---|---|---|
| GD-01 | The guest identity is a `did:key` generated **in the guest's browser** (an operator decision on the design), replacing the design's server-derived custodial key (M3b, `key_ref`, per-guest key value). The server holds the public DID only; it never holds, derives or receives private key material. | Removes the custodial key, its secret, its destruction rule and the operator's ability to act as a guest by key. A8 is reworded to match. | A requirement that the server sign for a guest. |
| GD-02 | The server cannot prove that a browser forgot its private key, in particular one that never returns. After the reap the DID is tombstoned (`erased:did`) and refused by every signature path, so a retained key is useless against this server, but it is not deleted. | The key is not ours to delete. The tombstone is the control; "destroyed" is claimed for server state only. | A DID method whose key the issuer can revoke elsewhere. |
| GD-03 | A claimed account's DID is not tombstoned: it is the account's permanent identity, signs in with its passkey, and the guest hand-off refuses it from the commit on. | The claim keeps the same DID and MXID by design (claim requirement GP-CLM-09 of the unpublished design set). | A change to the claim model. |
| GD-04 | The Bearer routes of `/guest` answer `Access-Control-Allow-Origin: *` without credentials (the cookie routes answer none). | The host tool and Meet client call them from their own origins; the Bearer token is the whole authorisation. | Any route moved between the groups. |

### Residual risks

| RR | Risk | Owner role | Review trigger |
|---|---|---|---|
| RR-01 | SFU token and connected participant survive removal up to the token lifetime; noise only in an end-to-end encrypted room. | lk-jwt and Synapse maintainers | lk-jwt eviction or LiveKit revocation lands; before production |
| RR-02 | Impersonation by a common real name that is neither reserved nor a lookalike of the host. | host, product owner | first reported incident |
| RR-03 | The operator can read guest data and act as a guest session (the operator cannot derive a guest's key). | operator | any third-party or multi-tenant operator |
| RR-04 | A token stolen from a guest browser is usable until the deadline (at most 4 hours). | siwx-oidc maintainers | a reported XSS in the client |
| RR-05 | A guest left logged in on a shared computer can be continued or claimed by the next user within the deadline. | product owner | a kiosk use case |
| RR-06 | A host admits the wrong person. | host | repeated reports |
| RR-07 | A mail scanner holds a copy of the link secret. | host, communications owner | a move to e-mail delivery of links |
| RR-08 | One Synapse row per guest for ever (erased account), plus two small Redis keys. | operator | row count above an operator threshold |
| RR-09 | Backups, `user_ips` and logs hold personal data beyond the reap. | operator, data-protection owner | a change of retention policy; a data-subject request |
| RR-10 | Guest confinement is not a perimeter: accounts are open to any valid proof. | siwx-oidc maintainers | any account-admission policy is introduced |
| RR-11 | The design depends on experimental upstream pieces (MSC4502 and MSC4512 appservice mode, `user_type` modification, `check_event_allowed` on knock). | Synapse and lk-jwt maintainers | each Synapse, lk-jwt or Element Call upgrade |
| RR-12 | Login CSRF can put a victim into an attacker's meeting. | client maintainers | a change in how the hand-off works |
| RR-13 | To-device and verification-request spam from a guest to a host. | Synapse maintainers | an upstream hook for to-device messages |
| RR-14 | Legacy wallet-derived MXIDs can be probed for existence. | siwx-oidc maintainers | MSC4263 stabilises |
| RR-15 | A stale `m.call.member` entry for a deactivated guest stays in the room state. | Synapse and client maintainers | a host-side "left" display or an active cleanup step |
| RR-16 | A claimed account cannot add a second passkey, so a lost passkey loses the account. | siwx-oidc maintainers | the key-lifecycle roadmap delivers rotation |
| RR-17 | In the `cross-site` topology a third-party page can trigger silent hand-offs for a guest with a live cookie, bounded by the device cap and the per-record rate; `same-site` (default) refuses such a navigation. | siwx-oidc maintainers | an operator choosing `cross-site`; a change in cookie semantics |
