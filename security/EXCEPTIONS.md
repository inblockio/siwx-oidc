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
