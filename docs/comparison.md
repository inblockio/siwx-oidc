# siwx-oidc: What It Does and How It Compares

## What siwx-oidc does

siwx-oidc is an OpenID Connect identity provider that accepts CAIP-122 wallet
signatures and WebAuthn passkeys as authentication. Users sign a challenge with
their existing wallet (Ethereum, Solana, or any CAIP-122 compatible chain) or a
device passkey. The server verifies the signature and issues standard OIDC tokens
(ID token, access token, refresh token) with the user's DID as the subject claim.

Any OIDC relying party can consume these tokens. The primary deployment target is
Matrix Synapse, where siwx-oidc replaces the Matrix Authentication Service (MAS)
entirely via MSC3861, handling token introspection, device provisioning,
cross-signing management, and the full device lifecycle including QR code login
(RFC 8628).

Users can also link a passkey to their wallet DID, so future logins with biometrics
produce the same identity as wallet logins. The headless client library supports
machine authentication with PEM keys and device authorization grants for CI/headless
environments.

The server is a single Rust binary (~18MB Alpine Docker image) with Redis as the
only dependency.

## What nobody else does

A survey of 16 open-source projects (active and abandoned) found no other project
that combines these three properties:

1. **Wallet signature as primary OIDC identity.** General IAM platforms (Keycloak,
   Casdoor, authentik) treat wallet login as a peripheral "social login" that binds
   an address to a traditional user account. siwx-oidc uses the DID derived from
   the wallet or passkey as the canonical identity. There is no username, no
   password, no email.

2. **MSC3861 compliance.** Matrix Synapse's delegated auth protocol requires token
   introspection, device provisioning via admin API, cross-signing reset support
   (MSC4312), and account management discovery (MSC4191). MAS implements this but
   accepts no wallet auth. siwx-oidc implements the same protocol surface with
   wallet/passkey auth underneath.

3. **Multi-ceremony, multi-chain, single identity model.** CAIP-122 (any chain),
   WebAuthn passkeys, and RFC 8628 device codes all converge into a single
   DID-based identity. A user can authenticate with MetaMask on desktop, Face ID
   on mobile, or a QR code on a headless device, and all sessions resolve to the
   same Matrix account.

## Landscape comparison

Survey conducted 2026-05-25. Covers all identified open-source projects that
attempt to bridge wallet or decentralized identity authentication to OIDC.

### Summary table

| Project | OIDC Provider | Wallet Auth | Passkeys | CAIP-122 | MSC3861 | Maintained | License |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|---------|
| **siwx-oidc** | Yes | Multi-chain | Yes | Yes | Yes | Yes | Apache 2.0 |
| spruceid/siwe-oidc | Yes | ETH only | No | No | No | No (Nov 2024) | Apache 2.0 |
| MAS | Yes | No | No | No | Yes | Yes | Apache 2.0 |
| Ory Hydra | Yes | No (needs custom) | No | No | No | Yes | Apache 2.0 |
| Pocket ID | Yes | No | Yes | No | No | Yes | BSD-2 |
| Keycloak + Keyblock | Yes | ETH (POC) | No | No | No | Keyblock: No | Apache 2.0 |
| Casdoor | Yes | MetaMask only | WebAuthn | No | No | Yes | Apache 2.0 |
| walt.id IDP Kit | Yes | SIWE | No | No | No | No (Jul 2024) | Apache 2.0 |
| vclogin + Hydra | Yes (via Hydra) | VC/VP only | No | No | No | Partial | Open source |
| web3-login | Yes | ETH only | No | No | No | No (Jan 2024) | MIT |
| DefGuard/avanguard | "OIDC-like" | ETH only | No | No | No | Low activity | Unknown |
| Hanko | Yes | No | Yes | No | No | Yes | Open source |
| Pocket ID | Yes | No | Yes | No | No | Yes | BSD-2 |
| SpruceID DIDKit | No (library) | N/A | N/A | N/A | N/A | Yes | Apache 2.0 |
| Privy | No (SaaS) | Yes | Yes | No | No | Acquired (Stripe) | Proprietary |
| Dynamic | No (SaaS) | Yes | Yes | No | No | Acquired (Fireblocks) | Proprietary |
| Web3Auth | No (SaaS) | Yes | No | No | No | Acquired (Consensys) | Proprietary |

### Detailed assessment

#### spruceid/siwe-oidc (upstream predecessor)

- **URL:** github.com/spruceid/siwe-oidc
- **Last commit:** November 2024
- **What it does:** OIDC Identity Provider for Sign-In with Ethereum. Issues OIDC
  tokens with the Ethereum address as `sub` claim.
- **Limitations:** Ethereum-only. No multi-chain CAIP-122, no passkeys, no device
  code flow, no MSC3861 support, no refresh tokens, no WebAuthn. No security audit.
- **Status:** Abandoned. No forks have picked it up with meaningful activity.
  siwx-oidc is the only actively maintained descendant.

#### Matrix Authentication Service (MAS)

- **URL:** github.com/matrix-org/matrix-authentication-service
- **What it does:** The official MSC3861 implementation. Handles OAuth 2.0/OIDC
  token issuance, device management, token introspection, user/session management
  for Matrix Synapse.
- **Limitations:** Not a wallet identity provider. Accepts username/password or
  upstream OIDC federation (Keycloak, Dex, etc.). No CAIP-122, no wallet
  signatures, no DID-based identity model.
- **Relationship:** siwx-oidc replaces MAS entirely, achieving the same MSC3861
  compliance with wallet/passkey auth as the primary identity model.

#### Ory Hydra

- **URL:** github.com/ory/hydra (~15k stars)
- **What it does:** OpenID Certified OIDC/OAuth 2.1 provider. Headless
  architecture that delegates login/consent to external services.
- **Limitations:** Not an identity provider by itself. No built-in wallet, SIWE,
  or Web3 support. You would need to build a custom login/consent app implementing
  CAIP-122 verification.
- **Assessment:** The closest theoretical alternative architecture would be Hydra +
  a custom CAIP-122 login app. This gives you certified OIDC but requires
  rebuilding siwx-oidc's auth logic. MSC3861 device lifecycle (provisioning,
  cross-signing reset, introspection with `mat_`/`mcr_` tokens) would still need
  custom development.

#### Pocket ID

- **URL:** github.com/pocket-id/pocket-id (~5,700 stars)
- **What it does:** Simple passkey-only OIDC provider. Self-hosted, supports LDAP
  sync, group-based access control.
- **Limitations:** Passkey-only. No wallet signatures, no SIWE/CAIP-122, no Web3
  support. Traditional user account model (admin creates users). No MSC3861.
- **Assessment:** Closest in spirit (passkey-first, simple, self-hosted OIDC) but
  entirely different identity model. No path to wallet auth.

#### Keycloak + Keyblock plugin

- **URL:** github.com/keycloak/keycloak (~25k stars)
- **Plugin:** github.com/ineat/keyblock (27 stars)
- **What it does:** Keycloak is a full enterprise IAM. Keyblock is a POC adding
  Ethereum wallet authentication via a custom Keycloak SPI.
- **Limitations:** Keyblock is abandoned, uses deprecated Ropsten testnet. No
  CAIP-122, no multi-chain, no passkey linking. Building a proper wallet
  authenticator SPI from scratch is possible but substantial. MSC3861 device
  lifecycle would need custom development on top.
- **Assessment:** Massive overkill for the use case. The wallet integration would
  be a custom SPI, not leveraging any existing Keycloak capability.

#### Casdoor

- **URL:** github.com/casdoor/casdoor
- **What it does:** Full-featured open-source IAM platform with MetaMask Web3
  login as one of many identity providers.
- **Limitations:** MetaMask/Web3 login is a "social login provider" within a
  large IAM platform. The Ethereum address is bound as an attribute on a
  traditional user account. No CAIP-122 message format, no multi-chain DID
  support, no MSC3861-specific features.
- **Assessment:** Could serve as a general OIDC IdP for Matrix, but the wallet
  integration is superficial (address binding, not DID-based identity).

#### walt.id IDP Kit

- **URL:** github.com/walt-id/waltid-idpkit (25 stars)
- **Last commit:** July 2024
- **What it does:** OIDC identity provider supporting SIWE and Verifiable
  Credentials (SIOPv2). Translates OIDC auth requests into SIWE or VC
  presentation requests.
- **Limitations:** Abandoned. Dependencies (SSI-Kit, Wallet-Kit) were officially
  discontinued Q3 2024. Successor monorepo does not include an IDP Kit equivalent.
- **Assessment:** Was the most architecturally similar project. Now dead.

#### GAIA-X ssi-to-oidc-bridge (vclogin + Ory Hydra)

- **URL:** github.com/GAIA-X4PLC-AAD/ssi-to-oidc-bridge
- **What it does:** Bridges Verifiable Credential wallet presentations (OID4VP) to
  standard OIDC tokens via Ory Hydra.
- **Limitations:** Focused on Verifiable Credentials, not CAIP-122 wallet
  signatures. No direct wallet signing. No MSC3861 support. Academic/research
  project context.
- **Assessment:** Good reference architecture for VC-to-OIDC bridging. Different
  authentication model from siwx-oidc.

#### web3-login

- **URL:** github.com/web3-login/web3-login
- **Last commit:** January 2024
- **What it does:** OIDC provider using Ethereum addresses as identity, with NFT
  ownership for access control.
- **Limitations:** Ethereum-only, NFT-gated access model, unmaintained.

#### DefGuard/avanguard

- **URL:** github.com/DefGuard/avanguard (5 stars)
- **What it does:** Microservice performing "OIDC-like" sign-in with a Web3
  wallet. Part of DefGuard VPN ecosystem.
- **Limitations:** "OIDC-like" rather than fully OIDC-compliant. Tiny project.

#### Hanko

- **URL:** github.com/teamhanko/hanko
- **What it does:** Passkey-first authentication platform with OIDC support.
  Open-source alternative to Auth0/Clerk.
- **Limitations:** No wallet/Web3/SIWE/CAIP-122 support. Traditional user account
  model.

#### Commercial wallet auth providers

- **Privy:** Acquired by Stripe (June 2025). Closed-source, SaaS-only.
- **Dynamic:** Acquired by Fireblocks (2025). Closed-source, SaaS-only.
- **Web3Auth:** Acquired by MetaMask/Consensys. Partially open-source (client
  SDKs), but infrastructure is SaaS.
- None are self-hosted OIDC providers. None support MSC3861. All are now owned by
  larger companies with different strategic priorities.

## Why this matters for the Ethereum community

Matrix is the only widely deployed, end-to-end encrypted, federated messaging
protocol with an open spec. Ethereum projects that need secure communication (DAOs,
multisig coordination, protocol governance, support channels) currently face a
choice: use Matrix with traditional accounts (email/password), or use centralized
alternatives (Discord, Telegram).

siwx-oidc removes that trade-off. An Ethereum address becomes a Matrix identity
directly. No account creation, no email, no password. The user's existing wallet is
the credential.

Concrete use cases:

- **DAO governance channels** where membership is verifiable on-chain (the Matrix
  user ID contains the Ethereum address).
- **Multisig coordination** where participants are authenticated by the same keys
  that sign transactions.
- **Protocol teams** that want self-hosted, encrypted communication without
  requiring team members to create yet another account.
- **Any dApp** that already has wallet-connected users and wants to add messaging
  without introducing a separate identity system.

The passkey path matters because not every user has a wallet. A new user can
register with a fingerprint on their phone, get a `did:key` identity, and start
using Matrix immediately. If they later connect a wallet, the passkey can be linked
to their wallet DID. This lowers the barrier from "install MetaMask" to "tap your
fingerprint."

The implementation is a single self-hostable binary, not a SaaS dependency. It runs
alongside Synapse on the same server. There is no vendor, no API key, no
third-party token custody.
