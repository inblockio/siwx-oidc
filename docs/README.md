# Documentation

An index of the documentation in this repository. Start with the project
[README](../README.md).

## Guides

| Page | What it covers |
|---|---|
| [agents.md](agents.md) | Signing in software agents with their own key: `siwx-oidc-auth` CLI and library, stable devices, refresh, the device flow, verifying other parties, key custody |
| [identity-model.md](identity-model.md) | The three identifiers (alias, MXID, DID), MXID derivation and grandfathering, the `io.inblock.did` wire format, trust model, publication, verification, `GET /resolve`, the `io.inblock.mxid` claim |
| [matrix-integration.md](matrix-integration.md) | Wiring siwx-oidc into Synapse, dependencies and risks, MSC3861 history, token model, admin-token mint, device lifecycle, MSC4191 account management, device-code/QR login, cross-signing, what is not supported |
| [passkeys.md](passkeys.md) | WebAuthn architecture, DID derivation, linking to a wallet, picker scoping, the new-account policy, unknown credentials |
| [troubleshooting.md](troubleshooting.md) | Symptoms and fixes for headless, wallet, passkey, account, QR and DID problems; Redis inspection |
| [architecture.md](architecture.md) | Layers, code map, DID methods, frontend, Redis keyspace, logging, lineage from siwe-oidc |
| [configuration.md](configuration.md) | Every configuration option, key rotation, reverse proxy and CORS, running with Docker |
| [comparison.md](comparison.md) | How siwx-oidc compares with MAS and other options, including putting siwx-oidc behind MAS |

For contributors: [AGENTS.md](../AGENTS.md) (code rules and invariants),
[CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).

## API reference

| Path | What it covers |
|---|---|
| [api/README.md](api/README.md) | Which credential each endpoint wants, common flows, error conventions |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI description of every route; a test fails the build if a route is missing from it |

## Protocol reference

| Path | What it covers |
|---|---|
| [element-x-qr-code-protocol-spec.md](element-x-qr-code-protocol-spec.md) | MSC4108, MSC4388, MSC4341 and RFC 8628 as they apply to Element X QR login against siwx-oidc and Synapse (status as of May 2026) |

## Design notes

Dated records of design decisions. Later code may differ; the guides above
describe the current behaviour.

| Path | What it covers |
|---|---|
| [design/webauthn-plan.md](design/webauthn-plan.md) | The original plan for passkey login (2026-03) |
| [design/2026-06-18-passkey-scoping-and-new-user-gate.md](design/2026-06-18-passkey-scoping-and-new-user-gate.md) | Scoping the passkey picker and gating accidental account creation |
| [design/2026-06-19-passkey-offer-scoping-minimal-behavior.md](design/2026-06-19-passkey-offer-scoping-minimal-behavior.md) | The minimal behaviour for which passkeys are offered in each flow |
| [design/2026-07-25-webauthn-prf-4s-unlock-evaluation.md](design/2026-07-25-webauthn-prf-4s-unlock-evaluation.md) | Evaluation of WebAuthn PRF as a Matrix secret-storage unlock (rejected as proposed) |
| [design/2026-09-09-did-profile-field-feasibility.md](design/2026-09-09-did-profile-field-feasibility.md) | Feasibility of publishing the DID as an MSC4133 profile field on Synapse 1.159.0 |
| [design/guest-portal/00-overview.md](design/guest-portal/00-overview.md) | Draft design set for anonymous guests joining a Matrix video call by link: flow model, Synapse validation, guest client, security limits, claim by passkey, wireframes, implementation plan (design only, nothing implemented), reference material and the prepared next step, a consolidation session |

## Audits and findings

Dated investigation records. Each reflects the code and deployment at its date;
some cite internal working documents that are not part of this repository.

| Path | What it covers |
|---|---|
| [audit/msc3861-compliance-audit.md](audit/msc3861-compliance-audit.md) | May 2026 audit against MSC3861. Historical: written while the deployment used Synapse's experimental `msc3861` configuration; its "replaces MAS entirely" wording is superseded by [matrix-integration.md](matrix-integration.md) |
| [2026-06-14-account-management-e2e-findings.md](2026-06-14-account-management-e2e-findings.md) | Account erasure and device deletion in the browser; the single-re-auth account session |
| [audits/2026-06-18-passkey-code-review-open-findings.md](audits/2026-06-18-passkey-code-review-open-findings.md) | Open findings from a review of the passkey work |
| [audits/2026-06-23-elementx-refresh-rotation-signout.md](audits/2026-06-23-elementx-refresh-rotation-signout.md) | Mobile sign-outs caused by refresh-token rotation without a grace window, and the fix |
| [audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md](audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md) | Why Element Web 1.12.24 (matrix-js-sdk v42) could not log in, and the `response_mode=fragment` fix |
| [audits/2026-07-25-elementweb-jssdk-v42-compat-evidence.spec.mjs.txt](audits/2026-07-25-elementweb-jssdk-v42-compat-evidence.spec.mjs.txt) | The diagnostic browser spec behind that finding |
| [audits/2026-07-25-recovery-entry-and-qr-capability-audit.md](audits/2026-07-25-recovery-entry-and-qr-capability-audit.md) | Recovery-phrase entry and QR second-device login: capability audit |
| [audits/2026-07-25-state-machine-coverage-matrix.md](audits/2026-07-25-state-machine-coverage-matrix.md) | Test coverage of the session and onboarding state machines |
| [audits/2026-07-25-verify-gate-root-cause-SETTLED.md](audits/2026-07-25-verify-gate-root-cause-SETTLED.md) | Root cause of the Element Web "verify this device" trap |
| [audits/2026-07-25-verify-with-other-device-gap-evaluation.md](audits/2026-07-25-verify-with-other-device-gap-evaluation.md) | Whether "verify with other device" is integrated |
| [audits/2026-07-25-R3-recheck-verdict.md](audits/2026-07-25-R3-recheck-verdict.md) | Adversarial re-check of a session-durability requirement (short Redis outages) |
| [audits/2026-07-25-R4-recheck-verdict.md](audits/2026-07-25-R4-recheck-verdict.md) | Adversarial re-check of the "verify with other device" evaluation |
| [audits/2026-07-26-M4-private-half-totality.md](audits/2026-07-26-M4-private-half-totality.md) | Completing the secret-storage state machine's transitions |
| [audits/2026-07-26-ci-promotion-C0.md](audits/2026-07-26-ci-promotion-C0.md) | Moving ignored integration tests into CI |
| [audits/2026-07-26-reset-after-no-recovery-walk.md](audits/2026-07-26-reset-after-no-recovery-walk.md) | Identity reset without a recovery key, reproduced in the lab |
| [audits/2026-07-26-state-machine-reconciliation-ceremony-terminals.md](audits/2026-07-26-state-machine-reconciliation-ceremony-terminals.md) | Naming the missing terminal states of the verification ceremony |
| [audits/2026-09-10-attested-did-audit.md](audits/2026-09-10-attested-did-audit.md) | Adversarial audit of the provider-attested DID field |
| [audits/2026-09-10-msc4133-acl-probe.md](audits/2026-09-10-msc4133-acl-probe.md) | Live A/B probe showing the MSC4133 write-ACL backport protects `io.inblock.did` |
| [audits/2026-09-12-localpart-availability-conflation.md](audits/2026-09-12-localpart-availability-conflation.md) | "Localpart invalid" read as "localpart taken", and the remediation |
| [audits/2026-09-13-post-resolve-slice-adversarial-audit.md](audits/2026-09-13-post-resolve-slice-adversarial-audit.md) | Adversarial audit of `GET /resolve`, the `io.inblock.mxid` claim and their tests |

## User instructions

| Path | What it covers |
|---|---|
| [user-instructions/onboarding-wallet-passkey-flows.md](user-instructions/onboarding-wallet-passkey-flows.md) | End-user guide: wallet and passkey onboarding on computer and phone, and linking them into one account |

## Security

| Path | What it covers |
|---|---|
| [SECURITY.md](../SECURITY.md) | How to report a vulnerability |
| [security/EXCEPTIONS.md](../security/EXCEPTIONS.md) | Accepted security-advisory exceptions, with justification and review triggers |
| [security/vex/siwx-oidc.openvex.json](../security/vex/siwx-oidc.openvex.json) | The same exceptions as OpenVEX statements |

## Skills

[`skills/`](../skills/) holds task checklists written for AI coding assistants
and usable by people: adding a DID method, cipher suite or auth ceremony,
debugging the OIDC flow, cross-signing, Element X QR login, the pre-deployment
check, and building the Docker image.

## Related repositories

- [siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server):
  the Synapse and Element deployment, including the
  [Synapse patch registry](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/synapse/README.md)
  and the [Element Web patch registry](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/element-web/README.md).
- [aqua-auth](https://github.com/inblockio/aqua-auth): the DID and signature
  verification library siwx-oidc builds on.
