# Security policy

siwx-oidc is a pathfinder project run by inblock.io assets GmbH on a non-commercial basis and
provided as is, without warranty (Apache-2.0 §§7–8). There is no support offering, no SLA, and
no commitment to maintain it for third-party deployments. Security reports are welcome and
handled best-effort.

## Supported versions

There are no tagged releases yet. Only the latest commit on `main` is supported; fixes land there
and are not backported. The container image `ghcr.io/inblockio/siwx-oidc:latest` is built from
`main`.

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request for a vulnerability.

Report privately through GitHub (the repository's **Security** tab → **Report a
vulnerability**) or by email to **hello@inblock.io** with `SECURITY` in the subject.

Please include:

- what is affected (endpoint, flow, crate or file) and the commit you tested;
- steps to reproduce, or a proof of concept;
- the impact as you understand it (for example account takeover, token leakage, identity
  confusion between DIDs or Matrix IDs);
- whether the issue is already public, and how you would like to be credited.

## What to expect

Reports are acknowledged and handled on a best-effort basis. There are **no guaranteed response
or fix times**, no SLA and no bug bounty. We aim to tell you what we decide to do about a
confirmed issue, and to credit you in the fix unless you ask us not to. Please give us a
reasonable chance to fix the issue before you disclose it.

## Scope

In scope: the code in this repository, that is the `siwx-oidc` server, the `siwx-oidc-auth`
client, the sign-in frontend in `js/ui/`, the guest flow (`/guest/*`, `src/guest/`, `static/guest/`;
see below), and the published container image.

Out of scope here:

- the bundled Matrix deployment (Synapse configuration and patches, Element Web patches, reverse
  proxy): report to [siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server);
- CAIP-122 and DID verification inside the aqua-auth crate: report to
  [aqua-auth](https://github.com/inblockio/aqua-auth) (if unsure, report here and we
  will route it);
- vulnerabilities in Synapse, Element or other upstream projects: report to those projects.

## Guest mode

Guest mode (off by default, [operator guide](docs/guest-portal.md)) lets a person with a single-use
link join a call as a short-lived, restricted account. It is in scope. The surface a report should
look at: `/guest/peek`, `/redeem`, `/continue`, `/claim/*`, `/resume`, `/end`, the host routes
(`/guest/invites`, `/guest/meetings/end`), the `sign_in` guest branch, the reaper and the
`guest:control` kill switch.

Threat summary:

- **Link secret.** Only its SHA-256 is stored; an unknown id, a wrong secret and a bad body answer
  alike (`invalid_link`); the secret travels in the URL fragment and the request body, never in a path
  or query.
- **Browser-made identity.** The guest's `did:key` is generated in the guest's browser and proved by
  signature at redeem and hand-off. **The server never holds, derives or receives private key
  material.** A report that shows the server handling a guest private key is a vulnerability.
- **Confinement.** A guest DID is refused by every signature path except the live hand-off
  (`403 guest_identity`), and after the reap it is tombstoned (`erased:did`). Confinement inside Matrix
  (rooms, messages, invites, uploads) is the Synapse policy module's job, outside this repository.
- **Browser surface.** Every `/guest` response carries a strict CSP (no inline script),
  `X-Frame-Options: DENY`, `no-referrer`, `nosniff` and `no-store`; cookie-group POSTs must be provably
  same-origin and JSON, bodies are capped at 4 KiB (16 KiB on `claim/finish`), and the cookie routes
  answer no CORS.
- **Abuse bounds.** Per-host and global quotas, a daily mint ceiling, a reaping brake, a kill switch and
  audit events with alerts. Per-address rate limits are the reverse proxy's job (checked by
  `scripts/check-guest-proxy.sh`).

Residues we accept and do not hide (each is a reviewable entry in
[`security/EXCEPTIONS.md`](security/EXCEPTIONS.md#guest-mode-residual-risks)): the private key lives only
in the guest's browser and the server holds the public DID, so the server cannot prove a browser that
never returns forgot its key; other participants may have seen or recorded the call; a stale call-member
entry stays in the room; the SFU token outlives removal for up to its lifetime; backups and logs hold
personal data until their retention runs out. Reporting is unchanged: use the private channels above.

## Existing security material

- [`security/EXCEPTIONS.md`](security/EXCEPTIONS.md): accepted security-advisory exceptions,
  with justification, evidence and a review trigger for each, and the guest-mode residual risks.
- [`security/vex/`](security/vex/): the same exceptions as OpenVEX statements.
- [`.cargo/audit.toml`](.cargo/audit.toml): the `cargo audit` ignore list; every entry must have
  a row in `EXCEPTIONS.md` and a VEX statement.
- [`docs/audits/`](docs/audits/): dated audits and live probes of specific features.
