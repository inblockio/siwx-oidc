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
client, the sign-in frontend in `js/ui/`, and the published container image.

Out of scope here:

- the bundled Matrix deployment (Synapse configuration and patches, Element Web patches, reverse
  proxy): report to [siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server);
- CAIP-122 and DID verification inside the aqua-auth crate: report to
  [aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth) (if unsure, report here and we
  will route it);
- vulnerabilities in Synapse, Element or other upstream projects: report to those projects.

## Existing security material

- [`security/EXCEPTIONS.md`](security/EXCEPTIONS.md): accepted security-advisory exceptions,
  with justification, evidence and a review trigger for each.
- [`security/vex/`](security/vex/): the same exceptions as OpenVEX statements.
- [`.cargo/audit.toml`](.cargo/audit.toml): the `cargo audit` ignore list; every entry must have
  a row in `EXCEPTIONS.md` and a VEX statement.
- [`docs/audits/`](docs/audits/): dated audits and live probes of specific features.
