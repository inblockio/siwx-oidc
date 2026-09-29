# Contributing to siwx-oidc

Contributions are welcome: bug reports, fixes, documentation, tests, and reports of what did or
did not work in your deployment. Agent-assisted contributions are welcome too. The same rules
apply to them (see [AGENTS.md](AGENTS.md)), and the person who submits is responsible for what
they submit.

## What to expect

siwx-oidc is a pathfinder project for agent identity on Matrix, run by inblock.io assets GmbH on
a non-commercial basis and provided as is. The maintainers maintain it for their own use, so:

- review is **best-effort**, with no timelines;
- scope is decided by what the maintainers need; a good change can still be declined if it adds
  something we cannot maintain;
- interfaces may change without notice, and there are no tagged releases yet (`main` is what
  runs).

For anything larger than a small fix, please **open an issue first** and describe what you want
to change and why. That saves you work if the direction does not fit.

## Getting started

You need recent stable Rust and a Redis on `localhost:6379`:

```bash
docker run -d --name siwx-redis -p 6379:6379 redis

cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets        # CI sets RUSTFLAGS=-Dwarnings
cargo test --workspace                        # unit and integration tests; needs Redis
```

CI (`.github/workflows/ci.yml`) runs the same commands on every pull request, plus the
mock-stack and browser end-to-end suites and a build of the container image.

- `cargo test --test openapi_covers_every_route` fails when a route exists in the router
  (`src/axum_lib.rs`) but not in [docs/api/openapi.yaml](docs/api/openapi.yaml). Adding an
  endpoint means documenting it in the same change.
- The end-to-end suites (`tests/e2e_*.rs`) are `#[ignore]`d, apart from one pure check each in
  `e2e_account_lifecycle_live` and `e2e_did_field_live`. They need a running siwx-oidc, and some need a real homeserver;
  CI runs the mock-stack suites against a Synapse mock. Run one with
  `cargo test --test <name> -- --ignored --test-threads=1`. The other files in `tests/` run by
  default; `account_linking_dual_write` needs the Redis above, and `credential_migration_live`
  runs only when `MIGRATION_TEST_REDIS_URL` points at a disposable Redis.
- The sign-in frontend lives in `js/ui/`: `npm ci && npm run build` writes to `static/build/`.
- CAIP-122 and DID verification live in the external aqua-auth crate
  ([inblockio/aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth)), with its own tests.

To run the server locally, see the [quick start](README.md#quick-start).

## Conventions

- **Read [AGENTS.md](AGENTS.md) before changing code.** It lists the invariants the code
  depends on. Many tests pin a behaviour that looks simplifiable and is not (for example why an
  empty `device_id` is sent as `null` or why a status check matches exactly 500). If a test
  stands in your way, find out what it protects before changing it.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) with a
  scope, as in the history: `fix(resolve): …`, `feat(identity): …`, `docs(api): …`,
  `test(e2e): …`, `ci(docker): …`. Say *why* in the body.
- Keep a pull request to one concern, with tests for behaviour changes.
- Update the documentation that describes what you changed ([docs/](docs/README.md),
  `openapi.yaml`).
- Never commit secrets, host names or credentials of a real deployment.

## Licensing

siwx-oidc is licensed under Apache-2.0. By submitting a contribution you agree that it is
licensed under Apache-2.0, as section 5 of the license provides (inbound = outbound). There is
**no CLA**. You confirm that you have the right to submit the contribution under that license.

## Security issues

Do not report vulnerabilities in public issues or pull requests. See [SECURITY.md](SECURITY.md).
