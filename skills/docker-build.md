Build, test, and optionally push the siwx-oidc Docker image.

Docker images are built by GitHub Actions CI on push to main. Manual local
builds should only be used for testing, never for production deployment.

## Steps

1. Run the checks CI runs first (catches Rust issues early; `cargo test` needs Redis on
   localhost:6379, e.g. `docker run -d --rm --name siwx-redis -p 6379:6379 redis:7-alpine`):
```bash
cargo fmt -- --check
cargo clippy --workspace -- -D warnings
cargo test
```
aqua-auth is a pinned git dependency; its own tests run in its repository.

2. Run the frontend build locally to catch webpack errors before Docker:
```bash
cd js/ui && npm install --legacy-peer-deps && npm run build && cd ../..
```

3. Build the Docker image:
```bash
docker build -t ghcr.io/inblockio/siwx-oidc:latest .
```

4. Verify the image:
```bash
# Check image size (should be ~18MB)
docker images ghcr.io/inblockio/siwx-oidc:latest

# Verify both binaries are in the image (the server takes no CLI arguments;
# it reads SIWXOIDC_* configuration and starts)
docker run --rm --entrypoint ls ghcr.io/inblockio/siwx-oidc:latest /usr/local/bin
docker run --rm --entrypoint migrate-credentials ghcr.io/inblockio/siwx-oidc:latest --help

# Verify wget exists (needed for health checks)
docker run --rm --entrypoint which ghcr.io/inblockio/siwx-oidc:latest wget
```

5. Push to GitHub and let CI publish to GHCR:
```bash
git push origin main
gh run list -R inblockio/siwx-oidc --limit 1  # watch CI
```

Publishing to GHCR does not by itself deploy anything: roll the new image out
on your host (`docker compose pull siwx-oidc && docker compose up -d siwx-oidc`)
and verify with `/deploy-check`. If you rely on an auto-updater such as
watchtower, confirm it actually watches the siwx-oidc container (scope/label
configuration) before trusting it.

## Common issues

- **webpack `fullySpecified` errors**: ESM modules in node_modules need `fullySpecified: false` rule in webpack.config.js
- **clippy failures on CI but not locally**: CI uses latest stable Rust, check with `rustup update && cargo clippy`
- **Docker build fails at npm step**: The node_builder stage is independent; check `npm run build` locally first
- **Image too large**: Should be ~18MB. If much larger, check that the multi-stage build is working (final stage is `FROM alpine`, not the build stage)
