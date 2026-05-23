Build, test, and optionally push the siwx-oidc Docker image.

Docker images are built by GitHub Actions CI on push to main. Manual local
builds should only be used for testing, never for production deployment.

## Steps

1. Run tests first (catches Rust issues early):
```bash
cd ../aqua-auth && cargo test --features webauthn && cd -
cargo clippy --workspace -- -D warnings
```

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

# Verify the binary runs
docker run --rm ghcr.io/inblockio/siwx-oidc:latest --help 2>&1 || true

# Verify wget exists (needed for health checks)
docker run --rm --entrypoint which ghcr.io/inblockio/siwx-oidc:latest wget
```

5. Push to GitHub and let CI publish to GHCR:
```bash
git push origin main
gh run list -R inblockio/siwx-oidc --limit 1  # watch CI
```

Watchtower on the production server auto-pulls new images every 5 minutes.
No manual deployment steps needed.

## Common issues

- **webpack `fullySpecified` errors**: ESM modules in node_modules need `fullySpecified: false` rule in webpack.config.js
- **clippy failures on CI but not locally**: CI uses latest stable Rust, check with `rustup update && cargo clippy`
- **Docker build fails at npm step**: The node_builder stage is independent; check `npm run build` locally first
- **Image too large**: Should be ~18MB. If much larger, check that the multi-stage build is working (final stage is `FROM alpine`, not the build stage)
