Build, test, and optionally push the siwx-oidc Docker image.

## Steps

1. Run the siwx-core tests first (fast, catches Rust issues early):
```bash
cargo test -p siwx-core
cargo clippy -p siwx-core -- -D warnings
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

5. If the user wants to push, confirm first, then:
```bash
docker push ghcr.io/inblockio/siwx-oidc:latest
```

Note: Pushing to GHCR normally happens via CI (GitHub Actions on push to main).
Manual push requires `docker login ghcr.io` with a PAT that has `write:packages` scope.

## Common issues

- **webpack `fullySpecified` errors**: ESM modules in node_modules need `fullySpecified: false` rule in webpack.config.js
- **clippy failures on CI but not locally**: CI uses latest stable Rust, check with `rustup update && cargo clippy`
- **Docker build fails at npm step**: The node_builder stage is independent — check `npm run build` locally first
- **Image too large**: Should be ~18MB. If much larger, check that the multi-stage build is working (final stage is `FROM alpine`, not the build stage)
