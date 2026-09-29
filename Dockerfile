# syntax=docker/dockerfile:1
# Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
# Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
# Modified by inblock.io assets GmbH. See NOTICE.

FROM clux/muslrust:stable AS chef
WORKDIR /siwx-oidc
RUN cargo install cargo-chef

FROM chef AS dep_planner
COPY ./src/ ./src/
COPY ./siwx-oidc-auth/ ./siwx-oidc-auth/
COPY ./Cargo.lock ./
COPY ./Cargo.toml ./
COPY ./siwe-oidc.toml ./
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS dep_cacher
COPY --from=dep_planner /siwx-oidc/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM node:22-alpine AS node_builder
ADD --chown=node:node ./static /siwx-oidc/static
ADD --chown=node:node ./js/ui /siwx-oidc/js/ui
WORKDIR /siwx-oidc/js/ui
RUN npm install --legacy-peer-deps
RUN npm run build

FROM chef AS builder
COPY --from=dep_cacher /siwx-oidc/target/ ./target/
COPY --from=dep_cacher $CARGO_HOME $CARGO_HOME
COPY --from=dep_planner /siwx-oidc/ ./
RUN cargo build --release

FROM alpine
COPY --from=builder /siwx-oidc/target/x86_64-unknown-linux-musl/release/siwx-oidc /usr/local/bin/
# The credential backfill operator tool. `cargo build --release` above already
# produces it, so shipping it costs nothing but is REQUIRED: the aqua-auth 0.7.0
# migration cannot be run anywhere it is actually needed (dev-staging, prod) if
# the only artifact in the image is the server.
COPY --from=builder /siwx-oidc/target/x86_64-unknown-linux-musl/release/migrate-credentials /usr/local/bin/
WORKDIR /siwx-oidc
RUN mkdir -p ./static
COPY --from=node_builder /siwx-oidc/static/ ./static/
COPY --from=builder /siwx-oidc/siwe-oidc.toml ./
# Apache-2.0 section 4(a) and (d): every copy of the Work, the image included,
# carries the license and the NOTICE. Copied straight from the build context,
# which .dockerignore does not filter, so no build stage has to carry them.
COPY LICENSE NOTICE /usr/share/licenses/siwx-oidc/
ENV SIWEOIDC_ADDRESS="0.0.0.0"
EXPOSE 8000
ENTRYPOINT ["siwx-oidc"]
LABEL org.opencontainers.image.source="https://github.com/inblockio/siwx-oidc"
LABEL org.opencontainers.image.description="Key-first OpenID Connect provider and Matrix auth service: agents and people sign in with their own key, no passwords."
LABEL org.opencontainers.image.licenses="Apache-2.0"
