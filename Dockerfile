FROM clux/muslrust:stable as chef
WORKDIR /siwx-oidc
RUN cargo install cargo-chef

FROM chef as dep_planner
COPY ./src/ ./src/
COPY ./siwx-core/ ./siwx-core/
COPY ./siwx-oidc-auth/ ./siwx-oidc-auth/
COPY ./Cargo.lock ./
COPY ./Cargo.toml ./
COPY ./siwe-oidc.toml ./
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef as dep_cacher
COPY --from=dep_planner /siwx-oidc/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM node:22-alpine as node_builder
ENV PROJECT_ID=""
ADD --chown=node:node ./static /siwx-oidc/static
ADD --chown=node:node ./js/ui /siwx-oidc/js/ui
WORKDIR /siwx-oidc/js/ui
RUN npm install --legacy-peer-deps
RUN npm run build

FROM chef as builder
COPY --from=dep_cacher /siwx-oidc/target/ ./target/
COPY --from=dep_cacher $CARGO_HOME $CARGO_HOME
COPY --from=dep_planner /siwx-oidc/ ./
RUN cargo build --release

FROM alpine
COPY --from=builder /siwx-oidc/target/x86_64-unknown-linux-musl/release/siwx-oidc /usr/local/bin/
WORKDIR /siwx-oidc
RUN mkdir -p ./static
COPY --from=node_builder /siwx-oidc/static/ ./static/
COPY --from=builder /siwx-oidc/siwe-oidc.toml ./
ENV SIWEOIDC_ADDRESS="0.0.0.0"
EXPOSE 8000
ENTRYPOINT ["siwx-oidc"]
LABEL org.opencontainers.image.source https://github.com/inblockio/siwx-oidc
LABEL org.opencontainers.image.description "CAIP-122 to OpenID Connect bridge — Sign-In With X for any DID method"
LABEL org.opencontainers.image.licenses "MIT OR Apache-2.0"
