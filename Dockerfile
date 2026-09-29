# syntax=docker/dockerfile:1
# Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
# Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
# Modified by inblock.io assets GmbH. See NOTICE.

# Every base image is pinned to the digest of its multi-arch index, so a rebuild
# starts from the bytes the tag named when it was pinned, not from whatever the
# tag has moved to since. Dependabot is disabled for this repository, so bump by
# hand: resolve the tag's current index digest, e.g.
#   docker buildx imagetools inspect docker.io/library/alpine:3.24   (the "Digest:" line)
#   skopeo inspect --raw docker://docker.io/library/alpine:3.24 | sha256sum
# and replace tag and digest together. Tool versions installed with
# `cargo install` are pinned the same way, by `--version` plus `--locked`.

FROM docker.io/clux/muslrust:stable@sha256:fb4bd163dc90d308e1071d728f63306f624aae32775a3d5f6d57d397e91e1d05 AS chef
WORKDIR /siwx-oidc
RUN cargo install cargo-chef --version 0.1.78 --locked

# A stage of its own, so bumping cargo-about does not invalidate the dependency
# cache below. The `cli` feature is what builds the binary.
FROM chef AS about
RUN cargo install cargo-about --version 0.9.2 --locked --features cli

FROM chef AS dep_planner
COPY ./src/ ./src/
COPY ./siwx-oidc-auth/ ./siwx-oidc-auth/
COPY ./Cargo.lock ./
COPY ./Cargo.toml ./
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS dep_cacher
COPY --from=dep_planner /siwx-oidc/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json

FROM docker.io/library/node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS node_builder
ADD --chown=node:node ./static /siwx-oidc/static
ADD --chown=node:node ./js/ui /siwx-oidc/js/ui
WORKDIR /siwx-oidc/js/ui
# Installs exactly package-lock.json and fails if package.json disagrees with it.
RUN npm ci
# Also writes static/build/third-party-licenses.txt, and fails on a bundled
# package whose license is not accepted (js/ui/third-party-licenses.js).
RUN npm run build

FROM chef AS builder
COPY --from=dep_cacher /siwx-oidc/target/ ./target/
COPY --from=dep_cacher $CARGO_HOME $CARGO_HOME
COPY --from=dep_planner /siwx-oidc/ ./
RUN cargo build --release --locked
# License texts of every crate linked into the two binaries (scope and the
# accepted-license allowlist: about.toml). The script fails the build on an
# unaccepted license AND on any cargo-about warning, such as a clarification
# whose checksum no longer matches; it says why cargo-about's exit status alone
# is not enough.
COPY --from=about $CARGO_HOME/bin/cargo-about $CARGO_HOME/bin/
COPY about.toml about.hbs ./
COPY scripts/third-party-notices.sh ./scripts/
RUN ./scripts/third-party-notices.sh THIRD-PARTY-LICENSES-rust.txt

# The license texts of the Alpine packages in the runtime base below: the
# canonical texts from SPDX license-list-data at a pinned tag, each checked
# against its SHA-256 on download. Which licenses are needed is not decided
# here: the final stage fails the build when an installed package declares a
# license with no text in this set, so an Alpine bump that brings a new license
# stops until its text is added. Docker gives a remote ADD mode 0600, hence --chmod.
FROM scratch AS alpine_licenses
ARG SPDX_TEXT=https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/text
ADD --chmod=0644 --checksum=sha256:074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff ${SPDX_TEXT}/Apache-2.0.txt /alpine/Apache-2.0.txt
ADD --chmod=0644 --checksum=sha256:f32fb3b417a194167cfad068223fc975ba96c5960513a10f66a3c28720aec1df ${SPDX_TEXT}/BSD-2-Clause.txt /alpine/BSD-2-Clause.txt
ADD --chmod=0644 --checksum=sha256:aaf135472f81c5b4a0dca9367e5bb5e9750032b5bebe5442b36e4c0a47430df3 ${SPDX_TEXT}/GPL-2.0-only.txt /alpine/GPL-2.0-only.txt
ADD --chmod=0644 --checksum=sha256:aaf135472f81c5b4a0dca9367e5bb5e9750032b5bebe5442b36e4c0a47430df3 ${SPDX_TEXT}/GPL-2.0-or-later.txt /alpine/GPL-2.0-or-later.txt
ADD --chmod=0644 --checksum=sha256:b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5 ${SPDX_TEXT}/MIT.txt /alpine/MIT.txt
ADD --chmod=0644 --checksum=sha256:66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172 ${SPDX_TEXT}/MPL-2.0.txt /alpine/MPL-2.0.txt
ADD --chmod=0644 --checksum=sha256:bfb1112d49db5b1daecdfef24bd7e2f3ea0bafb33aa67aa0ab51e2bf8407c03d ${SPDX_TEXT}/Zlib.txt /alpine/Zlib.txt

# NOTICE names this Alpine release and where its source is; bump them together
# (the license check at the end of this stage fails when they disagree).
FROM docker.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# A fixed unprivileged UID/GID, so file ownership on mounted volumes and
# `runAsUser` policies can name it. Nothing is written at runtime (state lives
# in Redis); the binaries and static/ stay root-owned and world-readable.
RUN addgroup -S -g 10001 siwx-oidc \
    && adduser -S -D -H -u 10001 -G siwx-oidc -s /sbin/nologin siwx-oidc
COPY --from=builder /siwx-oidc/target/x86_64-unknown-linux-musl/release/siwx-oidc /usr/local/bin/
# The credential backfill operator tool. `cargo build --release` above already
# produces it, so shipping it costs nothing but is REQUIRED: the aqua-auth 0.7.0
# migration cannot be run anywhere it is actually needed (dev-staging, prod) if
# the only artifact in the image is the server.
COPY --from=builder /siwx-oidc/target/x86_64-unknown-linux-musl/release/migrate-credentials /usr/local/bin/
WORKDIR /siwx-oidc
RUN mkdir -p ./static
COPY --from=node_builder /siwx-oidc/static/ ./static/
# Apache-2.0 section 4(a) and (d): every copy of the Work, the image included,
# carries the license and the NOTICE. Copied straight from the build context,
# which .dockerignore does not filter, so no build stage has to carry them.
# --chmod, because a context file keeps the builder's mode: a checkout made
# under umask 002 would otherwise ship them group-writable.
COPY --chmod=0644 LICENSE NOTICE /usr/share/licenses/siwx-oidc/
# The third-party notices the MIT, BSD and Apache licenses of the linked crates
# and the bundled npm packages require in binary distributions (see NOTICE).
COPY --from=builder --chmod=0644 /siwx-oidc/THIRD-PARTY-LICENSES-rust.txt /usr/share/licenses/siwx-oidc/
COPY --from=node_builder --chmod=0644 /siwx-oidc/static/build/third-party-licenses.txt /usr/share/licenses/siwx-oidc/THIRD-PARTY-LICENSES-js.txt
# The license texts of this base image's packages (stage alpine_licenses),
# already 0644 from their ADD.
COPY --from=alpine_licenses /alpine/ /usr/share/licenses/alpine/
# Keeps what ships in step with what is installed. Fails the build when a
# package's declared license (its L: line in the apk database, an SPDX
# expression) has no text in /usr/share/licenses/alpine/, or when NOTICE does
# not name this Alpine release and its source. Keep it after any `apk add`.
RUN missing=$(awk '/^L:/ { sub(/^L:/, ""); gsub(/[()]/, " "); \
            for (i = 1; i <= NF; i++) if ($i != "AND" && $i != "OR" && $i != "WITH") print $i }' \
            /lib/apk/db/installed | sort -u | while read -r id; do \
            [ -f "/usr/share/licenses/alpine/$id.txt" ] || echo "$id"; done); \
    if [ -n "$missing" ]; then \
        echo "No license text in /usr/share/licenses/alpine/ for:" $missing \
             "- add it to the alpine_licenses stage." >&2; \
        exit 1; \
    fi; \
    rel=$(cat /etc/alpine-release); \
    for s in "Alpine Linux $rel" "aports/-/tree/v$rel" "distfiles/v${rel%.*}/"; do \
        grep -qF "$s" /usr/share/licenses/siwx-oidc/NOTICE \
            || { echo "NOTICE does not name '$s': update it for this base image." >&2; exit 1; }; \
    done
# No config file ships in the image: every setting has a default or comes from
# SIWXOIDC_* env (see config::figment). This one only makes the listener
# reachable from outside the container. The new prefix outranks the legacy
# SIWEOIDC_ one, so a deployment that needs a DIFFERENT bind address must set
# SIWXOIDC_ADDRESS; a legacy SIWEOIDC_ADDRESS cannot override this line.
ENV SIWXOIDC_ADDRESS="0.0.0.0"
EXPOSE 8000
# Numeric, so a runtime that enforces runAsNonRoot can verify it without
# reading /etc/passwd.
USER 10001:10001
ENTRYPOINT ["siwx-oidc"]
LABEL org.opencontainers.image.source="https://github.com/inblockio/siwx-oidc"
LABEL org.opencontainers.image.description="Key-first OpenID Connect provider and Matrix auth service: agents and people sign in with their own key, no passwords."
LABEL org.opencontainers.image.licenses="Apache-2.0"
