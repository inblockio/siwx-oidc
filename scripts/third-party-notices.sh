#!/usr/bin/env bash
# Writes the license texts of every Rust crate linked into the shipped binaries
# (siwx-oidc, migrate-credentials) and FAILS unless cargo-about resolved every
# one of them cleanly. This is the one implementation of that gate: the
# Dockerfile's builder stage runs it, and CI builds the Dockerfile on every pull
# request (.github/workflows/ci.yml, job `image`). Scope and the accepted
# licenses are in about.toml.
#
# Two ways cargo-about 0.9.2 ships an incomplete notices file and still exits 0:
# - A clarification in about.toml whose checksum no longer matches (a dependency
#   bump changed its license file) is only a warning. cargo-about then falls
#   back to the bare SPDX text, which drops the copyright lines the MIT and BSD
#   licenses require us to reproduce.
# - Its log tags carry ANSI colour codes even under `--color never`
#   ("[ESC[33mWARNESC[0m]"), so a plain grep for "[WARN]" never matches.
# So the gate strips the escapes before matching, and fails on any WARN or ERROR
# line as well as on a non-zero exit (`--fail`: a license about.toml does not
# accept).
#
# Usage: scripts/third-party-notices.sh [OUTPUT]
#   OUTPUT is relative to the repository root, default THIRD-PARTY-LICENSES-rust.txt.
#   Needs cargo-about 0.9.2 built with `--features cli` (see the Dockerfile).
set -euo pipefail

cd "$(dirname "$0")/.."
out=${1:-THIRD-PARTY-LICENSES-rust.txt}
log=$(mktemp)
trap 'rm -f "$log"' EXIT

status=0
# -L warn is cargo-about's default, spelled out so that a changed default
# cannot silence the lines this gate reads.
cargo about -L warn --color never generate --locked --fail about.hbs -o "$out" \
    2>"$log" || status=$?
cat "$log" >&2

esc=$(printf '\033')
findings=$(sed "s/${esc}\[[0-9;]*m//g" "$log" | grep -E '\[(WARN|ERROR)\]' || true)

if [ "$status" -ne 0 ] || [ -n "$findings" ]; then
    rm -f "$out"
    echo "third-party-notices: FAILED (cargo-about exit status $status)." >&2
    if [ -n "$findings" ]; then
        echo "Every WARN or ERROR above fails the gate. A checksum mismatch means a" >&2
        echo "clarified license file changed: read the new file, then put its" >&2
        echo "sha256sum into about.toml." >&2
    fi
    exit 1
fi
echo "third-party-notices: wrote $out" >&2
