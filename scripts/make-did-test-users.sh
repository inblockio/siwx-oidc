#!/usr/bin/env bash
#
# Provision throwaway siwx-oidc identities so the DID -> MXID lookup has
# something to find.
#
# Each named identity gets its own local key (so its did:key is stable across
# runs), signs in through the ordinary authorization-code flow, and therefore
# lands in Synapse exactly the way a real user does: a hash-derived localpart, a
# generated "Firstname Surname" alias, and the provider-attested `io.inblock.did`
# profile field. Nothing here is a shortcut around the real path -- that is the
# point, since what is being tested is the real path.
#
# Idempotent: re-running re-uses the keys, so the DIDs and MXIDs do not move. A
# second run also exercises the re-assertion path (siwx-oidc rewrites the DID
# field on every sign-in), which is how a clobbered field self-heals.
#
#   ./scripts/make-did-test-users.sh                 # alice + bob
#   ./scripts/make-did-test-users.sh carol dave erin # any names you like
#
# Env overrides: SIWX_SERVER, SIWX_HOMESERVER, SIWX_KEYDIR.
set -euo pipefail

SERVER=${SIWX_SERVER:-https://dev.siwx.inblock.io}
HOMESERVER=${SIWX_HOMESERVER:-https://dev.matrix.inblock.io}
KEYDIR=${SIWX_KEYDIR:-$HOME/.cache/siwx-did-test-users}
REDIRECT_URI=${SIWX_REDIRECT_URI:-http://localhost:8999/callback}

cd "$(dirname "$0")/.."
NAMES=("$@")
[ ${#NAMES[@]} -eq 0 ] && NAMES=(alice bob)

mkdir -p "$KEYDIR" && chmod 700 "$KEYDIR"

# One dynamically-registered OIDC client, cached. The client is only the OAuth
# relying party; it has nothing to do with the identities below.
CLIENT_FILE="$KEYDIR/client.json"
if [ ! -s "$CLIENT_FILE" ]; then
    echo "registering an OIDC client with $SERVER ..."
    curl -sS -X POST "$SERVER/register" -H 'Content-Type: application/json' \
        -d "{\"redirect_uris\":[\"$REDIRECT_URI\"],\"client_name\":\"did-search-test\"}" \
        > "$CLIENT_FILE"
fi
CLIENT_ID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['client_id'])" "$CLIENT_FILE")

# The localpart derivation, from the one JS mirror this repo already maintains.
derive_localpart() {
    node -e 'import("./e2e/browser/mxid-helper.mjs").then(m=>console.log(m.localpartFor(process.argv[1])))' "$1"
}
urlencode() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }

# The Matrix server_name, from the homeserver itself -- it is NOT always the
# hostname in the URL, and guessing it wrong builds an MXID that resolves to
# nobody.
SERVER_NAME=$(curl -sS "$HOMESERVER/_matrix/key/v2/server" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['server_name'])")

echo
for name in "${NAMES[@]}"; do
    KEY="$KEYDIR/$name.pem"
    if [ ! -s "$KEY" ]; then
        # Alternate the key type so both did:key prefixes are covered: Ed25519
        # yields z6Mk..., P-256 yields zDn... (the shape a passkey produces).
        if [ $(( $(printf '%s' "$name" | cksum | cut -d' ' -f1) % 2 )) -eq 0 ]; then
            openssl genpkey -algorithm Ed25519 -out "$KEY" 2>/dev/null
        else
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY" 2>/dev/null
        fi
        chmod 600 "$KEY"
    fi

    DID=$(cargo run -q -p siwx-oidc-auth -- --print-did --key-file "$KEY" 2>/dev/null | tail -1)
    # stdout carries the tokens and is discarded on purpose; stderr is captured
    # so a real failure is still reported instead of vanishing with it.
    if ! ERR=$(cargo run -q -p siwx-oidc-auth -- --server "$SERVER" --client-id "$CLIENT_ID" \
        --redirect-uri "$REDIRECT_URI" --key-file "$KEY" 2>&1 >/dev/null); then
        echo "sign-in FAILED for $name:" >&2; echo "$ERR" >&2; exit 1
    fi
    MXID="@$(derive_localpart "$DID"):$SERVER_NAME"

    echo "--- $name"
    echo "    DID   $DID"
    echo "    MXID  $MXID"
    curl -sS "$HOMESERVER/_matrix/client/v3/profile/$(urlencode "$MXID")" | python3 -c "
import sys, json
d = json.load(sys.stdin)
field = d.get('io.inblock.did') or {}
print('    alias', d.get('displayname'))
print('    field', field.get('did'), '(proof:', 'yes)' if field.get('proof') else 'ABSENT)')
assert field.get('did') == '$DID', 'published DID does not match -- lookup will NOT find this user'
"
    # The real check: signature, issuer, and the mxid binding that stops a proof
    # being copied out of somebody else's profile.
    cargo run -q -p siwx-oidc-auth -- --verify-did "$MXID" \
        --homeserver "$HOMESERVER" --server "$SERVER" > /dev/null \
        && echo "    verify OK (signature + issuer + mxid binding)"
    echo
done

echo "Search for any DID above in Element. Keys live in $KEYDIR (delete to start over)."
