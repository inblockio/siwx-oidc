// Matrix localpart / MXID derivation for the browser E2E suite.
//
// THIS IS A HAND-MAINTAINED MIRROR OF `src/mxid.rs`. Nothing links the two, so
// it drifts silently: when the server's derivation changes and this does not,
// every assertion keyed on an mxid (seeded devices, `detected_mxid`) goes red
// for a reason that has nothing to do with the product. That is not
// hypothetical — the opaque-localpart migration (2026-09-09) left this suite
// computing the LEGACY shape, and eight specs failed with "no SIWX_ device was
// provisioned" while provisioning was working perfectly, just under a localpart
// the tests were not looking at.
//
// Keep it in step with `mxid::localpart_for` / `mxid::legacy_localpart`, and
// with `mxid::canonicalize` in particular — the case rule is method-aware and
// is NOT cosmetic:
//
//   did:pkh:*            lowercased. The mixed case in an 0x… address is an
//                        EIP-55 checksum, not identity.
//   did:key:*/did:peer:* case PRESERVED. These are multibase base58btc, where
//                        case is part of the encoded key bytes; folding it maps
//                        two different public keys onto one account (siwx-oidc#17).
//
// Which shape a given DID actually gets is the GRANDFATHERING policy in
// `src/localpart.rs`, not something this file can decide: an identity that
// already has a Matrix account keeps its legacy localpart forever (Synapse has
// no rename API), and only a genuinely new identity gets `localpartFor`. Every
// spec here mints a fresh random wallet or passkey, so every identity here is
// new — which is why `localpartFor` is the right default for this suite and
// `legacyLocalpart` is exported only for a test that deliberately seeds a
// pre-migration account.

import { createHash } from 'node:crypto';

const BASE36_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
const OUTPUT_WIDTH = 16;
const DIGEST_BYTES_KEPT = 10; // 80 bits — see the "why 80 bits" note in src/mxid.rs

// `mxid::canonicalize`.
function canonicalize(did) {
  return did.startsWith('did:pkh:') ? did.toLowerCase() : did;
}

// `mxid::legacy_localpart` — the pre-2026-09 derivation. Permanent
// infrastructure, not dead code: grandfathering depends on it forever.
export function legacyLocalpart(did) {
  return did.replaceAll(':', '-').toLowerCase();
}

// `mxid::localpart_for` — exactly 16 lowercase base36 chars, one alphanumeric
// run, no separators (matrix.org's MSC4284 policy server refuses the long
// multi-word legacy shape; see src/mxid.rs).
export function localpartFor(did) {
  const digest = createHash('sha256').update(canonicalize(did), 'utf8').digest();
  let n = 0n;
  for (const byte of digest.subarray(0, DIGEST_BYTES_KEPT)) {
    n = (n << 8n) | BigInt(byte);
  }
  let out = '';
  while (n > 0n) {
    out = BASE36_ALPHABET[Number(n % 36n)] + out;
    n /= 36n;
  }
  return out.padStart(OUTPUT_WIDTH, BASE36_ALPHABET[0]);
}

export function didToMxid(did, serverName = 'matrix.test') {
  return `@${localpartFor(did)}:${serverName}`;
}
