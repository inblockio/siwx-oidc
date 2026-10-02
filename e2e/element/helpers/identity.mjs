/**
 * Identity assertions for a freshly minted account: what its Matrix ID looks
 * like, and how to prove which DID it belongs to.
 *
 * A spec must NOT compute the expected MXID from the DID. The localpart is
 * siwx-oidc's business (src/mxid.rs `localpart_for`, plus the grandfathering
 * policy in src/localpart.rs), and a hand-copied formula drifts silently from
 * it (a new account gets the opaque shape, a legacy account keeps the
 * `did-pkh-eip155-1-0x...` one, and which applies is decided server side). So a
 * spec asserts two independent things instead:
 *
 *  1. the SHAPE of the MXID: an opaque localpart on the lab server_name, and
 *  2. the BINDING: the DID this account was created for resolves to exactly that
 *     MXID, asked of the provider (`GET /resolve`, src/resolve.rs) and of the
 *     homeserver (the `io.inblock.did` profile field, src/did_assertion.rs).
 *
 * The binding is fixed at account creation and never changes, so there is no
 * "changed DID" case to test.
 */
import { expect } from '@playwright/test';

/** The lab homeserver's server_name (docker-compose.local.yml, MATRIX_HOST). */
export const SERVER_NAME = 'localhost';

/**
 * The localpart siwx-oidc mints for a NEW identity: exactly 16 characters from
 * the base36 alphabet `0-9a-z`, one alphanumeric run, no separators.
 *
 *   alphabet  src/mxid.rs:125  BASE36_ALPHABET = b"0123456789abcdefghijklmnopqrstuvwxyz"
 *   width     src/mxid.rs:131  OUTPUT_WIDTH = 16 (padded with '0', never shorter)
 *   minted by src/mxid.rs:147  localpart_for(did)
 *
 * Holds for every fresh wallet or passkey a spec creates. A grandfathered
 * account (one that already existed before 2026-09-09) keeps its legacy
 * `did-pkh-...` localpart and would NOT match: do not use this on one.
 */
export const OPAQUE_LOCALPART_RE = /^[0-9a-z]{16}$/;

/** `@<16 base36>:<serverName>`, and nothing else. */
export function expectOpaqueMxid(userId, serverName = SERVER_NAME) {
  expect(userId, 'whoami user_id').toMatch(/^@[^:]+:.+$/);
  const [localpart, ...rest] = userId.slice(1).split(':');
  expect(
    localpart,
    `localpart of ${userId} must be the opaque 16-char base36 shape (src/mxid.rs:125,131), ` +
      'not a DID-derived one',
  ).toMatch(OPAQUE_LOCALPART_RE);
  expect(rest.join(':'), `server name of ${userId}`).toBe(serverName);
}

/**
 * Two DID spellings are the same identity when siwx-oidc says so: did:pkh is
 * case-folded (the case of its 0x... address is an EIP-55 checksum), every other
 * method is compared byte for byte (src/mxid.rs `canonicalize`).
 */
function sameDid(a, b) {
  const canon = (d) => (d.startsWith('did:pkh:') ? d.toLowerCase() : d);
  return canon(a) === canon(b);
}

async function getJson(url) {
  const res = await fetch(url);
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: res.status, body, text };
}

/**
 * Prove `did` is the DID of account `userId`, from both ends:
 *
 *  - siwx `GET /resolve?did=` answers with exactly `userId` (exists, attested),
 *    and `GET /resolve?mxid=` answers with the same DID;
 *  - the homeserver's anonymous profile read of `io.inblock.did` carries the DID.
 *
 * Neither the MXID nor the DID is computed here; both are only compared.
 */
export async function expectDidBinding({ siwxUrl, matrixUrl, userId, did }) {
  const SIWX = siwxUrl.replace(/\/$/, '');
  const MATRIX = matrixUrl.replace(/\/$/, '');

  // DID -> MXID.
  const fwd = await getJson(`${SIWX}/resolve?did=${encodeURIComponent(did)}`);
  expect(fwd.status, `GET /resolve?did= -> ${fwd.text}`).toBe(200);
  expect(fwd.body.mxid, `/resolve maps ${did} to a different account`).toBe(userId);
  expect(fwd.body.exists, '/resolve: account exists').toBe(true);
  expect(fwd.body.attested, '/resolve: io.inblock.did binds to this account').toBe(true);
  expect(sameDid(fwd.body.did, did), `/resolve echoed ${fwd.body.did}`).toBe(true);

  // MXID -> DID.
  const back = await getJson(`${SIWX}/resolve?mxid=${encodeURIComponent(userId)}`);
  expect(back.status, `GET /resolve?mxid= -> ${back.text}`).toBe(200);
  expect(back.body.mxid).toBe(userId);
  expect(
    back.body.did && sameDid(back.body.did, did),
    `${userId} publishes ${back.body.did}, expected ${did}`,
  ).toBe(true);

  // The homeserver's own copy (MSC4133 extended profile, provider-written).
  const field = await getJson(
    `${MATRIX}/_matrix/client/v3/profile/${encodeURIComponent(userId)}/io.inblock.did`,
  );
  expect(field.status, `profile io.inblock.did of ${userId} -> ${field.text}`).toBe(200);
  const published = field.body?.['io.inblock.did'];
  expect(
    published?.did && sameDid(published.did, did),
    `profile field of ${userId} carries ${published?.did}, expected ${did}`,
  ).toBe(true);
}
