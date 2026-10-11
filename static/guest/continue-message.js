// The message the /guest/continue page signs. Pure (no imports, no browser globals), so a
// Node test can pin it against the Rust builder `build_continue_message`.

export const CONTINUE_STATEMENT = 'Continue as a guest';

/** Twelve lines, as the redeem message but with this statement, the login session's nonce
 *  and the exact redirect URI as the one resource. Times are `toISOString()` text. */
export function buildContinueMessage({ domain, alg, did, uri, nonce, issuedAt, expiration, redirectUri }) {
  return (
    `${domain} wants you to sign in with your ${alg} account:\n` +
    `${did}\n` +
    '\n' +
    `${CONTINUE_STATEMENT}\n` +
    '\n' +
    `URI: ${uri}\n` +
    'Version: 1\n' +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt.toISOString()}\n` +
    `Expiration Time: ${expiration.toISOString()}\n` +
    'Resources:\n' +
    `- ${redirectUri}`
  );
}
