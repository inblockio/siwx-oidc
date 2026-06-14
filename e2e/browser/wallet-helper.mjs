// Reusable mock-wallet primitives for the siwx-oidc browser E2E suite.
//
// Extracted verbatim (behaviour-preserving) from account.spec.mjs so both the
// account-management spec and the device-lifecycle spec drive the SAME mock
// EIP-1193 provider with REAL ethers EIP-191 signatures. The point of the mock
// is that it exercises the identical server-side CAIP-122 verification path as a
// real MetaMask would (only the provider plumbing is mocked, not the crypto).

import { Wallet } from 'ethers';

// A fixed throwaway test key — never used anywhere real. Kept here so callers
// that want the *default* shared identity can import it; tests that need a fresh
// per-test identity (the suite default) call `freshWallet()` instead.
export const DEFAULT_PRIV =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

// Derive the Matrix MXID for a did:pkh wallet DID, mirroring did_to_localpart
// (replace ':' with '-', lowercase) and the e2e server_name (matrix.test).
export function walletMxid(address, serverName = 'matrix.test') {
  const did = `did:pkh:eip155:1:${address}`;
  return `@${did.replaceAll(':', '-').toLowerCase()}:${serverName}`;
}

// Build a wallet bundle: { wallet, address, did, mxid }. Pass a private key to
// pin an identity, or omit it for a random throwaway key (the suite default so
// each test runs under a distinct identity).
export function makeWallet(priv = Wallet.createRandom().privateKey, serverName = 'matrix.test') {
  const wallet = new Wallet(priv);
  const address = wallet.address; // EIP-55 checksummed
  return {
    wallet,
    address,
    did: `did:pkh:eip155:1:${address}`,
    mxid: walletMxid(address, serverName),
  };
}

// Inject a mock EIP-1193 wallet that signs with the supplied ethers wallet.
// Adds `window.__signCount()` (count of personal_sign calls) so a test can prove
// "exactly one signature". Lifted verbatim from account.spec.mjs::injectWallet,
// generalized to take EITHER an ethers Wallet or a makeWallet() bundle
// ({ wallet, address, ... }).
export async function injectMockWallet(page, walletOrBundle) {
  // Normalize: a bundle carries the ethers Wallet under `.wallet`.
  const wallet = walletOrBundle && walletOrBundle.wallet
    ? walletOrBundle.wallet
    : walletOrBundle;
  const address = wallet.address;
  await page.exposeFunction('__ethSign', (msg) => wallet.signMessage(msg));
  await page.addInitScript((addr) => {
    let n = 0;
    window.__signCount = () => n;
    window.ethereum = {
      isMetaMask: true,
      isConnected: () => true,
      request: async ({ method, params }) => {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'personal_sign') { n++; return await window.__ethSign(params[0]); }
        throw Object.assign(new Error('unsupported ' + method), { code: 4200 });
      },
      on() {}, removeListener() {},
    };
  }, address);
}

// Read the personal_sign counter set up by injectMockWallet.
export async function countSignatures(page) {
  return page.evaluate(() => (window.__signCount ? window.__signCount() : 0));
}
