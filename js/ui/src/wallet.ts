// The wallet step of the sign-in page, kept apart from App.svelte so a test can load it.
//
// Least privilege. Sign-in needs an account address and one message signature, nothing
// else, so this page asks an injected EIP-1193 wallet for exactly:
//
//   - the `eth_accounts` permission (`wallet_requestPermissions`, or `eth_requestAccounts`
//     for a wallet without it),
//   - `personal_sign` (App.svelte `performSignIn`),
//   - on a wallet that sits on another network, a switch to Ethereum mainnet
//     (`wallet_switchEthereumChain`, chain id 1).
//
// It never sends a transaction, never reads a balance, never signs typed data and never
// adds a network. There is no WalletConnect and no project id (AGENTS.md, wire
// compatibility). The wording of the wallet's own connect dialog ("see your accounts and
// balances, suggest transactions") belongs to the wallet for every site that asks for the
// `eth_accounts` permission; a page cannot narrow it.
//
// Ethereum mainnet is the one network. The CAIP-122 message names chain 1 and the DID is
// `did:pkh:eip155:1:<address>`, so the wallet is asked to be on chain 1 as well; otherwise
// it shows its own current network (an L2, a testnet) in its prompts.

import { createConfig, connect, switchChain, http, injected } from '@wagmi/core';
import { mainnet } from 'viem/chains';

/** The only network the page knows. */
export const SIGN_IN_CHAIN = mainnet;

export function createWalletConfig() {
	return createConfig({
		chains: [SIGN_IN_CHAIN],
		connectors: [injected()],
		transports: {
			[SIGN_IN_CHAIN.id]: http(),
		},
	});
}

export type WalletConfig = ReturnType<typeof createWalletConfig>;

/**
 * Connects the injected wallet and asks it to move to Ethereum mainnet when it is on
 * another network. The switch is a request, not a condition: a wallet that declines or
 * cannot switch still signs in, because `personal_sign` does not depend on the network
 * and the signed message names chain 1 either way.
 */
export async function connectWallet(config: WalletConfig) {
	const result = await connect(config, { connector: injected() });
	if (result.chainId !== SIGN_IN_CHAIN.id) {
		try {
			await switchChain(config, { chainId: SIGN_IN_CHAIN.id });
		} catch (e) {
			console.warn('The wallet stays on its current network:', e instanceof Error ? e.message : e);
		}
	}
	return result;
}
