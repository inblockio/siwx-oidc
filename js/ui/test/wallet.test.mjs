// Pins what the sign-in page may ask an injected wallet for (js/ui/src/wallet.ts).
//
// The real @wagmi/core injected connector runs against a recording EIP-1193 provider, so
// the test sees every request the page makes, in order, and fails when one outside the
// allowed set appears: a transaction, a balance read, typed data, a network the page does
// not know. Run: npm test (node --test, no browser).
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';
import ts from 'typescript';

const here = dirname(fileURLToPath(import.meta.url));

// wallet.ts is TypeScript; strip its types into an untracked file next to the tests, so
// node resolves @wagmi/core and viem from js/ui/node_modules exactly as webpack does.
const out = join(here, '.build', 'wallet.mjs');
mkdirSync(dirname(out), { recursive: true });
const transpiled = ts.transpileModule(readFileSync(join(here, '..', 'src', 'wallet.ts'), 'utf8'), {
	compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, verbatimModuleSyntax: true },
});
writeFileSync(out, transpiled.outputText);

const { createWalletConfig, connectWallet, SIGN_IN_CHAIN } = await import(pathToFileURL(out).href);
const { signMessage } = await import('@wagmi/core');

const ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

// Everything the page may send a wallet. wallet_requestPermissions asks for the
// eth_accounts permission only; eth_requestAccounts is its fallback for wallets without
// it; eth_accounts and eth_chainId are reads of what the wallet already granted.
const ALLOWED = new Set([
	'wallet_requestPermissions',
	'eth_requestAccounts',
	'eth_accounts',
	'eth_chainId',
	'wallet_switchEthereumChain',
	'personal_sign',
]);

// A wallet on `chain`; `refuse` maps a method to the error code it answers with.
function wallet(chain, refuse = {}) {
	const log = [];
	let current = chain;
	const listeners = {};
	const provider = {
		log,
		isMetaMask: true,
		on(event, fn) { (listeners[event] ??= []).push(fn); },
		removeListener(event, fn) { listeners[event] = (listeners[event] ?? []).filter((f) => f !== fn); },
		async request({ method, params }) {
			log.push({ method, params });
			if (refuse[method]) throw Object.assign(new Error(`refused ${method}`), { code: refuse[method] });
			switch (method) {
				case 'wallet_requestPermissions':
					return [{ parentCapability: 'eth_accounts', caveats: [{ type: 'restrictReturnedAccounts', value: [ADDRESS] }] }];
				case 'eth_requestAccounts':
				case 'eth_accounts':
					return [ADDRESS];
				case 'eth_chainId':
					return '0x' + current.toString(16);
				case 'wallet_switchEthereumChain':
					current = Number(params[0].chainId);
					(listeners.chainChanged ?? []).forEach((fn) => fn('0x' + current.toString(16)));
					return null;
				case 'personal_sign':
					return '0x' + '11'.repeat(65);
				default:
					throw Object.assign(new Error(`unsupported ${method}`), { code: 4200 });
			}
		},
	};
	return provider;
}

async function signIn(provider) {
	globalThis.window = { ethereum: provider, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } };
	const config = createWalletConfig();
	const result = await connectWallet(config);
	const signature = await signMessage(config, { message: 'sign-in message' });
	return { config, result, signature };
}

const methods = (p) => p.log.map((r) => r.method);

test('Ethereum mainnet is the one network the page knows', () => {
	globalThis.window = { ethereum: wallet(1), addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } };
	const config = createWalletConfig();
	assert.deepEqual(config.chains.map((c) => c.id), [1]);
	assert.equal(SIGN_IN_CHAIN.id, 1);
	assert.equal(SIGN_IN_CHAIN.name, 'Ethereum');
	assert.deepEqual(Object.keys(config._internal.transports).map(Number), [1]);
});

test('a wallet on mainnet is asked for the account permission and one signature, nothing else', async () => {
	const p = wallet(1);
	const { result } = await signIn(p);
	assert.equal(result.accounts[0], ADDRESS);
	assert.equal(result.chainId, 1);
	assert.deepEqual([...new Set(methods(p))].sort(), ['eth_accounts', 'eth_chainId', 'personal_sign', 'wallet_requestPermissions']);
	assert.equal(methods(p).filter((m) => m === 'personal_sign').length, 1, 'exactly one signature');
	assert.equal(methods(p).includes('wallet_switchEthereumChain'), false, 'no switch when already on mainnet');
	const sign = p.log.find((r) => r.method === 'personal_sign');
	assert.equal(sign.params[1].toLowerCase(), ADDRESS.toLowerCase());
	const permission = p.log.find((r) => r.method === 'wallet_requestPermissions');
	assert.deepEqual(permission.params, [{ eth_accounts: {} }]);
});

test('a wallet on Arbitrum is asked to switch to Ethereum mainnet, and to nothing else about networks', async () => {
	const p = wallet(42161);
	const { result } = await signIn(p);
	assert.equal(result.chainId, 42161, 'connect reports the network the wallet was on');
	const switches = p.log.filter((r) => r.method === 'wallet_switchEthereumChain');
	assert.deepEqual(switches.map((r) => r.params), [[{ chainId: '0x1' }]]);
	assert.equal(methods(p).includes('wallet_addEthereumChain'), false);
	assert.equal(methods(p).at(-1), 'personal_sign');
});

test('a wallet that refuses the network switch still signs in', async () => {
	const p = wallet(42161, { wallet_switchEthereumChain: 4001 });
	const { signature } = await signIn(p);
	assert.match(signature, /^0x[0-9a-f]+$/);
	assert.equal(methods(p).filter((m) => m === 'wallet_switchEthereumChain').length, 1);
	assert.equal(methods(p).at(-1), 'personal_sign');
});

test('a wallet without wallet_requestPermissions falls back to eth_requestAccounts', async () => {
	const p = wallet(1, { wallet_requestPermissions: 4200 });
	const { result } = await signIn(p);
	assert.equal(result.accounts[0], ADDRESS);
	assert.ok(methods(p).includes('eth_requestAccounts'));
});

test('no flow sends a transaction, reads a balance, signs typed data or adds a network', async () => {
	const seen = new Set();
	for (const [chain, refuse] of [[1, {}], [42161, {}], [42161, { wallet_switchEthereumChain: 4001 }], [1, { wallet_requestPermissions: 4200 }]]) {
		const p = wallet(chain, refuse);
		await signIn(p);
		methods(p).forEach((m) => seen.add(m));
	}
	const outside = [...seen].filter((m) => !ALLOWED.has(m));
	assert.deepEqual(outside, [], `requests outside the allowed set: ${outside.join(', ')}`);
	for (const m of ['eth_sendTransaction', 'eth_signTransaction', 'eth_sendRawTransaction', 'eth_getBalance',
		'eth_signTypedData_v4', 'wallet_addEthereumChain', 'wallet_watchAsset', 'wallet_sendCalls']) {
		assert.equal(seen.has(m), false, m);
	}
});
