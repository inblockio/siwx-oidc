<script lang="ts">
	import { onMount } from 'svelte';
	import { createConfig, connect, disconnect, getAccount, signMessage, reconnect, http, watchAccount } from '@wagmi/core';
	import { injected } from '@wagmi/connectors';
	import { mainnet, arbitrum, polygon } from 'viem/chains';
	import { createSiweMessage } from 'viem/siwe';
	import Cookies from 'js-cookie';

	export let domain: string;
	export let nonce: string;
	export let redirect: string;
	export let state: string;
	export let oidc_nonce: string;
	export let client_id: string;

	let status = 'Not Logged In';
	let error: string | null = null;
	let connecting = false;
	let client_metadata: any = {};

	const config = createConfig({
		chains: [mainnet, arbitrum, polygon],
		connectors: [injected()],
		transports: {
			[mainnet.id]: http(),
			[arbitrum.id]: http(),
			[polygon.id]: http(),
		},
	});

	let oidc_nonce_param = '';
	if (oidc_nonce != null && oidc_nonce != '') {
		oidc_nonce_param = `&oidc_nonce=${oidc_nonce}`;
	}

	onMount(async () => {
		try {
			const resp = await fetch(`${window.location.origin}/client/${client_id}`);
			client_metadata = await resp.json();
		} catch (e) {
			console.error(e);
		}

		// Auto-reconnect if previously connected
		await reconnect(config);
	});

	async function handleConnect() {
		if (connecting) return;
		connecting = true;
		error = null;
		status = 'Connecting...';

		try {
			const result = await connect(config, { connector: injected() });

			if (result.accounts.length > 0) {
				await performSignIn(result.accounts[0], result.chainId);
			}
		} catch (e: any) {
			if (e.name === 'ConnectorNotFoundError' || e.message?.includes('No injected')) {
				error = 'No wallet detected. Please install MetaMask or another Ethereum wallet extension.';
			} else if (e.name === 'UserRejectedRequestError') {
				error = 'Connection rejected.';
			} else {
				error = e.shortMessage || e.message || 'Failed to connect wallet';
			}
			status = 'Not Logged In';
			console.error(e);
		} finally {
			connecting = false;
		}
	}

	async function performSignIn(address: string, chainId: number) {
		status = 'Signing message...';

		const expirationTime = new Date(
			new Date().getTime() + 2 * 24 * 60 * 60 * 1000, // 48h
		);

		const preparedMessage = createSiweMessage({
			domain: window.location.host,
			address: address as `0x${string}`,
			chainId,
			expirationTime,
			uri: window.location.origin,
			version: '1',
			statement: `You are signing-in to ${window.location.host}.`,
			nonce,
			resources: [redirect],
		});

		const signature = await signMessage(config, {
			message: preparedMessage,
		});

		const did = `did:pkh:eip155:${chainId}:${address}`;
		const session = {
			did,
			message: preparedMessage,
			signature,
		};
		Cookies.set('siwx', JSON.stringify(session), {
			expires: expirationTime,
			sameSite: 'Strict',
			secure: window.location.protocol === 'https:',
		});

		status = 'Redirecting...';
		window.location.replace(
			`/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(state)}&client_id=${encodeURI(
				client_id,
			)}${encodeURI(oidc_nonce_param)}`,
		);
	}
</script>

<div
	class="bg-no-repeat bg-cover bg-center bg-swe-landing font-satoshi bg-gray flex-grow w-full h-screen items-center flex justify-center flex-wrap flex-col"
	style="background-image: url('img/swe-landing.svg');"
>
	<div class="w-96 text-center bg-white rounded-20 text-grey flex h-100 flex-col p-12 shadow-lg shadow-white">
		{#if client_metadata.logo_uri}
			<div class="flex justify-evenly items-stretch">
				<img height="72" width="72" class="self-center mb-8" src="img/modal_icon.png" alt="Ethereum logo" />
				<img height="72" width="72" class="self-center mb-8" src={client_metadata.logo_uri} alt="Client logo" />
			</div>
		{:else}
			<img height="72" width="72" class="self-center mb-8" src="img/modal_icon.png" alt="Ethereum logo" />
		{/if}
		<h5>Welcome</h5>
		<span class="text-xs">
			Sign-In with Ethereum to continue to {client_metadata.client_name ? client_metadata.client_name : domain}
		</span>

		<button
			class="h-12 border hover:scale-105 justify-evenly shadow-xl border-white mt-4 duration-100 ease-in-out transition-all transform flex items-center"
			disabled={connecting}
			on:click={handleConnect}
		>
			<svg
				xmlns="http://www.w3.org/2000/svg"
				clip-rule="evenodd"
				fill-rule="evenodd"
				stroke-linejoin="round"
				stroke-miterlimit="1.41421"
				viewBox="170 30 220 350"
				class="w-6 h-8"
			>
				<g fill-rule="nonzero" transform="matrix(.781253 0 0 .781253 180 37.1453)">
					<path d="m127.961 0-2.795 9.5v275.668l2.795 2.79 127.962-75.638z" fill="#343434" /><path
						d="m127.962 0-127.962 212.32 127.962 75.639v-133.801z"
						fill="#8c8c8c"
					/>
					<path d="m127.961 312.187-1.575 1.92v98.199l1.575 4.601 128.038-180.32z" fill="#3c3c3b" /><path
						d="m127.962 416.905v-104.72l-127.962-75.6z"
						fill="#8c8c8c"
					/>
					<path d="m127.961 287.958 127.96-75.637-127.96-58.162z" fill="#141414" /><path
						d="m.001 212.321 127.96 75.637v-133.799z"
						fill="#393939"
					/>
				</g>
			</svg>
			<p class="font-bold">
				{#if connecting}Connecting...{:else}Sign-In with Ethereum{/if}
			</p>
		</button>

		{#if error}
			<span class="text-xs text-red-500 mt-2">{error}</span>
		{/if}

		<div class="self-center mt-auto text-center font-semibold text-xs">
			By using this service you agree to the <a href="/legal/terms-of-use.pdf">Terms of Use</a> and
			<a href="/legal/privacy-policy.pdf">Privacy Policy</a>.
		</div>

		{#if client_metadata.client_uri}
			<span class="text-xs mt-4">Request linked to {client_metadata.client_uri}</span>
		{/if}
	</div>
</div>

<style global lang="postcss">
	@tailwind base;
	@tailwind components;
	@tailwind utilities;

	.tooltip {
		@apply invisible absolute;
	}

	.has-tooltip:hover .tooltip {
		@apply visible z-50;
	}
	html,
	body {
		position: relative;
		width: 100vw;
		height: 100vh;
		margin: 0px;
		padding: 0px;
		font-size: 18px;
		background: #ecf2fe;
		display: flex;
		flex-direction: column;
		overflow-x: hidden;
		@apply font-satoshi;
	}

	h1,
	h2,
	h3,
	h4,
	h5,
	h6 {
		@apply font-extrabold;
		@apply font-satoshi;
	}

	h1 {
		font-size: 76px;
		line-height: 129px;
		letter-spacing: -4.5%;
	}

	h2 {
		font-size: 66px;
		line-height: 101px;
		letter-spacing: -3%;
	}

	h3 {
		font-size: 52px;
		line-height: 80px;
		letter-spacing: -1.5%;
	}

	h4 {
		font-size: 48px;
		line-height: 63px;
		letter-spacing: -1%;
	}

	h5 {
		font-size: 32px;
		line-height: 49px;
		letter-spacing: -0.5%;
	}

	h6 {
		font-size: 24px;
		line-height: 37px;
		letter-spacing: -0.5%;
	}

	body {
		color: #222222;
	}

	a {
		text-decoration: none;
		color: #04d2ca;
	}

	td,
	th {
		font-family: 'Satoshi';
		font-weight: 400;
	}

	pre {
		white-space: pre-wrap; /* Since CSS 2.1 */
		white-space: -moz-pre-wrap; /* Mozilla, since 1999 */
		white-space: -pre-wrap; /* Opera 4-6 */
		white-space: -o-pre-wrap; /* Opera 7 */
		word-wrap: break-word; /* Internet Explorer 5.5+ */
	}

	/**
	Custom scrollbar settings
	*/
	::-webkit-scrollbar-track {
		border-radius: 8px;
		background-color: #ccc;
	}

	::-webkit-scrollbar-thumb {
		border-radius: 8px;
		background-color: #888;
	}
	::-webkit-scrollbar {
		height: 6px;
		border-radius: 8px;
		width: 6px;
		background-color: #ccc;
	}

	.grecaptcha-badge {
		visibility: hidden;
	}
</style>
