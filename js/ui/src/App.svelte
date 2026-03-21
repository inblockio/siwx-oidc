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
	export let code_challenge: string;
	export let code_challenge_method: string;

	let status = 'Not Logged In';
	let error: string | null = null;
	let connecting = false;
	let passkeyLoading = false;
	let linkingPasskey = false;
	let showLinkOption = false;
	let linkSuccess = false;
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

	let pkce_params = '';
	if (code_challenge != null && code_challenge != '') {
		pkce_params = `&code_challenge=${code_challenge}`;
		if (code_challenge_method != null && code_challenge_method != '') {
			pkce_params += `&code_challenge_method=${code_challenge_method}`;
		} else {
			pkce_params += '&code_challenge_method=S256';
		}
	}

	function buildSignInUrl(): string {
		return `/sign_in?redirect_uri=${encodeURI(redirect)}&state=${encodeURI(state)}&client_id=${encodeURI(client_id)}${encodeURI(oidc_nonce_param)}${encodeURI(pkce_params)}`;
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

		// Show option to link a passkey before redirecting.
		showLinkOption = true;
		status = 'Signed — link a passkey or continue';
	}

	function proceedToSignIn() {
		status = 'Redirecting...';
		window.location.replace(buildSignInUrl());
	}

	async function handleLinkPasskey() {
		if (linkingPasskey) return;
		linkingPasskey = true;
		error = null;
		status = 'Linking passkey to wallet...';

		try {
			// Step 1: Start link ceremony (server verifies siwx cookie for DID ownership).
			const startResp = await fetch('/link/webauthn/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{}',
			});
			if (!startResp.ok) {
				throw new Error(await startResp.text());
			}
			const options = await startResp.json();

			// Step 2: Browser WebAuthn API — user creates passkey.
			options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
			options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
			if (options.publicKey.excludeCredentials) {
				for (const c of options.publicKey.excludeCredentials) {
					c.id = base64urlToBuffer(c.id);
				}
			}

			const credential = await navigator.credentials.create({ publicKey: options.publicKey });
			if (!credential) throw new Error('No credential created');

			// Step 3: Send attestation to server.
			const attestationResponse = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse;
			const finishResp = await fetch('/link/webauthn/finish', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					id: credential.id,
					rawId: bufferToBase64url(new Uint8Array((credential as PublicKeyCredential).rawId)),
					type: credential.type,
					response: {
						attestationObject: bufferToBase64url(new Uint8Array(attestationResponse.attestationObject)),
						clientDataJSON: bufferToBase64url(new Uint8Array(attestationResponse.clientDataJSON)),
					},
				}),
			});
			if (!finishResp.ok) {
				throw new Error(await finishResp.text());
			}

			const result = await finishResp.json();
			linkSuccess = true;
			status = `Passkey linked to ${result.primary_did.substring(0, 30)}…`;
		} catch (e: any) {
			if (e.name === 'NotAllowedError') {
				error = 'Passkey linking was cancelled.';
			} else {
				error = e.message || 'Passkey linking failed';
			}
			status = 'Link failed — you can still continue';
		} finally {
			linkingPasskey = false;
		}
	}

	async function handlePasskeySignIn() {
		if (passkeyLoading) return;
		passkeyLoading = true;
		error = null;
		status = 'Authenticating with passkey...';

		try {
			// Step 1: Start authentication ceremony (server creates challenge)
			const startResp = await fetch('/webauthn/authenticate/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{}',
			});
			if (!startResp.ok) {
				throw new Error(await startResp.text());
			}
			const options = await startResp.json();

			// Step 2: Browser WebAuthn API — user selects passkey
			// Convert base64url challenge to ArrayBuffer
			options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
			if (options.publicKey.allowCredentials) {
				for (const c of options.publicKey.allowCredentials) {
					c.id = base64urlToBuffer(c.id);
				}
			}

			const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
			if (!assertion) throw new Error('No credential returned');

			// Step 3: Send assertion to server for verification
			const authResponse = (assertion as PublicKeyCredential).response as AuthenticatorAssertionResponse;
			const finishResp = await fetch('/webauthn/authenticate/finish', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					id: assertion.id,
					rawId: bufferToBase64url(new Uint8Array((assertion as PublicKeyCredential).rawId)),
					type: assertion.type,
					response: {
						authenticatorData: bufferToBase64url(new Uint8Array(authResponse.authenticatorData)),
						clientDataJSON: bufferToBase64url(new Uint8Array(authResponse.clientDataJSON)),
						signature: bufferToBase64url(new Uint8Array(authResponse.signature)),
						userHandle: authResponse.userHandle
							? bufferToBase64url(new Uint8Array(authResponse.userHandle))
							: null,
					},
				}),
			});
			if (!finishResp.ok) {
				throw new Error(await finishResp.text());
			}

			// Step 4: Redirect to /sign_in — session.verified_did is now set
			status = 'Redirecting...';
			window.location.replace(buildSignInUrl());
		} catch (e: any) {
			if (e.name === 'NotAllowedError') {
				error = 'Passkey authentication was cancelled.';
			} else {
				error = e.message || 'Passkey authentication failed';
			}
			status = 'Not Logged In';
			console.error(e);
		} finally {
			passkeyLoading = false;
		}
	}

	async function handlePasskeyRegister() {
		if (passkeyLoading) return;
		passkeyLoading = true;
		error = null;
		status = 'Registering passkey...';

		try {
			const startResp = await fetch('/webauthn/register/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ display_name: null }),
			});
			if (!startResp.ok) {
				throw new Error(await startResp.text());
			}
			const options = await startResp.json();

			// Convert base64url fields to ArrayBuffer
			options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
			options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
			if (options.publicKey.excludeCredentials) {
				for (const c of options.publicKey.excludeCredentials) {
					c.id = base64urlToBuffer(c.id);
				}
			}

			const credential = await navigator.credentials.create({ publicKey: options.publicKey });
			if (!credential) throw new Error('No credential created');

			const attestationResponse = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse;
			const finishResp = await fetch('/webauthn/register/finish', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					id: credential.id,
					rawId: bufferToBase64url(new Uint8Array((credential as PublicKeyCredential).rawId)),
					type: credential.type,
					response: {
						attestationObject: bufferToBase64url(new Uint8Array(attestationResponse.attestationObject)),
						clientDataJSON: bufferToBase64url(new Uint8Array(attestationResponse.clientDataJSON)),
					},
				}),
			});
			if (!finishResp.ok) {
				throw new Error(await finishResp.text());
			}

			const result = await finishResp.json();
			status = `Passkey registered! DID: ${result.did.substring(0, 24)}…`;
			error = null;

			// After registration, authenticate immediately
			await handlePasskeySignIn();
		} catch (e: any) {
			if (e.name === 'NotAllowedError') {
				error = 'Passkey registration was cancelled.';
			} else {
				error = e.message || 'Passkey registration failed';
			}
			status = 'Not Logged In';
			console.error(e);
		} finally {
			passkeyLoading = false;
		}
	}

	// -- Base64url <-> ArrayBuffer helpers --

	function base64urlToBuffer(b64: string): ArrayBuffer {
		const padding = '='.repeat((4 - (b64.length % 4)) % 4);
		const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
		const raw = atob(base64);
		const arr = new Uint8Array(raw.length);
		for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
		return arr.buffer;
	}

	function bufferToBase64url(buf: Uint8Array): string {
		let binary = '';
		for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
		return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}
</script>

<div
	class="font-satoshi flex-grow w-full h-screen items-center flex justify-center flex-wrap flex-col"
	style="background: radial-gradient(ellipse at 60% 40%, #2a1004 0%, #0d0d0d 65%);"
>
	<div class="w-96 text-center bg-white rounded-20 text-grey flex h-100 flex-col p-12 shadow-lg shadow-white">
		{#if client_metadata.logo_uri}
			<div class="flex justify-evenly items-stretch">
				<img height="72" width="72" class="self-center mb-8" src="img/inblockio-logo.png" alt="inblockio logo" />
				<img height="72" width="72" class="self-center mb-8" src={client_metadata.logo_uri} alt="Client logo" />
			</div>
		{:else}
			<img height="72" width="72" class="self-center mb-8" src="img/inblockio-logo.png" alt="inblockio logo" />
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

		<div class="flex items-center my-3">
			<div class="flex-grow border-t border-gray-300"></div>
			<span class="mx-3 text-xs text-gray-400">or</span>
			<div class="flex-grow border-t border-gray-300"></div>
		</div>

		<button
			class="h-12 border hover:scale-105 justify-evenly shadow-xl border-white duration-100 ease-in-out transition-all transform flex items-center"
			disabled={passkeyLoading}
			on:click={handlePasskeySignIn}
		>
			<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5">
				<path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd" />
			</svg>
			<p class="font-bold">
				{#if passkeyLoading}Authenticating...{:else}Sign-In with Passkey{/if}
			</p>
		</button>

		<button
			class="text-xs text-gray-400 hover:text-gray-600 mt-1 underline cursor-pointer"
			disabled={passkeyLoading}
			on:click={handlePasskeyRegister}
		>
			Register a new passkey
		</button>

		{#if showLinkOption}
			<div class="mt-3 p-3 border border-gray-200 rounded text-xs">
				{#if linkSuccess}
					<p class="text-green-600 font-semibold mb-2">Passkey linked successfully!</p>
					<button
						class="h-10 w-full border hover:scale-105 shadow-xl border-white duration-100 ease-in-out transition-all transform flex items-center justify-center font-bold"
						on:click={proceedToSignIn}
					>
						Continue
					</button>
				{:else}
					<p class="mb-2">Link a passkey so you can sign in without a wallet next time?</p>
					<div class="flex gap-2">
						<button
							class="flex-1 h-10 border hover:scale-105 shadow-xl border-white duration-100 ease-in-out transition-all transform flex items-center justify-center font-bold"
							disabled={linkingPasskey}
							on:click={handleLinkPasskey}
						>
							{#if linkingPasskey}Linking...{:else}Yes, link passkey{/if}
						</button>
						<button
							class="flex-1 h-10 border hover:scale-105 shadow-xl border-white duration-100 ease-in-out transition-all transform flex items-center justify-center font-bold text-gray-400"
							disabled={linkingPasskey}
							on:click={proceedToSignIn}
						>
							Skip
						</button>
					</div>
				{/if}
			</div>
		{/if}

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
		background: #0d0d0d;
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
