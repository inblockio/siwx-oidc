<script lang="ts">
	import { onMount } from 'svelte';
	import { createConfig, connect, disconnect, getAccount, signMessage, reconnect, http, watchAccount } from '@wagmi/core';
	import { injected } from '@wagmi/connectors';
	import { mainnet } from 'viem/chains';
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
	let mounted = false;

	// --- Passkey scoping + new-user gate (Task 5) ---
	// When /webauthn/authenticate/start is scoped by a valid siwx_user cookie the
	// server returns `detected_mxid`. Unscoped (no/forged cookie or the `all:true`
	// escape) it is null and the UI behaves exactly as before. Method availability
	// is resolved live (the passkey ceremony) / locally (is a wallet provider
	// injected?), never predicted from a server-reported hint.
	let detectedMxid: string | null = null;
	// Set when authenticate/finish reports `new_user: true`: signing in would CREATE
	// a brand-new account, so we gate instead of auto-redirecting. Holds the mxid to
	// show. null = no gate.
	let newUserGate: { mxid: string } | null = null;

	const config = createConfig({
		chains: [mainnet],
		connectors: [injected()],
		transports: {
			[mainnet.id]: http(),
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
		// MSC4191/MSC4312 account-management deep links can land on the bare issuer
		// root (e.g. a homeserver whose account_management_url points here instead of
		// /account). Forward them to the account page, preserving the query, rather
		// than dead-ending on the sign-in SPA (which then fetched /client/null).
		const params = new URLSearchParams(window.location.search);
		if (params.has('action')) {
			window.location.replace(`/account${window.location.search}`);
			return;
		}

		// Only fetch client metadata when a real client_id is present. A bare-root
		// visit carries no client_id; fetching /client/null (or /client/undefined)
		// 404s and dead-ends the page.
		if (client_id != null && client_id !== '' && client_id !== 'null' && client_id !== 'undefined') {
			try {
				const resp = await fetch(`${window.location.origin}/client/${client_id}`);
				client_metadata = await resp.json();
			} catch (e) {
				console.error(e);
			}
		}

		await reconnect(config);
		mounted = true;
	});

	async function handleConnect() {
		if (connecting) return;
		connecting = true;
		error = null;
		status = 'Connecting...';

		try {
			const result = await connect(config, { connector: injected() });

			if (result.accounts.length > 0) {
				await performSignIn(result.accounts[0]);
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

	async function performSignIn(address: string) {
		status = 'Signing message...';

		const expirationTime = new Date(
			new Date().getTime() + 2 * 24 * 60 * 60 * 1000, // 48h
		);

		const preparedMessage = createSiweMessage({
			domain: window.location.host,
			address: address as `0x${string}`,
			chainId: 1,
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

		const did = `did:pkh:eip155:1:${address}`;
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
			const startResp = await fetch('/link/webauthn/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{}',
			});
			if (!startResp.ok) {
				throw new Error(await startResp.text());
			}
			const options = await startResp.json();

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
			status = `Passkey linked to ${result.primary_did.substring(0, 30)}...`;
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

	// `forceAll` drives the "use a different passkey" escape hatch: it re-runs
	// authenticate/start with {"all": true}, forcing usernameless (all keys) even
	// when a valid siwx_user cookie would otherwise scope the picker to one account.
	async function handlePasskeySignIn(forceAll = false) {
		if (passkeyLoading) return;
		passkeyLoading = true;
		error = null;
		// Re-running start clears any prior gate so we never show stale gate copy.
		newUserGate = null;
		status = 'Authenticating with passkey...';

		try {
			const startResp = await fetch('/webauthn/authenticate/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: forceAll ? JSON.stringify({ all: true }) : '{}',
			});
			if (!startResp.ok) {
				throw new Error(await startResp.text());
			}
			const options = await startResp.json();

			// Detected-account affordance: present ONLY when the server scoped this
			// request (valid cookie, not the escape hatch). When unscoped this is
			// null/absent and the UI shows no account hint.
			detectedMxid = forceAll ? null : (options.detected_mxid ?? null);

			options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
			// Discoverable login: the server returns an empty `allowCredentials`, so the
			// authenticator offers the user's own resident passkeys (not a server-wide
			// picker). An empty/absent list is a no-op here — never treat it as an error.
			if (options.publicKey.allowCredentials) {
				for (const c of options.publicKey.allowCredentials) {
					c.id = base64urlToBuffer(c.id);
				}
			}

			const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
			if (!assertion) throw new Error('No credential returned');

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
				const errBody = await finishResp.clone().json().catch(() => null);
				if (errBody && errBody.error === 'unknown_credential') {
					// Progressive enhancement: ask the platform to prune this stale passkey
					// from the picker. Privacy-safe (we only signal an id the client just
					// presented). Best-effort + feature-detected; unsupported browsers skip it.
					try {
						const pkc = window.PublicKeyCredential as any;
						if (pkc && typeof pkc.signalUnknownCredential === 'function' && options.publicKey.rpId) {
							await pkc.signalUnknownCredential({
								rpId: options.publicKey.rpId,
								credentialId: errBody.credential_id,
							});
						}
					} catch (_) {
						/* best-effort prune; ignore */
					}
					throw new Error(
						errBody.message ||
							'This passkey is no longer valid. Remove it from your device settings or use another sign-in method.'
					);
				}
				throw new Error(await finishResp.text());
			}

			// New-user gate: when the server reports this passkey resolves to a DID
			// with NO existing account, signing in would CREATE one. Do NOT auto-
			// redirect; show the gate and let the user confirm or pick another key.
			// Nothing is provisioned until the browser navigates to /sign_in (the
			// "Continue" action), so cancelling leaves zero Synapse state.
			const result = await finishResp.json().catch(() => ({}));
			if (result && result.new_user === true) {
				newUserGate = { mxid: result.mxid || '' };
				status = 'New account — confirm to continue';
				return;
			}

			// Existing user: keep the current immediate redirect.
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

	// New-user gate actions.
	function confirmNewUser() {
		newUserGate = null;
		status = 'Redirecting...';
		window.location.replace(buildSignInUrl());
	}

	function gateTryAnother() {
		// Back to the picker: re-run start usernameless (all keys) so the user can
		// pick a different passkey. Clears the gate first.
		newUserGate = null;
		handlePasskeySignIn(true);
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
			status = `Passkey registered! DID: ${result.did.substring(0, 24)}...`;
			error = null;

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

<div class="login-page" class:mounted>
	<div class="ambient-glow"></div>

	<div class="login-card">
		<div class="card-inner">
			<!-- Logo area -->
			<div class="logo-area">
				{#if client_metadata.logo_uri}
					<div class="logo-pair">
						<img src="img/inblockio-logo.png" alt="inblock.io" class="logo" />
						<span class="logo-connector"></span>
						<img src={client_metadata.logo_uri} alt="Client" class="logo" />
					</div>
				{:else}
					<img src="img/inblockio-logo.png" alt="inblock.io" class="logo logo-single" />
				{/if}
			</div>

			{#if newUserGate}
				<!-- === New-user gate: a passkey resolving to a brand-new account === -->
				<!-- Nothing is provisioned yet; Continue navigates to /sign_in (which
				     creates the account), Try another returns to the picker. -->
				<div class="auth-section gate-section">
					<h1 class="title">Create a new account?</h1>
					<p class="subtitle">
						This passkey will create a <strong>new account</strong>{#if newUserGate.mxid}
							(<span class="gate-mxid">{newUserGate.mxid}</span>){/if}.
					</p>
					<p class="gate-note">
						You can restore your messages later with your recovery key.
					</p>

					<div class="link-actions">
						<button class="btn btn-primary" on:click={confirmNewUser}>
							<span>Continue</span>
							<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="btn-icon btn-icon-right">
								<path fill-rule="evenodd" d="M3 10a.75.75 0 0 1 .75-.75h10.638L10.23 5.29a.75.75 0 1 1 1.04-1.08l5.5 5.25a.75.75 0 0 1 0 1.08l-5.5 5.25a.75.75 0 1 1-1.04-1.08l4.158-3.96H3.75A.75.75 0 0 1 3 10Z" clip-rule="evenodd" />
							</svg>
						</button>
						<button
							class="btn btn-ghost"
							disabled={passkeyLoading}
							on:click={gateTryAnother}
						>
							<span>{#if passkeyLoading}Opening picker...{:else}Try another passkey{/if}</span>
						</button>
					</div>
				</div>

			{:else if !showLinkOption}
				<!-- === Default state: choose auth method === -->
				<div class="auth-section">
					<h1 class="title">Sign in</h1>
					<p class="subtitle">
						Continue to {client_metadata.client_name || domain}
					</p>

					{#if detectedMxid}
						<!-- Detected-account affordance: the picker is scoped to this account. -->
						<div class="detected-account">
							<span class="detected-label">Signing in as</span>
							<span class="detected-mxid">{detectedMxid}</span>
						</div>
					{/if}

					<!-- Primary: Ethereum -->
					<button
						class="btn btn-primary"
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
							class="btn-icon eth-icon"
						>
							<g fill-rule="nonzero" transform="matrix(.781253 0 0 .781253 180 37.1453)">
								<path d="m127.961 0-2.795 9.5v275.668l2.795 2.79 127.962-75.638z" fill="#343434" />
								<path d="m127.962 0-127.962 212.32 127.962 75.639v-133.801z" fill="#8c8c8c" />
								<path d="m127.961 312.187-1.575 1.92v98.199l1.575 4.601 128.038-180.32z" fill="#3c3c3b" />
								<path d="m127.962 416.905v-104.72l-127.962-75.6z" fill="#8c8c8c" />
								<path d="m127.961 287.958 127.96-75.637-127.96-58.162z" fill="#141414" />
								<path d="m.001 212.321 127.96 75.637v-133.799z" fill="#393939" />
							</g>
						</svg>
						<span>{#if connecting}Connecting wallet...{:else}Sign in with Ethereum{/if}</span>
					</button>

					<!-- Divider -->
					<div class="divider">
						<div class="divider-line"></div>
						<span class="divider-text">or</span>
						<div class="divider-line"></div>
					</div>

					<!-- Secondary: Passkey sign-in -->
					<button
						class="btn btn-secondary"
						disabled={passkeyLoading}
						on:click={() => handlePasskeySignIn()}
					>
						<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="btn-icon">
							<path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd" />
						</svg>
						<span>{#if passkeyLoading}Authenticating...{:else}Sign in with Passkey{/if}</span>
					</button>

					{#if detectedMxid}
						<!-- Escape hatch: re-run usernameless so the picker shows ALL keys. -->
						<p class="register-hint">
							<button
								class="link-btn"
								disabled={passkeyLoading}
								on:click={() => handlePasskeySignIn(true)}
							>
								Use a different passkey
							</button>
						</p>
					{/if}

					<p class="register-hint">
						No passkey yet?
						<button
							class="link-btn"
							disabled={passkeyLoading}
							on:click={handlePasskeyRegister}
						>
							Create one
						</button>
					</p>
				</div>

			{:else}
				<!-- === Post-Ethereum: passkey linking === -->
				<div class="auth-section link-section">
					{#if linkSuccess}
						<div class="success-badge">
							<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon">
								<path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
							</svg>
						</div>
						<h1 class="title">Passkey linked</h1>
						<p class="subtitle">You can use it to sign in next time without a wallet.</p>
						<button class="btn btn-primary" on:click={proceedToSignIn}>
							<span>Continue to {client_metadata.client_name || domain}</span>
							<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="btn-icon btn-icon-right">
								<path fill-rule="evenodd" d="M3 10a.75.75 0 0 1 .75-.75h10.638L10.23 5.29a.75.75 0 1 1 1.04-1.08l5.5 5.25a.75.75 0 0 1 0 1.08l-5.5 5.25a.75.75 0 1 1-1.04-1.08l4.158-3.96H3.75A.75.75 0 0 1 3 10Z" clip-rule="evenodd" />
							</svg>
						</button>
					{:else}
						<div class="success-badge">
							<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon">
								<path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
							</svg>
						</div>
						<h1 class="title">Wallet verified</h1>
						<p class="subtitle">
							Link a passkey so you can sign in without a wallet next time.
						</p>

						<div class="link-actions">
							<button
								class="btn btn-primary"
								disabled={linkingPasskey}
								on:click={handleLinkPasskey}
							>
								<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="btn-icon">
									<path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd" />
								</svg>
								<span>{#if linkingPasskey}Linking...{:else}Link a passkey{/if}</span>
							</button>

							<button
								class="btn btn-ghost"
								disabled={linkingPasskey}
								on:click={proceedToSignIn}
							>
								<span>Skip for now</span>
								<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="btn-icon btn-icon-right">
									<path fill-rule="evenodd" d="M3 10a.75.75 0 0 1 .75-.75h10.638L10.23 5.29a.75.75 0 1 1 1.04-1.08l5.5 5.25a.75.75 0 0 1 0 1.08l-5.5 5.25a.75.75 0 1 1-1.04-1.08l4.158-3.96H3.75A.75.75 0 0 1 3 10Z" clip-rule="evenodd" />
								</svg>
							</button>
						</div>
					{/if}
				</div>
			{/if}

			<!-- Error display -->
			{#if error}
				<div class="error-msg">
					<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="error-icon">
						<path fill-rule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 5Zm0 10a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clip-rule="evenodd" />
					</svg>
					<span>{error}</span>
				</div>
			{/if}

			<!-- Footer -->
			<div class="footer">
				<p>
					By continuing you agree to the
					<a href="/legal/terms-of-use.html">Terms of Use</a> and
					<a href="/legal/privacy-policy.html">Privacy Policy</a>.
				</p>
				{#if client_metadata.client_uri}
					<p class="client-uri">Requested by {client_metadata.client_uri}</p>
				{/if}
			</div>
		</div>
	</div>
</div>

<style lang="postcss">
	@tailwind base;
	@tailwind components;
	@tailwind utilities;

	/* ---- Page ---- */

	:global(html), :global(body) {
		margin: 0;
		padding: 0;
		width: 100%;
		height: 100%;
		background: #f5f5f5;
		overflow-x: hidden;
		font-family: 'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
		-webkit-font-smoothing: antialiased;
		-moz-osx-font-smoothing: grayscale;
	}

	.login-page {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 100vh;
		padding: 24px;
		background: #f5f5f5;
		opacity: 0;
		transition: opacity 0.6s ease;
	}

	.login-page.mounted {
		opacity: 1;
	}

	.ambient-glow {
		position: fixed;
		top: -30%;
		left: 50%;
		transform: translateX(-50%);
		width: 800px;
		height: 600px;
		background: radial-gradient(
			ellipse at center,
			rgba(232, 97, 26, 0.06) 0%,
			rgba(232, 97, 26, 0.02) 40%,
			transparent 70%
		);
		pointer-events: none;
		z-index: 0;
	}

	/* ---- Card ---- */

	.login-card {
		position: relative;
		z-index: 1;
		width: 100%;
		max-width: 400px;
		border-radius: 20px;
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.06);
		box-shadow:
			0 1px 3px rgba(0, 0, 0, 0.04),
			0 8px 32px -8px rgba(0, 0, 0, 0.08);
	}

	.card-inner {
		padding: 40px 36px 32px;
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	/* ---- Logo ---- */

	.logo-area {
		display: flex;
		justify-content: center;
		margin-bottom: 32px;
	}

	.logo {
		width: 52px;
		height: 52px;
		object-fit: contain;
		border-radius: 12px;
	}

	.logo-single {
		width: 56px;
		height: 56px;
	}

	.logo-pair {
		display: flex;
		align-items: center;
		gap: 16px;
	}

	.logo-connector {
		display: block;
		width: 24px;
		height: 1px;
		background: rgba(0, 0, 0, 0.12);
		position: relative;
	}

	.logo-connector::after {
		content: '';
		position: absolute;
		right: -2px;
		top: -2px;
		width: 5px;
		height: 5px;
		border-radius: 50%;
		background: rgba(0, 0, 0, 0.12);
	}

	/* ---- Auth section ---- */

	.auth-section {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
	}

	.title {
		font-family: 'Satoshi', sans-serif;
		font-weight: 700;
		font-size: 22px;
		line-height: 1.3;
		color: #1a1a1a;
		margin: 0 0 6px;
		letter-spacing: -0.3px;
	}

	.subtitle {
		font-size: 14px;
		line-height: 1.5;
		color: rgba(0, 0, 0, 0.4);
		margin: 0 0 28px;
	}

	/* ---- Detected-account affordance + new-user gate (Task 5) ---- */

	.detected-account {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 10px 14px;
		margin: 0 0 16px;
		border-radius: 12px;
		background: rgba(232, 97, 26, 0.06);
		border: 1px solid rgba(232, 97, 26, 0.16);
		text-align: left;
	}

	.detected-label {
		font-size: 12px;
		color: rgba(0, 0, 0, 0.4);
	}

	.detected-mxid,
	.gate-mxid {
		font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
		font-size: 13px;
		font-weight: 600;
		color: rgba(0, 0, 0, 0.75);
		word-break: break-all;
	}

	.gate-note {
		font-size: 13px;
		line-height: 1.5;
		color: rgba(0, 0, 0, 0.5);
		margin: 0 0 24px;
	}

	/* ---- Buttons ---- */

	.btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
		height: 48px;
		padding: 0 20px;
		border-radius: 12px;
		font-family: 'Satoshi', sans-serif;
		font-weight: 600;
		font-size: 14px;
		letter-spacing: 0.1px;
		cursor: pointer;
		transition: all 0.15s ease;
		border: none;
		outline: none;
		width: 100%;
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		background: linear-gradient(135deg, #EF5402 0%, #D4570F 100%);
		color: #fff;
		box-shadow:
			0 1px 2px rgba(0, 0, 0, 0.1),
			0 0 0 1px rgba(232, 97, 26, 0.12) inset;
	}

	.btn-primary:not(:disabled):hover {
		background: linear-gradient(135deg, #ff6a1a 0%, #EF5402 100%);
		box-shadow:
			0 4px 16px rgba(232, 97, 26, 0.25),
			0 0 0 1px rgba(232, 97, 26, 0.15) inset;
		transform: translateY(-1px);
	}

	.btn-primary:not(:disabled):active {
		transform: translateY(0);
		box-shadow:
			0 1px 4px rgba(232, 97, 26, 0.12),
			0 0 0 1px rgba(232, 97, 26, 0.1) inset;
	}

	.btn-secondary {
		background: rgba(0, 0, 0, 0.03);
		color: #1a1a1a;
		border: 1px solid rgba(0, 0, 0, 0.08);
	}

	.btn-secondary:not(:disabled):hover {
		background: rgba(0, 0, 0, 0.06);
		border-color: rgba(0, 0, 0, 0.12);
		transform: translateY(-1px);
	}

	.btn-secondary:not(:disabled):active {
		transform: translateY(0);
		background: rgba(0, 0, 0, 0.05);
	}

	.btn-ghost {
		background: transparent;
		color: rgba(0, 0, 0, 0.4);
		border: 1px solid rgba(0, 0, 0, 0.06);
	}

	.btn-ghost:not(:disabled):hover {
		color: rgba(0, 0, 0, 0.65);
		background: rgba(0, 0, 0, 0.02);
		border-color: rgba(0, 0, 0, 0.1);
	}

	.btn-icon {
		width: 18px;
		height: 18px;
		flex-shrink: 0;
	}

	.btn-icon-right {
		width: 16px;
		height: 16px;
		margin-left: -2px;
	}

	.eth-icon {
		width: 14px;
		height: 22px;
	}

	/* ---- Divider ---- */

	.divider {
		display: flex;
		align-items: center;
		gap: 14px;
		margin: 16px 0;
		width: 100%;
	}

	.divider-line {
		flex: 1;
		height: 1px;
		background: rgba(0, 0, 0, 0.07);
	}

	.divider-text {
		font-size: 12px;
		color: rgba(0, 0, 0, 0.25);
		text-transform: uppercase;
		letter-spacing: 1px;
		font-weight: 500;
	}

	/* ---- Register hint ---- */

	.register-hint {
		text-align: center;
		font-size: 13px;
		color: rgba(0, 0, 0, 0.35);
		margin: 12px 0 0;
	}

	.link-btn {
		background: none;
		border: none;
		padding: 0;
		margin: 0;
		color: #E8611A;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		font-family: inherit;
		text-decoration: none;
		transition: color 0.15s ease;
	}

	.link-btn:hover {
		color: #EF5402;
	}

	.link-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	/* ---- Link section (post-Ethereum) ---- */

	.link-section {
		align-items: center;
		text-align: center;
	}

	.link-section .subtitle {
		max-width: 280px;
	}

	.success-badge {
		margin-bottom: 16px;
	}

	.success-icon {
		width: 40px;
		height: 40px;
		color: #E8611A;
	}

	.link-actions {
		display: flex;
		flex-direction: column;
		gap: 10px;
		width: 100%;
	}

	/* ---- Error ---- */

	.error-msg {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		margin-top: 16px;
		padding: 10px 14px;
		border-radius: 10px;
		background: rgba(239, 68, 68, 0.05);
		border: 1px solid rgba(239, 68, 68, 0.12);
	}

	.error-msg span {
		font-size: 13px;
		line-height: 1.4;
		color: #dc2626;
	}

	.error-icon {
		width: 16px;
		height: 16px;
		color: #dc2626;
		flex-shrink: 0;
		margin-top: 1px;
	}

	/* ---- Footer ---- */

	.footer {
		margin-top: 28px;
		padding-top: 20px;
		border-top: 1px solid rgba(0, 0, 0, 0.05);
		text-align: center;
	}

	.footer p {
		font-size: 11px;
		line-height: 1.5;
		color: rgba(0, 0, 0, 0.3);
		margin: 0;
	}

	.footer a {
		color: rgba(0, 0, 0, 0.45);
		text-decoration: none;
		transition: color 0.15s ease;
	}

	.footer a:hover {
		color: rgba(0, 0, 0, 0.7);
	}

	.client-uri {
		margin-top: 6px !important;
		font-size: 10px !important;
		color: rgba(0, 0, 0, 0.2) !important;
	}

	/* ---- Tooltip (kept for compat) ---- */

	:global(.tooltip) {
		@apply invisible absolute;
	}

	:global(.has-tooltip:hover .tooltip) {
		@apply visible z-50;
	}

	:global(.grecaptcha-badge) {
		visibility: hidden;
	}

	/* ---- Scrollbar ---- */

	:global(::-webkit-scrollbar-track) {
		border-radius: 8px;
		background-color: #eee;
	}

	:global(::-webkit-scrollbar-thumb) {
		border-radius: 8px;
		background-color: #ccc;
	}

	:global(::-webkit-scrollbar) {
		height: 6px;
		width: 6px;
		border-radius: 8px;
		background-color: #eee;
	}
</style>
