import './global.css';

import App from './App.svelte';

const params = new URLSearchParams(window.location.search);

const app = new App({
	target: document.body,
	props: {
		domain: params.get('domain'),
		nonce: params.get('nonce'),
		redirect: params.get('redirect_uri'),
		state: params.get('state'),
		oidc_nonce: params.get('oidc_nonce'),
		client_id: params.get('client_id'),
		code_challenge: params.get('code_challenge'),
		code_challenge_method: params.get('code_challenge_method'),
	}
});

export default app;
