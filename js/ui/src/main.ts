// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

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
		response_mode: params.get('response_mode'),
	}
});

export default app;
