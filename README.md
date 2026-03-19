# OpenID Connect Identity Provider for Sign-In with Ethereum

## Getting Started

> The front-end depends on WalletConnect, meaning you will need to create a
> project with them and have the environment variable `PROJECT_ID` set when you
> build the front-end.

### Stand-Alone Binary

> **WARNING - ** Due to the reliance on WalletConnect, and the project ID being
> loaded at compile-time, the current version of the Docker image won't have a
> working web app.

#### Dependencies

Redis, or a Redis compatible database (e.g. MemoryDB in AWS), is required.

#### Starting the IdP

The Docker image is available at `ghcr.io/spruceid/siwe_oidc:0.1.0`. Here is an
example usage:
```bash
docker run -p 8000:8000 -e SIWEOIDC_REDIS_URL="redis://redis" ghcr.io/spruceid/siwe_oidc:latest
```

It can be configured either with the `siwe-oidc.toml` configuration file, or
through environment variables:
* `SIWEOIDC_ADDRESS` is the IP address to bind to.
* `SIWEOIDC_REDIS_URL` is the URL to the Redis instance.
* `SIWEOIDC_BASE_URL` is the URL you want to advertise in the OIDC configuration
  (e.g. `https://oidc.example.com`).
* `SIWEOIDC_SIGNING_KEY_PEM` is the signing key (PKCS#8 PEM, ES256/P-256 ECDSA).
  One will be generated if none is provided.

### OIDC Functionalities

The current flow is very basic -- after the user is authenticated you will
receive:
- an Ethereum address as the subject (`sub` field); and
- an ENS domain as the `preferred_username` (with a fallback to the address).

For the core OIDC information, it is available under
`/.well-known/openid-configuration`.

OIDC Conformance Suite:
- 🟨 (25/29, and 10 skipped) [basic](https://www.certification.openid.net/plan-detail.html?plan=gXe7Ju1O1afZa&public=true) (`email` scope skipped,  `profile` scope partially supported, ACR, `prompt=none` and request URIs yet to be supported);
- 🟩 [config](https://www.certification.openid.net/plan-detail.html?plan=SAmBjvtyfTDVn&public=true);
- 🟧 [dynamic code](https://www.certification.openid.net/plan-detail.html?plan=7rexGcCd4SWJa&public=true).

### TODO Items

* Additional information, from native projects (e.g. ENS domains profile
  pictures), to more traditional ones (e.g. email).

## Development

### Stand Alone Binary

A Docker Compose is available to test the IdP locally with Keycloak.

1. You will first need to run:
```bash
docker-compose -f test/docker-compose.yml up -d
```

2. And then edit your `/etc/hosts` to have `siwe-oidc` point to `127.0.0.1`.
   This is so both your browser, and Keycloak, can access the IdP.

3. In Keycloak, you will need to create a new IdP. You can use
   `http://siwe-oidc:8000/.well-known/openid-configuration` to fill the settings
   automatically. As for the client ID/secret, you can use `sdf`/`sdf`.

## Disclaimer

Our identity provider for Sign-In with Ethereum has not yet undergone a formal
security audit. We welcome continued feedback on the usability, architecture,
and security of this implementation.
