# Finding: Element Web ≥ 1.12.24 (matrix-js-sdk v42) cannot log in against siwx-oidc

**Date:** 2026-07-25 (parallel-container investigation on the local Element lab)
**Status:** OPEN — blocks any future Element Web upgrade past 1.12.23
**Evidence:** `2026-07-25-elementweb-jssdk-v42-compat-evidence.spec.mjs.txt` (the
Playwright shim spec that isolated both causes), lab run logs in the Phase-2
session records.

## Summary

Element Web v1.12.24 ships "Adapt OAuth2 implementation to Matrix Spec v1.18"
(element-web #34026 / matrix-js-sdk #5390 → js-sdk **v42.0.0**). Against current
siwx-oidc, login fails BEFORE any UI: Element falls back to the legacy
`/_matrix/client/v3/login/sso/redirect`, which 404s under MSC3861 — the exact
silent dead-end class of the auth_metadata finding. Two independent causes,
both verified live with client-side shims (fixing each in isolation confirms
the other):

1. **Metadata validation.** js-sdk v42 `isValidAuthMetadata`
   (src/oauth/discover.ts) hard-requires `response_modes_supported` containing
   BOTH `"query"` and `"fragment"`. siwx's provider metadata omits the field
   entirely → issuer validation fails → silent legacy-SSO fallback → 404.
2. **Response mode.** js-sdk v42 sends `response_mode=fragment` on /authorize
   and reads the authorization response ONLY from the URL fragment. siwx has no
   `response_mode` handling — `sign_in` (src/oidc.rs) always appends
   `?code=…&state=…` as query params → Element never recognizes the return and
   bounce-loops back to /authorize. (js-sdk in 1.12.20 also *requests* fragment
   but tolerates query delivery; v42 is strict.)

Non-issues, confirmed once both causes were shimmed: v42 drops the `openid`
scope (siwx accepts Matrix-only scopes), dynamic client registration works,
token exchange completes ("Logged in via OAuth2 native flow").

## Required siwx-oidc fix (before any Element ≥ 1.12.24 anywhere)

1. Advertise `response_modes_supported: ["query", "fragment"]` in the provider
   metadata (`oidc::provider_metadata_value`) — but ONLY together with (2);
   advertising fragment without honoring it makes v42 strictly worse.
2. Honor `response_mode=fragment`: carry the requested response_mode through
   the authorize session, and have `sign_in` deliver
   `#code=…&state=…` (fragment) instead of query when requested.
3. Re-run: mock browser suite, Element suite, and a 1.12.24 parallel container
   (see the evidence spec for the shim-free repro), plus
   `scripts/check-auth-metadata.sh` (which WARNs on the missing field until
   this ships — flip the WARN to FAIL once implemented and deployed).

## Deployment guard rail

`scripts/check-auth-metadata.sh` (deploy-check step 4) warns when
`response_modes_supported` lacks query+fragment. Do not bump Element Web
(lab OR prod) past 1.12.23 until the fix above is deployed and the guard is
flipped to FAIL.
