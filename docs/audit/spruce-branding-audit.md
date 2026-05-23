# Spruce Branding Audit — HIGH PRIORITY (Pre-Production)

**Date:** 2026-05-23
**Status:** OPEN
**Priority:** HIGH — must be resolved before production deployment

## Summary

siwx-oidc was forked from Spruce Systems, Inc.'s siwe-oidc. Two critical
public-facing legal documents still carry Spruce branding, contact info, and
legal terms. Users currently agree to Spruce's Terms of Use and Privacy Policy
when logging in. This is legally incorrect for an inblock.io assets GmbH
deployment.

## Findings

### Critical (public-facing, user-visible)

| File | Content | Severity |
|------|---------|----------|
| `static/legal/terms-of-use.pdf` | Entire document is Spruce's ToU. 40+ mentions of "Spruce," "SPRUCE SYSTEMS, INC.", contact `hello@spruceid.com`, address `228 Park Avenue S #28788 New York, NY 10003`. Binding arbitration in NY. References `oidc.login.xyz`. | CRITICAL |
| `static/legal/privacy-policy.pdf` | Entire document is Spruce's Privacy Policy. 20+ mentions of "Spruce," contact `hello@spruceid.com`, same NY address. Data controller = Spruce. GDPR/CCPA sections reference Spruce. | CRITICAL |
| `js/ui/src/App.svelte:500-502` | Footer "By continuing you agree to the Terms of Use and Privacy Policy" links to the above PDFs. Every user sees this on login. | HIGH |

### Low (non-public, dev-only)

| File | Content | Severity |
|------|---------|----------|
| `wrangler_example.toml:14` | `BASE_URL = "https://siweoidc.spruceid.xyz"` (dead Cloudflare Workers artifact) | LOW |
| `test/docker-compose.yml:5` | `image: ghcr.io/spruceid/siwe_oidc:latest` (old upstream image ref) | LOW |

### License files

| File | Issue |
|------|-------|
| `LICENSE-MIT` | Copyright `(c) 2018 Ashley Williams` (cargo init template boilerplate, not Spruce, not inblock.io) |
| `LICENSE-APACHE` | Standard Apache 2.0 text, no copyright holder named. Fine as-is. |

## Required Actions

### A) Replace legal documents (CRITICAL, requires lawyer)

The Terms of Use and Privacy Policy must be replaced with inblock.io assets GmbH
documents. Problems with current documents:

- Users cannot contact `hello@spruceid.com` for data requests
- Spruce is named as data controller under GDPR, but has no relationship to our deployment
- Arbitration clause binds users to NY courts under Spruce's name
- `oidc.login.xyz` URLs in both documents are not our domain
- Data processing description is incomplete (only mentions "Ethereum Account Information",
  missing passkey credentials, DIDs, Redis session data, Synapse integration)

New documents must:

1. Name **inblock.io assets GmbH** as service operator
2. Use inblock.io contact details
3. Reference actual deployment domain(s)
4. Use **German/EU law** as governing law (not NY arbitration)
5. Include DSGVO/GDPR-compliant privacy policy naming inblock.io as data controller
6. Describe actual data processed: wallet addresses, DIDs, passkey credentials, session data, Synapse device provisioning
7. Include Impressum-style disclosure (required for German GmbH)

### B) Update LICENSE-MIT copyright (can do immediately)

Replace:
```
Copyright (c) 2018 Ashley Williams <ashley666ashley@gmail.com>
```
With:
```
Copyright (c) 2021 Spruce Systems, Inc.
Copyright (c) 2024-2026 inblock.io assets GmbH
```

Preserves attribution to original authors (Apache 2.0 Section 4(c) requires
retaining copyright notices) while adding our own.

### C) Add NOTICE file (can do immediately)

Apache 2.0 Section 4(d) encourages a NOTICE file:

```
siwx-oidc
Copyright 2024-2026 inblock.io assets GmbH

This project is derived from siwe-oidc, originally developed by
Spruce Systems, Inc. (https://github.com/spruceid/siwe-oidc).
The original work was licensed under MIT OR Apache-2.0.
```

### D) Clean up stale Spruce references (can do immediately)

- `wrangler_example.toml`: delete entirely (Cloudflare Workers deployment unused)
- `test/docker-compose.yml:5`: update image to `ghcr.io/inblockio/siwx-oidc:latest`

### E) Update Cargo.toml (can do immediately)

Add `authors` field:
```toml
authors = ["inblock.io assets GmbH"]
```

### F) Consider HTML instead of PDF for legal docs

HTML is more accessible, easier to update, and can be version-controlled
meaningfully. PDFs are opaque binary blobs in git.

## Completion Checklist

- [ ] New Terms of Service drafted (lawyer review)
- [ ] New Privacy Policy drafted (lawyer review, DSGVO-compliant)
- [ ] Legal PDFs replaced in `static/legal/`
- [ ] LICENSE-MIT copyright updated
- [ ] NOTICE file created
- [ ] `wrangler_example.toml` deleted
- [ ] `test/docker-compose.yml` image reference updated
- [ ] `Cargo.toml` authors field added
- [ ] Frontend footer links verified working with new documents
