# Audit — dev-staging deploy pipeline (process-pipeline Phase 3)

**Date:** 2026-07-30 · **Plan:** `docs/superpowers/plans/2026-07-30-dev-staging-deploy-caddy-migration.md` · **Independent evidence:** `docs/audits/2026-07-30-dev-staging-audit-evidence.md` (T6 verifier re-ran every check from scratch; no discrepancies vs. implementers' claims).

## Layer 1 — Hypothesis trace

| ID | Hypothesis (short) | Status | Evidence |
|----|--------------------|--------|----------|
| H1 | Static Caddyfile replicates the 5 nginx-proxy vhosts | **Confirmed** | T3: 5/5 vhosts byte-identical to pre-cutover baselines (1808/15/1719/52199/6843 B), LE issuers. T6 independent: 5/5 → 200, LE cert, HSTS, `via: 1.1 Caddy`. |
| H2 | Cutover <60 s, rollback = restart old containers | **Confirmed** (burn-in gate open) | Measured worst-case downtime **8.7 s** (395-sample external probe); cutover commands 1.39 s. `aqua_proxy`/`aqua_acme` intact, `restart=no` (T6 `docker inspect`). 24 h burn-in completes **2026-07-31 ~17:44 UTC** — teardown decision then. |
| H3 | Adapted stack → e2e login works | **Confirmed** | T4: dynamic client registration + headless did:key flow → `mat_`/`mcr_` tokens → `whoami` = `@did-key-…:dev.matrix.inblock.io`, `SIWX_` device. T6 repeated with a FRESH throwaway key incl. ES256 `id_token` claim/kid validation against `/jwk`. |
| H4 | dev server_name + well-known → discovery works | **Confirmed** | `.well-known/matrix/client` (m.homeserver, m.authentication.issuer=dev.siwx, rtc_foci) + `/server` + `/_matrix/client/versions` all 200 (T4, re-verified T6). |
| H5 | Stack fits: ≥1 GB available at idle | **Confirmed** | 10.3-min window: available 2521→2543 MB, used ↓22 MB, swap flat 1 MB, no restarts; T6 at the 30-min mark: 2521 MB available (>2× the bar). |
| H6 | Push to main → box converges in minutes | **Confirmed** | siwx-oidc main push 18:39:40Z → CI build success 18:43:47Z → box timer tick 18:47:20Z pulled + recreated container healthy: digest `1ea913fa…` → `0732dbf8…` (independently re-inspected). Convergence ~7.7 min, zero manual steps. |
| H7 | LiveKit ports bind + reachable config | **Confirmed** | 7881/tcp LISTEN + 101 UDP sockets 50100-50200 bound; ufw ALLOW rules v4+v6 (T3 added, T6 verified). |

## Layer 2 — Acceptance criteria

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| AC1 | 5 legacy vhosts on HTTPS via Caddy | **Yes** | H1 |
| AC2 | 3 dev domains serve with valid TLS | **Yes** | H1/H4 sweep + Element 200 with config → dev.matrix |
| AC3 | End-to-end login (headless verified) | **Yes** | H3 (twice, independently) |
| AC4 | Push to main auto-deploys, digest change verified | **Yes** | H6 |
| AC5 | Caddy-everywhere directive recorded | **Yes** | `~/.claude/CLAUDE.md` §Infrastructure directive |
| AC6 | Rollback documented + available ≥24 h | **Partial (time-gated)** | Documented (runbook §7), containers intact + restart=no; window closes 2026-07-31 ~17:44 UTC, then `down` the old proxy project per runbook §8. |

## Discovered during execution (register kept immutable)

1. **Synapse `:main` (1.157.1) removed `experimental_features.msc3861`** — the entrypoint's config hard-fails; stable `matrix_authentication_service` schema is narrower and may assume a real MAS. Dev pinned `IMAGE_TAG=sha-4266aa8` (1.153.0). **Prod-facing:** prod compose floats the same tags — a routine `pull && up -d` on prod would break Synapse today. Strategic overlap with the MSC4388 rendezvous risk (upstream consolidating on real MAS).
2. **`lk-jwt-service:latest` hard-requires `LIVEKIT_FULL_ACCESS_HOMESERVERS`** — fixed for dev (`823818b`); prod compose has the same gap, unfixed.
3. **inblockio gh PAT invalid** (SEC-0001 rotation landed). Per user directive, pipeline pivoted to SSH-only: fast-forward merges instead of PRs; auto-deploy is a **box-side pull-model systemd timer** (5-min cadence, flock-serialized `ci-deploy.sh`) needing no GitHub secret. Push-model job merged but dormant behind a secret-presence guard (skips green).
4. **Signing-key exposure incident (T4, remediated):** resolved compose config printed the fresh `SIWEOIDC_SIGNING_KEY_PEM` once into a transcript; key regenerated on the box before first stack start — exposed key never signed anything.
5. **Cutover-quality defects found by baseline diffing (fixed):** HSTS header-order inversion (RFC 6797 first-header-wins downgrade) and `200MB`(decimal)≠`200m`(binary) body-size mismatch → `200MiB`.
6. **Pre-existing red `ci` workflow on siwx-oidc main** (lint/test, failing before this work, e.g. `17a1d344`) — untouched, needs a separate fix.
7. **Landmine (standing):** `/home/dev/aquafier-js/deployment/docker-compose-dev.yml` contains a dormant duplicate proxy pair neutralized only by an override file — never run compose there (runbook §0).

## Verdict

All 7 hypotheses confirmed with executed-command evidence; 5/6 acceptance criteria met, AC6 time-gated (closes 2026-07-31 evening). No remediation loop required.

## Open items / follow-up backlog

1. 2026-07-31 ~17:44 UTC: end burn-in — `docker compose -f /home/dev/aquafier-rs/deployment/docker-compose-proxy.yml down` (runbook §8).
2. Synapse 1.157 / `matrix_authentication_service` compatibility investigation (prod-facing, strategic; pairs with MSC4388 tripwire = `msc_4388.rs` appearing in matrix-rust-sdk).
3. Port to prod compose: `LIVEKIT_FULL_ACCESS_HOMESERVERS` + pinned image tags.
4. Fix the pre-existing red `ci` (lint/test) workflow on siwx-oidc main.
5. Testing two-tier build-out (separate pipeline): Tier 1 headless `qrphone` (matrix-rust-sdk MSC4108) in CI critical-path; expensive tiers as local pre-push qualification; orient on Element/matrix.org tooling.
6. Optional: restore PAT → enables PRs, `gh` visibility, and the dormant push-model deploy (secrets commands in runbook §9).
7. Re-verify `response_modes_supported` on dev.siwx after `fix/finding3-fragment-response-mode` merges and auto-deploys.
