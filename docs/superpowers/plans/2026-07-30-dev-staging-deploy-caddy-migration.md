# Dev-staging deploy: siwx-matrix stack on dev-aquafire + Caddy migration + CI auto-deploy

**Date:** 2026-07-30 · **Orchestrator:** Fable (team-lead), Opus for the risky live migration, Sonnet for implementation/DevOps · **Pipeline:** /process-pipeline (logic-model → execute → audit)

## Context (verified 2026-07-30)

- **Target box:** dev-aquafire = `207.154.209.103` (`ssh -p 8022 dev@207.154.209.103`, key `~/.ssh/id_inblock_deploy`, passwordless sudo). Ubuntu 24.04, 2 vCPU, 3.9 GB RAM (~2.77 GB available), 103 GB disk free, load ~0.16.
- **Already running there (must not break):** 9 containers behind `aqua_proxy` (ghcr.io/inblockio/ngnix-proxy:master, docker-gen `VIRTUAL_HOST` pattern) + `aqua_acme` (acme-companion). Live vhosts: `aquafier.inblock.io`, `aquafier-api.inblock.io` → deployment-aqua-container-1; `dev.aqua-node.inblock.io` → aqua-explorer; `dev.aquafire.inblock.io` → aquafier-rs:3000; `draw.inblock.io` → excalidraw. Plus 2× postgres:18, MinIO (no vhost, internal).
- **Stack to deploy:** `../siwx-oidc-matrix-server` prod compose = custom Synapse (SQLite, no Postgres), Redis, siwx-oidc, Element Web, LiveKit (+lk-jwt-service). ~0.5–1.2 GB RAM loaded, ~1 GB images. Reverse proxy NOT in compose (prod uses external portal Caddy).
- **DNS (already resolving):** `dev.matrix.inblock.io`, `dev.siwx.inblock.io`, `dev.element.inblock.io` → all A → 207.154.209.103. `dev.matrix.inblock.io` is the Matrix `server_name` (permanent for this instance's MXIDs).
- **User decisions:** adopt Caddy — replace nginx-proxy on this box (global directive recorded in `~/.claude/CLAUDE.md`); full stack incl. LiveKit; testing-pipeline build-out (qrphone Tier 1, Android tier) is FOLLOW-UP scope, two-tiered (cheap critical-path tests in CI, expensive qualification tests locally, oriented on matrix.org/Element upstream tooling).
- **CI today:** both repos build+push images to GHCR on push to main; NO deploy step anywhere; `deploy.sh` hardcodes prod host + prod portal Caddyfile; prod watchtower is dead code.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | A static Caddyfile replicates the 5 nginx-proxy vhosts (same upstream container:port, Caddy joined to the same docker networks) | all 5 existing services serve identically over HTTPS via Caddy | upstream ports readable from generated nginx conf (`docker exec aqua_proxy cat /etc/nginx/conf.d/default.conf`); no load-bearing nginx-specific directive (websocket upgrade and body-size limits re-expressed in Caddy) | `curl -sSI https://<vhost>` ×5 post-cutover: expected status + Let's Encrypt issuer |
| H2 | nginx-proxy + acme-companion are STOPPED (not removed) and Caddy binds 80/443 | cutover downtime <60 s per vhost and rollback = stop caddy, `docker start aqua_proxy aqua_acme` | nothing else binds 80/443; LE rate limits not exhausted (8 new certs ≪ limits) | timed cutover log; rollback procedure written + containers verified still present |
| H3 | Prod compose adapted for dev-staging (dev domains, Caddy vhosts incl. `strip_upstream_cors`, fresh secrets on the box) | Element Web ↔ siwx-oidc ↔ Synapse login works end-to-end on dev | GHCR `main` images healthy; SQLite adequate for staging | OIDC discovery curl + headless `siwx-oidc-auth` flow + `whoami` returns expected MXID |
| H4 | `MATRIX_HOST=dev.matrix.inblock.io` + `.well-known` served via Caddy | client discovery + MSC3861 introspection work | DNS stays pointed at the box | `curl https://dev.matrix.inblock.io/.well-known/matrix/client` shows `m.homeserver` + `m.authentication`; login smoke passes |
| H5 | Full stack (incl. LiveKit) lands on a box with ~2.77 GB available | ≥1 GB RAM still available at idle after 30 min burn-in | existing containers' usage stays stable (~1.2 GB) | `free -m` + `docker stats --no-stream` after burn-in |
| H6 | A CD job with a dedicated restricted SSH key runs `docker compose pull && up -d` on push to main | dev box converges to newest `main` images within ~5 min of CI publish | GitHub secrets settable with current PAT; port 8022 reachable from GH runners (contingency: self-hosted runner/tailscale if firewalled) | one real workflow run; image digests on box change to newest GHCR digests |
| H7 | LiveKit publishes 7881/tcp + 50100–50200/udp with `use_external_ip: true` | ports bind cleanly and SFU advertises 207.154.209.103 | ports currently free; no cloud firewall dropping UDP | `ss -tlnp`/`ss -ulnp` before; container healthy + port bound after |

## Tasks

### T1: Global Caddy directive + project memory — DONE inline (orchestrator)
**Hypotheses:** — (AC5)
Directive added to `~/.claude/CLAUDE.md`; memory `dev-aquafire-staging` written.

### T2: Author dev-staging artifacts in siwx-oidc-matrix-server (Sonnet)
**Hypotheses:** H1 (draft), H3, H4, H7 (prep)
**Files (new branch `dev-staging` in `../siwx-oidc-matrix-server`):**
- `Caddyfile.dev-aquafire` — all 8 vhosts: 5 migrated (upstreams TBD by T3 inventory) + `dev.matrix.inblock.io` (Synapse + `.well-known/matrix/{client,server}` + livekit subpaths), `dev.siwx.inblock.io` (CORS strip), `dev.element.inblock.io`
- `docker-compose.dev-staging.yml` — prod services + a `caddy:2-alpine` service binding 80/443, joined to the existing containers' networks (external networks)
- `.env.dev-staging.example` — names only, secrets generated on the box
- `docs/2026-07-30-dev-staging-dev-aquafire.md` — runbook: cutover, rollback, secret generation
- [ ] PR against main (deploy pulls from the branch until merged)

### T3: Live proxy migration on dev-aquafire (Opus — riskiest step)
**Hypotheses:** H1, H2
- [ ] Inventory: dump generated nginx conf for exact upstream IP:port per vhost; list docker networks of the 5 backends; check 7881/50100–50200 free (H7 pre-check)
- [ ] Fill real upstreams into `Caddyfile.dev-aquafire`; stage caddy container (not yet on 80/443)
- [ ] Cutover: `docker stop aqua_proxy aqua_acme` → start Caddy on 80/443 → watch cert issuance
- [ ] Verify all 5 vhosts (H1 check); timed log (H2)
- [ ] Rollback REHEARSED on paper + old containers kept stopped ≥24 h burn-in; DevOps docs updated

### T4: Stand up the stack (Sonnet)
**Hypotheses:** H3, H4, H5, H7
- [ ] `/home/dev/matrix-staging/` on the box: compose + Caddyfile from T2 branch, generate secrets (`SIWEOIDC_SIGNING_KEY_PEM`, `MAS_SHARED_SECRET`, LiveKit keys) on the box only
- [ ] `docker compose up -d`; verify OIDC discovery, `.well-known`, Element loads, Synapse healthy
- [ ] H5 burn-in measurement

### T5: CI auto-deploy (Sonnet)
**Hypotheses:** H6
- [ ] Dedicated deploy keypair on the box (`command=`-restricted authorized_keys entry if practical)
- [ ] GitHub secrets in BOTH repos (`gh secret set`); deploy job appended to each `docker.yml` (main-push + workflow_dispatch, gated on successful image publish): SSH → `docker compose pull && up -d` in `/home/dev/matrix-staging`
- [ ] One verified run end-to-end (H6 check)

### T6: E2E smoke + evidence (Sonnet)
**Hypotheses:** H3, H4 (confirm)
- [ ] Headless `siwx-oidc-auth` auth-code flow against `https://dev.siwx.inblock.io` (did:key) + Matrix `whoami`
- [ ] curl checks: discovery, well-known, element index, introspection reachable
- [ ] Evidence file for audit

### T7: Audit (orchestrator)
Hypothesis trace + acceptance criteria per process-pipeline; remediation loop if needed.

**Dependencies:** T2 → T3 → T4 → T6; T5 starts after T2, its live verification after T4.

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|----------|------------|
| AC1 | All 5 pre-existing vhosts serve over HTTPS with valid LE certs via Caddy | H1, H2 |
| AC2 | The 3 dev domains serve their services with valid TLS | H3, H4 |
| AC3 | End-to-end login: headless client (and Element Web manually) gets tokens from dev.siwx and a valid Synapse session on dev.matrix | H3, H4 |
| AC4 | A push to main (or dispatch) auto-deploys to the box, verified by digest change | H6 |
| AC5 | Caddy-everywhere directive recorded globally | — |
| AC6 | Rollback path documented and available (old proxy containers intact ≥24 h) | H2 |

## Boundary conditions

- **Never** touch prod (142.93.168.4) or the bare aquafire box (46.101.241.226).
- The 5 live vhosts may be down only during the cutover window (<~60 s target); rollback stays one command away until burn-in passes.
- Secrets are generated on the box, never committed, never pasted into chat/CI logs.
- `dev.matrix.inblock.io` as server_name is permanent for this instance — accepted.
- Do NOT rely on watchtower; CD is explicit SSH deploy.
- Testing build-out (qrphone, Android tier, e2e-in-CI) = separate follow-up pipeline.
- Memory governance: if a subagent spawn is denied, run inline sequentially — never bypass.

## Risks (top 3)

1. **Cutover breaks a live aquafier service** (hidden nginx behavior, wrong upstream port) → mitigations: exact conf dump first, Opus on this task, instant rollback, 24 h burn-in with old containers stopped-not-removed.
2. **CPU contention** (2 vCPU, ~15 containers after deploy) → accept for staging; resize droplet before perf testing.
3. **GH runners can't reach port 8022** → contingency: self-hosted runner or Tailscale on the box.
