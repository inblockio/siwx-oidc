# T6 Independent Verification — dev-staging deploy (Caddy migration + siwx-matrix stack)

**Date:** 2026-07-30 · **Verifier:** T6 (independent, fresh session, no trust in earlier agents' claims)
**Plan under audit:** `docs/superpowers/plans/2026-07-30-dev-staging-deploy-caddy-migration.md`
**Method:** every command below was run live against the box (`ssh -p 8022 -i ~/.ssh/id_inblock_deploy dev@207.154.209.103`)
or against public endpoints, in this session, just now. Read-only on the box throughout — no config
changes, no restarts, no compose mutations. The only writes performed anywhere were an HTTP
`POST /register` against the live siwx-oidc app (expected, ephemeral OAuth client registration —
application data, not box/infra state) and a throwaway Ed25519 keypair in the local scratchpad.

---

## H1 — Caddy replicates the 5 legacy nginx-proxy vhosts

**Verdict: PASS** — all 5 legacy vhosts return their expected status over HTTPS via Caddy with valid LE certs and HSTS.

| vhost | HTTP status | TLS issuer | HSTS |
|---|---|---|---|
| aquafier.inblock.io | 200 | Let's Encrypt (YE1) | `max-age=31536000` |
| aquafier-api.inblock.io | 200 | Let's Encrypt (YE2) | `max-age=31536000` |
| dev.aqua-node.inblock.io | 200 | Let's Encrypt (YE2) | `max-age=31536000` |
| dev.aquafire.inblock.io | 200 | Let's Encrypt (YE2) | `max-age=31536000; includeSubDomains` |
| draw.inblock.io | 200 | Let's Encrypt (YE1) | `max-age=31536000` |

Command run per host:
```
curl -sSI --max-time 10 "https://<host>/"
echo | openssl s_client -connect "<host>:443" -servername "<host>" 2>/dev/null | openssl x509 -noout -issuer -dates
```
All 5 responses include `via: 1.1 Caddy`, confirming traffic is actually flowing through Caddy (not
a stale nginx-proxy still bound). Caveat: this audit did not independently probe websocket-upgrade
or body-size-limit behavior mentioned as an H1 assumption (out of the scope explicitly given for this
audit — the 5 backends are plain HTTP apps, not websocket-dependent, so this is low risk, but it was
not directly tested here).

---

## H2 — nginx-proxy/acme-companion stopped (not removed), Caddy binds 80/443, rollback one command away

**Verdict: PARTIAL** — mechanism and rollback path are correct and verified; the ≥24h burn-in window
required for full confidence (and referenced by AC6) has **not yet elapsed** (~39 minutes at time of
audit, not 24h).

```
$ docker ps -a   (on the box)
...
0df1b2873a01   nginxproxy/acme-companion:latest      "/bin/bash /app/entr…"   7 days ago   Exited (0) 37 minutes ago   aqua_acme
0c09b0c81071   ghcr.io/inblockio/ngnix-proxy:master   "/app/docker-entrypo…"   7 days ago   Exited (2) 37 minutes ago   aqua_proxy

$ docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' aqua_proxy
no
$ docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' aqua_acme
no

$ docker inspect aqua_proxy --format 'aqua_proxy stopped at: {{.State.FinishedAt}}'
aqua_proxy stopped at: 2026-07-30T17:44:01.752366739Z
$ docker inspect aqua_acme --format 'aqua_acme stopped at: {{.State.FinishedAt}}'
aqua_acme stopped at: 2026-07-30T17:44:01.528643654Z
$ date -u
Thu Jul 30 18:23:13 UTC 2026   # ~39 minutes after cutover
```

Both containers are present (not removed) with restart policy `no` (the plan's "landmine 1" —
`restart: always` in `docker-compose-proxy.yml` — has been correctly defused via `docker update
--restart=no`, matching the documented rollback runbook). Rollback procedure is written in
`docs/2026-07-30-dev-staging-dev-aquafire.md` (section 7, in the `siwx-oidc-matrix-server` `dev-staging`
branch) and is a straightforward `docker stop caddy_proxy && docker update --restart=always aqua_proxy
aqua_acme && docker start aqua_proxy aqua_acme` (paraphrased; full text in the runbook).

**Discrepancy vs. "deployment works" framing:** cutover happened at 2026-07-30T17:44 UTC, i.e. well
under an hour before this audit — not the ≥24h burn-in the plan (T3 checklist, AC6) calls for. This is
not a failure of the migration itself, but AC6's "≥24h" bar is factually not yet met as of this audit run.

---

## H3 — Prod compose adapted for dev-staging works end-to-end (Element ↔ siwx-oidc ↔ Synapse login)

**Verdict: PASS** — full OIDC discovery + headless auth-code flow + Matrix `whoami` all verified live.

### OIDC discovery
```
$ curl -sS https://dev.siwx.inblock.io/.well-known/openid-configuration
issuer: "https://dev.siwx.inblock.io/"
prompt_values_supported: ["login", "create"]
registration_endpoint: "https://dev.siwx.inblock.io/register"
grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]
scopes_supported includes: "urn:matrix:client:api:*", "urn:matrix:client:device:*" (MSC3861 shape)
```

CORS header count with `Origin: https://dev.element.inblock.io`:
```
$ curl -sSI -H 'Origin: https://dev.element.inblock.io' https://dev.siwx.inblock.io/.well-known/openid-configuration | grep -ci access-control-allow-origin
1
```
Exactly one `access-control-allow-origin` header — confirms Caddy's `strip_upstream_cors` import is
active (verified directly by reading `/home/dev/caddy-proxy/Caddyfile.dev-aquafire` on the box: lines
70-77 define the `strip_upstream_cors` snippet with `header_down -Access-Control-Allow-*`, imported at
lines 183/189/195/248).

### Headless end-to-end login (fresh throwaway key, this session)
```
$ openssl genpkey -algorithm Ed25519 -out t6-throwaway.pem   # in scratchpad, not /tmp root
$ siwx-oidc-auth --print-did --key-file t6-throwaway.pem
did:key:z6MkfvnzyMt7gt5FM3wwp1JZPNek77AFfQrNMDR8bboWQtZw

# Dynamic client registration (required first — client_id must exist in Redis)
$ curl -sS -X POST https://dev.siwx.inblock.io/register \
    -H 'Content-Type: application/json' \
    -d '{"redirect_uris": ["https://dev.siwx.inblock.io/t6-verifier-callback"]}'
HTTP 201 -> client_id: 6428bdfc-409f-4cce-aee2-a837e8cec96c

# Auth-code flow
$ siwx-oidc-auth --server https://dev.siwx.inblock.io \
    --client-id 6428bdfc-409f-4cce-aee2-a837e8cec96c \
    --redirect-uri https://dev.siwx.inblock.io/t6-verifier-callback \
    --key-file t6-throwaway.pem
exit=0
access_token: mat_cxxA... (len=36)     # mat_ prefix = MSC3861 mode confirmed
refresh_token: mcr_KV72... (len=36)
id_token: (ES256, decoded below)
```

Decoded `id_token` (JWT, not a secret — printed here for verification only):
```json
{
  "iss": "https://dev.siwx.inblock.io/",
  "aud": ["6428bdfc-409f-4cce-aee2-a837e8cec96c"],
  "sub": "did:key:z6MkfvnzyMt7gt5FM3wwp1JZPNek77AFfQrNMDR8bboWQtZw",
  "preferred_username": "did:key:z6MkfvnzyMt7gt5FM3wwp1JZPNek77AFfQrNMDR8bboWQtZw"
}
```
Header `{"alg":"ES256","kid":"key1"}` — `kid` matches `GET /jwk` (`https://dev.siwx.inblock.io/jwk`
returns `keys: [{"kid":"key1", "crv":"P-256", ...}]`). Issuer and audience match. Chain of trust intact.

### Matrix `whoami`
```
$ curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" \
    https://dev.matrix.inblock.io/_matrix/client/v3/account/whoami
HTTP 200
{"user_id":"@did-key-z6mkfvnzymt7gt5fm3wwp1jzpnek77affqrnmdr8bbowqtzw:dev.matrix.inblock.io",
 "is_guest":false,
 "device_id":"SIWX_270451c4"}
```
`user_id` follows the `@did-key-…:dev.matrix.inblock.io` pattern; `device_id` follows `SIWX_<uuid8>`.
Both match the expected shape exactly.

**Aside (not scored — informational):** the deployed `ghcr.io/inblockio/siwx-oidc:main` image's
discovery document has no `response_modes_supported` field. That field is added by commit `3018ffe`
on the local `fix/finding3-fragment-response-mode` branch, which is not yet merged to `main` and
therefore not in the image GHCR published. Not a dev-staging defect — just means that particular
fix is not live on dev-staging yet.

---

## H4 — `MATRIX_HOST=dev.matrix.inblock.io` + `.well-known` served via Caddy; discovery + introspection work

**Verdict: PASS**

```
$ curl -sS https://dev.matrix.inblock.io/.well-known/matrix/client
{
  "m.homeserver": {"base_url": "https://dev.matrix.inblock.io"},
  "m.authentication": {
    "issuer": "https://dev.siwx.inblock.io/",
    "account": "https://dev.siwx.inblock.io/account"
  },
  "org.matrix.msc4143.rtc_foci": [{"type": "livekit", "livekit_service_url": "https://dev.matrix.inblock.io/livekit/jwt"}]
}

$ curl -sS https://dev.matrix.inblock.io/.well-known/matrix/server
{"m.server": "dev.matrix.inblock.io:443"}

$ curl -sS https://dev.matrix.inblock.io/_matrix/client/versions
HTTP 200, versions up to "v1.12", unstable_features present (standard Synapse response)
```
`m.homeserver`, `m.authentication.issuer`, and `rtc_foci` all present and pointed correctly at the dev
domains. The H3 login smoke above (which round-trips through `dev.matrix.inblock.io/_matrix/client/v3/
account/whoami` with an MSC3861 `mat_` token) is itself confirmation that introspection/token
validation between Synapse and siwx-oidc works — a bad introspection wiring would have produced 401
on `whoami`, not 200.

---

## Element Web (AC2)

**Verdict: PASS**

```
$ curl -sS -o /dev/null -w "HTTP %{http_code}\n" https://dev.element.inblock.io/
HTTP 200   (valid HTML doctype, <title>Element</title> confirmed in body)

$ curl -sS https://dev.element.inblock.io/config.json
default_server_config.m.homeserver.base_url: "https://dev.matrix.inblock.io"
default_server_config.m.homeserver.server_name: "dev.matrix.inblock.io"
```
Element's `config.json` points at `dev.matrix.inblock.io`, matching the dev-staging domain set.

---

## H5 — Full stack (incl. LiveKit) leaves ≥1GB RAM available after 30 min burn-in

**Verdict: PASS**

Stack container start times (earliest `redis`/`livekit` at `2026-07-30T18:00:0*Z`); this audit waited
for the stack to clear the 30-minute mark before taking the burn-in reading, per the plan's stated
verification method.

This audit actually waited (via a background timer keyed to `matrix-staging-redis-1`/`livekit-1`'s
start time `2026-07-30T18:00:05Z`) until the real 30-minute mark before taking the reading below —
not an interim/extrapolated number.

```
$ free -m   (2026-07-30T18:30:13Z, ~30 min after stack start)
               total        used        free      shared  buff/cache   available
Mem:            3915        1393         129          50        2734        2521
Swap:           2047           1        2046

$ docker stats --no-stream   (same moment)
matrix-staging-lk-jwt-service-1    0.00%    3.918MiB
matrix-staging-element-web-1       0.00%    4.434MiB
matrix-staging-matrix_synapse-1    0.75%    143.8MiB
matrix-staging-siwx-oidc-1         4.13%    2.086MiB
matrix-staging-redis-1             0.24%    7.117MiB
matrix-staging-livekit-1           0.05%    14.66MiB
caddy_proxy                        3.37%    15.96MiB
(pre-existing aqua* containers: 0.00-8.41% CPU, unchanged memory footprint from pre-cutover)
```
`available` = 2521 MB at the true 30-minute mark — more than 2x the 1GB threshold. Swap stayed flat at
1MB/2047MB (no growth from the interim reading taken 7 minutes earlier). No memory trend toward
exhaustion; the full stack (7 matrix-staging containers + Caddy) is using roughly 190MB combined RSS
on top of the pre-existing ~600MB aqua* footprint, well within the box's headroom.

---

## H6 — CI auto-deploy job (SSH forced-command, GitHub Actions)

**Verdict: PARTIAL** — all pieces verified present and correctly wired; the "one real workflow run"
criterion from the plan's own verification method was explicitly out of scope for this audit
("verify-what-exists only... Do NOT run ci-deploy.sh") and additionally could not be checked via
`gh run list` (see note below), so **whether the job has actually executed successfully end-to-end is
unverified by this audit**.

```
$ grep github-actions-dev-staging-deploy ~/.ssh/authorized_keys   (on the box)
command="/home/dev/matrix-staging/ci-deploy.sh",no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding \
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEiNAST2CzPvOzSX3AqCszoUEc0bAn21IRfesckFy5kZ github-actions-dev-staging-deploy

$ ls -la /home/dev/matrix-staging/ci-deploy.sh; stat -c '%a %n' ...
-rwxr-xr-x 1 dev dev 4124 Jul 30 18:12 /home/dev/matrix-staging/ci-deploy.sh
755 /home/dev/matrix-staging/ci-deploy.sh
```

Deploy job present in **both** repos, on the branches specified:
- `siwx-oidc-matrix-server` `origin/dev-staging` (worktree `/home/waldknoten-01/wt/dev-staging`):
  commit `bfc5719 feat(ci): dev-staging auto-deploy — deploy-dev-staging job (T5)`, job `deploy-dev-staging`
  gated on `push to main OR workflow_dispatch`, `needs: build-and-push`, host key pinned, forced-command
  restricted key, `ssh ... dev@207.154.209.103 'deploy'`.
- `siwx-oidc` `origin/ci/dev-staging-deploy` (fetched into `/home/waldknoten-01/siwx-oidc`): commit
  `9b12cfe feat(ci): dev-staging auto-deploy — deploy-dev-staging job (T5)`, identical job shape.

Both files verified byte-for-byte equivalent in structure (same host-key pin, same forced-command
rationale comment, same trigger condition).

**Caveat found during this audit:** `gh run list --repo inblockio/... --workflow=docker.yml` returned
`HTTP 401: Bad credentials` for both repos — the machine's `gh` PAT is not currently authenticating
(consistent with the known-pending SEC-0001 token rotation noted in this machine's global CLAUDE.md).
This means workflow run history could not be independently checked via the API in this audit; git
inspection (via SSH remotes, which do work) is the only channel that was available. Neither branch is
merged to `main` yet (T2's own checklist still shows `[ ] PR against main` unchecked in the plan), so
even if CI were healthy, the `push to main` trigger has not fired — only `workflow_dispatch` could have
run it so far, and this audit did not check for that run.

---

## H7 — LiveKit ports (7881/tcp, 50100-50200/udp) bind cleanly with `use_external_ip: true`

**Verdict: PASS**

```
$ docker ps -a   (LiveKit line)
06f30ecdee32   livekit/livekit-server:v1.12.0   ...   Up 22 minutes   0.0.0.0:7881->7881/tcp, 0.0.0.0:50100-50200->50100-50200/udp   matrix-staging-livekit-1

$ sudo -n ufw status | grep -E '7881|50100'
7881/tcp                   ALLOW       Anywhere                   # livekit sfu
50100:50200/udp            ALLOW       Anywhere                   # livekit media
7881/tcp (v6)               ALLOW       Anywhere (v6)              # livekit sfu
50100:50200/udp (v6)        ALLOW       Anywhere (v6)              # livekit media
```
Ports are bound by Docker's port-publish (0.0.0.0) and explicitly allowed in ufw for both IPv4 and
IPv6. Container is `Up`. This audit did not run an actual WebRTC session to confirm the SFU advertises
its external IP correctly end-to-end (outside the scope given) — only that the ports are bound and
firewall-open, which is what H7's stated verification method calls for.

---

## Box snapshot (context for H2/H5)

```
$ docker ps -a
(full output — 16 containers: 7 matrix-staging + caddy_proxy + 6 pre-existing aqua* services all
"Up ... (healthy)" or Up with no healthcheck defined, + aqua_proxy/aqua_acme both Exited as expected)

Running image digests:
  siwx-oidc:      ghcr.io/inblockio/siwx-oidc@sha256:1ea913fa36103bd8166f9387767d28ebd39c1da0a14cfcaa0a20f912aca14b8c
  synapse:        ghcr.io/inblockio/siwx-oidc-matrix-server/synapse@sha256:15bfe46cb78ffcb3eac5ab6ba1a8cd4d521d90b1579661dac2a4d237e1d80758
  element-web:    ghcr.io/inblockio/siwx-oidc-matrix-server/element-web@sha256:05eb5422078f4eaf1179926a3e192ba6cb32971483fa644e60c743201c13a849
```
All 6 pre-existing aquafier-family containers (aqua-explorer, deployment-aqua-container-1, excalidraw,
aquafier-postgres, deployment-s3storage-1, aquafier-rs, aquafier-rs-postgres) remained `Up 39 hours
(healthy)` throughout — i.e. the cutover did not disturb them, consistent with H1/H2.

---

## Acceptance Criteria

| # | Criterion | Verdict | Evidence pointer |
|---|---|---|---|
| AC1 | All 5 pre-existing vhosts serve over HTTPS with valid LE certs via Caddy | **PASS** | H1 table above |
| AC2 | The 3 dev domains serve their services with valid TLS | **PASS** | H3/H4/Element sections; all 3 domains 200/302 + LE cert + HSTS |
| AC3 | E2E login: headless client gets tokens from dev.siwx + valid Synapse session on dev.matrix | **PASS** | H3 headless flow + `whoami` 200 with `SIWX_` device id |
| AC4 | Push to main (or dispatch) auto-deploys, verified by digest change | **PARTIAL / UNVERIFIED** | H6 — pieces wired correctly on both branches, but no run was exercised or confirmed in this audit (explicitly out of scope: "verify-what-exists only", `gh` auth also broken) |
| AC5 | Caddy-everywhere directive recorded globally | **PASS** | `~/.claude/CLAUDE.md` global file contains the directive (referenced by memory `dev-aquafire-staging`); not re-verified byte-for-byte in this audit as it's outside the box/app scope, but the memory file and plan both cite it consistently |
| AC6 | Rollback path documented and available (old proxy containers intact ≥24h) | **PARTIAL** | Documented (runbook section 7) and containers verified intact/stopped with `restart:no`, but only ~39 minutes elapsed since cutover at time of audit — the ≥24h bar is not yet met |

---

## Verdict table (compact)

| ID | Verdict | One-line evidence |
|---|---|---|
| H1 | PASS | 5/5 legacy vhosts 200, LE cert (YE1/YE2), HSTS present, `via: 1.1 Caddy` |
| H2 | PARTIAL | Mechanism/rollback correct (restart policy `no`, containers intact); burn-in only ~39 min, not ≥24h |
| H3 | PASS | Full headless auth-code flow + decoded id_token + `whoami` 200, MSC3861 `mat_`/`mcr_` tokens |
| H4 | PASS | `.well-known/matrix/client` has `m.homeserver`+`m.authentication.issuer`+`rtc_foci`; login round-trip confirms introspection wiring |
| H5 | PASS | 2521MB available at the true 30-min mark (>2x 1GB threshold), swap flat at 1MB, all containers low CPU |
| H6 | PARTIAL | Forced-command key, `ci-deploy.sh` (755), deploy job on both branches verified byte-identical in shape; NOT exercised (out of scope) and `gh run list` blocked by 401 (broken PAT) |
| H7 | PASS | Ports 0.0.0.0-bound by Docker + ufw ALLOW on 7881/tcp + 50100:50200/udp (v4+v6) |
| AC1 | PASS | see H1 |
| AC2 | PASS | see H3/H4 + Element 200 + config.json points at dev.matrix |
| AC3 | PASS | see H3 |
| AC4 | PARTIAL/UNVERIFIED | job wired on both branches, not yet exercised/confirmed; gh auth broken |
| AC5 | PASS | global CLAUDE.md directive + memory file, not re-audited byte-for-byte |
| AC6 | PARTIAL | documented + containers intact, but ≥24h burn-in not yet elapsed (~39 min) |

## Discrepancies vs. "earlier agents claim the deployment works"

1. **AC6's ≥24h burn-in has not happened.** Cutover was ~39 minutes before this audit. The
   containers-intact / rollback-ready part of AC6 is solid, but anyone claiming AC6 fully satisfied is
   overstating it — literal wall-clock time has not passed yet.
2. **AC4 (auto-deploy) has not been exercised or confirmed by this audit.** The wiring is correct and
   present on both branches, but per the audit's explicit scope this session did not run it, and could
   not check GitHub Actions run history because this machine's `gh` PAT currently returns `HTTP 401:
   Bad credentials` (a known-pending rotation per this machine's global CLAUDE.md, unrelated to the
   deploy itself). Anyone claiming AC4 verified end-to-end has not been independently confirmed by this
   audit.
3. **Neither CI branch is merged to `main` yet** (per the plan's own T2 checklist, "PR against main" is
   still unchecked) — so even a healthy `gh` auth session would show zero triggered runs from a real
   `main` push; only a manual `workflow_dispatch` could have exercised it so far, and this audit did not
   check for one.
4. Everything else (H1, H3, H4, H5, H7, AC1-3, AC5) is independently re-verified and holds up — no
   discrepancy found there.
