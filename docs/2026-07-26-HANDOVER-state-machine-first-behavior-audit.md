# HANDOVER — start from the state machine, audit the user behaviour it implies

**Date:** 2026-07-26 (second handover of the day; supersedes the operational state in
`2026-07-26-HANDOVER-session-durability-iteration-loop.md`, whose **method** sections §1–§2 remain
the authority and should still be read)
**Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`)
**Companion:** `siwx-oidc-matrix-server` `main` @ `cd17c90`

---

## 0. Start here, in this order

1. **`docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md` — §M4c first.**
   It is new (2026-07-26) and it is the reason the previous session lost hours.
2. `docs/audits/2026-07-25-state-machine-coverage-matrix.md` — **§5.9** (M4c coverage) and **§6.3**
   (register addendum U10, and the status correction closing U6).
3. `docs/audits/2026-07-26-state-machine-reconciliation-ceremony-terminals.md` — why the gap
   existed and what it cost.
4. `docs/audits/2026-07-25-verify-gate-root-cause-SETTLED.md` — **read both UPDATE sections.** The
   document marks its own §3 wrong, then a second update marks a further claim wrong. The
   corrections are the useful part.
5. Method only: previous handover §1 (the eight lessons) and §2 (the loop).

---

## 1. The governing idea for the next session

**The product goals are the user-visible projection of the state machine. Audit them in that
direction.** Do not start from a bug list and work backwards; start from the map, enumerate the
terminals a real user can reach, and ask of each: *is it named, is it reachable, does the user have
an action, and is there a test watching it?*

The previous session proved why this matters. Two client states —

| | success | wedge |
|---|---|---|
| phase | `3 (Done)` | `2 (Busy)` |
| buttons | `["Done"]` | **zero** |
| crypto | healthy | healthy |
| user | clicks Done, reaches app | **trapped; only a reload escapes** |

— were **indistinguishable at the level the tests asserted at** ("the app shell never renders"),
because neither had a name. That ambiguity produced two wrong diagnoses, one withdrawn P0, and a
"defect" that turned out to be a missing click in the harness. Naming them (M4c) is what made the
discriminator obvious: **phase + button count.**

**Invariant I-C1, now in the map:** *no terminal may present zero user-actionable controls while
the underlying crypto is healthy.* That is a product requirement expressed as a state-machine
property, and it is checkable. Look for more of that shape.

---

## 2. Requirement state (all evidence-backed, commands in §5)

| | Requirement | Status | Evidence |
|---|---|---|---|
| R1 | Restart → nobody notices | **CONFIRMED** | T5 leg, two runs (`904dccb`) |
| R2 | Refresh race survives | grace on `main`, **UNDEPLOYED** | F12 |
| R3 | Redis blip survives | landed (`dd34e3f`); premise refuted, real defect fixed | — |
| R4 | Add a device, verify from a live one | **PROVEN** | `EW-V1` incl. assertion 8 |
| R5/R6 | Phrase required **and** enterable | **SATISFIED** | `ew-recovery-entry` 4 passed |

Labs are now durable by construction (T6): both `siwx-e2e-redis` and `siwx-real-redis` have named
volumes + AOF, and `up.sh` gates on Redis actually answering rather than on siwx-oidc's `/health`.

**Nothing is deployed.** Decision 2 holds: prod release only after the final audit.

---

## 3. What the next session should actually do

### 3.1 The audit pass (primary)

Walk M0–M5 **plus M4c** and produce, per machine, the four-column answer above. Concretely, the
known-thin places:

- **`C_Working` is uncovered.** Nothing asserts the difference between a healthy transient `Busy`
  (≥1 button) and `T_C_Wedged` (zero buttons). The whole invariant rests on that distinction and no
  test states it directly. **Write the assertion that names it.**
- **M4's private half is still not total** (finding T-M4). `S4_*` and `Backup_*` are declared states
  with **no transition table, no events, no terminals**. There is no defined answer for
  `4S_key_rotated_while_master_stale`, `backup_deleted_with_XS_present`, or
  `recovery_key_lost_with_no_second_device` — all user-reachable. Six of the sixteen uncovered
  states live here.
- **U3′ remains the worst undefined state** and is untouched: `forceReset` on a cold-cache probe
  silently orphans an existing 4S key and the message-key backup. It does not block or lie — it
  *succeeds* while destroying history. Everything else costs a session; this costs the user their
  messages. `cb75cce` addressed the destructive branch; confirm that closes U3′, or say why not.
- **U5 / `Q0` `T_OfferWithheld`**: "Not supported by your account provider" is a **false**
  explanation — the OP supports it; the user's own crypto state is the cause. A truthful
  disabled-reason is a small change with real user impact.
- **U7**: an unverified current device is offered no way to initiate verification. U5+U6+U7 compose
  into "reset is the only visible exit", which is the destructive one.

### 3.2 The structural gap behind all of it

**`e2e/element` does not run in CI** (C-0, only narrowed by `d0219b3`, which covers `e2e/browser`).
Every M4/M4c/M5 verdict in the matrix means "a test exists that genuinely asserts this", **not**
"this is guarded". A change can break every cross-signing terminal and CI stays green. Closing this
needs a cross-repo harness (real Synapse + Element + Caddy). Until then, treat green as
un-regressed-by-default.

---

## 4. Gated on the owner — do not run unprompted

- **H-D5** baseline is self-contradictory: ~548 `invalid_grant`/72h (map §1.4) vs ~7/4d
  back-solved from the same source. Needs a **prod log read**. The hypothesis cannot be evaluated
  until reconciled.
- **T7 / H-D6**: whether prod's stored tokens already carry the current `TokenMetadata` shape
  (`did`, `name`). If that read FAILS, the dual-read migration becomes mandatory and the
  "flush is stale" decision re-opens.
- **Whether the RUNNING prod container matches `docker-compose.yml`.** The repo config is durable
  (named `redis_data`, F9); the running state is unverified. T6 fixed the *labs*, not prod.
- **Deployment** of R2's grace + everything on this branch.

---

## 5. Commands

```bash
# Lab — ALWAYS with --env-file (omitting it resolves SIWEOIDC_SIGNING_KEY_PEM empty -> panic)
cd ~/siwx-oidc-matrix-server
docker-compose -f docker-compose.local.yml --env-file .env.local up -d

# Suites
cd ~/wt/siwx-durability
bash e2e/element/run.sh ew-recovery-entry        # R5/R6 — 4 passed
bash e2e/element/run.sh ew-verify-sas            # R4 + assertion 8 (the T_C_Wedged watcher)
bash e2e/element/t5-restart-survival.sh          # R1 / H-D1, restarts the whole stack
bash e2e/browser/run.sh                          # 26 tests, ~13s
bash e2e/up.sh                                   # mock stack; now durable + Redis-gated
bash e2e/down.sh            # keeps the data volume;  --purge wipes it

# Guards
python3 scripts/check-patch-hunks.py             # in siwx-oidc-matrix-server
~/bin/resource-guard.sh verdict                  # before any subagent fan-out
```

**Verify what is actually running before drawing conclusions from it.** Grep the built asset, do
not reason from image timestamps — that inference was made this session and was wrong:

```bash
podman exec siwx-oidc-matrix-server-element-web-1 \
  sh -c "grep -rl 'cross-signing not ready 10s after verification' /usr/share/nginx/html"
```

---

## 6. Traps this session actually hit (each cost real time)

- **A harness gap presents exactly like a product defect — this has now happened three times.**
  Before writing up a dramatic user-facing failure, reproduce the same scenario by a different path.
- **Playwright clears `outputDir` at the start of every run.** State shared between two invocations
  must not live under `test-results/`, or phase 2 reads a file phase 1's successor just deleted.
- **`date +%s%3N` is broken here.** This box has uutils coreutils 0.8.0, which ignores the `%3N`
  width modifier and appends full nanoseconds — it printed `1176248s` for a 10s restart.
- **`scope` is absent from the token JSON** on `authorization_code` and `refresh_token` grants;
  only `token_device_code` calls `set_scopes`. Derive `device_id` from `whoami`, not from `scope`.
- **An anonymous volume under `--appendonly yes` is worse than no AOF.** `inspect` and the command
  line both look durable while any recreate silently comes back empty. The redis image's own
  `VOLUME /data` mints one whenever no named volume is given — with or without a `-v` flag.
- **A readiness gate that has never failed is unproven.** The T6 gate was verified by sabotaging
  only the Redis image in a copy of the real script and confirming exit 1 *before* siwx-oidc started.

---

## 7. Commits on this branch (this session)

| Commit | What |
|---|---|
| `54e40d4` | `EW-R1-2` was a harness gap, not the R5/R6 trap — measured, then fixed |
| `f8525a2` | Named the ceremony-view terminals; refuted the "same bug" claim |
| `904dccb` | **T5** restart-survival leg — H-D1 confirmed, twice |
| `f2b3b32` | **T6** `up.sh` durable + Redis readiness gate (both paths verified) |
| `2fb286e` | **T6** `siwx-real-redis` named volume; `up` now owns it |
| *(this)* | M4c merged into the map + matrix; this handover |

**Do not delete `EW-V1` assertion 8 or `EW-R1-2` to get a green suite.** They are the only watchers
on `T_C_Wedged` (U10).
