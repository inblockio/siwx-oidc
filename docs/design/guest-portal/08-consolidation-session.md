# Guest portal 08: consolidation session (preparation)

**Status:** DRAFT preparation. **The session has not been held and nothing in this document is decided.** This file prepares an interactive design session with the product owner; it adds no requirement, changes no `GP-` row of 01 to 07, and starts no spike, milestone or code.
**Scope:** how the three tracks of material in this pull request are brought into one final plan: what each track is, the worksheet that lines the 28 reference features up against the design set, the collisions between the tracks, the agenda, what the session produces, and what stays untouched until it is over. It is the step after [07](07-implementation-plan.md) and the first thing to read after [00](00-overview.md) once the set has been reviewed.
**Inputs, frozen for the session:** the design set 00 to 07 and its [gallery](wireframes/index.html) at the head of this branch when the session opens; the [case study](reference/waiting-room-case-study.md) (28 features `RF-01` to `RF-28`) at the revision named in its header; the [reference wireframes](reference/waiting-room-wireframes/) at the hashes in [reference/README.md](reference/README.md); the [Track C evaluation](reference/meedio-connect.md) at the head of this branch. Nothing is edited between the freeze and the session, so every statement below can be checked against a fixed text.
**Conventions:** `RF-nn` is feature Fn of the case study, `W1` to `W7` are its screens (not the steps W1 to W5 of [01 section 4](01-flow-model.md)), `CS-nn` is a slot for a decision the session takes. Status words in section 3 describe what the design set says today and are not dispositions.

## 1. The three tracks

| | Track A: the design set (00 to 07 and 09, gallery) | Track B: reference material (case study, requirements list, W1 to W7) | Track C: the meedio-connect evaluation |
|---|---|---|---|
| Question it answers | How can an anonymous visitor join a Matrix video call by link on a Synapse homeserver with delegated authentication, safely, and keep the account if they want to | What does a best-of-breed waiting room and guest handling contain, according to seven meeting apps | What has a vendor actually shipped on Matrix for a waiting room and guests, and can that client be the guest client |
| Subject | A confined, ephemeral account minted by the identity provider, a policy module, a thin client, a passkey claim | A meeting product with organisations, admin settings, hosts, co-hosts, plans and a lobby | An AGPL client snapshot (2025) on MatrixRTC and LiveKit with a knock waiting room and its own vendor backend |
| Strength | Validated against code and upstream sources; every rule has an identifier, a test and a milestone | A broad feature inventory with a priority for each feature and a named best example | Real code read at a pinned commit; Matrix-native, so its patterns map onto the same primitives (knock, invite, kick) |
| Weakness | The host side is upstream Element Web: one knock at a time, no alert, no labels beyond "(Guest)" | Unverified; assumes organisation accounts, a mailer, host-authored text and a host lobby that the design set does not have | Not a base (D22): no media E2EE, guests by `/register` on a second homeserver, js-sdk 37, a vendor backend |
| Form | 9 documents and a clickable gallery | 1 document with a 28-feature list, a 7-screen canvas | 1 evaluation document |
| Status | Draft, awaiting maintainer review | Reference, unchecked | Reference, each claim with a status |

The tracks overlap on one journey (guest arrives, asks to join, host admits, call) and differ in scope everywhere else. Track C is the only one that runs on Matrix: where Track B says what a waiting room should contain, Track C shows how one vendor built it from knock, invite and kick. The session does not pick a winner. It decides which parts of Tracks B and C enter the final plan, in what form, and what that does to Track A.

**Requirements added before the session.** R10 (Element X parity for registered users) and R11 (e-mail registration with custodial keys and a migration path to an HSM) were set by the product owner on 2026-10-02 and live in [09](09-registered-users.md). They are inputs, not candidates: the session applies them where they meet the guest tracks (CS-10) and does not reopen them.

## 2. What the session produces

A **final plan**, as edits to this set and one register, with nothing left implicit:

1. **A scope statement** of one paragraph (CS-01), so that every later row can be tested against it.
2. **A disposition for each of RF-01 to RF-28:** v1, later, replaced by an existing design rule, or out. Each with a reason in one line.
3. **One decision per collision** of section 4 (CS-02 to CS-10), recorded in the table of section 6 with the consequence for 00 to 07.
4. **One reconciled screen inventory:** the screens of 06 and W1 to W7 merged into a single list, with one visual language (CS-08).
5. **The still-open decisions of the design set that the feature pass touches** (the D-numbers of [00 section 7](00-overview.md#7-decisions-log)); the others are scheduled, not forced.
6. **The first gate:** which spike runs first and who starts it. The recommendation in 07 section 3 is SP-2.
7. **The edit list** for 00 to 07 and for the traceability matrix, with an owner for each file.

The session is done when items 1 to 7 exist in writing. A decision that is not taken stays open with an owner and a date, and the plan says so.

## 3. Worksheet: the 28 features against the design set

Read from the design set at the frozen head. **Status:** Covered (the design does it), Partial (part of it, or a different form), Excluded (a non-goal of 04 section 6.1 rules it out today), Conflicts (a rule of the set says otherwise), Not in set (nothing found by search and by reading the owning sections). The right-hand column is empty on purpose: the disposition is the session's work.

| RF | Feature | Pri | Screen | The design set today | Status | Disposition |
|---|---|---|---|---|---|---|
| RF-01 | Bypass rules: everyone, org, trusted orgs, invitees, hosts only | Must | W7 | Every guest knocks; there is no bypass. Invites are per guest and single use by default (D6), which is the "invitees only" case. `skipLobby` is never a way past the knock (D14, 03 GP-CLI-14) | Partial | |
| RF-02 | Separate switch for phone dial-in callers | Must | W7 | No dial-in or phone path anywhere in the set | Not in set | |
| RF-03 | Admin-enforced, lockable defaults; one protection mandatory | Must | W7 | Operator configuration that fails closed: deny-by-default host allow-list (D5, 01 GP-FLOW-10), encryption and `knock` required at mint (GP-FLOW-28), startup refusals (04 GP-SEC-51). No per-organisation admin page | Partial | |
| RF-04 | Trust label on every waiting guest: Internal, External, Verified, Unverified | Must | W5 | One label, the operator suffix " (Guest)" seeded by the identity provider and kept by the module (04 GP-SEC-19, 06 GP-UX-02), shown in the upstream knock bar (06 H5). Federation is off for a guest deployment (P3), so no account of another organisation is in the room. Verifying a guest is NG-01 | Partial | |
| RF-05 | Admit or deny one, several, or all | Must | W5 | One at a time: the host's own client lists each knock with Approve and Deny (06 H5, upstream, not designed here). No select-all, no admit-all | Partial | |
| RF-06 | Send a participant back to the waiting room | Must | W6 | Nothing. The nearest Matrix action is a kick, and a kick counts against the guest's re-knock cap (GP-FLOW-33, 02 GP-SYN-21) | Not in set | |
| RF-07 | Co-hosts can admit; only admitters see the lobby | Must | W5 | Admission is a power level (invite 50 or 100, kick and ban 50 or more, 01 section 4.3). Whoever holds the power sees the knock bar. No co-host role in the guest tooling | Partial | |
| RF-08 | Host alert: banner with count, optional sound, screen-reader announcement | Must | W4 | A named gap. A knock raises no Matrix notification by default. GP-FLOW-29 requires a host-visible notice outside Matrix push; 06 open decision 5 proposes a per-room push rule, and whether it raises an alert has not been run | Partial | |
| RF-09 | Guest pre-join with name, camera and mic check | Must | W1 | G1 name form showing the exact name (GP-UX-02); G3 device check that never blocks joining (GP-UX-08, 03 GP-CLI-09) | Covered | |
| RF-10 | Clear waiting status, including "host hasn't joined yet" | Must | W2 | G3 shows "Asking the host to let you in", `slow` after 2 minutes, `declined`, `admitted`, with the session clock (06 G3). No state says the host has not joined | Partial | |
| RF-11 | Anonymous and bot knocks held in a separate Suspected queue | Must | W5 | Nothing at the knock. Controls sit before it: per-guest single-use invites (D6), the host allow-list (D5), minting quotas (04 GP-SEC-02). Anti-automation beyond those is NG-08 | Excluded | |
| RF-12 | Knocking blocked after two denials; remove with rejoin block | Must | W3, W6 | A different rule: at most 3 knocks per guest and room in 10 minutes, enforced by the policy module, with the host's ban as the permanent stop (GP-FLOW-33, GP-SYN-21). A deny is a kick (06 H5) | Conflicts | |
| RF-13 | Waiting guests receive no media, keys, roster or passwords | Must | Backend | The call is mounted only at membership `join` (D14, GP-CLI-14) and the room is encrypted by rule (D7). That a new device gets call keys only after admission is spike SP-2, open. A knocker does receive stripped room state (name, topic, avatar, encryption, join rules) by Synapse default (02 section 3.6) | Partial | |
| RF-14 | Message the whole lobby or one guest, optional reply | Should | W2, W5 | Excluded by NG-05. Also against the member-event allow-list that drops `reason` (GP-FLOW-09, GP-SYN-08) and the rule that a guest sends no event but its own membership (GP-SYN-18). No host-to-knocker channel is established | Excluded | |
| RF-15 | Branded waiting screen: title, logo, description, video | Should | W2, W7 | The meeting title comes from `GET /guest/context` after redeem. No host-controlled text before redeem (D21, 04 GP-SEC-15); the join and consent pages carry operator text only. No logo, description or video | Partial | |
| RF-16 | Queue position shown to the guest | Should | W2 | Nothing | Not in set | |
| RF-17 | Email one-time code for guests without an account | Should | W1 | Excluded by NG-01 (no e-mail verification). No mailer in v1; the address is self-asserted and never a login or recovery factor (05 CP-08, 04 GP-SEC-26) | Excluded | |
| RF-18 | Hold a guest with a message | Should | W3, W5 | Excluded by NG-05; same constraints as RF-06 and RF-14 | Excluded | |
| RF-19 | Auto-lock the meeting after N minutes | Should | W7 | Nothing. The nearest are the hard per-guest deadline (00 section 3, 01 section 6.2) and the host's end of meeting (`POST /guest/meetings/end`, 01 section 4.2) | Not in set | |
| RF-20 | Admit straight into an assigned breakout room | Should | W5 | Nothing; one call room per meeting | Not in set | |
| RF-21 | Host-absent rules: everyone to the waiting room if the host drops; timeout | Should | W7 | Nothing. The identity provider cannot see "in call" or "last participant leaves"; both are deferred (01 sections 6.2 and 7.1) | Not in set | |
| RF-22 | Report a participant to trust and safety | Should | W6 | Nothing found | Not in set | |
| RF-23 | Audit log of who admitted whom, and how | Should | Admin log | No admission log is specified. A claim writes one audit event (05 GP-CLM-21). Approve is an invite from the host (06 H5), so the sender is on the room's member event; that is inferred and has not been read here | Not in set | |
| RF-24 | Domain allow and block lists | Could | W7 | Nothing for guests. The allow-list of D5 names who may host, not which guest domains may join | Not in set | |
| RF-25 | Remember choice for repeat requests | Could | W5 | Nothing | Not in set | |
| RF-26 | Notify-host button that emails the host | Could | W2 | Nothing; there is no mailer in v1. GP-FLOW-29 is about the host seeing a knock, not a guest-triggered mail | Not in set | |
| RF-27 | Keyboard shortcut to admit | Could | W4 | Nothing; the host interface is upstream (06 H5) | Not in set | |
| RF-28 | API and webhooks for knock, admit, hold, reject | Could | API | A host API for invites exists (`GET /guest/invites`, the end verbs, 01 section 4.2). No knock or admit events; webhooks are deliberately not built in v1 (01 section 6.2) | Partial | |

Counts: of 28 features, 1 Covered, 10 Partial, 4 Excluded, 1 Conflicts, 12 Not in set. Of the 13 musts: 1 Covered, 8 Partial, 1 Excluded (RF-11), 1 Conflicts (RF-12), 2 Not in set (RF-02, RF-06).

**Track C against the features.** Only the features where the meedio-connect evaluation shows a pattern. Statuses are those of [reference/meedio-connect.md](reference/meedio-connect.md); the disposition stays the session's work.

| RF | What meedio-connect does | Status |
|---|---|---|
| RF-05 | Accept (an invite) or deny (a kick) per waiting person, in a participants sidebar | Verified (present) |
| RF-07 | The waiting list and its actions are shown to room owners only | Verified (present) |
| RF-08 | A sound plays on the host side when the waiting list changes | Verified (wired to the waiting list); the exact trigger Inferred |
| RF-09 | Pre-join camera preview, with dialogs for blocked, busy, missing and pending devices and browser-specific instructions | Verified (present) |
| RF-10 | A waiting screen while the membership is `knock`, and a denial message | Verified |
| RF-13 | No contrast available: the client has no media E2EE at all, so it says nothing about what a waiting guest receives | Verified |

**Screens side by side** (what the session lines up in the first block):

| Reference screen | Nearest design-set screen | Gap |
|---|---|---|
| W1 Guest pre-join | G1 join page; G3 device zone | W1 puts name, device check and e-mail code on one screen; the set splits them and has no code |
| W2 Guest waiting room | G3 lobby (`knocking`, `slow`) | Branded header, welcome media, place in line, host messages: none in the set |
| W3 Guest other states | G3 `slow`, `declined`; G6; G7 | "Host not here yet", "on hold" have no equivalent |
| W4 Host lobby alert | 06 H5, the notification gap, open decision 5 | The set names the gap and has no alert design |
| W5 Host waiting room panel | 06 H5 (upstream knock bar) | Groups, select-all, per-guest menu: none |
| W6 Host send back, remove, report | none (upstream kick and ban) | Send back and report have no equivalent |
| W7 Settings | the configuration surface of 01 (operator configuration, no screen) | A host-facing settings page does not exist in the set |

## 4. Collisions to settle

Each collision is a place where the two tracks cannot both stand as written. The position is a recommendation to bring, open for the product owner, and every one carries the evidence of section 3.

| Id | Collision | Features and rules | Position to bring |
|---|---|---|---|
| CS-01 | **Scope.** A guest portal on Matrix, or a general meeting product with organisations | RF-01, RF-02, RF-03, RF-20, RF-24 presuppose organisation accounts, phone and admin consoles the set does not have | Track A is the product; Track B is a feature source. The features above stay out unless the scope is widened on purpose |
| CS-02 | **Host side.** The upstream knock bar, or a host lobby panel as in W4 and W5 | RF-05, RF-07, RF-08, RF-11 (grouping), RF-25, RF-27 against 06 H5 and GP-FLOW-29 | v1 stays on the upstream bar and closes the alert gap first. The host tool of H3 already holds the host token and the invite list, so it is the place a lobby panel would grow, as its own workstream with its own gate |
| CS-03 | **Text between host and guest.** Lobby messages, hold messages, welcome text | RF-14, RF-15, RF-18 against NG-05, D21, GP-SEC-15, GP-SYN-08 | Keep NG-05 and D21 for v1. Allow operator-set branding on the pages the operator owns. Revisit messaging only with a channel proposal and its own threat model, because this is the injection surface those rules remove |
| CS-04 | **Who the guest is.** Four trust labels and an e-mail code | RF-04, RF-17 against NG-01, 05 CP-08, GP-SEC-26, P3 | One label, "(Guest)", in v1 and no guest mailer. A "Verified" label is a new workstream with privacy and operations scope, not a screen change. R11 brings a reviewed mailer for registered users; whether guests use it is CS-10 |
| CS-05 | **Denial rule.** Two denials block, or 3 knocks in 10 minutes plus ban | RF-12 against GP-FLOW-33, GP-SYN-21 | Keep the rate rule. It needs no extra state and counts kicks. A denial counter would need the module to tell a deny from a kick, which Matrix does not distinguish |
| CS-06 | **Send back and hold.** | RF-06, RF-18 against GP-SYN-21 (a kick counts as a knock) and NG-05 | Not in v1. A send-back is a kick and a re-knock: it spends the guest's knock budget and does not take back what the guest already received. What a removed guest keeps has not been checked and is the first thing to verify |
| CS-07 | **Host absent and auto-lock.** | RF-19, RF-21 against 01 sections 6.2 and 7.1 | v1 keeps the per-guest deadline and the host's end of meeting. A host-absent rule needs a presence signal the identity provider cannot see; decide whether a media-server webhook justifies a new public route |
| CS-08 | **One look.** The reference wireframes use a blue accent on grey; the gallery uses an orange accent on grey | W1 to W7 against G1 to G7 and H0 to H5 | Choose one at the session and reconcile the screen lists of section 3 into one inventory; the gallery is the one that has states, copy and a check script |
| CS-09 | **Track C: what to take.** Patterns from a client that is not a base | reference/meedio-connect.md section 4 against 03 GP-CLI-09, GP-CLI-14, 01 GP-FLOW-29 and RF-05, RF-08, RF-09, RF-10; its telemetry lesson against 04 GP-SEC-44, which covers server logs only | Take the patterns as designs, not code (its React 18 and js-sdk 37 against the component's React 19 and v43). Extend GP-SEC-44 to the guest client: no third-party telemetry by default, and no access, refresh, OpenID or LiveKit token and no media key in the console, a rageshake or telemetry |
| CS-10 | **R10 and R11 meet the guest tracks.** | R11 brings a mailer and an address that authenticates, for registered users, against CS-04, NG-01, 04 GP-SEC-23 to GP-SEC-26, RF-17 and RF-26; R10 adds Element X rows to SP-8 and acceptance A9 | R10 and R11 stand (product owner). The guest rules stay: a guest's address stays unverified and never authenticates. The R11 mailer is not a guest mailer by default: RF-17 and RF-26 need their own decision, now that a reviewed mailer exists. Offering "register with e-mail" next to the passkey claim on the guest end screen is the session's call (it would be a second way to keep an account, 05) |

## 5. Order of work

Interactive, with the product owner. Each block ends in a written output, and the register of section 6 is filled as decisions are taken.

| Block | Content | Output |
|---|---|---|
| 0 | Frame: confirm the goal, the three tracks, the added requirements R10 and R11, and what "final plan" means (section 2) | Agreed outputs |
| 1 | Walk the screens: the gallery and the reference canvas side by side, using the table at the end of section 3 | Shared picture, input to CS-08 |
| 2 | Scope (CS-01) | The scope statement |
| 3 | Feature pass RF-01 to RF-28, musts first, one line each | Dispositions in the worksheet |
| 4 | Collisions CS-02 to CS-07, CS-09 and CS-10, one decision each | Rows of section 6 |
| 5 | The open decisions of the set that blocks 3 and 4 touched (D3, D5 and D17, D9, D10, D16, D20 and D21 are the likely ones, plus D22 to D24 for Track C, R10 and R11) | Decided or scheduled |
| 6 | Close: edit list, owners, first gate | Section 2, items 6 and 7 |

**Read first:** [00 sections 1, 2 and 7](00-overview.md), the gallery screens H5, G1, G3 and G5, the Verdict, Scorecard and Feature list of the [case study](reference/waiting-room-case-study.md), the boards W2, W4 and W5 of the reference canvas, sections 2 to 4 of the [Track C evaluation](reference/meedio-connect.md), and section 0 of [09](09-registered-users.md).

## 6. Decision register (empty until the session)

Filled live. A row states the decision, its consequence for the files of 00 to 07, and who edits them.

| Id | Question | Decision | Consequence for 00 to 07 | Owner | Date |
|---|---|---|---|---|---|
| CS-01 | Scope line | | | | |
| CS-02 | Host side | | | | |
| CS-03 | Text between host and guest | | | | |
| CS-04 | Who the guest is | | | | |
| CS-05 | Denial rule | | | | |
| CS-06 | Send back and hold | | | | |
| CS-07 | Host absent and auto-lock | | | | |
| CS-08 | One look | | | | |
| CS-09 | Track C: what to take | | | | |
| CS-10 | R10 and R11 meet the guest tracks | | | | |

## 7. What does not happen before the session

- No edit to 00 to 07 beyond the pointers that announce this step, and no change to any `GP-` row, with one exception: the requirements R10 and R11 that the product owner set on 2026-10-02, which added 09 and its wiring into 00, 03, 04 and 07.
- No spike, no milestone, no code, no change to a running system. The first spike waits for the first gate of the session.
- The pull request stays a draft. Nothing is proposed for merge on the strength of the reference material.
- The Track B reference files are not edited. A change in the sources arrives as a new export with new hashes, and the session works from the frozen one. The Track C evaluation is edited only to correct a claim against its pinned sources.
- The disposition column of section 3 stays empty. A pre-filled disposition would be a decision taken without the product owner.

## 8. After the session (not started)

Planned only so that the end of the session has a place to go: apply the register to 00 to 07, regenerate the traceability matrix of 07, re-run the checks of the set, rewrite the milestone list if the scope moved, and publish the final plan as the revision of this pull request. None of this is part of this change.

## Validation status

| Claim | Evidence | Status |
|---|---|---|
| The design set excludes guest-to-host messaging, e-mail verification and anti-automation beyond its listed controls | 04 section 6.1, NG-05, NG-01, NG-08 | Verified (read) |
| A knock after a deny, a kick or a cancel counts toward the cap of 3 in 10 minutes | 01 GP-FLOW-33, 02 GP-SYN-21 | Verified (read) |
| The host admits through the upstream knock bar, one line per guest, and a knock raises no notification by default | 06 section 5.6 (H5), 01 GP-FLOW-29 | Verified (read; the push-rule remedy has not been run) |
| The member event of a guest keeps only `membership` and the canonical `displayname` | 01 GP-FLOW-09, 02 GP-SYN-08 | Verified (read) |
| No mailer exists in v1, and e-mail is self-asserted | 05 CP-08, 04 GP-SEC-26 | Verified (read) |
| Federation is off for a guest deployment | 01 and 00, prerequisite P3 | Verified (read; an operator assertion, not enforced by the server) |
| The status column of section 3 matches the design set | a search of 00 to 07 for each feature's terms and a read of the owning rows | Verified for the rows that cite an identifier; **absence claims ("Nothing", "Not in set") are Unverified** beyond that search |
| Approve is an invite from the host, so the admitting host is on the room's member event | 06 section 5.6 says Approve is an invite; the event content was not read | Unverified (inferred) |
| What a guest that has been kicked still holds (room keys, call keys) | not examined | Unverified; the first check before CS-06 |
| The case study's vendor, advisory and date claims | none run by this repository | Unverified |
| A host-to-knocker channel does not exist in the design set | searched; none specified | Unverified (an absence claim) |
| The Track C rows of section 3 match the evaluation | reference/meedio-connect.md section 4 and its validation table | Verified (read) |
| GP-SEC-44 governs server log lines only | 04 GP-SEC-44, enforcement point S | Verified (read) |

## Open decisions

1. **Named-vendor security table in a public repository.** Recommendation: before the pull request leaves draft, a maintainer reads that table of the case study and decides to keep, cite or remove it; this document does not depend on it.
2. **A static preview of the reference canvas.** Recommendation: generate one only if the product owner wants to review the boards outside the canvas viewer; it would be a derived file, marked as such, and is not part of this change.
3. **Spike SP-2 before or after the session.** Recommendation: after. Nothing starts before the session ends, and SP-2 stays the first spike (07 section 3).
