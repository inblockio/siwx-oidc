# Guest portal reference material

**Status:** reference documentation. Source artefacts kept next to the design set so that the next step, the [consolidation session](../08-consolidation-session.md), has its inputs in one place. Nothing here is part of the design contract of [00](../00-overview.md) to [07](../07-implementation-plan.md): no `GP-` identifier depends on a file in this folder, and no milestone builds from it until the consolidation session has decided what to take over.

## Contents

| Path | What it is | Used by |
|---|---|---|
| [waiting-room-case-study.md](waiting-room-case-study.md) | A survey of how seven meeting apps handle waiting rooms and guests (scorecard, security history, 12-test hands-on protocol) and the **28-feature requirements list** (13 must, 10 should, 5 could), each feature naming the app that does it best and the reference screen that draws it | [08](../08-consolidation-session.md) sections 3 and 4 |
| [waiting-room-wireframes/](waiting-room-wireframes/) | Seven reference screens, W1 to W7: guest pre-join, waiting room and other states on a phone; host alert, waiting room panel and participant actions on desktop; waiting room and guest settings. Blue tags on each screen carry the feature number F1 to F28 of the case study | [08](../08-consolidation-session.md) sections 3 and 4 |

The design set's own screens (host H0 to H5, guest G1 to G7, claim K1 and K2) stay in [06](../06-wireframes.md) and its [gallery](../wireframes/index.html). The two wireframe sets were drawn independently and are not yet reconciled; that is the work of the consolidation session.

## Rules for this folder

1. **Source artefacts are kept as received.** The wireframe files are byte-identical to the copies exported from the canvas they were drawn in (hashes below). The case study is a Markdown conversion of the living document it was written in, with only the conversions its header lists. A change belongs in the source and arrives here as a new export, never as an edit in place.
2. **Identifiers.** The case study numbers its features F1 to F28. The design set cites them as `RF-01` to `RF-28` (RF-nn is feature Fn), so they cannot be confused with the F-numbers of the claim failure rows in 05 or the findings in 04. The screens are cited as `W1` to `W7`.
3. **Nothing in here is verified by this repository.** The case study says no hands-on test was run. Its vendor, advisory and date claims are leads until someone checks them; before the pull request leaves draft, a maintainer should decide whether to keep the named-vendor security table in a public repository at all.
4. **Sample data is placeholder data.** The wireframes use invented names (Jordan, Priya S., Sam K., Alex, MeetingBot 7), a masked phone number and bracketed placeholders. None of it is real.

## Viewing the wireframes

The `.dc.html` files and `canvas.json` are sources for the design canvas they were drawn in: each board starts with `<script src="./support.js">`, a file the canvas viewer supplies and this repository does not carry, and each board links a web font from a public font host. They were not tested in a plain browser, and a plain browser is not expected to render them correctly. Open them in the canvas viewer, or ask for a static preview to be generated as a derived file (not part of this change). `canvas.json` lists the boards, their frames and the note that explains the blue tags.

## Integrity

SHA-256 of the files as exported (the wireframe files are not edited after export):

| File | SHA-256 |
|---|---|
| `canvas.json` | `7c59ce7de8fb0933fd7584b010ab5410282218624a9a8fc8e0c8387f4be5c327` |
| `Main.dc.html` (W1) | `3538dc1c5978f646f1389516276151679a78a3f4905cba420f2e9d3531fe43e3` |
| `W2-guest-waiting.dc.html` | `e5f0ed8d76688809a2cd1e9f2d9cdb8a4a29df23136e2a94e29b90ee69e1e3b3` |
| `W3-guest-states.dc.html` | `fb3c75d4a9ef9bc3190784c355c263fec219f11f4c650abab3c3553e0bf62f19` |
| `W4-host-alert.dc.html` | `f3cd60eec7725cd81028a3dae53ef830f0887400afae5a38e6cb5a18ce65fc7a` |
| `W5-host-lobby.dc.html` | `571b4a78a59db4a4b8988601905b0ef27969bd908e48f7b993dd1b06b27e28d3` |
| `W6-host-participants.dc.html` | `1956bb5bdb72246e06a5cf41770c2378e3804e427f9782aa71b6af33bbcb812a` |
| `W7-policy-settings.dc.html` | `aa54af59ea7320c9ab9975061415647bbcbc7dd45983765f7689e157874b8031` |

Compare with the output of `sha256sum *` run inside `waiting-room-wireframes/`.
