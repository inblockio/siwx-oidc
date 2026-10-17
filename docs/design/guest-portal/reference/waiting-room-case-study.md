# Guest portal reference A: waiting room case study and feature list

**Status:** reference documentation. A source artefact kept with the design set as received. It is not part of the design contract of 00 to 07, no `GP-` identifier depends on it, and this repository has not checked any of its claims.
**Origin:** a living document written for the maintainers and dated 2026-09-30, exported at revision 12. The text below the rule is that document, unchanged. Conversions only: headings are demoted by one level, the byline (a person's name) is dropped and its date kept, tables and links are Markdown (one link, to the private page of the wireframe canvas, now points to the copy in this folder), and the scorecard chart is the table under "Scorecard" built from the chart's own data.
**Used by:** [08 consolidation session](../08-consolidation-session.md), which reads the 28-feature list as requirements input. The screens that draw the features are the reference wireframes in [waiting-room-wireframes/](waiting-room-wireframes/).
**Feature identifiers:** the document numbers its features F1 to F28. This set cites them as `RF-01` to `RF-28` (RF-nn is feature Fn of this document), so they cannot be confused with the F-numbers of other documents (the failure rows of 05, the findings of 04).
**Caveats:** the study says no hands-on test was run and that its scores rest on vendor documentation, published security research and academic studies. Vendor, advisory and date claims in it are leads, not facts, until someone verifies them. It describes a general meeting product with organisation accounts; the design set describes an anonymous invite-link guest portal on Matrix, so the two differ in scope (08 section 3).

---

## Meeting App Waiting Rooms & Guest Handling — Case Study

Dated 2026-09-30.

### Verdict

**Zoom has the best waiting room and guest handling overall: 88/100, ahead of Microsoft Teams and Cisco Webex at 83 each.** It has the most granular bypass rules, the fullest host toolkit (admit, admit all, send back, rename, two-way lobby chat, report, admit straight into breakout rooms) and a brandable waiting screen with video that only Webex matches.

**Pick Teams if verifying who a guest is matters most.** It has the richest trust labels (External, Unverified, Email verified), email one-time passcodes and a separate "Suspected threats" lobby queue for bots. Weight identity and security higher and Teams ties Zoom at 86.5.

**Zoom's weak spot is its security record**: its waiting room leaked meeting keys and video in 2020, and on-premise connectors had admission-bypass bugs in 2022. All were fixed.

No independent lab has tested these waiting rooms head-to-head. The scores rest on vendor documentation, published security research and the few academic studies that exist. The hands-on test protocol below lets you verify them.

### Method

Seven apps were compared as of 30 Sep 2026: Zoom, Microsoft Teams, Google Meet, Cisco Webex, BigBlueButton, Jitsi Meet and Whereby. Each was scored 1–5 (half points allowed) on six criteria, weighted to 100.

| Criterion | Weight | What earns a 5 |
|---|---|---|
| Admission policy | 20 | Fine-grained bypass rules (org, trusted orgs, invitees, domains, dial-in) and admin-enforced defaults |
| Host admit workflow | 20 | Admit or deny one, many or all; send back; delegate to co-hosts; lock; remove; report |
| Guest identity and verification | 20 | Trust labels, sign-in or SSO requirements, domain lists, one-time passcodes, bot detection |
| Waiting experience and messaging | 15 | Device check, clear status, branding, queue position, lobby chat |
| Security record | 15 | No lobby bypass or leak in published research or CVEs |
| API and automation | 10 | Lobby settings, admit actions and lobby events available to developers |

Evidence comes from vendor help pages, admin and API docs, release notes, CVE advisories, security research and academic studies. Community forums were used only where vendors say nothing, and are flagged.

A second, security-first weighting (identity 30, security 20, policy 20, host 15, experience 10, API 5) tests how sensitive the ranking is.

Limits: no hands-on tests were run for this study. Features depend on plan and account type; Meet's waiting room, for example, exists only on paid Workspace editions.

### Scorecard

| App | Default weighting | Security-first weighting (identity 30, security 20) |
|---|---|---|
| Zoom | 88 | 86.5 |
| Microsoft Teams | 83 | 86.5 |
| Cisco Webex | 83 | 82.5 |
| Google Meet | 74.5 | 77 |
| BigBlueButton | 66.5 | 64 |
| Whereby | 66 | 61.5 |
| Jitsi Meet | 61.5 | 57.5 |

*Weighted from the criterion scores below · weights in Method · as of 30 Sep 2026*

Zoom leads by five points on default weights. Webex's lobby nearly matches it but has no lobby messaging and a 2020 lobby leak. BigBlueButton, Whereby and Jitsi trail because they leave guest identity to the integrating app or to whoever holds the link.

Criterion scores, 1–5, behind the totals:

| App | Policy | Host workflow | Identity | Experience | Security | API |
|---|---|---|---|---|---|---|
| Zoom | 5 | 4.5 | 4.5 | 5 | 3 | 4 |
| Microsoft Teams | 5 | 3.5 | 5 | 3 | 4 | 4 |
| Cisco Webex | 4.5 | 4.5 | 4.5 | 4 | 3 | 4 |
| Google Meet | 3.5 | 4 | 4 | 3 | 4.5 | 3 |
| BigBlueButton | 3 | 4 | 2.5 | 4 | 3.5 | 3 |
| Whereby | 2.5 | 3.5 | 2 | 4 | 4 | 5 |
| Jitsi Meet | 2.5 | 3.5 | 2.5 | 4 | 2.5 | 4 |

### Platform findings

The three enterprise leaders each own one strength: Zoom the host toolkit, Teams guest identity, Webex bulk admission. The others are narrower.

| App | Strongest for guests and hosts | Main gaps |
|---|---|---|
| [Zoom](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059359) | Bypass by account, allowed domains or invite list; send back to waiting room; rename; two-way lobby chat (optional); branded title, logo, description and video; SSO or domain-based authentication profiles; moves everyone to the waiting room if the host drops; admits straight into breakout rooms (7.2.0, Sep 2026) | No multi-select, only Admit all; no email passcode check; branding and authentication need a paid plan; waiting room can't be customised by API |
| [Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-lobby) | Six bypass scopes plus a separate dial-in switch; External, Unverified and Email verified labels; email one-time passcodes (Premium); bot detection holding suspects in a "Suspected threats" queue (2026); lobby visible only to admitters (Sep 2026); reporting of external users | No send-back to lobby (community reports); lobby chat is one-way; guests removed after 30 minutes unadmitted; no Graph endpoint to admit; town halls have no lobby |
| [Cisco Webex](https://help.webex.com/article/3gt73c/Webex-App-%7C-Let-someone-into-your-meeting) | Lobby grouped into Internal, External and Unverified; multi-select and select all; move to lobby; auto-lock after 0–20 minutes; branded lobby with banner, logo and video; Notify host button; CAPTCHA; Admit Participants API; Ctrl+Shift+G to admit | No messages to the lobby; no lobby webhooks; domain limits dodged by joining as a guest unless device tokens are enforced; meeting ends 5 minutes after the host leaves if only lobby users remain |
| [Google Meet](https://support.google.com/meet/answer/16523457?hl=en) | Knocking on every meeting with Open, Trusted or Restricted access; anonymous and bot knocks auto-denied in Trusted; knock blocking after two denials (documented for Education); two-queue "safeguarded" admit flow on all accounts (2026); send back to waiting room; up to 25 co-hosts; audit log of who admitted whom (2026) | Waiting room is opt-in, off by default and paid-only; no customisation; announcements are one-way; no waiting-room API field or knock events |
| [BigBlueButton](https://docs.bigbluebutton.org/development/api/) | Queue position shown to guests (3.0); broadcast and private messages to waiting guests; Remember choice; remove with rejoin ban; policy per meeting via API | Identity comes from the integrating app (Greenlight, Moodle), with no checks of its own; server default admits everyone; no send-back; dial-in bypass bug open in 3.0.9–3.0.10 |
| [Jitsi Meet](https://jitsi.github.io/handbook/docs/dev-guide/iframe-events) | Pre-join device check; two-way private lobby chat; IFrame API for knock events and answers; self-hostable | Lobby off per room by default; a room password skips it; token bypass only via community plugins; no send-back or ban |
| [Whereby](https://docs.whereby.com/whereby-product-features/waiting-rooms) | Locked rooms with knocking on every consumer plan; hold or reject with a message; clear knock states; best embed API (accept, hold, reject, knock webhooks) | No guest identity checks; no Admit all found; no domain or sign-in policies; not in the free Embedded plan |

### Security track record

Zoom, Webex and Jitsi have each had a waiting room that leaked something to people it was holding: keys and video, attendee details, or the room password. No lobby bypass has been published for Teams, Meet or Whereby, though that partly reflects less research on them.

| Date | App | Finding | Status |
|---|---|---|---|
| Open | BigBlueButton | Dial-in callers skip moderator approval in 3.0.9–3.0.10 ([issue #23536](https://github.com/bigbluebutton/bigbluebutton/issues/23536)) | Unfixed |
| Aug 2026 | Zoom | In-meeting annotation code-execution bugs; press advises waiting room, passcodes and authentication to keep attackers out ([CSO](https://www.csoonline.com/article/4208223/zoom-zero-click-rce-flaws-allow-attackers-to-compromise-meeting-participants.html)) | Patched |
| May 2024 | Jitsi Meet | Guests admitted from the lobby were sent the room password, which let others skip the lobby, CVE-2024-33530 ([ERNW](https://insinuator.net/2024/05/vulnerability-in-jitsi-meet-meeting-password-disclosure-affecting-meetings-with-lobbies/)) | Fixed in 2.0.9457 |
| May 2024 | Cisco Webex | Guessable meeting numbers exposed metadata of German government meetings ([SecurityWeek](https://www.securityweek.com/cisco-patches-webex-bugs-following-exposure-of-german-government-meetings/)) | Fixed 28 May 2024 |
| 2023 | BigBlueButton | Script injection through lobby messages, CVE-2023-43797 ([advisory](https://github.com/bigbluebutton/bigbluebutton/security/advisories/GHSA-v6wg-q866-h73x)) | Fixed in 2.6.11 |
| 2023 | Google Meet | Researcher showed dial-in PINs skip knocking in Trusted meetings ([write-up](https://basu-banakar.medium.com/google-meet-flaw-join-any-organisation-call-not-an-0day-but-still-acts-as-0day-refused-by-4d65730df403)) | By design, per Google |
| 2022 | Zoom | On-premise Meeting Connector let waiting users join without approval or invisibly, CVE-2022-28749 and CVE-2022-28754 ([advisory](https://github.com/advisories/GHSA-hf5f-6q2f-wm25)) | Fixed |
| Nov 2020 | Cisco Webex | IBM "ghost" bugs: the lobby leaked attendee names, emails and IPs (CVE-2020-3441); invisible joining; audio after removal ([BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-fixes-webex-bugs-allowing-ghost-attackers-in-meetings/)) | Fixed |
| Apr 2020 | Zoom | People in the waiting room received meeting keys and live video ([Citizen Lab](https://citizenlab.ca/2020/04/zooms-waiting-room-vulnerability/)) | Fixed 7–8 Apr 2020 |
| 2019–20 | Microsoft Teams | Users reported removed participants rejoining without the lobby ([forum](https://techcommunity.microsoft.com/t5/microsoft-teams/removed-users-can-rejoin-in-seconds-bypassing-the-lobby/td-p/1298590)) | Unclear |

Research also limits what a waiting room can do. The largest Zoombombing study found 70–82% of disruption calls came from invited insiders with real names, whom a host vetting names can't spot ([Ling et al., IEEE S&P 2021](https://arxiv.org/abs/2009.03822)). Per-participant links and sign-in checks matter as much as the lobby itself.

### Feature list

The best-of-breed waiting room has 28 features: 13 must-haves, 10 should-haves and 5 could-haves. Each names the app that does it best today and the wireframe screen (W1–W7) that draws it.

| # | Feature | Priority | Best today | Screen |
|---|---|---|---|---|
| 1 | Bypass rules: everyone, org, trusted orgs, invitees or hosts only | Must | Teams | W7 |
| 2 | Separate switch for phone dial-in callers | Must | Teams | W7 |
| 3 | Admin-enforced, lockable defaults; at least one protection mandatory | Must | Zoom | W7 |
| 4 | Trust label on every waiting guest: Internal, External, Verified, Unverified | Must | Webex, Teams | W5 |
| 5 | Admit or deny one, several (multi-select) or all | Must | Webex | W5 |
| 6 | Send a participant back to the waiting room | Must | Zoom, Meet, Webex | W6 |
| 7 | Co-hosts can admit; only admitters see the lobby | Must | Teams | W5 |
| 8 | Host alert: banner with count, optional sound, screen-reader announcement | Must | Zoom | W4 |
| 9 | Guest pre-join with name, camera and mic check | Must | Jitsi, Whereby, Teams | W1 |
| 10 | Clear waiting status, including "host hasn't joined yet" | Must | Zoom | W2 |
| 11 | Anonymous and bot knocks held in a separate Suspected queue | Must | Teams, Meet | W5 |
| 12 | Knocking blocked after two denials; remove with rejoin block | Must | Meet, Zoom | W3, W6 |
| 13 | Waiting guests receive no media, keys, roster or passwords | Must | Lesson of Zoom 2020, Webex 2020, Jitsi 2024 | Backend |
| 14 | Message the whole lobby or one guest, with optional reply | Should | Zoom, BigBlueButton, Jitsi | W2, W5 |
| 15 | Branded waiting screen: title, logo, description, video | Should | Zoom, Webex | W2, W7 |
| 16 | Queue position shown to the guest | Should | BigBlueButton | W2 |
| 17 | Email one-time passcode for guests without an account | Should | Teams (Premium) | W1 |
| 18 | Hold a guest with a message | Should | Whereby | W3, W5 |
| 19 | Auto-lock the meeting after N minutes | Should | Webex | W7 |
| 20 | Admit straight into an assigned breakout room | Should | Zoom, Webex | W5 |
| 21 | Host-absent rules: everyone to waiting room if host drops; timeout | Should | Zoom, Teams | W7 |
| 22 | Report a participant to trust and safety | Should | Zoom, Teams, Meet | W6 |
| 23 | Audit log of who admitted whom, and how | Should | Meet | Admin log |
| 24 | Domain allow and block lists | Could | Zoom, Webex | W7 |
| 25 | Remember choice for repeat requests | Could | BigBlueButton | W5 |
| 26 | Notify host button that emails the host | Could | Webex | W2 |
| 27 | Keyboard shortcut to admit | Could | Webex | W4 |
| 28 | API and webhooks for knock, admit, hold and reject | Could | Whereby, Webex | API |

### Wireframes

Seven screens cover the full guest and host journey; they are in the [Waiting Room Wireframes](waiting-room-wireframes/) canvas. Blue F-tags on each screen point to the numbered Feature list above.

| Screen | What it shows | Features |
|---|---|---|
| W1 Guest: pre-join (phone) | Name, camera and mic check, guest label, optional email verification, Ask to join | F4, F9, F17 |
| W2 Guest: waiting room (phone) | Branded header, host-present status, place in line, welcome media, two-way host messages, self-check | F9, F10, F14, F15, F16 |
| W3 Guest: other states (phone) | Host not here yet with Notify host; on hold with message; denied twice | F10, F12, F18, F21, F26 |
| W4 Host: lobby alert (desktop) | Toast with count split by trust label, Admit all except suspected, mute, shortcut | F4, F8, F11, F27 |
| W5 Host: waiting room panel (desktop) | Groups by trust, multi-select, per-guest menu (breakout, hold, message, block, report), lock, Remember choice | F2, F4, F5, F7, F11, F12, F14, F18, F20, F22, F25 |
| W6 Host: participant actions (desktop) | Send back to waiting room with Undo, remove and block, report | F6, F12, F22 |
| W7 Settings: waiting room and guests | Bypass scope, dial-in, domain lists, admin locks, who can admit, guest checks, host-absent rules, waiting screen, audit log | F1–F4, F7, F11, F12, F14–F17, F19, F21, F23, F24 |

### Hands-on test protocol

Twelve tests, about two hours per app, turn the scorecard from documented to measured. Use a host in your organisation, a signed-in guest from another organisation, a signed-out browser and a phone dial-in, all with the waiting room on. Record pass or fail, clicks and seconds.

1. **Guest join time.** Signed-out guest opens the link: seconds and installs until the waiting screen; is a camera and mic check offered?
2. **Labels.** What label does the host see for each guest type?
3. **Host absent.** Guest arrives first: what do they see, and what happens after 30 minutes?
4. **Bulk admit.** Ten guests knock: clicks to admit eight and deny two.
5. **Send back.** Move an admitted guest to the waiting room; confirm audio, video and chat stop.
6. **Repeat knocks.** Deny a guest twice: can they knock a third time?
7. **Remove and block.** Rejoin with the same link, then from a fresh browser profile under a new name.
8. **Dial-in.** Call in with the meeting ID: does the caller wait?
9. **Lobby chat.** Message the lobby and one guest; can the guest reply?
10. **Leak check.** While waiting, watch the guest's network traffic (browser developer tools): any media, participant names or passwords before admission is a fail.
11. **Accessibility.** Join and admit using only a keyboard and a screen reader (NVDA or VoiceOver).
12. **Bot.** Join with a headless browser or recording bot: is it flagged or held apart?

### Sources

- **Zoom:** [Waiting Room settings](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059359) · [Managing the Waiting Room](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0063329) · [Security option requirement](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059862) · [Authentication profiles](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0061263) · [Guest labels](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0066590) · [Breakout rooms](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0061222) · [Webhook events](https://developers.zoom.us/docs/api/meetings/events/) · [Customising via API (forum)](https://devforum.zoom.us/t/customize-modify-waiting-room-via-api/137242)
- **Microsoft Teams:** [Who can bypass the lobby](https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-lobby) · [Using the lobby](https://support.microsoft.com/en-us/teams/meetings/using-the-lobby-in-microsoft-teams-meetings) · [Anonymous users](https://learn.microsoft.com/en-us/microsoftteams/anonymous-users-in-meetings) · [Join verification](https://learn.microsoft.com/en-us/microsoftteams/join-verification-check) · [Joining without an account](https://support.microsoft.com/en-us/teams/meetings/join-a-meeting-without-an-account-in-microsoft-teams) · [lobbyBypassSettings (Graph)](https://learn.microsoft.com/en-us/graph/api/resources/lobbybypasssettings?view=graph-rest-1.0) · [Lobby chat, MC1069555](https://mc.merill.net/message/MC1069555) · [CAPTCHA retirement](https://blog-en.topedia.com/2026/04/microsoft-retires-the-captcha-challenges-for-teams-meeting-join/)
- **Google Meet:** [Access types](https://support.google.com/meet/answer/9302870?hl=en) · [Waiting room](https://support.google.com/meet/answer/16523457?hl=en) · [Waiting room launch](https://workspaceupdates.googleblog.com/2025/10/new-waiting-rooms-google-meet.html) · [Safeguarded admit flow](https://workspaceupdates.googleblog.com/2026/02/safeguarded-guest-admit-flow-in-google-meet.html) · [Knock blocking](https://workspaceupdates.googleblog.com/2020/08/block-google-meet-participants-from.html) · [Meet REST API spaces](https://developers.google.com/workspace/meet/api/reference/rest/v2/spaces)
- **Cisco Webex:** [Let someone into your meeting](https://help.webex.com/article/3gt73c/Webex-App-%7C-Let-someone-into-your-meeting) · [Secure meetings: Control Hub](https://help.webex.com/en-us/article/ov50hy/Webex-best-practices-for-secure-meetings:-Control-Hub) · [Customise the lobby](https://help.webex.com/en-us/article/7r8vcg/Webex-App-%7C-Customize-the-lobby) · [Lock or unlock](https://help.webex.com/en-us/article/vjfafi/Lock-or-unlock-your-Webex-meeting) · [CAPTCHA](https://help.webex.com/article/qfb19w/CAPTCHA-for-Webex-Meetings) · [Meetings API](https://developer.webex.com/meeting/docs/meetings)
- **BigBlueButton:** [API reference](https://docs.bigbluebutton.org/development/api/) · [Customisation](https://docs.bigbluebutton.org/administration/customize/) · [New in 3.0](https://docs.bigbluebutton.org/new-features/)
- **Jitsi Meet:** [Lobby module](https://github.com/jitsi/jitsi-meet/blob/master/resources/prosody-plugins/mod_muc_lobby_rooms.lua) · [IFrame API events](https://jitsi.github.io/handbook/docs/dev-guide/iframe-events) · [Token authentication](https://jitsi.github.io/handbook/docs/devops-guide/token-authentication/)
- **Whereby:** [Waiting rooms](https://docs.whereby.com/whereby-product-features/waiting-rooms) · [Lock and knock](https://whereby.helpscoutdocs.com/article/464-lock-knock) · [Meetings REST API](https://docs.whereby.com/reference/whereby-rest-api-reference/meetings) · [Freedom of the Press Foundation review](https://freedom.press/digisec/blog/what-we-know-whereby/)
- **Independent research:** [Ling et al., A First Look at Zoombombing (2021)](https://arxiv.org/abs/2009.03822) · [Ling and Stringhini, EuroUSEC 2024](https://seclab.bu.edu/people/gianluca/papers/zoombombing-eurousec2024.pdf) · [Leporini et al., accessibility of Zoom, Meet and Teams (2022)](https://dl.acm.org/doi/10.1145/3573012) · [CISA SCuBA Teams baseline](https://www.cisa.gov/sites/default/files/2023-12/Teams%20SCB_12.20.2023.pdf) · [University of Michigan Zoom security results](https://safecomputing.umich.edu/sites/default/files/2021-10-20%20Zoom%20Security%20SUMIT%202021%20Presentation%20Slides.pdf)
