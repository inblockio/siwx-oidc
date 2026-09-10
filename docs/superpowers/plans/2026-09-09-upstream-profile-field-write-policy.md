# Handover plan — write-protecting the DID profile field (upstream + interim patch)

**Status:** DRAFT FOR STEELMANNING. Nothing filed, nothing patched, no upstream
comment posted. Author: Claude, 2026-09-09. Decision owner: Tim.

**Headline: do not write our own PR. One already exists, it is active, and it
does exactly what we need — including the admin exemption we depend on.**

---

## 1. What changed since the "we should file a PR" conversation

The plan we discussed was: patch Synapse locally to make `io.inblock.did`
admin-writable-only, and upstream that patch. Searching upstream first found
prior art that makes writing our own implementation the wrong move.

| Ref | What | State |
|---|---|---|
| [element-hq/synapse#18525](https://github.com/element-hq/synapse/issues/18525) | Issue: "Add config to prevent changes to custom profile keys" | open, filed 2025-06-07 by `Periclod` |
| [element-hq/synapse#18562](https://github.com/element-hq/synapse/pull/18562) | First attempt, by `anoadragon453` (Synapse maintainer). Largely Codex-written, self-flagged as such | open, **stale since 2025-07-02**, 0 comments |
| [element-hq/synapse#19980](https://github.com/element-hq/synapse/pull/19980) | Successor by `Barry3D`, picked up #18562's review comments | open, **active**, last push 2026-08-14, CLA signed, maintainer review under way |

The original issue asks for precisely our semantics, in the reporter's own
words: *"I think the same behavior like with displayname and avatar_url where
only admins can set the values would make sense."*

## 2. Why #19980 is exactly what we need — verified against its diff

Both mutation paths are gated, and **`by_admin` is exempt from the gate**:

```python
if not by_admin and self._is_profile_field_disallowed(field_name):
    raise SynapseError(403, "Changing this profile field is disabled on this server", Codes.FORBIDDEN)
```

The same three-line guard is added to `delete_profile_field` (message: "Deleting
this profile field is disabled on this server"). The predicate is allowlist-wins,
denylist-otherwise:

```python
allowlist = self.hs.config.experimental.msc4133_key_allowlist
if allowlist is not None:
    return field_name not in allowlist
denylist = self.hs.config.experimental.msc4133_key_denylist
return denylist is not None and field_name in denylist
```

Consequences for us, all load-bearing:

- **Our write path keeps working.** siwx-oidc's minted admin token carries
  `urn:synapse:admin:*`; MAS's `is_server_admin` is literally
  `"urn:synapse:admin:*" in requester.scope` (`synapse/api/auth/mas.py:274`), and
  the servlet sets `by_admin=is_admin`. So we land on the exempt branch.
- **Deletion is covered too.** A user cannot delete the field to make themselves
  falsely un-attributable. Without this, the protection would be trivially
  sidestepped in one direction.
- **Config surface:** `experimental.msc4133_key_denylist: ["io.inblock.did"]` is
  all we would add to `homeserver.yaml`. Denylist, not allowlist — an allowlist
  would forbid every *other* custom field server-wide, which is not our call to
  make for our users.

Files touched upstream: `config/experimental.py`, `handlers/profile.py`,
`rest/client/capabilities.py`, plus three test files. ~460 lines total, most of
it tests.

## 3. Recommended plan

### 3a. Drive #19980 to merge instead of competing with it

Opening a third implementation would fragment review attention on a PR that is
already 90% there and whose author is responsive. Our leverage is different and
more useful: we are a **production deployment with a concrete use case**, which
is exactly what a stalled config-option PR lacks.

Contribute, in this order:

1. **A use-case comment on #18525 or #19980.** Short: an OIDC/MSC3861 provider
   publishes a server-asserted identity field (the user's DID) into MSC4133
   profiles; without a denylist any user can overwrite their own copy and
   misrepresent their cryptographic identity to other clients. This is the
   missing "why now" for a PR that currently reads as speculative hardening.
2. **Our positions on the author's three open questions** (§4) — they are asked
   in his 2026-08-14 comment and are what the PR is waiting on.
3. **Testing evidence** from dev once we carry the patch (§3b): the denylist
   blocking a user write while the admin-token write succeeds is exactly the
   test matrix a reviewer wants and nobody has run against a real deployment.

Explicit non-goal: do not rewrite his branch or "helpfully" open a rebased
version while he is active. That is how contributors get burned off.

### 3b. Carry #19980 as our interim local patch

Upstream review runs weeks to months, and the maintainer has floated stabilising
MSC4133 *first*, which could push this out further. So we ship the protection
ourselves in the meantime.

- Backport the `handlers/profile.py` + `config/experimental.py` hunks onto our
  pinned `matrixdotorg/synapse:v1.159.0`. Skip `capabilities.py` and the tests:
  the capability advertisement is a client-facing nicety we do not need, and
  every line we skip is a line we do not forward-port.
- **This would be our first Synapse patch.** The image is currently stock
  (`FROM matrixdotorg/synapse:v1.159.0` + `wget` + `yq` + our entrypoint), so
  this creates a new forward-port obligation on every bump — and we were *forced*
  into 1.157→1.159 by a security release once already. It needs the same registry
  discipline as `patches/element-web/README.md`: why, evidence, and an explicit
  retirement condition.
- **Retirement condition:** #19980 merges and appears in a released Synapse we
  have adopted. Then the patch is deleted and only the `homeserver.yaml`
  denylist entry remains.
- The upstream diff targets `develop`; it will not apply cleanly to 1.159.0. The
  patch must be a rebased variant, and it must keep upstream's config key names
  **verbatim** so that adopting the merged version is a no-op for our config.

### 3c. Only if #19980 dies

If the PR is abandoned (author goes quiet AND maintainers do not pick it up),
*then* we file a successor — under Tim's account, from a personal fork, with
"Allow edits by maintainers" enabled so reviewers can push to the branch. Credit
Barry3D and anoadragon453 in the description; it is their design.

## 4. Our positions on the three open questions blocking the PR

These are the author's own open items from 2026-08-14. Having a deploying user
answer them is worth more than another +1.

**Q1 — should deletion of custom profile fields be restricted?**
**Yes, keep it.** A server-asserted field that the user can delete is not
server-asserted. Gating both mutations on one predicate is also simpler to reason
about than a split policy. Counter-argument to be fair to: deletion is
fail-*closed* (a consumer sees nothing rather than something false), so it is
less dangerous than an unrestricted write — but "less dangerous" is not a reason
to leave a hole in a field whose whole purpose is to be authoritative.

**Q2 — how to handle `displayname` / `avatar_url` mixing in the advertised
capability?**
**Keep them out of the custom-field lists.** They already have dedicated
`enable_set_displayname` / `enable_set_avatar_url` knobs with their own
`by_admin` exemptions (`handlers/profile.py:245` and `:367`). Folding them into
the same advertisement makes the capability ambiguous in exactly the way the
author himself worried about — a client cannot tell whether an allowlist is
active or whether it is only seeing the two legacy fields. Two mechanisms, two
advertisements.

**Q3 — should configuring both lists be an error?**
**Yes, fail at startup with a `ConfigError`.** Silent precedence ("allowlist
wins") is a config footgun: an operator who sets both has a mental model that is
already wrong, and the failure mode is a field they believe is denied being
writable. Synapse's house style is to reject contradictory config loudly.

**Q4 — ours to add: the `experimental.msc4133_*` naming is now inconsistent.**
On 1.159.0 `ProfileFieldRestServlet` registers the **stable**
`/_matrix/client/v3/profile/{userId}/{field_name}` route *unconditionally*;
`experimental_features.msc4133_enabled` gates only the redundant
`unstable/uk.tcpip.msc4133/...` alias. So the feature is already de-facto stable
while its new config lives under `experimental`. Worth raising — it is a
concrete, checkable observation, and it partially answers the "stabilise first"
blocker: much of the stabilisation has already happened.

## 5. How this fits the signed-assertion work

These protect different populations and neither replaces the other:

| Mechanism | Protects against | Fails when |
|---|---|---|
| Signed assertion (JWS binding DID + MXID, verifiable via our JWKS) | Forgery, for any consumer that verifies | The consumer does not verify, or does not check the `mxid` claim against the profile it read |
| Denylist (this plan) | Forgery being *possible at all* on our server, for every consumer including those that never verify | The config is wrong, or a future Synapse drops the option |

The denylist covers precisely the population the signature cannot reach: naive
consumers. Because our homeserver is authoritative for our users' profiles and
custom fields **do** federate (`handlers/profile.py::on_profile_query` returns
`get_profile_fields(user)`), the denylist protects remote readers too, not just
on-box ones.

## 6. Risks and objections (steelman targets)

1. **"The patch will outlive its welcome."** Likely true if upstream waits for
   MSC4133 stabilisation. Mitigation: keep it to two hunks, keep config names
   identical to upstream, write the retirement condition into the registry.
2. **"We are protecting a field nobody reads yet."** Fair. Today the only
   consumer class is aqua-agents, whose grant ceremony already requires a
   signature by the DID key, so it is safe without any of this. The protection is
   for the *next* consumer — which is exactly the one that cost us a day.
3. **"A denylist is blunt."** It denies the field to every user with no
   exceptions. That is what we want here, but it means we cannot later let users
   self-assert a *different* DID in the same key. If that is ever desired, it
   needs a second, unprotected field.
4. **"First Synapse patch is a real cost."** Yes — this is the strongest
   objection, and the reason 3b is scoped to two hunks rather than the full PR.
5. **Not yet verified:** whether the rebased hunks apply cleanly to 1.159.0, and
   whether `Codes.FORBIDDEN` and the config plumbing exist unchanged on that tag.
   Must be checked before committing to 3b.

## 7. Open questions for Tim

- Comment upstream under Tim's account, or stay silent and just carry the patch?
  (A production use case posted publicly names inblock.io as an MSC4133 deployer.)
- Carry the interim patch, or wait for upstream and accept an unprotected field
  in the meantime given the signature already covers verifying consumers?
- Denylist entry only, or also switch dev to an allowlist to see the capability
  advertisement behave?
