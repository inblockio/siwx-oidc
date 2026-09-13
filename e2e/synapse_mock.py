#!/usr/bin/env python3
"""Faithful in-memory mock of the Synapse endpoints siwx-oidc calls.

# The route table is a MIRROR of `src/synapse_client.rs`, and it drifts silently

Every route below exists because some function in `src/synapse_client.rs` calls
it. When that file gains, moves or drops an endpoint and this file is not
updated, the mock keeps answering `404`/`401` and the two `#[ignore]`d suites it
drives (`tests/e2e_race_teardown.rs`, `tests/e2e_account_management.rs`) go red
for a reason that has NOTHING to do with the product -- which is how they came
to be quietly unrunnable between commit `db79e75` and the 2026-09-10 audit
(finding D12): they sat outside `cargo test --workspace` AND outside the
e2e-harness check list, so nothing executed them for two structural refactors in
a row. See `e2e/README.md` for the one-line drift check.

# Two credentials, since the Synapse 1.157 port

Synapse 1.157 **deleted** the `experimental_features.msc3861.admin_token` shim
that let the OIDC provider present the MAS shared secret as a server-admin
credential. From 1.157 on the shared secret is honoured on exactly one surface,
and this mock models that split -- because a mock with one credential cannot
catch the class of bug the split introduced (calling an admin route with the
shared secret, which is now a hard 401 in production and used to be fine).

| Surface | Credential | Routes |
|---|---|---|
| `/_synapse/mas/*` | `Authorization: Bearer <SECRET>`, exact string equality | provision_user, upsert_device, allow_cross_signing_reset, is_localpart_available, query_user, delete_device, delete_user, reactivate_user |
| `/_synapse/admin/*` + the AUTHENTICATED C-S API | a **minted admin token** (`src/admin_token.rs`, `msa_` prefix), validated by REAL introspection against siwx-oidc | list_devices (get_device is list+filter), keys/query, PUT profile field |
| the UNauthenticated C-S API | none | GET profile, GET profile field |

The admin surface is NOT a rubber stamp: `_admin_auth` introspects the presented
bearer at `POST {SYNAPSE_MOCK_OIDC_BASE}/oauth2/introspect` (exactly as Synapse's
`MasDelegatedAuth` does, with the same shared-secret client auth) and then
applies Synapse 1.159's own two-step check from `synapse/api/auth/mas.py`:

  1. `active: true` AND the scope grants the C-S API
     (`urn:matrix:client:api:*`, or the MSC2967 unstable twin) -- checked FIRST,
     so an admin-only scope is rejected outright -> 401 `M_UNKNOWN_TOKEN`.
  2. `is_server_admin` is literally `"urn:synapse:admin:*" in requester.scope`
     -> 403 `M_FORBIDDEN` when the token is valid but not admin.

That is the whole point of doing it for real rather than sniffing the `msa_`
prefix: if `admin_token::ADMIN_SCOPE` ever loses either half, or the mint stops
storing the token, these suites go red here instead of in production. A mock
that authorises anything with the right prefix would hide exactly that bug.

**No introspection caching, deliberately.** Real Synapse caches an introspection
result for 2 minutes with no invalidation -- a documented hazard callers are told
not to rely on (`src/admin_token.rs`, "Caller note"). Reproducing it in a test
double would make `__reject_admin_token` and the re-mint-on-401 retry
nondeterministic, so every admin request introspects.

# Routes

  -- MAS surface (shared secret) ---------------------------------------------
  POST   /_synapse/mas/provision_user             synapse_client::provision_user
  POST   /_synapse/mas/upsert_device              synapse_client::upsert_device
  POST   /_synapse/mas/allow_cross_signing_reset  synapse_client::allow_cross_signing_reset
  GET    /_synapse/mas/is_localpart_available     synapse_client::is_localpart_available
  GET    /_synapse/mas/query_user                 synapse_client::query_user
  POST   /_synapse/mas/delete_device              synapse_client::delete_device
  POST   /_synapse/mas/delete_user                synapse_client::deactivate_user
  POST   /_synapse/mas/reactivate_user            synapse_client::reactivate_user

  -- admin surface (minted admin token) --------------------------------------
  GET    /_synapse/admin/v2/users/{mxid}/devices  synapse_client::list_devices (and get_device)
  POST   /_matrix/client/v3/keys/query            synapse_client::has_cross_signing_keys
  PUT    /_matrix/client/v3/profile/{mxid}/{field} synapse_client::publish_did_field

  -- unauthenticated C-S API -------------------------------------------------
  GET    /_matrix/client/v3/profile/{mxid}        synapse_client::has_profile_row
  GET    /_matrix/client/v3/profile/{mxid}/{field} (read-back for tests; the GET
         twin of publish_did_field, which siwx-oidc itself does not call)

  -- test-only control plane (never authenticated, never call-logged) --------
  GET    /__state                 whole in-memory state
  POST   /__reset                 clear everything, restore the real secret
  POST   /__seed_user             mark a localpart as EXISTING (+ profile row)
  POST   /__seed_device           seed a device (implies EXISTING + profile row)
  POST   /__set_secret            change the MAS shared secret (401s that surface)
  POST   /__reject_admin_token    make the ADMIN surface reject, MAS untouched
  POST   /__profile               force a profile row present / empty / absent
  POST   /__fail                  arm a 500/timeout on a logical endpoint

Routes REMOVED by the 1.157 port (`DELETE .../devices/{id}`,
`POST /_synapse/admin/v1/deactivate/{mxid}`, `PUT /_synapse/admin/v2/users/{mxid}`)
answer a loud `410` naming their MAS replacement rather than a bare 404, so a
regression that reverts to the old wire shape is diagnosed at the mock instead of
producing a confusing "device not found".

`is_localpart_available` models EXISTING vs NEW accounts: a localpart that has
been provisioned (provision_user / upsert_device), has a seeded device
(__seed_device), or is explicitly seeded (__seed_user) returns HTTP 400
(M_USER_IN_USE, read by siwx-oidc as an existing account); any other localpart
returns 200 {available:true} (a NEW identity). This lets the new-identity gate
distinguish a returning user from a brand-new one. __reset clears all of it.
"""
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse, parse_qs, urlencode
from urllib.request import Request, urlopen

SECRET = os.environ.get("SYNAPSE_MOCK_SECRET", "testsecret")
PORT = int(os.environ.get("SYNAPSE_MOCK_PORT", "8090"))
# The Matrix server_name this mock pretends to be. MUST match the stack's
# SIWEOIDC_MATRIX_SERVER_NAME: the MAS wire format is localpart-scoped, so the
# mock is the side that turns a localpart back into the `@lp:server` key that
# DEVICES / LIFECYCLE / PROFILES are keyed on (and that the tests assert against).
SERVER_NAME = os.environ.get("SYNAPSE_MOCK_SERVER_NAME", "matrix.test")
# Base URL of the siwx-oidc under test, used to introspect admin tokens exactly
# as Synapse does. Intentionally has NO GUESSED default: inventing a port would
# let the admin surface fail closed for a config reason while looking like a
# product failure. Unset => every admin call answers 401 naming this variable.
#
# `SIWEOIDC_BASE_URL` is accepted as a fallback because it is the stack's own
# authoritative spelling of the same value -- e2e/env.sh, e2e/up.sh and the CI
# job all export it -- so reading it is not a guess. Without this, a harness
# that sets only the standard variable (the `rust-e2e-mock` CI job does) gets a
# mock that cannot authorise ANY admin call, which surfaces as a 400 on
# `devices_list` and reads exactly like a product bug.
OIDC_BASE = (
    os.environ.get("SYNAPSE_MOCK_OIDC_BASE")
    or os.environ.get("SIWEOIDC_BASE_URL")
    or ""
).rstrip("/")
INTROSPECT_TIMEOUT = float(os.environ.get("SYNAPSE_MOCK_INTROSPECT_TIMEOUT", "5"))

# Scopes from `src/admin_token.rs::ADMIN_SCOPE`. Both halves are load-bearing;
# see the module docstring above for Synapse's two-step check.
MATRIX_API_SCOPE = "urn:matrix:client:api:*"
MATRIX_API_SCOPE_UNSTABLE = "urn:matrix:org.matrix.msc2967.client:api:*"
SYNAPSE_ADMIN_SCOPE = "urn:synapse:admin:*"

LOCK = threading.Lock()
# user_id ("@lp:server") -> list[device dict]
DEVICES = {}
# Set of localparts that EXIST on this homeserver. Drives the contract of
# GET /_synapse/mas/is_localpart_available: a localpart NOT in this set is
# "available" (HTTP 200 -> the siwx-oidc gate reads it as a NEW identity); a
# localpart in this set is taken (HTTP 400 M_USER_IN_USE -> EXISTING identity).
#
# A user becomes existing when it is provisioned (provision_user / upsert_device),
# when a device is seeded for it (__seed_device), or when it is explicitly seeded
# (__seed_user). This faithfully models the real Synapse: an account that has been
# provisioned or carries devices exists. Without it the mock answered "available"
# for everyone, which made the new-identity gate (correctly) reject every account /
# QR re-auth — masking the real behaviour the lifecycle suite relies on.
EXISTING_USERS = set()
# user_id -> {"deactivated": bool, "erased": bool}
LIFECYCLE = {}
# user_id -> {"displayname": str|None, "avatar_url": str|None}
#
# PRESENCE OF THE KEY IS THE `profiles` ROW. Synapse's `users` row and its
# `profiles` row are separate, and an account can have the first without the
# second — that is element-hq/synapse#19702, still unfixed in 1.159.0, and the
# condition `has_profile_row` / `publish_did_field` discriminate on. So
# `localpart in EXISTING_USERS` (users row) and `user_id in PROFILES` (profiles
# row) are modelled as two INDEPENDENT facts. Do not collapse them.
PROFILES = {}
# user_id -> {field_name: json value} — MSC4133 custom profile fields, which is
# where `publish_did_field` writes `io.inblock.did`.
PROFILE_FIELDS = {}
CALL_LOG = []  # list of "METHOD path"
# Mutable expected secret (so a test can flip it to force 401s) and the
# admin-surface kill switch (see __reject_admin_token).
STATE = {"secret": SECRET, "reject_admin": False}
# Per-logical-endpoint fault injection (H14). Maps a logical endpoint name to a
# mode string: "500" returns HTTP 500, "timeout" sleeps long enough that the
# siwx-oidc reqwest client times out. Cleared by /__reset.
#   POST /__fail {"endpoint": "delete_device", "mode": "500"|"timeout"|"off"}
# Recognized endpoints: delete_device, list_devices, deactivate, query_user,
# publish_did_field. ("get_device" is gone as a fault target because
# `synapse_client::get_device` no longer has a route of its own — since the 1.157
# port it is `list_devices` plus a client-side filter, so fault it via
# "list_devices".)
FAIL = {}
# How long a "timeout" fault sleeps before (not) responding, in seconds. Must
# exceed the siwx-oidc Synapse HTTP client timeout so the call fails.
TIMEOUT_SLEEP_SECS = float(os.environ.get("SYNAPSE_MOCK_TIMEOUT_SLEEP", "30"))
# Counts effective device-delete operations per (user_id, device_id) so a race
# test can prove at most one delete actually mutated state. Distinct from
# CALL_LOG (which records every request, including idempotent no-ops).
EFFECTIVE_DELETES = {}

# Twisted's generic 500 body. element-hq/synapse#19702 surfaces as an uncaught
# TypeError, so its 500 is BYTE-IDENTICAL to the 500 from an exhausted database
# connection pool — which is precisely why `publish_did_field` must confirm a
# row-less account with a probe instead of inferring it from the status code
# (audit finding D1). Emitting the real generic body here is what makes that
# distinction testable at all.
GENERIC_500 = {"errcode": "M_UNKNOWN", "error": "Internal server error"}


def _localpart_of(user_id):
    """Extract the localpart from an mxid `@localpart:server` (or pass through a
    bare localpart). Mirrors how siwx-oidc queries is_localpart_available with the
    `did_to_localpart` value, so the seeded mxid and the queried localpart match."""
    if not user_id:
        return user_id
    s = user_id[1:] if user_id.startswith("@") else user_id
    return s.split(":", 1)[0]


def _mxid(localpart):
    return f"@{localpart}:{SERVER_NAME}"


def _device(device_id, display_name=None, last_seen_ip=None, last_seen_ts=None):
    return {
        "device_id": device_id,
        "display_name": display_name,
        "last_seen_ip": last_seen_ip,
        "last_seen_ts": last_seen_ts,
        "user_id": None,
    }


def _mark_existing(localpart):
    """Record a `users` row, and NOTHING else. Caller must hold LOCK.

    Deliberately does not touch PROFILES. The `users` row and the `profiles` row
    are independent facts (see the PROFILES comment), and a helper that quietly
    created both would make the row-less state — element-hq/synapse#19702, the
    condition `has_profile_row` and `publish_did_field` exist to discriminate —
    unreachable: `upsert_device` would keep healing it as a side effect of
    provisioning a device, which is not something Synapse does.
    """
    if localpart:
        EXISTING_USERS.add(localpart)


def _mark_profile(localpart, displayname=None):
    """Record a `profiles` row (and the `users` row that must accompany it).

    Caller must hold LOCK.

    A normal Synapse account has both, so this is what `provision_user` and the
    seed helpers use. The row-less state is the ANOMALY and is reachable only by
    asking for it explicitly via `POST /__profile {"state": "absent"}` —
    otherwise every test in both suites would incidentally exercise the #19702
    self-heal path and the tests that mean to exercise it would prove nothing.
    """
    if not localpart:
        return
    EXISTING_USERS.add(localpart)
    uid = _mxid(localpart)
    if uid not in PROFILES:
        PROFILES[uid] = {"displayname": displayname, "avatar_url": None}
    elif displayname is not None:
        PROFILES[uid]["displayname"] = displayname


def _introspect(token):
    """Introspect `token` at the siwx-oidc under test, as Synapse's
    `MasDelegatedAuth` does. Returns `(response_dict, error_string)`.

    Client-authenticates with `STATE["secret"]` — the SAME value this mock
    compares MAS bearers against — because that is what Synapse does: the
    introspection client secret and `matrix_authentication_service.secret` are
    one configured value. Keeping them tied means `__set_secret` stays a
    coherent simulation of "the operator's shared secret is wrong" rather than
    two independent knobs.
    """
    if not OIDC_BASE:
        return None, (
            "neither SYNAPSE_MOCK_OIDC_BASE nor SIWEOIDC_BASE_URL is set, so "
            "this mock cannot introspect admin tokens; set one to the siwx-oidc "
            "base URL (see e2e/up.sh)"
        )
    data = urlencode({"token": token, "token_type_hint": "access_token"}).encode()
    req = Request(f"{OIDC_BASE}/oauth2/introspect", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", f"Bearer {STATE['secret']}")
    try:
        with urlopen(req, timeout=INTROSPECT_TIMEOUT) as r:
            return json.loads(r.read() or b"{}"), None
    except Exception as e:  # noqa: BLE001 — any failure is an auth failure here
        return None, f"introspection call failed: {e}"


class Handler(BaseHTTPRequestHandler):
    # quieter logging
    def log_message(self, fmt, *args):
        sys.stderr.write("[synapse-mock] " + (fmt % args) + "\n")

    # -- helpers ----------------------------------------------------------
    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _send(self, code, obj=None):
        payload = json.dumps(obj if obj is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _bearer(self):
        v = self.headers.get("Authorization", "")
        return v[7:] if v.startswith("Bearer ") else None

    def _mas_authed(self):
        """MAS surface auth: exact string equality against the shared secret.

        `synapse/rest/synapse/mas/__init__.py` compares the bearer to
        `matrix_authentication_service.secret` verbatim. There is no token
        lookup and no scope — presenting anything else is a 401.
        """
        return self._bearer() == STATE["secret"]

    def _admin_auth(self):
        """Admin surface auth. Returns `None` when authorised, else `(code, body)`.

        Implements Synapse 1.159's `MasDelegatedAuth.get_user_by_access_token`
        followed by `is_server_admin`, against a REAL introspection of the
        presented token. See the module docstring for why this is not a prefix
        sniff.
        """
        if STATE["reject_admin"]:
            # Models Synapse refusing the minted credential without the MAS
            # shared secret being wrong — see __reject_admin_token.
            return 401, {
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "admin token rejected (forced by /__reject_admin_token)",
            }
        token = self._bearer()
        if not token:
            return 401, {"errcode": "M_MISSING_TOKEN", "error": "no access token"}
        if token == STATE["secret"]:
            # THE regression this whole split exists to catch: presenting the MAS
            # shared secret on the admin surface. Honoured before 1.157, a hard
            # 401 from 1.157 on. Answer exactly what production answers.
            return 401, {
                "errcode": "M_UNKNOWN_TOKEN",
                "error": (
                    "the MAS shared secret is not an access token on this surface; "
                    "Synapse 1.157 deleted the admin_token shim — mint an "
                    "admin-scoped token instead (src/admin_token.rs)"
                ),
            }
        introspection, err = _introspect(token)
        if err:
            return 401, {"errcode": "M_UNKNOWN_TOKEN", "error": err}
        if not introspection.get("active"):
            return 401, {"errcode": "M_UNKNOWN_TOKEN", "error": "token is not active"}
        scope = (introspection.get("scope") or "").split()
        # Step 1: the C-S API scope is checked FIRST, so an admin-only scope is
        # rejected outright rather than granting admin.
        if MATRIX_API_SCOPE not in scope and MATRIX_API_SCOPE_UNSTABLE not in scope:
            return 401, {
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Token doesn't grant access to the Matrix C-S API",
            }
        # Step 2: is_server_admin(requester) == "urn:synapse:admin:*" in scope.
        if SYNAPSE_ADMIN_SCOPE not in scope:
            return 403, {
                "errcode": "M_FORBIDDEN",
                "error": f"You are not a server admin (scope lacks {SYNAPSE_ADMIN_SCOPE})",
            }
        return None

    def _log(self, method, path):
        with LOCK:
            CALL_LOG.append(f"{method} {path}")

    def _maybe_fail(self, endpoint):
        """If a fault is armed for `endpoint`, enact it and return True.

        "500"     -> respond 500 immediately.
        "timeout" -> sleep past the client's timeout, then respond 500 (the
                     siwx-oidc client will already have given up). Returns True
                     either way so the caller skips its normal handling.
        """
        with LOCK:
            mode = FAIL.get(endpoint)
        if not mode or mode == "off":
            return False
        if mode == "timeout":
            time.sleep(TIMEOUT_SLEEP_SECS)
            try:
                self._send(500, {"errcode": "M_UNKNOWN", "error": "simulated timeout"})
            except Exception:
                pass
            return True
        # default: "500"
        self._send(500, {"errcode": "M_UNKNOWN", "error": "simulated failure"})
        return True

    def _ported_away(self, replacement):
        """Answer a route the 1.157 port moved onto `/_synapse/mas/*`.

        A bare 404 here would reach the caller as "device not found" / "user not
        found" and send whoever is debugging after a phantom state bug. The 410
        and the errcode are deliberately NOT Synapse-shaped: nothing in
        production emits them, so seeing one is unambiguously "this mock was
        called on a route siwx-oidc must no longer use".
        """
        return self._send(410, {
            "errcode": "SIWX_MOCK_PORTED_ROUTE",
            "error": (
                f"this route was removed from siwx-oidc by the Synapse 1.157 port; "
                f"use {replacement}"
            ),
        })

    # -- routing ----------------------------------------------------------
    def do_GET(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        # test introspection (no auth)
        if path == "/__state":
            with LOCK:
                return self._send(200, {
                    "devices": DEVICES,
                    "lifecycle": LIFECYCLE,
                    "calls": list(CALL_LOG),
                    "fail": dict(FAIL),
                    "effective_deletes": dict(EFFECTIVE_DELETES),
                    "existing_users": sorted(EXISTING_USERS),
                    "profiles": PROFILES,
                    "profile_fields": PROFILE_FIELDS,
                    "reject_admin": STATE["reject_admin"],
                })
        if path == "/health":
            return self._send(200, {"ok": True})
        # Log BEFORE authenticating. A request log that silently drops rejected
        # requests is a debugging trap: the 1.157 port's symptom was a stream of
        # 401s, and the old mock's call log showed nothing at all.
        self._log("GET", path)

        # -- unauthenticated C-S API ---------------------------------------
        # GET /_matrix/client/v3/profile/{mxid}/{field}  (read-back for tests)
        m = re.match(r"^/_matrix/client/v3/profile/([^/]+)/(.+)$", path)
        if m:
            return self._profile_field_get(m.group(1), m.group(2))
        # GET /_matrix/client/v3/profile/{mxid}  (has_profile_row)
        m = re.match(r"^/_matrix/client/v3/profile/([^/]+)$", path)
        if m:
            return self._profile_get(m.group(1))

        # -- admin surface --------------------------------------------------
        # GET /_synapse/admin/v2/users/{user_id}/devices  (list_devices)
        m = re.match(r"^/_synapse/admin/v2/users/([^/]+)/devices$", path)
        if m:
            denied = self._admin_auth()
            if denied:
                return self._send(*denied)
            if self._maybe_fail("list_devices"):
                return
            user_id = m.group(1)
            with LOCK:
                devs = DEVICES.get(user_id, [])
                return self._send(200, {"devices": devs, "total": len(devs)})
        # GET /_synapse/admin/v2/users/{user_id}/devices/{device_id}
        if re.match(r"^/_synapse/admin/v2/users/(.+)/devices/(.+)$", path):
            # Not "ported away" — this route still exists on real Synapse. It is
            # siwx-oidc that stopped using it: `get_device` is now `list_devices`
            # plus a client-side filter, which is what scopes the lookup to the
            # authenticated user. Answering 410 keeps the mock honest about the
            # call list it mirrors.
            return self._ported_away(
                "synapse_client::get_device (list_devices + client-side filter)"
            )

        # -- MAS surface ----------------------------------------------------
        if p.path.startswith("/_synapse/mas/"):
            if not self._mas_authed():
                return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
            qs = parse_qs(p.query)
            localpart = (qs.get("localpart") or [""])[0]
            # GET /_synapse/mas/is_localpart_available
            if p.path.startswith("/_synapse/mas/is_localpart_available"):
                with LOCK:
                    exists = localpart in EXISTING_USERS
                if exists:
                    # Taken. NOTE the errcode is load-bearing: since 2026-09-12
                    # the client reads ONLY `M_USER_IN_USE` as "taken"
                    # (`classify_localpart_refusal`). `M_INVALID_USERNAME` /
                    # `M_EXCLUSIVE` mean "Synapse refuses this name", and every
                    # other 4xx is INDETERMINATE and becomes an Err. The old
                    # "any 4xx = not available" behaviour this comment used to
                    # describe was the defect, not the contract.
                    # (an EXISTING account), so the new-identity gate does NOT reject.
                    return self._send(400, {"errcode": "M_USER_IN_USE", "error": "in use"})
                return self._send(200, {"available": True})
            # GET /_synapse/mas/query_user  (synapse_client::query_user)
            #
            # Backs `webauthn::reject_if_deactivated`, the sign-in gate that
            # stops a deactivated account signing straight back in. Its absence
            # from the old mock is why seven race/teardown tests failed: the gate
            # fails CLOSED on a probe error, so a 404 from the mock turned every
            # account re-auth into a 401 "this account has been deactivated".
            if p.path.startswith("/_synapse/mas/query_user"):
                if self._maybe_fail("query_user"):
                    return
                with LOCK:
                    exists = localpart in EXISTING_USERS
                    life = LIFECYCLE.get(_mxid(localpart), {})
                    profile = PROFILES.get(_mxid(localpart), {})
                if not exists:
                    # `MasQueryUserResource` answers 404 for an unknown account;
                    # the client maps that to Ok(None) — the new-identity case,
                    # which a DIFFERENT gate owns.
                    return self._send(404, {"errcode": "M_NOT_FOUND", "error": "User not found"})
                return self._send(200, {
                    "user_id": _mxid(localpart),
                    "display_name": profile.get("displayname"),
                    "avatar_url": profile.get("avatar_url"),
                    "is_suspended": False,
                    "is_deactivated": bool(life.get("deactivated", False)),
                })
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    # -- profile helpers ---------------------------------------------------
    def _profile_get(self, raw_user_id):
        """GET /_matrix/client/v3/profile/{mxid} — the `has_profile_row` probe.

        Reproduces the THREE measured response shapes that
        `synapse_client::profile_404_means_row_absent` discriminates between
        (see its table; live-verified on 1.154.0 and re-verified 2026-09-10).
        Getting these wrong in the mock would make the 2026-08-02 fix — the one
        that stopped the self-heal clobbering a deliberately-cleared displayname
        — untestable.

        Unauthenticated on purpose: `ProfileRestServlet.on_GET` authenticates
        only when `require_auth_for_profile_requests` is set, and it defaults to
        False (`config/server.py`).
        """
        user_id = unquote(raw_user_id)
        with LOCK:
            has_row = user_id in PROFILES
            profile = dict(PROFILES.get(user_id, {}))
        if not has_row:
            # TRULY ABSENT: a `users` row with no `profiles` row.
            return self._send(404, {"errcode": "M_UNKNOWN", "error": "No row found (profiles)"})
        displayname = profile.get("displayname")
        avatar_url = profile.get("avatar_url")
        if displayname is None and avatar_url is None:
            # PRESENT BUT EMPTY. Synapse also 404s this — with a DIFFERENT
            # errcode, which is the only thing separating it from the case above.
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": "Profile was not found"})
        out = {}
        if displayname is not None:
            out["displayname"] = displayname
        if avatar_url is not None:
            out["avatar_url"] = avatar_url
        return self._send(200, out)

    def _profile_field_get(self, raw_user_id, field):
        """GET /_matrix/client/v3/profile/{mxid}/{field} (MSC4133).

        siwx-oidc DOES call this in production: since `/resolve` shipped it is
        that endpoint's read path (`synapse_client::read_did_field`), which since
        2026-09-13 reads ANONYMOUSLY first and only mints a token if the
        homeserver answers 401/403. Tests also call it, to read back what
        `publish_did_field` wrote. A row-less account 500s here rather than
        404ing because element-hq/synapse#19702 bites on READS too:
        `get_profile_field` subscripts an unguarded `txn.fetchone()`.
        """
        user_id = unquote(raw_user_id)
        with LOCK:
            has_row = user_id in PROFILES
            value = PROFILE_FIELDS.get(user_id, {}).get(field, KeyError)
        if not has_row:
            return self._send(500, GENERIC_500)
        if value is KeyError:
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": "Profile field not found"})
        return self._send(200, {field: value})

    def do_POST(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        body = self._body()
        # test helpers (no auth, never call-logged) ------------------------
        if path == "/__seed_device":
            uid = body.get("user_id") or _mxid(body["localpart"])
            with LOCK:
                DEVICES.setdefault(uid, []).append(_device(
                    body["device_id"], body.get("display_name"),
                    body.get("last_seen_ip"), body.get("last_seen_ts")))
                # A user that carries a device EXISTS (so the new-identity gate
                # treats it as a returning account, not a fresh registration),
                # and a normal pre-existing account has a profile row too.
                _mark_profile(_localpart_of(uid))
            return self._send(200, {"ok": True, "user_id": uid})
        # Explicitly mark a user as EXISTING without seeding a device. Accepts a
        # `user_id` mxid or a bare `localpart`. Used to test flows that must
        # distinguish a returning account from a brand-new identity.
        if path == "/__seed_user":
            lp = body.get("localpart") or _localpart_of(body.get("user_id", ""))
            with LOCK:
                _mark_profile(lp)
            return self._send(200, {"ok": True, "localpart": lp})
        # Force a user's `profiles` row into one of the three states
        # `has_profile_row` must tell apart:
        #   "present" — a row with a displayname            -> GET 200
        #   "empty"   — a row with displayname+avatar null  -> GET 404 M_NOT_FOUND
        #   "absent"  — NO row (element-hq/synapse#19702)   -> GET 404 M_UNKNOWN,
        #                                                      field PUT/GET 500
        # Deliberately independent of EXISTING_USERS: the whole bug class is a
        # `users` row without a `profiles` row.
        if path == "/__profile":
            uid = body.get("user_id") or _mxid(body.get("localpart", ""))
            state = body.get("state", "present")
            with LOCK:
                if state == "absent":
                    PROFILES.pop(uid, None)
                    # MSC4133 custom fields live in the same `profiles` row, so
                    # no row means no fields. Leaving them behind would let a
                    # test read back a value the homeserver could not serve.
                    PROFILE_FIELDS.pop(uid, None)
                elif state == "empty":
                    PROFILES[uid] = {"displayname": None, "avatar_url": None}
                else:
                    PROFILES[uid] = {
                        "displayname": body.get("displayname", "seeded"),
                        "avatar_url": body.get("avatar_url"),
                    }
            return self._send(200, {"ok": True, "user_id": uid, "state": state})
        if path == "/__reset":
            with LOCK:
                DEVICES.clear(); LIFECYCLE.clear(); CALL_LOG.clear()
                FAIL.clear(); EFFECTIVE_DELETES.clear()
                EXISTING_USERS.clear(); PROFILES.clear(); PROFILE_FIELDS.clear()
                STATE["secret"] = SECRET
                STATE["reject_admin"] = False
            return self._send(200, {"ok": True})
        if path == "/__set_secret":
            with LOCK:
                STATE["secret"] = body.get("secret", SECRET)
            return self._send(200, {"ok": True})
        # Make the ADMIN surface reject every token while leaving the MAS shared
        # secret intact.
        #
        # Since the 1.157 port these are two DIFFERENT credentials, so
        # `__set_secret` can no longer isolate an admin-token failure: a wrong
        # shared secret breaks `query_user` first, and the deactivated-account
        # gate (`webauthn::reject_if_deactivated`) then fails closed with a 401
        # before any admin call is ever attempted. This knob is the admin half of
        # what `__set_secret` used to cover on its own.
        if path == "/__reject_admin_token":
            with LOCK:
                STATE["reject_admin"] = bool(body.get("reject", True))
            return self._send(200, {"ok": True, "reject_admin": STATE["reject_admin"]})
        # Arm/disarm a fault on a logical endpoint (H14). mode "off"/absent clears.
        if path == "/__fail":
            endpoint = body.get("endpoint", "")
            mode = body.get("mode", "off")
            with LOCK:
                if not endpoint or mode in ("off", None):
                    FAIL.pop(endpoint, None)
                else:
                    FAIL[endpoint] = mode
            return self._send(200, {"ok": True, "fail": dict(FAIL)})

        self._log("POST", path)

        # -- admin surface --------------------------------------------------
        if path == "/_matrix/client/v3/keys/query":
            denied = self._admin_auth()
            if denied:
                return self._send(*denied)
            # report no master cross-signing key (keeps pre-flight warnings off)
            return self._send(200, {"master_keys": {}})

        # -- routes the 1.157 port moved onto /_synapse/mas/* ----------------
        if re.match(r"^/_synapse/admin/v1/deactivate/(.+)$", path):
            return self._ported_away("POST /_synapse/mas/delete_user")

        # -- MAS surface ----------------------------------------------------
        if not path.startswith("/_synapse/mas/"):
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})
        if not self._mas_authed():
            return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
        if path == "/_synapse/mas/provision_user":
            lp = body.get("localpart")
            with LOCK:
                known = lp in EXISTING_USERS
                has_row = _mxid(lp) in PROFILES
            # element-hq/synapse#19702 ALSO makes the repair inert. `provision_user`
            # with a `set_displayname` runs `_check_profile_size`, which subscripts
            # an unguarded `txn.fetchone()`, so writing a displayname onto an
            # account that has a `users` row but NO `profiles` row raises an
            # uncaught TypeError -> generic 500. That is why
            # `oidc::provision_synapse_device`'s self-heal is documented as
            # "currently inert ... and self-activates once the pinned Synapse image
            # is bumped past that fix".
            #
            # Modelled deliberately: a mock that let the heal succeed would be MORE
            # forgiving than production, and would turn the one e2e test of the
            # row-less path into a proof of behaviour no deployed homeserver has.
            # A brand-new account is unaffected — it gets both rows at once.
            if known and not has_row and body.get("set_displayname") is not None:
                return self._send(500, GENERIC_500)
            with LOCK:
                _mark_profile(lp, body.get("set_displayname"))
            return self._send(200, {})
        if path == "/_synapse/mas/upsert_device":
            uid = _mxid(body["localpart"])
            with LOCK:
                # Provisioning a device implies the user EXISTS — but it does
                # NOT create a profile row. Synapse's device handler never
                # touches `profiles`, and pretending otherwise would silently
                # repair every row-less account.
                _mark_existing(body["localpart"])
                devs = DEVICES.setdefault(uid, [])
                if not any(d["device_id"] == body["device_id"] for d in devs):
                    devs.append(_device(body["device_id"], body.get("display_name")))
            return self._send(200, {})
        if path == "/_synapse/mas/allow_cross_signing_reset":
            return self._send(200, {})
        # POST /_synapse/mas/delete_device {localpart, device_id}
        #
        # Ported from DELETE /_synapse/admin/v2/users/{mxid}/devices/{id}. Same
        # `device_handler.delete_devices` underneath; only the wire format and
        # the credential changed. Answers 204 on real Synapse — modelled, so a
        # client that starts requiring a JSON body back fails here too.
        if path == "/_synapse/mas/delete_device":
            if self._maybe_fail("delete_device"):
                return
            uid = _mxid(body.get("localpart", ""))
            device_id = body.get("device_id", "")
            with LOCK:
                devs = DEVICES.get(uid, [])
                existed = any(d["device_id"] == device_id for d in devs)
                DEVICES[uid] = [d for d in devs if d["device_id"] != device_id]
                if existed:
                    # Count only the delete that actually mutated state, so a race
                    # test can assert at most one *effective* deletion occurred.
                    key = f"{uid}/{device_id}"
                    EFFECTIVE_DELETES[key] = EFFECTIVE_DELETES.get(key, 0) + 1
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # POST /_synapse/mas/delete_user {localpart, erase}
        #
        # NOT a deletion despite the name: a pass-through to the same
        # `deactivate_account_handler.deactivate_account(user_id, erase_data=erase)`
        # the old admin route reached. erase=false is reversible via
        # reactivate_user; erase=true is GDPR erasure and purges the profile.
        if path == "/_synapse/mas/delete_user":
            if self._maybe_fail("deactivate"):
                return
            if "erase" not in body or not isinstance(body["erase"], bool):
                # `erase` is a required StrictBool in the MAS request model — no
                # default and no coercion from "true"/1. Omitting it must FAIL,
                # not quietly pick the safe value, or a client that forgot it
                # would look fine here and erase nothing in production.
                return self._send(400, {
                    "errcode": "M_INVALID_PARAM",
                    "error": "`erase` is required and must be a JSON boolean",
                })
            uid = _mxid(body.get("localpart", ""))
            erase = body["erase"]
            with LOCK:
                LIFECYCLE[uid] = {"deactivated": True, "erased": erase}
                # deactivation drops the account's devices
                DEVICES[uid] = []
                if erase:
                    # GDPR erasure purges the profile row. This is what makes an
                    # erased account read as "truly absent" to has_profile_row —
                    # a documented, accepted interplay, not an accident.
                    PROFILES.pop(uid, None)
                    PROFILE_FIELDS.pop(uid, None)
            return self._send(200, {})
        # POST /_synapse/mas/reactivate_user {localpart}
        if path == "/_synapse/mas/reactivate_user":
            uid = _mxid(body.get("localpart", ""))
            with LOCK:
                cur = LIFECYCLE.get(uid, {"deactivated": False, "erased": False})
                if cur.get("erased"):
                    # Only an erase=false deactivation can be restored.
                    return self._send(400, {
                        "errcode": "M_UNKNOWN",
                        "error": "cannot reactivate an erased account",
                    })
                cur["deactivated"] = False
                LIFECYCLE[uid] = cur
            return self._send(200, {})
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def do_DELETE(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        self._log("DELETE", path)
        if re.match(r"^/_synapse/admin/v2/users/(.+)/devices/(.+)$", path):
            return self._ported_away("POST /_synapse/mas/delete_device")
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def do_PUT(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        body = self._body()
        self._log("PUT", path)
        # PUT /_matrix/client/v3/profile/{mxid}/{field}  (publish_did_field)
        m = re.match(r"^/_matrix/client/v3/profile/([^/]+)/(.+)$", path)
        if m:
            return self._profile_field_put(m.group(1), m.group(2), body)
        if re.match(r"^/_synapse/admin/v2/users/(.+)$", path):
            return self._ported_away("POST /_synapse/mas/reactivate_user")
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def _profile_field_put(self, raw_user_id, field, body):
        """PUT /_matrix/client/v3/profile/{mxid}/{field} — `publish_did_field`.

        Requires an ADMIN token, and not merely a valid one:
        `handlers/profile.py` on 1.159 reads
        `if not by_admin and target_user != requester.user: raise AuthError(403)`,
        and under MAS `by_admin` is `"urn:synapse:admin:*" in requester.scope`.
        Writing another user's profile is only possible through that exemption,
        which is exactly what `_admin_auth` models — so a scope regression in
        `admin_token::ADMIN_SCOPE` surfaces here as a 403, not as silence.
        """
        # Admin auth FIRST: Synapse authenticates before it looks anything up, so
        # an unauthorised caller learns nothing about which mxids exist.
        denied = self._admin_auth()
        if denied:
            return self._send(*denied)
        if self._maybe_fail("publish_did_field"):
            return
        user_id = unquote(raw_user_id)
        with LOCK:
            known = _localpart_of(user_id) in EXISTING_USERS
            has_row = user_id in PROFILES
        if not known:
            # The stable v3 profile route is registered unconditionally, so a 404
            # means the mxid is unknown to this homeserver — never "no such
            # field". `publish_did_field` treats it as a genuine error.
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": "User not found"})
        if not has_row:
            # element-hq/synapse#19702: `_check_profile_size` subscripts an
            # unguarded `txn.fetchone()` -> uncaught TypeError -> Twisted's
            # GENERIC 500. Byte-identical to a 500 from a dead database, which is
            # why the client must confirm with has_profile_row before excusing it.
            return self._send(500, GENERIC_500)
        # MSC4133's PUT body echoes the field name as its single key.
        if field not in body:
            return self._send(400, {
                "errcode": "M_BAD_JSON",
                "error": f"body must carry the field name `{field}` as its key",
            })
        with LOCK:
            PROFILE_FIELDS.setdefault(user_id, {})[field] = body[field]
        return self._send(200, {})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write(
        f"[synapse-mock] listening on 127.0.0.1:{PORT} secret={SECRET!r} "
        f"server_name={SERVER_NAME!r} oidc_base={OIDC_BASE!r}\n"
    )
    srv.serve_forever()
