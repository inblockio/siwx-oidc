#!/usr/bin/env python3
"""Faithful in-memory mock of the Synapse endpoints siwx-oidc calls.

Mirrors the exact contract in src/synapse_client.rs. Synapse 1.157 DELETED the
`admin_token` shim that let the MAS shared secret stand in for a server-admin
credential, so there are two auth surfaces and this mock models both:

  `Bearer <SECRET>` -- the MAS shared secret (SYNAPSE_MOCK_SECRET, default
  "testsecret"), honoured ONLY on /_synapse/mas/*:
    GET    /_synapse/mas/is_localpart_available
    GET    /_synapse/mas/query_user
    POST   /_synapse/mas/provision_user
    POST   /_synapse/mas/upsert_device
    POST   /_synapse/mas/allow_cross_signing_reset
    POST   /_synapse/mas/delete_device
    POST   /_synapse/mas/delete_user      (deactivate; `erase` is the GDPR flag)
    POST   /_synapse/mas/reactivate_user

  `Bearer msa_...` -- a minted, admin-scoped access token (src/admin_token.rs),
  validated by INTROSPECTING it back against siwx-oidc:
    GET    /_synapse/admin/v2/users/{user_id}/devices
    GET    /_synapse/admin/v2/users/{user_id}/devices/{device_id}
    POST   /_matrix/client/v3/keys/query

Admin-surface auth is NOT a prefix check. The mock POSTs the presented bearer to
`${SIWEOIDC_BASE_URL}/oauth2/introspect` (RFC 7662; form body `token=...`,
authenticated with the MAS shared secret) and requires all four of the conditions
`src/admin_token.rs` documents, which were read off Synapse 1.159's
`MasDelegatedAuth.get_user_by_access_token` (synapse/api/auth/mas.py):

  1. `active: true`, and `exp`/`expires_in` not elapsed.
  2. `scope` carries BOTH the Matrix C-S API scope `urn:matrix:client:api:*` (or
     its MSC2967 unstable twin) AND `urn:synapse:admin:*`. Synapse checks the
     C-S scope FIRST, so an admin-only scope string is rejected outright.
  3. `username` is present and resolves to an existing user (EXISTING_USERS
     here, `store.get_user_by_id` there).
  4. `device_id` is absent/null, or names a device that exists. An empty string
     is NOT "absent": Synapse reads it as a zero-length device id and raises
     AuthError(500, "Invalid device ID in introspection result"). This mock
     answers that same HTTP 500 -- deliberately NOT a 401 -- because that branch
     is the regression guard for `render_device_id` in src/introspect.rs, which
     renders a deviceless token's `device_id` as JSON `null`.

Introspection FAILS CLOSED: a timeout (INTROSPECT_TIMEOUT_SECS), a connection
error, a non-2xx, or an undecodable body all reject. Results are never cached --
Synapse's own 2-minute introspection cache is a Synapse behaviour, and caching
it here would hide the revocation timing this mock exists to expose. Only the
Python stdlib is used; the mock has no third-party dependencies and must keep
none.

The introspection credential is the mock's CURRENT STATE["secret"], because in
production Synapse and MAS share ONE secret -- so __set_secret now breaks BOTH
surfaces, which is faithful. Presenting that shared secret as a bearer on the
admin surface still answers 401 M_UNKNOWN_TOKEN, exactly as 1.159 does: it is a
secret, not a token, so it introspects to `{"active": false}`.
__set_admin_token_valid remains the independent lever, a short-circuit checked
BEFORE introspection, and is still the only way to express "Synapse rejected the
admin token while /_synapse/mas/* keeps working". A test that wants that must
use it; breaking the secret instead fails earlier, on the MAS deactivation probe
the login path runs before any admin call, and never reaches an admin call at
all.

The legacy admin routes (POST /_synapse/admin/v1/deactivate/{user_id},
DELETE /_synapse/admin/v2/users/{user_id}/devices/{device_id},
PUT /_synapse/admin/v2/users/{user_id}) are kept on the admin surface but are no
longer called by siwx-oidc; they were ported to /_synapse/mas/* in b9c1af6.

State is in-memory; test-only helpers live under /__.

`is_localpart_available` models EXISTING vs NEW accounts: a localpart that has been
provisioned (provision_user / upsert_device), has a seeded device (__seed_device), or
is explicitly seeded (POST /__seed_user {localpart|user_id}) returns HTTP 400
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
from urllib.parse import unquote, urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen

SECRET = os.environ.get("SYNAPSE_MOCK_SECRET", "testsecret")
PORT = int(os.environ.get("SYNAPSE_MOCK_PORT", "8090"))
SERVER_NAME = os.environ.get("SYNAPSE_MOCK_SERVER_NAME", "matrix.test")
# Where the mock introspects admin-surface bearers: siwx-oidc itself. Both CI
# jobs and e2e/up.sh export SIWEOIDC_BASE_URL; the default matches e2e/env.sh.
# There is deliberately NO admin-token prefix constant any more: real Synapse
# does not look at the prefix, it introspects, and so does this mock.
SIWEOIDC_BASE_URL = os.environ.get("SIWEOIDC_BASE_URL", "http://localhost:18080")
# Timeout for the introspection round trip. Short on purpose: the mock sits in
# the request path of every admin call, so a hang here would be indistinguishable
# from a siwx-oidc hang. Every failure mode rejects (fail closed), so a short
# timeout can only ever produce a 401 -- never a false accept.
INTROSPECT_TIMEOUT_SECS = 2.0
# The scope `MasDelegatedAuth.is_server_admin` tests for (1.159).
SYNAPSE_ADMIN_SCOPE = "urn:synapse:admin:*"
# The Matrix C-S API scope, stable spelling first, MSC2967 unstable twin second.
# Synapse accepts either, and checks this BEFORE it looks at the admin scope.
MATRIX_API_SCOPES = (
    "urn:matrix:client:api:*",
    "urn:matrix:org.matrix.msc2967.client:api:*",
)

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
CALL_LOG = []  # list of "METHOD path"
# Mutable expected secret (so a test can flip it to force 401s).
STATE = {"secret": SECRET, "admin_token_valid": True}
# Per-logical-endpoint fault injection (H14). Maps a logical endpoint name to a
# mode string: "500" returns HTTP 500, "timeout" sleeps long enough that the
# siwx-oidc reqwest client times out. Cleared by /__reset.
#   POST /__fail {"endpoint": "delete_device", "mode": "500"|"timeout"|"off"}
# Recognized endpoints: delete_device, list_devices, get_device, deactivate.
FAIL = {}
# How long a "timeout" fault sleeps before (not) responding, in seconds. Must
# exceed the siwx-oidc Synapse HTTP client timeout so the call fails.
TIMEOUT_SLEEP_SECS = float(os.environ.get("SYNAPSE_MOCK_TIMEOUT_SLEEP", "30"))
# Counts effective device-DELETE operations per (user_id, device_id) so a race
# test can prove at most one DELETE actually mutated state. Distinct from
# CALL_LOG (which records every request, including idempotent no-ops).
EFFECTIVE_DELETES = {}


def _localpart_of(user_id):
    """Extract the localpart from an mxid `@localpart:server` (or pass through a
    bare localpart). Mirrors how siwx-oidc queries is_localpart_available with the
    `did_to_localpart` value, so the seeded mxid and the queried localpart match."""
    if not user_id:
        return user_id
    s = user_id[1:] if user_id.startswith("@") else user_id
    return s.split(":", 1)[0]


def _user_id(localpart):
    """Render a localpart as an mxid on this mock's server.

    The /_synapse/mas/* wire format is localpart-scoped (no server in the body),
    but DEVICES/LIFECYCLE are keyed by mxid because the admin API and the test
    helpers both speak mxids. This is the one conversion point.
    """
    if not localpart:
        return localpart
    return localpart if localpart.startswith("@") else f"@{localpart}:{SERVER_NAME}"


def _device(device_id, display_name=None, last_seen_ip=None, last_seen_ts=None):
    return {
        "device_id": device_id,
        "display_name": display_name,
        "last_seen_ip": last_seen_ip,
        "last_seen_ts": last_seen_ts,
        "user_id": None,
    }


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
        return v[len("Bearer "):] if v.startswith("Bearer ") else None

    def _mas_authed(self):
        """/_synapse/mas/*: exact string equality against the MAS shared secret."""
        return self._bearer() == STATE["secret"]

    def _introspect(self, token):
        """POST `token` to siwx-oidc's RFC 7662 endpoint, as Synapse 1.159 does.

        Returns the decoded introspection response, or None on ANY failure --
        timeout, connection refused, non-2xx, undecodable body. The caller FAILS
        CLOSED on None. Never cached.

        The credential is the mock's CURRENT shared secret, not the boot-time
        one: production Synapse and MAS share a single secret, so breaking it
        must break admin auth too. The lock is released before the request --
        never hold it across network I/O.
        """
        with LOCK:
            secret = STATE["secret"]
        req = Request(
            SIWEOIDC_BASE_URL.rstrip("/") + "/oauth2/introspect",
            data=urlencode({"token": token}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Bearer " + secret,
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=INTROSPECT_TIMEOUT_SECS) as resp:
                if not 200 <= resp.status < 300:
                    return None
                return json.loads(resp.read() or b"{}")
        except Exception as e:
            sys.stderr.write(f"[synapse-mock] introspection failed: {e!r}\n")
            return None

    def _admin_auth_error(self):
        """Validate an admin-surface bearer the way Synapse 1.159 does.

        Returns None when the token authorizes the call, else the
        `(http_status, body)` this surface must answer with. See the module
        docstring for the four conditions and where each comes from.

        The shared secret is NOT accepted here -- that is the whole point of the
        1.157 change -- but nothing special-cases it: it simply introspects to
        `{"active": false}`.
        """
        tok = self._bearer()
        if tok is None:
            return (401, {"errcode": "M_MISSING_TOKEN", "error": "no access token"})

        # Short-circuit test lever, checked BEFORE introspection so a test can
        # force "Synapse rejected the admin token" without forging a token.
        with LOCK:
            if not STATE["admin_token_valid"]:
                return (401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})

        data = self._introspect(tok)
        if data is None:
            # Fail closed: introspection unreachable, slow or broken.
            return (401, {"errcode": "M_UNKNOWN_TOKEN",
                          "error": "introspection failed"})

        # (1) active, and not expired.
        if not data.get("active"):
            return (401, {"errcode": "M_UNKNOWN_TOKEN", "error": "token is not active"})
        exp = data.get("exp")
        if isinstance(exp, (int, float)) and exp <= time.time():
            return (401, {"errcode": "M_UNKNOWN_TOKEN", "error": "token has expired"})
        expires_in = data.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in <= 0:
            return (401, {"errcode": "M_UNKNOWN_TOKEN", "error": "token has expired"})

        # (2) scope. The C-S API scope is checked FIRST, exactly as 1.159 does:
        # an admin-only scope string is rejected here, before is_server_admin is
        # ever consulted.
        scopes = set((data.get("scope") or "").split())
        if not scopes.intersection(MATRIX_API_SCOPES):
            return (401, {"errcode": "M_UNKNOWN_TOKEN",
                          "error": "Token doesn't grant access to the Matrix C-S API"})
        if SYNAPSE_ADMIN_SCOPE not in scopes:
            return (403, {"errcode": "M_FORBIDDEN", "error": "You are not a server admin"})

        # (3) username present, and resolving to a user that exists here.
        username = data.get("username")
        if not isinstance(username, str) or not username:
            return (500, {"errcode": "M_UNKNOWN",
                          "error": "No username in introspection result"})
        localpart = _localpart_of(username)
        with LOCK:
            known = localpart in EXISTING_USERS
        if not known:
            # DEVIATION, deliberate: real Synapse raises AuthError(500, "User not
            # found") here. This mock answers 401 because /__reset wipes
            # EXISTING_USERS out from under a still-cached admin token, and
            # `SynapseClient::admin_request` re-mints (which re-provisions the
            # service user) only on 401/403 -- a 500 would make every first admin
            # call after a reset fail, testing the harness rather than siwx-oidc.
            # The check still bites: the call is refused, and the error names it.
            return (401, {"errcode": "M_UNKNOWN_TOKEN",
                          "error": f"introspected username {username!r} resolves to no "
                                   f"user (real Synapse: AuthError(500, 'User not found'))"})

        # (4) device_id absent/null, or naming a device that exists. An empty
        # string is NOT absent -- Synapse reads it as a zero-length device id --
        # and this 500 is the regression guard for `render_device_id` in
        # src/introspect.rs. It must NOT be softened into a 401.
        device_id = data.get("device_id")
        if device_id is not None:
            if not isinstance(device_id, str) or device_id == "":
                return (500, {"errcode": "M_UNKNOWN",
                              "error": "Invalid device ID in introspection result"})
            with LOCK:
                devs = DEVICES.get(_user_id(localpart), [])
                exists = any(d["device_id"] == device_id for d in devs)
            if not exists:
                return (401, {"errcode": "M_UNKNOWN_TOKEN",
                              "error": f"Unknown device {device_id} in introspection result"})

        return None

    def _require_admin(self):
        """Gate an admin-surface request. On refusal it SENDS the response
        itself (401, 403 or 500 -- the status is part of the contract) and
        returns False, so callers read `if not self._require_admin(): return`.
        """
        err = self._admin_auth_error()
        if err is None:
            return True
        code, body = err
        self._send(code, body)
        return False

    def _deny(self):
        return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})

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
                })
        if path == "/health":
            return self._send(200, {"ok": True})
        # --- MAS surface: the shared secret ---
        if p.path.startswith("/_synapse/mas/"):
            if not self._mas_authed():
                return self._deny()
            self._log("GET", path)
            # GET /_synapse/mas/is_localpart_available
            if p.path.startswith("/_synapse/mas/is_localpart_available"):
                qs = parse_qs(p.query)
                localpart = (qs.get("localpart") or [""])[0]
                with LOCK:
                    exists = localpart in EXISTING_USERS
                if exists:
                    # Taken: the siwx-oidc client treats any 4xx as "not available"
                    # (an EXISTING account), so the new-identity gate does NOT reject.
                    return self._send(400, {"errcode": "M_USER_IN_USE", "error": "in use"})
                return self._send(200, {"available": True})
            # GET /_synapse/mas/query_user -- the deactivation probe the login
            # path runs before admitting a session. 404 means "no such user",
            # which siwx-oidc reads as None (a brand-new identity), so an
            # unknown localpart must NOT be an error here.
            if p.path.startswith("/_synapse/mas/query_user"):
                qs = parse_qs(p.query)
                localpart = (qs.get("localpart") or [""])[0]
                uid = _user_id(localpart)
                with LOCK:
                    if localpart not in EXISTING_USERS:
                        return self._send(404, {"errcode": "M_NOT_FOUND", "error": "user"})
                    life = LIFECYCLE.get(uid, {"deactivated": False, "erased": False})
                    return self._send(200, {
                        "user_id": uid,
                        "display_name": None,
                        "avatar_url": None,
                        "is_suspended": False,
                        "is_deactivated": bool(life.get("deactivated", False)),
                    })
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})
        # --- admin surface: a minted admin token, never the shared secret ---
        if not self._require_admin():
            return
        self._log("GET", path)
        # GET /_synapse/admin/v2/users/{user_id}/devices  (list_devices)
        m = re.match(r"^/_synapse/admin/v2/users/([^/]+)/devices$", path)
        if m:
            if self._maybe_fail("list_devices"):
                return
            user_id = m.group(1)
            with LOCK:
                devs = DEVICES.get(user_id, [])
                return self._send(200, {"devices": devs, "total": len(devs)})
        # GET /_synapse/admin/v2/users/{user_id}/devices/{device_id}  (get_device)
        m = re.match(r"^/_synapse/admin/v2/users/(.+)/devices/(.+)$", path)
        if m:
            if self._maybe_fail("get_device"):
                return
            user_id, device_id = m.group(1), m.group(2)
            with LOCK:
                devs = DEVICES.get(user_id, [])
                dev = next((d for d in devs if d["device_id"] == device_id), None)
            if dev is None:
                return self._send(404, {"errcode": "M_NOT_FOUND", "error": "device"})
            return self._send(200, dev)
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def do_POST(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        body = self._body()
        # test helpers (no auth) ------------------------------------------
        if path == "/__seed_device":
            uid = body.get("user_id") or f"@{body['localpart']}:{body['server']}"
            with LOCK:
                DEVICES.setdefault(uid, []).append(_device(
                    body["device_id"], body.get("display_name"),
                    body.get("last_seen_ip"), body.get("last_seen_ts")))
                # A user that carries a device EXISTS (so the new-identity gate
                # treats it as a returning account, not a fresh registration).
                EXISTING_USERS.add(_localpart_of(uid))
            return self._send(200, {"ok": True, "user_id": uid})
        # Explicitly mark a user as EXISTING without seeding a device. Accepts a
        # `user_id` mxid or a bare `localpart`. Used to test flows that must
        # distinguish a returning account from a brand-new identity.
        if path == "/__seed_user":
            lp = body.get("localpart") or _localpart_of(body.get("user_id", ""))
            with LOCK:
                if lp:
                    EXISTING_USERS.add(lp)
            return self._send(200, {"ok": True, "localpart": lp})
        if path == "/__reset":
            with LOCK:
                DEVICES.clear(); LIFECYCLE.clear(); CALL_LOG.clear()
                FAIL.clear(); EFFECTIVE_DELETES.clear()
                EXISTING_USERS.clear()
                STATE["secret"] = SECRET
                STATE["admin_token_valid"] = True
            return self._send(200, {"ok": True})
        if path == "/__set_secret":
            with LOCK:
                STATE["secret"] = body.get("secret", SECRET)
            return self._send(200, {"ok": True})
        # Accept or reject the MINTED ADMIN TOKEN, independently of the shared
        # secret. Models Synapse refusing the token (introspection failed, the
        # scope lacked urn:synapse:admin:*, or `username` resolved to no user)
        # while /_synapse/mas/* keeps working -- the only way to exercise the
        # admin-auth failure path on 1.157+, where the two credentials are
        # separate. Cleared by /__reset.
        #   POST /__set_admin_token_valid {"valid": false}
        if path == "/__set_admin_token_valid":
            with LOCK:
                STATE["admin_token_valid"] = bool(body.get("valid", True))
            return self._send(200, {"ok": True, "admin_token_valid": STATE["admin_token_valid"]})
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
        # --- MAS surface: the shared secret -------------------------------
        if path.startswith("/_synapse/mas/"):
            if not self._mas_authed():
                return self._deny()
            self._log("POST", path)
            if path == "/_synapse/mas/provision_user":
                lp = body.get("localpart")
                if lp:
                    with LOCK:
                        EXISTING_USERS.add(lp)
                return self._send(200, {})
            if path == "/_synapse/mas/upsert_device":
                uid = _user_id(body["localpart"])
                with LOCK:
                    # Provisioning a device for a user implies the user EXISTS.
                    EXISTING_USERS.add(body["localpart"])
                    devs = DEVICES.setdefault(uid, [])
                    if not any(d["device_id"] == body["device_id"] for d in devs):
                        devs.append(_device(body["device_id"], body.get("display_name")))
                return self._send(200, {})
            if path == "/_synapse/mas/allow_cross_signing_reset":
                return self._send(200, {})
            # POST /_synapse/mas/delete_device {localpart, device_id}
            # Ported from DELETE /_synapse/admin/v2/users/{mxid}/devices/{id}.
            # Keeps that route's fault injection and EFFECTIVE_DELETES counting:
            # the race suite asserts at most one STATE-MUTATING delete per
            # (mxid, device_id), so the counter must live wherever the real
            # deletion happens.
            if path == "/_synapse/mas/delete_device":
                if self._maybe_fail("delete_device"):
                    return
                uid = _user_id(body.get("localpart", ""))
                device_id = body.get("device_id", "")
                with LOCK:
                    devs = DEVICES.get(uid, [])
                    existed = any(d["device_id"] == device_id for d in devs)
                    DEVICES[uid] = [d for d in devs if d["device_id"] != device_id]
                    if existed:
                        key = f"{uid}/{device_id}"
                        EFFECTIVE_DELETES[key] = EFFECTIVE_DELETES.get(key, 0) + 1
                return self._send(200, {})
            # POST /_synapse/mas/delete_user {localpart, erase}
            # Despite the name this is DEACTIVATION, not deletion: Synapse routes
            # it to the same deactivate_account(user_id, erase_data=erase) handler
            # the old admin route used. `erase` is the GDPR selector.
            if path == "/_synapse/mas/delete_user":
                if self._maybe_fail("deactivate"):
                    return
                uid = _user_id(body.get("localpart", ""))
                erase = bool(body.get("erase", False))
                with LOCK:
                    LIFECYCLE[uid] = {"deactivated": True, "erased": erase}
                    # deactivation drops the account's devices
                    DEVICES[uid] = []
                return self._send(200, {})
            # POST /_synapse/mas/reactivate_user {localpart}
            if path == "/_synapse/mas/reactivate_user":
                uid = _user_id(body.get("localpart", ""))
                with LOCK:
                    cur = LIFECYCLE.get(uid, {"deactivated": False, "erased": False})
                    cur["deactivated"] = False
                    LIFECYCLE[uid] = cur
                return self._send(200, {})
            return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})
        # --- admin surface: a minted admin token, never the shared secret ---
        if not self._require_admin():
            return
        self._log("POST", path)
        if path == "/_matrix/client/v3/keys/query":
            # report no master cross-signing key (keeps pre-flight warnings off)
            return self._send(200, {"master_keys": {}})
        # POST /_synapse/admin/v1/deactivate/{user_id}  (legacy, no longer called)
        m = re.match(r"^/_synapse/admin/v1/deactivate/(.+)$", path)
        if m:
            if self._maybe_fail("deactivate"):
                return
            user_id = m.group(1)
            erase = bool(body.get("erase", False))
            with LOCK:
                LIFECYCLE[user_id] = {"deactivated": True, "erased": erase}
                # deactivation drops the account's devices
                DEVICES[user_id] = []
            return self._send(200, {"id_server_unbind_result": "success"})
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def do_DELETE(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        # Legacy admin surface: siwx-oidc now deletes devices via
        # POST /_synapse/mas/delete_device. Kept so a live-suite probe still works.
        if not self._require_admin():
            return
        self._log("DELETE", path)
        # DELETE /_synapse/admin/v2/users/{user_id}/devices/{device_id}
        m = re.match(r"^/_synapse/admin/v2/users/(.+)/devices/(.+)$", path)
        if m:
            if self._maybe_fail("delete_device"):
                return
            user_id, device_id = m.group(1), m.group(2)
            with LOCK:
                devs = DEVICES.get(user_id, [])
                existed = any(d["device_id"] == device_id for d in devs)
                DEVICES[user_id] = [d for d in devs if d["device_id"] != device_id]
                if existed:
                    # Count only the DELETE that actually mutated state, so a race
                    # test can assert at most one *effective* deletion occurred.
                    key = f"{user_id}/{device_id}"
                    EFFECTIVE_DELETES[key] = EFFECTIVE_DELETES.get(key, 0) + 1
            return self._send(200, {})
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})

    def do_PUT(self):
        p = urlparse(self.path)
        path = unquote(p.path)
        body = self._body()
        # Legacy admin surface: reactivation now goes through
        # POST /_synapse/mas/reactivate_user.
        if not self._require_admin():
            return
        self._log("PUT", path)
        # PUT /_synapse/admin/v2/users/{user_id}
        m = re.match(r"^/_synapse/admin/v2/users/(.+)$", path)
        if m:
            user_id = m.group(1)
            with LOCK:
                cur = LIFECYCLE.get(user_id, {"deactivated": False, "erased": False})
                if body.get("deactivated") is False:
                    cur["deactivated"] = False
                LIFECYCLE[user_id] = cur
            return self._send(200, {"name": user_id, "deactivated": cur["deactivated"]})
        return self._send(404, {"errcode": "M_NOT_FOUND", "error": path})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write(f"[synapse-mock] listening on 127.0.0.1:{PORT} secret={SECRET!r}\n")
    srv.serve_forever()
