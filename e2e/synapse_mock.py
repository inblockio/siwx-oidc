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

  `Bearer msa_...` -- a minted, admin-scoped access token (src/admin_token.rs):
    GET    /_synapse/admin/v2/users/{user_id}/devices
    GET    /_synapse/admin/v2/users/{user_id}/devices/{device_id}
    POST   /_matrix/client/v3/keys/query

Presenting the shared secret on the admin surface answers 401 M_UNKNOWN_TOKEN,
exactly as 1.159 does -- there it is a shared secret, not a token. The two
credentials fail INDEPENDENTLY, so there are two levers: __set_secret breaks the
MAS surface, __set_admin_token_valid breaks the admin surface. A test that wants
"Synapse rejected the admin token" must use the latter; breaking the secret
instead fails earlier, on the MAS deactivation probe, and never reaches an admin
call at all.

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
from urllib.parse import unquote, urlparse, parse_qs

SECRET = os.environ.get("SYNAPSE_MOCK_SECRET", "testsecret")
PORT = int(os.environ.get("SYNAPSE_MOCK_PORT", "8090"))
SERVER_NAME = os.environ.get("SYNAPSE_MOCK_SERVER_NAME", "matrix.test")
# Prefix of a minted admin token (`ADMIN_TOKEN_PREFIX` in src/admin_token.rs).
# Real Synapse validates such a token by introspecting it against siwx-oidc and
# checking the returned scope; the mock cannot introspect, so it accepts any
# token carrying the prefix and uses __set_admin_token_valid as the reject lever.
ADMIN_TOKEN_PREFIX = "msa_"

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

    def _admin_authed(self):
        """/_synapse/admin/* and the authenticated C-S API: a minted access token.

        The shared secret is NOT accepted here -- that is the whole point of the
        1.157 change. Real Synapse validates the token by introspecting it against
        siwx-oidc and requiring both `urn:matrix:client:api:*` and
        `urn:synapse:admin:*` in the returned scope; the mock cannot introspect, so
        it accepts the token prefix and offers __set_admin_token_valid as the
        reject lever.
        """
        tok = self._bearer()
        if tok is None or not tok.startswith(ADMIN_TOKEN_PREFIX):
            return False
        return bool(STATE["admin_token_valid"])

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
        if not self._admin_authed():
            return self._deny()
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
        if not self._admin_authed():
            return self._deny()
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
        if not self._admin_authed():
            return self._deny()
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
        if not self._admin_authed():
            return self._deny()
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
