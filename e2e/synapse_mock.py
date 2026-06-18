#!/usr/bin/env python3
"""Faithful in-memory mock of the Synapse endpoints siwx-oidc calls.

Mirrors the exact contract in src/synapse_client.rs:
  POST   /_synapse/mas/provision_user
  POST   /_synapse/mas/upsert_device
  POST   /_synapse/mas/allow_cross_signing_reset
  GET    /_synapse/mas/is_localpart_available
  POST   /_matrix/client/v3/keys/query
  GET    /_synapse/admin/v2/users/{user_id}/devices
  DELETE /_synapse/admin/v2/users/{user_id}/devices/{device_id}
  POST   /_synapse/admin/v1/deactivate/{user_id}
  PUT    /_synapse/admin/v2/users/{user_id}

All require `Authorization: Bearer <SECRET>` (set via SYNAPSE_MOCK_SECRET, default
"testsecret"); a wrong/missing token yields 401 so the admin-auth-failure path can be
exercised. State is in-memory; test-only helpers live under /__.

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
STATE = {"secret": SECRET}
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

    def _authed(self):
        return self.headers.get("Authorization", "") == f"Bearer {STATE['secret']}"

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
        if not self._authed():
            return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
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
            return self._send(200, {"ok": True})
        if path == "/__set_secret":
            with LOCK:
                STATE["secret"] = body.get("secret", SECRET)
            return self._send(200, {"ok": True})
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
        # authed synapse endpoints ----------------------------------------
        if not self._authed():
            return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
        self._log("POST", path)
        if path == "/_synapse/mas/provision_user":
            lp = body.get("localpart")
            if lp:
                with LOCK:
                    EXISTING_USERS.add(lp)
            return self._send(200, {})
        if path == "/_synapse/mas/upsert_device":
            uid = f"@{body['localpart']}:matrix.test"
            with LOCK:
                # Provisioning a device for a user implies the user EXISTS.
                EXISTING_USERS.add(body["localpart"])
                devs = DEVICES.setdefault(uid, [])
                if not any(d["device_id"] == body["device_id"] for d in devs):
                    devs.append(_device(body["device_id"], body.get("display_name")))
            return self._send(200, {})
        if path == "/_synapse/mas/allow_cross_signing_reset":
            return self._send(200, {})
        if path == "/_matrix/client/v3/keys/query":
            # report no master cross-signing key (keeps pre-flight warnings off)
            return self._send(200, {"master_keys": {}})
        # POST /_synapse/admin/v1/deactivate/{user_id}
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
        if not self._authed():
            return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
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
        if not self._authed():
            return self._send(401, {"errcode": "M_UNKNOWN_TOKEN", "error": "bad admin token"})
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
