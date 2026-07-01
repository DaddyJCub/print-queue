"""Tests for the agent's local device-page UI server (ZMOD-style).

Driven against the real stdlib HTTP server with a fake controller, so no serial
hardware or Flask-style deps are needed.
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

# The agent package lives under agent/, outside the app import path.
AGENT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent")
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from printqueue_agent import local_ui  # noqa: E402
from printqueue_agent.controller import Busy, ControllerError, NotFound  # noqa: E402


class FakeController:
    def __init__(self):
        self.files = []
        self.started = None
        self.paused = False
        self.canceled = False
        self.temps = {}
        self.jogs = []
        self.homed = None
        self.estopped = False
        self.fan = None

    def info(self):
        return {"name": "Garage LK5", "printer_code": "LK5_PRO", "agent_version": "1.0.0"}

    def state(self):
        return {"state": "printing" if self.started and not self.canceled else "idle",
                "connected": True, "progress": 42, "print_active": bool(self.started)}

    def list_files(self):
        return [{"name": n, "size": 5, "mtime": 1} for n in self.files]

    def save_upload(self, fn, data):
        if not fn.endswith((".gcode", ".gco", ".g")):
            raise ControllerError("Only .gcode files are accepted")
        if not data:
            raise ControllerError("Empty file")
        self.files.append(fn)
        return fn

    def start_file(self, fn):
        if fn not in self.files:
            raise NotFound("File not found")
        if self.started:
            raise Busy("already printing")
        self.started = fn

    def delete_file(self, fn):
        if fn not in self.files:
            raise NotFound("nope")
        self.files.remove(fn)

    def pause(self): self.paused = True
    def resume(self): self.paused = False
    def cancel(self): self.canceled = True; self.started = None
    def estop(self): self.estopped = True; self.started = None
    def set_temp(self, t, v): self.temps[t] = v
    def jog(self, a, d): self.jogs.append((a, d))
    def home(self, a=""): self.homed = a
    def set_fan(self, s): self.fan = s
    def snapshot(self): return None


@pytest.fixture
def server():
    ctrl = FakeController()
    httpd = local_ui.create_server(ctrl, "127.0.0.1", 0, api_key="secret")
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.1)
    yield ctrl, f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _req(base, path, method="GET", data=None, headers=None, ct=None):
    r = urllib.request.Request(base + path, data=data, method=method)
    if ct:
        r.add_header("Content-Type", ct)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


AUTH = {"X-Api-Key": "secret"}


def test_device_page_renders(server):
    _ctrl, base = server
    status, body = _req(base, "/")
    assert status == 200
    assert b"Garage LK5" in body
    assert b"/api/state" in body  # the page wires up the control API


def test_octoprint_version_handshake(server):
    _ctrl, base = server
    status, body = _req(base, "/api/version")
    assert status == 200
    assert json.loads(body)["api"] == "0.1"


def test_state_endpoint(server):
    _ctrl, base = server
    status, body = _req(base, "/api/state")
    assert status == 200
    assert json.loads(body)["progress"] == 42


def test_control_requires_api_key(server):
    _ctrl, base = server
    assert _req(base, "/api/pause", method="POST")[0] == 401
    assert _req(base, "/api/pause", method="POST", headers=AUTH)[0] == 200


def test_api_key_via_query_param(server):
    _ctrl, base = server
    assert _req(base, "/api/cancel?apikey=secret", method="POST")[0] == 200


def _multipart(fields, fname=None, fdata=b""):
    boundary = "----pqtest"
    parts = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
    pre = "".join(parts).encode()
    if fname is not None:
        pre += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n").encode() + fdata + b"\r\n"
    pre += f"--{boundary}--\r\n".encode()
    return pre, f"multipart/form-data; boundary={boundary}"


def test_octoprint_upload_and_print(server):
    ctrl, base = server
    body, ct = _multipart({"print": "true"}, fname="cube.gcode", fdata=b"G28\nG1 X1\n")
    status, resp = _req(base, "/api/files/local", method="POST", data=body, headers=AUTH, ct=ct)
    assert status == 201, resp
    assert json.loads(resp)["done"] is True
    assert ctrl.files == ["cube.gcode"]
    assert ctrl.started == "cube.gcode"  # print=true also started it


def test_octoprint_upload_without_print(server):
    ctrl, base = server
    body, ct = _multipart({}, fname="part.gcode", fdata=b"G28\n")
    status, _ = _req(base, "/api/files/local", method="POST", data=body, headers=AUTH, ct=ct)
    assert status == 201
    assert ctrl.files == ["part.gcode"]
    assert ctrl.started is None


def test_native_upload_then_print_then_delete(server):
    ctrl, base = server
    body, ct = _multipart({}, fname="a.gcode", fdata=b"G28\n")
    assert _req(base, "/api/files", method="POST", data=body, headers=AUTH, ct=ct)[0] == 201
    assert ctrl.files == ["a.gcode"]

    pr = _req(base, "/api/print", method="POST",
              data=json.dumps({"file": "a.gcode"}).encode(),
              headers={**AUTH, "Content-Type": "application/json"})
    assert pr[0] == 200 and ctrl.started == "a.gcode"

    dl = _req(base, "/api/files/delete", method="POST",
              data=json.dumps({"file": "a.gcode"}).encode(),
              headers={**AUTH, "Content-Type": "application/json"})
    assert dl[0] == 200 and ctrl.files == []


def test_upload_rejects_non_gcode(server):
    _ctrl, base = server
    body, ct = _multipart({}, fname="evil.txt", fdata=b"nope")
    status, _ = _req(base, "/api/files", method="POST", data=body, headers=AUTH, ct=ct)
    assert status == 400


def test_temp_and_jog_and_home(server):
    ctrl, base = server
    _req(base, "/api/temp", method="POST", data=json.dumps({"target": "nozzle", "value": 215}).encode(),
         headers={**AUTH, "Content-Type": "application/json"})
    _req(base, "/api/jog", method="POST", data=json.dumps({"axis": "X", "distance": 10}).encode(),
         headers={**AUTH, "Content-Type": "application/json"})
    _req(base, "/api/home", method="POST", data=json.dumps({"axes": "XY"}).encode(),
         headers={**AUTH, "Content-Type": "application/json"})
    assert ctrl.temps["nozzle"] == 215
    assert ("X", 10) in ctrl.jogs
    assert ctrl.homed == "XY"


def test_estop_and_fan(server):
    ctrl, base = server
    assert _req(base, "/api/estop", method="POST", headers=AUTH)[0] == 200
    assert ctrl.estopped is True
    fan = _req(base, "/api/fan", method="POST", data=json.dumps({"speed": 128}).encode(),
               headers={**AUTH, "Content-Type": "application/json"})
    assert fan[0] == 200 and ctrl.fan == 128


def test_estop_requires_api_key(server):
    _ctrl, base = server
    assert _req(base, "/api/estop", method="POST")[0] == 401


def test_print_busy_returns_409(server):
    ctrl, base = server
    ctrl.files = ["a.gcode"]
    ctrl.started = "a.gcode"  # already printing
    pr = _req(base, "/api/print", method="POST", data=json.dumps({"file": "a.gcode"}).encode(),
              headers={**AUTH, "Content-Type": "application/json"})
    assert pr[0] == 409


def test_open_when_no_api_key():
    """With no key configured the control API is open (trusted LAN)."""
    ctrl = FakeController()
    httpd = local_ui.create_server(ctrl, "127.0.0.1", 0, api_key="")
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        base = f"http://127.0.0.1:{port}"
        assert _req(base, "/api/cancel", method="POST")[0] == 200
        assert ctrl.canceled is True
    finally:
        httpd.shutdown()
