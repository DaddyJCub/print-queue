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
from printqueue_agent import serial_printer as sp  # noqa: E402
from printqueue_agent.controller import Busy, ControllerError, NotFound  # noqa: E402


def test_state_reports_uploading_without_touching_serial(tmp_path):
    """During an upload the serial lock is held, so state() must report cached
    upload progress instead of calling (and blocking on) query_status."""
    from printqueue_agent.controller import AgentPrinterController

    class _UI:  # cfg.local_ui
        spool_dir = str(tmp_path)
    class _Cam:
        enabled = False
    class _Cfg:
        agent_id = "agent-x"; agent_version = "1.1.0"; name = "Bench"
        local_ui = _UI(); camera = _Cam()
    class _Printer:
        connected = True
        def query_status(self):
            raise AssertionError("query_status must not run during an upload")
    class _Agent:
        cfg = _Cfg(); printer = _Printer()
        print_active = threading.Event(); camera = None

    ctrl = AgentPrinterController(_Agent())
    ctrl._upload_pct = 42
    st = ctrl.state()
    assert st["state"] == "uploading"
    assert st["progress"] == 42
    assert st["connected"] is True


def test_upload_releases_lock_on_m28_failure(tmp_path, monkeypatch):
    """Regression: a failed M28 must not leak the serial lock (which would
    deadlock every subsequent status query forever)."""
    monkeypatch.setattr(sp, "serial", object())  # bypass the pyserial import guard
    p = sp.SerialPrinter("/dev/null", 115200)

    def fake_send(cmd, timeout=30):
        if cmd.startswith("M28"):
            raise RuntimeError("simulated M28 failure at print start")
        return "ok"

    monkeypatch.setattr(p, "send_command", fake_send)
    f = tmp_path / "a.gcode"
    f.write_text("G28\nG1 X1\n")

    with pytest.raises(RuntimeError):
        p.upload_to_sd(str(f))

    # The lock must be free despite the failure.
    assert p._lock.acquire(blocking=False) is True
    p._lock.release()


def test_connect_tries_fallback_bauds(monkeypatch):
    """A wrong configured baud must fall back to a rate the printer answers on."""
    monkeypatch.setattr(sp, "serial", object())  # bypass pyserial import guard
    p = sp.SerialPrinter("/dev/null", 250000)  # configured baud "wrong"
    tried = []

    def fake_open(baud):
        tried.append(baud)
        if baud != 115200:
            raise RuntimeError("no response")

    monkeypatch.setattr(p, "_open_and_handshake", fake_open)
    monkeypatch.setattr(p, "_log_firmware", lambda: None)
    monkeypatch.setattr(p, "close", lambda: None)

    p.connect()
    assert p.baud == 115200
    assert tried[0] == 250000  # the configured rate is tried first


def test_wait_ok_tolerates_busy(monkeypatch):
    """'echo:busy: processing' means the printer is alive and working, not dead —
    it must keep waiting for 'ok' rather than time out."""
    monkeypatch.setattr(sp, "serial", object())
    p = sp.SerialPrinter("/dev/null", 115200)
    seq = iter(["echo:busy: processing", "echo:busy: processing", "ok T:20 /0"])
    monkeypatch.setattr(p, "_readline", lambda: next(seq, ""))
    assert "ok" in p._wait_ok(timeout=5).lower()


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
        self.restarted = False

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
    def restart_agent(self): self.restarted = True
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


def test_restart_agent(server):
    ctrl, base = server
    assert _req(base, "/api/restart", method="POST", headers=AUTH)[0] == 200
    assert ctrl.restarted is True
    # And it's guarded behind the API key like the other mutating actions.
    assert _req(base, "/api/restart", method="POST")[0] == 401


def test_print_busy_returns_409(server):
    ctrl, base = server
    ctrl.files = ["a.gcode"]
    ctrl.started = "a.gcode"  # already printing
    pr = _req(base, "/api/print", method="POST", data=json.dumps({"file": "a.gcode"}).encode(),
              headers={**AUTH, "Content-Type": "application/json"})
    assert pr[0] == 409


def test_client_wraps_network_errors_as_servererror():
    """A fully-unreachable server must raise ServerError (not a raw requests
    exception), so the agent flips its online indicator to offline."""
    from printqueue_agent.client import PrintQueueClient, ServerError
    c = PrintQueueClient("http://127.0.0.1:9", "agent-x", "code", timeout=1)
    c._token = "tok"  # skip provisioning; exercise the request path directly
    with pytest.raises(ServerError):
        c.heartbeat("1.1.0", {"state": "idle"})


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
