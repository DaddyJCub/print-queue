"""Local device-page web UI served by the agent (ZMOD-style).

A small stdlib HTTP server (no extra pip deps) that exposes:

* a **device page** at ``/`` — live status, camera, file list, full manual
  control (start/pause/resume/cancel, temps, jog/home, fan);
* a JSON **control API** under ``/api/...`` used by that page;
* an **OctoPrint-compatible** upload API (``GET /api/version`` +
  ``POST /api/files/local``) so Orca Slicer can "Send to printer" straight to
  the Pi and optionally start the print — the same handshake ZMOD/Fluidd expose.

All serial access goes through the controller, which serializes it against the
agent's own loop. Mutating endpoints require the configured API key (if any);
the device page itself is open on the LAN, matching OctoPrint/Fluidd.
"""

from __future__ import annotations

import email
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .controller import ControllerError
from .device_page import render_page

log = logging.getLogger("printqueue.localui")


def _parse_multipart(content_type: str, body: bytes) -> Tuple[Dict[str, str], Dict[str, Tuple[str, bytes]]]:
    """Return (fields, files) from a multipart/form-data body."""
    raw = b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = email.message_from_bytes(raw)
    fields: Dict[str, str] = {}
    files: Dict[str, Tuple[str, bytes]] = {}
    if not msg.is_multipart():
        return fields, files
    for part in msg.get_payload():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_param("filename", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if filename:
            files[name] = (filename, payload)
        elif name:
            fields[name] = payload.decode("utf-8", "ignore")
    return fields, files


def make_handler(controller, api_key: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PrintQueueAgent"
        protocol_version = "HTTP/1.1"

        # ── helpers ────────────────────────────────────────────────
        def _authed(self) -> bool:
            if not api_key:
                return True
            key = self.headers.get("X-Api-Key", "")
            if not key:
                q = parse_qs(urlparse(self.path).query)
                key = (q.get("apikey") or [""])[0]
            return key == api_key

        def _write(self, data: bytes) -> None:
            # The browser polls constantly and often closes a connection before we
            # finish writing; that's normal, so swallow disconnects quietly.
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionError):
                pass

        def _send_json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj).encode("utf-8")
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            except (BrokenPipeError, ConnectionError):
                return
            self._write(body)

        def _send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                # Never cache: the device page embeds the current API key, so a stale
                # cached copy would keep sending an old key and get 401s.
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            except (BrokenPipeError, ConnectionError):
                return
            self._write(data)

        def _unauthorized(self) -> None:
            # Drain any request body so HTTP/1.1 keep-alive doesn't desync, log it
            # (visible via `get_logs` / journalctl), then 401.
            self._read_body()
            log.warning("Unauthorized %s %s from %s (bad/again missing API key)",
                        self.command, self.path, self.client_address[0])
            self._send_json({"error": "unauthorized"}, status=401)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(length) if length else b""

        def _read_json(self) -> Dict[str, Any]:
            try:
                return json.loads(self._read_body() or b"{}")
            except Exception:
                return {}

        def _err(self, exc: Exception) -> None:
            status = getattr(exc, "status", 400)
            self._send_json({"error": str(exc)}, status=status)

        def log_message(self, *args):  # quieten default stderr logging
            return

        # ── routing ────────────────────────────────────────────────
        def do_GET(self):
            path = urlparse(self.path).path
            try:
                if path == "/" or path == "/index.html":
                    html = render_page(controller.info(), api_key).encode("utf-8")
                    return self._send_bytes(html, "text/html; charset=utf-8")
                if path == "/api/printer":
                    return self._send_json({"info": controller.info(), "state": controller.state()})
                if path == "/api/state":
                    return self._send_json(controller.state())
                if path == "/api/files":
                    return self._send_json({"files": controller.list_files()})
                if path == "/api/update-state":
                    return self._send_json(controller.update_state())
                if path == "/api/update-verification":
                    q = parse_qs(urlparse(self.path).query)
                    cmd_ids = (q.get("cmd_ids") or [""])[0]
                    return self._send_json(controller.verify_update(cmd_ids))
                if path == "/api/snapshot":
                    snap = controller.snapshot()
                    if not snap:
                        return self._send_json({"error": "no camera"}, status=404)
                    return self._send_bytes(snap[0], snap[1])
                # OctoPrint discovery handshake
                if path == "/api/version":
                    return self._send_json({
                        "api": "0.1", "server": "1.3.10",
                        "text": "OctoPrint (PrintQueue agent)",
                    })
                return self._send_json({"error": "not found"}, status=404)
            except ControllerError as e:
                return self._err(e)
            except (BrokenPipeError, ConnectionError):
                return  # client went away mid-response; nothing to do
            except Exception as e:  # pragma: no cover - defensive
                log.exception("UI GET %s failed", path)
                return self._send_json({"error": str(e)}, status=500)

        def do_DELETE(self):
            path = urlparse(self.path).path
            if not self._authed():
                return self._unauthorized()
            try:
                if path.startswith("/api/files/"):
                    controller.delete_file(path[len("/api/files/"):])
                    return self._send_json({"ok": True})
                return self._send_json({"error": "not found"}, status=404)
            except ControllerError as e:
                return self._err(e)

        def do_POST(self):
            path = urlparse(self.path).path
            if not self._authed():
                return self._unauthorized()
            try:
                # OctoPrint upload: multipart, optional ?print / print=true field.
                if path == "/api/files/local":
                    ctype = self.headers.get("Content-Type", "")
                    fields, files = _parse_multipart(ctype, self._read_body())
                    if "file" not in files:
                        return self._send_json({"error": "no file"}, status=400)
                    fname, data = files["file"]
                    saved = controller.save_upload(fname, data)
                    do_print = str(fields.get("print", "")).lower() in ("true", "1", "yes")
                    if do_print:
                        controller.start_file(saved)
                    return self._send_json({
                        "done": True,
                        "files": {"local": {"name": saved, "origin": "local"}},
                    }, status=201)

                # Native device-page API.
                if path == "/api/files":
                    ctype = self.headers.get("Content-Type", "")
                    _fields, files = _parse_multipart(ctype, self._read_body())
                    if "file" not in files:
                        return self._send_json({"error": "no file"}, status=400)
                    fname, data = files["file"]
                    return self._send_json({"ok": True, "name": controller.save_upload(fname, data)}, status=201)
                if path == "/api/print":
                    body = self._read_json()
                    controller.start_file(body.get("file", ""))
                    return self._send_json({"ok": True})
                if path == "/api/print-mode":
                    mode = self._read_json().get("mode", "")
                    try:
                        return self._send_json({"ok": True, "print_mode": controller.set_print_mode(mode)})
                    except ValueError as e:
                        return self._send_json({"error": str(e)}, status=400)
                if path == "/api/pause":
                    controller.pause(); return self._send_json({"ok": True})
                if path == "/api/resume":
                    controller.resume(); return self._send_json({"ok": True})
                if path == "/api/cancel":
                    controller.cancel(); return self._send_json({"ok": True})
                if path == "/api/estop":
                    controller.estop(); return self._send_json({"ok": True})
                if path == "/api/restart":
                    controller.restart_agent(); return self._send_json({"ok": True})
                if path == "/api/temp":
                    b = self._read_json()
                    controller.set_temp(b.get("target", ""), b.get("value", 0))
                    return self._send_json({"ok": True})
                if path == "/api/jog":
                    b = self._read_json()
                    controller.jog(b.get("axis", ""), b.get("distance", 0))
                    return self._send_json({"ok": True})
                if path == "/api/home":
                    controller.home(self._read_json().get("axes", ""))
                    return self._send_json({"ok": True})
                if path == "/api/fan":
                    controller.set_fan(self._read_json().get("speed", 0))
                    return self._send_json({"ok": True})
                if path == "/api/files/delete":
                    controller.delete_file(self._read_json().get("file", ""))
                    return self._send_json({"ok": True})
                if path == "/api/update":
                    return self._send_json(controller.start_update())
                return self._send_json({"error": "not found"}, status=404)
            except ControllerError as e:
                return self._err(e)
            except (BrokenPipeError, ConnectionError):
                return  # client went away mid-response; nothing to do
            except Exception as e:  # pragma: no cover - defensive
                log.exception("UI POST %s failed", path)
                return self._send_json({"error": str(e)}, status=500)

    return Handler


def create_server(controller, host: str, port: int, api_key: str = "") -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(controller, api_key))
    httpd.daemon_threads = True
    return httpd


def start_in_thread(controller, host: str, port: int, api_key: str = "") -> ThreadingHTTPServer:
    httpd = create_server(controller, host, port, api_key)
    t = threading.Thread(target=httpd.serve_forever, name="local-ui", daemon=True)
    t.start()
    log.info("Local device UI on http://%s:%d", host, port)
    return httpd
