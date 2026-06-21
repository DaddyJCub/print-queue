"""Printer controller behind the local device-page UI.

The HTTP server (``local_ui``) talks to a controller, never to the serial layer
directly. The real controller wraps the agent's :class:`SerialPrinter`, camera
and an on-host *spool* directory (uploaded G-code lives here before being sent to
the printer's SD card). Tests substitute a fake controller with the same surface.

A local print runs in a background worker thread; ``agent.print_active`` is set
for its duration so the agent's central-job loop doesn't grab the port at the
same time.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("printqueue.controller")


class ControllerError(Exception):
    """Raised for user-facing controller failures (mapped to HTTP 4xx)."""

    status = 400


class Busy(ControllerError):
    status = 409


class NotFound(ControllerError):
    status = 404


def _safe_name(name: str) -> str:
    """Reject path traversal; keep a plain G-code filename."""
    base = os.path.basename(name or "")
    if not base or base in (".", "..") or "/" in base or "\\" in base:
        raise ControllerError("Invalid filename")
    if not base.lower().endswith((".gcode", ".gco", ".g")):
        raise ControllerError("Only .gcode files are accepted")
    return base


class AgentPrinterController:
    def __init__(self, agent):
        self.agent = agent
        cfg = agent.cfg
        spool = cfg.local_ui.spool_dir or os.path.join(
            os.path.expanduser("~"), ".printqueue", "spool"
        )
        os.makedirs(spool, exist_ok=True)
        self.spool_dir = spool
        self._upload_pct: Optional[int] = None
        self._active_file: Optional[str] = None

    # ── identity ──────────────────────────────────────────────────
    def info(self) -> Dict[str, Any]:
        c = self.agent.cfg
        return {
            "name": getattr(c, "name", None) or c.agent_id,
            "agent_id": c.agent_id,
            "printer_code": "LK5_PRO",
            "agent_version": c.agent_version,
        }

    # ── state ─────────────────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        printer = self.agent.printer
        if printer and printer.connected:
            st = printer.query_status().as_dict()
        else:
            st = {"state": "offline"}
        if self._upload_pct is not None:
            st["state"] = "uploading"
            st["progress"] = self._upload_pct
        st["connected"] = bool(printer and printer.connected)
        st["print_active"] = self.agent.print_active.is_set()
        if self._active_file:
            st["current_file"] = self._active_file
        return st

    # ── files ─────────────────────────────────────────────────────
    def list_files(self) -> List[Dict[str, Any]]:
        out = []
        for name in os.listdir(self.spool_dir):
            p = os.path.join(self.spool_dir, name)
            if os.path.isfile(p):
                stt = os.stat(p)
                out.append({"name": name, "size": stt.st_size, "mtime": int(stt.st_mtime)})
        out.sort(key=lambda f: f["mtime"], reverse=True)
        return out

    def save_upload(self, filename: str, data: bytes) -> str:
        name = _safe_name(filename)
        if not data:
            raise ControllerError("Empty file")
        with open(os.path.join(self.spool_dir, name), "wb") as fh:
            fh.write(data)
        log.info("Stored upload %s (%d bytes)", name, len(data))
        return name

    def delete_file(self, filename: str) -> None:
        name = _safe_name(filename)
        path = os.path.join(self.spool_dir, name)
        if not os.path.isfile(path):
            raise NotFound("File not found")
        os.remove(path)

    # ── print lifecycle ───────────────────────────────────────────
    def start_file(self, filename: str) -> None:
        name = _safe_name(filename)
        path = os.path.join(self.spool_dir, name)
        if not os.path.isfile(path):
            raise NotFound("File not found")
        printer = self.agent.printer
        if not printer or not printer.connected:
            raise ControllerError("Printer is offline")
        if self.agent.print_active.is_set() or printer.is_busy():
            raise Busy("A print is already in progress")
        self.agent.print_active.set()
        self._active_file = name
        threading.Thread(target=self._print_worker, args=(path, name), daemon=True).start()

    def _print_worker(self, path: str, name: str) -> None:
        printer = self.agent.printer
        try:
            self._upload_pct = 0
            printer.upload_to_sd(path, on_progress=lambda p: setattr(self, "_upload_pct", p))
            printer.start_sd_print()
            printer.enable_auto_reports(self.agent.cfg.heartbeat_interval_s, self.agent.cfg.poll_interval_s)
            log.info("Local print started: %s", name)
        except Exception as e:
            log.exception("Local print failed: %s", e)
            self._active_file = None
        finally:
            self._upload_pct = None
            # The print now runs autonomously from SD; release the loop guard.
            self.agent.print_active.clear()

    def _require_printer(self):
        printer = self.agent.printer
        if not printer or not printer.connected:
            raise ControllerError("Printer is offline")
        return printer

    def pause(self) -> None:
        self._require_printer().pause_print()

    def resume(self) -> None:
        self._require_printer().resume_print()

    def cancel(self) -> None:
        self._require_printer().abort_print()
        self._active_file = None

    # ── manual controls ───────────────────────────────────────────
    def set_temp(self, target: str, value: float) -> None:
        printer = self._require_printer()
        value = max(0.0, min(300.0, float(value)))
        if target == "nozzle":
            printer.set_hotend_temp(value)
        elif target == "bed":
            printer.set_bed_temp(value)
        else:
            raise ControllerError(f"Unknown heater: {target}")

    def jog(self, axis: str, distance: float) -> None:
        if self.agent.print_active.is_set():
            raise Busy("Cannot jog during a print")
        self._require_printer().jog(axis, float(distance))

    def home(self, axes: str = "") -> None:
        if self.agent.print_active.is_set():
            raise Busy("Cannot home during a print")
        self._require_printer().home(axes)

    def set_fan(self, speed: int) -> None:
        self._require_printer().set_fan(int(speed))

    # ── camera ────────────────────────────────────────────────────
    def snapshot(self) -> Optional[Tuple[bytes, str]]:
        cam = getattr(self.agent, "camera", None)
        if not cam or not getattr(self.agent.cfg.camera, "enabled", False):
            return None
        try:
            frame = cam.capture()
        except Exception:
            return None
        return (frame, "image/jpeg") if frame else None
