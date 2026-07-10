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

# End-user-facing model names (the device page is customer-facing, so we never
# show the internal agent id there unless nothing friendlier is available).
FRIENDLY_PRINTER_NAMES = {
    "LK5_PRO": "Longer LK5 Pro",
}


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
        self._stream_pct: Optional[int] = None
        self._active_file: Optional[str] = None
        self._print_start_ts: Optional[float] = None
        self._cancel = threading.Event()
        self._paused = threading.Event()

    # ── identity ──────────────────────────────────────────────────
    def info(self) -> Dict[str, Any]:
        c = self.agent.cfg
        printer_code = "LK5_PRO"
        # Prefer an operator-set display name, else the friendly model name;
        # only fall back to the agent id if we truly have nothing else.
        display = (getattr(c.local_ui, "display_name", "") or "").strip()
        name = display or FRIENDLY_PRINTER_NAMES.get(printer_code) or c.agent_id
        return {
            "name": name,
            "agent_id": c.agent_id,
            "printer_code": printer_code,
            "agent_version": c.agent_version,
        }

    # ── state ─────────────────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        printer = self.agent.printer
        connected = bool(printer and printer.connected)
        # During an upload the serial lock is held for the whole transfer, so
        # never call query_status() then — it would block this request for
        # minutes. Report the cached upload progress instead.
        if self._upload_pct is not None:
            st = {"state": "uploading", "progress": self._upload_pct}
        elif self._stream_pct is not None:
            # Host-streaming: the port lock is free between lines, so a status
            # query is safe here — the device page keeps live temps + progress.
            st = printer.query_status().as_dict() if connected else {"state": "printing"}
            st["state"] = "printing"
            st["progress"] = self._stream_pct
        elif self.agent.print_active.is_set():
            st = {"state": "printing"}
        elif connected:
            st = printer.query_status().as_dict()
        else:
            st = {"state": "offline"}
        st["connected"] = connected
        # The running agent's version, so the device page can detect a restart to
        # new code (version changed since the page loaded) and reload itself.
        st["agent_version"] = self.agent.cfg.agent_version
        # Connectivity to the central Printellect server (from the agent's last
        # heartbeat), so the device page can show a server indicator too.
        st["server_connected"] = bool(getattr(self.agent, "server_online", False))
        st["print_active"] = self.agent.print_active.is_set()
        if self._active_file:
            st["current_file"] = self._active_file
        # Derive elapsed/remaining for any running print so the device page can
        # show times, not just a byte-percentage. Tracked from when we first
        # observe the printing state (works regardless of who started it).
        if st.get("state") == "printing":
            if self._print_start_ts is None:
                self._print_start_ts = time.time()
            elapsed = int(time.time() - self._print_start_ts)
            st["elapsed_s"] = elapsed
            prog = st.get("progress")
            if isinstance(prog, (int, float)) and 0 < prog < 100:
                st["eta_s"] = int(elapsed * (100 - prog) / prog)
        else:
            self._print_start_ts = None
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

    def _stream_mode(self) -> bool:
        return (getattr(self.agent.cfg, "print_mode", "sd") or "sd").lower() == "stream"

    def _print_worker(self, path: str, name: str) -> None:
        printer = self.agent.printer
        streaming = self._stream_mode()
        try:
            if streaming:
                # Host-stream: prints as it sends (no slow SD upload). print_active
                # stays set for the whole print since stream_print blocks until done.
                self._cancel.clear()
                self._paused.clear()
                self._stream_pct = 0
                printer.enable_auto_reports(self.agent.cfg.heartbeat_interval_s, self.agent.cfg.poll_interval_s)
                completed = printer.stream_print(
                    path,
                    on_progress=lambda p: setattr(self, "_stream_pct", p),
                    should_continue=lambda: not self._cancel.is_set(),
                    paused=lambda: self._paused.is_set(),
                )
                if not completed:
                    try:
                        printer.abort_print()  # canceled: stop heating + motion
                    except Exception:
                        pass
                    self._active_file = None
                log.info("Stream print %s: %s", "finished" if completed else "canceled", name)
            else:
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
            self._stream_pct = None
            # SD: print runs autonomously now. Stream: the print just finished.
            self.agent.print_active.clear()
            if streaming:
                self._active_file = None
                self._print_start_ts = None

    def _require_printer(self):
        printer = self.agent.printer
        if not printer or not printer.connected:
            raise ControllerError("Printer is offline")
        return printer

    def pause(self) -> None:
        if self._stream_pct is not None:
            self._paused.set()  # stream: hold at the next line
        else:
            self._require_printer().pause_print()

    def resume(self) -> None:
        if self._stream_pct is not None:
            self._paused.clear()
        else:
            self._require_printer().resume_print()

    def cancel(self) -> None:
        self._cancel.set()  # stop a running stream
        self._paused.clear()
        self._require_printer().abort_print()
        self._active_file = None
        self._print_start_ts = None

    def estop(self) -> None:
        """Emergency stop — halt the printer immediately (M112)."""
        self._require_printer().emergency_stop()
        self.agent.print_active.clear()
        self._active_file = None
        self._print_start_ts = None

    def restart_agent(self) -> None:
        """Exit the process so the service manager restarts a fresh agent.

        This is how updated agent code (e.g. a new device page) is applied from
        the device UI. Refused mid-print so we never drop a running job.
        """
        if self.agent.print_active.is_set():
            raise Busy("Cannot restart while a print is running")
        printer = self.agent.printer
        if printer and printer.connected and printer.is_busy():
            raise Busy("Cannot restart while a print is running")
        from .commands import _delayed_exit
        log.info("Agent restart requested from the device page")
        _delayed_exit(1.0, code=0)

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

    # ── OTA update state/actions (via central server) ────────────
    def update_state(self) -> Dict[str, Any]:
        try:
            return self.agent.client.self_update_state()
        except Exception as e:
            raise ControllerError(str(e))

    def start_update(self) -> Dict[str, Any]:
        try:
            return self.agent.client.self_update()
        except Exception as e:
            raise ControllerError(str(e))

    def verify_update(self, cmd_ids: str) -> Dict[str, Any]:
        if not cmd_ids:
            raise ControllerError("cmd_ids required")
        try:
            return self.agent.client.self_update_verification(cmd_ids)
        except Exception as e:
            raise ControllerError(str(e))
