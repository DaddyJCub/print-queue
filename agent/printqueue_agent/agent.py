"""
Main agent loop.

State machine (per iteration):
  * Ensure a serial connection to the printer (skip the cycle if the port is
    busy — e.g. someone is printing from Cura — so we never interfere).
  * Heartbeat the printer's status to the server.
  * If idle, claim the next queued job and run it:
      download gcode -> upload to SD -> start SD print -> monitor to completion.
  * Periodically push a camera snapshot if configured.

The print itself lives on the printer's SD card, so even if this agent or its
host restarts mid-print, the print continues and we simply re-attach to monitor.
"""

from __future__ import annotations

import logging
import os
import socket
import tempfile
import threading
import time
from typing import Optional

from .camera import Camera
from .client import PrintQueueClient, ServerError
from .commands import CommandExecutor, install_log_ring
from .config import AgentConfig
from .serial_printer import PrinterStatus, SerialPrinter, list_serial_ports

log = logging.getLogger("printqueue.agent")


class Agent:
    def __init__(self, cfg: AgentConfig, config_path: Optional[str] = None):
        self.cfg = cfg
        self.config_path = config_path
        self.client = PrintQueueClient(
            cfg.server_url, cfg.agent_id, cfg.claim_code,
            verify_tls=cfg.verify_tls,
        )
        self.printer: Optional[SerialPrinter] = None
        self.camera = Camera(cfg.camera, verify_tls=cfg.verify_tls)
        self.commands = CommandExecutor(self)
        # Set while a print is being started locally (device page), so the
        # central-job loop doesn't grab the serial port at the same time.
        self.print_active = threading.Event()
        self._ui_server = None
        self._last_heartbeat = 0.0
        self._last_snapshot = 0.0
        # Whether the last heartbeat/provision reached the server (surfaced as the
        # "Printellect" connection indicator on the device page).
        self.server_online = False
        self._cached_ip: Optional[str] = None
        # Live print mode ("sd" | "stream"), switchable at runtime from the device
        # page / admin and persisted to config.json so it survives a restart.
        self.print_mode = (getattr(cfg, "print_mode", "sd") or "sd").strip().lower()
        # Progress (0-100) of the print the agent is currently driving, so the
        # heartbeat/admin can show it (SD upload, SD print, or stream).
        self.print_progress: Optional[int] = None
        # Serial trace (TX>/RX< logging), toggleable at runtime.
        self.serial_debug = bool(getattr(cfg, "serial_debug", False))
        install_log_ring()

    def set_serial_debug(self, enabled) -> bool:
        """Turn the serial TX>/RX< trace on/off live and persist it."""
        enabled = bool(enabled)
        self.serial_debug = enabled
        self.cfg.serial_debug = enabled
        if self.printer is not None:
            self.printer.trace = enabled
        self._persist_config({"serial_debug": enabled})
        log.info("Serial trace %s", "ENABLED" if enabled else "disabled")
        return enabled

    def set_print_mode(self, mode: str) -> str:
        """Change the print mode at runtime and persist it. Applies to the NEXT
        print (a running print keeps its mode)."""
        mode = (mode or "").strip().lower()
        if mode not in ("sd", "stream"):
            raise ValueError("print_mode must be 'sd' or 'stream'")
        self.print_mode = mode
        self.cfg.print_mode = mode
        self._persist_config({"print_mode": mode})
        log.info("Print mode set to %s", mode)
        return mode

    def _persist_config(self, updates: dict) -> None:
        """Best-effort merge of key/values into config.json on disk."""
        if not self.config_path or not os.path.isfile(self.config_path):
            return
        try:
            import json
            with open(self.config_path, "r") as fh:
                data = json.load(fh)
            data.update(updates)
            tmp = self.config_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, self.config_path)
        except Exception as e:
            log.warning("Could not persist config (%s): %s", updates, e)

    def _primary_ip(self) -> str:
        """Best-effort primary LAN IPv4 of this host (cached).

        Used so the server always knows how to reach the on-device page, without
        depending on a separate host-info command.
        """
        if self._cached_ip is not None:
            return self._cached_ip
        ip = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))  # no packets sent; just picks the route
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                ip = ""
        self._cached_ip = ip
        return ip

    def _heartbeat_status(self, status: PrinterStatus) -> dict:
        """Printer status plus the bits the server needs to link to this device."""
        d = status.as_dict()
        ip = self._primary_ip()
        if ip:
            d["agent_ip"] = ip
        if self.cfg.local_ui.enabled:
            d["device_ui_port"] = self.cfg.local_ui.port
        d["print_mode"] = self.print_mode
        d["serial_debug"] = self.serial_debug
        return d

    def _maybe_start_local_ui(self) -> None:
        """Start the ZMOD-style device-page web server (once)."""
        if self._ui_server is not None or not self.cfg.local_ui.enabled:
            return
        try:
            from .controller import AgentPrinterController
            from .local_ui import start_in_thread
            controller = AgentPrinterController(self)
            self._ui_server = start_in_thread(
                controller, self.cfg.local_ui.host, self.cfg.local_ui.port, self.cfg.local_ui.api_key,
            )
        except Exception as e:
            log.warning("Could not start local device UI: %s", e)

    def reload_config(self) -> None:
        """Re-read config.json (used by the reload_config command)."""
        if not self.config_path:
            return
        self.cfg = AgentConfig.load(self.config_path)
        self.camera = Camera(self.cfg.camera, verify_tls=self.cfg.verify_tls)

    # ── connection management ─────────────────────────────────────
    def _resolve_port(self) -> Optional[str]:
        if self.cfg.serial_port and self.cfg.serial_port != "auto":
            return self.cfg.serial_port
        ports = list_serial_ports()
        if not ports:
            return None
        # Prefer a real USB serial adapter (the printer) over the Pi's onboard
        # UART (/dev/ttyS0, /dev/ttyAMA0), which "auto" would otherwise grab and
        # then time out on ("readiness to read but returned no data").
        usb = [p for p in ports if "USB" in p.upper() or "ACM" in p.upper()]
        chosen = (usb or ports)[0]
        if usb and chosen != ports[0]:
            log.info("Auto-selected USB serial port %s (skipped %s)", chosen, ports[0])
        return chosen

    def _ensure_printer(self) -> bool:
        if self.printer and self.printer.connected:
            return True
        port = self._resolve_port()
        if not port:
            log.warning("No serial port available (printer off or unplugged?)")
            return False
        try:
            self.printer = SerialPrinter(port, self.cfg.baud_rate)
            self.printer.trace = self.serial_debug
            self.printer.connect()
            self.printer.enable_auto_reports(self.cfg.heartbeat_interval_s, self.cfg.poll_interval_s)
            return True
        except Exception as e:
            # Port busy (Cura connected) or printer not ready — back off, don't crash.
            log.warning("Cannot connect to printer right now: %s", e)
            self.printer = None
            return False

    def _printer_status(self) -> PrinterStatus:
        if not self.printer or not self.printer.connected:
            return PrinterStatus(state="offline")
        # While a print holds the port (upload or stream), don't send M105 — it
        # would block. Report cached temps (from auto-reports) + our progress so
        # the server/admin still see live status.
        if self.print_active.is_set():
            st = self.printer.cached_status()
            st.state = "printing"
            if self.print_progress is not None:
                st.progress = self.print_progress
            return st
        return self.printer.query_status()

    # ── main loop ─────────────────────────────────────────────────
    def run_forever(self) -> None:
        log.info("Starting agent %s -> %s", self.cfg.agent_id, self.cfg.server_url)
        self._maybe_start_local_ui()
        self._provision_with_retry()
        while True:
            try:
                self._tick()
            except KeyboardInterrupt:
                log.info("Shutting down")
                break
            except Exception as e:
                log.exception("Unexpected error in loop: %s", e)
            # In long-poll mode the events call blocks (its own pacing); in plain
            # polling mode we wait poll_interval_s between ticks.
            if not self.cfg.long_poll:
                time.sleep(self.cfg.poll_interval_s)
        if self.printer:
            self.printer.close()

    def _provision_with_retry(self) -> None:
        delay = 2
        while True:
            try:
                self.client.provision(self.cfg.agent_version)
                self.server_online = True
                return
            except Exception as e:
                self.server_online = False
                log.warning("Provision failed (%s); retrying in %ss", e, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def _tick(self) -> None:
        connected = self._ensure_printer()
        status = self._printer_status()

        # A printer that stops answering (reset, USB dropout, 5V back-power glitch)
        # leaves the port nominally "open", so query_status times out forever and
        # the agent never recovers. Drop the dead connection so the next tick
        # reconnects and re-syncs. (Not while a local upload holds the port.)
        if (status.state == "offline" and self.printer is not None
                and not self.print_active.is_set()):
            log.warning("Printer unresponsive — dropping connection to force a reconnect")
            try:
                self.printer.close()
            except Exception:
                pass
            self.printer = None
            connected = False

        now = time.time()
        if now - self._last_heartbeat >= self.cfg.heartbeat_interval_s:
            try:
                self.client.heartbeat(self.cfg.agent_version, self._heartbeat_status(status))
                self.server_online = True
            except ServerError as e:
                self.server_online = False
                log.warning("Heartbeat failed: %s", e)
            self._last_heartbeat = now

        self._maybe_snapshot()

        # Jobs are only claimed when connected, idle and not mid local print;
        # commands are always picked up (e.g. to manage an offline printer).
        want_jobs = connected and status.state == "idle" and not self.print_active.is_set()
        if self.cfg.long_poll:
            self._poll_events(want_jobs)
        else:
            self._poll_commands()
            if want_jobs:
                try:
                    job = self.client.next_job()
                except ServerError as e:
                    log.warning("Job poll failed: %s", e)
                    job = None
                if job:
                    self._run_job(job)

    def _poll_events(self, want_jobs: bool) -> None:
        """Long-poll for the next command/job and act on it (low-latency path)."""
        # Cap the hold so heartbeats/snapshots still happen on cadence.
        timeout = max(1, min(self.cfg.stream_timeout_s, self.cfg.heartbeat_interval_s))
        if self.cfg.camera.enabled:
            timeout = min(timeout, self.cfg.camera.interval_s)
        try:
            ev = self.client.next_event(timeout, want_jobs=want_jobs)
            self.server_online = True
        except ServerError as e:
            self.server_online = False
            log.warning("Event poll failed: %s", e)
            time.sleep(min(self.cfg.poll_interval_s, 5))  # back off; avoid hot loop on outage
            return
        if not ev:
            return
        if ev.get("type") == "command" and ev.get("command"):
            self.commands.handle(ev["command"])
        elif ev.get("type") == "job" and ev.get("job"):
            self._run_job(ev["job"])

    def _poll_commands(self) -> None:
        """Pick up and run any queued remote-management commands (polling mode)."""
        try:
            cmd = self.client.next_command()
            self.server_online = True
        except ServerError as e:
            self.server_online = False
            log.warning("Command poll failed: %s", e)
            return
        if cmd:
            self.commands.handle(cmd)

    def _maybe_snapshot(self) -> None:
        if not self.cfg.camera.enabled:
            return
        now = time.time()
        if now - self._last_snapshot < self.cfg.camera.interval_s:
            return
        self._last_snapshot = now
        frame = self.camera.capture()
        if frame:
            try:
                self.client.upload_snapshot(frame)
            except ServerError as e:
                log.warning("Snapshot upload failed: %s", e)

    # ── job execution ─────────────────────────────────────────────
    def _run_job(self, job: dict) -> None:
        job_id = job["job_id"]
        file_name = job.get("file_name") or "print.gcode"
        log.info("Claimed job %s (%s)", job_id, file_name)

        tmp_path = os.path.join(tempfile.gettempdir(), f"pq_{job_id}.gcode")
        self.print_active.set()  # block the device page from racing for the port
        try:
            self.client.update_job(job_id, "claimed")
            self.client.download_job_file(job_id, tmp_path)

            assert self.printer is not None
            # Final safety check: never start over an in-progress print.
            if self.printer.is_busy():
                log.warning("Printer became busy; deferring job %s", job_id)
                self.client.update_job(job_id, "queued")
                return

            if self.print_mode == "stream":
                # Host-stream directly (no slow SD upload); prints as it sends.
                self.printer.enable_auto_reports(3, self.cfg.poll_interval_s)
                self.client.update_job(job_id, "printing", progress=0)
                # Throttle the cancel check: it's called per line, but each is a
                # server round-trip, so only re-check every few seconds.
                cc = {"t": 0.0, "canceled": False}

                def _still_wanted() -> bool:
                    now = time.time()
                    if now - cc["t"] >= 5:
                        cc["t"] = now
                        cc["canceled"] = self._job_canceled(job_id)
                    return not cc["canceled"]

                def _sprog(p):
                    self.print_progress = p
                    self._safe_update(job_id, "printing", progress=p)

                completed = self.printer.stream_print(
                    tmp_path,
                    on_progress=_sprog,
                    should_continue=_still_wanted,
                )
                if completed:
                    self.client.update_job(job_id, "completed", progress=100)
                else:
                    self.printer.abort_print()
                    self.client.update_job(job_id, "canceled")
            else:
                self.client.update_job(job_id, "uploading", progress=0)
                self.printer.upload_to_sd(
                    tmp_path,
                    on_progress=lambda p: self._safe_update(job_id, "uploading", progress=p),
                )

                self.printer.start_sd_print()
                self.printer.enable_auto_reports(self.cfg.heartbeat_interval_s, self.cfg.poll_interval_s)
                self.client.update_job(job_id, "printing", progress=0)

                self._monitor_print(job_id)
        except Exception as e:
            log.exception("Job %s failed: %s", job_id, e)
            try:
                self.client.update_job(job_id, "failed", error=str(e))
            except ServerError:
                pass
        finally:
            self.print_active.clear()
            self.print_progress = None
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _safe_update(self, job_id: str, status: str, **kwargs) -> None:
        try:
            self.client.update_job(job_id, status, **kwargs)
        except ServerError as e:
            log.warning("job update failed: %s", e)

    def _job_canceled(self, job_id: str) -> bool:
        """True if the server marked this job canceled (admin 'Cancel job')."""
        try:
            info = self.client.get_job(job_id)
        except ServerError as e:
            log.warning("Job status check failed: %s", e)
            return False
        return bool(info and info.get("status") == "canceled")

    def _monitor_print(self, job_id: str) -> None:
        """Poll until the SD print finishes (or is canceled server-side)."""
        assert self.printer is not None
        printing_seen = False
        last_report = 0.0
        while True:
            status = self.printer.query_status()

            now = time.time()
            if now - last_report >= self.cfg.heartbeat_interval_s:
                # Honor an admin 'Cancel job' by aborting the physical SD print.
                if self._job_canceled(job_id):
                    log.info("Job %s canceled server-side; aborting print", job_id)
                    try:
                        self.printer.abort_print()
                    except Exception as e:
                        log.warning("Abort after cancel failed: %s", e)
                    return
                self._safe_update(job_id, "printing", progress=status.progress or 0)
                try:
                    self.client.heartbeat(self.cfg.agent_version, self._heartbeat_status(status))
                    self.server_online = True
                except ServerError:
                    self.server_online = False
                self._maybe_snapshot()
                last_report = now

            if status.state == "printing":
                printing_seen = True
            elif printing_seen and status.state == "idle":
                # Transitioned printing -> idle == finished.
                log.info("Job %s completed", job_id)
                self._safe_update(job_id, "completed", progress=100)
                return

            time.sleep(self.cfg.poll_interval_s)
