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
import tempfile
import time
from typing import Optional

from .camera import Camera
from .client import PrintQueueClient, ServerError
from .config import AgentConfig
from .serial_printer import PrinterStatus, SerialPrinter, list_serial_ports

log = logging.getLogger("printqueue.agent")


class Agent:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.client = PrintQueueClient(
            cfg.server_url, cfg.agent_id, cfg.claim_code,
            verify_tls=cfg.verify_tls,
        )
        self.printer: Optional[SerialPrinter] = None
        self.camera = Camera(cfg.camera, verify_tls=cfg.verify_tls)
        self._last_heartbeat = 0.0
        self._last_snapshot = 0.0

    # ── connection management ─────────────────────────────────────
    def _resolve_port(self) -> Optional[str]:
        if self.cfg.serial_port and self.cfg.serial_port != "auto":
            return self.cfg.serial_port
        ports = list_serial_ports()
        return ports[0] if ports else None

    def _ensure_printer(self) -> bool:
        if self.printer and self.printer.connected:
            return True
        port = self._resolve_port()
        if not port:
            log.warning("No serial port available (printer off or unplugged?)")
            return False
        try:
            self.printer = SerialPrinter(port, self.cfg.baud_rate)
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
        return self.printer.query_status()

    # ── main loop ─────────────────────────────────────────────────
    def run_forever(self) -> None:
        log.info("Starting agent %s -> %s", self.cfg.agent_id, self.cfg.server_url)
        self._provision_with_retry()
        while True:
            try:
                self._tick()
            except KeyboardInterrupt:
                log.info("Shutting down")
                break
            except Exception as e:
                log.exception("Unexpected error in loop: %s", e)
            time.sleep(self.cfg.poll_interval_s)
        if self.printer:
            self.printer.close()

    def _provision_with_retry(self) -> None:
        delay = 2
        while True:
            try:
                self.client.provision(self.cfg.agent_version)
                return
            except Exception as e:
                log.warning("Provision failed (%s); retrying in %ss", e, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def _tick(self) -> None:
        connected = self._ensure_printer()
        status = self._printer_status()

        now = time.time()
        if now - self._last_heartbeat >= self.cfg.heartbeat_interval_s:
            try:
                self.client.heartbeat(self.cfg.agent_version, status.as_dict())
            except ServerError as e:
                log.warning("Heartbeat failed: %s", e)
            self._last_heartbeat = now

        self._maybe_snapshot()

        # Only pick up new work when connected and idle.
        if connected and status.state == "idle":
            job = None
            try:
                job = self.client.next_job()
            except ServerError as e:
                log.warning("Job poll failed: %s", e)
            if job:
                self._run_job(job)

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
        try:
            self.client.update_job(job_id, "claimed")
            self.client.download_job_file(job_id, tmp_path)

            assert self.printer is not None
            # Final safety check: never start over an in-progress print.
            if self.printer.is_busy():
                log.warning("Printer became busy; deferring job %s", job_id)
                self.client.update_job(job_id, "queued")
                return

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
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _safe_update(self, job_id: str, status: str, **kwargs) -> None:
        try:
            self.client.update_job(job_id, status, **kwargs)
        except ServerError as e:
            log.warning("job update failed: %s", e)

    def _monitor_print(self, job_id: str) -> None:
        """Poll until the SD print finishes (or is canceled server-side)."""
        assert self.printer is not None
        printing_seen = False
        last_report = 0.0
        while True:
            status = self.printer.query_status()

            now = time.time()
            if now - last_report >= self.cfg.heartbeat_interval_s:
                self._safe_update(job_id, "printing", progress=status.progress or 0)
                try:
                    self.client.heartbeat(self.cfg.agent_version, status.as_dict())
                except ServerError:
                    pass
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
