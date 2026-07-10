"""
Serial driver for Marlin-based printers (Longer LK5 Pro and friends).

Strategy
--------
We do NOT host-stream the print line-by-line over USB (that ties the print to
the PC staying on). Instead we:

  1. Upload the sliced gcode to the printer's SD card (``M28``/``M29``) using
     Marlin's line-numbered + checksummed protocol so the transfer is verified
     byte-for-byte (same accuracy as printing the file from SD by hand).
  2. Start an SD print (``M23``/``M24``). From then on the printer runs
     **autonomously** — the host can disconnect and the print still finishes.
  3. Keep the connection open only to *monitor* (``M27`` SD progress, ``M105``
     temps). Marlin happily answers these report queries during an SD print.

Because a serial port can only be held by one program, the agent owning the
port means Cura cannot be connected at the same time — which is intended: the
agent replaces Cura as the print *driver* (you still slice in Cura). If the
port is already in use (e.g. a manual Cura print), :meth:`connect` fails and the
agent backs off instead of interfering.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

try:
    import serial  # pyserial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover - import guard for environments w/o pyserial
    serial = None
    list_ports = None

log = logging.getLogger("printqueue.serial")

# Name used for the uploaded file on the printer's SD card. Kept short/uppercase
# (8.3) for maximum firmware compatibility. A single active job overwrites it.
SD_FILENAME = "PQPRINT.GCO"


@dataclass
class PrinterStatus:
    state: str = "idle"            # idle | printing | paused | offline
    progress: Optional[int] = None  # 0-100 (SD byte progress)
    sd_current: Optional[int] = None
    sd_total: Optional[int] = None
    nozzle_temp: Optional[float] = None
    nozzle_target: Optional[float] = None
    bed_temp: Optional[float] = None
    bed_target: Optional[float] = None
    current_file: Optional[str] = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _checksum(line: str) -> int:
    cs = 0
    for ch in line:
        cs ^= ord(ch)
    return cs & 0xFF


def list_serial_ports() -> list[str]:
    if list_ports is None:
        return []
    return [p.device for p in list_ports.comports()]


class SerialPrinter:
    """Thin, robust wrapper around a Marlin printer's USB serial line."""

    def __init__(self, port: str, baud: int = 115200, connect_timeout: float = 20.0):
        if serial is None:
            raise RuntimeError("pyserial is not installed. Run: pip install pyserial")
        self.port = port
        self.baud = baud
        self.connect_timeout = connect_timeout
        self._ser: Optional["serial.Serial"] = None
        self._line_no = 0
        # Re-entrant lock: the agent loop and the local-UI server thread share
        # this one port, so every serial round-trip must be serialized.
        self._lock = threading.RLock()

    # ── connection ────────────────────────────────────────────────
    def connect(self) -> None:
        """Open the port and bring the printer to a ready state.

        Hardened for the things that plague USB-serial Marlin boards (the LK5 Pro
        especially): the board resets when the port opens (DTR), so we wait for it
        to boot; a back-power brownout can drop the first reply, so we retry the
        handshake; and a wrong baud yields no ``ok``, so we try the configured
        rate first then common fallbacks.

        Raises if the port is busy (another program owns it) or no baud responds,
        so the caller can back off without disturbing an in-progress print.
        """
        bauds: list[int] = []
        for b in (self.baud, 115200, 250000, 57600):
            if b and b not in bauds:
                bauds.append(b)

        last_err: Optional[Exception] = None
        for baud in bauds:
            try:
                self._open_and_handshake(baud)
                self.baud = baud
                log.info("Connected to printer on %s @ %d", self.port, baud)
                self._log_firmware()
                return
            except Exception as e:
                last_err = e
                log.warning("No response on %s @ %d baud (%s)", self.port, baud, e)
                self.close()
        raise RuntimeError(f"Could not communicate with printer on {self.port}: {last_err}")

    def _open_and_handshake(self, baud: int) -> None:
        # exclusive=True (POSIX) makes a *second* opener fail cleanly instead of
        # both processes sharing the port and corrupting each other's traffic
        # ("device reports readiness to read but returned no data / multiple
        # access on port"). Not supported on Windows, so guard it.
        kwargs = {"timeout": 2, "write_timeout": 15}
        if os.name == "posix":
            kwargs["exclusive"] = True
        try:
            self._ser = serial.Serial(self.port, baud, **kwargs)
        except Exception as e:
            raise RuntimeError(f"Could not open {self.port} (already in use by another "
                               f"program / a second agent?): {e}") from e
        # The board resets when the port opens (DTR); wait for it to boot.
        self._wait_for_boot(timeout=8.0)
        self._ser.reset_input_buffer()
        self._line_no = 0
        # The first M110 after a reset/brownout is sometimes dropped — retry.
        last: Optional[Exception] = None
        for _ in range(3):
            try:
                self._send_now("M110 N0")
                self._wait_ok(timeout=8.0)
                return
            except Exception as e:
                last = e
                time.sleep(0.8)
        raise RuntimeError(f"no 'ok' to M110 handshake: {last}")

    def _wait_for_boot(self, timeout: float) -> None:
        """Drain the printer's post-reset boot output. Returns on the Marlin
        'start' banner, or promptly once the line falls quiet (no-reset boards)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._readline()
            except Exception:
                return
            if not line:
                return  # quiet: boot finished, or the board didn't reset
            low = line.lower()
            if low.startswith("start") or "marlin" in low:
                log.info("Printer booted: %s", line[:120])
                time.sleep(0.3)
                return

    def _log_firmware(self) -> None:
        # Ask the printer what firmware it runs so it's visible in the logs
        # (answers "what does my board support?" without guessing).
        try:
            resp = self.send_command("M115", timeout=8)
            for ln in resp.splitlines():
                if "FIRMWARE_NAME" in ln or "MACHINE_TYPE" in ln:
                    log.info("Printer firmware: %s", ln.strip()[:200])
                    break
        except Exception as e:
            log.warning("Could not read firmware (M115): %s", e)

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            try:
                self._ser.close()
            finally:
                self._ser = None

    @property
    def connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    # ── low-level IO ──────────────────────────────────────────────
    def _send_now(self, command: str) -> None:
        """Send a raw command (no line number) immediately."""
        assert self._ser is not None
        self._ser.write((command + "\n").encode("ascii", errors="ignore"))
        self._ser.flush()

    def _readline(self) -> str:
        assert self._ser is not None
        return self._ser.readline().decode("ascii", errors="ignore").strip()

    def _wait_ok(self, timeout: float = 10.0) -> str:
        """Read until an 'ok' (collecting any report lines), or raise on timeout."""
        deadline = time.time() + timeout
        buf = []
        while time.time() < deadline:
            line = self._readline()
            if not line:
                continue
            buf.append(line)
            low = line.lower()
            if low.startswith("ok"):
                return "\n".join(buf)
            if low.startswith("resend") or low.startswith("rs"):
                # Surface resend requests to the checksummed sender.
                return "\n".join(buf)
            if "busy" in low:
                # "echo:busy: processing" — the printer is alive but working
                # (e.g. a slow SD write or long move). Extend the deadline so we
                # don't falsely time out mid-operation, the way OctoPrint does.
                deadline = time.time() + timeout
        raise TimeoutError("Timed out waiting for 'ok' from printer")

    def send_command(self, command: str, timeout: float = 30.0) -> str:
        """Send a single gcode command with line number + checksum, handling resends."""
        with self._lock:
            for attempt in range(5):
                self._line_no += 1
                payload = f"N{self._line_no} {command}"
                framed = f"{payload}*{_checksum(payload)}"
                self._send_now(framed)
                resp = self._wait_ok(timeout=timeout)
                low = resp.lower()
                if "resend" in low or low.startswith("rs"):
                    # Roll back the line number and retry.
                    self._line_no -= 1
                    time.sleep(0.05)
                    continue
                return resp
            raise RuntimeError(f"Repeated resend requests for: {command}")

    # ── status ────────────────────────────────────────────────────
    def query_status(self) -> PrinterStatus:
        """One-shot status snapshot via M105 (temps) + M27 (SD progress)."""
        st = PrinterStatus(state="idle")
        try:
            with self._lock:
                temp_resp = self.send_command("M105", timeout=8)
                self._parse_temps(temp_resp, st)
                sd_resp = self.send_command("M27", timeout=8)
                self._parse_sd(sd_resp, st)
        except Exception as e:
            log.warning("Status query failed: %s", e)
            st.state = "offline"
        return st

    @staticmethod
    def _parse_temps(resp: str, st: PrinterStatus) -> None:
        # e.g. "ok T:205.0 /210.0 B:60.0 /60.0 @:127"
        import re

        m = re.search(r"T:\s*([\d.]+)\s*/\s*([\d.]+)", resp)
        if m:
            st.nozzle_temp = float(m.group(1))
            st.nozzle_target = float(m.group(2))
        m = re.search(r"B:\s*([\d.]+)\s*/\s*([\d.]+)", resp)
        if m:
            st.bed_temp = float(m.group(1))
            st.bed_target = float(m.group(2))

    @staticmethod
    def _parse_sd(resp: str, st: PrinterStatus) -> None:
        import re

        # "SD printing byte 1234/56789" or "Not SD printing"
        m = re.search(r"SD printing byte\s+(\d+)\s*/\s*(\d+)", resp)
        if m:
            cur, total = int(m.group(1)), int(m.group(2))
            st.sd_current, st.sd_total = cur, total
            st.state = "printing"
            st.progress = int(cur * 100 / total) if total else 0
        elif "not sd printing" in resp.lower():
            st.state = "idle"

    def is_busy(self) -> bool:
        """True if an SD print is already running (don't start a new job)."""
        return self.query_status().state == "printing"

    # ── job execution ─────────────────────────────────────────────
    def upload_to_sd(self, gcode_path: str, on_progress: Optional[Callable[[int], None]] = None) -> None:
        """Stream a local gcode file to the printer's SD card (M28 ... M29).

        Logs progress every 5% (and at least every 15s) so ``journalctl -f`` /
        the "View logs" panel show exactly where a slow serial upload is at.
        """
        import os

        total = os.path.getsize(gcode_path)
        sent = 0
        lines = 0
        last_pct = -1
        start = time.time()
        last_log = start
        next_log_pct = 0

        log.info("Uploading %s -> SD:%s (%d bytes). Serial SD writes are slow "
                 "(~one round-trip per line); this can take several minutes.",
                 os.path.basename(gcode_path), SD_FILENAME, total)
        # Hold the port for the whole transfer so nothing interleaves commands.
        # M28 MUST be inside the try: if it raises, the finally still releases the
        # lock (otherwise a serial hiccup at print start deadlocks every status
        # query forever).
        self._lock.acquire()
        try:
            self.send_command(f"M28 {SD_FILENAME}", timeout=30)
            with open(gcode_path, "r", errors="ignore") as fh:
                for raw in fh:
                    line = raw.split(";", 1)[0].strip()  # drop comments/whitespace
                    sent += len(raw)
                    if not line:
                        continue
                    self.send_command(line, timeout=30)
                    lines += 1
                    pct = int(sent * 100 / total) if total else 0
                    if on_progress and pct != last_pct:
                        last_pct = pct
                        on_progress(pct)
                    now = time.time()
                    if pct >= next_log_pct or now - last_log >= 15:
                        elapsed = now - start
                        rate = sent / elapsed if elapsed > 0 else 0.0  # bytes/s
                        eta = int((total - sent) / rate) if rate > 0 else 0
                        log.info("Upload %2d%% — %d/%d bytes, %d lines, %.1f KB/s, ETA %ds",
                                 pct, sent, total, lines, rate / 1024, eta)
                        last_log = now
                        next_log_pct = (pct // 5 + 1) * 5
        finally:
            # Always close the SD file, even on error. Marlin requires lines
            # after M28 to keep the line-number/checksum framing, so close with
            # the framed sender (a raw M29 after numbered lines can error); fall
            # back to a raw M29 if the framed one is rejected.
            try:
                self.send_command("M29", timeout=30)
            except Exception as e:
                log.warning("Framed M29 failed (%s); sending raw M29", e)
                self._send_now("M29")
                try:
                    self._wait_ok(timeout=30)
                except Exception:
                    pass
            finally:
                self._lock.release()
        dur = time.time() - start
        log.info("Upload complete: %s — %d lines, %d bytes in %.0fs (%.1f KB/s)",
                 SD_FILENAME, lines, sent, dur, (sent / 1024) / dur if dur > 0 else 0.0)

    def start_sd_print(self) -> None:
        """Select the uploaded file and begin the (autonomous) SD print."""
        self.send_command(f"M23 {SD_FILENAME}", timeout=15)
        self.send_command("M24", timeout=15)
        log.info("SD print started: %s", SD_FILENAME)

    def stream_print(self, gcode_path: str,
                     on_progress: Optional[Callable[[int], None]] = None,
                     should_continue: Optional[Callable[[], bool]] = None,
                     paused: Optional[Callable[[], bool]] = None) -> bool:
        """Host-stream a gcode file straight to the printer (no SD upload).

        The printer prints as we send; Marlin's per-line ``ok`` is the flow
        control. Far faster to *start* than an SD upload (no upfront copy), but
        the connection must stay up for the whole print. Returns True if the file
        was fully sent, False if canceled via ``should_continue``.

        We do NOT hold the port lock across the whole print — each line self-locks
        — so status/heartbeat queries can interleave (temps stay live) exactly as
        OctoPrint polls during a print.
        """
        import os

        total = os.path.getsize(gcode_path)
        sent = 0
        lines = 0
        last_pct = -1
        start = time.time()
        last_log = start
        next_log_pct = 0

        log.info("Streaming %s to printer (%d bytes) — prints as it sends.",
                 os.path.basename(gcode_path), total)
        with self._lock:
            self._line_no = 0
            self.send_command("M110 N0", timeout=15)

        with open(gcode_path, "r", errors="ignore") as fh:
            for raw in fh:
                # Hold here while paused (the printer drains its planner buffer
                # then idles at temp); status queries still interleave meanwhile.
                while paused is not None and paused():
                    if should_continue is not None and not should_continue():
                        break
                    time.sleep(0.3)
                if should_continue is not None and not should_continue():
                    log.info("Stream print canceled at %d%%", last_pct)
                    return False
                line = raw.split(";", 1)[0].strip()
                sent += len(raw)
                if not line:
                    continue
                # Heating/homing lines (M109/M190/G28) can block for minutes;
                # _wait_ok tolerates the 'busy' keepalive, so a long timeout is safe.
                self.send_command(line, timeout=600)
                lines += 1
                pct = int(sent * 100 / total) if total else 0
                if on_progress and pct != last_pct:
                    last_pct = pct
                    on_progress(pct)
                now = time.time()
                if pct >= next_log_pct or now - last_log >= 20:
                    log.info("Print %2d%% — %d/%d bytes, %d lines sent", pct, sent, total, lines)
                    last_log = now
                    next_log_pct = (pct // 10 + 1) * 10
        dur = time.time() - start
        log.info("Stream print finished: %d lines, %d bytes in %.0fs", lines, sent, dur)
        return True

    def enable_auto_reports(self, temp_interval_s: int = 5, sd_interval_s: int = 5) -> None:
        """Ask Marlin to stream temp/SD reports so monitoring is low-overhead."""
        try:
            self.send_command(f"M155 S{temp_interval_s}", timeout=8)
            self.send_command(f"M27 S{sd_interval_s}", timeout=8)
        except Exception as e:
            log.warning("Could not enable auto-reports (non-fatal): %s", e)

    def abort_print(self) -> None:
        """Stop an in-progress SD print and cool down, across firmware versions.

        ``M524`` (clean SD abort) only exists on Marlin 2.0+. The stock LK5 Pro
        ships Marlin 1.1.9, which has no host abort gcode — so we fall back to
        ``M25`` (pause SD print, halting motion) plus cooling the hotend/bed and
        turning the fan off. On 1.1.9 a full job clear may still require the
        printer's screen; see the integration doc.
        """
        log.info("Stopping SD print")
        aborted = False
        try:
            self.send_command("M524", timeout=15)  # Marlin 2.0+ clean abort
            aborted = True
        except Exception as e:
            log.warning("M524 not available (%s); falling back to M25 pause", e)
        if not aborted:
            try:
                self.send_command("M25", timeout=15)  # pause SD print (1.1.9-safe)
            except Exception as e:
                log.warning("M25 pause failed: %s", e)
        for cmd in ("M104 S0", "M140 S0", "M107"):  # nozzle off, bed off, fan off
            try:
                self.send_command(cmd, timeout=8)
            except Exception:
                pass

    def emergency_stop(self) -> None:
        """Immediately halt the printer (Marlin ``M112``).

        M112 kills the planner and heaters at once — used for the device-page
        E-STOP. Marlin enters a killed state and may not return a clean ``ok``,
        so we send it raw and don't block on the response. Recovery needs an
        ``M999``/reset or a power-cycle.
        """
        log.warning("EMERGENCY STOP (M112)")
        with self._lock:
            try:
                self._send_now("M112")
            finally:
                try:
                    self._wait_ok(timeout=3)
                except Exception:
                    pass

    # ── manual controls (device page) ─────────────────────────────
    def pause_print(self) -> None:
        self.send_command("M25", timeout=15)   # pause SD print

    def resume_print(self) -> None:
        self.send_command("M24", timeout=15)   # resume SD print

    def set_hotend_temp(self, celsius: float) -> None:
        self.send_command(f"M104 S{int(celsius)}", timeout=8)

    def set_bed_temp(self, celsius: float) -> None:
        self.send_command(f"M140 S{int(celsius)}", timeout=8)

    def home(self, axes: str = "") -> None:
        axes = "".join(c for c in axes.upper() if c in "XYZ")
        self.send_command(("G28 " + " ".join(axes)).strip() if axes else "G28", timeout=60)

    def jog(self, axis: str, distance: float, feed: int = 3000) -> None:
        axis = axis.upper()
        if axis not in "XYZE":
            raise ValueError(f"Bad jog axis: {axis}")
        with self._lock:
            self.send_command("G91", timeout=8)            # relative
            self.send_command(f"G1 {axis}{distance} F{feed}", timeout=15)
            self.send_command("G90", timeout=8)            # back to absolute

    def set_fan(self, speed_0_255: int) -> None:
        speed = max(0, min(255, int(speed_0_255)))
        self.send_command(f"M106 S{speed}" if speed else "M107", timeout=8)
