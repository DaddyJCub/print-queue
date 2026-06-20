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

    # ── connection ────────────────────────────────────────────────
    def connect(self) -> None:
        """Open the port and wait for the printer to be ready.

        Raises if the port is busy (another program — e.g. Cura — owns it), so
        the caller can back off without disturbing an in-progress print.
        """
        try:
            self._ser = serial.Serial(self.port, self.baud, timeout=2)
        except Exception as e:
            raise RuntimeError(f"Could not open {self.port} (in use by another program?): {e}") from e

        # Many boards reset on connect; give Marlin time to boot, then flush.
        time.sleep(2.0)
        self._ser.reset_input_buffer()
        # Reset line numbering for the checksummed protocol.
        self._line_no = 0
        self._send_now("M110 N0")
        self._wait_ok(timeout=self.connect_timeout)
        log.info("Connected to printer on %s @ %d", self.port, self.baud)

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
        raise TimeoutError("Timed out waiting for 'ok' from printer")

    def send_command(self, command: str, timeout: float = 30.0) -> str:
        """Send a single gcode command with line number + checksum, handling resends."""
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
        """Stream a local gcode file to the printer's SD card (M28 ... M29)."""
        import os

        total = os.path.getsize(gcode_path)
        sent = 0
        last_pct = -1

        log.info("Uploading %s -> SD:%s (%d bytes)", gcode_path, SD_FILENAME, total)
        self.send_command(f"M28 {SD_FILENAME}", timeout=30)
        try:
            with open(gcode_path, "r", errors="ignore") as fh:
                for raw in fh:
                    line = raw.split(";", 1)[0].strip()  # drop comments/whitespace
                    sent += len(raw)
                    if not line:
                        continue
                    self.send_command(line, timeout=30)
                    if on_progress and total:
                        pct = int(sent * 100 / total)
                        if pct != last_pct:
                            last_pct = pct
                            on_progress(pct)
        finally:
            # Always close the SD file, even on error.
            self._send_now("M29")
            self._wait_ok(timeout=30)
        log.info("Upload complete: %s", SD_FILENAME)

    def start_sd_print(self) -> None:
        """Select the uploaded file and begin the (autonomous) SD print."""
        self.send_command(f"M23 {SD_FILENAME}", timeout=15)
        self.send_command("M24", timeout=15)
        log.info("SD print started: %s", SD_FILENAME)

    def enable_auto_reports(self, temp_interval_s: int = 5, sd_interval_s: int = 5) -> None:
        """Ask Marlin to stream temp/SD reports so monitoring is low-overhead."""
        try:
            self.send_command(f"M155 S{temp_interval_s}", timeout=8)
            self.send_command(f"M27 S{sd_interval_s}", timeout=8)
        except Exception as e:
            log.warning("Could not enable auto-reports (non-fatal): %s", e)

    def abort_print(self) -> None:
        """Abort an in-progress SD print and cool down."""
        log.info("Aborting SD print")
        try:
            self.send_command("M524", timeout=15)  # abort SD print
        except Exception as e:
            log.warning("M524 abort failed: %s", e)
        for cmd in ("M104 S0", "M140 S0", "M107"):  # nozzle off, bed off, fan off
            try:
                self.send_command(cmd, timeout=8)
            except Exception:
                pass
