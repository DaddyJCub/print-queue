"""Flash printer firmware (.hex) via avrdude.

The LK5 Pro mainboard is an 8-bit ATmega2560 (Arduino-Mega-class) flashed over
the same USB serial port the agent uses for printing. This is **opt-in** and
**risky** — a bad flash can brick the board — so it only runs when
``firmware.enabled`` is true in the agent config, never while printing, and the
printer serial connection is released first.

Requires avrdude on the host (``sudo apt install avrdude`` on a Pi; bundled with
the Arduino IDE on Windows).
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict

from .config import FirmwareConfig

log = logging.getLogger("printqueue.flash")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def flash(client, fw_cfg: FirmwareConfig, port: str, firmware_url: str,
          expected_sha: str | None, file_name: str = "firmware.hex") -> Dict[str, Any]:
    """Download and flash a firmware image. Returns a result dict for reporting."""
    if not fw_cfg.enabled:
        raise RuntimeError("Firmware flashing is disabled on this agent (set firmware.enabled)")
    if shutil.which(fw_cfg.avrdude_path) is None and not os.path.isfile(fw_cfg.avrdude_path):
        raise RuntimeError(f"avrdude not found ('{fw_cfg.avrdude_path}'); install it first")
    if not port:
        raise RuntimeError("No serial port to flash")

    work = tempfile.mkdtemp(prefix="pq_fw_")
    hex_path = os.path.join(work, file_name if file_name.endswith(".hex") else "firmware.hex")
    try:
        client.download_bundle(firmware_url, hex_path)
        if expected_sha:
            actual = _sha256(hex_path)
            if actual.lower() != expected_sha.lower():
                raise RuntimeError(f"Firmware checksum mismatch (expected {expected_sha}, got {actual})")

        cmd = [
            fw_cfg.avrdude_path,
            "-c", fw_cfg.programmer,
            "-p", fw_cfg.mcu,
            "-P", port,
            "-b", str(fw_cfg.baud),
            "-D",                       # do not auto-erase whole chip
            "-U", f"flash:w:{hex_path}:i",
            *fw_cfg.extra_args,
        ]
        log.info("Running: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(f"avrdude failed (exit {proc.returncode}):\n{output[-2000:]}")
        log.info("Firmware flash complete")
        return {"flashed": True, "output": output[-2000:]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
