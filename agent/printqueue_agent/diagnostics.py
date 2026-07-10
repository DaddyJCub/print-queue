"""Self-diagnostic (`python -m printqueue_agent --doctor`).

Runs a battery of checks and prints a report that pinpoints *why* the printer
isn't talking — distinguishing the common causes that otherwise look identical:

  * wrong port (the Pi's onboard UART) ....... SILENT on a non-USB tty
  * a second process holding the port ........ port opens non-exclusively / busy
  * wrong baud ............................... GARBAGE (bytes, but no `ok`)
  * printer off / cable / brownout ........... SILENT on the real USB port
  * Pi undervoltage (power / back-power) ..... vcgencmd throttled bits set
  * healthy link ............................. OK + firmware string
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import List, Optional, Tuple

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    serial = None
    list_ports = None

# USB-serial chips commonly found on Marlin printers (VID -> label).
_KNOWN_USB_VIDS = {
    0x1A86: "CH340/CH341 (very common on LK5 Pro)",
    0x10C4: "CP210x (Silicon Labs)",
    0x0403: "FTDI",
    0x2341: "Arduino",
    0x2A03: "Arduino",
}


def _fmt(status: str, msg: str) -> str:
    icon = {"ok": "✅", "warn": "⚠️ ", "fail": "❌", "info": "•"}.get(status, "•")
    return f"  {icon} {msg}"


def _enumerate_ports() -> List[dict]:
    out = []
    if list_ports is None:
        return out
    for p in list_ports.comports():
        out.append({
            "device": p.device,
            "desc": p.description,
            "hwid": p.hwid,
            "vid": p.vid,
            "pid": p.pid,
            "onboard": ("ttyS" in p.device or "ttyAMA" in p.device),
        })
    return out


def _procs_holding(port: str) -> List[Tuple[str, str]]:
    """Same-user processes with the port open (scans /proc; best-effort)."""
    holders = []
    mypid = str(os.getpid())
    if not os.path.isdir("/proc"):
        return holders
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fddir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fddir):
                try:
                    if os.readlink(os.path.join(fddir, fd)) == port:
                        cmd = _cmdline(pid)
                        holders.append((pid, cmd))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return holders


def _agent_procs() -> List[Tuple[str, str]]:
    """Other *running agent* processes — not the shell that launched us, not this
    --doctor run, and not non-python matches."""
    out = []
    skip = {str(os.getpid()), str(os.getppid())}
    if not os.path.isdir("/proc"):
        return out
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or pid in skip:
            continue
        cmd = _cmdline(pid)
        if "printqueue_agent" not in cmd or "python" not in cmd.lower():
            continue
        if "--doctor" in cmd or "--list-ports" in cmd:
            continue
        out.append((pid, cmd))
    return out


def _cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
    except OSError:
        return "?"


def _undervoltage() -> Optional[Tuple[int, str]]:
    """(bits, raw) from `vcgencmd get_throttled`, or None if not a Pi."""
    try:
        r = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=5)
        raw = r.stdout.strip()
        return int(raw.split("=")[-1], 16), raw
    except Exception:
        return None


def _probe(port: str, bauds: List[int]) -> List[Tuple[int, str, str]]:
    """Try to open + handshake at each baud. Returns (baud, verdict, detail)."""
    results = []
    for baud in bauds:
        kwargs = {"timeout": 2}
        if os.name == "posix":
            kwargs["exclusive"] = True
        try:
            ser = serial.Serial(port, baud, **kwargs)
        except Exception as e:
            results.append((baud, "OPEN_FAIL", str(e)))
            continue
        try:
            time.sleep(2.0)  # let the board boot if it reset on open
            ser.reset_input_buffer()
            ser.write(b"\nM115\n")
            ser.flush()
            deadline = time.time() + 5
            raw = b""
            while time.time() < deadline:
                chunk = ser.read(256)
                if chunk:
                    raw += chunk
                    if b"ok" in raw.lower():
                        break
            text = raw.decode("ascii", "replace").strip()
            if b"ok" in raw.lower() or b"FIRMWARE" in raw:
                fw = next((ln for ln in text.splitlines() if "FIRMWARE_NAME" in ln), text[:200])
                results.append((baud, "OK", fw[:200]))
                return results  # good — stop probing
            results.append((baud, "GARBAGE" if raw else "SILENT",
                            (repr(text[:120]) if raw else "no bytes received")))
        finally:
            try:
                ser.close()
            except Exception:
                pass
    return results


def run(cfg) -> str:
    lines: List[str] = ["", "═══ Print-queue agent doctor ═══", ""]

    if serial is None:
        lines.append(_fmt("fail", "pyserial not installed — run: pip install pyserial"))
        return "\n".join(lines)

    # 1) Config
    lines.append("Config:")
    lines.append(_fmt("info", f"server_url = {cfg.server_url}"))
    lines.append(_fmt("info", f"serial_port = {cfg.serial_port}   baud = {cfg.baud_rate}"))

    # 2) Permissions / power (Pi)
    lines.append("")
    lines.append("Host:")
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            lines.append(_fmt("ok", "running as root (serial access allowed)"))
        else:
            import grp
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
            if "dialout" in groups:
                lines.append(_fmt("ok", "user is in the 'dialout' group (serial access allowed)"))
            else:
                lines.append(_fmt("fail", "user is NOT in 'dialout' — run: sudo usermod -aG dialout $USER (then reboot)"))
    except Exception:
        pass
    uv = _undervoltage()
    if uv is not None:
        bits, raw = uv
        if bits == 0:
            lines.append(_fmt("ok", f"no undervoltage ({raw})"))
        else:
            now = bits & 0x1
            past = bits & 0x10000
            msg = f"UNDERVOLTAGE detected ({raw}) —"
            msg += " happening NOW;" if now else ""
            msg += " occurred since boot;" if past else ""
            msg += " weak Pi PSU or printer back-power. Use a 5.25V/3A supply and tape the USB 5V pin."
            lines.append(_fmt("fail" if now else "warn", msg))

    # 3) Ports
    lines.append("")
    lines.append("Serial ports:")
    ports = _enumerate_ports()
    if not ports:
        lines.append(_fmt("fail", "no serial ports found — printer off/unplugged, cable bad, or not enumerating"))
    printer_port = None
    for p in ports:
        label = ""
        if p["vid"] in _KNOWN_USB_VIDS:
            label = f" — {_KNOWN_USB_VIDS[p['vid']]}"
            printer_port = printer_port or p["device"]
        elif p["onboard"]:
            label = " — Pi onboard UART (NOT the printer)"
        lines.append(_fmt("info", f"{p['device']}  [{p['desc']}]{label}"))

    # 4) Which port would be used, and who holds it
    resolved = cfg.serial_port if (cfg.serial_port and cfg.serial_port != "auto") else (
        printer_port or (ports[0]["device"] if ports else None))
    lines.append("")
    lines.append("Selected port:")
    if not resolved:
        lines.append(_fmt("fail", "no port to test"))
        return "\n".join(lines)
    lines.append(_fmt("info", f"would use: {resolved}"))
    others = _agent_procs()
    if others:
        lines.append(_fmt("fail", f"{len(others)} OTHER agent process(es) running — they fight for the port:"))
        for pid, cmd in others[:4]:
            lines.append(_fmt("info", f"  pid {pid}: {cmd[:90]}"))
        lines.append(_fmt("info", "  stop extras: sudo systemctl restart printqueue-agent, then kill any stray pid"))
    holders = _procs_holding(resolved)
    if holders:
        lines.append(_fmt("warn", f"port already open by: " + ", ".join(f"pid {h[0]}" for h in holders)))

    # 5) The actual handshake probe
    lines.append("")
    lines.append(f"Handshake probe on {resolved}:")
    bauds = []
    for b in (cfg.baud_rate, 115200, 250000, 57600):
        if b and b not in bauds:
            bauds.append(b)
    verdict_summary = "unknown"
    for baud, verdict, detail in _probe(resolved, bauds):
        if verdict == "OK":
            lines.append(_fmt("ok", f"{baud} baud: CONNECTED — {detail}"))
            verdict_summary = f"healthy at {baud} baud"
        elif verdict == "OPEN_FAIL":
            lines.append(_fmt("fail", f"{baud} baud: cannot open — {detail}"))
            verdict_summary = "port busy / permission (another process holds it)"
        elif verdict == "GARBAGE":
            lines.append(_fmt("warn", f"{baud} baud: got bytes but no 'ok' (wrong baud?) — {detail}"))
        else:
            lines.append(_fmt("warn", f"{baud} baud: SILENT — {detail}"))

    # 6) Verdict
    lines.append("")
    lines.append("Most likely issue:")
    if "healthy" in verdict_summary:
        lines.append(_fmt("ok", f"Serial link is {verdict_summary}. If it drops mid-print, suspect power (undervoltage above)."))
    elif "busy" in verdict_summary:
        holder_is_agent = any("printqueue_agent" in c for _, c in holders) or bool(others)
        if holder_is_agent:
            lines.append(_fmt("warn", "The running agent already holds the port (expected). For a clean probe, "
                                      "stop it first:  sudo systemctl stop printqueue-agent  →  re-run --doctor  →  "
                                      "sudo systemctl start printqueue-agent"))
        else:
            lines.append(_fmt("fail", "Another (non-agent) process holds the port — close it, then retry."))
    elif resolved and ("ttyS" in resolved or "ttyAMA" in resolved):
        lines.append(_fmt("fail", "Testing the Pi's onboard UART, not the printer. Pin serial_port to the /dev/ttyUSB* device."))
    elif any(p["vid"] in _KNOWN_USB_VIDS for p in ports):
        lines.append(_fmt("fail", "USB printer is present but SILENT — printer off/asleep, bad/again cable, wrong baud, or a brownout. "
                                  "Power-cycle the printer, reseat the cable; if it only fails under load, it's power (tape 5V pin)."))
    else:
        lines.append(_fmt("fail", "No printer USB device detected — check it's powered on and the USB cable carries data."))
    lines.append("")
    return "\n".join(lines)
