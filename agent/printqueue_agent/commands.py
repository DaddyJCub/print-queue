"""Remote-management command handling for the agent.

The server can queue commands (restart, reboot, logs, …) that the agent polls
and executes — the same poll-based model as the Printellect devices. Keeping
this here keeps the main loop small.
"""

from __future__ import annotations

import collections
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import platform
from typing import Any, Dict, Optional

log = logging.getLogger("printqueue.commands")

# In-memory ring buffer of recent log lines so `get_logs` works without a log
# file or journald dependency (cross-platform).
_LOG_RING: "collections.deque[str]" = collections.deque(maxlen=500)


class RingBufferLogHandler(logging.Handler):
    def emit(self, record):
        try:
            _LOG_RING.append(self.format(record))
        except Exception:
            pass


def install_log_ring() -> None:
    """Attach the ring-buffer handler to the root logger (idempotent)."""
    root = logging.getLogger()
    if any(isinstance(h, RingBufferLogHandler) for h in root.handlers):
        return
    h = RingBufferLogHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
    root.addHandler(h)


def recent_logs(limit: int = 200) -> str:
    lines = list(_LOG_RING)[-limit:]
    return "\n".join(lines)


class CommandExecutor:
    """Executes management commands and reports lifecycle back to the server."""

    def __init__(self, agent):
        self.agent = agent  # back-reference for config / restart hooks

    def handle(self, cmd: Dict[str, Any]) -> None:
        cmd_id = cmd["cmd_id"]
        action = cmd.get("action")
        payload = cmd.get("payload") or {}
        client = self.agent.client
        log.info("Executing command %s: %s", cmd_id, action)
        try:
            client.update_command(cmd_id, "executing")
        except Exception as e:
            log.warning("Could not mark command executing: %s", e)

        try:
            handler = getattr(self, f"_do_{action}", None)
            if handler is None:
                client.update_command(cmd_id, "failed", error=f"Unsupported action: {action}")
                return
            result = handler(payload, cmd_id)
            client.update_command(cmd_id, "completed", result=result or {})
        except Exception as e:
            log.exception("Command %s failed: %s", cmd_id, e)
            try:
                client.update_command(cmd_id, "failed", error=str(e))
            except Exception:
                pass

    # ── handlers ──────────────────────────────────────────────────
    def _do_pause_print(self, payload, cmd_id) -> Dict[str, Any]:
        """Pause the running print (sent by Printellect Watch on a confirmed
        failure). Pause only — resuming/canceling stays a human decision."""
        printer = self.agent.printer
        if not printer or not printer.connected:
            raise RuntimeError("Printer is offline")
        printer.pause_print()
        log.warning(
            "⏸️ Print paused by server command (reason: %s)",
            payload.get("reason", "unspecified"),
        )
        return {"paused": True, "reason": payload.get("reason")}

    def _do_get_logs(self, payload, cmd_id) -> Dict[str, Any]:
        limit = int(payload.get("limit", 200))
        return {"logs": recent_logs(limit), "agent_version": self.agent.cfg.agent_version}

    def _do_identify(self, payload, cmd_id) -> Dict[str, Any]:
        log.info("👋 IDENTIFY — this is agent %s", self.agent.cfg.agent_id)
        return {"identified": True}

    def _do_set_print_mode(self, payload, cmd_id) -> Dict[str, Any]:
        mode = self.agent.set_print_mode(payload.get("mode", ""))
        return {"print_mode": mode}

    def _do_get_host_info(self, payload, cmd_id) -> Dict[str, Any]:
        def _run(args, timeout=8):
            try:
                p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
                return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
            except Exception as e:
                return 1, "", str(e)

        info: Dict[str, Any] = {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "hostname": platform.node(),
            "agent_id": self.agent.cfg.agent_id,
        }

        rc, out, err = _run(["hostname", "-I"])
        if rc == 0 and out:
            info["ip_addrs"] = [x for x in out.split() if x]

        if shutil.which("iwgetid"):
            rc, out, err = _run(["iwgetid", "-r"])
            info["wifi_ssid"] = out if rc == 0 and out else None

        if shutil.which("timedatectl"):
            rc, out, err = _run(["timedatectl", "show", "-p", "Timezone", "--value"])
            if rc == 0:
                info["timezone"] = out

        if shutil.which("free"):
            rc, out, err = _run(["free", "-m"])
            if rc == 0:
                info["memory"] = out

        if shutil.which("df"):
            rc, out, err = _run(["df", "-h", "/"])
            if rc == 0:
                info["disk_root"] = out

        return info

    def _do_set_hostname(self, payload, cmd_id) -> Dict[str, Any]:
        hostname = str(payload.get("hostname") or "").strip()
        if not hostname:
            raise RuntimeError("hostname is required")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}", hostname):
            raise RuntimeError("invalid hostname (letters/numbers/hyphen, max 63)")
        if sys.platform.startswith("win"):
            raise RuntimeError("set_hostname is not supported on Windows agent hosts")
        if not shutil.which("hostnamectl"):
            raise RuntimeError("hostnamectl not available on host")

        proc = subprocess.run(
            ["sudo", "hostnamectl", "set-hostname", hostname],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "hostnamectl failed").strip())
        return {"hostname": hostname, "changed": True}

    def _do_set_timezone(self, payload, cmd_id) -> Dict[str, Any]:
        tz = str(payload.get("timezone") or "").strip()
        if not tz:
            raise RuntimeError("timezone is required")
        if sys.platform.startswith("win"):
            raise RuntimeError("set_timezone is not supported on Windows agent hosts")
        if not shutil.which("timedatectl"):
            raise RuntimeError("timedatectl not available on host")

        proc = subprocess.run(
            ["sudo", "timedatectl", "set-timezone", tz],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "timedatectl failed").strip())
        return {"timezone": tz, "changed": True}

    def _do_set_wifi(self, payload, cmd_id) -> Dict[str, Any]:
        if sys.platform.startswith("win"):
            raise RuntimeError("set_wifi is not supported on Windows agent hosts")
        ssid = str(payload.get("ssid") or "").strip()
        psk = str(payload.get("psk") or "")
        iface = str(payload.get("iface") or "wlan0").strip() or "wlan0"
        hidden = bool(payload.get("hidden"))
        if not ssid:
            raise RuntimeError("ssid is required")
        if not psk:
            raise RuntimeError("psk is required")
        if not shutil.which("nmcli"):
            raise RuntimeError("nmcli not available; cannot set Wi-Fi on this host")

        args = ["nmcli", "dev", "wifi", "connect", ssid, "password", psk, "ifname", iface]
        if hidden:
            args.extend(["hidden", "yes"])
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "nmcli wifi connect failed").strip())
        return {
            "ssid": ssid,
            "iface": iface,
            "hidden": hidden,
            "changed": True,
            "note": "Wi-Fi profile applied via nmcli",
        }

    def _do_reload_config(self, payload, cmd_id) -> Dict[str, Any]:
        self.agent.reload_config()
        return {"reloaded": True}

    def _do_restart_agent(self, payload, cmd_id) -> Dict[str, Any]:
        # Report completion first, then exit so the service manager restarts us.
        try:
            self.agent.client.update_command(cmd_id, "completed", result={"restarting": True})
        except Exception:
            pass
        log.info("Restarting agent on command")
        _delayed_exit(1.0, code=0)
        return None  # already reported

    def _do_update_agent(self, payload, cmd_id) -> Dict[str, Any]:
        """OTA self-update: download a bundle, verify, swap the package, restart.

        Refuses while a print is running. Requires the service manager (systemd /
        NSSM) to auto-restart the process after we exit.
        """
        if self.agent.printer and self.agent.printer.is_busy():
            raise RuntimeError("Refusing to update: a print is in progress")

        version = payload.get("version", "?")
        bundle_url = payload.get("bundle_url")
        expected_sha = payload.get("sha256")
        if not bundle_url:
            raise RuntimeError("No bundle_url in update payload")

        from . import apply_update  # local import keeps the dependency contained

        log.info("Updating agent to %s", version)
        apply_update.download_and_apply(self.agent.client, bundle_url, expected_sha)

        # Report success before restarting; the new version reports via heartbeat.
        try:
            self.agent.client.update_command(cmd_id, "completed", result={"updated_to": version, "restarting": True})
        except Exception:
            pass
        _delayed_exit(1.0, code=0)
        return None

    def _do_flash_firmware(self, payload, cmd_id) -> Dict[str, Any]:
        """Flash printer firmware via avrdude (opt-in, guarded)."""
        from . import flash_firmware

        fw_cfg = self.agent.cfg.firmware
        if not fw_cfg.enabled:
            raise RuntimeError("Firmware flashing is disabled on this agent (set firmware.enabled)")
        if self.agent.printer and self.agent.printer.is_busy():
            raise RuntimeError("Refusing to flash: a print is in progress")

        firmware_url = payload.get("firmware_url")
        if not firmware_url:
            raise RuntimeError("No firmware_url in payload")

        # Release the serial port so avrdude can take it over.
        port = self.agent._resolve_port()
        if self.agent.printer:
            self.agent.printer.close()
            self.agent.printer = None
        if not port:
            raise RuntimeError("No serial port available to flash")

        return flash_firmware.flash(
            self.agent.client, fw_cfg, port, firmware_url,
            payload.get("sha256"), payload.get("file_name", "firmware.hex"),
        )

    def _do_reboot_host(self, payload, cmd_id) -> Dict[str, Any]:
        if self.agent.printer and self.agent.printer.is_busy():
            raise RuntimeError("Refusing to reboot: a print is in progress")
        try:
            self.agent.client.update_command(cmd_id, "completed", result={"rebooting": True})
        except Exception:
            pass
        log.info("Rebooting host on command")
        _reboot_host()
        return None


def _delayed_exit(delay_s: float, code: int = 0) -> None:
    def _bye():
        import time
        time.sleep(delay_s)
        os._exit(code)
    threading.Thread(target=_bye, daemon=True).start()


def _reboot_host() -> None:
    if sys.platform.startswith("win"):
        subprocess.Popen(["shutdown", "/r", "/t", "5"])
    else:
        # Needs passwordless sudo for reboot (documented in the setup guide).
        subprocess.Popen(["sudo", "reboot"])
