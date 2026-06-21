"""Remote-management command handling for the agent.

The server can queue commands (restart, reboot, logs, …) that the agent polls
and executes — the same poll-based model as the Printellect devices. Keeping
this here keeps the main loop small.
"""

from __future__ import annotations

import collections
import logging
import os
import subprocess
import sys
import threading
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
    def _do_get_logs(self, payload, cmd_id) -> Dict[str, Any]:
        limit = int(payload.get("limit", 200))
        return {"logs": recent_logs(limit), "agent_version": self.agent.cfg.agent_version}

    def _do_identify(self, payload, cmd_id) -> Dict[str, Any]:
        log.info("👋 IDENTIFY — this is agent %s", self.agent.cfg.agent_id)
        return {"identified": True}

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
