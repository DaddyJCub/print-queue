"""
boot.py — Pico root boot file.

Runs first on every power-on / reset. Responsibilities:
  1. OTA boot guard: detect pending OTA, increment fail counter, rollback if needed.
  2. Set sys.path so imports resolve from /current and /current/lib.
  3. Check for TEST_MODE flag file.

This file is NEVER replaced by OTA — it lives permanently at the Pico root.
"""

import sys
import os
import json
import machine  # noqa: F401 — available in MicroPython


def _load_json(path, default=None):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except OSError:
        pass


def _exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


def _rmtree(path):
    """Recursively remove a directory tree."""
    try:
        for entry in os.listdir(path):
            full = path + "/" + entry
            try:
                os.listdir(full)
                _rmtree(full)
            except OSError:
                os.remove(full)
        os.rmdir(path)
    except OSError:
        pass


def _rename(src, dst):
    """Rename/move a directory."""
    try:
        os.rename(src, dst)
    except OSError:
        pass


APP_STATE_PATH = "/app_state.json"
MAX_BOOT_FAILURES = 3

app_state = _load_json(APP_STATE_PATH, {})
pending = app_state.get("pending_version")

if pending:
    fail_count = app_state.get("boot_fail_count", 0) + 1
    app_state["boot_fail_count"] = fail_count
    _save_json(APP_STATE_PATH, app_state)

    if fail_count >= MAX_BOOT_FAILURES:
        print("[BOOT] OTA rollback triggered after {} failures".format(fail_count))
        if _exists("/prev"):
            _rmtree("/current")
            _rename("/prev", "/current")
        app_state.pop("pending_version", None)
        app_state["boot_fail_count"] = 0
        _save_json(APP_STATE_PATH, app_state)
        print("[BOOT] Rollback complete. Rebooting.")
        machine.reset()
    else:
        print(
            "[BOOT] Pending OTA version={}, boot attempt {}/{}".format(
                pending, fail_count, MAX_BOOT_FAILURES
            )
        )


for p in ("/current/lib", "/current"):
    if p not in sys.path:
        sys.path.insert(0, p)


_TEST_MODE = _exists("/TEST_MODE")
if _TEST_MODE:
    print("[BOOT] TEST_MODE flag detected")

print("[BOOT] sys.path={}".format(sys.path))
print("[BOOT] Boot sequence complete.")
