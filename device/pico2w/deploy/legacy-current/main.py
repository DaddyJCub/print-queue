"""
main.py — Pico root main shim.

MicroPython auto-runs /main.py after /boot.py. This shim imports
the real application from /current/main.py (resolved via sys.path set
in boot.py) and runs it.

This file is never replaced by OTA; it remains at Pico root.
"""

import machine
import json
import sys


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


_TEST_MODE = False
try:
    import os

    os.stat("/TEST_MODE")
    _TEST_MODE = True
except OSError:
    pass

if _TEST_MODE:
    print("[MAIN] Entering test mode...")
    try:
        from tests import test_menu

        test_menu.run()
    except ImportError as e:
        print("[MAIN] Test menu not found: {}".format(e))
    except KeyboardInterrupt:
        print("[MAIN] Test menu exited.")
else:
    print("[MAIN] Starting application...")
    try:
        from main import run as app_run

        app_run()
    except Exception as e:
        print("[MAIN] FATAL: {}".format(e))
        sys.print_exception(e)
        app_state = _load_json("/app_state.json", {})
        fail_count = app_state.get("boot_fail_count", 0) + 1
        app_state["boot_fail_count"] = fail_count
        _save_json("/app_state.json", app_state)
        print("[MAIN] Boot fail count now {}. Rebooting in 5s...".format(fail_count))
        import time

        time.sleep(5)
        machine.reset()
