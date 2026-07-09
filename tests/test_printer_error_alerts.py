"""Printer error alerts — Klipper/Moonraker fault watcher.

Covers: message classification, MoonrakerAPI.get_error_state normalization,
and the alert state machine (new fault → alert once → cooldown silence →
reminder → recovery).
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import clear_all_test_data, get_test_db, init_test_db, now_iso

import app.printer_error_alerts as pea
from app import main as app_main


# ─────────────────────────── fixtures ───────────────────────────

@pytest.fixture(autouse=True)
def _configure(monkeypatch):
    init_test_db()
    clear_all_test_data()
    conn = get_test_db()
    for table in ("printer_error_events", "printer_error_state"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()

    calls = {"push": [], "email": []}
    settings = {
        "printer_error_alerts_enabled": "1",
        "printer_error_alerts_interval_seconds": "20",
        "printer_error_alerts_cooldown_minutes": "30",
        "printer_error_alerts_notify_email": "1",
        "printer_error_alerts_notify_recovery": "1",
        "admin_notify_emails": "admin@example.com",
    }

    def get_setting(key, default=None):
        return settings.get(key, default if default is not None else "")

    def get_bool_setting(key, default=False):
        return get_setting(key, "1" if default else "0").strip() == "1"

    # A single fake Moonraker-like printer whose error state the test controls.
    state_holder = {"err": None}

    class _FakeAPI:
        async def get_error_state(self):
            return state_holder["err"]

    pea.configure(
        db=app_main.db,
        now_iso=now_iso,
        get_setting=get_setting,
        get_bool_setting=get_bool_setting,
        get_printer_api=lambda code: _FakeAPI() if code == "AD5X" else None,
        get_printer_codes=lambda with_labels=False: (
            [("AD5X", "FlashForge AD5X")] if with_labels else ["AD5X"]
        ),
        is_polling_paused=lambda code: False,
        send_push_notification_to_admins=lambda *a, **kw: calls["push"].append((a, kw)),
        send_email=lambda *a, **kw: calls["email"].append((a, kw)),
        parse_email_list=app_main.parse_email_list,
        demo_mode=lambda: False,
    )
    return {"calls": calls, "settings": settings, "state": state_holder}


def _run(coro):
    # A fresh loop per call — robust when other tests (e.g. TestClient) have
    # already opened/closed the default event loop earlier in the suite.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─────────────────────────── classification ───────────────────────────

@pytest.mark.parametrize("message,expected_cat", [
    ("Heater extruder not heating at expected rate", "thermal_fault"),
    ("Thermal runaway on heater_bed", "thermal_fault"),
    ("ADC out of range", "thermistor_fault"),
    ("Lost communication with MCU 'mcu'", "mcu_comms"),
    ("Timer too close", "timing_fault"),
    ("Filament runout detected", "filament"),
    ("Probe failed to home Z", "homing_probe"),
    ("Printer is shutdown", "klipper_shutdown"),
    ("Some totally novel failure text", "klipper_error"),
])
def test_classify_error(message, expected_cat):
    cls = pea.classify_error({"state": "error", "message": message})
    assert cls["category"] == expected_cat
    assert cls["emoji"] and cls["headline"]


def test_classify_never_empty():
    # No message, unknown state — still returns a usable bucket, never raises.
    cls = pea.classify_error({"state": "", "message": ""})
    assert cls["category"]


# ─────────────────────── get_error_state normalization ───────────────────────

def _api_with(objects):
    api = app_main.MoonrakerAPI("http://printer.test")

    async def _fake_query(timeout=5.0):
        return objects

    api._query_objects = _fake_query
    return api


def test_get_error_state_webhooks_shutdown():
    api = _api_with({"webhooks": {"state": "shutdown", "state_message": "MCU 'mcu' shutdown: Timer too close"}})
    err = _run(api.get_error_state())
    assert err["severity"] == "error"
    assert err["source"] == "klipper"
    assert "Timer too close" in err["message"]


def test_get_error_state_print_error():
    api = _api_with({
        "webhooks": {"state": "ready"},
        "print_stats": {"state": "error", "message": "Extruder below minimum temp"},
    })
    err = _run(api.get_error_state())
    assert err["severity"] == "error"
    assert err["source"] == "print"


def test_get_error_state_filament_pause_is_warning():
    api = _api_with({
        "webhooks": {"state": "ready"},
        "print_stats": {"state": "paused", "message": "Filament runout triggered"},
    })
    err = _run(api.get_error_state())
    assert err["severity"] == "warning"
    assert err["source"] == "print"


def test_get_error_state_plain_pause_is_healthy():
    # A user pause with no message must not be treated as a fault.
    api = _api_with({
        "webhooks": {"state": "ready"},
        "print_stats": {"state": "paused", "message": ""},
    })
    assert _run(api.get_error_state()) is None


def test_get_error_state_healthy_when_printing():
    api = _api_with({
        "webhooks": {"state": "ready"},
        "print_stats": {"state": "printing", "message": ""},
    })
    assert _run(api.get_error_state()) is None


def test_get_error_state_none_on_empty_objects():
    api = _api_with(None)
    assert _run(api.get_error_state()) is None


# ─────────────────────────── state machine ───────────────────────────

def _state_row():
    conn = get_test_db()
    try:
        row = conn.execute(
            "SELECT * FROM printer_error_state WHERE printer_code = 'AD5X'"
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _events():
    conn = get_test_db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM printer_error_events ORDER BY created_at"
        ).fetchall()]
    finally:
        conn.close()


def test_healthy_printer_no_alert(_configure):
    _configure["state"]["err"] = None
    _run(pea.check_printer("AD5X"))
    assert _configure["calls"]["push"] == []
    assert _state_row() is None


def test_new_fault_alerts_once(_configure):
    _configure["state"]["err"] = {
        "severity": "error", "source": "klipper", "state": "shutdown",
        "message": "Lost communication with MCU 'mcu'",
    }
    _run(pea.check_printer("AD5X"))

    assert len(_configure["calls"]["push"]) == 1
    assert len(_configure["calls"]["email"]) == 1
    row = _state_row()
    assert row and row["signature"] and row["category"] == "mcu_comms"
    assert row["alert_count"] == 1
    evs = _events()
    assert len(evs) == 1 and evs[0]["action"] == "alerted"


def test_same_fault_within_cooldown_is_silent(_configure):
    _configure["state"]["err"] = {
        "severity": "error", "source": "klipper", "state": "shutdown",
        "message": "ADC out of range",
    }
    _run(pea.check_printer("AD5X"))
    _run(pea.check_printer("AD5X"))  # immediately again — inside cooldown

    assert len(_configure["calls"]["push"]) == 1  # no second alert
    assert [e["action"] for e in _events()] == ["alerted"]


def test_same_fault_after_cooldown_reminds(_configure):
    _configure["state"]["err"] = {
        "severity": "error", "source": "klipper", "state": "shutdown",
        "message": "ADC out of range",
    }
    _run(pea.check_printer("AD5X"))

    # Age the last alert past the cooldown window.
    old = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
    conn = get_test_db()
    conn.execute("UPDATE printer_error_state SET alerted_at = ? WHERE printer_code = 'AD5X'", (old,))
    conn.commit()
    conn.close()

    _run(pea.check_printer("AD5X"))
    assert len(_configure["calls"]["push"]) == 2  # reminder fired
    actions = [e["action"] for e in _events()]
    assert actions == ["alerted", "reminded"]
    assert _state_row()["alert_count"] == 2


def test_recovery_clears_state_and_notifies(_configure):
    _configure["state"]["err"] = {
        "severity": "error", "source": "klipper", "state": "shutdown",
        "message": "Heater extruder not heating at expected rate",
    }
    _run(pea.check_printer("AD5X"))
    assert len(_configure["calls"]["push"]) == 1

    # Printer recovers.
    _configure["state"]["err"] = None
    _run(pea.check_printer("AD5X"))

    assert len(_configure["calls"]["push"]) == 2  # recovery push
    row = _state_row()
    assert row and (row["signature"] or "") == ""  # cleared
    actions = [e["action"] for e in _events()]
    assert actions == ["alerted", "recovered"]


def test_admin_page_renders_error_alert_card(admin_client):
    """The Printellect Watch admin page shows the error-alert settings + save route."""
    resp = admin_client.get("/admin/print-monitor")
    assert resp.status_code == 200
    assert "Printer error alerts" in resp.text
    assert "/admin/printer-error-alerts" in resp.text


def test_admin_save_error_alert_settings(admin_client):
    resp = admin_client.post(
        "/admin/printer-error-alerts",
        data={"err_enabled": "1", "err_interval_seconds": "25",
              "err_cooldown_minutes": "15", "err_notify_email": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    from app.main import get_bool_setting, get_setting
    assert get_bool_setting("printer_error_alerts_enabled", False) is True
    assert get_setting("printer_error_alerts_interval_seconds", "") == "25"
    assert get_setting("printer_error_alerts_cooldown_minutes", "") == "15"
    # Unchecked checkbox → disabled
    assert get_bool_setting("printer_error_alerts_notify_recovery", True) is False


def test_changed_fault_realerts(_configure):
    _configure["state"]["err"] = {
        "severity": "error", "source": "klipper", "state": "shutdown",
        "message": "ADC out of range",
    }
    _run(pea.check_printer("AD5X"))

    # A different fault appears before the first cleared — alert again immediately.
    _configure["state"]["err"] = {
        "severity": "error", "source": "print", "state": "error",
        "message": "Extruder below minimum temp",
    }
    _run(pea.check_printer("AD5X"))

    assert len(_configure["calls"]["push"]) == 2
    actions = [e["action"] for e in _events()]
    assert actions == ["alerted", "alerted"]
