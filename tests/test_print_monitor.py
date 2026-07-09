"""Printellect Watch (AI print monitoring) — worker pieces.

Covers: active-print discovery (dual build/request query), HMAC frame
submission (signing + fail-open), the alert state machine (confirm → alert
once → cooldown → mute), and opt-in auto-pause.
"""
import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tests.conftest import clear_all_test_data, get_test_db, init_test_db, now_iso

import app.print_monitor as pm
from app import main as app_main


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@pytest.fixture(autouse=True)
def _configure_monitor():
    """Point the monitor module at the test DB with recording stubs."""
    init_test_db()
    clear_all_test_data()
    conn = get_test_db()
    for table in ("print_monitor_events", "print_monitor_sessions"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    calls = {"push": [], "email": [], "pause": []}
    settings = {
        "print_monitor_enabled": "1",
        "print_monitor_url": "https://cm.test/api/print-monitor/frames",
        "print_monitor_secret": "test-secret",
        "print_monitor_interval_seconds": "60",
        "print_monitor_warmup_minutes": "0",
        "print_monitor_max_frame_kb": "1500",
        "print_monitor_alert_cooldown_minutes": "30",
        "print_monitor_notify_email": "1",
        "admin_notify_emails": "admin@example.com",
        "bug_app_id": "printellect",
    }

    class _PausableAPI:
        async def pause_print(self):
            calls["pause"].append(True)
            return True

    def get_setting(key, default=None):
        return settings.get(key, default if default is not None else "")

    def get_bool_setting(key, default=False):
        return get_setting(key, "1" if default else "0").strip() == "1"

    pm.configure(
        db=app_main.db,
        now_iso=now_iso,
        get_setting=get_setting,
        get_bool_setting=get_bool_setting,
        capture_camera_snapshot=lambda code: None,
        is_polling_paused=lambda code: False,
        send_push_notification_to_admins=lambda *a, **kw: calls["push"].append((a, kw)),
        send_email=lambda *a, **kw: calls["email"].append((a, kw)),
        parse_email_list=app_main.parse_email_list,
        get_printer_api=lambda code: _PausableAPI() if code == "AD5X" else None,
        demo_mode=lambda: False,
    )
    # Optional live-status gate deps are opt-in per test; keep them out of the
    # shared _deps so leakage between tests can't silently stop monitoring.
    pm._deps.pop("get_cached_printer_status", None)
    pm._deps.pop("get_printer_last_seen", None)
    yield {"calls": calls, "settings": settings}


def _insert_request(conn, *, status="PRINTING", printer="AD5X", total_builds=1):
    rid = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO requests (id, created_at, updated_at, requester_name, requester_email,
                              print_name, material, colors, status, printer, total_builds)
        VALUES (?, ?, ?, 'T', 't@example.com', 'Benchy', 'PLA', 'Black', ?, ?, ?)
        """,
        (rid, now_iso(), now_iso(), status, printer, total_builds),
    )
    return rid


def _insert_build(conn, request_id, *, status="PRINTING", printer="AD5X"):
    bid = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO builds (id, request_id, build_number, status, printer, print_name, created_at, updated_at, started_at)
        VALUES (?, ?, 1, ?, ?, 'Benchy part', ?, ?, ?)
        """,
        (bid, request_id, status, printer, now_iso(), now_iso(), now_iso()),
    )
    return bid


def _target(session_id, printer="AD5X", request_id=None, started_minutes_ago=60):
    return {
        "session_id": session_id,
        "request_id": request_id or session_id,
        "build_id": None,
        "printer_code": printer,
        "print_name": "Benchy",
        "material": "PLA",
        "started_at": _iso(datetime.now(timezone.utc) - timedelta(minutes=started_minutes_ago)),
    }


# ── active-print discovery ───────────────────────────────────────────────────

def test_get_active_targets_dual_query():
    conn = get_test_db()
    multi_rid = _insert_request(conn, status="IN_PROGRESS", total_builds=2)
    build_id = _insert_build(conn, multi_rid)
    single_rid = _insert_request(conn, status="PRINTING", total_builds=1)
    _insert_request(conn, status="DONE")  # not printing → ignored
    conn.commit()
    conn.close()

    targets = pm.get_active_targets()
    ids = {t["session_id"] for t in targets}
    assert build_id in ids       # build-level row
    assert single_rid in ids     # legacy single-build request row
    assert len(ids) == 2

    by_id = {t["session_id"]: t for t in targets}
    assert by_id[build_id]["request_id"] == multi_rid
    assert by_id[single_rid]["build_id"] is None


def test_dedupe_targets_by_printer_keeps_newest():
    # Several PRINTING jobs on one printer (queued batch) must collapse to a
    # single monitored target — one camera, one active print.
    targets = [
        {"session_id": "a", "printer_code": "AD5X", "started_at": "2026-07-06T10:00:00+00:00"},
        {"session_id": "b", "printer_code": "AD5X", "started_at": "2026-07-06T10:22:00+00:00"},
        {"session_id": "c", "printer_code": "AD5X", "started_at": "2026-07-06T10:10:00+00:00"},
        {"session_id": "d", "printer_code": "ADVENTURER_4", "started_at": "2026-07-06T09:00:00+00:00"},
    ]
    result = pm.dedupe_targets_by_printer(targets)
    by_printer = {t["printer_code"]: t["session_id"] for t in result}
    assert len(result) == 2
    assert by_printer["AD5X"] == "b"  # most recently started
    assert by_printer["ADVENTURER_4"] == "d"


# ── live-status gate ─────────────────────────────────────────────────────────

def test_live_is_printing_unknown_without_helper(_configure_monitor):
    # No cache helper injected → cannot tell → None (keep monitoring).
    assert pm._live_is_printing("AD5X") is None


def test_live_is_printing_reads_fresh_cache(_configure_monitor):
    cache = {"AD5X": {"is_printing": True, "status": "PRINTING"}}
    pm.configure(
        get_cached_printer_status=lambda code: cache.get(code),
        get_printer_last_seen=lambda code: now_iso(),
    )
    assert pm._live_is_printing("AD5X") is True

    cache["AD5X"] = {"is_printing": False, "status": "READY"}
    assert pm._live_is_printing("AD5X") is False

    cache["AD5X"] = {"is_printing": False, "status": "PAUSED"}
    assert pm._live_is_printing("AD5X") is True  # a paused print is still watched


def test_live_is_printing_ignores_stale_cache(_configure_monitor):
    cache = {"AD5X": {"is_printing": False, "status": "READY"}}
    old = _iso(datetime.now(timezone.utc) - timedelta(minutes=10))
    pm.configure(
        get_cached_printer_status=lambda code: cache.get(code),
        get_printer_last_seen=lambda code: old,
    )
    # Cache too old to trust → None so we never wrongly stop a real print.
    assert pm._live_is_printing("AD5X") is None


async def test_process_target_ends_session_when_not_printing(_configure_monitor):
    captured: list[str] = []
    cache = {"AD5X": {"is_printing": False, "status": "READY"}}
    pm.configure(
        capture_camera_snapshot=lambda code: captured.append(code),
        get_cached_printer_status=lambda code: cache.get(code),
        get_printer_last_seen=lambda code: now_iso(),
    )
    target = _target(str(uuid.uuid4()), printer="AD5X")
    pm._load_or_create_session(target)  # a live "watching" session exists

    await pm._process_target(target, 60)

    assert captured == []  # no camera grab for an idle bed
    session = pm._existing_session(target["session_id"])
    assert session is not None and session["state"] == "ended"


async def test_process_target_captures_when_live_status_confirms_printing(_configure_monitor):
    captured: list[str] = []

    async def _capture(code):
        captured.append(code)
        return b""  # empty → capture_frame yields no frame, nothing submitted

    cache = {"AD5X": {"is_printing": True, "status": "PRINTING"}}
    pm.configure(
        capture_camera_snapshot=_capture,
        get_cached_printer_status=lambda code: cache.get(code),
        get_printer_last_seen=lambda code: now_iso(),
    )
    target = _target(str(uuid.uuid4()), printer="AD5X")

    await pm._process_target(target, 60)

    # Live status agrees it's printing, so the gate did not short-circuit and we
    # proceeded to attempt a capture.
    assert captured == ["AD5X"]
    session = pm._existing_session(target["session_id"])
    assert session is not None and session["state"] != "ended"


# ── HMAC submission ──────────────────────────────────────────────────────────

async def test_submit_frame_signs_body(monkeypatch):
    captured = {}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, content=None, headers=None):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return httpx.Response(200, json={"verdict": "ok"})

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    result = await pm.submit_frame({"session_key": "build:x", "image_base64": "QUJD"})

    assert result == {"verdict": "ok"}
    expected = hmac.new(b"test-secret", captured["content"], hashlib.sha256).hexdigest()
    assert captured["headers"]["X-JCubHub-Signature"] == f"sha256={expected}"
    assert captured["headers"]["X-JCubHub-App"] == "printellect"
    assert captured["headers"]["X-JCubHub-Monitor-Contract"] == "1.0.0"


async def test_submit_frame_fail_open(monkeypatch, _configure_monitor):
    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, content=None, headers=None):
            return httpx.Response(500, text="boom")

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    assert await pm.submit_frame({"x": 1}) is None

    class _Exploding:
        def __init__(self, *a, **kw):
            raise ConnectionError("cm down")

    monkeypatch.setattr(httpx, "AsyncClient", _Exploding)
    assert await pm.submit_frame({"x": 1}) is None

    # No URL/secret configured → silently disabled.
    _configure_monitor["settings"]["print_monitor_url"] = ""
    assert await pm.submit_frame({"x": 1}) is None


# ── alert state machine ──────────────────────────────────────────────────────

def _confirmed_response(**over):
    resp = {
        "frame_id": str(uuid.uuid4()),
        "verdict": "failure",
        "failure_type": "spaghetti",
        "confidence": 0.92,
        "reasoning": "strands everywhere",
        "source": "ollama",
        "session": {"confirmed_failure": True, "confirmed_failure_type": "spaghetti"},
    }
    resp.update(over)
    return resp


async def test_confirmed_failure_alerts_once_with_cooldown(_configure_monitor):
    calls = _configure_monitor["calls"]
    target = _target(str(uuid.uuid4()), printer="ADVENTURER_4")
    session = pm._load_or_create_session(target)

    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert len(calls["push"]) == 1
    assert len(calls["email"]) == 1
    assert calls["pause"] == []  # autopause off by default

    # Second confirmation inside the cooldown window: no new alert.
    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert len(calls["push"]) == 1

    # Cooldown elapsed → alert again.
    conn = get_test_db()
    stale = _iso(datetime.now(timezone.utc) - timedelta(minutes=45))
    conn.execute(
        "UPDATE print_monitor_sessions SET alerted_at = ? WHERE id = ?",
        (stale, target["session_id"]),
    )
    conn.commit()
    conn.close()
    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert len(calls["push"]) == 2


async def test_unconfirmed_verdicts_never_alert(_configure_monitor):
    calls = _configure_monitor["calls"]
    target = _target(str(uuid.uuid4()))
    session = pm._load_or_create_session(target)
    await pm._handle_response(
        session, target,
        {"verdict": "failure", "failure_type": "spaghetti", "confidence": 0.9,
         "source": "ollama", "session": {"confirmed_failure": False}},
        "QUJD",
    )
    assert calls["push"] == []

    event = pm.get_latest_event(target["session_id"])
    assert event["verdict"] == "failure"
    assert event["action"] == "none"


async def test_muted_session_suppresses_alerts(_configure_monitor):
    calls = _configure_monitor["calls"]
    target = _target(str(uuid.uuid4()))
    pm._load_or_create_session(target)
    assert pm.mute_session(target["session_id"])

    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert calls["push"] == []


async def test_claude_failure_verdict_counts_as_confirmed(_configure_monitor):
    calls = _configure_monitor["calls"]
    target = _target(str(uuid.uuid4()))
    session = pm._load_or_create_session(target)
    await pm._handle_response(
        session, target,
        _confirmed_response(source="claude", session={"confirmed_failure": False}),
        "QUJD",
    )
    assert len(calls["push"]) == 1


# ── auto-pause ───────────────────────────────────────────────────────────────

async def test_autopause_only_when_enabled_and_once(_configure_monitor):
    calls = _configure_monitor["calls"]
    settings = _configure_monitor["settings"]
    settings["print_monitor_autopause_AD5X"] = "1"

    target = _target(str(uuid.uuid4()), printer="AD5X")
    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert calls["pause"] == [True]

    event = pm.get_latest_event(target["session_id"])
    assert event["action"] == "paused"
    # Pause notification plus the failure alert.
    assert len(calls["push"]) == 2

    # Already paused → never pause again.
    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert calls["pause"] == [True]


async def test_autopause_unsupported_printer_alert_only(_configure_monitor):
    calls = _configure_monitor["calls"]
    settings = _configure_monitor["settings"]
    settings["print_monitor_autopause_ADVENTURER_4"] = "1"

    # get_printer_api stub returns None for ADVENTURER_4 (no pause support).
    target = _target(str(uuid.uuid4()), printer="ADVENTURER_4")
    session = pm._load_or_create_session(target)
    await pm._handle_response(session, target, _confirmed_response(), "QUJD")
    assert calls["pause"] == []
    assert len(calls["push"]) == 1  # failure alert still fired
