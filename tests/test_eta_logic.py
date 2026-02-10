import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import sys
import pytest

TEST_ROOT = Path(__file__).resolve().parent
DATA_DIR = TEST_ROOT / "tmp_data"
UPLOAD_DIR = TEST_ROOT / "tmp_uploads"
sys.path.append(str(TEST_ROOT.parent))

for path in (DATA_DIR, UPLOAD_DIR):
    path.mkdir(parents=True, exist_ok=True)

DB_FILE = DATA_DIR / "app.db"
os.environ["DB_PATH"] = str(DB_FILE)
os.environ["UPLOAD_DIR"] = str(UPLOAD_DIR)
os.environ.setdefault("DEMO_MODE", "1")
os.environ.setdefault("LOG_LEVEL", "ERROR")

from app.main import (  # noqa: E402
    ensure_migrations,
    get_request_eta_info,
    get_smart_eta,
    init_db,
)


def _reset_db():
    """Ensure a clean schema and empty tables for ETA-focused tests."""
    init_db()
    ensure_migrations()
    conn = sqlite3.connect(DB_FILE, timeout=30)
    # Disable foreign keys to allow deletion in any order
    conn.execute("PRAGMA foreign_keys = OFF")
    tables = [
        "build_snapshots",
        "build_status_events",
        "builds",
        "status_events",
        "print_history",
        "requests",
    ]
    for table in tables:
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def fresh_db():
    _reset_db()
    yield


def _seed_request_with_builds(builds_payload, request_status="IN_PROGRESS", print_time_minutes=None):
    """
    Helper to insert a request plus builds.
    builds_payload: list of dicts with keys status, minutes, progress, started_at.
    """
    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    rid = str(uuid.uuid4())

    completed_count = sum(1 for b in builds_payload if b["status"] == "COMPLETED")
    failed_count = sum(1 for b in builds_payload if b["status"] == "FAILED")

    # Determine active build info
    active_build = next((b for b in builds_payload if b["status"] == "PRINTING"), None)
    active_build_id = str(uuid.uuid4()) if active_build else None
    printing_started_at = active_build.get("started_at") if active_build else None

    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, status,
            total_builds, completed_builds, failed_builds, active_build_id,
            printing_started_at, print_time_minutes, slicer_estimate_minutes, access_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            now_iso,
            now_iso,
            "ETA Tester",
            "eta@example.com",
            "PRUSA",
            "PLA",
            "Black",
            None,
            "ETA fixture",
            request_status,
            len(builds_payload),
            completed_count,
            failed_count,
            active_build_id,
            printing_started_at,
            print_time_minutes,
            None,
            "token",
        ),
    )

    for idx, b in enumerate(builds_payload, start=1):
        build_id = active_build_id if active_build and b is active_build else str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO builds (
                id, request_id, build_number, status, printer, material, print_name,
                print_time_minutes, slicer_estimate_minutes, started_at, completed_at,
                progress, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                build_id,
                rid,
                idx,
                b["status"],
                "PRUSA",
                "PLA",
                f"Build {idx}",
                b.get("minutes"),
                b.get("minutes"),
                b.get("started_at"),
                None,
                b.get("progress"),
                now_iso,
                now_iso,
            ),
        )

    conn.commit()
    req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    conn.close()
    return rid, dict(req_row)


def test_progress_jump_is_smoothed():
    start = datetime(2024, 1, 1, 12, 0, 0)
    now_early = start + timedelta(minutes=30)
    now_later = start + timedelta(minutes=50)

    eta_early = get_smart_eta(
        current_percent=49,
        printing_started_at=start.isoformat(),
        estimated_minutes=180,
        now=now_early,
    )
    eta_late = get_smart_eta(
        current_percent=80,
        printing_started_at=start.isoformat(),
        estimated_minutes=180,
        now=now_later,
    )

    assert eta_early and eta_late
    remaining_early = (eta_early - now_early).total_seconds()
    remaining_late = (eta_late - now_later).total_seconds()
    assert remaining_early > remaining_late > 0


def test_eta_smoothing_avoids_overly_optimistic_drop():
    start = datetime(2024, 1, 1, 9, 0, 0)
    now = start + timedelta(minutes=5)

    eta = get_smart_eta(
        current_percent=10,
        printing_started_at=start.isoformat(),
        estimated_minutes=120,
        now=now,
    )
    assert eta
    remaining = (eta - now).total_seconds()
    assert remaining > 3600  # Still over an hour remaining after smoothing
    assert remaining < 8000  # But not wildly inflated


def test_request_eta_rolls_up_printing_and_queue():
    now = datetime(2024, 1, 1, 12, 0, 0)
    started = (now - timedelta(minutes=60)).isoformat()
    rid, req = _seed_request_with_builds(
        [
            {"status": "PRINTING", "minutes": 120, "progress": 50, "started_at": started},
            {"status": "READY", "minutes": 30, "progress": None, "started_at": None},
            {"status": "PENDING", "minutes": 45, "progress": None, "started_at": None},
        ],
        request_status="IN_PROGRESS",
    )

    info = get_request_eta_info(rid, req, now=now)
    assert info["current_build_eta"]
    assert info["total_eta"]

    expected_request_eta = (now + timedelta(seconds=8460)).isoformat()
    assert info["request_eta_dt"] == expected_request_eta


def test_blocked_request_reports_blocked_eta():
    now = datetime(2024, 1, 2, 8, 0, 0)
    rid, req = _seed_request_with_builds(
        [
            {"status": "FAILED", "minutes": 60, "progress": None, "started_at": None},
            {"status": "PENDING", "minutes": 30, "progress": None, "started_at": None},
        ],
        request_status="BLOCKED",
    )

    info = get_request_eta_info(rid, req, now=now)
    assert info["blocked"] is True
    assert info["request_eta"] == "Blocked"
    assert info["request_eta_dt"] is None


def test_missing_estimates_fall_back_to_defaults():
    now = datetime(2024, 1, 3, 10, 0, 0)
    rid, req = _seed_request_with_builds(
        [
            {"status": "READY", "minutes": None, "progress": None, "started_at": None},
            {"status": "PENDING", "minutes": None, "progress": None, "started_at": None},
        ],
        request_status="IN_PROGRESS",
        print_time_minutes=None,
    )

    info = get_request_eta_info(rid, req, now=now)
    assert info["request_eta_dt"] is not None
    expected_eta = (now + timedelta(minutes=120)).isoformat()
    assert info["request_eta_dt"] == expected_eta


# ── Moonraker Live ETA Tests ──────────────────────────────────────────────

class TestMoonrakerLiveETA:
    """Tests for Moonraker time_remaining integration into ETA pipeline."""

    def test_moonraker_time_remaining_used_directly(self):
        """When moonraker_time_remaining is provided, it should be used directly."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        eta = get_smart_eta(
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=3600,  # 1 hour remaining
        )
        assert eta is not None
        remaining = (eta - now).total_seconds()
        # Should be exactly 3600 seconds (1 hour) since Moonraker is authoritative
        assert remaining == pytest.approx(3600, abs=1)

    def test_moonraker_time_remaining_zero(self):
        """When moonraker_time_remaining is 0, ETA should be now."""
        now = datetime(2024, 6, 1, 14, 0, 0)
        eta = get_smart_eta(
            current_percent=99,
            printing_started_at=(now - timedelta(hours=2)).isoformat(),
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=0,
        )
        assert eta is not None
        assert eta == now

    def test_moonraker_time_remaining_overrides_layer_calc(self):
        """Moonraker ETA should take priority over layer-based calculation."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        # Layer-based would estimate ~1 hour, but Moonraker says 30 minutes
        eta = get_smart_eta(
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            current_layer=100,
            total_layers=200,
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=1800,  # 30 minutes
        )
        assert eta is not None
        remaining = (eta - now).total_seconds()
        # Should be 30 minutes (Moonraker), not ~1 hour (layer calc)
        assert remaining == pytest.approx(1800, abs=1)

    def test_moonraker_none_falls_back_to_layer_calc(self):
        """When moonraker_time_remaining is None, should fall back to layer/percent calculation."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        eta = get_smart_eta(
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=None,  # Not available
        )
        assert eta is not None
        remaining = (eta - now).total_seconds()
        # Should use percent-based fallback, not be exactly 3600
        assert remaining > 0

    def test_moonraker_eta_flows_through_request_eta_info(self):
        """Moonraker time_remaining should flow through get_request_eta_info via printer_status."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        started = (now - timedelta(minutes=60)).isoformat()
        rid, req = _seed_request_with_builds(
            [
                {"status": "PRINTING", "minutes": 120, "progress": 50, "started_at": started},
                {"status": "READY", "minutes": 30, "progress": None, "started_at": None},
            ],
            request_status="IN_PROGRESS",
        )

        # Simulate Moonraker printer status with time_remaining
        printer_status = {
            "progress": 50,
            "current_layer": 100,
            "total_layers": 200,
            "moonraker_time_remaining": 1800,  # 30 minutes
            "is_moonraker": True,
        }

        info = get_request_eta_info(rid, req, printer_status=printer_status, now=now)
        assert info["current_build_eta"] is not None
        # The current build ETA should reflect Moonraker's 30 min remaining
        # Total request ETA = current build (30 min) + queued build (30 min) = 60 min
        assert info["request_eta_dt"] is not None

    def test_moonraker_eta_more_accurate_than_percent(self):
        """Moonraker ETA should produce different result than percent-based when they disagree."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        started = (now - timedelta(minutes=10)).isoformat()

        # Without Moonraker
        eta_no_moonraker = get_smart_eta(
            current_percent=10,
            printing_started_at=started,
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=None,
        )

        # With Moonraker saying 45 minutes left
        eta_with_moonraker = get_smart_eta(
            current_percent=10,
            printing_started_at=started,
            estimated_minutes=120,
            now=now,
            moonraker_time_remaining=2700,  # 45 min
        )

        assert eta_no_moonraker is not None
        assert eta_with_moonraker is not None

        remaining_no_mr = (eta_no_moonraker - now).total_seconds()
        remaining_with_mr = (eta_with_moonraker - now).total_seconds()

        # Moonraker should say exactly 45 min
        assert remaining_with_mr == pytest.approx(2700, abs=1)
        # Without Moonraker, it would be different (based on progress extrapolation)
        assert remaining_no_mr != remaining_with_mr

    def test_moonraker_eta_in_builds_info(self):
        """Build-level ETA display should be populated when Moonraker data is available."""
        now = datetime(2024, 6, 1, 12, 0, 0)
        started = (now - timedelta(minutes=30)).isoformat()
        rid, req = _seed_request_with_builds(
            [
                {"status": "COMPLETED", "minutes": 60, "progress": None, "started_at": None},
                {"status": "PRINTING", "minutes": 60, "progress": 50, "started_at": started},
                {"status": "PENDING", "minutes": 60, "progress": None, "started_at": None},
            ],
            request_status="IN_PROGRESS",
        )

        printer_status = {
            "progress": 75,
            "moonraker_time_remaining": 900,  # 15 minutes
            "is_moonraker": True,
        }

        info = get_request_eta_info(rid, req, printer_status=printer_status, now=now)

        # Find the PRINTING build in builds_info
        printing_builds = [bi for bi in info["builds_info"] if bi["status"] == "PRINTING"]
        assert len(printing_builds) == 1
        assert printing_builds[0]["eta_display"] is not None
        assert printing_builds[0]["progress"] == 75  # Updated from printer_status
