from app.main import (
    MoonrakerAPI,
    _apply_observed_printing_gate,
    _should_auto_complete_poll_result,
    db,
    find_matching_requests_for_file,
    now_iso,
    start_build,
)
from conftest import create_test_request


def test_auto_match_skips_in_progress_request_with_active_printing_build(client):
    req = create_test_request(
        status="IN_PROGRESS",
        print_name="Calibration Cube",
        printer="AD5X",
        with_builds=2,
    )

    conn = db()
    now = now_iso()
    builds = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? ORDER BY build_number",
        (req["request_id"],),
    ).fetchall()

    # Simulate a request that is already actively printing one build.
    conn.execute(
        "UPDATE builds SET status = 'PRINTING', printer = 'AD5X', started_at = ?, updated_at = ? WHERE id = ?",
        (now, now, builds[0]["id"]),
    )
    conn.execute(
        "UPDATE builds SET status = 'READY', updated_at = ? WHERE id = ?",
        (now, builds[1]["id"]),
    )
    conn.execute(
        "UPDATE requests SET active_build_id = ?, printer = 'AD5X', updated_at = ? WHERE id = ?",
        (builds[0]["id"], now, req["request_id"]),
    )
    conn.commit()
    conn.close()

    matches = find_matching_requests_for_file("Calibration_Cube_0.2mm_PLA.gcode", "AD5X")

    assert not matches


def test_start_build_allows_start_despite_other_printing_build(client):
    # A physical printer can only run one build at a time, so another build left
    # flagged PRINTING on the same printer is treated as stale rather than a hard
    # conflict. Starting a build is an explicit admin action and must not be wedged
    # by a lingering PRINTING row (which previously returned a 400 with no UI
    # recovery path). The same-request guard still prevents double-starts.
    req_a = create_test_request(status="APPROVED", printer="AD5X", with_builds=1)
    req_b = create_test_request(status="APPROVED", printer="AD5X", with_builds=1)

    conn = db()
    now = now_iso()
    build_a = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? ORDER BY build_number LIMIT 1",
        (req_a["request_id"],),
    ).fetchone()["id"]
    build_b = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? ORDER BY build_number LIMIT 1",
        (req_b["request_id"],),
    ).fetchone()["id"]

    # Existing active print on AD5X.
    conn.execute(
        "UPDATE builds SET status = 'PRINTING', printer = 'AD5X', started_at = ?, updated_at = ? WHERE id = ?",
        (now, now, build_a),
    )
    conn.execute(
        "UPDATE requests SET active_build_id = ?, status = 'IN_PROGRESS', updated_at = ? WHERE id = ?",
        (build_a, now, req_a["request_id"]),
    )

    # Candidate build remains queueable.
    conn.execute(
        "UPDATE builds SET status = 'READY', printer = 'AD5X', updated_at = ? WHERE id = ?",
        (now, build_b),
    )
    conn.commit()
    conn.close()

    result = start_build(build_b, "AD5X", "Test start is not wedged by stale PRINTING row")

    assert result["success"] is True


def test_multi_build_moonraker_standby_with_duration_is_treated_complete(client):
    api = MoonrakerAPI("http://localhost:7125")
    should_complete = _should_auto_complete_poll_result(
        is_printing=False,
        is_complete=False,
        percent_complete=0,
        printer_api=api,
        started_at=now_iso(),
        extended_status={"state": "standby", "message": "", "print_duration": 42},
    )
    assert should_complete is True


def test_observed_printing_gate_suppresses_unconfirmed_completion():
    # Printer reports complete but the build was never observed printing (e.g. it was
    # auto-started in the DB while FlashForge still held the previous print's 100%
    # state). Completion must be suppressed so the cascade can't happen.
    newly_confirmed, allow_complete = _apply_observed_printing_gate(
        printing_confirmed_at=None, is_printing=False, should_complete=True
    )
    assert newly_confirmed is False
    assert allow_complete is False


def test_observed_printing_gate_confirms_when_printer_running():
    # Poller sees the printer actively running an as-yet unconfirmed build.
    newly_confirmed, allow_complete = _apply_observed_printing_gate(
        printing_confirmed_at=None, is_printing=True, should_complete=False
    )
    assert newly_confirmed is True
    assert allow_complete is False


def test_observed_printing_gate_allows_completion_once_confirmed():
    # Build was previously observed printing; printer now reports complete.
    newly_confirmed, allow_complete = _apply_observed_printing_gate(
        printing_confirmed_at=now_iso(), is_printing=False, should_complete=True
    )
    assert newly_confirmed is False
    assert allow_complete is True


def test_start_build_resets_printing_confirmed(client):
    req = create_test_request(status="APPROVED", printer="AD5X", with_builds=1)
    conn = db()
    build_id = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? ORDER BY build_number LIMIT 1",
        (req["request_id"],),
    ).fetchone()["id"]
    # Simulate a stale confirmation left over from a prior run.
    conn.execute(
        "UPDATE builds SET status = 'READY', printer = 'AD5X', printing_confirmed_at = ? WHERE id = ?",
        (now_iso(), build_id),
    )
    conn.commit()
    conn.close()

    result = start_build(build_id, "AD5X", "Test confirmation reset")
    assert result["success"] is True

    conn = db()
    row = conn.execute(
        "SELECT status, printing_confirmed_at FROM builds WHERE id = ?", (build_id,)
    ).fetchone()
    conn.close()
    assert row["status"] == "PRINTING"
    assert row["printing_confirmed_at"] is None


def test_multi_build_moonraker_cancelled_standby_not_auto_complete(client):
    api = MoonrakerAPI("http://localhost:7125")
    should_complete = _should_auto_complete_poll_result(
        is_printing=False,
        is_complete=False,
        percent_complete=0,
        printer_api=api,
        started_at=now_iso(),
        extended_status={"state": "standby", "message": "cancelled by user", "print_duration": 42},
    )
    assert should_complete is False
