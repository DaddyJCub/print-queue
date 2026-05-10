from app.main import (
    MoonrakerAPI,
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


def test_start_build_blocks_when_printer_already_printing(client):
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

    result = start_build(build_b, "AD5X", "Test concurrent start prevention")

    assert result["success"] is False
    assert "already printing" in result["error"].lower()


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
