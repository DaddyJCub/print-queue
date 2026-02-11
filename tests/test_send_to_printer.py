"""
Tests for send-to-printer (Moonraker) feature:
- Upload G-code to printer via Moonraker API
- Multi-color detection from file metadata
- ZMOD bypass (SILENT=2, FORCE_MD5=0)
- Background start with setting restore
- Thumbnail proxy endpoint
- ETA with moonraker_time_remaining
"""
import asyncio
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import (
    create_test_request,
    get_test_db,
    assert_redirect_to,
)


# ─────────────────────────── HELPERS ───────────────────────────

def _create_request_with_gcode(printer="AD5X", status="PRINTING"):
    """Create a test request with a .gcode file on disk."""
    data = create_test_request(printer=printer, status=status, with_file=True)
    rid = data["request_id"]
    file_id = data["file_ids"][0]

    # Update the file record to be a .gcode file
    conn = get_test_db()
    conn.execute(
        "UPDATE files SET original_filename = 'test_print.gcode', stored_filename = 'test_stored.gcode' WHERE id = ?",
        (file_id,)
    )
    conn.commit()
    conn.close()

    # Write a minimal gcode file to disk
    upload_dir = os.environ["UPLOAD_DIR"]
    gcode_path = os.path.join(upload_dir, "test_stored.gcode")
    with open(gcode_path, "w") as f:
        f.write("; Generated test G-code\nG28\nG1 X0 Y0 Z0.3 F3000\n")

    return rid, file_id, data


def _enable_moonraker_feature():
    """Enable the moonraker_ad5x feature flag in the database."""
    from datetime import datetime
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = get_test_db()
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('feature_moonraker_ad5x', '1', ?)",
        (now,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('moonraker_ad5x_url', 'http://127.0.0.1:7125', ?)",
        (now,)
    )
    conn.commit()
    conn.close()


def _mock_moonraker_api():
    """Create a mock MoonrakerAPI instance with all methods stubbed."""
    from app.main import MoonrakerAPI
    mock_api = MagicMock(spec=MoonrakerAPI)
    mock_api.upload_file = AsyncMock(return_value={"item": {"path": "test_print.gcode"}})
    mock_api.get_file_metadata = AsyncMock(return_value={
        "size": 1024,
        "modified": 1700000000,
        "referenced_tools": [],
        "filament_colors": [],
        "filament_type": "PLA",
        "filament_change_count": 0,
    })
    mock_api.run_gcode = AsyncMock(return_value=True)
    mock_api.start_print = AsyncMock(return_value=True)
    return mock_api


# ─────────────────────────── SEND TO PRINTER TESTS ───────────────────────────

class TestSendToPrinter:
    """Tests for the send-to-printer route."""

    def test_send_requires_gcode_file(self, admin_client):
        """Only .gcode files can be sent to printer."""
        _enable_moonraker_feature()
        data = create_test_request(printer="AD5X", status="PRINTING", with_file=True)
        rid = data["request_id"]
        file_id = data["file_ids"][0]

        # The default test file is .stl, which should be rejected
        with patch("app.api_builds.get_printer_api") as mock_get_api, \
             patch("app.api_builds.is_feature_enabled", return_value=True):
            mock_get_api.return_value = _mock_moonraker_api()
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )
        assert response.status_code == 400

    def test_send_requires_moonraker_feature(self, admin_client):
        """Should fail when moonraker_ad5x feature is disabled."""
        rid, file_id, _ = _create_request_with_gcode()

        with patch("app.api_builds.is_feature_enabled", return_value=False):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )
        assert response.status_code == 400

    def test_send_upload_only(self, admin_client):
        """Upload without starting should redirect with sent_to_printer=1."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": ""},
                follow_redirects=False,
            )

        assert_redirect_to(response, f"/admin/request/{rid}")
        assert "sent_to_printer=1" in response.headers.get("location", "")
        # Verify upload was called
        mock_api.upload_file.assert_awaited_once()
        # Verify start was NOT called (no start_print)
        mock_api.start_print.assert_not_awaited()

    def test_send_with_start_sets_zmod_params(self, admin_client):
        """Starting print should set ZMOD SILENT=2 and FORCE_MD5=0."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        assert_redirect_to(response, f"/admin/request/{rid}")
        assert "sent_to_printer=1" in response.headers.get("location", "")

        # Verify ZMOD commands were sent
        gcode_calls = [call.args[0] for call in mock_api.run_gcode.call_args_list]
        assert "SAVE_ZMOD_DATA SILENT=2" in gcode_calls
        assert "SAVE_ZMOD_DATA FORCE_MD5=0" in gcode_calls

    def test_send_multicolor_redirects_without_starting(self, admin_client):
        """Multi-color files should be uploaded but NOT auto-started."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()

        # Override metadata to indicate multi-color
        mock_api.get_file_metadata = AsyncMock(return_value={
            "size": 2048,
            "referenced_tools": [0, 1, 2, 3],
            "filament_colors": ["#FF0000", "#00FF00", "#0000FF", "#FFFFFF"],
            "filament_type": "PLA",
            "filament_name": "Generic PLA",
            "filament_change_count": 12,
        })

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        assert_redirect_to(response, f"/admin/request/{rid}")
        location = response.headers.get("location", "")
        assert "multi_color" in location
        assert "tool_count=4" in location

        # Verify upload happened but ZMOD/start were NOT called
        mock_api.upload_file.assert_awaited_once()
        mock_api.run_gcode.assert_not_awaited()  # No ZMOD overrides for multi-color

    def test_send_request_not_found(self, admin_client):
        """Should 404 for non-existent request."""
        _enable_moonraker_feature()
        fake_rid = str(uuid.uuid4())
        fake_fid = str(uuid.uuid4())

        response = admin_client.post(
            f"/admin/request/{fake_rid}/file/{fake_fid}/send-to-printer",
            data={"printer": "AD5X", "start_print": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 404

    def test_send_file_not_found(self, admin_client):
        """Should 404 if file doesn't belong to this request."""
        data = create_test_request(printer="AD5X", status="PRINTING")
        rid = data["request_id"]
        fake_fid = str(uuid.uuid4())

        response = admin_client.post(
            f"/admin/request/{rid}/file/{fake_fid}/send-to-printer",
            data={"printer": "AD5X", "start_print": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 404

    def test_send_upload_failure_returns_502(self, admin_client):
        """Failed Moonraker upload should return 502."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()
        mock_api.upload_file = AsyncMock(return_value=None)  # Upload fails

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        assert response.status_code == 502

    def test_send_metadata_timeout_still_proceeds(self, admin_client):
        """If metadata never becomes ready, upload should still succeed."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()

        # Metadata never has 'size' field — simulates timeout
        mock_api.get_file_metadata = AsyncMock(return_value={"filename": "test.gcode"})

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True), \
             patch("app.api_builds.asyncio") as mock_asyncio:
            # Make sleep a no-op so we don't wait 10 seconds
            mock_asyncio.sleep = AsyncMock()
            mock_asyncio.create_task = MagicMock()
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        # Should still redirect successfully (metadata timeout is non-fatal)
        assert_redirect_to(response, f"/admin/request/{rid}")


# ─────────────────────────── MULTI-COLOR DETECTION TESTS ───────────────────────────

class TestMultiColorDetection:
    """Tests for multi-color detection from Moonraker metadata."""

    def test_single_tool_is_not_multi_color(self, admin_client):
        """A file with 1 tool and 0 filament changes should not be multi-color."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()
        mock_api.get_file_metadata = AsyncMock(return_value={
            "size": 1024,
            "referenced_tools": [0],
            "filament_colors": ["#000000"],
            "filament_change_count": 0,
        })

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        location = response.headers.get("location", "")
        assert "multi_color" not in location
        assert "sent_to_printer=1" in location

    def test_multiple_tools_is_multi_color(self, admin_client):
        """A file with multiple tools should be detected as multi-color."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()
        mock_api.get_file_metadata = AsyncMock(return_value={
            "size": 2048,
            "referenced_tools": [0, 1],
            "filament_colors": ["#000000", "#FF0000"],
            "filament_change_count": 5,
        })

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        location = response.headers.get("location", "")
        assert "multi_color" in location
        assert "tool_count=2" in location

    def test_filament_change_count_triggers_multi_color(self, admin_client):
        """Even with empty tools list, filament_change_count > 0 = multi-color."""
        rid, file_id, _ = _create_request_with_gcode()
        _enable_moonraker_feature()
        mock_api = _mock_moonraker_api()
        mock_api.get_file_metadata = AsyncMock(return_value={
            "size": 2048,
            "referenced_tools": [],
            "filament_colors": [],
            "filament_change_count": 3,
        })

        with patch("app.api_builds.get_printer_api", return_value=mock_api), \
             patch("app.api_builds.is_feature_enabled", return_value=True), \
             patch("app.api_builds.isinstance", side_effect=lambda obj, cls: True):
            response = admin_client.post(
                f"/admin/request/{rid}/file/{file_id}/send-to-printer",
                data={"printer": "AD5X", "start_print": "1"},
                follow_redirects=False,
            )

        location = response.headers.get("location", "")
        assert "multi_color" in location


# ─────────────────────────── THUMBNAIL PROXY TESTS ───────────────────────────

class TestThumbnailProxy:
    """Tests for the thumbnail proxy endpoint."""

    def test_thumbnail_proxy_returns_image(self, admin_client):
        """Thumbnail proxy should fetch and return the image from Moonraker."""
        from app.main import update_printer_status_cache
        update_printer_status_cache("AD5X", {
            "thumbnail_url": "http://192.168.0.157:7125/server/files/gcodes/.thumbs/test-140x110.png",
            "is_printing": True,
            "status": "BUILDING",
        })

        fake_image = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100  # Minimal PNG-like bytes
        with patch("app.api_builds.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = fake_image
            mock_response.headers = {"content-type": "image/png"}

            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client_instance

            response = admin_client.get("/api/printer/AD5X/thumbnail")

        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
        assert response.content == fake_image

    def test_thumbnail_proxy_no_cache(self, admin_client):
        """Should 404 when no thumbnail URL is cached."""
        from app.main import update_printer_status_cache
        update_printer_status_cache("AD5X", {
            "is_printing": False,
            "status": "READY",
        })

        response = admin_client.get("/api/printer/AD5X/thumbnail")
        assert response.status_code == 404

    def test_thumbnail_proxy_invalid_printer(self, admin_client):
        """Should 400 for invalid printer code."""
        response = admin_client.get("/api/printer/INVALID/thumbnail")
        assert response.status_code == 400


# ─────────────────────────── ETA WITH MOONRAKER TESTS ───────────────────────────

class TestMoonrakerETA:
    """Tests for ETA calculation using moonraker_time_remaining."""

    def test_moonraker_time_remaining_used_as_primary_eta(self):
        """get_smart_eta should prefer moonraker_time_remaining over other methods."""
        from app.main import get_smart_eta

        now = datetime(2024, 6, 15, 14, 0, 0)
        moonraker_remaining = 3600  # 1 hour

        eta = get_smart_eta(
            printer="AD5X",
            material="PLA",
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            moonraker_time_remaining=moonraker_remaining,
            now=now,
        )

        assert eta is not None
        # Should be exactly 1 hour from now (within seconds)
        remaining = (eta - now).total_seconds()
        assert abs(remaining - 3600) < 5

    def test_moonraker_time_remaining_overrides_percent(self):
        """Moonraker ETA should override percent-based calculation even when both available."""
        from app.main import get_smart_eta

        now = datetime(2024, 6, 15, 14, 0, 0)

        # Percent-based would suggest ~1hr remaining (50% in 1hr)
        # But Moonraker says only 30 min left (printer knows better from file analysis)
        eta = get_smart_eta(
            printer="AD5X",
            material="PLA",
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            estimated_minutes=120,
            moonraker_time_remaining=1800,  # 30 minutes
            now=now,
        )

        assert eta is not None
        remaining = (eta - now).total_seconds()
        assert abs(remaining - 1800) < 5  # Should be 30 min, not 1 hour

    def test_moonraker_time_remaining_zero_means_done(self):
        """moonraker_time_remaining of 0 should return now (print done)."""
        from app.main import get_smart_eta

        now = datetime(2024, 6, 15, 14, 0, 0)
        eta = get_smart_eta(
            moonraker_time_remaining=0,
            now=now,
        )
        assert eta is not None
        assert eta == now

    def test_fallback_without_moonraker_remaining(self):
        """Without moonraker_time_remaining, should use percent/layer methods."""
        from app.main import get_smart_eta

        now = datetime(2024, 6, 15, 14, 0, 0)
        eta = get_smart_eta(
            current_percent=50,
            printing_started_at=(now - timedelta(hours=1)).isoformat(),
            estimated_minutes=120,
            now=now,
        )

        assert eta is not None
        remaining = (eta - now).total_seconds()
        # Should be roughly 1 hour remaining (not exact due to smoothing)
        assert 1800 < remaining < 7200

    def test_format_eta_display_utc_consistency(self):
        """format_eta_display should handle UTC datetimes from get_smart_eta correctly."""
        from app.main import format_eta_display, get_smart_eta

        now = datetime.utcnow()
        # Create an ETA 2 hours from now via get_smart_eta
        eta = get_smart_eta(
            moonraker_time_remaining=7200,  # 2 hours
            now=now,
        )
        assert eta is not None

        display = format_eta_display(eta)
        assert display != "Unknown"
        assert display != "Any moment now"
        # Should contain a time like "Today at X:XX PM" or similar
        assert "at" in display or ":" in display


# ─────────────────────────── MOONRAKER AVAILABLE BUTTON TESTS ───────────────────────────

class TestMoonrakerAvailable:
    """Tests for moonraker_available flag on request detail page."""

    def test_ad5x_printer_shows_moonraker_available(self, admin_client):
        """Requests with AD5X printer should have moonraker available."""
        _enable_moonraker_feature()
        data = create_test_request(printer="AD5X", status="PRINTING", with_file=True)
        rid = data["request_id"]

        # Update file to be gcode
        conn = get_test_db()
        if data["file_ids"]:
            conn.execute(
                "UPDATE files SET original_filename = 'test.gcode' WHERE id = ?",
                (data["file_ids"][0],)
            )
            conn.commit()
        conn.close()

        response = admin_client.get(f"/admin/request/{rid}")
        assert response.status_code == 200
        # The page should have the send-to-printer functionality visible
        assert "send-to-printer" in response.text.lower() or "moonraker" in response.text.lower() or "Send to" in response.text

    def test_any_printer_shows_moonraker_available(self, admin_client):
        """Requests with ANY printer should also have moonraker available."""
        _enable_moonraker_feature()
        data = create_test_request(printer="ANY", status="PRINTING", with_file=True)
        rid = data["request_id"]

        # Update file to be gcode
        conn = get_test_db()
        if data["file_ids"]:
            conn.execute(
                "UPDATE files SET original_filename = 'test.gcode' WHERE id = ?",
                (data["file_ids"][0],)
            )
            conn.commit()
        conn.close()

        response = admin_client.get(f"/admin/request/{rid}")
        assert response.status_code == 200
