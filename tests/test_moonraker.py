"""
Tests for Moonraker/Klipper API integration for AD5X.

Covers:
- MoonrakerAPI class unit tests (state mapping, ETA, cache invalidation)
- get_printer_api() factory branching (feature flag on/off, URL configured/not)
- Admin control routes (auth, feature flag guard, confirm safeguard)
- Printer settings persistence for Moonraker config
- Feature flag toggle behaviour
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta

from tests.conftest import (
    get_test_db,
    clear_all_test_data,
    assert_html_contains,
    assert_html_not_contains,
)

from app.main import (
    MoonrakerAPI,
    get_printer_api,
    FlashForgeAPI,
    set_setting,
    get_setting,
    is_feature_enabled,
)
from app.auth import update_feature_flag


# ─────────────────── HELPERS ───────────────────────────────────────────

def enable_moonraker_flag():
    """Enable the moonraker_ad5x feature flag in test DB."""
    update_feature_flag("moonraker_ad5x", enabled=True)


def disable_moonraker_flag():
    """Disable the moonraker_ad5x feature flag in test DB."""
    update_feature_flag("moonraker_ad5x", enabled=False)


def configure_moonraker_url(url: str = "http://192.168.0.157:7125"):
    """Set the Moonraker URL in settings."""
    set_setting("moonraker_ad5x_url", url)


def configure_moonraker_api_key(key: str = "test-api-key-123"):
    """Set the Moonraker API key in settings."""
    set_setting("moonraker_ad5x_api_key", key)


# ─────────────────── MoonrakerAPI CLASS TESTS ──────────────────────────

class TestMoonrakerAPIInit:
    """Tests for MoonrakerAPI construction and configuration."""

    def test_init_stores_url_and_key(self):
        """MoonrakerAPI should store base URL and API key."""
        api = MoonrakerAPI("http://192.168.0.157:7125", "my-key")
        assert api.base_url == "http://192.168.0.157:7125"
        assert api.api_key == "my-key"

    def test_init_strips_trailing_slash(self):
        """Trailing slash on URL should be stripped."""
        api = MoonrakerAPI("http://192.168.0.157:7125/")
        assert api.base_url == "http://192.168.0.157:7125"

    def test_init_empty_api_key(self):
        """API key can be empty string (no auth)."""
        api = MoonrakerAPI("http://localhost:7125", "")
        assert api.api_key == ""

    def test_headers_include_api_key_when_set(self):
        """Headers should include X-Api-Key when API key is configured."""
        api = MoonrakerAPI("http://localhost:7125", "secret")
        headers = api._headers()
        assert headers["X-Api-Key"] == "secret"

    def test_headers_empty_when_no_api_key(self):
        """Headers should be empty dict when no API key."""
        api = MoonrakerAPI("http://localhost:7125", "")
        headers = api._headers()
        assert "X-Api-Key" not in headers


class TestMoonrakerStateMapping:
    """Tests for Moonraker state → FlashForge status mapping."""

    def test_printing_maps_to_building(self):
        assert MoonrakerAPI._STATE_MAP["printing"] == "BUILDING"

    def test_paused_maps_to_paused(self):
        assert MoonrakerAPI._STATE_MAP["paused"] == "PAUSED"

    def test_complete_maps_to_build_complete(self):
        assert MoonrakerAPI._STATE_MAP["complete"] == "BUILD_COMPLETE"

    def test_standby_maps_to_ready(self):
        assert MoonrakerAPI._STATE_MAP["standby"] == "READY"

    def test_error_maps_to_error(self):
        assert MoonrakerAPI._STATE_MAP["error"] == "ERROR"

    def test_cancelled_maps_to_ready(self):
        assert MoonrakerAPI._STATE_MAP["cancelled"] == "READY"

    def test_unknown_state_not_in_map(self):
        """Unknown states fall through to .get() default."""
        assert MoonrakerAPI._STATE_MAP.get("rebooting", "UNKNOWN") == "UNKNOWN"


class TestMoonrakerGetStatus:
    """Tests for get_status() with mocked _query_objects."""

    @pytest.mark.asyncio
    async def test_get_status_printing(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "printing"},
        })
        result = await api.get_status()
        assert result == {"MachineStatus": "BUILDING"}

    @pytest.mark.asyncio
    async def test_get_status_standby(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "standby"},
        })
        result = await api.get_status()
        assert result == {"MachineStatus": "READY"}

    @pytest.mark.asyncio
    async def test_get_status_returns_none_on_failure(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value=None)
        result = await api.get_status()
        assert result is None


class TestMoonrakerProgress:
    """Tests for get_progress() and get_percent_complete()."""

    @pytest.mark.asyncio
    async def test_get_progress_50_percent(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "virtual_sdcard": {"progress": 0.5},
        })
        result = await api.get_progress()
        assert result == {"PercentageCompleted": 50}

    @pytest.mark.asyncio
    async def test_get_progress_zero(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "virtual_sdcard": {"progress": 0.0},
        })
        result = await api.get_progress()
        assert result == {"PercentageCompleted": 0}

    @pytest.mark.asyncio
    async def test_get_percent_complete(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "virtual_sdcard": {"progress": 0.73},
        })
        result = await api.get_percent_complete()
        assert result == 73


class TestMoonrakerTemperature:
    """Tests for get_temperature() and get_bed_temp()."""

    @pytest.mark.asyncio
    async def test_get_temperature(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "extruder": {"temperature": 205.3, "target": 210.0},
        })
        result = await api.get_temperature()
        assert result["Temperature"] == "205.3"
        assert result["TargetTemperature"] == "210.0"

    @pytest.mark.asyncio
    async def test_get_bed_temp(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "heater_bed": {"temperature": 59.8, "target": 60.0},
        })
        result = await api.get_bed_temp()
        assert result["temperature"] == 59.8
        assert result["target"] == 60.0


class TestMoonrakerExtended:
    """Tests for get_extended_status() and related."""

    @pytest.mark.asyncio
    async def test_extended_status_with_layers(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {
                "filename": "benchy.gcode",
                "state": "printing",
                "print_duration": 1200.0,
                "filament_used": 5000.0,
                "message": "",
                "info": {"current_layer": 50, "total_layer": 200},
            },
            "display_status": {"progress": 0.25},
        })
        result = await api.get_extended_status()
        assert result["current_file"] == "benchy.gcode"
        assert result["current_layer"] == 50
        assert result["total_layers"] == 200
        assert result["filament_used"] == 5000.0
        assert result["print_duration"] == 1200.0
        assert result["display_progress"] == 25

    @pytest.mark.asyncio
    async def test_is_printing_true(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "printing"},
        })
        assert await api.is_printing() is True

    @pytest.mark.asyncio
    async def test_is_printing_false_when_standby(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "standby"},
        })
        assert await api.is_printing() is False

    @pytest.mark.asyncio
    async def test_is_complete(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "complete"},
        })
        assert await api.is_complete() is True

    @pytest.mark.asyncio
    async def test_is_complete_false_when_printing(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "printing"},
        })
        assert await api.is_complete() is False


class TestMoonrakerHeadLocation:
    """Tests for get_head_location()."""

    @pytest.mark.asyncio
    async def test_get_head_location(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._query_objects = AsyncMock(return_value={
            "toolhead": {"position": [100.5, 200.3, 10.2, 0]},
        })
        result = await api.get_head_location()
        assert result == {"X": 100.5, "Y": 200.3, "Z": 10.2}


class TestMoonrakerCacheInvalidation:
    """Tests for cache management."""

    def test_invalidate_cache_clears_data(self):
        api = MoonrakerAPI("http://localhost:7125")
        api._cached_objects = {"some": "data"}
        api._cached_at = 1000.0
        api._invalidate_cache()
        assert api._cached_objects is None
        assert api._cached_at == 0

    @pytest.mark.asyncio
    async def test_control_actions_invalidate_cache(self):
        """start_print, pause, resume, cancel should clear the cache."""
        api = MoonrakerAPI("http://localhost:7125")

        # Mock httpx to simulate a successful response
        mock_response = MagicMock()
        mock_response.status_code = 200

        for method_name in ["start_print", "pause_print", "resume_print", "cancel_print"]:
            api._cached_objects = {"old": "data"}
            api._cached_at = 999.0

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client

                if method_name == "start_print":
                    await api.start_print("test.gcode")
                else:
                    await getattr(api, method_name)()

            assert api._cached_objects is None, f"{method_name} should invalidate cache"
            assert api._cached_at == 0, f"{method_name} should reset cache timestamp"


class TestMoonrakerCalculateEta:
    """Tests for calculate_eta() method."""

    def test_eta_at_50_percent(self):
        api = MoonrakerAPI("http://localhost:7125")
        start = (datetime.now() - timedelta(hours=1)).isoformat()
        eta = api.calculate_eta(50, start)
        # At 50% with 1 hour elapsed, ~1 hour remaining
        assert eta is not None
        assert 3000 < eta < 4200  # roughly 1 hour ± tolerance

    def test_eta_at_zero_percent_returns_none(self):
        api = MoonrakerAPI("http://localhost:7125")
        start = datetime.now().isoformat()
        assert api.calculate_eta(0, start) is None

    def test_eta_at_99_percent_small_value(self):
        api = MoonrakerAPI("http://localhost:7125")
        start = (datetime.now() - timedelta(hours=2)).isoformat()
        eta = api.calculate_eta(99, start)
        assert eta is not None
        assert eta < 200  # should be small


# ─────────────────── FACTORY FUNCTION TESTS ────────────────────────────

class TestGetPrinterApiFactory:
    """Tests for get_printer_api() branching on feature flag + settings."""

    def test_ad5x_returns_flashforge_when_flag_off(self, client):
        """AD5X should use FlashForge when moonraker flag is disabled."""
        disable_moonraker_flag()
        api = get_printer_api("AD5X")
        assert isinstance(api, FlashForgeAPI)

    def test_ad5x_returns_moonraker_when_flag_on_and_url_set(self, client):
        """AD5X should use Moonraker when flag enabled + URL configured."""
        enable_moonraker_flag()
        configure_moonraker_url("http://192.168.0.157:7125")
        api = get_printer_api("AD5X")
        assert isinstance(api, MoonrakerAPI)
        assert api.base_url == "http://192.168.0.157:7125"

    def test_ad5x_falls_back_to_flashforge_when_no_url(self, client):
        """AD5X should fall back to FlashForge if flag on but no URL."""
        enable_moonraker_flag()
        set_setting("moonraker_ad5x_url", "")
        api = get_printer_api("AD5X")
        assert isinstance(api, FlashForgeAPI)

    def test_ad5x_moonraker_includes_api_key(self, client):
        """API key should be passed through to MoonrakerAPI."""
        enable_moonraker_flag()
        configure_moonraker_url()
        configure_moonraker_api_key("my-secret-key")
        api = get_printer_api("AD5X")
        assert isinstance(api, MoonrakerAPI)
        assert api.api_key == "my-secret-key"

    def test_adventurer4_always_uses_flashforge(self, client):
        """ADVENTURER_4 should always use FlashForge, even if moonraker flag is on."""
        enable_moonraker_flag()
        configure_moonraker_url()
        api = get_printer_api("ADVENTURER_4")
        assert isinstance(api, FlashForgeAPI)

    def test_unknown_printer_returns_none(self, client):
        """Unknown printer code should return None."""
        assert get_printer_api("UNKNOWN_PRINTER") is None


# ─────────────────── FEATURE FLAG TESTS ────────────────────────────────

class TestMoonrakerFeatureFlag:
    """Tests for the moonraker_ad5x feature flag."""

    def test_flag_can_be_disabled(self, client):
        """moonraker_ad5x can be explicitly disabled."""
        disable_moonraker_flag()
        assert is_feature_enabled("moonraker_ad5x") is False

    def test_flag_can_be_enabled(self, client):
        """Should be able to enable moonraker_ad5x flag."""
        enable_moonraker_flag()
        assert is_feature_enabled("moonraker_ad5x") is True

    def test_flag_toggle_roundtrip(self, client):
        """Enabling then disabling should return to disabled state."""
        enable_moonraker_flag()
        assert is_feature_enabled("moonraker_ad5x") is True
        disable_moonraker_flag()
        assert is_feature_enabled("moonraker_ad5x") is False

    def test_toggle_reverts_api(self, client):
        """Toggling flag off should switch AD5X back to FlashForge instantly."""
        enable_moonraker_flag()
        configure_moonraker_url()
        assert isinstance(get_printer_api("AD5X"), MoonrakerAPI)

        disable_moonraker_flag()
        assert isinstance(get_printer_api("AD5X"), FlashForgeAPI)


# ─────────────────── SETTINGS PERSISTENCE TESTS ───────────────────────

class TestMoonrakerSettings:
    """Tests for Moonraker settings persistence."""

    def test_moonraker_url_persists(self, client):
        set_setting("moonraker_ad5x_url", "http://10.0.0.50:7125")
        assert get_setting("moonraker_ad5x_url") == "http://10.0.0.50:7125"

    def test_moonraker_api_key_persists(self, client):
        set_setting("moonraker_ad5x_api_key", "secret-key-abc")
        assert get_setting("moonraker_ad5x_api_key") == "secret-key-abc"

    def test_settings_page_loads_with_moonraker_section(self, admin_client):
        """Printer settings page should load and mention Moonraker."""
        response = admin_client.get("/admin/printer-settings")
        assert response.status_code == 200
        # The page should contain Moonraker-related content
        assert "moonraker" in response.text.lower() or "Moonraker" in response.text

    def test_settings_page_shows_moonraker_url_field(self, admin_client):
        """Should show Moonraker URL input when feature flag is on."""
        enable_moonraker_flag()
        response = admin_client.get("/admin/printer-settings")
        assert response.status_code == 200
        assert "moonraker_ad5x_url" in response.text


# ─────────────────── ADMIN CONTROL ROUTE TESTS ────────────────────────

class TestMoonrakerControlRoutesAuth:
    """Tests that Moonraker control routes require admin auth."""

    CONTROL_ROUTES = [
        ("GET", "/api/admin/moonraker/AD5X/test"),
        ("GET", "/api/admin/moonraker/AD5X/files"),
        ("POST", "/api/admin/printer/AD5X/upload"),
        ("POST", "/api/admin/printer/AD5X/start"),
        ("POST", "/api/admin/printer/AD5X/pause"),
        ("POST", "/api/admin/printer/AD5X/resume"),
        ("POST", "/api/admin/printer/AD5X/cancel"),
    ]

    @pytest.mark.parametrize("method,path", CONTROL_ROUTES)
    def test_unauthenticated_access_denied(self, client, method, path):
        """All Moonraker control routes should deny unauthenticated access."""
        if method == "GET":
            response = client.get(path, follow_redirects=False)
        else:
            response = client.post(path, follow_redirects=False)
        # Should redirect to login or return 401/403
        assert response.status_code in (302, 303, 307, 401, 403), \
            f"{method} {path} should require auth, got {response.status_code}"


class TestMoonrakerControlRoutesFeatureFlag:
    """Tests that control routes check the feature flag."""

    def test_test_route_403_when_flag_disabled(self, admin_client):
        """Test connection should 403 when flag is off."""
        disable_moonraker_flag()
        response = admin_client.get("/api/admin/moonraker/AD5X/test")
        assert response.status_code == 403

    def test_files_route_403_when_flag_disabled(self, admin_client):
        """List files should 403 when flag is off."""
        disable_moonraker_flag()
        response = admin_client.get("/api/admin/moonraker/AD5X/files")
        assert response.status_code == 403

    def test_pause_403_when_flag_disabled(self, admin_client):
        """Pause should 403 when flag is off."""
        disable_moonraker_flag()
        response = admin_client.post(
            "/api/admin/printer/AD5X/pause",
            data={"confirm": "1"},
        )
        assert response.status_code == 403

    def test_cancel_403_when_flag_disabled(self, admin_client):
        """Cancel should 403 when flag is off."""
        disable_moonraker_flag()
        response = admin_client.post(
            "/api/admin/printer/AD5X/cancel",
            data={"confirm": "1"},
        )
        assert response.status_code == 403


class TestMoonrakerControlRoutesPrinterValidation:
    """Tests that control routes reject non-AD5X printers."""

    def test_test_route_400_for_adventurer4(self, admin_client):
        """Moonraker test should reject ADVENTURER_4."""
        enable_moonraker_flag()
        response = admin_client.get("/api/admin/moonraker/ADVENTURER_4/test")
        assert response.status_code == 400

    def test_files_route_400_for_adventurer4(self, admin_client):
        """Moonraker file list should reject ADVENTURER_4."""
        enable_moonraker_flag()
        response = admin_client.get("/api/admin/moonraker/ADVENTURER_4/files")
        assert response.status_code == 400


class TestMoonrakerControlRoutesConfirmSafeguard:
    """Tests that destructive actions require confirm=1."""

    def _enable_and_configure(self):
        """Enable flag and configure URL so _require_moonraker passes."""
        enable_moonraker_flag()
        configure_moonraker_url()

    def test_start_requires_confirm(self, admin_client):
        """Start print should fail without confirm=1."""
        self._enable_and_configure()
        response = admin_client.post(
            "/api/admin/printer/AD5X/start",
            data={"filename": "test.gcode", "confirm": "0"},
        )
        assert response.status_code == 400

    def test_pause_requires_confirm(self, admin_client):
        """Pause should fail without confirm=1."""
        self._enable_and_configure()
        response = admin_client.post(
            "/api/admin/printer/AD5X/pause",
            data={"confirm": "0"},
        )
        assert response.status_code == 400

    def test_resume_requires_confirm(self, admin_client):
        """Resume should fail without confirm=1."""
        self._enable_and_configure()
        response = admin_client.post(
            "/api/admin/printer/AD5X/resume",
            data={"confirm": "0"},
        )
        assert response.status_code == 400

    def test_cancel_requires_confirm(self, admin_client):
        """Cancel should fail without confirm=1."""
        self._enable_and_configure()
        response = admin_client.post(
            "/api/admin/printer/AD5X/cancel",
            data={"confirm": "0"},
        )
        assert response.status_code == 400


class TestMoonrakerUploadValidation:
    """Tests for file upload validation."""

    def _enable_and_configure(self):
        enable_moonraker_flag()
        configure_moonraker_url()

    def test_upload_rejects_non_gcode_file(self, admin_client):
        """Only .gcode files should be accepted."""
        self._enable_and_configure()
        response = admin_client.post(
            "/api/admin/printer/AD5X/upload",
            files={"file": ("model.stl", b"solid test", "application/octet-stream")},
        )
        assert response.status_code == 400
        assert "gcode" in response.text.lower()

    def test_upload_rejects_no_file(self, admin_client):
        """Upload should fail without a file."""
        self._enable_and_configure()
        response = admin_client.post("/api/admin/printer/AD5X/upload")
        assert response.status_code == 422  # FastAPI validation error

    def test_upload_403_when_flag_disabled(self, admin_client):
        """Upload should 403 when flag is off."""
        disable_moonraker_flag()
        response = admin_client.post(
            "/api/admin/printer/AD5X/upload",
            files={"file": ("test.gcode", b"G28\nG1 X10", "application/octet-stream")},
        )
        assert response.status_code == 403


class TestMoonrakerStartPrintValidation:
    """Tests for start print validation."""

    def _enable_and_configure(self):
        enable_moonraker_flag()
        configure_moonraker_url()

    def test_start_requires_filename(self, admin_client):
        """Start print should require a filename."""
        self._enable_and_configure()
        # FastAPI will return 422 if required Form field is missing
        response = admin_client.post(
            "/api/admin/printer/AD5X/start",
            data={"confirm": "1"},
        )
        assert response.status_code == 422


class TestMoonrakerCancelSafetyCheck:
    """Tests for cancel print safety checks."""

    def _enable_and_configure(self):
        enable_moonraker_flag()
        configure_moonraker_url()

    def test_cancel_requires_printing_state(self, admin_client):
        """Cancel should verify printer is actually printing/paused (without force)."""
        self._enable_and_configure()

        # Mock _require_moonraker to return a mock MoonrakerAPI
        mock_api = AsyncMock()
        mock_api.is_printing = AsyncMock(return_value=False)
        mock_api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "standby"},
        })

        with patch("app.admin._require_moonraker", return_value=mock_api):
            response = admin_client.post(
                "/api/admin/printer/AD5X/cancel",
                data={"confirm": "1", "force": "0"},
            )
            assert response.status_code == 409
            assert "not currently printing" in response.text.lower()

    def test_cancel_with_force_bypasses_state_check(self, admin_client):
        """Cancel with force=1 should bypass state check."""
        self._enable_and_configure()

        mock_api = AsyncMock()
        mock_api.is_printing = AsyncMock(return_value=False)
        mock_api._query_objects = AsyncMock(return_value={
            "print_stats": {"state": "standby"},
        })
        mock_api.cancel_print = AsyncMock(return_value=True)

        with patch("app.admin._require_moonraker", return_value=mock_api):
            response = admin_client.post(
                "/api/admin/printer/AD5X/cancel",
                data={"confirm": "1", "force": "1"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["action"] == "cancel"


# ─────────────────── ADMIN UI TESTS ───────────────────────────────────

class TestAdminQueueMoonrakerUI:
    """Tests for Moonraker-related UI in admin queue page."""

    def test_admin_queue_loads(self, admin_client):
        """Admin queue page should load without errors."""
        response = admin_client.get("/admin")
        assert response.status_code == 200

    def test_admin_queue_has_moonraker_js_functions(self, admin_client):
        """Queue page should include Moonraker JS control functions."""
        response = admin_client.get("/admin")
        assert response.status_code == 200
        # Check for key Moonraker JS functions in the page
        assert "moonrakerControl" in response.text

    def test_admin_features_page_shows_moonraker_flag(self, admin_client):
        """Features page should list the moonraker_ad5x flag."""
        response = admin_client.get("/admin/features")
        assert response.status_code == 200
        assert "moonraker_ad5x" in response.text.lower() or "Moonraker" in response.text

    def test_admin_debug_loads_with_moonraker(self, admin_client):
        """Debug page should load and include Moonraker test section."""
        response = admin_client.get("/admin/debug")
        assert response.status_code == 200
        assert "moonraker" in response.text.lower()


# ─────────────────── PRINTER STATUS API TESTS ─────────────────────────

class TestPrinterStatusAPIWithMoonraker:
    """Tests for /api/printers/status with Moonraker data."""

    def test_printer_status_endpoint_returns_ok(self, admin_client):
        """Printer status API should return valid JSON (demo mode)."""
        response = admin_client.get("/api/printers/status")
        assert response.status_code == 200
        data = response.json()
        assert "AD5X" in data or "printers" in data or isinstance(data, dict)

    def test_printer_status_endpoint_requires_auth(self, client):
        """Printer status API should require authentication."""
        response = client.get("/api/printers/status")
        assert response.status_code in (401, 302, 303)


# ─────────────────── MOONRAKER WEBCAM / CAMERA TESTS ──────────────────

class TestMoonrakerGetWebcams:
    """Tests for MoonrakerAPI.get_webcams() method."""

    @pytest.mark.asyncio
    async def test_get_webcams_returns_list(self):
        """get_webcams should return list of webcam entries from API."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        mock_response = {
            "result": {
                "webcams": [
                    {
                        "name": "Default",
                        "location": "printer",
                        "service": "mjpegstreamer",
                        "enabled": True,
                        "stream_url": "http://192.168.0.157:8080/?action=stream",
                        "snapshot_url": "http://192.168.0.157:8080/?action=snapshot",
                        "uid": "abc-123",
                    }
                ]
            }
        }
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            webcams = await api.get_webcams()
            assert webcams is not None
            assert len(webcams) == 1
            assert webcams[0]["name"] == "Default"
            assert "stream_url" in webcams[0]

    @pytest.mark.asyncio
    async def test_get_webcams_returns_none_on_error(self):
        """get_webcams should return None when API is unreachable."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            webcams = await api.get_webcams()
            assert webcams is None

    @pytest.mark.asyncio
    async def test_get_webcams_empty_list(self):
        """get_webcams should return empty list when no webcams configured."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        mock_response = {"result": {"webcams": []}}
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            webcams = await api.get_webcams()
            assert webcams == []


class TestMoonrakerGetCameraUrls:
    """Tests for MoonrakerAPI.get_camera_urls() method."""

    @pytest.mark.asyncio
    async def test_get_camera_urls_full_urls(self):
        """get_camera_urls should return full URLs from webcam."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch.object(api, "get_webcams", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = [
                {
                    "name": "ustreamer",
                    "enabled": True,
                    "service": "mjpegstreamer",
                    "stream_url": "http://192.168.0.157:8080/?action=stream",
                    "snapshot_url": "http://192.168.0.157:8080/?action=snapshot",
                }
            ]
            result = await api.get_camera_urls()
            assert result is not None
            assert result["stream_url"] == "http://192.168.0.157:8080/?action=stream"
            assert result["snapshot_url"] == "http://192.168.0.157:8080/?action=snapshot"

    @pytest.mark.asyncio
    async def test_get_camera_urls_relative_urls(self):
        """get_camera_urls should resolve relative URLs against Moonraker host."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch.object(api, "get_webcams", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = [
                {
                    "name": "cam",
                    "enabled": True,
                    "stream_url": "/webcam/?action=stream",
                    "snapshot_url": "/webcam/?action=snapshot",
                }
            ]
            result = await api.get_camera_urls()
            assert result is not None
            # Relative URLs should resolve against the Moonraker host (without port)
            assert result["stream_url"] == "http://192.168.0.157/webcam/?action=stream"
            assert result["snapshot_url"] == "http://192.168.0.157/webcam/?action=snapshot"

    @pytest.mark.asyncio
    async def test_get_camera_urls_no_webcams(self):
        """get_camera_urls should return None when no webcams."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch.object(api, "get_webcams", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = None
            result = await api.get_camera_urls()
            assert result is None

    @pytest.mark.asyncio
    async def test_get_camera_urls_empty_list(self):
        """get_camera_urls should return None when webcam list is empty."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch.object(api, "get_webcams", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = []
            result = await api.get_camera_urls()
            assert result is None

    @pytest.mark.asyncio
    async def test_get_camera_urls_picks_first_enabled(self):
        """get_camera_urls should pick the first enabled webcam."""
        api = MoonrakerAPI("http://192.168.0.157:7125")
        with patch.object(api, "get_webcams", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = [
                {
                    "name": "disabled_cam",
                    "enabled": False,
                    "stream_url": "http://host/bad",
                    "snapshot_url": "",
                },
                {
                    "name": "good_cam",
                    "enabled": True,
                    "stream_url": "http://host:8080/?action=stream",
                    "snapshot_url": "http://host:8080/?action=snapshot",
                },
            ]
            result = await api.get_camera_urls()
            assert result is not None
            assert result["name"] == "good_cam"


class TestGetCameraUrl:
    """Tests for the get_camera_url() sync function with Moonraker auto-derive."""

    def test_adventurer4_returns_manual_url(self, client):
        """get_camera_url for Adventurer 4 should always return manual setting."""
        from app.main import get_camera_url
        set_setting("camera_adventurer_4_url", "http://10.0.0.1:8080/?action=stream")
        result = get_camera_url("ADVENTURER_4")
        assert result == "http://10.0.0.1:8080/?action=stream"

    def test_ad5x_returns_manual_url_when_set(self, client):
        """get_camera_url should return manual URL when one is configured."""
        from app.main import get_camera_url
        set_setting("camera_ad5x_url", "http://192.168.0.157:8080/?action=stream")
        result = get_camera_url("AD5X")
        assert result == "http://192.168.0.157:8080/?action=stream"

    def test_ad5x_auto_derives_from_moonraker_url(self, client):
        """get_camera_url should derive ustreamer URL from Moonraker IP when no manual URL set."""
        from app.main import get_camera_url
        set_setting("camera_ad5x_url", "")
        enable_moonraker_flag()
        configure_moonraker_url("http://192.168.0.157:7125")
        result = get_camera_url("AD5X")
        assert result == "http://192.168.0.157:8080/?action=stream"

    def test_ad5x_returns_empty_when_no_moonraker(self, client):
        """get_camera_url should return empty when no manual URL and Moonraker disabled."""
        from app.main import get_camera_url
        set_setting("camera_ad5x_url", "")
        disable_moonraker_flag()
        result = get_camera_url("AD5X")
        assert result == ""

    def test_unknown_printer_returns_none(self, client):
        """get_camera_url should return None for unknown printers."""
        from app.main import get_camera_url
        result = get_camera_url("UNKNOWN")
        assert result is None


class TestGetCameraUrlAsync:
    """Tests for get_camera_url_async() with Moonraker webcam discovery."""

    @pytest.mark.asyncio
    async def test_manual_url_takes_priority(self, client):
        """Manual camera URL should always take priority over auto-discovery."""
        from app.main import get_camera_url_async
        set_setting("camera_ad5x_url", "http://manual:8080/?action=stream")
        enable_moonraker_flag()
        configure_moonraker_url("http://192.168.0.157:7125")
        result = await get_camera_url_async("AD5X")
        assert result == "http://manual:8080/?action=stream"

    @pytest.mark.asyncio
    async def test_auto_discovers_from_moonraker(self, client):
        """Should auto-discover camera URL from Moonraker webcam API."""
        from app.main import get_camera_url_async
        set_setting("camera_ad5x_url", "")
        enable_moonraker_flag()
        configure_moonraker_url("http://192.168.0.157:7125")

        mock_cam_urls = {
            "stream_url": "http://192.168.0.157:8080/?action=stream",
            "snapshot_url": "http://192.168.0.157:8080/?action=snapshot",
            "name": "cam",
            "service": "mjpegstreamer",
        }
        with patch("app.main.MoonrakerAPI.get_camera_urls", new_callable=AsyncMock, return_value=mock_cam_urls):
            result = await get_camera_url_async("AD5X")
            assert result == "http://192.168.0.157:8080/?action=stream"

    @pytest.mark.asyncio
    async def test_falls_back_to_derived_url(self, client):
        """Should fall back to derived ustreamer URL when webcam discovery fails."""
        from app.main import get_camera_url_async
        set_setting("camera_ad5x_url", "")
        enable_moonraker_flag()
        configure_moonraker_url("http://192.168.0.157:7125")

        with patch("app.main.MoonrakerAPI.get_camera_urls", new_callable=AsyncMock, return_value=None):
            result = await get_camera_url_async("AD5X")
            assert result == "http://192.168.0.157:8080/?action=stream"

    @pytest.mark.asyncio
    async def test_returns_empty_when_moonraker_disabled(self, client):
        """Should return empty string when Moonraker is disabled and no manual URL."""
        from app.main import get_camera_url_async
        set_setting("camera_ad5x_url", "")
        disable_moonraker_flag()
        result = await get_camera_url_async("AD5X")
        assert result == ""


class TestMoonrakerWebcamEndpoint:
    """Tests for the /api/admin/moonraker/{printer_code}/webcams API endpoint."""

    def test_webcam_endpoint_requires_auth(self, client):
        """Webcam test endpoint should require admin auth."""
        response = client.get("/api/admin/moonraker/AD5X/webcams")
        assert response.status_code in (401, 302, 303)

    def test_webcam_endpoint_requires_moonraker(self, admin_client):
        """Webcam endpoint should fail when Moonraker is not enabled."""
        disable_moonraker_flag()
        response = admin_client.get("/api/admin/moonraker/AD5X/webcams")
        # Should get an error (feature disabled or not configured)
        assert response.status_code in (400, 403, 503)

    def test_webcam_endpoint_rejects_invalid_printer(self, admin_client):
        """Webcam endpoint should reject non-AD5X printers."""
        enable_moonraker_flag()
        configure_moonraker_url()
        response = admin_client.get("/api/admin/moonraker/ADVENTURER_4/webcams")
        assert response.status_code == 400
