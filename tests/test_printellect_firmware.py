import sys
import time
from pathlib import Path


DEVICE_ROOT = Path(__file__).resolve().parent.parent / "device" / "pico2w"
if str(DEVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(DEVICE_ROOT))

from lib.command_runner import CommandRunner  # noqa: E402
from lib.hardware import HardwareAdapter  # noqa: E402
from lib.versioning import get_reported_versions  # noqa: E402
import lib.command_runner as command_runner_module  # noqa: E402
import main as firmware_main  # noqa: E402


class FakeApi:
    def __init__(self):
        self.status_calls = []
        self.state_calls = []

    def command_status(self, cmd_id, status, error=None, result=None):
        self.status_calls.append(
            {
                "cmd_id": cmd_id,
                "status": status,
                "error": error,
                "result": result,
            }
        )

    def state_update(self, state):
        self.state_calls.append(state)


def test_hardware_adapter_tracks_light_color_and_effect():
    hw = HardwareAdapter()
    color_result = hw.set_light_color({"r": 10, "g": 132, "b": 255})
    assert color_result["light_color"] == {"r": 10, "g": 132, "b": 255}
    assert color_result["hex"] == "#0A84FF"

    effect_result = hw.set_light_effect("pulse", speed_ms=250, duration_ms=1200, color={"r": 52, "g": 199, "b": 89})
    assert effect_result["light_effect"] == "pulse"
    assert effect_result["speed_ms"] == 250
    assert effect_result["duration_ms"] == 1200
    assert effect_result["hex"] == "#34C759"

    state = hw.get_state()
    assert state["light_color"] == {"r": 52, "g": 199, "b": 89}
    assert state["light_effect"] == "pulse"


def test_hardware_adapter_effects_animate_and_expire():
    hw = HardwareAdapter()
    hw.set_brightness(100)
    hw.set_light_color({"r": 255, "g": 255, "b": 255})
    hw.set_light_effect("strobe", speed_ms=40, duration_ms=180)

    seen = set()
    for _ in range(8):
        hw.update()
        seen.add(hw._last_np_rgb)
        time.sleep(0.03)

    assert (0, 0, 0) in seen
    assert any(rgb != (0, 0, 0) for rgb in seen)

    # Duration should auto-expire to off.
    time.sleep(0.20)
    hw.update()
    assert hw.get_state()["light_effect"] == "off"


def test_reported_versions_prioritize_pending_and_last_good():
    fw, app = get_reported_versions(
        {"fw_version": "fw-2.1.0", "app_version": "1.0.0"},
        {"pending_version": "1.1.0", "last_good_version": "1.0.9"},
    )
    assert fw == "fw-2.1.0"
    assert app == "1.1.0"

    fw2, app2 = get_reported_versions(
        {"fw_version": "fw-2.1.0", "app_version": "1.0.0"},
        {"last_good_version": "1.0.9"},
    )
    assert fw2 == "fw-2.1.0"
    assert app2 == "1.0.9"


def test_reported_versions_fall_back_to_config_then_defaults():
    fw, app = get_reported_versions({"fw_version": "fw-3.0.0", "app_version": "2.0.0"}, {})
    assert fw == "fw-3.0.0"
    assert app == "2.0.0"

    fw_default, app_default = get_reported_versions({}, {})
    assert fw_default == "fw-0.0.0"
    assert app_default == "app-0.0.0"


def test_firmware_main_exports_legacy_run_entrypoint():
    assert hasattr(firmware_main, "run")
    assert callable(firmware_main.run)


def test_command_runner_reports_result_for_light_color(monkeypatch):
    monkeypatch.setattr(command_runner_module, "in_ring", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(command_runner_module, "append_ring", lambda *_args, **_kwargs: None)

    hw = HardwareAdapter()
    api = FakeApi()
    runner = CommandRunner(hw, api, "/tmp/app_state_test.json")

    runner.execute(
        {
            "cmd_id": "cmd-light-color",
            "action": "set_light_color",
            "payload": {"color": {"r": 255, "g": 59, "b": 48}},
        }
    )

    assert api.status_calls[0]["status"] == "executing"
    assert api.status_calls[-1]["status"] == "completed"
    assert api.status_calls[-1]["result"]["hex"] == "#FF3B30"
    assert api.state_calls[-1]["light_color"] == {"r": 255, "g": 59, "b": 48}


def test_command_runner_reports_failure_result(monkeypatch):
    monkeypatch.setattr(command_runner_module, "in_ring", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(command_runner_module, "append_ring", lambda *_args, **_kwargs: None)

    hw = HardwareAdapter()
    api = FakeApi()
    runner = CommandRunner(hw, api, "/tmp/app_state_test.json")

    runner.execute(
        {
            "cmd_id": "cmd-unsupported",
            "action": "not_real_action",
            "payload": {},
        }
    )

    assert api.status_calls[0]["status"] == "executing"
    assert api.status_calls[-1]["status"] == "failed"
    assert "unsupported action" in (api.status_calls[-1]["error"] or "")
    assert "exception" in (api.status_calls[-1]["result"] or {})


def test_command_runner_self_test_and_identify(monkeypatch):
    monkeypatch.setattr(command_runner_module, "in_ring", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(command_runner_module, "append_ring", lambda *_args, **_kwargs: None)

    hw = HardwareAdapter()
    api = FakeApi()
    runner = CommandRunner(hw, api, "/tmp/app_state_test.json")

    runner.execute(
        {
            "cmd_id": "cmd-self-test",
            "action": "self_test",
            "payload": {"quick": True},
        }
    )
    assert api.status_calls[-1]["status"] == "completed"
    assert isinstance(api.status_calls[-1]["result"], dict)
    assert "ok" in api.status_calls[-1]["result"]

    runner.execute(
        {
            "cmd_id": "cmd-identify",
            "action": "identify_device",
            "payload": {"duration_ms": 800, "color": {"r": 255, "g": 214, "b": 10}},
        }
    )
    assert api.status_calls[-1]["status"] == "completed"
    assert api.status_calls[-1]["result"]["identify"] is True

    runner.execute(
        {
            "cmd_id": "cmd-speaker-validate",
            "action": "speaker_validate",
            "payload": {"track_id": "juggernog", "duration_ms": 600},
        }
    )
    assert api.status_calls[-1]["status"] == "completed"
    assert isinstance(api.status_calls[-1]["result"], dict)
    assert "audio_driver" in api.status_calls[-1]["result"]

    runner.execute(
        {
            "cmd_id": "cmd-button-snapshot",
            "action": "button_snapshot",
            "payload": {},
        }
    )
    assert api.status_calls[-1]["status"] == "completed"
    assert "bindings" in (api.status_calls[-1]["result"] or {})


def test_hardware_button_snapshot_and_runtime_telemetry():
    hw = HardwareAdapter()
    snap = hw.button_snapshot()
    assert isinstance(snap, dict)
    assert isinstance(snap.get("bindings"), list)
    assert "debounce_ms" in snap

    telemetry = hw.runtime_telemetry()
    assert isinstance(telemetry, dict)
    assert "uptime_ms" in telemetry
    assert "button_count" in telemetry


def test_hardware_speaker_validate_returns_structured_result():
    hw = HardwareAdapter()
    result = hw.speaker_validate(track_id="juggernog", duration_ms=500)
    assert isinstance(result, dict)
    assert "audio_driver" in result
    assert "ok" in result
