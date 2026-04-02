import time

try:
    import machine
except Exception:
    machine = None

from lib.file_store import read_json, write_json, delete_file
from lib.wifi_manager import WifiManager
from lib.setup_portal import run_setup_server
from lib.api_client import ApiClient
from lib.hardware import HardwareAdapter
from lib.command_runner import CommandRunner
from lib.ota_manager import OtaManager
from lib.reset_controller import ResetController
try:
    from lib.versioning import get_reported_versions
except Exception:
    # Legacy fallback for partial/manual updates where versioning module is absent.
    def get_reported_versions(cfg, _state):
        cfg = cfg or {}
        fw = str(cfg.get("fw_version") or "fw-0.0.0").strip() or "fw-0.0.0"
        app = str(cfg.get("app_version") or "app-0.0.0").strip() or "app-0.0.0"
        return fw, app


STATE_BOOT = "BOOT"
STATE_TRY_STA_CONNECT = "TRY_STA_CONNECT"
STATE_START_AP_SETUP = "START_AP_SETUP"
STATE_BACKEND_PROVISION_OR_RUN = "BACKEND_PROVISION_OR_RUN"
STATE_NORMAL_RUN = "NORMAL_RUN"

DEVICE_PATH = "/device.json"
WIFI_PATH = "/wifi.json"
TOKEN_PATH = "/token.json"
APP_STATE_PATH = "/app_state.json"
CONFIG_PATH = "/config.json"


def _restart():
    if machine:
        machine.reset()
    raise SystemExit


def _default_cfg():
    return {
        "api_base": "https://print.jcubhub.com",
        "fw_version": "fw-1.0.0",
        "app_version": "1.0.0",
        "heartbeat_interval_s": 20,
        "command_poll_interval_s": 1,
        "command_stream_enabled": True,
        "command_stream_timeout_s": 8,
        "provision_poll_interval_s": 3,
        "sta_connect_timeout_s": 10,
        "sta_connect_retries": 3,
        "reset_pin": None,
        "wifi_reset_hold_s": 10,
        "factory_reset_hold_s": 20,
    }


def _reported_versions(cfg):
    state = read_json(APP_STATE_PATH, default={}) or {}
    return get_reported_versions(cfg, state)


def _handle_reset_event(event, api=None, fw_version=None, app_version=None):
    fw = fw_version or "fw-0.0.0"
    app = app_version or "app-0.0.0"
    if event == "wifi_reset":
        delete_file(WIFI_PATH)
        if api:
            try:
                api.heartbeat(fw, app, reset_event="wifi_reset")
            except Exception:
                pass
        _restart()

    if event == "factory_reset":
        delete_file(WIFI_PATH)
        delete_file(TOKEN_PATH)
        if api:
            try:
                api.heartbeat(fw, app, reset_event="factory_reset")
            except Exception:
                pass
        _restart()


def main():
    cfg = _default_cfg()
    cfg.update(read_json(CONFIG_PATH, default={}) or {})

    device = read_json(DEVICE_PATH, default=None)
    if not device:
        raise Exception("Missing /device.json")

    device_id = device.get("device_id")
    claim_code = device.get("claim_code")
    if not device_id or not claim_code:
        raise Exception("Invalid /device.json")

    wifi = read_json(WIFI_PATH, default={}) or {}
    token_json = read_json(TOKEN_PATH, default={}) or {}

    wifi_mgr = WifiManager()
    hw = HardwareAdapter(cfg=cfg)
    # Boot cue: blue pulses.
    hw.flash_status({"r": 0, "g": 0, "b": 100}, count=2, interval_ms=180)
    reset_ctl = ResetController(
        pin_num=cfg.get("reset_pin", 15),
        wifi_hold_s=cfg["wifi_reset_hold_s"],
        factory_hold_s=cfg["factory_reset_hold_s"],
    )

    api = ApiClient(cfg["api_base"], device_id, claim_code)
    if token_json.get("device_token"):
        api.set_token(token_json["device_token"])

    ota_mgr = OtaManager(api, APP_STATE_PATH)
    try:
        ota_mgr.boot_guard()
    except Exception:
        pass
    cmd_runner = CommandRunner(hw, api, APP_STATE_PATH, ota_manager=ota_mgr)

    state = STATE_BOOT
    last_heartbeat = 0
    last_poll = 0

    while True:
        fw_version, app_version = _reported_versions(cfg)
        reset_event = reset_ctl.poll()
        if reset_event:
            if reset_event == "soft_reset":
                hw.reboot()
            else:
                _handle_reset_event(
                    reset_event,
                    api=api if api.device_token else None,
                    fw_version=fw_version,
                    app_version=app_version,
                )

        hw.set_led_phase(reset_ctl.led_phase())

        if state == STATE_BOOT:
            wifi = read_json(WIFI_PATH, default={}) or {}
            token_json = read_json(TOKEN_PATH, default={}) or {}
            if token_json.get("device_token"):
                api.set_token(token_json["device_token"])
            state = STATE_TRY_STA_CONNECT
            continue

        if state == STATE_TRY_STA_CONNECT:
            if not wifi.get("ssid"):
                state = STATE_START_AP_SETUP
                continue

            # Wi-Fi connect in progress: amber pulses.
            hw.flash_status({"r": 100, "g": 100, "b": 0}, count=2, interval_ms=180)
            ok = wifi_mgr.connect_sta(
                wifi.get("ssid"),
                wifi.get("password", ""),
                timeout_s=cfg["sta_connect_timeout_s"],
                retries=cfg["sta_connect_retries"],
            )
            if ok:
                # Connected: green confirmation.
                hw.flash_status({"r": 0, "g": 100, "b": 0}, count=2, interval_ms=120)
            else:
                # Failed connect: red warning.
                hw.flash_status({"r": 160, "g": 0, "b": 0}, count=2, interval_ms=120)
            state = STATE_BACKEND_PROVISION_OR_RUN if ok else STATE_START_AP_SETUP
            continue

        if state == STATE_START_AP_SETUP:
            # AP setup mode: purple cue.
            hw.flash_status({"r": 128, "g": 0, "b": 128}, count=2, interval_ms=180)
            ssid = "PRINTELLECT-SETUP-%s" % str(device_id)[-4:].upper()
            wifi_mgr.start_ap(ssid)
            saved = run_setup_server(device, wifi_path=WIFI_PATH)
            if saved:
                _restart()
            time.sleep(1)
            continue

        if state == STATE_BACKEND_PROVISION_OR_RUN:
            if not wifi_mgr.is_connected():
                state = STATE_TRY_STA_CONNECT
                continue

            token = read_json(TOKEN_PATH, default={}).get("device_token")
            if not token:
                # Provisioning poll: cyan pulse.
                hw.flash_status({"r": 0, "g": 100, "b": 100}, count=1, interval_ms=140)
                status, body = api.provision(fw_version, app_version)
                if status == 200 and body and body.get("status") == "provisioned":
                    token = body.get("device_token")
                    write_json(TOKEN_PATH, {"device_token": token})
                    api.set_token(token)
                    hw.flash_status({"r": 0, "g": 120, "b": 0}, count=2, interval_ms=100)
                else:
                    time.sleep(cfg["provision_poll_interval_s"])
                    continue

            state = STATE_NORMAL_RUN
            last_heartbeat = 0
            last_poll = 0
            continue

        if state == STATE_NORMAL_RUN:
            if not wifi_mgr.is_connected():
                state = STATE_TRY_STA_CONNECT
                continue

            now = time.time()

            # Confirm staged OTA once a bearer-authenticated loop is healthy.
            try:
                ota_mgr.confirm_pending_boot()
            except Exception:
                pass

            if now - last_heartbeat >= cfg["heartbeat_interval_s"]:
                status, _ = api.heartbeat(fw_version, app_version, rssi=wifi_mgr.rssi())
                if status == 401:
                    delete_file(TOKEN_PATH)
                    api.set_token(None)
                    state = STATE_BACKEND_PROVISION_OR_RUN
                    continue
                last_heartbeat = now

            local_state = hw.check_local_button_actions()
            if local_state:
                try:
                    api.state_update(hw.get_state())
                except Exception:
                    pass

            if now - last_poll >= cfg["command_poll_interval_s"]:
                status = 204
                body = None
                stream_enabled = cfg.get("command_stream_enabled", True) and hasattr(api, "command_stream")
                if stream_enabled:
                    status, body = api.command_stream(timeout_s=cfg.get("command_stream_timeout_s", 8))
                    # Fallback to polling if stream endpoint is unavailable.
                    if status in (404, 405, 500):
                        status, body = api.next_command()
                else:
                    status, body = api.next_command()
                if status == 401:
                    delete_file(TOKEN_PATH)
                    api.set_token(None)
                    state = STATE_BACKEND_PROVISION_OR_RUN
                    continue
                if status == 200 and body:
                    cmd_runner.execute(body)
                last_poll = now

            time.sleep(0.05)
            continue


def run():
    """Legacy entrypoint used by root /main.py shim on existing field devices."""
    main()


if __name__ == "__main__":
    main()
