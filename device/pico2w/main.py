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
        "heartbeat_interval_s": 20,
        "command_poll_interval_s": 1,
        "provision_poll_interval_s": 3,
        "sta_connect_timeout_s": 10,
        "sta_connect_retries": 3,
        "wifi_reset_hold_s": 10,
        "factory_reset_hold_s": 20,
    }


def _handle_reset_event(event, api=None):
    if event == "wifi_reset":
        delete_file(WIFI_PATH)
        if api:
            try:
                api.heartbeat("unknown", "unknown", reset_event="wifi_reset")
            except Exception:
                pass
        _restart()

    if event == "factory_reset":
        delete_file(WIFI_PATH)
        delete_file(TOKEN_PATH)
        if api:
            try:
                api.heartbeat("unknown", "unknown", reset_event="factory_reset")
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
    hw = HardwareAdapter()
    reset_ctl = ResetController(
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
        reset_event = reset_ctl.poll()
        if reset_event:
            if reset_event == "soft_reset":
                hw.reboot()
            else:
                _handle_reset_event(reset_event, api=api if api.device_token else None)

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

            ok = wifi_mgr.connect_sta(
                wifi.get("ssid"),
                wifi.get("password", ""),
                timeout_s=cfg["sta_connect_timeout_s"],
                retries=cfg["sta_connect_retries"],
            )
            state = STATE_BACKEND_PROVISION_OR_RUN if ok else STATE_START_AP_SETUP
            continue

        if state == STATE_START_AP_SETUP:
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
                status, body = api.provision("fw-unknown", "app-unknown")
                if status == 200 and body and body.get("status") == "provisioned":
                    token = body.get("device_token")
                    write_json(TOKEN_PATH, {"device_token": token})
                    api.set_token(token)
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
                status, _ = api.heartbeat("fw-unknown", "app-unknown", rssi=wifi_mgr.rssi())
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


if __name__ == "__main__":
    main()
