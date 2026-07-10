"""Agent configuration: loaded from a JSON file with environment-variable overrides."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CameraConfig:
    enabled: bool = False
    # Either fetch a snapshot from a local URL (e.g. ustreamer/OctoPrint/mjpg-streamer)...
    snapshot_url: Optional[str] = None
    # ...or grab a frame directly from a local capture device (requires opencv-python).
    device_index: Optional[int] = None
    interval_s: int = 10


@dataclass
class LocalUIConfig:
    # ZMOD-style device page served by the agent on the Pi/host LAN.
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 7130
    # Optional API key. Required for slicer upload (Orca/OctoPrint) and for
    # mutating control actions. Empty = open (fine on a trusted home LAN).
    api_key: str = ""
    # Where uploaded G-code is stored on the host before being sent to the SD.
    spool_dir: str = ""
    # End-user-facing title shown on the device page. Blank = a friendly printer
    # model name (e.g. "Longer LK5 Pro") rather than the internal agent id.
    display_name: str = ""


@dataclass
class FirmwareConfig:
    # Printer-firmware flashing is OFF by default — it can brick the board.
    enabled: bool = False
    avrdude_path: str = "avrdude"
    mcu: str = "atmega2560"       # LK5 Pro mainboard
    programmer: str = "wiring"    # Mega2560 bootloader
    baud: int = 115200
    extra_args: list = field(default_factory=list)


@dataclass
class AgentConfig:
    # Server / identity
    server_url: str = "https://print.jcubhub.com"
    agent_id: str = ""
    claim_code: str = ""
    agent_version: str = "1.0.0"
    verify_tls: bool = True

    # Printer / serial
    serial_port: str = "auto"      # "auto" picks the first available port
    baud_rate: int = 115200
    # How prints run:
    #   "sd"     – upload the file to the printer's SD then print from it. The
    #              print survives an agent/host restart, but the upfront SD upload
    #              over serial is slow (~1 KB/s).
    #   "stream" – host-stream the gcode straight to the printer; printing starts
    #              in seconds (no upload), but the agent must stay connected for
    #              the whole print.
    print_mode: str = "sd"

    # Loop timing
    poll_interval_s: int = 5
    heartbeat_interval_s: int = 15
    # Long-poll: hold one connection open for near-instant command/job dispatch
    # instead of polling every poll_interval_s. Falls back to polling if false.
    long_poll: bool = True
    stream_timeout_s: int = 20

    camera: CameraConfig = field(default_factory=CameraConfig)
    firmware: FirmwareConfig = field(default_factory=FirmwareConfig)
    local_ui: LocalUIConfig = field(default_factory=LocalUIConfig)

    @staticmethod
    def load(path: str) -> "AgentConfig":
        data = {}
        if path and os.path.isfile(path):
            with open(path, "r") as fh:
                data = json.load(fh)

        runtime_version = _read_package_version()
        env_version = os.getenv("PQ_AGENT_VERSION")
        file_version = data.get("agent_version")
        if env_version:
            resolved_version = env_version
        elif file_version and not (str(file_version).strip() == "1.0.0" and runtime_version != "1.0.0"):
            resolved_version = str(file_version)
        else:
            resolved_version = runtime_version

        cam_data = data.get("camera", {}) or {}
        fw_data = data.get("firmware", {}) or {}
        ui_data = data.get("local_ui", {}) or {}
        cfg = AgentConfig(
            server_url=os.getenv("PQ_SERVER_URL", data.get("server_url", AgentConfig.server_url)),
            agent_id=os.getenv("PQ_AGENT_ID", data.get("agent_id", "")),
            claim_code=os.getenv("PQ_CLAIM_CODE", data.get("claim_code", "")),
            agent_version=resolved_version,
            verify_tls=_as_bool(os.getenv("PQ_VERIFY_TLS"), data.get("verify_tls", True)),
            serial_port=os.getenv("PQ_SERIAL_PORT", data.get("serial_port", "auto")),
            baud_rate=int(os.getenv("PQ_BAUD", data.get("baud_rate", 115200))),
            print_mode=(os.getenv("PQ_PRINT_MODE", data.get("print_mode", "sd")) or "sd").strip().lower(),
            poll_interval_s=int(data.get("poll_interval_s", 5)),
            heartbeat_interval_s=int(data.get("heartbeat_interval_s", 15)),
            long_poll=_as_bool(os.getenv("PQ_LONG_POLL"), data.get("long_poll", True)),
            stream_timeout_s=int(data.get("stream_timeout_s", 20)),
            camera=CameraConfig(
                enabled=_as_bool(os.getenv("PQ_CAMERA_ENABLED"), cam_data.get("enabled", False)),
                snapshot_url=os.getenv("PQ_CAMERA_URL", cam_data.get("snapshot_url")),
                device_index=cam_data.get("device_index"),
                interval_s=int(cam_data.get("interval_s", 10)),
            ),
            firmware=FirmwareConfig(
                enabled=_as_bool(os.getenv("PQ_FIRMWARE_ENABLED"), fw_data.get("enabled", False)),
                avrdude_path=fw_data.get("avrdude_path", "avrdude"),
                mcu=fw_data.get("mcu", "atmega2560"),
                programmer=fw_data.get("programmer", "wiring"),
                baud=int(fw_data.get("baud", 115200)),
                extra_args=list(fw_data.get("extra_args", [])),
            ),
            local_ui=LocalUIConfig(
                enabled=_as_bool(os.getenv("PQ_LOCAL_UI_ENABLED"), ui_data.get("enabled", True)),
                host=ui_data.get("host", "0.0.0.0"),
                port=int(os.getenv("PQ_LOCAL_UI_PORT", ui_data.get("port", 7130))),
                api_key=os.getenv("PQ_LOCAL_UI_API_KEY", ui_data.get("api_key", "")),
                spool_dir=ui_data.get("spool_dir", ""),
                display_name=ui_data.get("display_name", ""),
            ),
        )
        if not cfg.agent_id or not cfg.claim_code:
            raise ValueError("agent_id and claim_code are required (set them in config.json or env)")
        return cfg


def _as_bool(env_val: Optional[str], default: bool) -> bool:
    if env_val is None:
        return bool(default)
    return env_val.strip().lower() in ("1", "true", "yes", "on")


def _read_package_version() -> str:
    try:
        init_py = os.path.join(os.path.dirname(__file__), "__init__.py")
        with open(init_py, "r", encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", text)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return AgentConfig.agent_version
