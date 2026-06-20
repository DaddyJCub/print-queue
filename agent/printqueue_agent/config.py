"""Agent configuration: loaded from a JSON file with environment-variable overrides."""

from __future__ import annotations

import json
import os
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

    # Loop timing
    poll_interval_s: int = 5
    heartbeat_interval_s: int = 15

    camera: CameraConfig = field(default_factory=CameraConfig)

    @staticmethod
    def load(path: str) -> "AgentConfig":
        data = {}
        if path and os.path.isfile(path):
            with open(path, "r") as fh:
                data = json.load(fh)

        cam_data = data.get("camera", {}) or {}
        cfg = AgentConfig(
            server_url=os.getenv("PQ_SERVER_URL", data.get("server_url", AgentConfig.server_url)),
            agent_id=os.getenv("PQ_AGENT_ID", data.get("agent_id", "")),
            claim_code=os.getenv("PQ_CLAIM_CODE", data.get("claim_code", "")),
            agent_version=data.get("agent_version", AgentConfig.agent_version),
            verify_tls=_as_bool(os.getenv("PQ_VERIFY_TLS"), data.get("verify_tls", True)),
            serial_port=os.getenv("PQ_SERIAL_PORT", data.get("serial_port", "auto")),
            baud_rate=int(os.getenv("PQ_BAUD", data.get("baud_rate", 115200))),
            poll_interval_s=int(data.get("poll_interval_s", 5)),
            heartbeat_interval_s=int(data.get("heartbeat_interval_s", 15)),
            camera=CameraConfig(
                enabled=_as_bool(os.getenv("PQ_CAMERA_ENABLED"), cam_data.get("enabled", False)),
                snapshot_url=os.getenv("PQ_CAMERA_URL", cam_data.get("snapshot_url")),
                device_index=cam_data.get("device_index"),
                interval_s=int(cam_data.get("interval_s", 10)),
            ),
        )
        if not cfg.agent_id or not cfg.claim_code:
            raise ValueError("agent_id and claim_code are required (set them in config.json or env)")
        return cfg


def _as_bool(env_val: Optional[str], default: bool) -> bool:
    if env_val is None:
        return bool(default)
    return env_val.strip().lower() in ("1", "true", "yes", "on")
