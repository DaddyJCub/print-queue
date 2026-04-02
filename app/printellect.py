import asyncio
import json
import io
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.auth import get_current_account, get_current_admin, is_feature_enabled, require_account, require_admin
from app.printellect_service import (
    claim_hash,
    generate_device_token,
    rotate_and_issue_device_token,
    token_hash,
    verify_claim_code,
)

router = APIRouter(tags=["printellect"])
logger = logging.getLogger("printellect.devices")
templates = Jinja2Templates(directory="app/templates")

# Credits nav global (callable, evaluated at render time)
def _credits_nav_enabled():
    try:
        return is_feature_enabled("store_rewards")
    except Exception:
        return False
templates.env.globals["credits_nav_enabled"] = _credits_nav_enabled

def _dashboard_nav_enabled():
    try:
        from app.auth import get_feature_flag
        flag = get_feature_flag("dashboard_home")
        return flag.enabled if flag else False
    except Exception:
        return False
templates.env.globals["dashboard_nav_enabled"] = _dashboard_nav_enabled

def _new_request_url():
    try:
        from app.auth import get_feature_flag
        flag = get_feature_flag("dashboard_home")
        return "/new-request" if (flag and flag.enabled) else "/"
    except Exception:
        return "/"
templates.env.globals["new_request_url"] = _new_request_url

ONLINE_WINDOW_SECONDS = int(os.getenv("DEVICE_ONLINE_WINDOW_SECONDS", "60"))
DEVICE_MIN_POLL_SECONDS = float(os.getenv("DEVICE_MIN_POLL_SECONDS", "1.0"))
PROVISION_POLL_INTERVAL_MS = int(os.getenv("DEVICE_PROVISION_POLL_MS", "1000"))
RELEASES_DIR = os.getenv("RELEASES_DIR", os.path.join("local_data", "releases"))
DEVICE_SOURCE_DIR = os.getenv("DEVICE_SOURCE_DIR", os.path.join("device", "pico2w"))
PAIRING_SESSION_MINUTES = int(os.getenv("PAIRING_SESSION_MINUTES", "10"))
DEVICE_STREAM_MAX_SECONDS = int(os.getenv("DEVICE_STREAM_MAX_SECONDS", "25"))
DEVICE_STREAM_POLL_STEP_SECONDS = max(0.05, float(os.getenv("DEVICE_STREAM_POLL_STEP_SECONDS", "0.25")))
PRINTELLECT_FEATURE_KEY = os.getenv("PRINTELLECT_FEATURE_KEY", "printellect_device_control")
PRINTELLECT_DEMO_OPEN_ACCESS = os.getenv(
    "PRINTELLECT_DEMO_OPEN_ACCESS",
    "0",
).lower() in ("true", "1", "yes", "on")

_poll_lock = threading.Lock()
_last_poll_at: Dict[str, float] = {}
_claim_fail_lock = threading.Lock()
_claim_failures: Dict[str, list[float]] = {}
MAX_CLAIM_FAILURES = int(os.getenv("PRINTELLECT_MAX_CLAIM_FAILURES", "8"))
CLAIM_FAIL_WINDOW_SECONDS = int(os.getenv("PRINTELLECT_CLAIM_FAIL_WINDOW_S", "300"))
PRINTELLECT_PAIR_BASE_URL = os.getenv("PRINTELLECT_PAIR_BASE_URL", "https://print.jcubhub.com").rstrip("/")

LIGHT_EFFECT_VALUES = {
    "solid",
    "pulse",
    "rainbow",
    "strobe",
    "ambient",
    "chase",
    "off",
}


class LightColorActionBody(BaseModel):
    color: Optional[Any] = Field(
        default=None,
        description="Hex (#RRGGBB) or RGB object ({r,g,b})",
    )
    r: Optional[int] = Field(default=None, ge=0, le=255)
    g: Optional[int] = Field(default=None, ge=0, le=255)
    b: Optional[int] = Field(default=None, ge=0, le=255)


class LightEffectActionBody(BaseModel):
    effect: str = Field(..., description="Effect name, e.g. pulse, rainbow, solid")
    duration_ms: Optional[int] = Field(default=None, gt=0)
    speed_ms: Optional[int] = Field(default=None, ge=50, le=10000)
    color: Optional[Any] = Field(
        default=None,
        description="Optional effect color as #RRGGBB or {r,g,b}",
    )
    r: Optional[int] = Field(default=None, ge=0, le=255)
    g: Optional[int] = Field(default=None, ge=0, le=255)
    b: Optional[int] = Field(default=None, ge=0, le=255)


class TestLightsActionBody(BaseModel):
    pattern: Optional[str] = None
    effect: Optional[str] = None
    duration_ms: int = Field(..., gt=0)
    speed_ms: Optional[int] = Field(default=None, ge=50, le=10000)
    color: Optional[Any] = Field(
        default=None,
        description="Optional test color as #RRGGBB or {r,g,b}",
    )
    r: Optional[int] = Field(default=None, ge=0, le=255)
    g: Optional[int] = Field(default=None, ge=0, le=255)
    b: Optional[int] = Field(default=None, ge=0, le=255)


class SpeakerValidateActionBody(BaseModel):
    track_id: Optional[str] = Field(default=None, description="Optional track id to validate speaker playback")
    duration_ms: Optional[int] = Field(default=None, ge=200, le=5000)


class DeviceCommandStatusBody(BaseModel):
    status: str = Field(..., description="executing | completed | failed")
    error: Optional[str] = Field(default=None, description="Failure message when status=failed")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Optional command execution details")


class DeviceUpdateStatusBody(BaseModel):
    status: str = Field(..., description="idle | available | downloading | applying | success | rollback | failed")
    progress: Optional[int] = Field(default=0, ge=0, le=100)
    version: Optional[str] = Field(default=None, description="Reported app version for this update status")
    target_version: Optional[str] = Field(default=None, description="Alias of version")
    error: Optional[str] = Field(default=None, description="Failure detail")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Optional structured update diagnostics")


class DeviceBootOkBody(BaseModel):
    version: Optional[str] = Field(default=None, description="Booted app version")


class ApiOkResponse(BaseModel):
    ok: bool = True


class ActionEnqueueResponse(ApiOkResponse):
    cmd_id: str
    action: str
    payload: Dict[str, Any]


class DeviceCommandResponse(BaseModel):
    cmd_id: str
    action: str
    payload: Dict[str, Any]
    created_at: str


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("DB_PATH", "/data/app.db"), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=False)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_version_text(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _mark_update_version_mismatch(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    expected_version: str,
    reported_version: Optional[str],
    source: str,
) -> str:
    msg = (
        "version mismatch (%s): expected=%s reported=%s"
        % (source, expected_version, reported_version or "missing")
    )
    ts = now_iso()
    mismatch_result = {
        "source": source,
        "expected_version": expected_version,
        "reported_version": reported_version,
        "kind": "version_mismatch",
    }
    conn.execute(
        """
        INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, last_result_json, updated_at)
        VALUES (?, ?, 'failed', 100, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            target_version = excluded.target_version,
            status = 'failed',
            progress = 100,
            last_error = excluded.last_error,
            last_result_json = excluded.last_result_json,
            updated_at = excluded.updated_at
        """,
        (device_id, expected_version, msg, _json_dumps(mismatch_result), ts),
    )
    return msg


def _claim_hash(claim_code: str) -> str:
    return claim_hash(claim_code)


def _verify_claim(claim_code: str, stored_hash: Optional[str]) -> bool:
    return verify_claim_code(claim_code, stored_hash)


def _token_hash(token: str) -> str:
    return token_hash(token)


def _hash_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _hash_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _build_pairing_urls(device_id: str, claim_code: str, name: str = "") -> Dict[str, str]:
    # Keep QR payload compact for sticker-size printing and better camera reliability.
    params: Dict[str, str] = {"d": device_id, "c": claim_code}
    if name:
        params["n"] = name
    query = urlencode(params)
    return {
        "qr_payload": f"printellect://pair?{query}",
        "fallback_url": f"{PRINTELLECT_PAIR_BASE_URL}/pair?{query}",
    }


def _build_device_json(device_id: str, claim_code: str, hw_model: str = "pico2w") -> Dict[str, str]:
    return {
        "device_id": device_id,
        "claim_code": claim_code,
        "hw_model": hw_model,
    }


def _qr_svg(payload: str) -> str:
    if not payload or len(payload) > 1024:
        raise HTTPException(status_code=422, detail="Invalid QR payload")
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except Exception as exc:
        raise HTTPException(status_code=503, detail="QR generator unavailable") from exc
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=8,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    data = image.to_string()
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return str(data)


def _is_online(last_seen_at: Optional[str]) -> bool:
    ts = _parse_iso(last_seen_at)
    if not ts:
        return False
    return (datetime.now(ts.tzinfo) - ts) <= timedelta(seconds=ONLINE_WINDOW_SECONDS)


def _heartbeat_warnings(heartbeat: Dict[str, Any]) -> list[Dict[str, Any]]:
    warnings: list[Dict[str, Any]] = []
    telemetry = heartbeat.get("telemetry") if isinstance(heartbeat, dict) else None
    if not isinstance(telemetry, dict):
        return warnings

    temp = telemetry.get("internal_temp_c")
    if isinstance(temp, (int, float)) and temp >= 70:
        warnings.append({"code": "temp_high", "level": "warn", "message": f"High internal temp ({temp:.1f}C)"})

    vsys = telemetry.get("vsys_v")
    if isinstance(vsys, (int, float)):
        if vsys < 4.60:
            warnings.append({"code": "voltage_low", "level": "warn", "message": f"Low VSYS ({vsys:.2f}V)"})
        elif vsys > 5.40:
            warnings.append({"code": "voltage_high", "level": "warn", "message": f"High VSYS ({vsys:.2f}V)"})

    mem_free = telemetry.get("mem_free_bytes")
    if isinstance(mem_free, int) and mem_free < 20_000:
        warnings.append({"code": "mem_low", "level": "warn", "message": f"Low free memory ({mem_free} bytes)"})

    return warnings


def _safe_release_join(base: Path, rel_path: str) -> Path:
    candidate = (base / rel_path).resolve()
    base_resolved = base.resolve()
    if base_resolved == candidate or base_resolved in candidate.parents:
        return candidate
    raise HTTPException(status_code=400, detail="Invalid release path")


def _rgb_to_hex(rgb: Dict[str, int]) -> str:
    return "#{:02X}{:02X}{:02X}".format(rgb["r"], rgb["g"], rgb["b"])


def _parse_rgb_obj(value: Any, field_name: str = "color") -> Dict[str, int]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail=f"{field_name} must be #RRGGBB or object with r,g,b")
    rgb: Dict[str, int] = {}
    for key in ("r", "g", "b"):
        channel = value.get(key)
        if not isinstance(channel, int) or channel < 0 or channel > 255:
            raise HTTPException(status_code=422, detail=f"{field_name}.{key} must be integer 0-255")
        rgb[key] = channel
    return rgb


def _parse_hex_color(value: str, field_name: str = "color") -> Dict[str, int]:
    text = value.strip()
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", text):
        raise HTTPException(status_code=422, detail=f"{field_name} must be #RRGGBB")
    return {
        "r": int(text[1:3], 16),
        "g": int(text[3:5], 16),
        "b": int(text[5:7], 16),
    }


def _normalize_rgb_from_payload(
    payload: Dict[str, Any],
    *,
    required: bool,
    field_name: str = "color",
) -> Optional[Dict[str, int]]:
    color = payload.get(field_name)
    if color is None and all(ch in payload for ch in ("r", "g", "b")):
        color = {"r": payload.get("r"), "g": payload.get("g"), "b": payload.get("b")}

    if color is None:
        if required:
            raise HTTPException(status_code=422, detail=f"{field_name} is required")
        return None

    if isinstance(color, str):
        return _parse_hex_color(color, field_name=field_name)
    if isinstance(color, dict):
        return _parse_rgb_obj(color, field_name=field_name)
    raise HTTPException(status_code=422, detail=f"{field_name} must be #RRGGBB or object with r,g,b")


def _audit(
    conn: sqlite3.Connection,
    action: str,
    actor_type: str,
    actor_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        conn.execute(
            """
            INSERT INTO audit_log (id, created_at, action, actor_type, actor_id, actor_name, actor_ip, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                now_iso(),
                action,
                actor_type,
                actor_id,
                target_type,
                target_id,
                _json_dumps(details or {}),
            ),
        )
    except Exception as exc:
        logger.warning("audit write failed: %s", exc)


def _claim_fail_key(request: Request, device_id: str, claim_code: str) -> str:
    claim_fp = _claim_hash(claim_code)[:24] if claim_code else "none"
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{device_id}:{claim_fp}"


def _record_claim_failure(request: Request, device_id: str, claim_code: str) -> bool:
    now = time.time()
    key = _claim_fail_key(request, device_id, claim_code)
    window_start = now - CLAIM_FAIL_WINDOW_SECONDS
    with _claim_fail_lock:
        attempts = _claim_failures.get(key, [])
        attempts = [t for t in attempts if t >= window_start]
        attempts.append(now)
        _claim_failures[key] = attempts
        return len(attempts) >= MAX_CLAIM_FAILURES


def _clear_claim_failures(request: Request, device_id: str, claim_code: str) -> None:
    key = _claim_fail_key(request, device_id, claim_code)
    with _claim_fail_lock:
        _claim_failures.pop(key, None)


def init_printellect_tables(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            name TEXT,
            owner_user_id TEXT,
            claim_code_hash TEXT,
            created_at TEXT NOT NULL,
            claimed_at TEXT,
            last_provisioned_at TEXT,
            last_seen_at TEXT,
            fw_version TEXT,
            app_version TEXT,
            rssi INTEGER,
            heartbeat_json TEXT,
            notes TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_tokens (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(device_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pairing_sessions (
            session_id TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            claimed_device_id TEXT,
            claimed_at TEXT,
            status TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS commands (
            cmd_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            action TEXT NOT NULL,
            payload_json TEXT,
            result_json TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            requested_by_user_id TEXT,
            delivered_at TEXT,
            executing_at TEXT,
            completed_at TEXT,
            error TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(device_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_state (
            device_id TEXT PRIMARY KEY,
            state_json TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(device_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS releases (
            version TEXT PRIMARY KEY,
            channel TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by_user_id TEXT,
            notes TEXT,
            manifest_json TEXT,
            bundle_path TEXT,
            is_current INTEGER DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_update_status (
            device_id TEXT PRIMARY KEY,
            target_version TEXT,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            last_result_json TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(device_id)
        )
        """
    )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_lookup ON device_tokens(token_hash, revoked_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_device ON device_tokens(device_id, revoked_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_queue ON commands(device_id, status, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pairing_sessions_owner ON pairing_sessions(owner_user_id, status, expires_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_releases_channel_current ON releases(channel, is_current)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_update_status ON device_update_status(status, updated_at)")


def ensure_printellect_migrations(cur: sqlite3.Cursor) -> None:
    cur.execute("PRAGMA table_info(devices)")
    cols = {row[1] for row in cur.fetchall()}
    if cols:
        if "claimed_at" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN claimed_at TEXT")
        if "last_provisioned_at" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN last_provisioned_at TEXT")
        if "heartbeat_json" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN heartbeat_json TEXT")

    cur.execute("PRAGMA table_info(commands)")
    command_cols = {row[1] for row in cur.fetchall()}
    if command_cols and "result_json" not in command_cols:
        cur.execute("ALTER TABLE commands ADD COLUMN result_json TEXT")

    cur.execute("PRAGMA table_info(device_update_status)")
    update_cols = {row[1] for row in cur.fetchall()}
    if update_cols and "last_result_json" not in update_cols:
        cur.execute("ALTER TABLE device_update_status ADD COLUMN last_result_json TEXT")


def _get_device_for_owner(conn: sqlite3.Connection, device_id: str, owner_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    if row["owner_user_id"] != owner_id:
        raise HTTPException(status_code=403, detail="Not allowed for this device")
    return row


def _admin_device_payload(row: sqlite3.Row) -> Dict[str, Any]:
    heartbeat = _json_loads(row["heartbeat_json"], {}) if "heartbeat_json" in row.keys() else {}
    return {
        "device_id": row["device_id"],
        "name": row["name"],
        "owner_user_id": row["owner_user_id"],
        "claimed": bool(row["owner_user_id"]),
        "created_at": row["created_at"],
        "claimed_at": row["claimed_at"] if "claimed_at" in row.keys() else None,
        "last_seen_at": row["last_seen_at"],
        "online": _is_online(row["last_seen_at"]),
        "fw_version": row["fw_version"],
        "app_version": row["app_version"],
        "rssi": row["rssi"],
        "heartbeat": heartbeat,
        "telemetry_warnings": _heartbeat_warnings(heartbeat),
        "notes": row["notes"] if "notes" in row.keys() else None,
        "state": _json_loads(row["state_json"], {}) if "state_json" in row.keys() else {},
        "update": {
            "status": (row["update_status"] if "update_status" in row.keys() else None) or "idle",
            "target_version": row["target_version"] if "target_version" in row.keys() else None,
            "progress": row["progress"] if ("progress" in row.keys() and row["progress"] is not None) else 0,
            "last_error": row["last_error"] if "last_error" in row.keys() else None,
            "result": _json_loads(row["last_result_json"], {}) if "last_result_json" in row.keys() else {},
        },
    }


def _validate_action_payload(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if action == "play_perk":
        perk = payload.get("perk")
        if not isinstance(perk, str) or not perk.strip():
            raise HTTPException(status_code=422, detail="perk is required")
        return {"perk_id": perk.strip()}

    if action == "set_idle":
        mode = payload.get("mode")
        if not isinstance(mode, str) or not mode.strip():
            raise HTTPException(status_code=422, detail="mode is required")
        return {"mode": mode.strip()}

    if action == "set_brightness":
        level = payload.get("level")
        if not isinstance(level, int) or level < 0 or level > 100:
            raise HTTPException(status_code=422, detail="level must be integer 0-100")
        return {"level": level}

    if action == "set_volume":
        level = payload.get("level")
        if not isinstance(level, int) or level < 0 or level > 30:
            raise HTTPException(status_code=422, detail="level must be integer 0-30")
        return {"level": level}

    if action == "test_lights":
        pattern = payload.get("effect") or payload.get("pattern")
        duration_ms = payload.get("duration_ms")
        if not isinstance(pattern, str) or not pattern.strip():
            raise HTTPException(status_code=422, detail="pattern or effect is required")
        if not isinstance(duration_ms, int) or duration_ms <= 0:
            raise HTTPException(status_code=422, detail="duration_ms must be a positive integer")
        cleaned: Dict[str, Any] = {
            "pattern": pattern.strip(),
            "effect": pattern.strip(),
            "duration_ms": duration_ms,
        }
        speed_ms = payload.get("speed_ms")
        if speed_ms is not None:
            if not isinstance(speed_ms, int) or speed_ms < 50 or speed_ms > 10000:
                raise HTTPException(status_code=422, detail="speed_ms must be integer 50-10000")
            cleaned["speed_ms"] = speed_ms
        color = _normalize_rgb_from_payload(payload, required=False, field_name="color")
        if color is not None:
            cleaned["color"] = color
            cleaned["hex"] = _rgb_to_hex(color)
        return cleaned

    if action == "test_audio":
        track_id = payload.get("track_id")
        if not isinstance(track_id, str) or not track_id.strip():
            raise HTTPException(status_code=422, detail="track_id is required")
        return {"track_id": track_id.strip()}

    if action == "speaker_validate":
        cleaned: Dict[str, Any] = {}
        track_id = payload.get("track_id")
        if track_id is not None:
            if not isinstance(track_id, str) or not track_id.strip():
                raise HTTPException(status_code=422, detail="track_id must be a non-empty string")
            cleaned["track_id"] = track_id.strip()
        duration_ms = payload.get("duration_ms")
        if duration_ms is not None:
            if not isinstance(duration_ms, int) or duration_ms < 200 or duration_ms > 5000:
                raise HTTPException(status_code=422, detail="duration_ms must be integer 200-5000")
            cleaned["duration_ms"] = duration_ms
        return cleaned

    if action == "self_test":
        quick = payload.get("quick", True)
        if not isinstance(quick, bool):
            raise HTTPException(status_code=422, detail="quick must be boolean")
        return {"quick": quick}

    if action == "button_snapshot":
        return {}

    if action == "identify_device":
        cleaned: Dict[str, Any] = {}
        duration_ms = payload.get("duration_ms")
        if duration_ms is not None:
            if not isinstance(duration_ms, int) or duration_ms < 200 or duration_ms > 15000:
                raise HTTPException(status_code=422, detail="duration_ms must be integer 200-15000")
            cleaned["duration_ms"] = duration_ms
        color = _normalize_rgb_from_payload(payload, required=False, field_name="color")
        if color is not None:
            cleaned["color"] = color
            cleaned["hex"] = _rgb_to_hex(color)
        return cleaned

    if action == "set_light_color":
        color = _normalize_rgb_from_payload(payload, required=True, field_name="color")
        return {"color": color, "hex": _rgb_to_hex(color)}

    if action == "set_light_effect":
        effect = payload.get("effect")
        if not isinstance(effect, str) or not effect.strip():
            raise HTTPException(status_code=422, detail="effect is required")
        effect_clean = effect.strip().lower()
        if effect_clean not in LIGHT_EFFECT_VALUES:
            raise HTTPException(
                status_code=422,
                detail=f"effect must be one of: {', '.join(sorted(LIGHT_EFFECT_VALUES))}",
            )
        cleaned = {"effect": effect_clean}
        duration_ms = payload.get("duration_ms")
        if duration_ms is not None:
            if not isinstance(duration_ms, int) or duration_ms <= 0:
                raise HTTPException(status_code=422, detail="duration_ms must be a positive integer")
            cleaned["duration_ms"] = duration_ms
        speed_ms = payload.get("speed_ms")
        if speed_ms is not None:
            if not isinstance(speed_ms, int) or speed_ms < 50 or speed_ms > 10000:
                raise HTTPException(status_code=422, detail="speed_ms must be integer 50-10000")
            cleaned["speed_ms"] = speed_ms
        color = _normalize_rgb_from_payload(payload, required=False, field_name="color")
        if color is not None:
            cleaned["color"] = color
            cleaned["hex"] = _rgb_to_hex(color)
        return cleaned

    if action == "ota_apply":
        version = payload.get("version")
        if not isinstance(version, str) or not version.strip():
            raise HTTPException(status_code=422, detail="version is required")
        return {"version": version.strip()}

    if action == "notify_shipping":
        status = payload.get("status", "in_transit")
        allowed = ("in_transit", "out_for_delivery", "delivered", "exception")
        if status not in allowed:
            status = "in_transit"
        return {"status": status}

    return {}


def notify_device_shipping_status(requester_email: str, shipping_status: str):
    """Queue a shipping LED notification to all devices owned by the requester.

    Called by the tracking poller when a shipment status changes.
    Maps shipping_status to a simplified LED status and enqueues a command.
    """
    status_map = {
        "IN_TRANSIT": "in_transit",
        "OUT_FOR_DELIVERY": "out_for_delivery",
        "DELIVERED": "delivered",
        "EXCEPTION": "exception",
        "RETURNED": "exception",
    }
    led_status = status_map.get(shipping_status)
    if not led_status:
        return  # No LED notification for this status

    conn = None
    try:
        conn = sqlite3.connect(os.getenv("DB_PATH", "/data/app.db"), timeout=1)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 1000")
        # Resolve account from canonical accounts table.
        acct = conn.execute(
            "SELECT id FROM accounts WHERE LOWER(email) = LOWER(?)",
            (requester_email,),
        ).fetchone()
        if not acct:
            conn.close()
            return

        # Queue notifications for all claimed devices owned by the account.
        devices = conn.execute(
            "SELECT * FROM devices WHERE owner_user_id = ?",
            (acct["id"],),
        ).fetchall()

        for device in devices:
            try:
                _enqueue_command(
                    conn,
                    device,
                    requested_by_user_id=acct["id"],
                    action="notify_shipping",
                    payload={"status": led_status},
                    require_online=False,
                )
            except Exception:
                pass  # Device might have gone offline

        conn.commit()
    except Exception:
        # Don't let device notification failures break shipping flow.
        logger.debug("shipping device notification skipped due to error", exc_info=True)
    finally:
        if conn is not None:
            conn.close()


def _enqueue_command(
    conn: sqlite3.Connection,
    device_row: sqlite3.Row,
    requested_by_user_id: str,
    action: str,
    payload: Dict[str, Any],
    *,
    require_online: bool = True,
) -> str:
    if require_online and not _is_online(device_row["last_seen_at"]):
        raise HTTPException(status_code=409, detail="Device is offline")

    if action == "play_perk":
        state_row = conn.execute(
            "SELECT state_json FROM device_state WHERE device_id = ?",
            (device_row["device_id"],),
        ).fetchone()
        state = _json_loads(state_row["state_json"] if state_row else None, {})
        if bool(state.get("playing")):
            raise HTTPException(status_code=409, detail="Device is already playing")

    cmd_id = str(uuid.uuid4())
    ts = now_iso()
    conn.execute(
        """
        INSERT INTO commands
            (cmd_id, device_id, action, payload_json, result_json, status, created_at, updated_at, requested_by_user_id)
        VALUES (?, ?, ?, ?, NULL, 'queued', ?, ?, ?)
        """,
        (cmd_id, device_row["device_id"], action, _json_dumps(payload), ts, ts, requested_by_user_id),
    )

    _audit(
        conn,
        action="printellect_command_enqueued",
        actor_type="user",
        actor_id=requested_by_user_id,
        target_type="device",
        target_id=device_row["device_id"],
        details={"cmd_id": cmd_id, "action": action, "payload": payload},
    )

    return cmd_id


def _release_paths(version: str) -> Dict[str, Path]:
    root = Path(RELEASES_DIR) / version
    return {
        "root": root,
        "manifest": root / "manifest.json",
        "bundle": root / "app_bundle.zip",
        "extracted": root / "extracted",
    }


def _extract_bundle(bundle_path: Path, extracted_dir: Path) -> None:
    if extracted_dir.exists():
        for sub in sorted(extracted_dir.rglob("*"), reverse=True):
            if sub.is_file():
                sub.unlink(missing_ok=True)
            elif sub.is_dir():
                sub.rmdir()
    extracted_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(bundle_path, "r") as zf:
        for info in zf.infolist():
            rel = info.filename
            if not rel or rel.endswith("/"):
                continue
            target = _safe_release_join(extracted_dir, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as dst:
                dst.write(src.read())


def _build_manifest_file_list(extracted_dir: Path, exclude_paths: Optional[set[str]] = None) -> list[Dict[str, Any]]:
    files: list[Dict[str, Any]] = []
    if not extracted_dir.exists():
        return files
    excluded = {p.lstrip("/") for p in (exclude_paths or set())}

    for file_path in sorted(extracted_dir.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(extracted_dir).as_posix()
        if rel in excluded:
            continue
        files.append(
            {
                "path": rel,
                "sha256": _hash_file(file_path),
                "size": file_path.stat().st_size,
            }
        )
    return files


def _default_required_release_paths(entrypoint: str = "main.py", available_files: Optional[set[str]] = None) -> list[str]:
    ep = str(entrypoint or "main.py").strip().lstrip("/") or "main.py"
    required = [ep]
    core = [
        "lib/api_client.py",
        "lib/command_runner.py",
        "lib/hardware.py",
        "lib/ota_manager.py",
        "lib/__init__.py",
    ]
    if available_files:
        for path in core:
            if path in available_files:
                required.append(path)
    # Keep deterministic ordering without duplicates.
    out: list[str] = []
    seen: set[str] = set()
    for item in required:
        key = item.strip().lstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _ensure_release_safety_manifest(manifest_json: Dict[str, Any], extracted_files: list[Dict[str, Any]]) -> None:
    files_set = {str(f.get("path") or "").strip().lstrip("/") for f in extracted_files}
    files_set.discard("")

    entrypoint = str(manifest_json.get("entrypoint") or "main.py").strip().lstrip("/") or "main.py"
    if entrypoint not in files_set:
        raise HTTPException(status_code=422, detail=f"entrypoint missing from bundle: {entrypoint}")

    safety = manifest_json.get("safety")
    if not isinstance(safety, dict):
        safety = {}

    required_paths = safety.get("required_paths")
    if not isinstance(required_paths, list) or not required_paths:
        required_paths = _default_required_release_paths(entrypoint=entrypoint, available_files=files_set)
    normalized_required: list[str] = []
    for raw in required_paths:
        rel = str(raw or "").strip().lstrip("/")
        if rel:
            normalized_required.append(rel)
    if not normalized_required:
        normalized_required = _default_required_release_paths(entrypoint=entrypoint, available_files=files_set)

    missing = [rel for rel in normalized_required if rel not in files_set]
    if missing:
        raise HTTPException(status_code=422, detail=f"bundle missing required files: {', '.join(missing)}")

    safety["schema_version"] = int(safety.get("schema_version") or 1)
    safety["entrypoint"] = entrypoint
    safety["required_paths"] = normalized_required
    safety["generated_at"] = now_iso()
    safety["supports_layouts"] = safety.get("supports_layouts") or ["legacy-current", "current-rooted"]
    manifest_json["safety"] = safety


def _resolve_release_row(conn: sqlite3.Connection, version: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM releases WHERE version = ?", (version,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Release not found")
    return row


async def _device_from_bearer(request: Request) -> sqlite3.Row:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    conn = db()
    token_row = conn.execute(
        """
        SELECT dt.*, d.device_id
        FROM device_tokens dt
        JOIN devices d ON d.device_id = dt.device_id
        WHERE dt.token_hash = ? AND dt.revoked_at IS NULL
        ORDER BY dt.created_at DESC
        LIMIT 1
        """,
        (_token_hash(token),),
    ).fetchone()

    if not token_row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid token")

    conn.execute("UPDATE device_tokens SET last_used_at = ? WHERE id = ?", (now_iso(), token_row["id"]))
    conn.commit()

    device_row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (token_row["device_id"],)).fetchone()
    conn.close()
    if not device_row:
        raise HTTPException(status_code=401, detail="Unknown device")
    return device_row


async def _require_printellect_account(account=Depends(require_account)):
    if not PRINTELLECT_DEMO_OPEN_ACCESS and not is_feature_enabled(
        PRINTELLECT_FEATURE_KEY,
        user_id=getattr(account, "id", None),
        email=getattr(account, "email", None),
    ):
        raise HTTPException(status_code=403, detail="Printellect feature is not enabled for this account")
    return account


@router.get("/pair")
async def pair_entry(
    request: Request,
    device_id: str = "",
    claim: str = "",
    name: str = "",
    d: str = "",
    c: str = "",
    n: str = "",
    account=Depends(get_current_account),
):
    device_id = (device_id or d or "").strip().lower()
    claim = (claim or c or "").strip()
    name = (name or n or "").strip()
    if not account:
        next_qs = urlencode({"next": str(request.url)})
        return RedirectResponse(url=f"/auth/login?{next_qs}", status_code=303)
    await _require_printellect_account(account=account)
    return templates.TemplateResponse(
        "printellect_pair.html",
        {
            "request": request,
            "account": account,
            "prefill_device_id": device_id,
            "prefill_claim": claim,
            "prefill_name": name,
        },
    )


@router.get("/printellect/devices", response_class=HTMLResponse)
async def devices_page(request: Request, account=Depends(_require_printellect_account)):
    return templates.TemplateResponse("devices.html", {"request": request, "account": account})


@router.get("/printellect/add-device", response_class=HTMLResponse)
async def add_device_wizard_page(request: Request, account=Depends(_require_printellect_account)):
    return templates.TemplateResponse("device_add_wizard.html", {"request": request, "account": account})


@router.get("/printellect/help", response_class=HTMLResponse)
async def help_page(request: Request, account=Depends(_require_printellect_account)):
    admin = await get_current_admin(request)
    return templates.TemplateResponse(
        "help_printellect.html",
        {"request": request, "account": account, "is_admin": bool(admin)},
    )


@router.get("/printellect/devices/{device_id}", response_class=HTMLResponse)
async def owner_device_detail_page(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    conn = db()
    _get_device_for_owner(conn, device_id, account.id)

    # Fetch active shipments for this account's email so we can show shipping status
    active_shipments = []
    try:
        email = account.email
        ship_rows = conn.execute(
            """SELECT r.id, r.print_name, r.requester_name,
                      rs.shipping_status, rs.tracking_number, rs.tracking_url,
                      rs.carrier, rs.service, rs.estimated_delivery_date, rs.delivered_at
               FROM requests r
               JOIN request_shipping rs ON rs.request_id = r.id
               WHERE r.requester_email = ? AND r.fulfillment_method = 'shipping'
                 AND rs.shipping_status NOT IN ('CANCELLED')
               ORDER BY rs.updated_at DESC
               LIMIT 5""",
            (email,),
        ).fetchall()
        active_shipments = [dict(row) for row in ship_rows]
    except Exception:
        pass

    conn.close()
    admin = await get_current_admin(request)
    return templates.TemplateResponse(
        "device_detail.html",
        {
            "request": request,
            "account": account,
            "device_id": device_id,
            "is_admin": bool(admin),
            "active_shipments": active_shipments,
        },
    )


@router.get("/admin/printellect/devices", response_class=HTMLResponse)
async def admin_devices_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("admin_printellect_devices.html", {"request": request, "admin": admin})


@router.get("/admin/printellect/releases", response_class=HTMLResponse)
async def admin_releases_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("admin_printellect_releases.html", {"request": request, "admin": admin})


@router.get("/admin/printellect/ota-status", response_class=HTMLResponse)
async def admin_ota_status_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("admin_printellect_ota_status.html", {"request": request, "admin": admin})


# ---------------------------------------------------------------------------
# Admin Docs Viewer — serves markdown docs from docs/ directory
# ---------------------------------------------------------------------------

_DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"
_ALLOWED_DOCS = {
    "README.md",
    "printellect-admin-api.md",
    "printellect-device-api.md",
    "printellect-device-state-machine.md",
    "printellect-firmware-dev.md",
    "printellect-flashing-guide.md",
    "printellect-local-qa.md",
    "printellect-ota-and-recovery.md",
    "printellect-pico-api-programming-guide.md",
    "printellect-pico-final-implementation-guide.md",
    "printellect-pico-integration-handoff.md",
    "printellect-device-control-roadmap.md",
    "printellect-user-api.md",
    "setup-my-printellect-base.md",
}


@router.get("/admin/printellect/docs", response_class=HTMLResponse)
async def admin_docs_index(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse(
        "admin_printellect_docs.html",
        {"request": request, "admin": admin, "doc_name": None, "doc_html": None, "doc_list": sorted(_ALLOWED_DOCS)},
    )


@router.get("/admin/printellect/docs/{doc_name}", response_class=HTMLResponse)
async def admin_docs_view(request: Request, doc_name: str, admin=Depends(require_admin)):
    # Validate against allowlist — no path traversal possible
    if doc_name not in _ALLOWED_DOCS:
        raise HTTPException(status_code=404, detail="Document not found")
    doc_path = _DOCS_DIR / doc_name
    if not doc_path.is_file():
        raise HTTPException(status_code=404, detail="Document not found")
    raw = doc_path.read_text(encoding="utf-8")
    # Convert markdown to HTML (basic conversion without external deps)
    doc_html = _md_to_html(raw)
    return templates.TemplateResponse(
        "admin_printellect_docs.html",
        {"request": request, "admin": admin, "doc_name": doc_name, "doc_html": doc_html, "doc_list": sorted(_ALLOWED_DOCS)},
    )


def _md_to_html(md: str) -> str:
    """Minimal markdown-to-HTML converter — no external dependencies."""
    import html as _html

    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    in_list = False
    in_table = False
    code_lang = ""

    for line in lines:
        # Fenced code blocks
        if line.startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                code_lang = _html.escape(line[3:].strip())
                cls = f' class="language-{code_lang}"' if code_lang else ""
                out.append(f"<pre><code{cls}>")
                in_code = True
            continue
        if in_code:
            out.append(_html.escape(line))
            continue

        stripped = line.strip()

        # Tables
        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # Skip separator rows
            if all(set(c) <= {"-", ":", " "} for c in cells):
                continue
            if not in_table:
                out.append("<div class='overflow-x-auto'><table class='doc-table'>")
                in_table = True
            out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        elif in_table:
            out.append("</table></div>")
            in_table = False

        # Close list if not a list item
        if in_list and not stripped.startswith("- ") and not stripped.startswith("* ") and stripped:
            out.append("</ul>")
            in_list = False

        # Headings
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            level = min(level, 6)
            text = stripped[level:].strip()
            slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
            out.append(f"<h{level} id=\"{slug}\">{_inline(text)}</h{level}>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
        elif stripped.startswith("> "):
            out.append(f"<blockquote>{_inline(stripped[2:])}</blockquote>")
        elif stripped.startswith("---"):
            out.append("<hr>")
        elif stripped == "":
            out.append("")
        else:
            out.append(f"<p>{_inline(stripped)}</p>")

    if in_code:
        out.append("</code></pre>")
    if in_list:
        out.append("</ul>")
    if in_table:
        out.append("</table></div>")
    return "\n".join(out)


def _inline(text: str) -> str:
    """Convert inline markdown: bold, italic, code, links."""
    import html as _html

    # Inline code
    text = re.sub(r"`([^`]+)`", lambda m: f"<code>{_html.escape(m.group(1))}</code>", text)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # Links
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" class="doc-link">\1</a>', text)
    return text


@router.post("/api/printellect/pairing/start")
async def pairing_start(account=Depends(_require_printellect_account)):
    session_id = str(uuid.uuid4())
    created = datetime.utcnow()
    expires = created + timedelta(minutes=PAIRING_SESSION_MINUTES)
    conn = db()
    conn.execute(
        """
        INSERT INTO pairing_sessions (session_id, owner_user_id, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, 'pending')
        """,
        (
            session_id,
            account.id,
            created.isoformat(timespec="seconds") + "Z",
            expires.isoformat(timespec="seconds") + "Z",
        ),
    )
    _audit(
        conn,
        action="printellect_pairing_started",
        actor_type="user",
        actor_id=account.id,
        target_type="pairing_session",
        target_id=session_id,
    )
    conn.commit()
    conn.close()
    return JSONResponse(
        {
            "ok": True,
            "session_id": session_id,
            "expires_at": expires.isoformat(timespec="seconds") + "Z",
        }
    )


@router.post("/api/printellect/pairing/claim")
async def claim_device(request: Request, account=Depends(_require_printellect_account)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    device_id = (payload.get("device_id") or "").strip().lower()
    claim_code = (payload.get("claim_code") or "").strip()
    name = (payload.get("name") or "").strip()
    session_id = (payload.get("session_id") or "").strip()

    if not device_id or not claim_code:
        raise HTTPException(status_code=422, detail="device_id and claim_code are required")

    conn = db()
    if session_id:
        srow = conn.execute(
            "SELECT * FROM pairing_sessions WHERE session_id = ? AND owner_user_id = ?",
            (session_id, account.id),
        ).fetchone()
        if not srow:
            conn.close()
            raise HTTPException(status_code=404, detail="Pairing session not found")
        if _parse_iso(srow["expires_at"]) and datetime.utcnow() > _parse_iso(srow["expires_at"]).replace(tzinfo=None):
            conn.execute("UPDATE pairing_sessions SET status = 'expired' WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            raise HTTPException(status_code=410, detail="Pairing session expired")

    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    if not _verify_claim(claim_code, row["claim_code_hash"]):
        if _record_claim_failure(request, device_id, claim_code):
            conn.close()
            raise HTTPException(status_code=429, detail="Too many failed claim attempts")
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid claim code")

    existing_owner = row["owner_user_id"]
    if existing_owner and existing_owner != account.id:
        conn.close()
        raise HTTPException(status_code=409, detail="Device is already claimed by another account")

    ts = now_iso()
    if name:
        conn.execute(
            "UPDATE devices SET owner_user_id = ?, name = ?, claimed_at = COALESCE(claimed_at, ?) WHERE device_id = ?",
            (account.id, name, ts, device_id),
        )
    else:
        conn.execute(
            "UPDATE devices SET owner_user_id = ?, claimed_at = COALESCE(claimed_at, ?) WHERE device_id = ?",
            (account.id, ts, device_id),
        )
    if session_id:
        conn.execute(
            "UPDATE pairing_sessions SET status = 'complete', claimed_device_id = ?, claimed_at = ? WHERE session_id = ?",
            (device_id, ts, session_id),
        )

    _audit(
        conn,
        action="printellect_pairing_claimed",
        actor_type="user",
        actor_id=account.id,
        target_type="device",
        target_id=device_id,
        details={"session_id": session_id or None, "name": name or None},
    )
    conn.commit()
    conn.close()
    _clear_claim_failures(request, device_id, claim_code)

    latest = db()
    latest_row = latest.execute(
        "SELECT name, last_seen_at, fw_version, app_version FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    latest.close()
    return JSONResponse(
        {
            "status": "claimed",
            "device_id": device_id,
            "name": (latest_row["name"] if latest_row else None) or device_id,
            "next": "wait_for_online",
            "online": _is_online(latest_row["last_seen_at"] if latest_row else None),
            "device_url": f"/printellect/devices/{device_id}",
            "fw_version": latest_row["fw_version"] if latest_row else None,
            "app_version": latest_row["app_version"] if latest_row else None,
        }
    )


@router.get("/api/printellect/devices")
async def list_devices(account=Depends(_require_printellect_account)):
    conn = db()
    rows = conn.execute(
        """
        SELECT d.*, ds.state_json, us.status as update_status, us.target_version, us.progress, us.last_error, us.last_result_json
        FROM devices d
        LEFT JOIN device_state ds ON ds.device_id = d.device_id
        LEFT JOIN device_update_status us ON us.device_id = d.device_id
        WHERE d.owner_user_id = ?
        ORDER BY d.created_at DESC
        """,
        (account.id,),
    ).fetchall()

    devices = []
    for row in rows:
        last_command_row = conn.execute(
            """
            SELECT action, status, updated_at, error, result_json
            FROM commands
            WHERE device_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (row["device_id"],),
        ).fetchone()
        last_command = None
        if last_command_row:
            last_command = {
                "action": last_command_row["action"],
                "status": last_command_row["status"],
                "updated_at": last_command_row["updated_at"],
                "error": last_command_row["error"],
                "result": _json_loads(last_command_row["result_json"], {}) if "result_json" in last_command_row.keys() else {},
            }
        heartbeat = _json_loads(row["heartbeat_json"], {}) if "heartbeat_json" in row.keys() else {}
        devices.append(
            {
                "device_id": row["device_id"],
                "name": row["name"],
                "last_seen_at": row["last_seen_at"],
                "online": _is_online(row["last_seen_at"]),
                "fw_version": row["fw_version"],
                "app_version": row["app_version"],
                "rssi": row["rssi"],
                "heartbeat": heartbeat,
                "telemetry_warnings": _heartbeat_warnings(heartbeat),
                "state": _json_loads(row["state_json"], {}),
                "update_status": {
                    "status": row["update_status"] or "idle",
                    "target_version": row["target_version"],
                    "progress": row["progress"] if row["progress"] is not None else 0,
                    "last_error": row["last_error"],
                    "result": _json_loads(row["last_result_json"], {}),
                },
                "last_command": last_command,
            }
        )

    conn.close()
    return JSONResponse({"ok": True, "devices": devices})


@router.get("/api/printellect/devices/{device_id}")
async def device_detail(device_id: str, account=Depends(_require_printellect_account)):
    conn = db()
    drow = _get_device_for_owner(conn, device_id, account.id)
    state_row = conn.execute("SELECT state_json, updated_at FROM device_state WHERE device_id = ?", (device_id,)).fetchone()
    update_row = conn.execute("SELECT * FROM device_update_status WHERE device_id = ?", (device_id,)).fetchone()
    commands = conn.execute(
        "SELECT * FROM commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 30",
        (device_id,),
    ).fetchall()
    conn.close()
    heartbeat = _json_loads(drow["heartbeat_json"] if "heartbeat_json" in drow.keys() else None, {})

    return JSONResponse(
        {
            "ok": True,
            "device": {
                "device_id": drow["device_id"],
                "name": drow["name"],
                "last_seen_at": drow["last_seen_at"],
                "online": _is_online(drow["last_seen_at"]),
                "fw_version": drow["fw_version"],
                "app_version": drow["app_version"],
                "rssi": drow["rssi"],
                "heartbeat": heartbeat,
                "telemetry_warnings": _heartbeat_warnings(heartbeat),
                "state": _json_loads(state_row["state_json"] if state_row else None, {}),
                "state_updated_at": state_row["updated_at"] if state_row else None,
                "update_status": {
                    "status": update_row["status"] if update_row else "idle",
                    "target_version": update_row["target_version"] if update_row else None,
                    "progress": update_row["progress"] if update_row else 0,
                    "last_error": update_row["last_error"] if update_row else None,
                    "result": _json_loads(update_row["last_result_json"], {}) if update_row else {},
                    "updated_at": update_row["updated_at"] if update_row else None,
                },
                "recent_commands": [
                    {
                        "cmd_id": r["cmd_id"],
                        "action": r["action"],
                        "payload": _json_loads(r["payload_json"], {}),
                        "result": _json_loads(r["result_json"], {}) if "result_json" in r.keys() else {},
                        "status": r["status"],
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                        "error": r["error"],
                    }
                    for r in commands
                ],
            },
        }
    )


@router.get("/api/printellect/devices/{device_id}/support-bundle")
async def device_support_bundle(device_id: str, account=Depends(_require_printellect_account)):
    conn = db()
    drow = _get_device_for_owner(conn, device_id, account.id)
    state_row = conn.execute("SELECT state_json, updated_at FROM device_state WHERE device_id = ?", (device_id,)).fetchone()
    update_row = conn.execute("SELECT * FROM device_update_status WHERE device_id = ?", (device_id,)).fetchone()
    commands = conn.execute(
        "SELECT * FROM commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 100",
        (device_id,),
    ).fetchall()
    token_rows = conn.execute(
        "SELECT id, created_at, revoked_at, last_used_at FROM device_tokens WHERE device_id = ? ORDER BY created_at DESC LIMIT 10",
        (device_id,),
    ).fetchall()
    conn.close()

    payload = {
        "generated_at": now_iso(),
        "device": {
            "device_id": drow["device_id"],
            "name": drow["name"],
            "last_seen_at": drow["last_seen_at"],
            "online": _is_online(drow["last_seen_at"]),
            "fw_version": drow["fw_version"],
            "app_version": drow["app_version"],
            "rssi": drow["rssi"],
            "heartbeat": _json_loads(drow["heartbeat_json"] if "heartbeat_json" in drow.keys() else None, {}),
            "notes": drow["notes"] if "notes" in drow.keys() else None,
        },
        "state": {
            "updated_at": state_row["updated_at"] if state_row else None,
            "raw": _json_loads(state_row["state_json"] if state_row else None, {}),
        },
        "update_status": {
            "status": update_row["status"] if update_row else "idle",
            "target_version": update_row["target_version"] if update_row else None,
            "progress": update_row["progress"] if update_row else 0,
            "last_error": update_row["last_error"] if update_row else None,
            "result": _json_loads(update_row["last_result_json"], {}) if update_row else {},
            "updated_at": update_row["updated_at"] if update_row else None,
        },
        "recent_commands": [
            {
                "cmd_id": r["cmd_id"],
                "action": r["action"],
                "status": r["status"],
                "payload": _json_loads(r["payload_json"], {}),
                "result": _json_loads(r["result_json"], {}),
                "error": r["error"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in commands
        ],
        "tokens": [dict(r) for r in token_rows],
    }
    payload["device"]["telemetry_warnings"] = _heartbeat_warnings(payload["device"]["heartbeat"])

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.json", _json_dumps(payload))
        zf.writestr("state.json", _json_dumps(payload["state"]))
        zf.writestr("commands.json", _json_dumps(payload["recent_commands"]))
    filename = f"printellect-support-{device_id}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/printellect/admin/devices/{device_id}/support-bundle")
async def admin_device_support_bundle(device_id: str, admin=Depends(require_admin)):
    del admin
    conn = db()
    drow = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not drow:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    state_row = conn.execute("SELECT state_json, updated_at FROM device_state WHERE device_id = ?", (device_id,)).fetchone()
    update_row = conn.execute("SELECT * FROM device_update_status WHERE device_id = ?", (device_id,)).fetchone()
    commands = conn.execute(
        "SELECT * FROM commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 100",
        (device_id,),
    ).fetchall()
    conn.close()

    payload = {
        "generated_at": now_iso(),
        "device": dict(drow),
        "state": {
            "updated_at": state_row["updated_at"] if state_row else None,
            "raw": _json_loads(state_row["state_json"] if state_row else None, {}),
        },
        "update_status": {
            "status": update_row["status"] if update_row else "idle",
            "target_version": update_row["target_version"] if update_row else None,
            "progress": update_row["progress"] if update_row else 0,
            "last_error": update_row["last_error"] if update_row else None,
            "result": _json_loads(update_row["last_result_json"], {}) if update_row else {},
            "updated_at": update_row["updated_at"] if update_row else None,
        },
        "recent_commands": [
            {
                "cmd_id": r["cmd_id"],
                "action": r["action"],
                "status": r["status"],
                "payload": _json_loads(r["payload_json"], {}),
                "result": _json_loads(r["result_json"], {}),
                "error": r["error"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in commands
        ],
    }
    heartbeat = _json_loads(drow["heartbeat_json"] if "heartbeat_json" in drow.keys() else None, {})
    payload["device"]["heartbeat"] = heartbeat
    payload["device"]["telemetry_warnings"] = _heartbeat_warnings(heartbeat)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.json", _json_dumps(payload))
    filename = f"printellect-support-{device_id}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.put("/api/printellect/devices/{device_id}/name")
async def rename_device(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    """Rename a device. Body: {"name": "My Device"}"""
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = (body.get("name") or "").strip()[:64]
    if not name:
        raise HTTPException(status_code=422, detail="Name cannot be empty")
    conn = db()
    _get_device_for_owner(conn, device_id, account.id)  # ownership check
    conn.execute("UPDATE devices SET name = ? WHERE device_id = ?", (name, device_id))
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True, "name": name})


async def _enqueue_user_action(
    device_id: str,
    account,
    action: str,
    request: Optional[Request] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> ActionEnqueueResponse:
    body = payload if payload is not None else {}
    if request is not None:
        try:
            body = await request.json()
        except Exception:
            body = {}

    payload_clean = _validate_action_payload(action, body)

    conn = db()
    drow = _get_device_for_owner(conn, device_id, account.id)
    cmd_id = _enqueue_command(conn, drow, account.id, action, payload_clean, require_online=True)
    conn.commit()
    conn.close()

    return ActionEnqueueResponse(ok=True, cmd_id=cmd_id, action=action, payload=payload_clean)


@router.post("/api/printellect/devices/{device_id}/actions/play", response_model=ActionEnqueueResponse)
async def action_play(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "play_perk", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/stop", response_model=ActionEnqueueResponse)
async def action_stop(device_id: str, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "stop_audio", payload={})


@router.post("/api/printellect/devices/{device_id}/actions/idle", response_model=ActionEnqueueResponse)
async def action_idle(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_idle", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/brightness", response_model=ActionEnqueueResponse)
async def action_brightness(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_brightness", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/volume", response_model=ActionEnqueueResponse)
async def action_volume(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_volume", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/light-color", response_model=ActionEnqueueResponse)
async def action_light_color(
    device_id: str,
    body: LightColorActionBody,
    account=Depends(_require_printellect_account),
):
    return await _enqueue_user_action(
        device_id,
        account,
        "set_light_color",
        payload=body.model_dump(exclude_none=True),
    )


@router.post("/api/printellect/devices/{device_id}/actions/light-effect", response_model=ActionEnqueueResponse)
async def action_light_effect(
    device_id: str,
    body: LightEffectActionBody,
    account=Depends(_require_printellect_account),
):
    return await _enqueue_user_action(
        device_id,
        account,
        "set_light_effect",
        payload=body.model_dump(exclude_none=True),
    )


@router.post("/api/printellect/devices/{device_id}/actions/test-lights", response_model=ActionEnqueueResponse)
async def action_test_lights(
    device_id: str,
    body: TestLightsActionBody,
    account=Depends(_require_printellect_account),
):
    return await _enqueue_user_action(
        device_id,
        account,
        "test_lights",
        payload=body.model_dump(exclude_none=True),
    )


@router.post("/api/printellect/devices/{device_id}/actions/test-audio", response_model=ActionEnqueueResponse)
async def action_test_audio(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "test_audio", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/speaker-validate", response_model=ActionEnqueueResponse)
async def action_speaker_validate(
    device_id: str,
    body: SpeakerValidateActionBody,
    account=Depends(_require_printellect_account),
):
    return await _enqueue_user_action(
        device_id,
        account,
        "speaker_validate",
        payload=body.model_dump(exclude_none=True),
    )


@router.post("/api/printellect/devices/{device_id}/actions/self-test", response_model=ActionEnqueueResponse)
async def action_self_test(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "self_test", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/identify", response_model=ActionEnqueueResponse)
async def action_identify(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "identify_device", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/button-snapshot", response_model=ActionEnqueueResponse)
async def action_button_snapshot(device_id: str, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "button_snapshot", payload={})


@router.post("/api/printellect/devices/{device_id}/actions/reboot", response_model=ActionEnqueueResponse)
async def action_reboot(device_id: str, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "reboot", payload={})


@router.post("/api/printellect/devices/{device_id}/actions/update", response_model=ActionEnqueueResponse)
async def action_update(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "ota_apply", request=request)


@router.get("/api/printellect/device/v1/debug")
async def device_debug_contract():
    return JSONResponse(
        {
            "service": "printellect-device-api",
            "version": "v1",
            "base_path": "/api/printellect/device/v1",
            "auth": {
                "provision": "claim_code",
                "device_endpoints": "bearer_token",
                "header": "Authorization: Bearer <device_token>",
            },
            "timing_defaults": {
                "provision_poll_interval_ms": PROVISION_POLL_INTERVAL_MS,
                "min_command_poll_interval_ms": int(DEVICE_MIN_POLL_SECONDS * 1000),
                "stream_max_timeout_s": DEVICE_STREAM_MAX_SECONDS,
                "recommended_heartbeat_interval_ms": 15000,
            },
            "actions_supported": [
                "play_perk",
                "stop_audio",
                "set_idle",
                "set_brightness",
                "set_volume",
                "set_light_color",
                "set_light_effect",
                "test_lights",
                "test_audio",
                "speaker_validate",
                "self_test",
                "identify_device",
                "button_snapshot",
                "reboot",
                "ota_apply",
            ],
            "command_status_values": ["executing", "completed", "failed"],
            "update_status_values": [
                "idle",
                "available",
                "downloading",
                "applying",
                "success",
                "rollback",
                "failed",
            ],
            "endpoints": [
                {"method": "POST", "path": "/api/printellect/device/v1/provision", "auth": "claim_code"},
                {"method": "POST", "path": "/api/printellect/device/v1/heartbeat", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/commands/next", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/commands/stream", "auth": "bearer"},
                {"method": "POST", "path": "/api/printellect/device/v1/commands/{cmd_id}/status", "auth": "bearer"},
                {"method": "POST", "path": "/api/printellect/device/v1/state", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/releases/latest", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/releases/{version}/manifest", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/releases/{version}/files/{file_path}", "auth": "bearer"},
                {"method": "GET", "path": "/api/printellect/device/v1/releases/{version}/bundle", "auth": "bearer"},
                {"method": "POST", "path": "/api/printellect/device/v1/update/status", "auth": "bearer"},
                {"method": "POST", "path": "/api/printellect/device/v1/boot-ok", "auth": "bearer"},
            ],
            "openapi": {
                "json_url": "/openapi.json",
                "docs_url": "/docs",
            },
        }
    )


@router.get("/api/printellect/admin/qr.svg")
async def admin_qr_svg(payload: str, admin=Depends(require_admin)):
    del admin
    return Response(content=_qr_svg(payload), media_type="image/svg+xml")


@router.post("/api/printellect/device/v1/provision")
async def device_provision(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    device_id = (payload.get("device_id") or "").strip().lower()
    claim_code = (payload.get("claim_code") or "").strip()
    fw_version = (payload.get("fw_version") or "").strip() or None
    app_version = (payload.get("app_version") or "").strip() or None

    if not device_id or not claim_code:
        raise HTTPException(status_code=422, detail="device_id and claim_code are required")

    conn = db()
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    if not _verify_claim(claim_code, row["claim_code_hash"]):
        if _record_claim_failure(request, device_id, claim_code):
            conn.close()
            raise HTTPException(status_code=429, detail="Too many failed claim attempts")
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid claim code")

    if not row["owner_user_id"]:
        conn.close()
        return JSONResponse(
            {
                "status": "unclaimed",
                "legacy_status": "waiting",
                "message": "Device not yet claimed",
                "poll_interval_ms": PROVISION_POLL_INTERVAL_MS,
            }
        )

    ts = now_iso()

    token = rotate_and_issue_device_token(conn, device_id=device_id, issued_at=ts)
    conn.execute(
        "UPDATE devices SET fw_version = COALESCE(?, fw_version), app_version = COALESCE(?, app_version), last_provisioned_at = ? WHERE device_id = ?",
        (fw_version, app_version, ts, device_id),
    )

    _audit(
        conn,
        action="printellect_device_provisioned",
        actor_type="device",
        actor_id=device_id,
        target_type="device",
        target_id=device_id,
        details={"owner_user_id": row["owner_user_id"]},
    )

    conn.commit()
    conn.close()
    _clear_claim_failures(request, device_id, claim_code)

    return JSONResponse(
        {
            "status": "provisioned",
            "legacy_status": "claimed",
            "device_token": token,
            "poll_interval_ms": PROVISION_POLL_INTERVAL_MS,
        }
    )


@router.post("/api/printellect/device/v1/heartbeat")
async def device_heartbeat(request: Request, device=Depends(_device_from_bearer)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    fw_version = _normalize_version_text(payload.get("fw_version"))
    app_version = _normalize_version_text(payload.get("app_version"))
    rssi = payload.get("rssi")
    if rssi is not None:
        try:
            rssi = int(rssi)
        except Exception:
            rssi = None
    telemetry = payload.get("telemetry")
    if telemetry is not None and not isinstance(telemetry, dict):
        telemetry = None
    reset_event = payload.get("reset_event")
    ts = now_iso()
    heartbeat_record: Dict[str, Any] = {
        "received_at": ts,
        "fw_version": fw_version,
        "app_version": app_version,
        "rssi": rssi,
    }
    if reset_event:
        heartbeat_record["reset_event"] = str(reset_event)
    if telemetry is not None:
        heartbeat_record["telemetry"] = telemetry

    conn = db()
    conn.execute(
        """
        UPDATE devices
        SET
            last_seen_at = ?,
            fw_version = COALESCE(?, fw_version),
            app_version = COALESCE(?, app_version),
            rssi = COALESCE(?, rssi),
            heartbeat_json = ?
        WHERE device_id = ?
        """,
        (ts, fw_version, app_version, rssi, _json_dumps(heartbeat_record), device["device_id"]),
    )

    # Guard against silent drift after an OTA was marked successful.
    if app_version:
        expected_row = conn.execute(
            "SELECT target_version, status FROM device_update_status WHERE device_id = ?",
            (device["device_id"],),
        ).fetchone()
        expected = _normalize_version_text(expected_row["target_version"]) if expected_row else None
        current_status = (expected_row["status"] or "").strip().lower() if expected_row else ""
        if expected and current_status == "success" and app_version != expected:
            mismatch = _mark_update_version_mismatch(
                conn,
                device_id=device["device_id"],
                expected_version=expected,
                reported_version=app_version,
                source="heartbeat",
            )
            _audit(
                conn,
                action="printellect_update_version_mismatch",
                actor_type="device",
                actor_id=device["device_id"],
                target_type="device",
                target_id=device["device_id"],
                details={"source": "heartbeat", "expected": expected, "reported": app_version, "error": mismatch},
            )

    if reset_event:
        _audit(
            conn,
            action="printellect_device_reset_reported",
            actor_type="device",
            actor_id=device["device_id"],
            target_type="device",
            target_id=device["device_id"],
            details={"reset_event": str(reset_event)},
        )

    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


@router.get(
    "/api/printellect/device/v1/commands/next",
    response_model=DeviceCommandResponse,
    responses={204: {"description": "No command available"}},
)
async def device_next_command(device=Depends(_device_from_bearer)):
    device_id = device["device_id"]
    now_mono = time.monotonic()
    with _poll_lock:
        last = _last_poll_at.get(device_id)
        if last is not None and (now_mono - last) < DEVICE_MIN_POLL_SECONDS:
            retry_after = max(1, int(DEVICE_MIN_POLL_SECONDS - (now_mono - last)))
            return Response(status_code=204, headers={"Retry-After": str(retry_after)})
        _last_poll_at[device_id] = now_mono

    conn = db()
    status, row = _claim_next_queued_command(conn, device_id)
    if status != "delivered" or row is None:
        conn.close()
        return Response(status_code=204)
    conn.commit()
    conn.close()
    return _command_row_response(row)


def _command_row_response(row: sqlite3.Row) -> DeviceCommandResponse:
    return DeviceCommandResponse(
        cmd_id=row["cmd_id"],
        action=row["action"],
        payload=_json_loads(row["payload_json"], {}),
        created_at=row["created_at"],
    )


def _claim_next_queued_command(conn: sqlite3.Connection, device_id: str) -> tuple[str, Optional[sqlite3.Row]]:
    inflight = conn.execute(
        "SELECT cmd_id FROM commands WHERE device_id = ? AND status IN ('delivered','executing') ORDER BY created_at LIMIT 1",
        (device_id,),
    ).fetchone()
    if inflight:
        return "inflight", None

    row = conn.execute(
        "SELECT * FROM commands WHERE device_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 1",
        (device_id,),
    ).fetchone()
    if not row:
        return "empty", None

    ts = now_iso()
    conn.execute(
        "UPDATE commands SET status = 'delivered', delivered_at = ?, updated_at = ? WHERE cmd_id = ?",
        (ts, ts, row["cmd_id"]),
    )
    _audit(
        conn,
        action="printellect_command_delivered",
        actor_type="device",
        actor_id=device_id,
        target_type="command",
        target_id=row["cmd_id"],
        details={"action": row["action"]},
    )
    return "delivered", row


@router.get(
    "/api/printellect/device/v1/commands/stream",
    response_model=DeviceCommandResponse,
    responses={204: {"description": "No command available"}},
)
async def device_command_stream(timeout_s: int = 15, device=Depends(_device_from_bearer)):
    timeout_s = max(1, min(int(timeout_s), DEVICE_STREAM_MAX_SECONDS))
    device_id = device["device_id"]
    deadline = time.monotonic() + timeout_s

    while True:
        conn = db()
        status, row = _claim_next_queued_command(conn, device_id)
        if status == "delivered" and row is not None:
            conn.commit()
            conn.close()
            return _command_row_response(row)
        conn.close()
        if status == "inflight":
            return Response(status_code=204)
        if time.monotonic() >= deadline:
            return Response(status_code=204, headers={"Retry-After": "1"})
        await asyncio.sleep(DEVICE_STREAM_POLL_STEP_SECONDS)


@router.post("/api/printellect/device/v1/commands/{cmd_id}/status", response_model=ApiOkResponse)
async def device_command_status(cmd_id: str, body: DeviceCommandStatusBody, device=Depends(_device_from_bearer)):
    status = (body.status or "").strip().lower()
    error = body.error
    result = body.result
    if status not in {"executing", "completed", "failed"}:
        raise HTTPException(status_code=422, detail="status must be executing|completed|failed")
    if result is not None and not isinstance(result, dict):
        raise HTTPException(status_code=422, detail="result must be an object")

    conn = db()
    row = conn.execute("SELECT * FROM commands WHERE cmd_id = ? AND device_id = ?", (cmd_id, device["device_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Command not found")

    ts = now_iso()
    if status == "executing":
        conn.execute(
            "UPDATE commands SET status = 'executing', executing_at = COALESCE(executing_at, ?), updated_at = ?, result_json = COALESCE(?, result_json) WHERE cmd_id = ?",
            (ts, ts, _json_dumps(result) if result is not None else None, cmd_id),
        )
    elif status == "completed":
        conn.execute(
            "UPDATE commands SET status = 'completed', completed_at = ?, updated_at = ?, error = NULL, result_json = COALESCE(?, result_json) WHERE cmd_id = ?",
            (ts, ts, _json_dumps(result) if result is not None else None, cmd_id),
        )
    else:
        conn.execute(
            "UPDATE commands SET status = 'failed', completed_at = ?, updated_at = ?, error = ?, result_json = COALESCE(?, result_json) WHERE cmd_id = ?",
            (ts, ts, str(error) if error else "unknown", _json_dumps(result) if result is not None else None, cmd_id),
        )

    _audit(
        conn,
        action="printellect_command_status",
        actor_type="device",
        actor_id=device["device_id"],
        target_type="command",
        target_id=cmd_id,
        details={"status": status, "error": error, "result": result},
    )
    conn.commit()
    conn.close()
    return ApiOkResponse(ok=True)


@router.post("/api/printellect/device/v1/state")
async def device_state_update(request: Request, device=Depends(_device_from_bearer)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    conn = db()
    conn.execute(
        """
        INSERT INTO device_state (device_id, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at
        """,
        (device["device_id"], _json_dumps(payload), now_iso()),
    )
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


@router.get("/api/printellect/device/v1/releases/latest")
async def device_latest_release(channel: str = "stable", device=Depends(_device_from_bearer)):
    conn = db()
    row = conn.execute(
        "SELECT * FROM releases WHERE channel = ? AND is_current = 1 ORDER BY created_at DESC LIMIT 1",
        (channel,),
    ).fetchone()
    conn.close()
    if not row:
        return Response(status_code=204)

    manifest = _json_loads(row["manifest_json"], {})
    version = row["version"]
    return JSONResponse(
        {
            "version": version,
            "channel": row["channel"],
            "manifest": manifest,
            "endpoints": {
                "manifest_url": f"/api/printellect/device/v1/releases/{version}/manifest",
                "file_base_url": f"/api/printellect/device/v1/releases/{version}/files",
                "bundle_url": f"/api/printellect/device/v1/releases/{version}/bundle",
            },
        }
    )


@router.get("/api/printellect/device/v1/releases/{version}/manifest")
async def device_release_manifest(version: str, device=Depends(_device_from_bearer)):
    conn = db()
    row = _resolve_release_row(conn, version)
    conn.close()
    manifest = _json_loads(row["manifest_json"], {})
    return JSONResponse({"version": version, "manifest": manifest})


@router.get("/api/printellect/device/v1/releases/{version}/bundle")
async def device_release_bundle(version: str, device=Depends(_device_from_bearer)):
    conn = db()
    row = _resolve_release_row(conn, version)
    conn.close()

    bundle_path = row["bundle_path"]
    if not bundle_path:
        raise HTTPException(status_code=404, detail="Release bundle missing")

    path = Path(bundle_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Release bundle file missing")

    return FileResponse(str(path), media_type="application/zip", filename=path.name)


@router.get("/api/printellect/device/v1/releases/{version}/files/{file_path:path}")
async def device_release_file(version: str, file_path: str, device=Depends(_device_from_bearer)):
    conn = db()
    row = _resolve_release_row(conn, version)
    conn.close()

    root = _release_paths(version)["extracted"]
    if not root.exists():
        raise HTTPException(status_code=404, detail="Extracted release not found")

    file_on_disk = _safe_release_join(root, file_path)
    if not file_on_disk.exists() or not file_on_disk.is_file():
        raise HTTPException(status_code=404, detail="Release file not found")

    media_type = mimetypes.guess_type(file_on_disk.name)[0] or "application/octet-stream"
    return FileResponse(str(file_on_disk), media_type=media_type, filename=file_on_disk.name)


@router.post("/api/printellect/device/v1/update/status", response_model=ApiOkResponse)
async def device_update_status(body: DeviceUpdateStatusBody, device=Depends(_device_from_bearer)):
    status = _normalize_version_text(body.status)
    status = (status or "").lower()
    target_version = _normalize_version_text(body.version or body.target_version)
    progress = body.progress if isinstance(body.progress, int) else 0
    last_error = body.error
    result = body.result

    valid = {"idle", "available", "downloading", "applying", "success", "rollback", "failed"}
    if status not in valid:
        raise HTTPException(status_code=422, detail="Invalid update status")
    if result is not None and not isinstance(result, dict):
        raise HTTPException(status_code=422, detail="result must be an object")

    progress = max(0, min(100, progress))

    conn = db()
    current_row = conn.execute(
        "SELECT target_version FROM device_update_status WHERE device_id = ?",
        (device["device_id"],),
    ).fetchone()
    expected_version = _normalize_version_text(current_row["target_version"]) if current_row else None

    if status == "success" and not (target_version or expected_version):
        conn.close()
        raise HTTPException(status_code=422, detail="version is required when status=success")

    if status == "success" and expected_version:
        reported = target_version or expected_version
        if reported != expected_version:
            mismatch = _mark_update_version_mismatch(
                conn,
                device_id=device["device_id"],
                expected_version=expected_version,
                reported_version=reported,
                source="update_status",
            )
            _audit(
                conn,
                action="printellect_update_version_mismatch",
                actor_type="device",
                actor_id=device["device_id"],
                target_type="device",
                target_id=device["device_id"],
                details={"source": "update_status", "expected": expected_version, "reported": reported, "error": mismatch},
            )
            conn.commit()
            conn.close()
            raise HTTPException(status_code=409, detail=mismatch)
        target_version = reported

    conn.execute(
        """
        INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, last_result_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            target_version = excluded.target_version,
            status = excluded.status,
            progress = excluded.progress,
            last_error = excluded.last_error,
            last_result_json = COALESCE(excluded.last_result_json, device_update_status.last_result_json),
            updated_at = excluded.updated_at
        """,
        (
            device["device_id"],
            target_version,
            status,
            progress,
            str(last_error) if last_error else None,
            _json_dumps(result) if result is not None else None,
            now_iso(),
        ),
    )

    if status == "success" and target_version:
        conn.execute(
            "UPDATE devices SET app_version = COALESCE(?, app_version) WHERE device_id = ?",
            (target_version, device["device_id"]),
        )

    _audit(
        conn,
        action="printellect_update_status",
        actor_type="device",
        actor_id=device["device_id"],
        target_type="device",
        target_id=device["device_id"],
        details={
            "status": status,
            "target_version": target_version,
            "progress": progress,
            "error": last_error,
            "result": result,
        },
    )
    conn.commit()
    conn.close()
    return ApiOkResponse(ok=True)


@router.post("/api/printellect/device/v1/boot-ok", response_model=ApiOkResponse)
async def device_boot_ok(body: DeviceBootOkBody, device=Depends(_device_from_bearer)):
    version = _normalize_version_text(body.version)

    conn = db()
    status_row = conn.execute(
        "SELECT target_version FROM device_update_status WHERE device_id = ?",
        (device["device_id"],),
    ).fetchone()
    expected = _normalize_version_text(status_row["target_version"]) if status_row else None

    if expected and not version:
        conn.close()
        raise HTTPException(status_code=422, detail="version is required when update target exists")

    if expected and version and version != expected:
        mismatch = _mark_update_version_mismatch(
            conn,
            device_id=device["device_id"],
            expected_version=expected,
            reported_version=version,
            source="boot_ok",
        )
        _audit(
            conn,
            action="printellect_update_version_mismatch",
            actor_type="device",
            actor_id=device["device_id"],
            target_type="device",
            target_id=device["device_id"],
            details={"source": "boot_ok", "expected": expected, "reported": version, "error": mismatch},
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=409, detail=mismatch)

    if version:
        conn.execute(
            """
            INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, last_result_json, updated_at)
            VALUES (?, ?, 'success', 100, NULL, NULL, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                target_version = excluded.target_version,
                status = 'success',
                progress = 100,
                last_error = NULL,
                last_result_json = NULL,
                updated_at = excluded.updated_at
            """,
            (device["device_id"], version, now_iso()),
        )
        conn.execute(
            "UPDATE devices SET app_version = COALESCE(?, app_version) WHERE device_id = ?",
            (version, device["device_id"]),
        )

    _audit(
        conn,
        action="printellect_boot_ok",
        actor_type="device",
        actor_id=device["device_id"],
        target_type="device",
        target_id=device["device_id"],
        details={"version": version},
    )
    conn.commit()
    conn.close()
    return ApiOkResponse(ok=True)


@router.post("/api/printellect/admin/devices")
async def admin_create_device(request: Request, admin=Depends(require_admin)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    device_id = (payload.get("device_id") or f"perkbase-{secrets.randbelow(9999):04d}").strip().lower()
    name = (payload.get("name") or device_id).strip()
    claim_code = (payload.get("claim_code") or secrets.token_urlsafe(16)).strip()

    if not device_id:
        raise HTTPException(status_code=422, detail="device_id is required")
    if not claim_code:
        raise HTTPException(status_code=422, detail="claim_code is required")

    conn = db()
    exists = conn.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(status_code=409, detail="device_id already exists")

    conn.execute(
        "INSERT INTO devices (device_id, name, owner_user_id, claim_code_hash, created_at) VALUES (?, ?, NULL, ?, ?)",
        (device_id, name, _claim_hash(claim_code), now_iso()),
    )

    _audit(
        conn,
        action="printellect_device_created",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="device",
        target_id=device_id,
        details={"name": name},
    )

    conn.commit()
    conn.close()

    pairing = _build_pairing_urls(device_id, claim_code, name)
    device_json = _build_device_json(device_id, claim_code)
    return JSONResponse(
        {
            "ok": True,
            "device": {
                "device_id": device_id,
                "name": name,
                "claim_code": claim_code,
                **pairing,
                "device_json": device_json,
            },
        }
    )


@router.post("/api/printellect/admin/devices/{device_id}/claim-code/rotate")
async def admin_rotate_claim_code(device_id: str, admin=Depends(require_admin)):
    claim_code = secrets.token_urlsafe(16)
    conn = db()
    row = conn.execute("SELECT device_id, name FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    conn.execute("UPDATE devices SET claim_code_hash = ? WHERE device_id = ?", (_claim_hash(claim_code), device_id))
    _audit(
        conn,
        action="printellect_claim_code_rotated",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="device",
        target_id=device_id,
    )
    conn.commit()
    conn.close()

    pairing = _build_pairing_urls(device_id, claim_code, row["name"] or device_id)
    device_json = _build_device_json(device_id, claim_code)
    return JSONResponse(
        {
            "ok": True,
            "device_id": device_id,
            "claim_code": claim_code,
            **pairing,
            "device_json": device_json,
        }
    )


def _fetch_admin_device_row(conn: sqlite3.Connection, device_id: str) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT d.*, ds.state_json, us.status as update_status, us.target_version, us.progress, us.last_error, us.last_result_json
        FROM devices d
        LEFT JOIN device_state ds ON ds.device_id = d.device_id
        LEFT JOIN device_update_status us ON us.device_id = d.device_id
        WHERE d.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    return row


@router.patch("/api/printellect/admin/devices/{device_id}")
async def admin_update_device(device_id: str, request: Request, admin=Depends(require_admin)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    updates = {}
    if "name" in payload:
        updates["name"] = (payload.get("name") or device_id).strip()
    if "notes" in payload:
        notes = payload.get("notes")
        updates["notes"] = (str(notes).strip() if notes is not None else None) or None
    if "owner_user_id" in payload:
        owner_user_id = (payload.get("owner_user_id") or "").strip()
        updates["owner_user_id"] = owner_user_id or None

    if not updates:
        raise HTTPException(status_code=422, detail="No updatable fields provided")

    conn = db()
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    new_owner = updates.get("owner_user_id", row["owner_user_id"])
    owner_changed = ("owner_user_id" in updates) and (new_owner != row["owner_user_id"])

    if "owner_user_id" in updates and new_owner:
        account_row = conn.execute("SELECT id FROM accounts WHERE id = ?", (new_owner,)).fetchone()
        if not account_row:
            conn.close()
            raise HTTPException(status_code=422, detail="owner_user_id not found")

    assignments = []
    params: list[Any] = []
    for key in ("name", "notes", "owner_user_id"):
        if key in updates:
            assignments.append(f"{key} = ?")
            params.append(updates[key])

    if owner_changed and not new_owner:
        assignments.append("claimed_at = NULL")
    elif owner_changed and new_owner:
        assignments.append("claimed_at = COALESCE(claimed_at, ?)")
        params.append(now_iso())

    params.append(device_id)
    conn.execute(f"UPDATE devices SET {', '.join(assignments)} WHERE device_id = ?", tuple(params))

    if owner_changed:
        conn.execute(
            "UPDATE device_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
            (now_iso(), device_id),
        )

    _audit(
        conn,
        action="printellect_device_updated",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="device",
        target_id=device_id,
        details={"updates": updates, "owner_changed": owner_changed},
    )
    conn.commit()
    refreshed = _fetch_admin_device_row(conn, device_id)
    conn.close()
    return JSONResponse({"ok": True, "device": _admin_device_payload(refreshed)})


@router.post("/api/printellect/admin/devices/{device_id}/unclaim")
async def admin_unclaim_device(device_id: str, admin=Depends(require_admin)):
    conn = db()
    row = conn.execute("SELECT owner_user_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    conn.execute("UPDATE devices SET owner_user_id = NULL, claimed_at = NULL WHERE device_id = ?", (device_id,))
    conn.execute(
        "UPDATE device_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
        (now_iso(), device_id),
    )
    _audit(
        conn,
        action="printellect_device_unclaimed",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="device",
        target_id=device_id,
        details={"previous_owner": row["owner_user_id"]},
    )
    conn.commit()
    refreshed = _fetch_admin_device_row(conn, device_id)
    conn.close()
    return JSONResponse({"ok": True, "device": _admin_device_payload(refreshed)})


@router.delete("/api/printellect/admin/devices/{device_id}")
async def admin_delete_device(device_id: str, force: bool = False, admin=Depends(require_admin)):
    conn = db()
    row = conn.execute("SELECT owner_user_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    if row["owner_user_id"] and not force:
        conn.close()
        raise HTTPException(status_code=409, detail="Device is claimed. Use force=1 to delete.")

    conn.execute("DELETE FROM device_tokens WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM commands WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM device_state WHERE device_id = ?", (device_id,))
    conn.execute("DELETE FROM device_update_status WHERE device_id = ?", (device_id,))
    conn.execute("UPDATE pairing_sessions SET claimed_device_id = NULL WHERE claimed_device_id = ?", (device_id,))
    conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))

    _audit(
        conn,
        action="printellect_device_deleted",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="device",
        target_id=device_id,
        details={"force": bool(force), "had_owner": bool(row["owner_user_id"])},
    )
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True, "deleted_device_id": device_id})


@router.get("/api/printellect/admin/devices")
async def admin_list_devices(admin=Depends(require_admin)):
    conn = db()
    rows = conn.execute(
        """
        SELECT d.*, ds.state_json, us.status as update_status, us.target_version, us.progress, us.last_error, us.last_result_json
        FROM devices d
        LEFT JOIN device_state ds ON ds.device_id = d.device_id
        LEFT JOIN device_update_status us ON us.device_id = d.device_id
        ORDER BY d.created_at DESC
        """
    ).fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append(_admin_device_payload(row))

    return JSONResponse({"ok": True, "devices": devices})


# --------------- release helpers ---------------


def _next_version(conn: sqlite3.Connection) -> str:
    """Auto-increment the latest release version (minor bump)."""
    row = conn.execute("SELECT version FROM releases ORDER BY created_at DESC LIMIT 1").fetchone()
    if not row:
        return "0.1.0"
    latest = row["version"]
    # Strip any suffix like "-pkg", "-test" etc.
    base = re.split(r"[^0-9.]", latest, maxsplit=1)[0].rstrip(".")
    parts = base.split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        nums = [0, 0, 0]
    while len(nums) < 3:
        nums.append(0)
    nums[1] += 1
    nums[2] = 0
    return ".".join(str(n) for n in nums[:3])


def _finalize_release(
    *,
    version: str,
    channel: str,
    notes: str,
    manifest_json: Dict[str, Any],
    bundle_bytes: bytes,
    bundle_sha256: str,
    admin: Any,
    mode: str = "upload",
) -> JSONResponse:
    """Persist a release to disk + DB and return the standard JSON response."""
    paths = _release_paths(version)
    actor_id = getattr(admin, "id", None)
    conn = db()
    exists = conn.execute("SELECT version FROM releases WHERE version = ?", (version,)).fetchone()
    if exists:
        conn.execute(
            """
            UPDATE releases
            SET channel = ?, notes = ?, manifest_json = ?, bundle_path = ?
            WHERE version = ?
            """,
            (channel, notes.strip() or None, _json_dumps(manifest_json), str(paths["bundle"]), version),
        )
    else:
        conn.execute(
            """
            INSERT INTO releases (version, channel, created_at, created_by_user_id, notes, manifest_json, bundle_path, is_current)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (version, channel, now_iso(), actor_id, notes.strip() or None, _json_dumps(manifest_json), str(paths["bundle"])),
        )

    _audit(
        conn,
        action="printellect_release_uploaded",
        actor_type="user",
        actor_id=actor_id,
        target_type="release",
        target_id=version,
        details={"channel": channel, "mode": mode},
    )
    conn.commit()
    conn.close()

    return JSONResponse(
        {
            "ok": True,
            "version": version,
            "channel": channel,
            "bundle_sha256": bundle_sha256,
            "mode": mode,
            "file_count": len(manifest_json.get("files") or []),
            "safety": manifest_json.get("safety") or {},
        }
    )


@router.post("/api/printellect/admin/releases/upload")
async def admin_upload_release(
    manifest: Optional[UploadFile] = File(None),
    bundle: Optional[UploadFile] = File(None),
    package: Optional[UploadFile] = File(None),
    version: str = Form(""),
    entrypoint: str = Form("main.py"),
    channel: str = Form("stable"),
    notes: str = Form(""),
    admin=Depends(require_admin),
):
    mode = "manifest_bundle"
    bundle_bytes: bytes
    manifest_json: Dict[str, Any] = {}
    embedded_manifest = False

    if package is not None:
        mode = "package"
        bundle_bytes = await package.read()
        if not bundle_bytes:
            raise HTTPException(status_code=422, detail="package zip is empty")
        try:
            with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
                if zf.testzip() is not None:
                    raise HTTPException(status_code=422, detail="package zip is invalid")
                if "manifest.json" in zf.namelist():
                    try:
                        manifest_json = json.loads(zf.read("manifest.json").decode("utf-8"))
                        embedded_manifest = True
                    except Exception:
                        raise HTTPException(status_code=422, detail="embedded manifest.json is invalid JSON")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=422, detail="package must be a valid zip")
        if manifest is not None or bundle is not None:
            raise HTTPException(status_code=422, detail="Use either package zip or manifest+bundle, not both")
    else:
        if manifest is None or bundle is None:
            raise HTTPException(status_code=422, detail="manifest and bundle are required unless package zip is provided")
        manifest_bytes = await manifest.read()
        bundle_bytes = await bundle.read()
        if not bundle_bytes:
            raise HTTPException(status_code=422, detail="bundle zip is empty")
        try:
            manifest_json = json.loads(manifest_bytes.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=422, detail="manifest must be valid JSON")

    version = (version or str(manifest_json.get("version") or "")).strip()
    if not version:
        raise HTTPException(status_code=422, detail="version is required (form field or manifest.version)")

    manifest_channel = str(manifest_json.get("channel") or "").strip()
    if manifest_channel:
        channel = manifest_channel
    if channel not in {"stable", "beta"}:
        raise HTTPException(status_code=422, detail="channel must be stable or beta")

    manifest_json["version"] = version
    manifest_json["channel"] = channel
    manifest_json["entrypoint"] = str(manifest_json.get("entrypoint") or entrypoint or "main.py").strip() or "main.py"

    paths = _release_paths(version)
    paths["root"].mkdir(parents=True, exist_ok=True)
    paths["bundle"].write_bytes(bundle_bytes)
    _extract_bundle(paths["bundle"], paths["extracted"])
    extracted_files = _build_manifest_file_list(
        paths["extracted"],
        exclude_paths={"manifest.json"} if embedded_manifest else None,
    )

    if mode == "package" and not extracted_files:
        raise HTTPException(status_code=422, detail="package zip has no files")

    bundle_sha256 = _hash_bytes(bundle_bytes)
    manifest_json["bundle_sha256"] = bundle_sha256
    manifest_json["bundle_size"] = len(bundle_bytes)

    if not isinstance(manifest_json.get("files"), list) or not manifest_json.get("files"):
        manifest_json["files"] = extracted_files
    else:
        available = {f["path"]: f for f in extracted_files}
        normalized = []
        for item in manifest_json["files"]:
            rel = str(item.get("path") or "").strip().lstrip("/")
            if not rel:
                raise HTTPException(status_code=422, detail="manifest files entries require path")
            if rel not in available:
                raise HTTPException(status_code=422, detail=f"manifest file missing from bundle: {rel}")
            actual = available[rel]
            expected_sha = str(item.get("sha256") or "").strip().lower()
            if expected_sha and expected_sha != actual["sha256"]:
                raise HTTPException(status_code=422, detail=f"sha256 mismatch for {rel}")
            normalized.append(
                {
                    "path": rel,
                    "sha256": actual["sha256"],
                    "size": actual["size"],
                }
            )
        manifest_json["files"] = normalized

    _ensure_release_safety_manifest(manifest_json, extracted_files)
    paths["manifest"].write_text(_json_dumps(manifest_json), encoding="utf-8")

    return _finalize_release(
        version=version,
        channel=channel,
        notes=notes,
        manifest_json=manifest_json,
        bundle_bytes=bundle_bytes,
        bundle_sha256=bundle_sha256,
        admin=admin,
        mode=mode,
    )


@router.post("/api/printellect/admin/releases/{version}/promote")
async def admin_promote_release(version: str, request: Request, admin=Depends(require_admin)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    requested_channel = str(payload.get("channel") or "").strip() or None

    conn = db()
    row = _resolve_release_row(conn, version)
    channel = requested_channel or row["channel"]
    if channel not in {"stable", "beta"}:
        conn.close()
        raise HTTPException(status_code=422, detail="channel must be stable or beta")

    conn.execute("UPDATE releases SET is_current = 0 WHERE channel = ?", (channel,))
    conn.execute("UPDATE releases SET channel = ?, is_current = 1 WHERE version = ?", (channel, version))

    _audit(
        conn,
        action="printellect_release_promoted",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="release",
        target_id=version,
        details={"channel": channel},
    )
    conn.commit()
    conn.close()

    return JSONResponse({"ok": True, "version": version, "channel": channel, "is_current": True})


@router.post("/api/printellect/admin/releases/build")
async def admin_build_from_source(request: Request, admin=Depends(require_admin)):
    """Build a release from the device/pico2w/ source directory."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    channel = str(payload.get("channel") or "stable").strip()
    if channel not in {"stable", "beta"}:
        raise HTTPException(status_code=422, detail="channel must be stable or beta")
    notes = str(payload.get("notes") or "").strip()
    entrypoint = str(payload.get("entrypoint") or "main.py").strip() or "main.py"

    source_dir = Path(DEVICE_SOURCE_DIR)
    if not source_dir.is_dir():
        raise HTTPException(
            status_code=500,
            detail=(
                f"Device source directory not found: {DEVICE_SOURCE_DIR}. "
                "Container/image is likely missing the device source tree; "
                "set DEVICE_SOURCE_DIR correctly or use Upload Release zip."
            ),
        )

    # Auto-increment version
    conn = db()
    version = _next_version(conn)
    conn.close()

    # Collect firmware source files (exclude non-firmware files)
    exclude_names = {"__pycache__", ".git", ".DS_Store"}
    exclude_suffixes = {".example", ".example.json"}
    exclude_files = {"README.md", "config.example.json", "device.json.example"}

    buf = io.BytesIO()
    file_count = 0
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if not file_path.is_file():
                continue
            # Skip excluded dirs
            if any(part in exclude_names for part in file_path.parts):
                continue
            rel = file_path.relative_to(source_dir).as_posix()
            if file_path.name in exclude_files:
                continue
            if any(rel.endswith(s) for s in exclude_suffixes):
                continue
            zf.write(file_path, rel)
            file_count += 1

    if file_count == 0:
        raise HTTPException(status_code=422, detail="No firmware source files found in device source directory")

    bundle_bytes = buf.getvalue()
    bundle_sha256 = _hash_bytes(bundle_bytes)

    # Write release to disk
    paths = _release_paths(version)
    paths["root"].mkdir(parents=True, exist_ok=True)
    paths["bundle"].write_bytes(bundle_bytes)
    _extract_bundle(paths["bundle"], paths["extracted"])
    extracted_files = _build_manifest_file_list(paths["extracted"])

    manifest_json = {
        "version": version,
        "channel": channel,
        "entrypoint": entrypoint,
        "bundle_sha256": bundle_sha256,
        "bundle_size": len(bundle_bytes),
        "files": extracted_files,
    }
    _ensure_release_safety_manifest(manifest_json, extracted_files)
    paths["manifest"].write_text(_json_dumps(manifest_json), encoding="utf-8")

    return _finalize_release(
        version=version,
        channel=channel,
        notes=notes,
        manifest_json=manifest_json,
        bundle_bytes=bundle_bytes,
        bundle_sha256=bundle_sha256,
        admin=admin,
        mode="build",
    )


@router.delete("/api/printellect/admin/releases/{version}")
async def admin_delete_release(version: str, admin=Depends(require_admin)):
    """Delete a release. Cannot delete a release that is_current."""
    conn = db()
    row = _resolve_release_row(conn, version)
    if row["is_current"]:
        conn.close()
        raise HTTPException(status_code=409, detail="Cannot delete the current release — demote it first")

    conn.execute("DELETE FROM releases WHERE version = ?", (version,))
    _audit(
        conn,
        action="printellect_release_deleted",
        actor_type="user",
        actor_id=getattr(admin, "id", None),
        target_type="release",
        target_id=version,
    )
    conn.commit()
    conn.close()

    # Remove release files from disk
    paths = _release_paths(version)
    if paths["root"].exists():
        shutil.rmtree(paths["root"], ignore_errors=True)

    return JSONResponse({"ok": True, "version": version, "deleted": True})


@router.post("/api/printellect/admin/releases/{version}/push")
async def admin_push_release(version: str, request: Request, admin=Depends(require_admin)):
    """Push an OTA update command to devices.

    Modes:
    - all (default): all claimed devices (or filtered subset)
    - canary: a small online subset (default 1) before broad rollout
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    conn = db()
    _resolve_release_row(conn, version)

    # Optionally filter by device_ids
    device_ids = payload.get("device_ids") or []
    mode = str(payload.get("mode") or "all").strip().lower()
    if mode not in {"all", "canary"}:
        conn.close()
        raise HTTPException(status_code=422, detail="mode must be all or canary")
    limit = payload.get("limit")
    if limit is None:
        limit = 1 if mode == "canary" else 0
    try:
        limit = int(limit)
    except Exception:
        conn.close()
        raise HTTPException(status_code=422, detail="limit must be an integer")
    if limit < 0 or limit > 1000:
        conn.close()
        raise HTTPException(status_code=422, detail="limit must be between 0 and 1000")
    online_only = bool(payload.get("online_only", mode == "canary"))

    if device_ids:
        placeholders = ",".join("?" for _ in device_ids)
        rows = conn.execute(
            f"SELECT * FROM devices WHERE owner_user_id IS NOT NULL AND device_id IN ({placeholders})",
            device_ids,
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM devices WHERE owner_user_id IS NOT NULL").fetchall()

    selected_rows = list(rows)
    if online_only:
        selected_rows = [r for r in selected_rows if _is_online(r["last_seen_at"])]
    if mode == "canary":
        canary_limit = limit or 1
        selected_rows = selected_rows[:canary_limit]
    elif limit > 0:
        selected_rows = selected_rows[:limit]

    actor_id = getattr(admin, "id", None) or "admin"
    pushed = 0
    pushed_device_ids: list[str] = []
    ts = now_iso()
    for device_row in selected_rows:
        _enqueue_command(
            conn,
            device_row,
            actor_id,
            "ota_apply",
            {"version": version},
            require_online=False,
        )
        # Upsert device_update_status
        conn.execute(
            """
            INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, last_result_json, updated_at)
            VALUES (?, ?, 'available', 0, NULL, NULL, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                target_version = excluded.target_version,
                status = 'available',
                progress = 0,
                last_error = NULL,
                last_result_json = NULL,
                updated_at = excluded.updated_at
            """,
            (device_row["device_id"], version, ts),
        )
        pushed += 1
        pushed_device_ids.append(device_row["device_id"])

    _audit(
        conn,
        action="printellect_release_pushed",
        actor_type="user",
        actor_id=actor_id,
        target_type="release",
        target_id=version,
        details={
            "devices_pushed": pushed,
            "mode": mode,
            "online_only": online_only,
            "limit": limit,
            "device_ids": pushed_device_ids,
        },
    )
    conn.commit()
    conn.close()

    return JSONResponse(
        {
            "ok": True,
            "version": version,
            "mode": mode,
            "online_only": online_only,
            "devices_pushed": pushed,
            "device_ids": pushed_device_ids,
        }
    )


@router.get("/api/printellect/admin/releases")
async def admin_list_releases(admin=Depends(require_admin)):
    conn = db()
    rows = conn.execute("SELECT * FROM releases ORDER BY created_at DESC").fetchall()
    conn.close()

    releases = []
    for row in rows:
        releases.append(
            {
                "version": row["version"],
                "channel": row["channel"],
                "created_at": row["created_at"],
                "created_by_user_id": row["created_by_user_id"],
                "notes": row["notes"],
                "is_current": bool(row["is_current"]),
                "manifest": _json_loads(row["manifest_json"], {}),
            }
        )

    return JSONResponse({"ok": True, "releases": releases})


@router.get("/api/printellect/admin/update-status")
async def admin_update_status(admin=Depends(require_admin)):
    conn = db()
    rows = conn.execute(
        """
        SELECT
            d.device_id,
            d.name,
            d.owner_user_id,
            d.fw_version,
            d.app_version,
            dus.target_version,
            dus.status,
            dus.progress,
            dus.last_error,
            dus.last_result_json,
            dus.updated_at
        FROM devices d
        LEFT JOIN device_update_status dus ON dus.device_id = d.device_id
        ORDER BY d.device_id
        """
    ).fetchall()
    conn.close()

    return JSONResponse(
        {
            "ok": True,
            "devices": [
                {
                    "device_id": row["device_id"],
                    "name": row["name"],
                    "owner_user_id": row["owner_user_id"],
                    "fw_version": row["fw_version"],
                    "app_version": row["app_version"],
                    "target_version": row["target_version"],
                    "status": row["status"] or "idle",
                    "progress": row["progress"] if row["progress"] is not None else 0,
                    "last_error": row["last_error"],
                    "result": _json_loads(row["last_result_json"], {}),
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ],
        }
    )
