import json
import logging
import mimetypes
import os
import sqlite3
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from app.auth import is_feature_enabled, require_account, require_admin
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

ONLINE_WINDOW_SECONDS = int(os.getenv("DEVICE_ONLINE_WINDOW_SECONDS", "60"))
DEVICE_MIN_POLL_SECONDS = float(os.getenv("DEVICE_MIN_POLL_SECONDS", "1.0"))
PROVISION_POLL_INTERVAL_MS = int(os.getenv("DEVICE_PROVISION_POLL_MS", "1000"))
RELEASES_DIR = os.getenv("RELEASES_DIR", os.path.join("local_data", "releases"))
PAIRING_SESSION_MINUTES = int(os.getenv("PAIRING_SESSION_MINUTES", "10"))
PRINTELLECT_FEATURE_KEY = os.getenv("PRINTELLECT_FEATURE_KEY", "printellect_device_control")

_poll_lock = threading.Lock()
_last_poll_at: Dict[str, float] = {}
_claim_fail_lock = threading.Lock()
_claim_failures: Dict[str, list[float]] = {}
MAX_CLAIM_FAILURES = int(os.getenv("PRINTELLECT_MAX_CLAIM_FAILURES", "8"))
CLAIM_FAIL_WINDOW_SECONDS = int(os.getenv("PRINTELLECT_CLAIM_FAIL_WINDOW_S", "300"))


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


def _is_online(last_seen_at: Optional[str]) -> bool:
    ts = _parse_iso(last_seen_at)
    if not ts:
        return False
    return (datetime.now(ts.tzinfo) - ts) <= timedelta(seconds=ONLINE_WINDOW_SECONDS)


def _safe_release_join(base: Path, rel_path: str) -> Path:
    candidate = (base / rel_path).resolve()
    base_resolved = base.resolve()
    if base_resolved == candidate or base_resolved in candidate.parents:
        return candidate
    raise HTTPException(status_code=400, detail="Invalid release path")


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


def _get_device_for_owner(conn: sqlite3.Connection, device_id: str, owner_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    if row["owner_user_id"] != owner_id:
        raise HTTPException(status_code=403, detail="Not allowed for this device")
    return row


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
        pattern = payload.get("pattern")
        duration_ms = payload.get("duration_ms")
        if not isinstance(pattern, str) or not pattern.strip():
            raise HTTPException(status_code=422, detail="pattern is required")
        if not isinstance(duration_ms, int) or duration_ms <= 0:
            raise HTTPException(status_code=422, detail="duration_ms must be a positive integer")
        return {"pattern": pattern.strip(), "duration_ms": duration_ms}

    if action == "test_audio":
        track_id = payload.get("track_id")
        if not isinstance(track_id, str) or not track_id.strip():
            raise HTTPException(status_code=422, detail="track_id is required")
        return {"track_id": track_id.strip()}

    if action == "ota_apply":
        version = payload.get("version")
        if not isinstance(version, str) or not version.strip():
            raise HTTPException(status_code=422, detail="version is required")
        return {"version": version.strip()}

    return {}


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
            (cmd_id, device_id, action, payload_json, status, created_at, updated_at, requested_by_user_id)
        VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)
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


def _build_manifest_file_list(extracted_dir: Path) -> list[Dict[str, Any]]:
    files: list[Dict[str, Any]] = []
    if not extracted_dir.exists():
        return files

    for file_path in sorted(extracted_dir.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(extracted_dir).as_posix()
        files.append(
            {
                "path": rel,
                "sha256": _hash_file(file_path),
                "size": file_path.stat().st_size,
            }
        )
    return files


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
    if not is_feature_enabled(
        PRINTELLECT_FEATURE_KEY,
        user_id=getattr(account, "id", None),
        email=getattr(account, "email", None),
    ):
        raise HTTPException(status_code=403, detail="Printellect feature is not enabled for this account")
    return account


@router.get("/printellect/devices", response_class=HTMLResponse)
async def devices_page(request: Request, account=Depends(_require_printellect_account)):
    return templates.TemplateResponse("devices.html", {"request": request, "account": account})


@router.get("/printellect/add-device", response_class=HTMLResponse)
async def add_device_wizard_page(request: Request, account=Depends(_require_printellect_account)):
    return templates.TemplateResponse("device_add_wizard.html", {"request": request, "account": account})


@router.get("/printellect/devices/{device_id}", response_class=HTMLResponse)
async def owner_device_detail_page(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    conn = db()
    _get_device_for_owner(conn, device_id, account.id)
    conn.close()
    return templates.TemplateResponse(
        "device_detail.html",
        {"request": request, "account": account, "device_id": device_id},
    )


@router.get("/admin/printellect/devices", response_class=HTMLResponse)
async def admin_devices_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("admin_printellect_devices.html", {"request": request, "admin": admin})


@router.get("/admin/printellect/releases", response_class=HTMLResponse)
async def admin_releases_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("admin_printellect_releases.html", {"request": request, "admin": admin})


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
        details={"session_id": session_id or None},
    )
    conn.commit()
    conn.close()
    _clear_claim_failures(request, device_id, claim_code)

    return JSONResponse({"status": "claimed", "device_id": device_id, "next": "wait_for_online"})


@router.get("/api/printellect/devices")
async def list_devices(account=Depends(_require_printellect_account)):
    conn = db()
    rows = conn.execute(
        """
        SELECT d.*, ds.state_json, us.status as update_status, us.target_version, us.progress, us.last_error
        FROM devices d
        LEFT JOIN device_state ds ON ds.device_id = d.device_id
        LEFT JOIN device_update_status us ON us.device_id = d.device_id
        WHERE d.owner_user_id = ?
        ORDER BY d.created_at DESC
        """,
        (account.id,),
    ).fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append(
            {
                "device_id": row["device_id"],
                "name": row["name"],
                "last_seen_at": row["last_seen_at"],
                "online": _is_online(row["last_seen_at"]),
                "fw_version": row["fw_version"],
                "app_version": row["app_version"],
                "rssi": row["rssi"],
                "state": _json_loads(row["state_json"], {}),
                "update_status": {
                    "status": row["update_status"] or "idle",
                    "target_version": row["target_version"],
                    "progress": row["progress"] if row["progress"] is not None else 0,
                    "last_error": row["last_error"],
                },
            }
        )

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
                "state": _json_loads(state_row["state_json"] if state_row else None, {}),
                "state_updated_at": state_row["updated_at"] if state_row else None,
                "update_status": {
                    "status": update_row["status"] if update_row else "idle",
                    "target_version": update_row["target_version"] if update_row else None,
                    "progress": update_row["progress"] if update_row else 0,
                    "last_error": update_row["last_error"] if update_row else None,
                    "updated_at": update_row["updated_at"] if update_row else None,
                },
                "recent_commands": [
                    {
                        "cmd_id": r["cmd_id"],
                        "action": r["action"],
                        "payload": _json_loads(r["payload_json"], {}),
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


async def _enqueue_user_action(
    device_id: str,
    account,
    action: str,
    request: Optional[Request] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
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

    return JSONResponse({"ok": True, "cmd_id": cmd_id, "action": action, "payload": payload_clean})


@router.post("/api/printellect/devices/{device_id}/actions/play")
async def action_play(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "play_perk", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/stop")
async def action_stop(device_id: str, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "stop_audio", payload={})


@router.post("/api/printellect/devices/{device_id}/actions/idle")
async def action_idle(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_idle", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/brightness")
async def action_brightness(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_brightness", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/volume")
async def action_volume(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "set_volume", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/test-lights")
async def action_test_lights(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "test_lights", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/test-audio")
async def action_test_audio(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "test_audio", request=request)


@router.post("/api/printellect/devices/{device_id}/actions/reboot")
async def action_reboot(device_id: str, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "reboot", payload={})


@router.post("/api/printellect/devices/{device_id}/actions/update")
async def action_update(device_id: str, request: Request, account=Depends(_require_printellect_account)):
    return await _enqueue_user_action(device_id, account, "ota_apply", request=request)


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

    fw_version = payload.get("fw_version")
    app_version = payload.get("app_version")
    rssi = payload.get("rssi")
    if rssi is not None:
        try:
            rssi = int(rssi)
        except Exception:
            rssi = None

    conn = db()
    conn.execute(
        """
        UPDATE devices
        SET last_seen_at = ?, fw_version = COALESCE(?, fw_version), app_version = COALESCE(?, app_version), rssi = COALESCE(?, rssi)
        WHERE device_id = ?
        """,
        (now_iso(), fw_version, app_version, rssi, device["device_id"]),
    )

    reset_event = payload.get("reset_event")
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


@router.get("/api/printellect/device/v1/commands/next")
async def device_next_command(device=Depends(_device_from_bearer)):
    device_id = device["device_id"]
    now_mono = time.monotonic()
    with _poll_lock:
        last = _last_poll_at.get(device_id)
        if last is not None and (now_mono - last) < DEVICE_MIN_POLL_SECONDS:
            retry_after = max(1, int(DEVICE_MIN_POLL_SECONDS - (now_mono - last)))
            raise HTTPException(status_code=429, detail="Poll interval too frequent", headers={"Retry-After": str(retry_after)})
        _last_poll_at[device_id] = now_mono

    conn = db()

    inflight = conn.execute(
        "SELECT cmd_id FROM commands WHERE device_id = ? AND status IN ('delivered','executing') ORDER BY created_at LIMIT 1",
        (device_id,),
    ).fetchone()
    if inflight:
        conn.close()
        return Response(status_code=204)

    row = conn.execute(
        "SELECT * FROM commands WHERE device_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 1",
        (device_id,),
    ).fetchone()
    if not row:
        conn.close()
        return Response(status_code=204)

    ts = now_iso()
    conn.execute("UPDATE commands SET status = 'delivered', delivered_at = ?, updated_at = ? WHERE cmd_id = ?", (ts, ts, row["cmd_id"]))
    _audit(
        conn,
        action="printellect_command_delivered",
        actor_type="device",
        actor_id=device_id,
        target_type="command",
        target_id=row["cmd_id"],
        details={"action": row["action"]},
    )
    conn.commit()
    conn.close()

    return JSONResponse(
        {
            "cmd_id": row["cmd_id"],
            "action": row["action"],
            "payload": _json_loads(row["payload_json"], {}),
            "created_at": row["created_at"],
        }
    )


@router.post("/api/printellect/device/v1/commands/{cmd_id}/status")
async def device_command_status(cmd_id: str, request: Request, device=Depends(_device_from_bearer)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    status = (payload.get("status") or "").strip().lower()
    error = payload.get("error")
    if status not in {"executing", "completed", "failed"}:
        raise HTTPException(status_code=422, detail="status must be executing|completed|failed")

    conn = db()
    row = conn.execute("SELECT * FROM commands WHERE cmd_id = ? AND device_id = ?", (cmd_id, device["device_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Command not found")

    ts = now_iso()
    if status == "executing":
        conn.execute(
            "UPDATE commands SET status = 'executing', executing_at = COALESCE(executing_at, ?), updated_at = ? WHERE cmd_id = ?",
            (ts, ts, cmd_id),
        )
    elif status == "completed":
        conn.execute(
            "UPDATE commands SET status = 'completed', completed_at = ?, updated_at = ?, error = NULL WHERE cmd_id = ?",
            (ts, ts, cmd_id),
        )
    else:
        conn.execute(
            "UPDATE commands SET status = 'failed', completed_at = ?, updated_at = ?, error = ? WHERE cmd_id = ?",
            (ts, ts, str(error) if error else "unknown", cmd_id),
        )

    _audit(
        conn,
        action="printellect_command_status",
        actor_type="device",
        actor_id=device["device_id"],
        target_type="command",
        target_id=cmd_id,
        details={"status": status, "error": error},
    )
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


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


@router.post("/api/printellect/device/v1/update/status")
async def device_update_status(request: Request, device=Depends(_device_from_bearer)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    status = (payload.get("status") or "").strip().lower()
    target_version = (payload.get("version") or payload.get("target_version") or "").strip() or None
    progress = payload.get("progress")
    last_error = payload.get("error")

    valid = {"idle", "available", "downloading", "applying", "success", "rollback", "failed"}
    if status not in valid:
        raise HTTPException(status_code=422, detail="Invalid update status")

    if not isinstance(progress, int):
        progress = 0
    progress = max(0, min(100, progress))

    conn = db()
    conn.execute(
        """
        INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            target_version = excluded.target_version,
            status = excluded.status,
            progress = excluded.progress,
            last_error = excluded.last_error,
            updated_at = excluded.updated_at
        """,
        (device["device_id"], target_version, status, progress, str(last_error) if last_error else None, now_iso()),
    )

    _audit(
        conn,
        action="printellect_update_status",
        actor_type="device",
        actor_id=device["device_id"],
        target_type="device",
        target_id=device["device_id"],
        details={"status": status, "target_version": target_version, "progress": progress, "error": last_error},
    )
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


@router.post("/api/printellect/device/v1/boot-ok")
async def device_boot_ok(request: Request, device=Depends(_device_from_bearer)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    version = (payload.get("version") or "").strip() or None

    conn = db()
    if version:
        conn.execute(
            """
            INSERT INTO device_update_status (device_id, target_version, status, progress, last_error, updated_at)
            VALUES (?, ?, 'success', 100, NULL, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                target_version = excluded.target_version,
                status = 'success',
                progress = 100,
                last_error = NULL,
                updated_at = excluded.updated_at
            """,
            (device["device_id"], version, now_iso()),
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
    return JSONResponse({"ok": True})


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

    return JSONResponse(
        {
            "ok": True,
            "device": {
                "device_id": device_id,
                "name": name,
                "claim_code": claim_code,
                "qr_payload": f"printellect://pair?device_id={device_id}&claim={claim_code}",
                "fallback_url": f"https://print.jcubhub.com/pair?device_id={device_id}&claim={claim_code}",
            },
        }
    )


@router.post("/api/printellect/admin/devices/{device_id}/claim-code/rotate")
async def admin_rotate_claim_code(device_id: str, admin=Depends(require_admin)):
    claim_code = secrets.token_urlsafe(16)
    conn = db()
    row = conn.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
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

    return JSONResponse(
        {
            "ok": True,
            "device_id": device_id,
            "claim_code": claim_code,
            "qr_payload": f"printellect://pair?device_id={device_id}&claim={claim_code}",
            "fallback_url": f"https://print.jcubhub.com/pair?device_id={device_id}&claim={claim_code}",
        }
    )


@router.get("/api/printellect/admin/devices")
async def admin_list_devices(admin=Depends(require_admin)):
    conn = db()
    rows = conn.execute(
        """
        SELECT d.*, ds.state_json, us.status as update_status, us.target_version, us.progress, us.last_error
        FROM devices d
        LEFT JOIN device_state ds ON ds.device_id = d.device_id
        LEFT JOIN device_update_status us ON us.device_id = d.device_id
        ORDER BY d.created_at DESC
        """
    ).fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append(
            {
                "device_id": row["device_id"],
                "name": row["name"],
                "owner_user_id": row["owner_user_id"],
                "claimed": bool(row["owner_user_id"]),
                "last_seen_at": row["last_seen_at"],
                "online": _is_online(row["last_seen_at"]),
                "fw_version": row["fw_version"],
                "app_version": row["app_version"],
                "state": _json_loads(row["state_json"], {}),
                "update": {
                    "status": row["update_status"] or "idle",
                    "target_version": row["target_version"],
                    "progress": row["progress"] if row["progress"] is not None else 0,
                    "last_error": row["last_error"],
                },
            }
        )

    return JSONResponse({"ok": True, "devices": devices})


@router.post("/api/printellect/admin/releases/upload")
async def admin_upload_release(
    manifest: UploadFile = File(...),
    bundle: UploadFile = File(...),
    channel: str = Form("stable"),
    notes: str = Form(""),
    admin=Depends(require_admin),
):
    manifest_bytes = await manifest.read()
    bundle_bytes = await bundle.read()

    try:
        manifest_json = json.loads(manifest_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=422, detail="manifest must be valid JSON")

    version = str(manifest_json.get("version") or "").strip()
    if not version:
        raise HTTPException(status_code=422, detail="manifest.version is required")

    manifest_channel = str(manifest_json.get("channel") or "").strip()
    if manifest_channel:
        channel = manifest_channel

    if channel not in {"stable", "beta"}:
        raise HTTPException(status_code=422, detail="channel must be stable or beta")

    paths = _release_paths(version)
    paths["root"].mkdir(parents=True, exist_ok=True)

    paths["manifest"].write_bytes(manifest_bytes)
    paths["bundle"].write_bytes(bundle_bytes)

    _extract_bundle(paths["bundle"], paths["extracted"])
    extracted_files = _build_manifest_file_list(paths["extracted"])

    bundle_sha256 = _hash_bytes(bundle_bytes)
    manifest_json["bundle_sha256"] = bundle_sha256
    manifest_json["bundle_size"] = len(bundle_bytes)
    manifest_json["channel"] = channel
    manifest_json["version"] = version

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

    paths["manifest"].write_text(_json_dumps(manifest_json), encoding="utf-8")

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
        details={"channel": channel},
    )
    conn.commit()
    conn.close()

    return JSONResponse({"ok": True, "version": version, "channel": channel, "bundle_sha256": bundle_sha256})


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
        SELECT d.device_id, d.name, d.owner_user_id, dus.target_version, dus.status, dus.progress, dus.last_error, dus.updated_at
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
                    "target_version": row["target_version"],
                    "status": row["status"] or "idle",
                    "progress": row["progress"] if row["progress"] is not None else 0,
                    "last_error": row["last_error"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ],
        }
    )
