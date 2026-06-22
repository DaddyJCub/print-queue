"""
Print-queue printer agent API.

This module powers cross-network printers that cannot be reached directly from
the server (e.g. a Longer LK5 Pro connected over USB to a Windows PC that lives
on a *separate* network from the print-queue container).

Instead of the server reaching *into* the printer's LAN (the FlashForge /
Moonraker model in ``app.main``), a small **agent** runs next to the printer and
makes only **outbound** HTTPS calls to this API:

    provision (claim code -> bearer token)
        -> heartbeat (report printer status / telemetry)
        -> GET jobs/next (claim a queued print job)
        -> GET jobs/{id}/file (download the sliced .gcode)
        -> POST jobs/{id}/status (stream progress + lifecycle)
        -> POST snapshot (optional webcam frame)

Because the agent only dials out, there are **no inbound ports** to open and the
channel is authenticated with a per-agent bearer token over TLS. This mirrors
the existing Printellect device contract (``app.printellect``) but is scoped to
3D-print jobs rather than IoT light/sound perks.

The Windows agent implementation lives under ``windows-agent/``.
"""

import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from app.auth import require_admin
from app.printellect_service import claim_hash, generate_device_token, token_hash, verify_claim_code

router = APIRouter(tags=["printer-agent"])

API_PREFIX = "/api/printer-agent/v1"
ADMIN_PREFIX = "/api/printer-agent/admin"

# An agent is "online" if we have seen a heartbeat within this window.
AGENT_ONLINE_WINDOW_SECONDS = int(os.getenv("AGENT_ONLINE_WINDOW_SECONDS", "120"))
# How often the agent should heartbeat / poll (advertised in provision response).
AGENT_HEARTBEAT_INTERVAL_S = int(os.getenv("AGENT_HEARTBEAT_INTERVAL_S", "15"))
AGENT_POLL_INTERVAL_S = int(os.getenv("AGENT_POLL_INTERVAL_S", "5"))
# Long-poll cap for jobs/stream.
AGENT_STREAM_MAX_SECONDS = int(os.getenv("AGENT_STREAM_MAX_SECONDS", "25"))
AGENT_STREAM_POLL_STEP_SECONDS = max(0.1, float(os.getenv("AGENT_STREAM_POLL_STEP_SECONDS", "0.5")))

# Brute-force protection on the claim code (per agent_id).
MAX_CLAIM_FAILURES = int(os.getenv("AGENT_MAX_CLAIM_FAILURES", "8"))
CLAIM_FAIL_WINDOW_SECONDS = int(os.getenv("AGENT_CLAIM_FAIL_WINDOW_S", "300"))
_claim_failures: Dict[str, List[float]] = {}

# Job lifecycle. ``queued`` is enqueued by an admin ("Send to LK5"); the agent
# drives it through the remaining states and reports them back.
JOB_STATUSES = {
    "queued",      # waiting for an agent to claim
    "claimed",     # agent fetched it, downloading
    "uploading",   # streaming gcode to the printer's SD card
    "printing",    # SD print running
    "paused",
    "completed",
    "failed",
    "canceled",
}
JOB_TERMINAL = {"completed", "failed", "canceled"}

# Remote-management commands the server may send to an agent (Printellect-style).
AGENT_COMMAND_ACTIONS = {
    "restart_agent",   # exit so the service manager restarts a fresh process
    "reboot_host",     # reboot the Pi/PC
    "reload_config",   # re-read config.json
    "get_logs",        # return recent agent log lines in the command result
    "identify",        # blink/log so an operator can find the unit
    "update_agent",    # download a new agent bundle, self-update, restart (OTA)
    "flash_firmware",  # flash printer firmware (.hex) via avrdude — opt-in on agent
}
COMMAND_STATUSES = {"queued", "delivered", "executing", "completed", "failed"}
COMMAND_TERMINAL = {"completed", "failed"}

# Directories where uploaded agent OTA bundles (.zip) and printer firmware
# (.hex) are stored.
AGENT_RELEASES_DIR = os.getenv("AGENT_RELEASES_DIR", os.path.join("local_data", "agent_releases"))
FIRMWARE_DIR = os.getenv("AGENT_FIRMWARE_DIR", os.path.join("local_data", "printer_firmware"))

# Printer codes that are serviced by an agent rather than a direct LAN API.
AGENT_PRINTER_CODES = {"LK5_PRO"}

INGEST_TOKEN_SETTING = "printer_agent_ingest_token"


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("DB_PATH", "/data/app.db"), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def upload_dir() -> str:
    return os.getenv("UPLOAD_DIR", "/uploads")


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return "{}"


def _json_loads(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


# ──────────────────────────── schema ────────────────────────────

def init_printer_agent_tables(cur: sqlite3.Cursor) -> None:
    """Create agent tables. Safe to call repeatedly (used from init_db)."""
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT,
            printer_code TEXT NOT NULL,
            claim_code_hash TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            claimed_at TEXT,
            last_seen_at TEXT,
            agent_version TEXT,
            status_json TEXT,
            notes TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agent_tokens (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT,
            FOREIGN KEY(agent_id) REFERENCES printer_agents(agent_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agent_jobs (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            request_id TEXT,
            file_id TEXT,
            file_name TEXT,
            stored_filename TEXT,
            sha256 TEXT,
            size_bytes INTEGER,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT,
            claimed_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY(agent_id) REFERENCES printer_agents(agent_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agent_snapshots (
            agent_id TEXT PRIMARY KEY,
            image BLOB,
            content_type TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(agent_id) REFERENCES printer_agents(agent_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agent_commands (
            cmd_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            payload_json TEXT,
            status TEXT NOT NULL,
            result_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT,
            delivered_at TEXT,
            completed_at TEXT,
            FOREIGN KEY(agent_id) REFERENCES printer_agents(agent_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_agent_releases (
            version TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            created_by TEXT,
            notes TEXT,
            bundle_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_firmware (
            version TEXT PRIMARY KEY,
            printer_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            notes TEXT,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_tokens_lookup ON printer_agent_tokens(token_hash, revoked_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_jobs_queue ON printer_agent_jobs(agent_id, status, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agents_printer ON printer_agents(printer_code, last_seen_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_agent_commands_queue ON printer_agent_commands(agent_id, status, created_at)")


# ──────────────────────────── settings / ingest token ────────────────────────────

def _get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        (key, value, now_iso()),
    )


def get_or_create_ingest_token(conn: sqlite3.Connection) -> str:
    """Static token the Cura post-processing uploader presents to ingest gcode."""
    token = _get_setting(conn, INGEST_TOKEN_SETTING, "")
    if not token:
        token = secrets.token_urlsafe(24)
        _set_setting(conn, INGEST_TOKEN_SETTING, token)
        conn.commit()
    return token


# ──────────────────────────── auth helpers ────────────────────────────

def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


async def _agent_from_bearer(request: Request) -> sqlite3.Row:
    token = _bearer_token(request)
    conn = db()
    try:
        token_row = conn.execute(
            """
            SELECT t.id AS token_id, t.agent_id AS agent_id
            FROM printer_agent_tokens t
            WHERE t.token_hash = ? AND t.revoked_at IS NULL
            ORDER BY t.created_at DESC
            LIMIT 1
            """,
            (token_hash(token),),
        ).fetchone()
        if not token_row:
            raise HTTPException(status_code=401, detail="Invalid token")

        agent = conn.execute(
            "SELECT * FROM printer_agents WHERE agent_id = ?", (token_row["agent_id"],)
        ).fetchone()
        if not agent or agent["revoked"]:
            raise HTTPException(status_code=401, detail="Unknown or revoked agent")

        conn.execute(
            "UPDATE printer_agent_tokens SET last_used_at = ? WHERE id = ?",
            (now_iso(), token_row["token_id"]),
        )
        conn.commit()
        return agent
    finally:
        conn.close()


def _record_claim_failure(agent_id: str) -> None:
    now = time.time()
    window = _claim_failures.setdefault(agent_id, [])
    window.append(now)
    cutoff = now - CLAIM_FAIL_WINDOW_SECONDS
    _claim_failures[agent_id] = [t for t in window if t >= cutoff]


def _claim_rate_limited(agent_id: str) -> bool:
    now = time.time()
    cutoff = now - CLAIM_FAIL_WINDOW_SECONDS
    window = [t for t in _claim_failures.get(agent_id, []) if t >= cutoff]
    _claim_failures[agent_id] = window
    return len(window) >= MAX_CLAIM_FAILURES


# ──────────────────────────── request models ────────────────────────────

class ProvisionRequest(BaseModel):
    agent_id: str
    claim_code: str
    agent_version: Optional[str] = None


class HeartbeatRequest(BaseModel):
    agent_version: Optional[str] = None
    printer: Optional[Dict[str, Any]] = None


class JobStatusRequest(BaseModel):
    status: str
    progress: Optional[int] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class CreateAgentRequest(BaseModel):
    name: str
    printer_code: str = "LK5_PRO"
    notes: Optional[str] = None


class EnqueueJobRequest(BaseModel):
    file_id: str
    request_id: Optional[str] = None


# ──────────────────────────── device-facing endpoints ────────────────────────────

@router.get(API_PREFIX + "/debug")
async def agent_debug():
    """Compact contract the agent can fetch for discovery / debugging."""
    return {
        "auth": "Authorization: Bearer <agent_token>",
        "job_statuses": sorted(JOB_STATUSES),
        "online_window_s": AGENT_ONLINE_WINDOW_SECONDS,
        "heartbeat_interval_s": AGENT_HEARTBEAT_INTERVAL_S,
        "poll_interval_s": AGENT_POLL_INTERVAL_S,
        "endpoints": {
            "provision": API_PREFIX + "/provision",
            "heartbeat": API_PREFIX + "/heartbeat",
            "jobs_next": API_PREFIX + "/jobs/next",
            "jobs_stream": API_PREFIX + "/jobs/stream",
            "job_file": API_PREFIX + "/jobs/{job_id}/file",
            "job_status": API_PREFIX + "/jobs/{job_id}/status",
            "snapshot": API_PREFIX + "/snapshot",
        },
        "openapi": "/openapi.json",
    }


@router.post(API_PREFIX + "/provision")
async def provision(body: ProvisionRequest):
    agent_id = body.agent_id.strip()
    if not agent_id:
        raise HTTPException(status_code=422, detail="agent_id required")

    if _claim_rate_limited(agent_id):
        return JSONResponse(
            {"detail": "Too many failed claim attempts"},
            status_code=429,
            headers={"Retry-After": str(CLAIM_FAIL_WINDOW_SECONDS)},
        )

    conn = db()
    try:
        agent = conn.execute("SELECT * FROM printer_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent or agent["revoked"]:
            _record_claim_failure(agent_id)
            raise HTTPException(status_code=403, detail="Unknown or revoked agent")

        if not verify_claim_code(body.claim_code, agent["claim_code_hash"]):
            _record_claim_failure(agent_id)
            raise HTTPException(status_code=403, detail="Invalid claim code")

        now = now_iso()
        token = generate_device_token(32)
        # Single active token per agent: revoke previous tokens on (re)provision.
        conn.execute(
            "UPDATE printer_agent_tokens SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
            (now, agent_id),
        )
        conn.execute(
            "INSERT INTO printer_agent_tokens (id, agent_id, token_hash, created_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), agent_id, token_hash(token), now, now),
        )
        conn.execute(
            "UPDATE printer_agents SET claimed_at = COALESCE(claimed_at, ?), last_seen_at = ?, agent_version = ? WHERE agent_id = ?",
            (now, now, body.agent_version, agent_id),
        )
        conn.commit()
        _claim_failures.pop(agent_id, None)
        return {
            "status": "provisioned",
            "agent_token": token,
            "printer_code": agent["printer_code"],
            "heartbeat_interval_s": AGENT_HEARTBEAT_INTERVAL_S,
            "poll_interval_s": AGENT_POLL_INTERVAL_S,
        }
    finally:
        conn.close()


@router.post(API_PREFIX + "/heartbeat")
async def heartbeat(body: HeartbeatRequest, request: Request):
    agent = await _agent_from_bearer(request)
    conn = db()
    try:
        status_json = _json_dumps(body.printer) if body.printer is not None else agent["status_json"]
        conn.execute(
            "UPDATE printer_agents SET last_seen_at = ?, agent_version = COALESCE(?, agent_version), status_json = ? WHERE agent_id = ?",
            (now_iso(), body.agent_version, status_json, agent["agent_id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "online_window_s": AGENT_ONLINE_WINDOW_SECONDS}


def _claim_next_job(conn: sqlite3.Connection, agent_id: str) -> Optional[sqlite3.Row]:
    """Atomically move the oldest queued job to ``claimed`` and return it."""
    row = conn.execute(
        "SELECT * FROM printer_agent_jobs WHERE agent_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 1",
        (agent_id,),
    ).fetchone()
    if not row:
        return None
    now = now_iso()
    updated = conn.execute(
        "UPDATE printer_agent_jobs SET status = 'claimed', claimed_at = ?, updated_at = ? WHERE job_id = ? AND status = 'queued'",
        (now, now, row["job_id"]),
    )
    if updated.rowcount == 0:
        return None  # raced with another claim
    conn.commit()
    return conn.execute("SELECT * FROM printer_agent_jobs WHERE job_id = ?", (row["job_id"],)).fetchone()


def _job_payload(job: sqlite3.Row) -> Dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "request_id": job["request_id"],
        "file_id": job["file_id"],
        "file_name": job["file_name"],
        "sha256": job["sha256"],
        "size_bytes": job["size_bytes"],
        "status": job["status"],
        "download_url": f"{API_PREFIX}/jobs/{job['job_id']}/file",
        "created_at": job["created_at"],
    }


@router.get(API_PREFIX + "/jobs/next")
async def jobs_next(request: Request):
    agent = await _agent_from_bearer(request)
    conn = db()
    try:
        job = _claim_next_job(conn, agent["agent_id"])
    finally:
        conn.close()
    if not job:
        return Response(status_code=204)
    return _job_payload(job)


@router.get(API_PREFIX + "/jobs/stream")
async def jobs_stream(request: Request, timeout_s: int = 20):
    """Long-poll variant of jobs/next for lower dispatch latency."""
    agent = await _agent_from_bearer(request)
    import asyncio

    deadline = time.monotonic() + min(max(1, timeout_s), AGENT_STREAM_MAX_SECONDS)
    while True:
        conn = db()
        try:
            job = _claim_next_job(conn, agent["agent_id"])
        finally:
            conn.close()
        if job:
            return _job_payload(job)
        if time.monotonic() >= deadline:
            return Response(status_code=204)
        await asyncio.sleep(AGENT_STREAM_POLL_STEP_SECONDS)


@router.get(API_PREFIX + "/jobs/{job_id}/file")
async def job_file(job_id: str, request: Request):
    agent = await _agent_from_bearer(request)
    conn = db()
    try:
        job = conn.execute(
            "SELECT * FROM printer_agent_jobs WHERE job_id = ? AND agent_id = ?",
            (job_id, agent["agent_id"]),
        ).fetchone()
    finally:
        conn.close()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job["stored_filename"]:
        raise HTTPException(status_code=404, detail="Job has no file")
    path = os.path.join(upload_dir(), job["stored_filename"])
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File missing on server")
    return FileResponse(
        path,
        media_type="text/plain.gcode" if str(job["file_name"]).lower().endswith(".gcode") else "application/octet-stream",
        filename=job["file_name"] or os.path.basename(path),
    )


def _reflect_request_status(conn: sqlite3.Connection, request_id: Optional[str], job_status: str) -> None:
    """Best-effort mirror of job lifecycle onto a linked queue request."""
    if not request_id:
        return
    mapping = {
        "printing": "PRINTING",
        "uploading": "PRINTING",
        "completed": "DONE",
    }
    new_status = mapping.get(job_status)
    if not new_status:
        return
    try:
        row = conn.execute("SELECT status FROM requests WHERE id = ?", (request_id,)).fetchone()
        if not row:
            return
        # Don't clobber a manually-set terminal state.
        if row["status"] in ("DONE", "CANCELED", "REJECTED"):
            return
        conn.execute(
            "UPDATE requests SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now_iso(), request_id),
        )
    except Exception:
        pass


@router.post(API_PREFIX + "/jobs/{job_id}/status")
async def job_status(job_id: str, body: JobStatusRequest, request: Request):
    agent = await _agent_from_bearer(request)
    status = body.status.strip().lower()
    if status not in JOB_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status '{status}'")

    conn = db()
    try:
        job = conn.execute(
            "SELECT * FROM printer_agent_jobs WHERE job_id = ? AND agent_id = ?",
            (job_id, agent["agent_id"]),
        ).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        now = now_iso()
        progress = job["progress"]
        if body.progress is not None:
            progress = max(0, min(100, int(body.progress)))

        started_at = job["started_at"]
        completed_at = job["completed_at"]
        if status in ("printing",) and not started_at:
            started_at = now
        if status in JOB_TERMINAL and not completed_at:
            completed_at = now
        if status == "completed":
            progress = 100

        conn.execute(
            """
            UPDATE printer_agent_jobs
            SET status = ?, progress = ?, error = ?, result_json = COALESCE(?, result_json),
                updated_at = ?, started_at = ?, completed_at = ?
            WHERE job_id = ?
            """,
            (
                status,
                progress,
                body.error,
                _json_dumps(body.result) if body.result is not None else None,
                now,
                started_at,
                completed_at,
                job_id,
            ),
        )
        _reflect_request_status(conn, job["request_id"], status)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


# ──────────────────────────── remote management commands ────────────────────────────

class CommandStatusRequest(BaseModel):
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def _claim_next_command(conn: sqlite3.Connection, agent_id: str) -> Optional[Dict[str, Any]]:
    """Atomically claim the oldest queued command for an agent, or return None."""
    row = conn.execute(
        "SELECT * FROM printer_agent_commands WHERE agent_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 1",
        (agent_id,),
    ).fetchone()
    if not row:
        return None
    now = now_iso()
    updated = conn.execute(
        "UPDATE printer_agent_commands SET status = 'delivered', delivered_at = ?, updated_at = ? "
        "WHERE cmd_id = ? AND status = 'queued'",
        (now, now, row["cmd_id"]),
    )
    if updated.rowcount == 0:
        return None
    conn.commit()
    return {
        "cmd_id": row["cmd_id"],
        "action": row["action"],
        "payload": _json_loads(row["payload_json"]),
        "created_at": row["created_at"],
    }


@router.get(API_PREFIX + "/commands/next")
async def commands_next(request: Request):
    """Agent claims the next queued management command (204 if none)."""
    agent = await _agent_from_bearer(request)
    conn = db()
    try:
        cmd = _claim_next_command(conn, agent["agent_id"])
    finally:
        conn.close()
    if not cmd:
        return Response(status_code=204)
    return cmd


@router.get(API_PREFIX + "/events/next")
async def events_next(request: Request, timeout_s: int = 20, want_jobs: int = 1):
    """Unified long-poll: holds the connection until a command (or, when
    want_jobs=1, a queued print) is ready — or until timeout (204).

    One held connection replaces constant command+job polling: sub-second
    dispatch with far fewer requests. Commands take priority over jobs.
    """
    agent = await _agent_from_bearer(request)
    import asyncio

    deadline = time.monotonic() + min(max(1, timeout_s), AGENT_STREAM_MAX_SECONDS)
    while True:
        conn = db()
        try:
            cmd = _claim_next_command(conn, agent["agent_id"])
            if cmd:
                return {"type": "command", "command": cmd}
            if want_jobs:
                job = _claim_next_job(conn, agent["agent_id"])
                if job:
                    return {"type": "job", "job": _job_payload(job)}
        finally:
            conn.close()
        if time.monotonic() >= deadline:
            return Response(status_code=204)
        await asyncio.sleep(AGENT_STREAM_POLL_STEP_SECONDS)


@router.post(API_PREFIX + "/commands/{cmd_id}/status")
async def command_status(cmd_id: str, body: CommandStatusRequest, request: Request):
    agent = await _agent_from_bearer(request)
    status = body.status.strip().lower()
    if status not in COMMAND_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status '{status}'")
    conn = db()
    try:
        cmd = conn.execute(
            "SELECT cmd_id FROM printer_agent_commands WHERE cmd_id = ? AND agent_id = ?",
            (cmd_id, agent["agent_id"]),
        ).fetchone()
        if not cmd:
            raise HTTPException(status_code=404, detail="Command not found")
        now = now_iso()
        completed_at = now if status in COMMAND_TERMINAL else None
        conn.execute(
            "UPDATE printer_agent_commands SET status = ?, result_json = COALESCE(?, result_json), "
            "error = ?, updated_at = ?, completed_at = COALESCE(?, completed_at) WHERE cmd_id = ?",
            (
                status,
                _json_dumps(body.result) if body.result is not None else None,
                body.error,
                now,
                completed_at,
                cmd_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.post(API_PREFIX + "/snapshot")
async def upload_snapshot(request: Request, image: Optional[UploadFile] = File(default=None)):
    """Receive the latest webcam frame from the agent (snapshot-push camera)."""
    agent = await _agent_from_bearer(request)
    if image is not None:
        data = await image.read()
        content_type = image.content_type or "image/jpeg"
    else:
        data = await request.body()
        content_type = request.headers.get("Content-Type", "image/jpeg")
    if not data:
        raise HTTPException(status_code=422, detail="Empty image")
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Snapshot too large")

    conn = db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO printer_agent_snapshots (agent_id, image, content_type, updated_at) VALUES (?, ?, ?, ?)",
            (agent["agent_id"], data, content_type, now_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


# ──────────────────────────── admin endpoints ────────────────────────────

def _agent_view(agent: sqlite3.Row) -> Dict[str, Any]:
    last_seen = agent["last_seen_at"]
    online = False
    if last_seen:
        try:
            seen = datetime.fromisoformat(last_seen.replace("Z", ""))
            online = (datetime.utcnow() - seen).total_seconds() <= AGENT_ONLINE_WINDOW_SECONDS
        except Exception:
            online = False
    return {
        "agent_id": agent["agent_id"],
        "name": agent["name"],
        "printer_code": agent["printer_code"],
        "created_at": agent["created_at"],
        "claimed_at": agent["claimed_at"],
        "last_seen_at": last_seen,
        "agent_version": agent["agent_version"],
        "online": online,
        "revoked": bool(agent["revoked"]),
        "status": _json_loads(agent["status_json"]),
        "notes": agent["notes"],
    }


@router.get(ADMIN_PREFIX + "/agents")
async def admin_list_agents(admin=Depends(require_admin)):
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM printer_agents ORDER BY created_at DESC").fetchall()
        ingest_token = get_or_create_ingest_token(conn)
    finally:
        conn.close()
    return {"agents": [_agent_view(r) for r in rows], "ingest_token": ingest_token}


@router.post(ADMIN_PREFIX + "/agents")
async def admin_create_agent(body: CreateAgentRequest, admin=Depends(require_admin)):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name required")
    agent_id = f"agent-{secrets.token_hex(6)}"
    claim_code = secrets.token_urlsafe(18)
    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO printer_agents (agent_id, name, printer_code, claim_code_hash, created_at, created_by, notes, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                agent_id,
                name,
                body.printer_code.strip() or "LK5_PRO",
                claim_hash(claim_code),
                now_iso(),
                getattr(admin, "id", None),
                body.notes,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    # claim_code is returned exactly once; only its hash is stored.
    return {
        "agent_id": agent_id,
        "claim_code": claim_code,
        "printer_code": body.printer_code,
        "note": "Store the claim_code now — it is not retrievable later.",
    }


@router.post(ADMIN_PREFIX + "/agents/{agent_id}/revoke")
async def admin_revoke_agent(agent_id: str, admin=Depends(require_admin)):
    conn = db()
    try:
        agent = conn.execute("SELECT agent_id FROM printer_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        now = now_iso()
        conn.execute("UPDATE printer_agents SET revoked = 1 WHERE agent_id = ?", (agent_id,))
        conn.execute(
            "UPDATE printer_agent_tokens SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
            (now, agent_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


class CommandRequest(BaseModel):
    action: str
    payload: Optional[Dict[str, Any]] = None


@router.post(ADMIN_PREFIX + "/agents/{agent_id}/commands")
async def admin_enqueue_command(agent_id: str, body: CommandRequest, admin=Depends(require_admin)):
    """Queue a remote-management command (restart, reboot, logs, …) for the agent."""
    action = body.action.strip()
    if action not in AGENT_COMMAND_ACTIONS:
        raise HTTPException(status_code=422, detail=f"Unknown action '{action}'")
    conn = db()
    try:
        agent = conn.execute("SELECT agent_id FROM printer_agents WHERE agent_id = ? AND revoked = 0", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        cmd_id = str(uuid.uuid4())
        now = now_iso()
        conn.execute(
            "INSERT INTO printer_agent_commands (cmd_id, agent_id, action, payload_json, status, created_at, updated_at, created_by) "
            "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
            (cmd_id, agent_id, action, _json_dumps(body.payload) if body.payload else None, now, now, getattr(admin, "id", None)),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "cmd_id": cmd_id, "status": "queued"}


@router.get(ADMIN_PREFIX + "/agents/{agent_id}/commands")
async def admin_list_commands(agent_id: str, admin=Depends(require_admin)):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT * FROM printer_agent_commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT 30",
            (agent_id,),
        ).fetchall()
    finally:
        conn.close()
    return {"commands": [{
        "cmd_id": r["cmd_id"], "action": r["action"], "status": r["status"],
        "error": r["error"], "result": _json_loads(r["result_json"]),
        "created_at": r["created_at"], "completed_at": r["completed_at"],
    } for r in rows]}


# ──────────────────────────── agent OTA releases ────────────────────────────

def _current_release(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM printer_agent_releases ORDER BY is_current DESC, created_at DESC LIMIT 1"
    ).fetchone()


@router.post(ADMIN_PREFIX + "/agent-releases")
async def admin_upload_agent_release(
    version: str = Form(...),
    notes: Optional[str] = Form(default=None),
    file: UploadFile = File(...),
    admin=Depends(require_admin),
):
    """Upload an agent OTA bundle (.zip containing the printqueue_agent package)."""
    import hashlib
    import io
    import zipfile

    version = version.strip()
    if not version:
        raise HTTPException(status_code=422, detail="version required")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=422, detail="Empty bundle")
    if len(data) > 64 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Bundle too large")

    # Validate it's a zip that actually contains the agent package.
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        raise HTTPException(status_code=422, detail="Bundle must be a .zip")
    if not any(n.endswith("printqueue_agent/__init__.py") or n == "printqueue_agent/__init__.py" for n in names):
        raise HTTPException(status_code=422, detail="Bundle must contain the printqueue_agent/ package")

    os.makedirs(AGENT_RELEASES_DIR, exist_ok=True)
    safe_version = "".join(c for c in version if c.isalnum() or c in ".-_")
    bundle_path = os.path.join(AGENT_RELEASES_DIR, f"agent-{safe_version}.zip")
    with open(bundle_path, "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()

    conn = db()
    try:
        conn.execute("UPDATE printer_agent_releases SET is_current = 0")
        conn.execute(
            "INSERT OR REPLACE INTO printer_agent_releases "
            "(version, created_at, created_by, notes, bundle_path, sha256, size_bytes, is_current) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (version, now_iso(), getattr(admin, "id", None), notes, bundle_path, sha, len(data)),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "version": version, "sha256": sha, "size_bytes": len(data)}


@router.get(ADMIN_PREFIX + "/agent-releases")
async def admin_list_agent_releases(admin=Depends(require_admin)):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT version, created_at, notes, sha256, size_bytes, is_current FROM printer_agent_releases "
            "ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    return {"releases": [dict(r) for r in rows]}


@router.post(ADMIN_PREFIX + "/agents/{agent_id}/update")
async def admin_push_update(agent_id: str, admin=Depends(require_admin)):
    """Queue an update_agent command pointing the agent at the current release."""
    conn = db()
    try:
        agent = conn.execute("SELECT agent_id FROM printer_agents WHERE agent_id = ? AND revoked = 0", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        rel = _current_release(conn)
        if not rel:
            raise HTTPException(status_code=404, detail="No agent release uploaded yet")
        cmd_id = str(uuid.uuid4())
        now = now_iso()
        payload = {
            "version": rel["version"],
            "sha256": rel["sha256"],
            "bundle_url": f"{API_PREFIX}/releases/agent/{rel['version']}/bundle",
        }
        conn.execute(
            "INSERT INTO printer_agent_commands (cmd_id, agent_id, action, payload_json, status, created_at, updated_at, created_by) "
            "VALUES (?, ?, 'update_agent', ?, 'queued', ?, ?, ?)",
            (cmd_id, agent_id, _json_dumps(payload), now, now, getattr(admin, "id", None)),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "cmd_id": cmd_id, "version": rel["version"]}


@router.get(API_PREFIX + "/releases/agent/{version}/bundle")
async def agent_download_bundle(version: str, request: Request):
    """Agent downloads an OTA bundle (bearer-authenticated)."""
    await _agent_from_bearer(request)
    conn = db()
    try:
        rel = conn.execute("SELECT bundle_path FROM printer_agent_releases WHERE version = ?", (version,)).fetchone()
    finally:
        conn.close()
    if not rel or not rel["bundle_path"] or not os.path.isfile(rel["bundle_path"]):
        raise HTTPException(status_code=404, detail="Release not found")
    return FileResponse(rel["bundle_path"], media_type="application/zip", filename=f"agent-{version}.zip")


# ──────────────────────────── printer firmware (avrdude) ────────────────────────────

def _current_firmware(conn: sqlite3.Connection, printer_code: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM printer_firmware WHERE printer_code = ? ORDER BY is_current DESC, created_at DESC LIMIT 1",
        (printer_code,),
    ).fetchone()


@router.post(ADMIN_PREFIX + "/firmware")
async def admin_upload_firmware(
    version: str = Form(...),
    printer_code: str = Form(default="LK5_PRO"),
    notes: Optional[str] = Form(default=None),
    file: UploadFile = File(...),
    admin=Depends(require_admin),
):
    """Upload a printer firmware image (.hex) for a printer model."""
    import hashlib

    version = version.strip()
    printer_code = (printer_code or "LK5_PRO").strip()
    if not version:
        raise HTTPException(status_code=422, detail="version required")
    original = os.path.basename(file.filename or "firmware.hex")
    if not original.lower().endswith(".hex"):
        raise HTTPException(status_code=422, detail="Firmware must be a .hex file")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=422, detail="Empty firmware")
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Firmware too large")

    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    safe = "".join(c for c in f"{printer_code}-{version}" if c.isalnum() or c in ".-_")
    path = os.path.join(FIRMWARE_DIR, f"{safe}.hex")
    with open(path, "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()

    conn = db()
    try:
        conn.execute("UPDATE printer_firmware SET is_current = 0 WHERE printer_code = ?", (printer_code,))
        conn.execute(
            "INSERT OR REPLACE INTO printer_firmware "
            "(version, printer_code, created_at, created_by, notes, file_path, file_name, sha256, size_bytes, is_current) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (version, printer_code, now_iso(), getattr(admin, "id", None), notes, path, original, sha, len(data)),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "version": version, "printer_code": printer_code, "sha256": sha, "size_bytes": len(data)}


@router.get(ADMIN_PREFIX + "/firmware")
async def admin_list_firmware(admin=Depends(require_admin)):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT version, printer_code, file_name, created_at, notes, sha256, size_bytes, is_current "
            "FROM printer_firmware ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    return {"firmware": [dict(r) for r in rows]}


@router.post(ADMIN_PREFIX + "/agents/{agent_id}/flash")
async def admin_flash_firmware(agent_id: str, admin=Depends(require_admin)):
    """Queue a flash_firmware command pointing the agent at the current firmware
    for its printer model. The agent only flashes if it is opt-in enabled."""
    conn = db()
    try:
        agent = conn.execute(
            "SELECT agent_id, printer_code FROM printer_agents WHERE agent_id = ? AND revoked = 0", (agent_id,)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        fw = _current_firmware(conn, agent["printer_code"])
        if not fw:
            raise HTTPException(status_code=404, detail=f"No firmware uploaded for {agent['printer_code']}")
        cmd_id = str(uuid.uuid4())
        now = now_iso()
        payload = {
            "version": fw["version"],
            "sha256": fw["sha256"],
            "file_name": fw["file_name"],
            "firmware_url": f"{API_PREFIX}/firmware/{agent['printer_code']}/{fw['version']}/file",
        }
        conn.execute(
            "INSERT INTO printer_agent_commands (cmd_id, agent_id, action, payload_json, status, created_at, updated_at, created_by) "
            "VALUES (?, ?, 'flash_firmware', ?, 'queued', ?, ?, ?)",
            (cmd_id, agent_id, _json_dumps(payload), now, now, getattr(admin, "id", None)),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "cmd_id": cmd_id, "version": fw["version"]}


@router.get(API_PREFIX + "/firmware/{printer_code}/{version}/file")
async def agent_download_firmware(printer_code: str, version: str, request: Request):
    """Agent downloads a firmware .hex (bearer-authenticated)."""
    await _agent_from_bearer(request)
    conn = db()
    try:
        fw = conn.execute(
            "SELECT file_path, file_name FROM printer_firmware WHERE printer_code = ? AND version = ?",
            (printer_code, version),
        ).fetchone()
    finally:
        conn.close()
    if not fw or not fw["file_path"] or not os.path.isfile(fw["file_path"]):
        raise HTTPException(status_code=404, detail="Firmware not found")
    return FileResponse(fw["file_path"], media_type="text/plain", filename=fw["file_name"] or f"{version}.hex")


@router.get(API_PREFIX + "/agent-package.tar.gz")
async def download_agent_package(token: str = ""):
    """Stream the agent source as a tarball so the guided setup is paste-and-go.

    Authorized with the Cura ingest token (a shared setup secret) rather than an
    admin session, since this runs on the Pi during first-time install.
    """
    import io
    import tarfile

    conn = db()
    try:
        expected = get_or_create_ingest_token(conn)
    finally:
        conn.close()
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing setup token")

    agent_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent")
    if not os.path.isdir(agent_dir):
        raise HTTPException(status_code=404, detail="Agent source not found on server")
    repo_root = os.path.dirname(agent_dir)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(agent_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__" and not d.endswith(".bak")]
            for name in files:
                if name.endswith(".pyc") or name == "config.json":
                    continue
                full = os.path.join(root, name)
                tar.add(full, arcname=os.path.relpath(full, repo_root))  # keeps "agent/" prefix
    return Response(
        content=buf.getvalue(),
        media_type="application/gzip",
        headers={"Content-Disposition": "attachment; filename=printqueue-agent.tar.gz"},
    )


@router.post(ADMIN_PREFIX + "/agents/{agent_id}/jobs")
async def admin_enqueue_job(agent_id: str, body: EnqueueJobRequest, admin=Depends(require_admin)):
    """The 'Send to LK5' action: queue a sliced gcode file for the agent."""
    conn = db()
    try:
        agent = conn.execute("SELECT * FROM printer_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not agent or agent["revoked"]:
            raise HTTPException(status_code=404, detail="Agent not found")

        file_row = conn.execute(
            "SELECT id, original_filename, stored_filename, size_bytes, sha256 FROM files WHERE id = ?",
            (body.file_id,),
        ).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if not str(file_row["original_filename"]).lower().endswith(".gcode"):
            raise HTTPException(status_code=422, detail="Only .gcode files can be sent to this printer")

        job_id = str(uuid.uuid4())
        now = now_iso()
        conn.execute(
            """
            INSERT INTO printer_agent_jobs
                (job_id, agent_id, request_id, file_id, file_name, stored_filename, sha256, size_bytes,
                 status, progress, created_at, updated_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?)
            """,
            (
                job_id,
                agent_id,
                body.request_id,
                file_row["id"],
                file_row["original_filename"],
                file_row["stored_filename"],
                file_row["sha256"],
                file_row["size_bytes"],
                now,
                now,
                getattr(admin, "id", None),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "job_id": job_id, "status": "queued"}


def _job_view(job: sqlite3.Row) -> Dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "agent_id": job["agent_id"],
        "request_id": job["request_id"],
        "file_name": job["file_name"],
        "size_bytes": job["size_bytes"],
        "status": job["status"],
        "progress": job["progress"],
        "error": job["error"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "started_at": job["started_at"],
        "completed_at": job["completed_at"],
        "result": _json_loads(job["result_json"]),
    }


@router.get(ADMIN_PREFIX + "/agents/{agent_id}/jobs")
async def admin_list_jobs(agent_id: str, admin=Depends(require_admin)):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT * FROM printer_agent_jobs WHERE agent_id = ? ORDER BY created_at DESC LIMIT 100",
            (agent_id,),
        ).fetchall()
    finally:
        conn.close()
    return {"jobs": [_job_view(r) for r in rows]}


@router.post(ADMIN_PREFIX + "/jobs/{job_id}/cancel")
async def admin_cancel_job(job_id: str, admin=Depends(require_admin)):
    """Mark a job canceled. The agent observes this and aborts the SD print."""
    conn = db()
    try:
        job = conn.execute("SELECT status FROM printer_agent_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job["status"] in JOB_TERMINAL:
            raise HTTPException(status_code=409, detail=f"Job already {job['status']}")
        now = now_iso()
        conn.execute(
            "UPDATE printer_agent_jobs SET status = 'canceled', completed_at = ?, updated_at = ? WHERE job_id = ?",
            (now, now, job_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@router.get(ADMIN_PREFIX + "/agents/{agent_id}/snapshot.jpg")
async def admin_agent_snapshot(agent_id: str, admin=Depends(require_admin)):
    conn = db()
    try:
        row = conn.execute(
            "SELECT image, content_type FROM printer_agent_snapshots WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row or not row["image"]:
        raise HTTPException(status_code=404, detail="No snapshot available")
    return Response(content=row["image"], media_type=row["content_type"] or "image/jpeg")


@router.get(ADMIN_PREFIX + "/gcode-files")
async def admin_list_gcode_files(admin=Depends(require_admin)):
    """Recent loose .gcode files (e.g. Cura uploads) available to dispatch."""
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, original_filename, size_bytes, created_at FROM files "
            "WHERE (request_id IS NULL OR request_id = '') AND LOWER(original_filename) LIKE '%.gcode' "
            "ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    return {"files": [dict(r) for r in rows]}


class DispatchRequest(BaseModel):
    file_id: str
    request_id: Optional[str] = None
    printer_code: str = "LK5_PRO"


@router.post(ADMIN_PREFIX + "/dispatch")
async def admin_dispatch(body: DispatchRequest, admin=Depends(require_admin)):
    """Send a request's .gcode file to its printer's agent (the "Send to LK5"
    button on the request page). Resolves the agent by printer_code so the admin
    doesn't have to pick one."""
    conn = db()
    try:
        agent = _resolve_target_agent(conn, None, body.printer_code or "LK5_PRO")
        if not agent:
            raise HTTPException(
                status_code=404,
                detail=f"No agent registered for {body.printer_code}. Add one under Print Agents.",
            )

        file_row = conn.execute(
            "SELECT id, original_filename, stored_filename, size_bytes, sha256 FROM files WHERE id = ?",
            (body.file_id,),
        ).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if not str(file_row["original_filename"]).lower().endswith(".gcode"):
            raise HTTPException(status_code=422, detail="Only .gcode files can be sent to this printer")

        job_id = str(uuid.uuid4())
        now = now_iso()
        conn.execute(
            """
            INSERT INTO printer_agent_jobs
                (job_id, agent_id, request_id, file_id, file_name, stored_filename, sha256, size_bytes,
                 status, progress, created_at, updated_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?)
            """,
            (
                job_id, agent["agent_id"], body.request_id, file_row["id"],
                file_row["original_filename"], file_row["stored_filename"],
                file_row["sha256"], file_row["size_bytes"], now, now, getattr(admin, "id", None),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "ok": True,
        "job_id": job_id,
        "agent_id": agent["agent_id"],
        "agent_name": agent["name"] or agent["agent_id"],
        "online": bool(agent["last_seen_at"]),
    }


# ──────────────────────────── admin web page ────────────────────────────

@router.get("/admin/printer-agents", response_class=HTMLResponse)
async def admin_printer_agents_page(request: Request, admin=Depends(require_admin)):
    # Reuse the main app's Jinja env so shared globals (environment, csrf, …) resolve.
    from app.main import templates
    return templates.TemplateResponse("admin_printer_agents.html", {"request": request, "admin": admin})


# ──────────────────────────── Cura ingest / one-click print ────────────────────────────

def _check_ingest_token(conn: sqlite3.Connection, presented: Optional[str]) -> None:
    expected = get_or_create_ingest_token(conn)
    if not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Invalid ingest token")


def _validate_gcode_name(filename: Optional[str]) -> str:
    original = os.path.basename(filename or "print.gcode")
    if not original.lower().endswith(".gcode"):
        raise HTTPException(status_code=422, detail="Only .gcode uploads are accepted")
    return original


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=422, detail="Empty file")
    if len(data) > 512 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")
    return data


def _store_gcode_bytes(data: bytes) -> tuple[str, str]:
    """Write gcode bytes to the upload dir; return (stored_filename, sha256)."""
    import hashlib

    os.makedirs(upload_dir(), exist_ok=True)
    stored = f"{uuid.uuid4().hex}.gcode"
    with open(os.path.join(upload_dir(), stored), "wb") as fh:
        fh.write(data)
    return stored, hashlib.sha256(data).hexdigest()


def _insert_loose_file(conn: sqlite3.Connection, original: str, stored: str, data: bytes, sha: str) -> str:
    file_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256)
        VALUES (?, '', ?, ?, ?, ?, ?)
        """,
        (file_id, now_iso(), original, stored, len(data), sha),
    )
    return file_id


def _resolve_target_agent(conn: sqlite3.Connection, agent_id: Optional[str], printer_code: str) -> Optional[sqlite3.Row]:
    if agent_id:
        return conn.execute(
            "SELECT * FROM printer_agents WHERE agent_id = ? AND revoked = 0", (agent_id,)
        ).fetchone()
    # No explicit agent: pick the most recently-seen, non-revoked agent for the printer.
    return conn.execute(
        "SELECT * FROM printer_agents WHERE printer_code = ? AND revoked = 0 "
        "ORDER BY (last_seen_at IS NOT NULL) DESC, last_seen_at DESC, created_at DESC LIMIT 1",
        (printer_code,),
    ).fetchone()


@router.post(API_PREFIX + "/ingest/gcode")
async def ingest_gcode(
    request: Request,
    file: UploadFile = File(...),
    x_ingest_token: Optional[str] = Header(default=None),
):
    """Receive a sliced .gcode from the Cura post-processing uploader.

    Authenticated by the static ingest token (not an agent bearer token), since
    Cura cannot hold an interactive admin session. The file is stored as a loose
    upload that an admin then dispatches with 'Send to LK5'. For true one-click
    upload-and-print from Cura, use ``/print`` instead.
    """
    conn = db()
    try:
        _check_ingest_token(conn, x_ingest_token)
        original = _validate_gcode_name(file.filename)
        data = await _read_upload(file)
        stored, sha = _store_gcode_bytes(data)
        file_id = _insert_loose_file(conn, original, stored, data, sha)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "file_id": file_id, "file_name": original, "size_bytes": len(data), "sha256": sha}


@router.post(API_PREFIX + "/print")
async def print_now(
    request: Request,
    file: UploadFile = File(...),
    agent_id: Optional[str] = Form(default=None),
    printer_code: Optional[str] = Form(default="LK5_PRO"),
    x_ingest_token: Optional[str] = Header(default=None),
):
    """One-click upload-and-print, used by the Cura "Send to LK5 Pro" plugin.

    Stores the gcode and immediately enqueues a job for the target agent — no
    separate dispatch step. The agent claims queued jobs automatically, so this
    is all it takes to go from "Slice" in Cura to a running print.

    The target is resolved by explicit ``agent_id`` if given, otherwise the most
    recently-seen, non-revoked agent for ``printer_code``.
    """
    conn = db()
    try:
        _check_ingest_token(conn, x_ingest_token)
        original = _validate_gcode_name(file.filename)
        data = await _read_upload(file)

        agent = _resolve_target_agent(conn, agent_id, printer_code or "LK5_PRO")
        if not agent:
            raise HTTPException(status_code=404, detail="No matching agent for this printer")

        stored, sha = _store_gcode_bytes(data)
        file_id = _insert_loose_file(conn, original, stored, data, sha)

        job_id = str(uuid.uuid4())
        now = now_iso()
        conn.execute(
            """
            INSERT INTO printer_agent_jobs
                (job_id, agent_id, request_id, file_id, file_name, stored_filename, sha256, size_bytes,
                 status, progress, created_at, updated_at, created_by)
            VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, 'cura')
            """,
            (job_id, agent["agent_id"], file_id, original, stored, sha, len(data), now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "ok": True,
        "job_id": job_id,
        "agent_id": agent["agent_id"],
        "file_name": original,
        "status": "queued",
        "message": f"Queued '{original}' for {agent['name'] or agent['agent_id']}",
    }


# ──────────────────────────── status backend (dashboard integration) ────────────────────────────

class AgentPrinterAPI:
    """Adapter so agent-backed printers plug into ``fetch_printer_status_with_cache``.

    Unlike FlashForge/Moonraker (which reach into the LAN), this reads the last
    heartbeat the agent pushed. Method names mirror the other printer APIs.
    """

    def __init__(self, printer_code: str):
        self.printer_code = printer_code

    def _latest(self) -> Optional[Dict[str, Any]]:
        conn = db()
        try:
            row = conn.execute(
                "SELECT status_json, last_seen_at FROM printer_agents "
                "WHERE printer_code = ? AND revoked = 0 AND last_seen_at IS NOT NULL "
                "ORDER BY last_seen_at DESC LIMIT 1",
                (self.printer_code,),
            ).fetchone()
        finally:
            conn.close()
        if not row or not row["last_seen_at"]:
            return None
        try:
            seen = datetime.fromisoformat(row["last_seen_at"].replace("Z", ""))
            if (datetime.utcnow() - seen).total_seconds() > AGENT_ONLINE_WINDOW_SECONDS:
                return None  # stale -> treat as offline
        except Exception:
            return None
        return _json_loads(row["status_json"])

    async def get_status(self) -> Optional[Dict[str, Any]]:
        status = self._latest()
        if status is None:
            return None
        state = str(status.get("state", "")).lower()
        machine = {
            "printing": "BUILDING_FROM_SD",
            "paused": "PAUSED",
            "idle": "READY",
            "ready": "READY",
        }.get(state, "READY")
        return {"MachineStatus": machine}

    async def get_percent_complete(self) -> Optional[int]:
        status = self._latest()
        if not status:
            return None
        pct = status.get("progress")
        return int(pct) if pct is not None else None

    async def get_temperature(self) -> Optional[Dict[str, Any]]:
        status = self._latest()
        if not status:
            return None
        cur = status.get("nozzle_temp")
        target = status.get("nozzle_target")
        if cur is None and target is None:
            return None
        return {"Temperature": f"{cur}/{target}", "TargetTemperature": target}

    async def get_extended_status(self) -> Optional[Dict[str, Any]]:
        status = self._latest()
        if not status:
            return None
        return {
            "current_file": status.get("current_file"),
            "current_layer": status.get("current_layer"),
            "total_layers": status.get("total_layers"),
        }


def get_agent_printer_api(printer_code: str) -> Optional[AgentPrinterAPI]:
    """Return an agent-backed status API for printer codes serviced by an agent."""
    if printer_code in AGENT_PRINTER_CODES:
        return AgentPrinterAPI(printer_code)
    return None
