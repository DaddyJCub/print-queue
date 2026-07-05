"""Printellect Watch — AI camera monitoring of active prints.

Background worker that captures a camera frame for every actively printing
build, submits it to JCubHub CM (Print Monitor Contract v1.0.0, same HMAC
scheme as the Sentinel bug reporter), and acts on the returned AI verdict:
alert admins on a confirmed failure and, opt-in per printer, auto-pause the
print. Fully fail-open — CM being down never disturbs a print.

Config lives in DB settings (admin UI editable, no redeploy):
  print_monitor_enabled                "1"/"0"
  print_monitor_url                    e.g. https://mgmt.jcubhub.com/api/print-monitor/frames
  print_monitor_secret                 per-app HMAC secret (blank = reuse bug_report_secret)
  print_monitor_interval_seconds       default 60
  print_monitor_warmup_minutes         default 10 (first layers look weird to AI)
  print_monitor_max_frame_kb           default 1500
  print_monitor_alert_cooldown_minutes default 30
  print_monitor_notify_email           "1"/"0"
  print_monitor_autopause_<PRINTER>    "1"/"0" per printer code (default off)

Env: ENABLE_PRINT_MONITOR gates the worker per replica (like the other pollers).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("printellect.print_monitor")

MONITOR_CONTRACT_VERSION = "1.0.0"
_SUBMIT_TIMEOUT = 30.0
# Frames older than this multiple of the poll interval are considered stale
# (agent offline / camera frozen) and are not submitted.
_AGENT_SNAPSHOT_MAX_AGE_FACTOR = 2.0

# Injected from app.main at startup via configure() — avoids a circular import,
# same pattern as app.bug_reporter.
_deps: Dict[str, Callable] = {}


def configure(**deps: Callable) -> None:
    """Inject main-module callables. Required keys:

    db, now_iso, get_setting, get_bool_setting, capture_camera_snapshot,
    is_polling_paused, send_push_notification_to_admins, send_email,
    parse_email_list, get_printer_api, demo_mode (0-arg -> bool)
    """
    _deps.update(deps)


def _d(name: str) -> Callable:
    return _deps[name]


# ------------------------
# Schema
# ------------------------

def init_print_monitor_tables(cur: sqlite3.Cursor) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS print_monitor_sessions (
            id TEXT PRIMARY KEY,              -- build id (or request id for single-build)
            request_id TEXT,
            build_id TEXT,
            printer_code TEXT NOT NULL,
            started_at TEXT,
            last_frame_at TEXT,
            frames_sent INTEGER DEFAULT 0,
            last_frame_hash TEXT,
            state TEXT DEFAULT 'watching',    -- watching|alerted|paused|muted|ended
            confirmed_failure_type TEXT,
            alerted_at TEXT,
            auto_paused INTEGER DEFAULT 0,
            muted INTEGER DEFAULT 0,
            cm_errors INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS print_monitor_events (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            created_at TEXT,
            verdict TEXT,
            failure_type TEXT,
            confidence REAL,
            source TEXT,
            reasoning TEXT,
            cm_frame_id TEXT,
            action TEXT DEFAULT 'none'        -- none|alerted|paused|muted
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_pm_events_session ON print_monitor_events(session_id, created_at)"
    )


# ------------------------
# Config helpers
# ------------------------

def _enabled() -> bool:
    return _d("get_bool_setting")("print_monitor_enabled", False)


def _monitor_url() -> str:
    return (_d("get_setting")("print_monitor_url", "") or "").strip()


def _monitor_secret() -> str:
    secret = (_d("get_setting")("print_monitor_secret", "") or "").strip()
    if secret:
        return secret
    # Printellect is already registered with CM for bug reports; CM falls back
    # to the same secret map, so reuse it unless a dedicated one is configured.
    return (_d("get_setting")("bug_report_secret", "") or "").strip()


def _app_id() -> str:
    return (_d("get_setting")("bug_app_id", "") or "").strip() or "printellect"


def _int_setting(key: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int((_d("get_setting")(key, str(default)) or str(default)).strip()))
    except (TypeError, ValueError):
        return default


def _interval_seconds() -> int:
    return min(600, _int_setting("print_monitor_interval_seconds", 60, minimum=30))


def _warmup_minutes() -> int:
    return _int_setting("print_monitor_warmup_minutes", 10, minimum=0)


def _max_frame_bytes() -> int:
    return _int_setting("print_monitor_max_frame_kb", 1500, minimum=50) * 1024


def _cooldown_minutes() -> int:
    return _int_setting("print_monitor_alert_cooldown_minutes", 30, minimum=1)


def _autopause_enabled(printer_code: str) -> bool:
    return _d("get_bool_setting")(f"print_monitor_autopause_{printer_code}", False)


# ------------------------
# Active print discovery (mirrors the two status pollers' dual query)
# ------------------------

def get_active_targets() -> List[Dict[str, Any]]:
    """One target per actively printing build: multi-build rows come from the
    builds table, legacy single-build prints from the requests row itself."""
    conn = _d("db")()
    targets: List[Dict[str, Any]] = []
    try:
        build_rows = conn.execute(
            """
            SELECT b.id AS build_id, b.request_id, b.printer, b.started_at,
                   b.print_name AS build_print_name,
                   r.print_name AS request_print_name, r.material
            FROM builds b
            JOIN requests r ON b.request_id = r.id
            WHERE b.status = 'PRINTING' AND b.printer IS NOT NULL
            """
        ).fetchall()
        for row in build_rows:
            targets.append({
                "session_id": row["build_id"],
                "request_id": row["request_id"],
                "build_id": row["build_id"],
                "printer_code": row["printer"],
                "print_name": row["build_print_name"] or row["request_print_name"],
                "material": row["material"],
                "started_at": row["started_at"],
            })

        covered_requests = {t["request_id"] for t in targets}
        req_rows = conn.execute(
            """
            SELECT id, printer, print_name, material, printing_started_at, total_builds
            FROM requests
            WHERE status = 'PRINTING' AND printer IS NOT NULL
            """
        ).fetchall()
        for row in req_rows:
            if (row["total_builds"] or 1) > 1 or row["id"] in covered_requests:
                continue
            targets.append({
                "session_id": row["id"],
                "request_id": row["id"],
                "build_id": None,
                "printer_code": row["printer"],
                "print_name": row["print_name"],
                "material": row["material"],
                "started_at": row["printing_started_at"],
            })
    finally:
        conn.close()
    return targets


# ------------------------
# Frame capture
# ------------------------

def _agent_snapshot(printer_code: str, max_age_seconds: float) -> Optional[Tuple[bytes, str]]:
    """Latest pushed snapshot for an agent-backed printer (e.g. LK5 Pro)."""
    conn = _d("db")()
    try:
        row = conn.execute(
            """
            SELECT s.image, s.content_type, s.updated_at
            FROM printer_agent_snapshots s
            JOIN printer_agents a ON a.agent_id = s.agent_id
            WHERE a.printer_code = ? AND a.revoked = 0 AND s.image IS NOT NULL
            ORDER BY s.updated_at DESC
            LIMIT 1
            """,
            (printer_code,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        updated = datetime.fromisoformat(str(row["updated_at"]).replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        if age > max_age_seconds:
            return None
    except (TypeError, ValueError):
        return None
    return bytes(row["image"]), row["content_type"] or "image/jpeg"


async def capture_frame(printer_code: str, interval_s: int) -> Optional[Tuple[bytes, str]]:
    from app.printer_agent import AGENT_PRINTER_CODES

    if printer_code in AGENT_PRINTER_CODES:
        return _agent_snapshot(printer_code, interval_s * _AGENT_SNAPSHOT_MAX_AGE_FACTOR)
    data = await _d("capture_camera_snapshot")(printer_code)
    if not data:
        return None
    return data, "image/jpeg"


# ------------------------
# CM client
# ------------------------

async def submit_frame(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """HMAC-signed POST of one frame to CM. Returns the verdict response dict,
    or None on any failure (fail-open — the caller just skips this cycle)."""
    url = _monitor_url()
    secret = _monitor_secret()
    if not url or not secret:
        return None
    try:
        body = json.dumps(payload).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        async with httpx.AsyncClient(timeout=_SUBMIT_TIMEOUT, follow_redirects=False) as client:
            r = await client.post(
                url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-JCubHub-App": _app_id(),
                    "X-JCubHub-Signature": f"sha256={sig}",
                    "X-JCubHub-Monitor-Contract": MONITOR_CONTRACT_VERSION,
                },
            )
        if r.status_code == 200:
            return r.json()
        if r.status_code in (301, 302, 303, 307, 308):
            logger.warning(
                "print_monitor frame blocked by reverse proxy (redirect to %s) — "
                "add an auth bypass for /api/print-monitor/frames like /api/reports.",
                r.headers.get("location", "?"),
            )
        else:
            logger.warning(
                "print_monitor frame rejected status=%s body=%.200s", r.status_code, r.text
            )
    except Exception as exc:  # fail open
        logger.warning("print_monitor frame post failed: %s", exc)
    return None


# ------------------------
# Session persistence
# ------------------------

def _load_or_create_session(target: Dict[str, Any]) -> Dict[str, Any]:
    conn = _d("db")()
    now = _d("now_iso")()
    try:
        row = conn.execute(
            "SELECT * FROM print_monitor_sessions WHERE id = ?", (target["session_id"],)
        ).fetchone()
        if row:
            return dict(row)
        conn.execute(
            """
            INSERT INTO print_monitor_sessions
                (id, request_id, build_id, printer_code, started_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target["session_id"], target["request_id"], target["build_id"],
                target["printer_code"], target["started_at"], now, now,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM print_monitor_sessions WHERE id = ?", (target["session_id"],)
        ).fetchone()
        return dict(row)
    finally:
        conn.close()


def _update_session(session_id: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = _d("now_iso")()
    cols = ", ".join(f"{k} = ?" for k in fields)
    conn = _d("db")()
    try:
        conn.execute(
            f"UPDATE print_monitor_sessions SET {cols} WHERE id = ?",
            (*fields.values(), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def _record_event(
    session_id: str,
    response: Optional[Dict[str, Any]],
    action: str = "none",
) -> None:
    conn = _d("db")()
    try:
        conn.execute(
            """
            INSERT INTO print_monitor_events
                (id, session_id, created_at, verdict, failure_type, confidence,
                 source, reasoning, cm_frame_id, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                session_id,
                _d("now_iso")(),
                (response or {}).get("verdict"),
                (response or {}).get("failure_type"),
                (response or {}).get("confidence"),
                (response or {}).get("source"),
                (response or {}).get("reasoning"),
                (response or {}).get("frame_id"),
                action,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_latest_event(session_id: str) -> Optional[Dict[str, Any]]:
    """Latest verdict for a build/request — used by admin UI badges."""
    conn = _d("db")()
    try:
        row = conn.execute(
            """
            SELECT e.*, s.state AS session_state, s.muted, s.auto_paused
            FROM print_monitor_events e
            JOIN print_monitor_sessions s ON s.id = e.session_id
            WHERE e.session_id = ?
            ORDER BY e.created_at DESC LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def mute_session(session_id: str) -> bool:
    conn = _d("db")()
    try:
        cur = conn.execute(
            "UPDATE print_monitor_sessions SET muted = 1, state = 'muted', updated_at = ? WHERE id = ?",
            (_d("now_iso")(), session_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ------------------------
# Verdict handling
# ------------------------

def _minutes_since(iso_ts: Optional[str]) -> Optional[float]:
    if not iso_ts:
        return None
    try:
        ts = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() / 60.0
    except (TypeError, ValueError):
        return None


def _should_alert(session: Dict[str, Any]) -> bool:
    if session.get("muted"):
        return False
    elapsed = _minutes_since(session.get("alerted_at"))
    if elapsed is None:
        return True
    return elapsed >= _cooldown_minutes()


def _alert_failure(
    session: Dict[str, Any],
    target: Dict[str, Any],
    response: Dict[str, Any],
    frame_b64: str,
) -> None:
    failure_type = (
        (response.get("session") or {}).get("confirmed_failure_type")
        or response.get("failure_type")
        or "failure"
    )
    print_name = target.get("print_name") or "print"
    printer = target["printer_code"]
    title = f"⚠️ Print failure detected: {print_name}"
    body = (
        f"AI detected {failure_type.replace('_', ' ')} on {printer}. "
        f"{response.get('reasoning') or ''}".strip()
    )
    url = f"/admin/request/{target['request_id']}" if target.get("request_id") else "/admin"

    try:
        _d("send_push_notification_to_admins")(
            title, body, url=url, tag=f"print-monitor-{session['id']}"
        )
    except Exception as exc:
        logger.warning("print_monitor push alert failed: %s", exc)

    if _d("get_bool_setting")("print_monitor_notify_email", True):
        try:
            admin_emails = _d("parse_email_list")(
                _d("get_setting")("admin_notify_emails", "")
            )
            if admin_emails:
                _d("send_email")(
                    admin_emails,
                    title,
                    f"{body}\n\nOpen: {url}",
                    None,
                    image_base64=frame_b64,
                )
        except Exception as exc:
            logger.warning("print_monitor email alert failed: %s", exc)


async def _maybe_auto_pause(session: Dict[str, Any], target: Dict[str, Any]) -> bool:
    """Pause the print once per build when the per-printer opt-in is on.

    Never cancels. Direct printers pause via their API (Moonraker has
    pause_print); agent-backed printers get a queued pause_print command.
    """
    printer = target["printer_code"]
    if session.get("auto_paused") or not _autopause_enabled(printer):
        return False

    try:
        from app.printer_agent import AGENT_PRINTER_CODES, enqueue_pause_command

        if printer in AGENT_PRINTER_CODES:
            return enqueue_pause_command(printer)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("print_monitor agent pause failed printer=%s: %s", printer, exc)
        return False

    try:
        api = _d("get_printer_api")(printer)
        if api is None or not hasattr(api, "pause_print"):
            logger.info("print_monitor auto-pause unsupported for %s", printer)
            return False
        return bool(await api.pause_print())
    except Exception as exc:
        logger.warning("print_monitor auto-pause failed printer=%s: %s", printer, exc)
        return False


async def _handle_response(
    session: Dict[str, Any],
    target: Dict[str, Any],
    response: Dict[str, Any],
    frame_b64: str,
) -> None:
    session_block = response.get("session") or {}
    confirmed = bool(session_block.get("confirmed_failure"))
    # Claude directly judging this frame a failure counts as confirmation too.
    if response.get("source") == "claude" and response.get("verdict") == "failure":
        confirmed = True

    if not confirmed:
        _record_event(session["id"], response)
        return

    action = "none"
    failure_type = session_block.get("confirmed_failure_type") or response.get("failure_type")

    if _should_alert(session):
        _alert_failure(session, target, response, frame_b64)
        action = "alerted"
        _update_session(
            session["id"],
            state="alerted",
            alerted_at=_d("now_iso")(),
            confirmed_failure_type=failure_type,
        )
        session["alerted_at"] = _d("now_iso")()
        session["state"] = "alerted"

    if await _maybe_auto_pause(session, target):
        action = "paused"
        _update_session(session["id"], state="paused", auto_paused=1)
        session["auto_paused"] = 1
        try:
            _d("send_push_notification_to_admins")(
                "⏸️ Print paused by Printellect Watch",
                f"{target.get('print_name') or 'Print'} on {target['printer_code']} was "
                f"paused after a confirmed {str(failure_type or 'failure').replace('_', ' ')}.",
                url=f"/admin/request/{target['request_id']}" if target.get("request_id") else "/admin",
                tag=f"print-monitor-pause-{session['id']}",
            )
        except Exception:
            pass

    _record_event(session["id"], response, action=action)


# ------------------------
# Worker
# ------------------------

async def _process_target(target: Dict[str, Any], interval_s: int) -> None:
    printer = target["printer_code"]

    warmup = _warmup_minutes()
    started_min = _minutes_since(target.get("started_at"))
    if warmup and started_min is not None and started_min < warmup:
        return
    if _d("is_polling_paused")(printer):
        return

    session = _load_or_create_session(target)
    if session.get("muted"):
        return

    frame = await capture_frame(printer, interval_s)
    if not frame:
        return
    data, _content_type = frame

    if len(data) > _max_frame_bytes():
        logger.debug("print_monitor frame too large printer=%s bytes=%s", printer, len(data))
        return

    frame_hash = hashlib.sha256(data).hexdigest()
    if frame_hash == session.get("last_frame_hash"):
        # Identical bytes = frozen stream or placeholder; nothing new to judge.
        return

    frame_b64 = base64.b64encode(data).decode("ascii")
    payload = {
        "app_id": _app_id(),
        "session_key": f"build:{target['session_id']}",
        "printer_code": printer,
        "request_id": target.get("request_id"),
        "build_id": target.get("build_id"),
        "print_name": target.get("print_name"),
        "material": target.get("material"),
        "elapsed_minutes": started_min,
        "sequence": int(session.get("frames_sent") or 0) + 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "image_base64": frame_b64,
    }
    payload = {k: v for k, v in payload.items() if v is not None}

    response = await submit_frame(payload)
    if response is None:
        _update_session(
            session["id"],
            cm_errors=int(session.get("cm_errors") or 0) + 1,
            last_frame_hash=frame_hash,
        )
        return

    _update_session(
        session["id"],
        frames_sent=int(session.get("frames_sent") or 0) + 1,
        last_frame_at=_d("now_iso")(),
        last_frame_hash=frame_hash,
    )
    await _handle_response(session, target, response, frame_b64)


async def print_monitor_worker() -> None:
    print("[PRINT-MONITOR] Printellect Watch worker started")
    if _d("demo_mode")():
        print("[PRINT-MONITOR] Demo mode active - monitoring disabled")
        while True:
            await asyncio.sleep(60)

    while True:
        interval_s = _interval_seconds()
        try:
            if not _enabled() or not _monitor_url() or not _monitor_secret():
                await asyncio.sleep(interval_s)
                continue

            targets = get_active_targets()
            # Sequential on purpose: snapshot capture can hold an MJPEG stream
            # open for several seconds and printers share the LAN.
            for target in targets:
                try:
                    await _process_target(target, interval_s)
                except Exception as exc:
                    logger.warning(
                        "print_monitor target failed printer=%s: %s",
                        target.get("printer_code"), exc,
                    )
        except Exception as exc:
            logger.warning("print_monitor cycle failed: %s", exc)
        await asyncio.sleep(interval_s)


def start_print_monitor() -> None:
    """Start the monitor worker in its own thread + event loop (like the other
    background pollers). Call once at startup."""

    def run_async() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(print_monitor_worker())

    thread = threading.Thread(target=run_async, daemon=True)
    thread.start()
