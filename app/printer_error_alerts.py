"""Printer error alerts — watch Klipper/Moonraker (ZMod) printers for faults.

A background worker that polls every Moonraker-backed printer and alerts admins
the moment the machine reports *any* fault: an MCU shutdown, thermal runaway, a
disconnected thermistor (ADC out of range), "Lost communication with MCU", a
Klipper config/startup error, a print aborted with an error, or a filament
runout/jam pause from the IFS/runout sensor.

Design goals (mirrors ``app.print_monitor``):
  * Dependency-injected — no import of ``app.main`` at module load (avoids the
    circular import), wired up via ``configure()`` at startup.
  * Fail-open — a printer being unreachable, or a malformed reply, never raises
    into the poll loop and never fabricates an alert.
  * Edge-triggered with a cooldown — one alert when a fault first appears, a
    reminder every ``cooldown`` minutes while it persists, and a "recovered"
    note when the machine returns to health. No alert-per-poll spam.

Detection is REST-only (``MoonrakerAPI.get_error_state``); no websocket needed.

Config lives in DB settings (admin UI editable, no redeploy):
  printer_error_alerts_enabled           "1"/"0"  (default off)
  printer_error_alerts_interval_seconds  default 20
  printer_error_alerts_cooldown_minutes  default 30
  printer_error_alerts_notify_email      "1"/"0"  (default on)
  printer_error_alerts_notify_recovery   "1"/"0"  (default on)

Env: ENABLE_PRINTER_ERROR_ALERTS gates the worker per replica (like the other
pollers).
"""
from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("printellect.printer_error_alerts")

# Injected from app.main at startup via configure() — same pattern as
# app.print_monitor / app.bug_reporter.
_deps: Dict[str, Callable] = {}


def configure(**deps: Callable) -> None:
    """Inject main-module callables. Required keys:

    db, now_iso, get_setting, get_bool_setting, get_printer_api,
    is_polling_paused, send_push_notification_to_admins, send_email,
    parse_email_list, get_printer_codes (0-arg -> List[str]), demo_mode
    (0-arg -> bool).
    """
    _deps.update(deps)


def _d(name: str) -> Callable:
    return _deps[name]


# ------------------------
# Schema
# ------------------------

def init_printer_error_tables(cur: sqlite3.Cursor) -> None:
    # One row per printer: the fault currently being tracked (if any).
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_error_state (
            printer_code TEXT PRIMARY KEY,
            severity TEXT,
            source TEXT,
            state TEXT,
            category TEXT,
            message TEXT,
            signature TEXT,          -- dedupe key; NULL/'' means "healthy"
            first_seen_at TEXT,
            last_seen_at TEXT,
            alerted_at TEXT,
            alert_count INTEGER DEFAULT 0,
            updated_at TEXT
        )
        """
    )
    # Append-only log for the admin UI / audit trail.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS printer_error_events (
            id TEXT PRIMARY KEY,
            printer_code TEXT,
            created_at TEXT,
            severity TEXT,
            source TEXT,
            state TEXT,
            category TEXT,
            message TEXT,
            action TEXT DEFAULT 'alerted'   -- alerted|reminded|recovered
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_printer_error_events_created "
        "ON printer_error_events(created_at)"
    )


# ------------------------
# Config helpers
# ------------------------

def _enabled() -> bool:
    return _d("get_bool_setting")("printer_error_alerts_enabled", False)


def _int_setting(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        raw = (_d("get_setting")(key, str(default)) or str(default)).strip()
        return max(minimum, min(maximum, int(raw)))
    except (TypeError, ValueError):
        return default


def _interval_seconds() -> int:
    return _int_setting("printer_error_alerts_interval_seconds", 20, 10, 300)


def _cooldown_minutes() -> int:
    return _int_setting("printer_error_alerts_cooldown_minutes", 30, 1, 720)


def _notify_email() -> bool:
    return _d("get_bool_setting")("printer_error_alerts_notify_email", True)


def _notify_recovery() -> bool:
    return _d("get_bool_setting")("printer_error_alerts_notify_recovery", True)


# ------------------------
# Error classification (pure — unit tested)
# ------------------------

# Ordered most-specific → generic. Each entry: (compiled regex, category,
# emoji, friendly one-liner). Matched against the lowercased Klipper message
# plus the raw state, so both "shutdown"/"error" states and message text hit.
_CLASSIFY_RULES = [
    (r"thermal runaway|not heating at (the )?expected rate|exceeds? max_?temp|"
     r"below min_?temp|heating fault",
     "thermal_fault", "🔥",
     "Heater fault / thermal runaway — Klipper shut down heating for safety."),
    (r"adc out of range",
     "thermistor_fault", "🌡️",
     "Thermistor reading out of range — a temperature sensor may be disconnected."),
    (r"lost communication with (the )?(mcu|host)|mcu '.*' shutdown|"
     r"can't communicate|unable to (open )?(serial|connect)|mcu.*shutdown",
     "mcu_comms", "🔌",
     "Lost communication with the printer's control board (MCU)."),
    (r"timer too close|missed scheduling|rescheduled timer",
     "timing_fault", "⏱️",
     "Klipper timing error (Timer too close) — the board fell behind."),
    (r"runout|run out|filament|jam|clog|tangle|no filament",
     "filament", "🧵",
     "Filament problem — runout, jam or clog detected."),
    (r"probe|z endstop|homing|failed to home|endstop still triggered",
     "homing_probe", "📐",
     "Homing / probe error — the printer couldn't establish position."),
    (r"shutdown",
     "klipper_shutdown", "🛑",
     "Klipper emergency shutdown — the printer halted."),
    (r"error|failed|fault",
     "klipper_error", "⚠️",
     "Klipper reported an error."),
]

_CLASSIFY_COMPILED = [
    (re.compile(pat, re.IGNORECASE), cat, emoji, friendly)
    for pat, cat, emoji, friendly in _CLASSIFY_RULES
]


def classify_error(err: Dict[str, Any]) -> Dict[str, str]:
    """Map a raw ``get_error_state`` dict to a friendly {category, emoji, headline}.

    Never raises; falls back to a generic bucket so an unrecognized Klipper
    message is still surfaced verbatim (the whole point: catch *any* error).
    """
    haystack = f"{err.get('state', '')} {err.get('message', '')}".lower()
    for rx, category, emoji, friendly in _CLASSIFY_COMPILED:
        if rx.search(haystack):
            return {"category": category, "emoji": emoji, "headline": friendly}
    return {
        "category": "printer_error",
        "emoji": "⚠️",
        "headline": "The printer reported an error.",
    }


def _signature(err: Dict[str, Any]) -> str:
    """Stable dedupe key so we don't re-alert the same persistent fault."""
    msg = re.sub(r"\s+", " ", str(err.get("message", "")).strip().lower())
    return f"{err.get('severity', '')}|{err.get('source', '')}|{msg}"[:400]


# ------------------------
# State persistence
# ------------------------

def _get_state(printer_code: str) -> Optional[Dict[str, Any]]:
    conn = _d("db")()
    try:
        row = conn.execute(
            "SELECT * FROM printer_error_state WHERE printer_code = ?",
            (printer_code,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _upsert_state(printer_code: str, **fields: Any) -> None:
    fields["printer_code"] = printer_code
    fields["updated_at"] = _d("now_iso")()
    cols = list(fields.keys())
    placeholders = ", ".join("?" for _ in cols)
    updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != "printer_code")
    conn = _d("db")()
    try:
        conn.execute(
            f"INSERT INTO printer_error_state ({', '.join(cols)}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT(printer_code) DO UPDATE SET {updates}",
            tuple(fields[c] for c in cols),
        )
        conn.commit()
    finally:
        conn.close()


def _clear_state(printer_code: str) -> None:
    """Mark a printer healthy again (blank signature, keep the row for history)."""
    _upsert_state(
        printer_code,
        severity=None, source=None, state=None, category=None, message=None,
        signature="", alerted_at=None, alert_count=0,
    )


def _record_event(
    printer_code: str, err: Dict[str, Any], cls: Dict[str, str], action: str
) -> None:
    conn = _d("db")()
    try:
        conn.execute(
            """
            INSERT INTO printer_error_events
                (id, printer_code, created_at, severity, source, state, category, message, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), printer_code, _d("now_iso")(),
                err.get("severity"), err.get("source"), err.get("state"),
                cls.get("category"), err.get("message"), action,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_events(limit: int = 20) -> List[Dict[str, Any]]:
    """Latest error/recovery events — used by the admin UI."""
    conn = _d("db")()
    try:
        rows = conn.execute(
            "SELECT * FROM printer_error_events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ------------------------
# Time helpers
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


# ------------------------
# Alerting
# ------------------------

def _printer_label(printer_code: str) -> str:
    try:
        for code, label in _d("get_printer_codes")(with_labels=True):
            if code == printer_code:
                return label
    except TypeError:
        pass
    return printer_code


def _alert(printer_code: str, err: Dict[str, Any], cls: Dict[str, str], reminder: bool) -> None:
    label = _printer_label(printer_code)
    sev = "warning" if err.get("severity") == "warning" else "error"
    prefix = "🔁 Still faulting" if reminder else ("⚠️ Printer warning" if sev == "warning" else "🚨 Printer error")
    title = f"{cls['emoji']} {prefix}: {label}"
    message = (err.get("message") or "").strip()
    body = cls["headline"]
    if message and message.lower() not in cls["headline"].lower():
        body = f"{cls['headline']}\n\n{message}"

    try:
        _d("send_push_notification_to_admins")(
            title, body, url="/admin/print-monitor",
            tag=f"printer-error-{printer_code}",
        )
    except Exception as exc:
        logger.warning("printer_error push alert failed printer=%s: %s", printer_code, exc)

    if _notify_email():
        try:
            admin_emails = _d("parse_email_list")(_d("get_setting")("admin_notify_emails", ""))
            if admin_emails:
                _d("send_email")(
                    admin_emails,
                    title,
                    f"{body}\n\nPrinter: {label} ({printer_code})\n"
                    f"State: {err.get('state', '?')}  ·  Source: {err.get('source', '?')}\n\n"
                    f"Open the printer dashboard: /admin/print-monitor",
                    None,
                )
        except Exception as exc:
            logger.warning("printer_error email alert failed printer=%s: %s", printer_code, exc)


def _notify_recovered(printer_code: str, prev: Dict[str, Any]) -> None:
    label = _printer_label(printer_code)
    try:
        _d("send_push_notification_to_admins")(
            f"✅ Printer recovered: {label}",
            f"{label} is back to normal after: {prev.get('message') or prev.get('category') or 'an error'}.",
            url="/admin/print-monitor",
            tag=f"printer-error-{printer_code}",
        )
    except Exception as exc:
        logger.warning("printer_error recovery push failed printer=%s: %s", printer_code, exc)


# ------------------------
# Per-printer check
# ------------------------

async def check_printer(printer_code: str) -> None:
    """Poll one printer's fault state and drive the alert state machine."""
    # Skip printers that aren't Moonraker-backed (FlashForge/agent have no
    # structured error channel here) and skip while a send/pause op holds the
    # printer, which can momentarily look like a fault.
    api = _d("get_printer_api")(printer_code)
    if api is None or not hasattr(api, "get_error_state"):
        return
    if _d("is_polling_paused")(printer_code):
        return

    try:
        err = await api.get_error_state()
    except Exception as exc:
        logger.debug("printer_error probe failed printer=%s: %s", printer_code, exc)
        return  # fail-open: unreachable printer is not a fault we can assert

    prev = _get_state(printer_code)
    prev_active = bool(prev and (prev.get("signature") or "").strip())

    # ── Healthy ────────────────────────────────────────────────────────────
    if err is None:
        if prev_active:
            cls = {"category": prev.get("category"), "emoji": "✅",
                   "headline": "Recovered"}
            _record_event(printer_code, {
                "severity": prev.get("severity"), "source": prev.get("source"),
                "state": "ready", "message": prev.get("message"),
            }, cls, action="recovered")
            _clear_state(printer_code)
            if _notify_recovery():
                _notify_recovered(printer_code, prev)
        return

    # ── Faulting ───────────────────────────────────────────────────────────
    cls = classify_error(err)
    sig = _signature(err)
    now = _d("now_iso")()

    if prev_active and prev.get("signature") == sig:
        # Same fault still present — remind only after the cooldown elapses.
        elapsed = _minutes_since(prev.get("alerted_at"))
        if elapsed is not None and elapsed < _cooldown_minutes():
            _upsert_state(printer_code, last_seen_at=now)
            return
        _alert(printer_code, err, cls, reminder=True)
        _record_event(printer_code, err, cls, action="reminded")
        _upsert_state(
            printer_code, last_seen_at=now, alerted_at=now,
            alert_count=int((prev.get("alert_count") or 0)) + 1,
        )
        return

    # New or changed fault — alert immediately.
    _alert(printer_code, err, cls, reminder=False)
    _record_event(printer_code, err, cls, action="alerted")
    _upsert_state(
        printer_code,
        severity=err.get("severity"), source=err.get("source"),
        state=err.get("state"), category=cls.get("category"),
        message=err.get("message"), signature=sig,
        first_seen_at=(prev.get("first_seen_at") if prev_active else now),
        last_seen_at=now, alerted_at=now,
        alert_count=(int(prev.get("alert_count") or 0) + 1) if prev_active else 1,
    )


# ------------------------
# Worker
# ------------------------

async def printer_error_alerts_worker() -> None:
    print("[PRINTER-ERROR] Printer error-alert worker started")
    if _d("demo_mode")():
        print("[PRINTER-ERROR] Demo mode active - error alerts disabled")
        while True:
            await asyncio.sleep(60)

    while True:
        interval_s = _interval_seconds()
        try:
            if not _enabled():
                await asyncio.sleep(interval_s)
                continue
            try:
                codes = list(_d("get_printer_codes")())
            except Exception:
                codes = []
            for code in codes:
                try:
                    await check_printer(code)
                except Exception as exc:
                    logger.warning("printer_error check failed printer=%s: %s", code, exc)
        except Exception as exc:
            logger.warning("printer_error cycle failed: %s", exc)
        await asyncio.sleep(interval_s)


def start_printer_error_alerts() -> None:
    """Start the worker in its own thread + event loop (like the other pollers)."""

    def run_async() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(printer_error_alerts_worker())

    thread = threading.Thread(target=run_async, daemon=True)
    thread.start()
