"""Printellect → JCubHub CM bug reporter.

Self-contained client for the JCubHub Sentinel report contract v1.0.0. Reports
unhandled exceptions, logged errors, and client-side JS errors to Central
Management. Fully fail-open: never raises, never blocks a request, guarded
against recursion. See CM docs/bug-tracking/REPORT_CONTRACT.md.

Env:
  BUG_REPORT_URL      e.g. https://mgmt.jcubhub.com/api/reports  (blank = disabled)
  BUG_REPORT_SECRET   the per-app HMAC secret registered in CM
  BUG_APP_ID          default "printellect"
  ENVIRONMENT, APP_VERSION are read by the caller and passed in.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import traceback
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("printellect.bug_reporter")

BUG_REPORT_URL = os.getenv("BUG_REPORT_URL", "").strip()
BUG_REPORT_SECRET = os.getenv("BUG_REPORT_SECRET", "").strip()
BUG_APP_ID = os.getenv("BUG_APP_ID", "printellect").strip()
_TIMEOUT = float(os.getenv("BUG_REPORT_TIMEOUT", "5"))

# Recursion guard + lightweight per-fingerprint throttle (don't resend the same
# error within the window).
_local = threading.local()
_THROTTLE_WINDOW = 60.0
_recent: dict[str, float] = {}
_recent_lock = threading.Lock()


def _enabled() -> bool:
    return bool(BUG_REPORT_URL and BUG_REPORT_SECRET)


def _fingerprint(message: str, stack: str | None) -> str:
    basis = f"{BUG_APP_ID}|{message[:200]}|{(stack or '')[:200]}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _throttled(fp: str) -> bool:
    now = time.monotonic()
    with _recent_lock:
        # prune
        for k, ts in list(_recent.items()):
            if now - ts > _THROTTLE_WINDOW:
                _recent.pop(k, None)
        if fp in _recent:
            return True
        _recent[fp] = now
    return False


def _post(payload: dict) -> None:
    try:
        body = json.dumps(payload).encode("utf-8")
        sig = hmac.new(BUG_REPORT_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
        with httpx.Client(timeout=_TIMEOUT) as client:
            client.post(
                BUG_REPORT_URL,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-JCubHub-App": BUG_APP_ID,
                    "X-JCubHub-Signature": f"sha256={sig}",
                    "X-JCubHub-Report-Contract": "1.0.0",
                },
            )
    except Exception as exc:  # fail open
        logger.debug("bug_report post failed: %s", exc)


def report(
    *,
    message: str,
    report_type: str = "error",
    severity: str | None = None,
    stack_trace: str | None = None,
    route: str | None = None,
    http_method: str | None = None,
    status_code: int | None = None,
    user_agent: str | None = None,
    reporter: str = "auto",
    reporter_email: str | None = None,
    context: dict | None = None,
    app_version: str | None = None,
    environment: str | None = None,
) -> None:
    """Fire-and-forget a report to CM. Safe to call from anywhere."""
    if not _enabled() or getattr(_local, "in_report", False):
        return
    try:
        _local.in_report = True
        fp = _fingerprint(message, stack_trace)
        if _throttled(fp):
            return
        payload = {
            "app_id": BUG_APP_ID,
            "type": report_type,
            "message": message[:4000],
            "severity": severity,
            "environment": environment,
            "app_version": app_version,
            "stack_trace": stack_trace[:16000] if stack_trace else None,
            "fingerprint": fp,
            "route": route,
            "http_method": http_method,
            "status_code": status_code,
            "user_agent": user_agent,
            "reporter": reporter,
            "reporter_email": reporter_email,
            "context": context,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        threading.Thread(target=_post, args=(payload,), daemon=True).start()
    except Exception as exc:
        logger.debug("bug_report build failed: %s", exc)
    finally:
        _local.in_report = False


def report_exception(exc: BaseException, **kwargs) -> None:
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    report(message=f"{type(exc).__name__}: {exc}", stack_trace=tb, **kwargs)


class BugReportLogHandler(logging.Handler):
    """Forward ERROR+ log records into the bug pipeline (covers background tasks
    and caught-and-logged errors). Never raises."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < logging.ERROR:
                return
            if record.name.startswith("printellect.bug_reporter"):
                return
            stack = None
            if record.exc_info:
                stack = "".join(traceback.format_exception(*record.exc_info))
            report(
                message=record.getMessage(),
                severity="medium",
                stack_trace=stack,
                context={"source": "logging", "logger": record.name},
            )
        except Exception:
            pass


def install_log_handler() -> None:
    """Attach the log handler to the root logger once (idempotent)."""
    if not _enabled():
        return
    root = logging.getLogger()
    if not any(isinstance(h, BugReportLogHandler) for h in root.handlers):
        root.addHandler(BugReportLogHandler(level=logging.ERROR))


# Client-side JS beacon. Inject into the base template so window.onerror and
# unhandledrejection (and a fetch wrapper) report client errors. The /feedback
# JS endpoint below proxies these to CM with the server-side secret (the browser
# never sees the secret).
CLIENT_BEACON_JS = """
(function () {
  function send(payload) {
    try {
      navigator.sendBeacon
        ? navigator.sendBeacon('/client-error', JSON.stringify(payload))
        : fetch('/client-error', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload), keepalive:true});
    } catch (e) {}
  }
  window.addEventListener('error', function (e) {
    send({message: (e && e.message) || 'window.onerror', stack: e && e.error && e.error.stack, route: location.pathname, type: 'error'});
  });
  window.addEventListener('unhandledrejection', function (e) {
    var r = e && e.reason;
    send({message: (r && r.message) || String(r) || 'unhandledrejection', stack: r && r.stack, route: location.pathname, type: 'error'});
  });
})();
"""
