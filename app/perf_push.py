"""
Push this app's performance snapshot to central-management over the *existing*
bug-report channel — same URL host, same per-app HMAC secret, same headers.

There is no new configuration and no new outbound connection type: if the app is
already set up to report bugs to cm (BUG_REPORT_URL / BUG_REPORT_SECRET /
BUG_APP_ID), it will also push perf snapshots to cm's /api/perf/ingest. cm's
single UI toggle decides whether to record them.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from urllib.parse import urlsplit, urlunsplit

import httpx

from app import perf
from app.bug_reporter import _app_id, _report_secret, _report_url

logger = logging.getLogger(__name__)

_INTERVAL_SECONDS = 60
_TIMEOUT_SECONDS = 5.0


def _derive_ingest_url(report_url: str) -> str | None:
    """Turn <base>/api/reports into <base>/api/perf/ingest."""
    parts = urlsplit(report_url or "")
    if not parts.scheme or not parts.netloc:
        return None
    path = parts.path.rstrip("/")
    if not path.endswith("/api/reports"):
        return None
    new_path = path[: -len("/api/reports")] + "/api/perf/ingest"
    return urlunsplit((parts.scheme, parts.netloc, new_path, "", ""))


async def _push_once() -> None:
    url = _report_url()
    secret = _report_secret()
    app_id = _app_id()
    if not url or not secret:
        return
    ingest_url = _derive_ingest_url(url)
    if not ingest_url:
        return
    collector = perf.get_collector()
    if collector is None:
        return

    body = json.dumps(collector.snapshot()).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
        await client.post(
            ingest_url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-JCubHub-App": app_id,
                "X-JCubHub-Signature": f"sha256={sig}",
            },
        )


async def run(interval: int = _INTERVAL_SECONDS) -> None:
    """Background loop: push a snapshot every `interval` seconds. Never raises."""
    while True:
        await asyncio.sleep(interval)
        try:
            await _push_once()
        except Exception as exc:  # metrics must never disrupt the app
            logger.debug("perf push failed: %s", exc)


def start() -> None:
    """Start the push loop as a background task on the running event loop."""
    asyncio.create_task(run())
