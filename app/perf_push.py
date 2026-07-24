"""
Push this app's performance snapshot to central-management over the *existing*
bug-report channel — the same POST /api/reports endpoint, same per-app HMAC
secret, same headers, with X-JCubHub-Kind: perf-snapshot so cm stores it as
metrics instead of a bug.

There is no new configuration, no new endpoint, and no new proxy bypass: if the
app is already set up to report bugs to cm (BUG_REPORT_URL / BUG_REPORT_SECRET /
BUG_APP_ID), it will also push perf snapshots. cm's single UI toggle decides
whether to record them.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging

import httpx

from app import perf
from app.bug_reporter import _app_id, _report_secret, _report_url

logger = logging.getLogger(__name__)

_INTERVAL_SECONDS = 60
_TIMEOUT_SECONDS = 5.0


async def _push_once() -> None:
    url = _report_url()
    secret = _report_secret()
    app_id = _app_id()
    if not url or not secret:
        return
    collector = perf.get_collector()
    if collector is None:
        return

    body = json.dumps(collector.snapshot()).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
        await client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-JCubHub-App": app_id,
                "X-JCubHub-Signature": f"sha256={sig}",
                "X-JCubHub-Kind": "perf-snapshot",
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
