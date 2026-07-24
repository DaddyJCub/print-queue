"""
In-app performance metrics collector.

Gives every JCubHub service an identical, dependency-light view of its own
runtime health so regressions (slow endpoints, memory growth, a blocked event
loop) show up as numbers instead of a vague "it felt slow".

Two consumers, one contract:
  * GET /api/perf       -> JSON, ingested by central-management's poller.
  * GET /api/perf.txt   -> a compact human-readable block you can copy/paste.

Two windows, as requested:
  * rolling  -> the last ~15 minutes (in-memory ring buffer, resets on restart).
  * since_boot -> cumulative totals since the process started.

No external dependencies are required: process metrics come from /proc on Linux
(all services run in linux/amd64 containers). If psutil happens to be installed
it is used as a faster path, but it is never required.

The module is deliberately self-contained so the same file can be dropped into
any FastAPI/Starlette service (print-queue, central-management, ...).
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from bisect import bisect_left
from collections import deque
from datetime import datetime, timezone
from typing import Callable

try:  # optional fast path; never required
    import psutil  # type: ignore

    _PROC = psutil.Process(os.getpid())
except Exception:  # pragma: no cover - psutil is optional
    psutil = None  # type: ignore
    _PROC = None

# Keep at most this many individual request samples for the rolling window.
# 20k samples is a few MB and comfortably covers 15 minutes for a homelab
# service; oldest samples are evicted first.
_MAX_SAMPLES = 20_000
_ROLLING_WINDOW_SECONDS = 900  # 15 minutes


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Nearest-rank percentile over a pre-sorted list. pct in [0, 100]."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 1)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac, 1)


class _RouteAggregate:
    __slots__ = ("count", "errors", "sum_ms", "max_ms")

    def __init__(self) -> None:
        self.count = 0
        self.errors = 0
        self.sum_ms = 0.0
        self.max_ms = 0.0


class PerfCollector:
    """Thread-safe, process-wide singleton collecting request + process metrics."""

    def __init__(self, app_name: str, app_version: str = "unknown") -> None:
        self.app_name = app_name
        self.app_version = app_version
        self._boot_monotonic = time.monotonic()
        self._boot_wall = time.time()
        self._lock = threading.Lock()

        # Rolling window: (monotonic_ts, route_key, dur_ms, is_error)
        self._samples: deque[tuple[float, str, float, bool]] = deque(maxlen=_MAX_SAMPLES)

        # Since-boot per-route aggregates, keyed by "METHOD route".
        self._since_boot: dict[str, _RouteAggregate] = {}
        self._since_boot_total = 0
        self._since_boot_errors = 0

        # CPU% needs two samples; remember the last one.
        self._last_cpu_wall: float | None = None
        self._last_cpu_seconds: float | None = None

        # Event-loop lag (ms), updated by an optional background monitor.
        self._event_loop_lag_ms: float | None = None

        # App-specific gauges: name -> zero-arg callable returning a number.
        self._gauges: dict[str, Callable[[], float]] = {}

    # ---- recording -------------------------------------------------------

    def record(self, method: str, route: str, dur_ms: float, status_code: int) -> None:
        key = f"{method} {route}"
        is_error = status_code >= 500
        now = time.monotonic()
        with self._lock:
            self._samples.append((now, key, dur_ms, is_error))
            agg = self._since_boot.get(key)
            if agg is None:
                agg = _RouteAggregate()
                self._since_boot[key] = agg
            agg.count += 1
            agg.sum_ms += dur_ms
            if dur_ms > agg.max_ms:
                agg.max_ms = dur_ms
            self._since_boot_total += 1
            if is_error:
                agg.errors += 1
                self._since_boot_errors += 1

    def register_gauge(self, name: str, fn: Callable[[], float]) -> None:
        """Register an app-specific numeric gauge (e.g. queue depth)."""
        self._gauges[name] = fn

    def set_event_loop_lag(self, lag_ms: float) -> None:
        self._event_loop_lag_ms = lag_ms

    # ---- process metrics -------------------------------------------------

    def _memory_rss_mb(self) -> float | None:
        if _PROC is not None:
            try:
                return round(_PROC.memory_info().rss / (1024 * 1024), 1)
            except Exception:
                pass
        try:
            with open(f"/proc/{os.getpid()}/status", "r") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        kb = float(line.split()[1])
                        return round(kb / 1024, 1)
        except Exception:
            pass
        return None

    def _cpu_percent(self) -> float | None:
        """CPU% consumed since the previous snapshot call (None on first call)."""
        now_wall = time.monotonic()
        try:
            t = os.times()
            cpu_seconds = t.user + t.system
        except Exception:
            return None
        prev_wall = self._last_cpu_wall
        prev_cpu = self._last_cpu_seconds
        self._last_cpu_wall = now_wall
        self._last_cpu_seconds = cpu_seconds
        if prev_wall is None or prev_cpu is None:
            return None
        elapsed = now_wall - prev_wall
        if elapsed <= 0:
            return None
        return round(((cpu_seconds - prev_cpu) / elapsed) * 100.0, 1)

    def _num_threads(self) -> int | None:
        try:
            return threading.active_count()
        except Exception:
            return None

    def _open_fds(self) -> int | None:
        try:
            return len(os.listdir(f"/proc/{os.getpid()}/fd"))
        except Exception:
            return None

    # ---- snapshot --------------------------------------------------------

    def snapshot(self) -> dict:
        now_mono = time.monotonic()
        cutoff = now_mono - _ROLLING_WINDOW_SECONDS

        with self._lock:
            # Drop anything older than the window, then copy what remains.
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.popleft()
            samples = list(self._samples)
            since_boot = {k: (v.count, v.errors, v.sum_ms, v.max_ms) for k, v in self._since_boot.items()}
            sb_total = self._since_boot_total
            sb_errors = self._since_boot_errors

        # ---- rolling window aggregation ----
        durations: dict[str, list[float]] = {}
        rolling_counts: dict[str, int] = {}
        rolling_errors: dict[str, int] = {}
        r_total = 0
        r_errors = 0
        for _ts, key, dur, is_err in samples:
            durations.setdefault(key, []).append(dur)
            rolling_counts[key] = rolling_counts.get(key, 0) + 1
            r_total += 1
            if is_err:
                rolling_errors[key] = rolling_errors.get(key, 0) + 1
                r_errors += 1

        rolling_routes = []
        for key, vals in durations.items():
            vals.sort()
            method, _, route = key.partition(" ")
            rolling_routes.append(
                {
                    "method": method,
                    "route": route,
                    "count": rolling_counts[key],
                    "errors": rolling_errors.get(key, 0),
                    "p50_ms": _percentile(vals, 50),
                    "p95_ms": _percentile(vals, 95),
                    "p99_ms": _percentile(vals, 99),
                    "max_ms": round(vals[-1], 1),
                }
            )
        rolling_routes.sort(key=lambda r: r["p95_ms"], reverse=True)

        since_boot_routes = []
        for key, (count, errors, sum_ms, max_ms) in since_boot.items():
            method, _, route = key.partition(" ")
            since_boot_routes.append(
                {
                    "method": method,
                    "route": route,
                    "count": count,
                    "errors": errors,
                    "mean_ms": round(sum_ms / count, 1) if count else 0.0,
                    "max_ms": round(max_ms, 1),
                }
            )
        since_boot_routes.sort(key=lambda r: r["mean_ms"], reverse=True)

        uptime = now_mono - self._boot_monotonic
        # Floor the elapsed span at 1s so req/min isn't nonsensical right after
        # boot (a handful of requests over ~0 seconds).
        window_minutes = max(min(uptime, _ROLLING_WINDOW_SECONDS), 1.0) / 60.0

        gauges = {}
        for name, fn in self._gauges.items():
            try:
                gauges[name] = fn()
            except Exception:
                gauges[name] = None

        return {
            "app": self.app_name,
            "version": self.app_version,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "uptime_seconds": int(uptime),
            "process": {
                "memory_rss_mb": self._memory_rss_mb(),
                "cpu_percent": self._cpu_percent(),
                "event_loop_lag_ms": self._event_loop_lag_ms,
                "num_threads": self._num_threads(),
                "open_fds": self._open_fds(),
            },
            "requests": {
                "rolling_window_seconds": _ROLLING_WINDOW_SECONDS,
                "rolling": {
                    "total": r_total,
                    "errors": r_errors,
                    "error_rate": round(r_errors / r_total, 4) if r_total else 0.0,
                    "req_per_min": round(r_total / window_minutes, 1) if window_minutes > 0 else 0.0,
                    "routes": rolling_routes,
                },
                "since_boot": {
                    "total": sb_total,
                    "errors": sb_errors,
                    "error_rate": round(sb_errors / sb_total, 4) if sb_total else 0.0,
                    "routes": since_boot_routes,
                },
            },
            "counters": gauges,
        }


# ---- text rendering ------------------------------------------------------


def _fmt_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def render_text(snap: dict, top_n: int = 8) -> str:
    """Render a snapshot as a compact, copy/paste-friendly block."""
    proc = snap["process"]
    rolling = snap["requests"]["rolling"]
    since = snap["requests"]["since_boot"]

    lines: list[str] = []
    lines.append(
        f"{snap['app']} v{snap['version']} @ {snap['generated_at']}  "
        f"up {_fmt_uptime(snap['uptime_seconds'])}"
    )

    def _n(v, suffix=""):
        return f"{v}{suffix}" if v is not None else "n/a"

    lines.append(
        f"mem {_n(proc['memory_rss_mb'], 'MB')}  "
        f"cpu {_n(proc['cpu_percent'], '%')}  "
        f"evloop_lag {_n(proc['event_loop_lag_ms'], 'ms')}  "
        f"threads {_n(proc['num_threads'])}  fds {_n(proc['open_fds'])}"
    )

    if snap.get("counters"):
        ctr = "  ".join(f"{k}={v}" for k, v in snap["counters"].items())
        lines.append(f"counters: {ctr}")

    lines.append(
        f"requests (last 15m): {rolling['total']}  "
        f"errors {rolling['errors']} ({rolling['error_rate'] * 100:.2f}%)  "
        f"{rolling['req_per_min']}/min"
    )
    if rolling["routes"]:
        lines.append("slowest routes (rolling p95):")
        for r in rolling["routes"][:top_n]:
            flag = "  <-- slow" if r["p95_ms"] >= 1000 else ""
            lines.append(
                f"  {r['method']:6}{r['route']:<34} "
                f"p50 {r['p50_ms']:>7.0f}ms  p95 {r['p95_ms']:>7.0f}ms  "
                f"max {r['max_ms']:>7.0f}ms  n={r['count']}"
                f"{('  err=' + str(r['errors'])) if r['errors'] else ''}{flag}"
            )

    lines.append(
        f"since boot: {since['total']} reqs  "
        f"errors {since['errors']} ({since['error_rate'] * 100:.2f}%)"
    )
    if since["routes"]:
        lines.append("slowest routes (since boot, by mean):")
        for r in since["routes"][:top_n]:
            lines.append(
                f"  {r['method']:6}{r['route']:<34} "
                f"mean {r['mean_ms']:>7.0f}ms  max {r['max_ms']:>7.0f}ms  n={r['count']}"
            )

    return "\n".join(lines)


# ---- FastAPI / Starlette integration ------------------------------------

_collector: PerfCollector | None = None


def get_collector() -> PerfCollector | None:
    return _collector


def install(app, app_name: str, app_version: str = "unknown") -> PerfCollector:
    """
    Install perf tracking on a FastAPI/Starlette app:
      * a middleware that times every request,
      * an optional event-loop lag monitor started on app startup,
      * GET /api/perf (JSON) and GET /api/perf.txt (text) endpoints.

    Returns the collector so callers can register app-specific gauges.
    """
    global _collector
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse

    collector = PerfCollector(app_name, app_version)
    _collector = collector

    class PerfMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            start = time.perf_counter()
            status_code = 500
            try:
                response = await call_next(request)
                status_code = response.status_code
                return response
            finally:
                dur_ms = (time.perf_counter() - start) * 1000.0
                # Prefer the matched route template (e.g. /printers/{id}) so
                # path params don't explode the cardinality. It is populated on
                # the shared scope during routing, which has completed by now.
                route_obj = request.scope.get("route")
                route = getattr(route_obj, "path", None) or request.url.path
                collector.record(request.method, route, dur_ms, status_code)

    app.add_middleware(PerfMiddleware)

    @app.on_event("startup")
    async def _start_event_loop_monitor() -> None:
        async def _monitor() -> None:
            interval = 1.0
            while True:
                before = time.perf_counter()
                await asyncio.sleep(interval)
                drift_ms = ((time.perf_counter() - before) - interval) * 1000.0
                collector.set_event_loop_lag(round(max(0.0, drift_ms), 2))

        asyncio.create_task(_monitor())

    @app.get("/api/perf")
    async def _perf_json():
        return JSONResponse(collector.snapshot())

    @app.get("/api/perf.txt")
    async def _perf_text():
        return PlainTextResponse(render_text(collector.snapshot()))

    return collector
