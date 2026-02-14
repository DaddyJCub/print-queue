import os, uuid, sqlite3, hashlib, smtplib, ssl, urllib.parse, json, base64, secrets
import logging
from logging.handlers import RotatingFileHandler
from email.message import EmailMessage
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
import asyncio
import threading
from collections import deque

import httpx
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Demo mode for local testing with fake data
from app.demo_data import (
    DEMO_MODE, seed_demo_data, reset_demo_data, get_demo_status,
    get_demo_printer_status, get_demo_printer_job, get_demo_all_printers_status
)

# New auth system - multi-admin, user accounts, feature flags
from app.auth import (
    init_auth_tables, init_feature_flags, is_feature_enabled,
    get_current_user, get_current_admin, optional_user,
    get_or_create_legacy_admin, log_audit
)
from app.models import AuditAction

# ─────────────────────────── VERSION ───────────────────────────
APP_VERSION = "0.16.0"
#
# VERSIONING SCHEME (Semantic Versioning - semver.org):
# We use 0.x.y because this software is in initial development, not yet a stable public release.
# Per SemVer: "Major version zero (0.y.z) is for initial development."
# When we reach a stable, production-ready release, we'll bump to 1.0.0.
#
# For 0.x.y versions:
#   - 0.MINOR.0 = New features (what would be MINOR in 1.x.x)
#   - 0.x.PATCH = Bug fixes only
#
# Changelog:
# 0.16.0 - [FEATURE] Printellect device control foundation: user/account modal flow, private feature toggle management, device debug endpoint, Pico handoff docs, CI feature-flag fixes
# 0.15.1 - [PATCH] Camera fix: skip ustreamer placeholder frames, use Moonraker snapshot URL, Shippo webhook hardening, shipping from-address override, 295 tests
# 0.15.0 - [FEATURE] Shipping fulfillment: Shippo integration (rates, labels, tracking), admin shipping dashboard, requester shipping portal, webhook support, 291 tests
# 0.14.0 - [FEATURE] ETA local timezone: server defaults to CST/CDT, client-side JS converts to user's local time with timezone label, 282 tests
# 0.13.0 - [FEATURE] Moonraker live ETA integration, file linking (G-code ↔ STL/3MF), card-based files UI, 260 tests (94 Moonraker + 28 file linking)
# 0.12.1 - [PATCH] Auto-start next build after completion, auto-match IN_PROGRESS requests, improved error logging
# 0.12.0 - [FEATURE] Guest account creation tips in emails: subtle CTAs in all notification emails, pre-filled registration, auto-link existing requests
# 0.11.1 - [PATCH] Safer printer controls & admin progress alerts
# 0.11.0 - [FEATURE] Designer workflow with assignments and design completion tracking
# 0.10.0 - [MAJOR] User accounts system: registration/login, profiles, multi-admin, feature flags, user management
# 0.9.0 - [FEATURE] Admin PWA navigation: Admin tab in bottom nav, unified navigation on admin pages, My Prints pagination
# --- Version scheme changed from 1.x.x to 0.x.x (Dec 2025) - all prior versions below are historical ---
# 1.8.23 - Admin dashboard pagination: "show more" for long lists, collapsible Recently Closed section
# 1.8.22 - Admin request page UX: cleaner build configuration section, inline quick actions, collapsible edit forms
# 1.8.21 - Flexible build reordering: allow reordering queued builds even while other builds are printing
# 1.8.20 - Multi-build display fixes: "Build X/Y" format, accurate printing count, progress bar fix for current build
# 1.8.19 - Fix multi-build printer display: show builds printing on both printers simultaneously, fix auto-refresh losing printer cards
# 1.8.18 - Fix printer connection conflicts: added polling pause on print start, connection locking, retry logic, admin polling control
# 1.8.17 - User 3D model viewer (STL/OBJ/3MF support), enhanced build details, file download from My Request page
# 1.8.16 - Progress notifications at milestones (25/50/75/90%), broadcast system for app updates, admin broadcast page
# 1.8.15 - Multi-build UX: clearer status labels (Queued/Done vs READY/COMPLETED), tooltips, queue build progress
# 1.8.14 - Push notification robustness: safe body parsing, JSON API contract, /api/push/health endpoint
# 1.8.13 - Per-build photos gallery, push notification fixes (JSONDecodeError), diagnostics panel
# 1.8.12 - Build management: edit/delete builds, strict printer validation, robust form handling
# 1.8.10 - Fixed admin session persistence (cookie path/secure), added smoke check endpoint
# 1.8.7 - Added logging system, fixed database connection errors in requester portal
# 1.8.6 - Build state fixes for IN_PROGRESS status in My Requests
# 1.8.1 - Printer retry logic (3 retries before offline), admin per-status email controls, duplicate request fix
# 1.8.0 - Store feature, my-request enhancements (cancel/resubmit, live printer view)
# 1.7.3 - Timelapse API: list and download timelapse videos from printers
# 1.7.2 - Request templates: save and reuse common form configurations
# 1.7.1 - Dynamic rush pricing based on queue size
# 1.7.0 - Auto-refresh queue, printer suggestions, repeat requests, rush priority, changelog page
# 1.6.0 - Smart ETA: learns from print history, shows estimated completion dates
# 1.5.0 - Extended status API: current filename, layer progress from M119/M27
# 1.4.0 - Camera streaming, auto-complete with snapshots, login redirect fix
# 1.3.0 - FlashForge printer integration, ETA calculations, analytics
# 1.2.0 - Admin dashboard, priority system, email notifications
# 1.1.0 - File uploads, status tracking, public queue
# 1.0.0 - Initial release

# ─────────────────────────── LOGGING SETUP ───────────────────────────
# In-memory log buffer for quick access via API
LOG_BUFFER_SIZE = 1000
log_buffer = deque(maxlen=LOG_BUFFER_SIZE)

class BufferHandler(logging.Handler):
    """Custom handler that stores logs in memory buffer"""
    def emit(self, record):
        try:
            msg = self.format(record)
            exc_text = None
            if record.exc_info:
                import traceback
                exc_text = ''.join(traceback.format_exception(*record.exc_info))
            log_buffer.append({
                "time": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "module": record.module,
                "name": record.name,
                "message": record.getMessage(),
                "formatted": msg,
                "exc_info": exc_text,
            })
        except Exception:
            pass

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", "/data/printellect.log")

# Create formatters
log_format = logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Setup root logger to capture ALL logs (including uvicorn, fastapi, httpx, etc.)
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Our app logger
logger = logging.getLogger("printellect")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Console handler - attached to root to capture everything
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)
console_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Buffer handler (for API access) - attached to root to capture everything
buffer_handler = BufferHandler()
buffer_handler.setFormatter(log_format)
buffer_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Add handlers to root logger (captures all loggers including uvicorn, fastapi)
root_logger.addHandler(console_handler)
root_logger.addHandler(buffer_handler)

# File handler (optional, only if writable)
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    # Avoid rotation to prevent file rename conflicts on Windows + reload workers
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=0,  # 0 disables rotation
        backupCount=0,
        delay=True,
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    root_logger.addHandler(file_handler)
    logger.info(f"File logging enabled: {LOG_FILE}")
except Exception as e:
    logger.warning(f"Could not enable file logging: {e}")

# Redirect print() statements to logger
class PrintToLogger:
    """Intercepts print() calls and sends them to the logger"""
    def __init__(self, logger, level=logging.INFO):
        self.logger = logger
        self.level = level
        self.buffer = ""
    
    def write(self, message):
        try:
            if message and message.strip():
                self.logger.log(self.level, message.rstrip())
        except Exception:
            # Never let logging failures break stdout/stderr writes
            pass
    
    def flush(self):
        try:
            return
        except Exception:
            pass
    
    def isatty(self):
        return False  # Needed for log formatters that expect a real stream
    
    def fileno(self):
        return 1  # Dummy fd for handlers that expect one

# Redirect stdout/stderr to capture print() statements
# In test mode we skip stream redirection because TestClient lifespan can hang with wrapped stdio streams.
import sys
TEST_MODE = os.getenv("TEST_MODE", "0").strip().lower() in ("1", "true", "yes")
if not TEST_MODE:
    sys.stdout = PrintToLogger(logging.getLogger("printellect.stdout"), logging.INFO)
    sys.stderr = PrintToLogger(logging.getLogger("printellect.stderr"), logging.ERROR)
    logger.info(f"Logging initialized at level {LOG_LEVEL} - capturing all output")
else:
    logger.info(f"Logging initialized at level {LOG_LEVEL} (test mode, stdio passthrough)")

# ─────────────────────────── HELPER FUNCTIONS ───────────────────────────
def row_get(row, key, default=None):
    """
    Safely get a value from a sqlite3.Row or dict.
    sqlite3.Row doesn't support .get(), so this provides a consistent interface.
    """
    if row is None:
        return default
    try:
        # Try bracket notation first (works for both Row and dict)
        val = row[key]
        return val if val is not None else default
    except (KeyError, IndexError):
        return default

APP_TITLE = "Printellect"

DB_PATH = os.getenv("DB_PATH", "/data/app.db")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/uploads")
BASE_URL = os.getenv("BASE_URL", "http://localhost:3000")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")

ALLOWED_EXTS = set([e.strip().lower() for e in os.getenv("ALLOWED_EXTS", ".stl,.3mf,.obj,.gcode,.step,.stp,.fpp,.zip").split(",") if e.strip()])
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")

# VAPID keys for Web Push notifications
# Generate new keys with this Python command:
# python -c "from cryptography.hazmat.primitives.asymmetric import ec; from cryptography.hazmat.backends import default_backend; import base64; key = ec.generate_private_key(ec.SECP256R1(), default_backend()); pn = key.private_numbers(); pub = pn.public_numbers; print('VAPID_PRIVATE_KEY=' + base64.urlsafe_b64encode(pn.private_value.to_bytes(32, 'big')).decode().rstrip('=')); print('VAPID_PUBLIC_KEY=' + base64.urlsafe_b64encode(b'\\x04' + pub.x.to_bytes(32, 'big') + pub.y.to_bytes(32, 'big')).decode().rstrip('='))"
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_CLAIMS_EMAIL = os.getenv("VAPID_CLAIMS_EMAIL", "mailto:admin@example.com")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# FastAPI app with reverse proxy support (trust X-Forwarded-* headers for HTTPS detection)

app = FastAPI(title=APP_TITLE)

# Exception handler middleware to log all unhandled exceptions
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

class ExceptionLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logger.error(
                f"Unhandled exception on {request.method} {request.url.path}: {e}",
                exc_info=True
            )
            raise

app.add_middleware(ExceptionLoggingMiddleware)

# Security middleware for CSRF, rate limiting, and security headers
from app.security import (
    CSRFMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware,
    get_csrf_token, csrf_input
)

# Add security middleware (order matters: first added = outermost)
# SecurityHeaders should be outermost to add headers to all responses
app.add_middleware(SecurityHeadersMiddleware)
# Rate limiting should be before CSRF to block excessive requests early
app.add_middleware(RateLimitMiddleware)
# CSRF middleware adds tokens to requests
app.add_middleware(CSRFMiddleware)

# --- Serve /sw.js from site root for PWA ---
from fastapi.responses import FileResponse
templates = Jinja2Templates(directory="app/templates")

# Timezone for display (default to US Eastern)
DISPLAY_TIMEZONE = os.getenv("DISPLAY_TIMEZONE", "America/New_York")

def format_datetime_local(value, fmt="%b %d, %Y at %I:%M %p"):
    """Convert ISO datetime string to local timezone for display"""
    if not value:
        return ""
    try:
        from datetime import timezone
        # Parse the ISO string
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = value
        
        # Convert to target timezone
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(DISPLAY_TIMEZONE)
            local_dt = dt.astimezone(tz)
        except Exception:
            # Fallback: just use UTC offset for US Eastern (-5 or -4 DST)
            from datetime import timedelta
            local_dt = dt - timedelta(hours=5)  # EST approximation
        
        return local_dt.strftime(fmt)
    except Exception:
        return str(value)

# Register filter with Jinja
templates.env.filters["localtime"] = format_datetime_local

# Register CSRF helper function as a global for templates
templates.env.globals["csrf_input"] = csrf_input
templates.env.globals["get_csrf_token"] = get_csrf_token

# NOTE: app/static must exist in your repo (can be empty with a .gitkeep)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ─────────────────────────── ERROR HANDLERS ───────────────────────────
# Custom error pages for better UX

from starlette.exceptions import HTTPException as StarletteHTTPException

ERROR_MESSAGES = {
    400: {
        "title": "Bad Request",
        "message": "Hmm, something's not quite right with that request. Double-check what you're trying to do and give it another shot!"
    },
    401: {
        "title": "Not Authorized",
        "message": "You'll need to log in first to access this page. Don't worry, it only takes a second!"
    },
    403: {
        "title": "Access Denied",
        "message": "Oops! Looks like you don't have permission to view this page. If you think this is a mistake, try logging in again."
    },
    404: {
        "title": "Page Not Found",
        "message": "Uh oh... we couldn't find what you were looking for. It might have been moved, deleted, or maybe the link is just taking a coffee break."
    },
    405: {
        "title": "Method Not Allowed",
        "message": "Whoops! That action isn't supported here. Try a different approach!"
    },
    408: {
        "title": "Request Timeout",
        "message": "That took a bit too long. The server got tired of waiting. Mind trying again?"
    },
    429: {
        "title": "Too Many Requests",
        "message": "Whoa there, speedster! You're going a bit too fast. Take a breather and try again in a moment."
    },
    500: {
        "title": "Something Went Wrong",
        "message": "Ope... not sure what happened there. We've logged this hiccup and will look into it. Try refreshing or come back in a bit!"
    },
    502: {
        "title": "Bad Gateway",
        "message": "Looks like there's a communication problem between our servers. Hang tight while we sort this out!"
    },
    503: {
        "title": "Service Unavailable",
        "message": "We're temporarily offline for maintenance or experiencing high traffic. We'll be back shortly!"
    },
    504: {
        "title": "Gateway Timeout",
        "message": "The server took too long to respond. Please try again in a moment."
    },
}

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with custom error pages"""
    error_code = exc.status_code
    error_info = ERROR_MESSAGES.get(error_code, {
        "title": "Error",
        "message": "Something unexpected happened. Please try again."
    })
    
    # Log the error
    logger.warning(f"HTTP {error_code} on {request.method} {request.url.path}: {exc.detail}")
    
    # Check if this is an API request (wants JSON response)
    accept_header = request.headers.get("accept", "")
    if "application/json" in accept_header and "text/html" not in accept_header:
        return Response(
            content=json.dumps({"detail": exc.detail or error_info["message"]}),
            status_code=error_code,
            media_type="application/json"
        )
    
    # Return HTML error page
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "error_code": error_code,
            "title": error_info["title"],
            "message": error_info["message"],
            "detail": exc.detail,
            "show_details": error_code >= 400 and error_code < 500,  # Show details for client errors
        },
        status_code=error_code
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions with a friendly error page"""
    import traceback
    
    # Log the full exception
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: {exc}",
        exc_info=True
    )
    
    # Get full traceback for error report
    tb_str = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    
    # Generate error ID for reference
    error_id = str(uuid.uuid4())[:8]
    
    # Try to save error to feedback table for admin review
    try:
        error_message = f"""🔴 Automatic Error Report (ID: {error_id})

URL: {request.method} {request.url}
Error: {type(exc).__name__}: {str(exc)}

User Agent: {request.headers.get('user-agent', 'N/A')[:200]}
Referer: {request.headers.get('referer', 'N/A')}

Traceback:
{tb_str[:2000]}"""
        
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        feedback_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO feedback (id, type, name, email, message, page_url, user_agent, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)""",
            (feedback_id, "error", "System", None, error_message.strip(), 
             str(request.url), request.headers.get('user-agent', '')[:500], datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
        conn.close()
        logger.info(f"Error report saved to feedback table with ID: {feedback_id}")
    except Exception as save_err:
        logger.error(f"Failed to save error report: {save_err}")
    
    error_info = ERROR_MESSAGES[500]
    
    # Check if this is an API request (wants JSON response)
    accept_header = request.headers.get("accept", "")
    if "application/json" in accept_header and "text/html" not in accept_header:
        return Response(
            content=json.dumps({"detail": "Internal server error", "error_id": error_id}),
            status_code=500,
            media_type="application/json"
        )
    
    # Return HTML error page
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "error_code": 500,
            "title": error_info["title"],
            "message": error_info["message"],
            "detail": str(exc) if os.getenv("DEBUG", "").lower() == "true" else None,
            "show_details": False,  # Don't show details for server errors in production
            "error_id": error_id,
        },
        status_code=500
    )

# Global printer status cache with retry logic
# Stores last successful status and failure count per printer
_printer_status_cache: Dict[str, Dict[str, Any]] = {}
_printer_failure_count: Dict[str, int] = {}
_printer_last_seen: Dict[str, str] = {}  # Timestamp of last successful poll

# Printer connection locks - prevents polling during print operations
# Uses asyncio.Lock for each printer to prevent simultaneous connections
_printer_locks: Dict[str, asyncio.Lock] = {}
_polling_paused_until: Dict[str, float] = {}  # Timestamp when to resume polling per printer
_POLL_PAUSE_DURATION = 30  # Seconds to pause polling after print operation

def get_printer_lock(printer_code: str) -> asyncio.Lock:
    """Get or create an asyncio lock for a specific printer"""
    if printer_code not in _printer_locks:
        _printer_locks[printer_code] = asyncio.Lock()
    return _printer_locks[printer_code]

def pause_printer_polling(printer_code: str, duration: int = None):
    """Pause polling for a printer for specified duration (default 30s)"""
    import time
    pause_duration = duration if duration is not None else _POLL_PAUSE_DURATION
    _polling_paused_until[printer_code] = time.time() + pause_duration
    print(f"[POLL] Pausing polling for {printer_code} for {pause_duration}s")
    add_poll_debug_log({
        "type": "poll_paused",
        "printer": printer_code,
        "duration": pause_duration,
        "message": f"Polling paused for {pause_duration}s (print operation in progress)"
    })

def is_polling_paused(printer_code: str) -> bool:
    """Check if polling is currently paused for a printer"""
    import time
    if printer_code not in _polling_paused_until:
        return False
    return time.time() < _polling_paused_until[printer_code]

def resume_printer_polling(printer_code: str):
    """Resume polling for a printer immediately"""
    if printer_code in _polling_paused_until:
        del _polling_paused_until[printer_code]
        print(f"[POLL] Resumed polling for {printer_code}")

# Debug log storage for polling diagnostics (circular buffer of last 100 entries)
_poll_debug_log: List[Dict[str, Any]] = []
_poll_debug_max_entries = 100

def add_poll_debug_log(entry: Dict[str, Any]):
    """Add an entry to the polling debug log"""
    global _poll_debug_log
    entry["timestamp"] = now_iso()
    _poll_debug_log.append(entry)
    # Keep only the last N entries
    if len(_poll_debug_log) > _poll_debug_max_entries:
        _poll_debug_log = _poll_debug_log[-_poll_debug_max_entries:]

def get_poll_debug_log() -> List[Dict[str, Any]]:
    """Get the polling debug log (newest first)"""
    return list(reversed(_poll_debug_log))

def get_cached_printer_status(printer_code: str) -> Optional[Dict[str, Any]]:
    """Get cached printer status (used during retry period)"""
    return _printer_status_cache.get(printer_code)

def get_printer_last_seen(printer_code: str) -> Optional[str]:
    """Get timestamp when printer was last successfully polled"""
    return _printer_last_seen.get(printer_code)

def update_printer_status_cache(printer_code: str, status: Dict[str, Any]):
    """Update cached printer status on successful poll"""
    _printer_status_cache[printer_code] = status
    _printer_last_seen[printer_code] = now_iso()
    _printer_failure_count[printer_code] = 0  # Reset failure count on success

def record_printer_failure(printer_code: str) -> int:
    """Record a printer poll failure and return the new failure count"""
    _printer_failure_count[printer_code] = _printer_failure_count.get(printer_code, 0) + 1
    return _printer_failure_count[printer_code]

def get_printer_failure_count(printer_code: str) -> int:
    """Get current failure count for a printer"""
    return _printer_failure_count.get(printer_code, 0)


async def fetch_printer_status_with_cache(printer_code: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Fetch printer status with cache fallback and timeout.
    Returns status dict with 'is_cached' flag if using cached data.
    Always includes camera_url even if offline.
    
    In DEMO_MODE, returns fake printer data instead of polling real printers.
    """
    camera_url = get_camera_url(printer_code)
    
    # Return demo data if in demo mode
    if DEMO_MODE:
        demo_status = get_demo_printer_status(printer_code)
        if demo_status:
            return {
                **demo_status,
                "camera_url": camera_url,
                "is_cached": False,
                "is_offline": False,
                "last_seen": now_iso(),
            }
        # Unknown printer in demo mode
        return {
            "status": "READY",
            "healthy": True,
            "is_printing": False,
            "camera_url": camera_url,
            "is_cached": False,
            "is_offline": False,
        }
    
    # Try live API first with short timeout
    try:
        printer_api = get_printer_api(printer_code)
        if printer_api:
            # Use asyncio.wait_for for timeout
            status = await asyncio.wait_for(printer_api.get_status(), timeout=timeout)
            
            if status:
                # Success - fetch additional data with timeouts
                progress = None
                temp_data = None
                extended = None
                
                try:
                    progress = await asyncio.wait_for(printer_api.get_percent_complete(), timeout=timeout)
                except:
                    pass
                    
                try:
                    temp_data = await asyncio.wait_for(printer_api.get_temperature(), timeout=timeout)
                except:
                    pass
                    
                try:
                    extended = await asyncio.wait_for(printer_api.get_extended_status(), timeout=timeout)
                except:
                    pass
                
                machine_status = status.get("MachineStatus", "UNKNOWN")
                result = {
                    "status": machine_status.replace("_FROM_SD", ""),
                    "temp": temp_data.get("Temperature", "").split("/")[0] if temp_data else None,
                    "target_temp": temp_data.get("TargetTemperature") if temp_data else None,
                    "progress": progress,
                    "healthy": machine_status in ["READY", "PRINTING", "BUILDING", "BUILDING_FROM_SD", "BUILD_COMPLETE", "BUILD_COMPLETE_FROM_SD", "PAUSED"],
                    "is_printing": machine_status in ["BUILDING", "BUILDING_FROM_SD"],
                    "current_file": extended.get("current_file") if extended else None,
                    "current_layer": extended.get("current_layer") if extended else None,
                    "total_layers": extended.get("total_layers") if extended else None,
                    "camera_url": camera_url,
                    "is_cached": False,
                    "last_seen": now_iso(),
                }
                
                # Moonraker-specific enrichment (extra data not available from FlashForge)
                if isinstance(printer_api, MoonrakerAPI):
                    result["is_moonraker"] = True
                    result["is_paused"] = machine_status == "PAUSED"
                    
                    # Bed temperature
                    try:
                        bed_data = await asyncio.wait_for(printer_api.get_bed_temp(), timeout=timeout)
                        if bed_data:
                            result["bed_temp"] = bed_data.get("temperature")
                            result["bed_target"] = bed_data.get("target")
                    except Exception:
                        pass
                    
                    # Extended Moonraker fields from the already-fetched extended status
                    if extended:
                        result["print_duration"] = extended.get("print_duration")
                        result["filament_used_m"] = round(extended.get("filament_used", 0) / 1000, 2) if extended.get("filament_used") else None
                    
                    # File-based ETA (the accurate 'File' time from Fluidd)
                    try:
                        file_eta_total = await asyncio.wait_for(printer_api.get_file_eta_seconds(), timeout=timeout)
                        if file_eta_total:
                            result["slicer_total_seconds"] = file_eta_total
                        time_remaining = await asyncio.wait_for(printer_api.get_time_remaining(), timeout=timeout)
                        if time_remaining is not None:
                            result["moonraker_time_remaining"] = time_remaining
                    except Exception:
                        pass
                    
                    # Thumbnail URL
                    try:
                        thumb = await asyncio.wait_for(printer_api.get_thumbnail_url(), timeout=timeout)
                        if thumb:
                            result["thumbnail_url"] = thumb
                    except Exception:
                        pass
                
                # Update cache on success
                update_printer_status_cache(printer_code, result)
                return result
                
    except asyncio.TimeoutError:
        logger.warning(f"[PRINTER] Timeout fetching status for {printer_code}")
        record_printer_failure(printer_code)
    except Exception as e:
        logger.warning(f"[PRINTER] Error fetching status for {printer_code}: {e}")
        record_printer_failure(printer_code)
    
    # API failed - try to use cached status
    cached = get_cached_printer_status(printer_code)
    last_seen = get_printer_last_seen(printer_code)
    
    if cached:
        # Return cached status with offline indicator
        return {
            **cached,
            "camera_url": camera_url,  # Always include camera
            "is_cached": True,
            "is_offline": True,
            "last_seen": last_seen,
        }
    
    # No cache available - return minimal offline status
    return {
        "status": None,
        "temp": None,
        "target_temp": None,
        "progress": None,
        "healthy": None,
        "is_printing": False,
        "current_file": None,
        "current_layer": None,
        "total_layers": None,
        "camera_url": camera_url,
        "is_cached": False,
        "is_offline": True,
        "last_seen": None,
    }

# Status flow for admin actions (request-level)
STATUS_FLOW = ["NEW", "NEEDS_INFO", "APPROVED", "IN_PROGRESS", "PRINTING", "BLOCKED", "DONE", "PICKED_UP", "REJECTED", "CANCELLED"]

# Build-level status flow (for multi-build requests)
BUILD_STATUS_FLOW = ["PENDING", "READY", "PRINTING", "COMPLETED", "FAILED", "SKIPPED"]

# Valid build state transitions
BUILD_TRANSITIONS = {
    "PENDING": ["READY", "SKIPPED"],
    "READY": ["PRINTING", "SKIPPED"],
    "PRINTING": ["COMPLETED", "FAILED"],
    "COMPLETED": [],  # Terminal state
    "FAILED": ["PENDING", "SKIPPED"],  # Can retry (back to PENDING) or skip
    "SKIPPED": [],  # Terminal state
}

# Dropdown options (Any is the default)
PRINTERS = [
    ("ANY", "Any"),
    ("ADVENTURER_4", "FlashForge Adventurer 4"),
    ("AD5X", "FlashForge AD5X"),
]

MATERIALS = [
    ("ANY", "Any"),
    ("PLA", "PLA"),
    ("PETG", "PETG"),
    ("ABS", "ABS"),
    ("TPU", "TPU"),
    ("RESIN", "Resin"),
    ("OTHER", "Other"),
]


def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    
    # Enable WAL mode for better concurrency (allows reads during writes)
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=30000")  # 30 second timeout

    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      requester_name TEXT NOT NULL,
      requester_email TEXT NOT NULL,
      printer TEXT NOT NULL,
      material TEXT NOT NULL,
      colors TEXT NOT NULL,
      link_url TEXT,
      notes TEXT,
      status TEXT NOT NULL,
      fulfillment_method TEXT NOT NULL DEFAULT 'pickup'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      stored_filename TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT,
      FOREIGN KEY(request_id) REFERENCES requests(id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS status_events (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      from_status TEXT,
      to_status TEXT NOT NULL,
      comment TEXT,
      FOREIGN KEY(request_id) REFERENCES requests(id)
    );
    """)

    # Shipping details per request (for fulfillment_method='shipping')
    cur.execute("""
    CREATE TABLE IF NOT EXISTS request_shipping (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      shipping_status TEXT NOT NULL DEFAULT 'REQUESTED',
      recipient_name TEXT,
      recipient_phone TEXT,
      address_line1 TEXT,
      address_line2 TEXT,
      city TEXT,
      state TEXT,
      postal_code TEXT,
      country TEXT DEFAULT 'US',
      service_preference TEXT,
      address_validation_status TEXT,
      address_validation_messages TEXT,
      normalized_address_json TEXT,
      package_weight_oz REAL,
      package_length_in REAL,
      package_width_in REAL,
      package_height_in REAL,
      quote_amount_cents INTEGER,
      quote_currency TEXT DEFAULT 'USD',
      quote_notes TEXT,
      quoted_at TEXT,
      quoted_by TEXT,
      selected_rate_id TEXT,
      provider TEXT DEFAULT 'shippo',
      provider_shipment_id TEXT,
      provider_transaction_id TEXT,
      carrier TEXT,
      service TEXT,
      rate_amount TEXT,
      tracking_number TEXT,
      tracking_status TEXT,
      tracking_url TEXT,
      label_url TEXT,
      label_pdf_url TEXT,
      shipped_at TEXT,
      delivered_at TEXT,
      last_provider_payload TEXT,
      metadata_json TEXT,
      FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS request_shipping_rate_snapshots (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'shippo',
      parcel_weight_oz REAL,
      parcel_length_in REAL,
      parcel_width_in REAL,
      parcel_height_in REAL,
      selected_rate_id TEXT,
      fetched_by TEXT,
      rates_json TEXT NOT NULL,
      FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS request_shipping_events (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      event_type TEXT NOT NULL,
      shipping_status TEXT,
      provider TEXT,
      provider_event_id TEXT,
      message TEXT,
      payload_json TEXT,
      FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
      UNIQUE(provider, provider_event_id)
    );
    """)

    # Settings table (key/value)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    """)

    # Print history for learning ETAs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS print_history (
      id TEXT PRIMARY KEY,
      request_id TEXT,
      printer TEXT NOT NULL,
      material TEXT,
      print_name TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      duration_minutes INTEGER NOT NULL,
      estimated_minutes INTEGER,
      total_layers INTEGER,
      file_name TEXT,
      created_at TEXT NOT NULL
    );
    """)

    # Request templates for quick resubmission
    cur.execute("""
    CREATE TABLE IF NOT EXISTS request_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      requester_name TEXT,
      requester_email TEXT,
      printer TEXT,
      material TEXT,
      colors TEXT,
      notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    """)

    # Messages for two-way communication on requests
    cur.execute("""
    CREATE TABLE IF NOT EXISTS request_messages (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      sender_type TEXT NOT NULL,
      message TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      FOREIGN KEY(request_id) REFERENCES requests(id)
    );
    """)
    # sender_type: 'admin' or 'requester'
    # is_read: 0 = unread, 1 = read (for notification badges)

    # Email lookup tokens for "My Requests" magic link authentication
    cur.execute("""
    CREATE TABLE IF NOT EXISTS email_lookup_tokens (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE,
      short_code TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    """)
    
    # Add short_code column if not exists (migration for existing DBs)
    try:
        cur.execute("ALTER TABLE email_lookup_tokens ADD COLUMN short_code TEXT")
    except:
        pass  # Column already exists

    # Store items - pre-made prints people can request
    cur.execute("""
    CREATE TABLE IF NOT EXISTS store_items (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT,
      material TEXT,
      colors TEXT,
      estimated_time_minutes INTEGER,
      image_data TEXT,
      link_url TEXT,
      notes TEXT,
      is_active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    """)
    # image_data: base64 encoded thumbnail image
    # is_active: 1 = visible in store, 0 = hidden

    # Store item files - pre-loaded files for store items
    cur.execute("""
    CREATE TABLE IF NOT EXISTS store_item_files (
      id TEXT PRIMARY KEY,
      store_item_id TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      stored_filename TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(store_item_id) REFERENCES store_items(id)
    );
    """)

    # Feedback table for bug reports and suggestions
    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      name TEXT,
      email TEXT,
      message TEXT NOT NULL,
      page_url TEXT,
      user_agent TEXT,
      status TEXT DEFAULT 'new',
      admin_notes TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT
    );
    """)

    # Push notification subscriptions
    cur.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    # Builds table - individual builds within a multi-build request
    cur.execute("""
        CREATE TABLE IF NOT EXISTS builds (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            build_number INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            printer TEXT,
            material TEXT,
            print_name TEXT,
            print_time_minutes INTEGER,
            slicer_estimate_minutes INTEGER,
            started_at TEXT,
            completed_at TEXT,
            progress INTEGER,
            final_temperature TEXT,
            file_name TEXT,
            total_layers INTEGER,
            notes TEXT,
            colors TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id)
        );
    """)

    # Build status events - history of build state changes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS build_status_events (
            id TEXT PRIMARY KEY,
            build_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL,
            comment TEXT,
            FOREIGN KEY(build_id) REFERENCES builds(id)
        );
    """)

    # Build snapshots - completion photos per build
    cur.execute("""
        CREATE TABLE IF NOT EXISTS build_snapshots (
            id TEXT PRIMARY KEY,
            build_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            snapshot_data TEXT NOT NULL,
            snapshot_type TEXT DEFAULT 'completion',
            FOREIGN KEY(build_id) REFERENCES builds(id)
        );
    """)

    # Build progress milestones - tracks which progress notifications have been sent per build
    # This prevents duplicate notifications when progress is re-polled
    cur.execute("""
        CREATE TABLE IF NOT EXISTS build_progress_milestones (
            id TEXT PRIMARY KEY,
            build_id TEXT NOT NULL,
            milestone_percent INTEGER NOT NULL,
            notified_at TEXT NOT NULL,
            notification_type TEXT DEFAULT 'push',
            FOREIGN KEY(build_id) REFERENCES builds(id),
            UNIQUE(build_id, milestone_percent)
        );
    """)

    # Broadcast notifications - history of system-wide notifications sent to all subscribers
    cur.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_notifications (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            url TEXT,
            broadcast_type TEXT DEFAULT 'custom',
            sent_at TEXT NOT NULL,
            sent_by TEXT,
            total_sent INTEGER DEFAULT 0,
            total_failed INTEGER DEFAULT 0,
            metadata TEXT
        );
    """)

    # User notification preferences - per-user settings for notification types
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_notification_prefs (
            email TEXT PRIMARY KEY,
            progress_push INTEGER DEFAULT 1,
            progress_email INTEGER DEFAULT 0,
            progress_milestones TEXT DEFAULT '50,75',
            status_push INTEGER DEFAULT 1,
            status_email INTEGER DEFAULT 1,
            broadcast_push INTEGER DEFAULT 1,
            updated_at TEXT
        );
    """)

    # ──────────────────────────────────────────────────────────────────────────
    # TRIPS FEATURE - Private trip planning (not visible on public pages)
    # ──────────────────────────────────────────────────────────────────────────
    
    # Trips table - main trip records
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trips (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            destination TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            timezone TEXT DEFAULT 'America/Los_Angeles',
            description TEXT,
            cover_image_url TEXT,
            pdf_itinerary_path TEXT,
            share_token TEXT,
            budget_cents INTEGER DEFAULT 0,
            created_by_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    
    # Trip members - who can access each trip
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trip_members (
            id TEXT PRIMARY KEY,
            trip_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            added_at TEXT NOT NULL,
            added_by_user_id TEXT NOT NULL,
            UNIQUE(trip_id, user_id)
        );
    """)
    
    # Trip events - flights, hotels, activities, etc.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trip_events (
            id TEXT PRIMARY KEY,
            trip_id TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'other',
            start_datetime TEXT NOT NULL,
            end_datetime TEXT,
            is_all_day INTEGER DEFAULT 0,
            timezone TEXT DEFAULT 'America/Los_Angeles',
            location_name TEXT,
            address TEXT,
            latitude REAL,
            longitude REAL,
            confirmation_number TEXT,
            notes TEXT,
            links TEXT,
            sort_order INTEGER DEFAULT 0,
            departure_location TEXT,
            arrival_location TEXT,
            flight_number TEXT,
            airline TEXT,
            departure_airport TEXT,
            arrival_airport TEXT,
            cost_cents INTEGER,
            reminder_minutes INTEGER DEFAULT 30,
            reminder_sent INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    
    # Trip event comments - lightweight collaboration
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trip_event_comments (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES trip_events(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    
    # Indexes for efficient queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_trip_members_user ON trip_members(user_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_trip_events_trip ON trip_events(trip_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_trip_events_start ON trip_events(start_datetime);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_trip_events_reminder ON trip_events(reminder_sent, start_datetime);")

    # ─────────────────────────────────────────────────────────────────────────────
    # UNIFIED ACCOUNTS TABLES (v0.11.0+)
    # ─────────────────────────────────────────────────────────────────────────────
    
    # Unified accounts table - single source of truth for all user/admin accounts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'unverified',
            
            -- Auth
            password_hash TEXT,
            email_verified INTEGER DEFAULT 0,
            email_verified_at TEXT,
            
            -- 2FA
            mfa_secret TEXT,
            mfa_enabled INTEGER DEFAULT 0,
            
            -- Profile
            phone TEXT,
            preferred_printer TEXT,
            preferred_material TEXT,
            preferred_colors TEXT,
            notes_template TEXT,
            avatar_url TEXT,
            notification_prefs TEXT DEFAULT '{}',
            
            -- Stats
            total_requests INTEGER DEFAULT 0,
            total_prints INTEGER DEFAULT 0,
            credits INTEGER DEFAULT 0,
            login_count INTEGER DEFAULT 0,
            
            -- Tokens
            magic_link_token TEXT,
            magic_link_expires TEXT,
            reset_token TEXT,
            reset_token_expires TEXT,
            
            -- Timestamps
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login TEXT,
            
            -- Migration tracking
            migrated_from_user_id TEXT,
            migrated_from_admin_id TEXT
        );
    """)
    
    # Sessions table - unified session management
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            
            -- Device info
            device_info TEXT,
            ip_address TEXT,
            user_agent TEXT,
            
            -- Timestamps
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_active TEXT,
            
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );
    """)
    
    # Request assignments - many-to-many for request collaboration
    cur.execute("""
        CREATE TABLE IF NOT EXISTS request_assignments (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'requester',
            
            -- Assignment metadata
            assigned_at TEXT NOT NULL,
            assigned_by_account_id TEXT,
            notes TEXT,
            
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
            UNIQUE(request_id, account_id, role)
        );
    """)
    
    # Indexes for accounts system
    cur.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_accounts_role ON accounts(role);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_request_assignments_request ON request_assignments(request_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_request_assignments_account ON request_assignments(account_id);")
    # Printellect device-control tables
    from app.printellect import init_printellect_tables
    init_printellect_tables(cur)
    # Shipping indexes are created in ensure_migrations() after the column/tables are guaranteed to exist

    conn.commit()
    conn.close()


def ensure_migrations():
    """
    Lightweight migrations for SQLite without external tooling.
    Adds columns if missing.
    """
    conn = db()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(requests)")
    cols = {row[1] for row in cur.fetchall()}  # row[1] = name

    if "special_notes" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN special_notes TEXT")

    if "priority" not in cols:
        # Priority: 1 = highest, 5 = lowest (default 3)
        cur.execute("ALTER TABLE requests ADD COLUMN priority INTEGER")
        cur.execute("UPDATE requests SET priority = 3 WHERE priority IS NULL")

    if "admin_notes" not in cols:
        # Internal work notes (admin-only)
        cur.execute("ALTER TABLE requests ADD COLUMN admin_notes TEXT")

    if "print_time_minutes" not in cols:
        # Estimated print time in minutes (set when PRINTING status)
        cur.execute("ALTER TABLE requests ADD COLUMN print_time_minutes INTEGER")

    if "turnaround_minutes" not in cols:
        # Time between prints (admin-set default: 30 min)
        cur.execute("ALTER TABLE requests ADD COLUMN turnaround_minutes INTEGER")

    if "printing_started_at" not in cols:
        # ISO timestamp when PRINTING status was set
        cur.execute("ALTER TABLE requests ADD COLUMN printing_started_at TEXT")

    if "estimated_finish_time" not in cols:
        # ISO timestamp for estimated completion (calculated from progress rate)
        cur.execute("ALTER TABLE requests ADD COLUMN estimated_finish_time TEXT")
        cur.execute("UPDATE requests SET turnaround_minutes = 30 WHERE turnaround_minutes IS NULL")

    if "print_name" not in cols:
        # User-friendly name for the print (e.g., "Dragon Statue", "Phone Holder")
        cur.execute("ALTER TABLE requests ADD COLUMN print_name TEXT")

    if "completion_snapshot" not in cols:
        # Base64-encoded JPEG snapshot taken when print auto-completes
        cur.execute("ALTER TABLE requests ADD COLUMN completion_snapshot TEXT")

    if "final_temperature" not in cols:
        # Temperature reading at completion (for records)
        cur.execute("ALTER TABLE requests ADD COLUMN final_temperature TEXT")

    if "access_token" not in cols:
        # Unique token for requester to access/edit their request
        cur.execute("ALTER TABLE requests ADD COLUMN access_token TEXT")
    
    # Always generate tokens for any requests missing them
    existing_without_token = cur.execute("SELECT id FROM requests WHERE access_token IS NULL").fetchall()
    for row in existing_without_token:
        token = secrets.token_urlsafe(32)
        cur.execute("UPDATE requests SET access_token = ? WHERE id = ?", (token, row[0]))

    # Add is_read column to request_messages if missing
    cur.execute("PRAGMA table_info(request_messages)")
    msg_cols = {row[1] for row in cur.fetchall()}
    if msg_cols and "is_read" not in msg_cols:
        cur.execute("ALTER TABLE request_messages ADD COLUMN is_read INTEGER DEFAULT 0")

    # Add store_item_id column if missing (for store requests)
    if "store_item_id" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN store_item_id TEXT")

    # Add printing_email_sent column if missing (tracks if PRINTING email has been sent with live data)
    if "printing_email_sent" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN printing_email_sent INTEGER DEFAULT 0")

    # Add slicer_estimate_minutes column if missing (stores original slicer estimate for accuracy tracking)
    if "slicer_estimate_minutes" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN slicer_estimate_minutes INTEGER")

    # Migrate print_history table - add estimated_minutes column
    cur.execute("PRAGMA table_info(print_history)")
    history_cols = {row[1] for row in cur.fetchall()}
    if history_cols and "estimated_minutes" not in history_cols:
        cur.execute("ALTER TABLE print_history ADD COLUMN estimated_minutes INTEGER")

    # Migrate files table - add file_metadata column for 3D model dimensions
    cur.execute("PRAGMA table_info(files)")
    files_cols = {row[1] for row in cur.fetchall()}
    if files_cols and "file_metadata" not in files_cols:
        cur.execute("ALTER TABLE files ADD COLUMN file_metadata TEXT")

    # Add notification_prefs column for per-request notification preferences
    # JSON format: {"email": true, "push": true} - defaults to email only
    if "notification_prefs" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN notification_prefs TEXT DEFAULT '{\"email\": true, \"push\": false}'")

    # User profile migrations
    cur.execute("PRAGMA table_info(users)")
    user_cols = {row[1] for row in cur.fetchall()}
    if user_cols and "avatar_url" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")

    # Design workflow columns
    if "requires_design" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN requires_design INTEGER DEFAULT 0")
    if "designer_admin_id" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN designer_admin_id TEXT")
    if "design_notes" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN design_notes TEXT")
    if "design_completed_at" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN design_completed_at TEXT")

    # Multi-build support columns
    if "total_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN total_builds INTEGER DEFAULT 1")
    if "completed_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN completed_builds INTEGER DEFAULT 0")
    if "failed_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN failed_builds INTEGER DEFAULT 0")
    if "active_build_id" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN active_build_id TEXT")

    if "fulfillment_method" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN fulfillment_method TEXT NOT NULL DEFAULT 'pickup'")
        cur.execute("UPDATE requests SET fulfillment_method = 'pickup' WHERE fulfillment_method IS NULL OR fulfillment_method = ''")

    # Notification log table
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_log'")
    if not cur.fetchone():
        cur.execute("""
            CREATE TABLE notification_log (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                channel TEXT NOT NULL,
                subject TEXT,
                body TEXT,
                endpoint TEXT,
                request_id TEXT,
                build_id TEXT,
                status TEXT,
                error TEXT,
                created_at TEXT NOT NULL
            )
        """)
    else:
        cur.execute("PRAGMA table_info(notification_log)")
        notif_cols = {row[1] for row in cur.fetchall()}
        if "endpoint" not in notif_cols:
            cur.execute("ALTER TABLE notification_log ADD COLUMN endpoint TEXT")

    # Add build_id to files table to associate files with specific builds
    if files_cols and "build_id" not in files_cols:
        cur.execute("ALTER TABLE files ADD COLUMN build_id TEXT")

    # Add linked_file_id to files table (link gcode to its source model file)
    if files_cols and "linked_file_id" not in files_cols:
        cur.execute("ALTER TABLE files ADD COLUMN linked_file_id TEXT")

    # Builds table migrations
    cur.execute("PRAGMA table_info(builds)")
    builds_cols = {row[1] for row in cur.fetchall()}
    if builds_cols and "notes" not in builds_cols:
        cur.execute("ALTER TABLE builds ADD COLUMN notes TEXT")
    if builds_cols and "colors" not in builds_cols:
        cur.execute("ALTER TABLE builds ADD COLUMN colors TEXT")

    # Migrate existing approved/printing/done requests that don't have builds yet
    existing_without_builds = cur.execute("""
        SELECT r.id FROM requests r 
        LEFT JOIN builds b ON r.id = b.request_id 
        WHERE r.status IN ('APPROVED', 'PRINTING', 'IN_PROGRESS', 'DONE', 'PICKED_UP')
        AND b.id IS NULL
    """).fetchall()
    
    for row in existing_without_builds:
        request_id = row[0]
        # Get file count for this request
        file_count = cur.execute("SELECT COUNT(*) FROM files WHERE request_id = ?", (request_id,)).fetchone()[0]
        build_count = max(1, file_count)
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        
        for i in range(build_count):
            build_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO builds (id, request_id, build_number, status, created_at, updated_at)
                VALUES (?, ?, ?, 'READY', ?, ?)
            """, (build_id, request_id, i + 1, now, now))
        
        # Update request with total_builds count
        cur.execute("UPDATE requests SET total_builds = ? WHERE id = ?", (build_count, request_id))

    # Add progress_milestones column to user_notification_prefs if missing
    cur.execute("PRAGMA table_info(user_notification_prefs)")
    prefs_cols = {row[1] for row in cur.fetchall()}
    if prefs_cols and "progress_milestones" not in prefs_cols:
        cur.execute("ALTER TABLE user_notification_prefs ADD COLUMN progress_milestones TEXT DEFAULT '50,75'")

    # Add reminder columns to trip_events if missing
    cur.execute("PRAGMA table_info(trip_events)")
    trip_event_cols = {row[1] for row in cur.fetchall()}
    if trip_event_cols:
        if "reminder_minutes" not in trip_event_cols:
            cur.execute("ALTER TABLE trip_events ADD COLUMN reminder_minutes INTEGER DEFAULT 30")
        if "reminder_sent" not in trip_event_cols:
            cur.execute("ALTER TABLE trip_events ADD COLUMN reminder_sent INTEGER DEFAULT 0")
        if "cost_cents" not in trip_event_cols:
            cur.execute("ALTER TABLE trip_events ADD COLUMN cost_cents INTEGER DEFAULT 0")

    # Trip sharing/budget columns
    cur.execute("PRAGMA table_info(trips)")
    trip_cols = {row[1] for row in cur.fetchall()}
    if trip_cols:
        if "share_token" not in trip_cols:
            cur.execute("ALTER TABLE trips ADD COLUMN share_token TEXT")
        if "budget_cents" not in trip_cols:
            cur.execute("ALTER TABLE trips ADD COLUMN budget_cents INTEGER DEFAULT 0")
        # Backfill share tokens for existing trips
        existing_without_share = cur.execute("SELECT id FROM trips WHERE share_token IS NULL OR share_token = ''").fetchall()
        import secrets
        for row in existing_without_share:
            cur.execute("UPDATE trips SET share_token = ? WHERE id = ?", (secrets.token_urlsafe(16), row[0]))

    # Trip event comments table
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='trip_event_comments'")
    if not cur.fetchone():
        cur.execute("""
            CREATE TABLE trip_event_comments (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(event_id) REFERENCES trip_events(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

    # ─────────────────────────────────────────────────────────────────────────────
    # UNIFIED ACCOUNTS MIGRATION - Add account_id to requests table
    # ─────────────────────────────────────────────────────────────────────────────
    cur.execute("PRAGMA table_info(requests)")
    req_cols = {row[1] for row in cur.fetchall()}
    
    # Add account_id FK to requests table (nullable for legacy/anonymous requests)
    if "account_id" not in req_cols:
        cur.execute("ALTER TABLE requests ADD COLUMN account_id TEXT")
        logger.info("Added account_id column to requests table")

    # ─────────────────────────────────────────────────────────────────────────────
    # SHIPPING TABLES + INDEXES
    # ─────────────────────────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS request_shipping (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            shipping_status TEXT NOT NULL DEFAULT 'REQUESTED',
            recipient_name TEXT,
            recipient_phone TEXT,
            address_line1 TEXT,
            address_line2 TEXT,
            city TEXT,
            state TEXT,
            postal_code TEXT,
            country TEXT DEFAULT 'US',
            service_preference TEXT,
            address_validation_status TEXT,
            address_validation_messages TEXT,
            normalized_address_json TEXT,
            package_weight_oz REAL,
            package_length_in REAL,
            package_width_in REAL,
            package_height_in REAL,
            quote_amount_cents INTEGER,
            quote_currency TEXT DEFAULT 'USD',
            quote_notes TEXT,
            quoted_at TEXT,
            quoted_by TEXT,
            selected_rate_id TEXT,
            provider TEXT DEFAULT 'shippo',
            provider_shipment_id TEXT,
            provider_transaction_id TEXT,
            carrier TEXT,
            service TEXT,
            rate_amount TEXT,
            tracking_number TEXT,
            tracking_status TEXT,
            tracking_url TEXT,
            label_url TEXT,
            label_pdf_url TEXT,
            shipped_at TEXT,
            delivered_at TEXT,
            last_provider_payload TEXT,
            metadata_json TEXT,
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS request_shipping_rate_snapshots (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'shippo',
            parcel_weight_oz REAL,
            parcel_length_in REAL,
            parcel_width_in REAL,
            parcel_height_in REAL,
            selected_rate_id TEXT,
            fetched_by TEXT,
            rates_json TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS request_shipping_events (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            shipping_status TEXT,
            provider TEXT,
            provider_event_id TEXT,
            message TEXT,
            payload_json TEXT,
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE,
            UNIQUE(provider, provider_event_id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_requests_fulfillment_method ON requests(fulfillment_method)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_request_shipping_status ON request_shipping(shipping_status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_request_shipping_tracking ON request_shipping(tracking_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_request_shipping_events_provider_event ON request_shipping_events(provider, provider_event_id)")

    # ─────────────────────────────────────────────────────────────────────────────
    # MIGRATE USERS + ADMINS → ACCOUNTS (v0.11.0 one-time migration)
    # ─────────────────────────────────────────────────────────────────────────────
    
    # Check if migration is needed (safely check each table exists)
    accounts_count = cur.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    
    users_count = 0
    try:
        users_count = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except:
        pass  # users table might not exist
    
    admins_count = 0
    try:
        admins_count = cur.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    except:
        pass  # admins table might not exist
    
    if accounts_count == 0 and (users_count > 0 or admins_count > 0):
        logger.info(f"Migrating {users_count} users and {admins_count} admins to accounts table...")
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        migrated_emails = set()
        
        # Role mapping for admins
        admin_role_map = {
            "super_admin": "owner",
            "admin": "admin", 
            "operator": "staff",
            "designer": "staff",
            "viewer": "staff",
        }
        
        # 1. Migrate admins first (they get elevated roles)
        if admins_count > 0:
            try:
                admins = cur.execute("SELECT * FROM admins").fetchall()
                admin_cols = [desc[0] for desc in cur.description]
                for admin_row in admins:
                    admin = dict(zip(admin_cols, admin_row))
                    email = admin.get("email", "").lower().strip()
                    if not email or email in migrated_emails:
                        continue
                    
                    account_id = str(uuid.uuid4())
                    legacy_role = admin.get("role", "operator")
                    new_role = admin_role_map.get(legacy_role, "staff")
                    status = "active" if admin.get("is_active", 1) else "suspended"
                    
                    cur.execute("""
                        INSERT INTO accounts (id, email, name, role, status, password_hash, 
                                              created_at, updated_at, migrated_from_admin_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        account_id, email, admin.get("name", email.split("@")[0]),
                        new_role, status, admin.get("password_hash"),
                        admin.get("created_at", now), now, admin.get("id")
                    ))
                    migrated_emails.add(email)
                    logger.info(f"  Migrated admin: {email} -> {new_role}")
            except Exception as e:
                logger.warning(f"Error migrating admins: {e}")
        
        # 2. Migrate users (check for email collisions with admins)
        if users_count > 0:
            users = cur.execute("SELECT * FROM users").fetchall()
            user_cols = [desc[0] for desc in cur.description]
            for user_row in users:
                user = dict(zip(user_cols, user_row))
                email = user.get("email", "").lower().strip()
                if not email:
                    continue
                
                if email in migrated_emails:
                    # Email already migrated from admins - update with user preferences
                    cur.execute("""
                        UPDATE accounts SET 
                            preferred_printer = ?,
                            preferred_material = ?,
                            preferred_colors = ?,
                            notes_template = ?,
                            notification_prefs = ?,
                            migrated_from_user_id = ?
                        WHERE email = ?
                    """, (
                        user.get("preferred_printer"),
                        user.get("preferred_material"),
                        user.get("preferred_colors"),
                        user.get("notes_template"),
                        user.get("notification_prefs", "{}"),
                        user.get("id"),
                        email
                    ))
                    logger.info(f"  Merged user preferences into existing account: {email}")
                else:
                    # New user account
                    account_id = str(uuid.uuid4())
                    status = "active" if user.get("email_verified", 0) else "unverified"
                    
                    cur.execute("""
                        INSERT INTO accounts (id, email, name, role, status, password_hash,
                                              email_verified, preferred_printer, preferred_material,
                                              preferred_colors, notes_template, notification_prefs,
                                              created_at, updated_at, migrated_from_user_id)
                        VALUES (?, ?, ?, 'user', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        account_id, email, user.get("name", email.split("@")[0]),
                        status, user.get("password_hash"),
                        user.get("email_verified", 0),
                        user.get("preferred_printer"),
                        user.get("preferred_material"),
                        user.get("preferred_colors"),
                        user.get("notes_template"),
                        user.get("notification_prefs", "{}"),
                        user.get("created_at", now), now, user.get("id")
                    ))
                    migrated_emails.add(email)
        
        # 3. Link requests to accounts by email
        unlinked = cur.execute("""
            SELECT r.id, r.requester_email 
            FROM requests r 
            WHERE r.account_id IS NULL AND r.requester_email IS NOT NULL
        """).fetchall()
        
        for req_id, req_email in unlinked:
            if not req_email:
                continue
            account = cur.execute(
                "SELECT id FROM accounts WHERE LOWER(email) = ?", 
                (req_email.lower().strip(),)
            ).fetchone()
            if account:
                cur.execute("UPDATE requests SET account_id = ? WHERE id = ?", 
                           (account[0], req_id))
        
        logger.info(f"Migration complete: {len(migrated_emails)} accounts created")

    # Printellect schema migrations
    from app.printellect import ensure_printellect_migrations
    ensure_printellect_migrations(cur)

    conn.commit()
    conn.close()


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


# ─────────────────────────── BUILD LIFECYCLE HELPERS ───────────────────────────

def derive_request_status_from_builds(request_id: str) -> str:
    """
    Derive the parent request status from its builds.
    Returns: NEW, APPROVED, IN_PROGRESS, BLOCKED, or DONE
    """
    conn = db()
    builds = conn.execute(
        "SELECT status FROM builds WHERE request_id = ?", (request_id,)
    ).fetchall()
    conn.close()
    
    if not builds:
        return "APPROVED"  # No builds = single-build legacy mode
    
    statuses = [b["status"] for b in builds]
    
    # If any build is FAILED and none are PRINTING, request is BLOCKED
    if "FAILED" in statuses and "PRINTING" not in statuses:
        return "BLOCKED"
    
    # If any build is PRINTING, request is IN_PROGRESS (or PRINTING for legacy compat)
    if "PRINTING" in statuses:
        return "IN_PROGRESS"
    
    # If all builds are COMPLETED or SKIPPED, request is DONE
    terminal = {"COMPLETED", "SKIPPED"}
    if all(s in terminal for s in statuses):
        return "DONE"
    
    # If some builds are READY or PENDING, request is IN_PROGRESS
    if "READY" in statuses or "PENDING" in statuses:
        if "COMPLETED" in statuses:
            return "IN_PROGRESS"  # Some done, some pending
        return "APPROVED"  # All pending/ready, none started
    
    return "IN_PROGRESS"


def sync_request_status_from_builds(request_id: str, skip_done_notification: bool = False) -> str:
    """
    Update the parent request's status and counters based on its builds.
    Returns the new status.
    
    Args:
        request_id: The request ID to sync
        skip_done_notification: If True, don't send DONE notification (caller will handle it)
    """
    conn = db()
    builds = conn.execute(
        "SELECT * FROM builds WHERE request_id = ?", (request_id,)
    ).fetchall()
    
    if not builds:
        conn.close()
        return "APPROVED"
    
    completed = sum(1 for b in builds if b["status"] == "COMPLETED")
    failed = sum(1 for b in builds if b["status"] == "FAILED")
    total = len(builds)
    
    # Get old status to detect transition to DONE
    old_request = conn.execute("SELECT status FROM requests WHERE id = ?", (request_id,)).fetchone()
    old_status = old_request["status"] if old_request else None
    
    new_status = derive_request_status_from_builds(request_id)
    
    # Find active build (currently PRINTING)
    active_build_id = None
    for b in builds:
        if b["status"] == "PRINTING":
            active_build_id = b["id"]
            break
    
    conn.execute("""
        UPDATE requests SET 
            status = ?,
            completed_builds = ?,
            failed_builds = ?,
            active_build_id = ?,
            updated_at = ?
        WHERE id = ?
    """, (new_status, completed, failed, active_build_id, now_iso(), request_id))
    conn.commit()
    
    # If transitioning to DONE, send completion notification (unless caller handles it)
    if new_status == "DONE" and old_status != "DONE" and total > 1 and not skip_done_notification:
        try:
            request = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
            conn.close()
            if request:
                print(f"[SYNC-STATUS] Request {request_id[:8]} transitioned to DONE, sending completion notification")
                send_request_complete_notification(dict(request))
        except Exception as e:
            print(f"[SYNC-STATUS] Failed to send DONE notification: {e}")
            conn.close()
    else:
        conn.close()
    
    return new_status


def start_build(build_id: str, printer: str, comment: Optional[str] = None) -> Dict[str, Any]:
    """
    Start a build (transition from READY/PENDING to PRINTING).
    Assigns the printer and records the start time.
    
    Args:
        build_id: The ID of the build to start
        printer: The printer code (must be a valid, specific printer - not "ANY")
        comment: Optional comment for the status change
    
    Returns:
        dict with keys: success, error (if failed)
    """
    # Validate printer selection - must be a specific printer, not "ANY" or empty
    valid_printer_codes = [p[0] for p in PRINTERS if p[0] != "ANY"]
    if not printer or printer.strip() == "" or printer == "ANY":
        return {"success": False, "error": "A specific printer must be selected to start a build"}
    
    if printer not in valid_printer_codes:
        return {"success": False, "error": f"Invalid printer: {printer}. Choose from: {', '.join(valid_printer_codes)}"}
    
    # Pause polling for this printer to prevent connection conflicts
    # This is important because the admin may be about to send a file to the printer
    pause_printer_polling(printer, 45)  # 45 seconds to allow file transfer
    
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return {"success": False, "error": "Build not found"}
    
    if build["status"] not in ("PENDING", "READY"):
        conn.close()
        return {"success": False, "error": f"Cannot start build - current status is {build['status']}"}
    
    now = now_iso()
    old_status = build["status"]
    
    # Block starting if design is required but not completed
    try:
        req_row = conn.execute("SELECT requires_design, design_completed_at FROM requests WHERE id = ?", (build["request_id"],)).fetchone()
        if req_row and req_row["requires_design"] == 1 and not req_row["design_completed_at"]:
            conn.close()
            return {"success": False, "error": "Design required. Mark design complete before starting this build."}
    except Exception:
        pass
    
    conn.execute("""
        UPDATE builds SET 
            status = 'PRINTING',
            printer = ?,
            started_at = ?,
            updated_at = ?
        WHERE id = ?
    """, (printer, now, now, build_id))
    
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, old_status, "PRINTING", comment or f"Started on {printer}")
    )
    
    # Update the parent request's active_build_id
    conn.execute(
        "UPDATE requests SET active_build_id = ?, updated_at = ? WHERE id = ?",
        (build_id, now, build["request_id"])
    )
    # Reset printing email flag and persist printer selection for this build
    conn.execute(
        "UPDATE requests SET printing_email_sent = 0, printer = ? WHERE id = ?",
        (printer, build["request_id"])
    )
    
    conn.commit()
    conn.close()
    
    # Clear any previously sent progress milestones when build starts (fresh start)
    clear_progress_milestones(build_id)
    
    # Sync parent request status
    sync_request_status_from_builds(build["request_id"])
    
    # Send build start notification (for multi-build requests)
    try:
        conn = db()
        request = conn.execute("SELECT * FROM requests WHERE id = ?", (build["request_id"],)).fetchone()
        updated_build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
        conn.close()
        
        if request and updated_build:
            send_build_start_notification(dict(updated_build), dict(request))
    except Exception as e:
        print(f"[BUILD-START] Failed to send start notification: {e}")
    
    return {"success": True}


def fail_build(build_id: str, comment: Optional[str] = None) -> bool:
    """
    Mark a build as FAILED.
    Returns True if successful.
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return False
    
    if build["status"] != "PRINTING":
        conn.close()
        return False
    
    now = now_iso()
    request_id = build["request_id"]
    
    conn.execute("""
        UPDATE builds SET 
            status = 'FAILED',
            completed_at = ?,
            updated_at = ?
        WHERE id = ?
    """, (now, now, build_id))
    
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, "PRINTING", "FAILED", comment or "Build failed")
    )
    
    # Clear active_build_id from parent request
    conn.execute(
        "UPDATE requests SET active_build_id = NULL, updated_at = ? WHERE id = ?",
        (now, request_id)
    )
    
    conn.commit()
    
    # Get request for notification
    request = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    
    # Sync parent request status (will set to BLOCKED)
    sync_request_status_from_builds(request_id)
    
    # Send failure notification
    if request:
        try:
            send_build_fail_notification(dict(build), dict(request), comment)
        except Exception as e:
            print(f"[BUILD-FAIL] Failed to send notification: {e}")
    
    return True


def retry_build(build_id: str, comment: Optional[str] = None) -> bool:
    """
    Reset a FAILED build back to PENDING for retry.
    Returns True if successful.
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return False
    
    if build["status"] != "FAILED":
        conn.close()
        return False
    
    now = now_iso()
    
    conn.execute("""
        UPDATE builds SET 
            status = 'PENDING',
            started_at = NULL,
            completed_at = NULL,
            progress = NULL,
            updated_at = ?
        WHERE id = ?
    """, (now, build_id))
    
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, "FAILED", "PENDING", comment or "Retrying build")
    )
    
    conn.commit()
    conn.close()
    
    # Clear progress milestones so notifications can fire again on retry
    clear_progress_milestones(build_id)
    
    # Sync parent request status
    sync_request_status_from_builds(build["request_id"])
    
    return True


def skip_build(build_id: str, comment: Optional[str] = None) -> bool:
    """
    Skip a build (mark as SKIPPED). Can skip PENDING, READY, or FAILED builds.
    Returns True if successful.
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return False
    
    if build["status"] not in ("PENDING", "READY", "FAILED"):
        conn.close()
        return False
    
    now = now_iso()
    old_status = build["status"]
    
    conn.execute("""
        UPDATE builds SET 
            status = 'SKIPPED',
            completed_at = ?,
            updated_at = ?
        WHERE id = ?
    """, (now, now, build_id))
    
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, old_status, "SKIPPED", comment or "Build skipped")
    )
    
    conn.commit()
    conn.close()
    
    # Sync parent request status
    sync_request_status_from_builds(build["request_id"])
    
    return True


def complete_build(build_id: str, comment: Optional[str] = None, snapshot_b64: Optional[str] = None) -> bool:
    """
    Manually mark a build as COMPLETED.
    Can complete a PRINTING build (manually confirm completion).
    Returns True if successful.
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return False
    
    if build["status"] != "PRINTING":
        conn.close()
        return False
    
    now = now_iso()
    request_id = build["request_id"]
    
    conn.execute("""
        UPDATE builds SET 
            status = 'COMPLETED',
            completed_at = ?,
            updated_at = ?
        WHERE id = ?
    """, (now, now, build_id))
    
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, "PRINTING", "COMPLETED", comment or "Manually completed by admin")
    )
    
    # Save snapshot if provided
    if snapshot_b64:
        conn.execute(
            "INSERT INTO build_snapshots (id, build_id, created_at, snapshot_data, snapshot_type) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), build_id, now, snapshot_b64, "completion")
        )
    
    conn.commit()
    
    # Get request for notification
    request = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    
    # Sync parent request status (skip DONE notification - we'll handle it below)
    sync_request_status_from_builds(request_id, skip_done_notification=True)
    
    # Send build completion notification (or request completion if final build)
    if request:
        try:
            build_dict = dict(build)
            build_dict["status"] = "COMPLETED"  # Update status in dict
            send_build_complete_notification(build_dict, dict(request), snapshot_b64)
        except Exception as e:
            print(f"[BUILD-COMPLETE] Failed to send notification: {e}")
    
    return True


def delete_build(build_id: str, force: bool = False) -> Dict[str, Any]:
    """
    Delete a build and clean up associated data.
    
    Args:
        build_id: The ID of the build to delete
        force: If True, allow deleting PRINTING builds (with warning)
    
    Returns:
        dict with keys: success, error, warning, request_id
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    
    if not build:
        conn.close()
        return {"success": False, "error": "Build not found"}
    
    request_id = build["request_id"]
    status = build["status"]
    build_number = build["build_number"]
    
    # Block deletion of PRINTING builds unless forced
    if status == "PRINTING" and not force:
        conn.close()
        return {
            "success": False, 
            "error": "Cannot delete a build that is currently PRINTING. Use force=True to override.",
            "requires_force": True
        }
    
    warning = None
    if status == "COMPLETED":
        warning = "Deleted a COMPLETED build - this may affect request history"
    elif status == "PRINTING" and force:
        warning = "Force-deleted a PRINTING build - printer may still be running"
    
    # Delete associated data
    # 1. Delete build snapshots
    conn.execute("DELETE FROM build_snapshots WHERE build_id = ?", (build_id,))
    
    # 2. Delete build status events
    conn.execute("DELETE FROM build_status_events WHERE build_id = ?", (build_id,))
    
    # 3. Delete the build itself
    conn.execute("DELETE FROM builds WHERE id = ?", (build_id,))
    
    # 4. Renumber remaining builds to maintain consistency
    remaining_builds = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? ORDER BY build_number",
        (request_id,)
    ).fetchall()
    
    for i, b in enumerate(remaining_builds, start=1):
        conn.execute(
            "UPDATE builds SET build_number = ?, updated_at = ? WHERE id = ?",
            (i, now_iso(), b["id"])
        )
    
    # 5. Update total_builds on the request
    new_total = len(remaining_builds)
    conn.execute(
        "UPDATE requests SET total_builds = ?, updated_at = ? WHERE id = ?",
        (new_total, now_iso(), request_id)
    )
    
    # 6. Clear active_build_id if we deleted the active build
    req = conn.execute("SELECT active_build_id FROM requests WHERE id = ?", (request_id,)).fetchone()
    if req and req["active_build_id"] == build_id:
        conn.execute(
            "UPDATE requests SET active_build_id = NULL, updated_at = ? WHERE id = ?",
            (now_iso(), request_id)
        )
    
    conn.commit()
    conn.close()
    
    # Sync parent request status (recalculate from remaining builds)
    sync_request_status_from_builds(request_id)
    
    # Clear from print match suggestions if the build's printer was involved
    if build["printer"]:
        clear_print_match_suggestion(build["printer"])
    
    print(f"[BUILD-DELETE] Deleted build {build_id[:8]} (was #{build_number}, status={status}) from request {request_id[:8]}")
    
    return {
        "success": True, 
        "warning": warning,
        "request_id": request_id,
        "deleted_build_number": build_number
    }


def setup_builds_for_request(request_id: str, build_count: int = None) -> int:
    """
    Create build records for a request based on its files.
    If build_count is specified, creates that many builds.
    Otherwise, creates one build per top-level file (linked child files
    share the same build as their parent, e.g. G-code linked to a model).
    Returns the number of builds created.
    """
    conn = db()
    
    # Check if builds already exist
    existing = conn.execute(
        "SELECT COUNT(*) as cnt FROM builds WHERE request_id = ?", (request_id,)
    ).fetchone()
    
    if existing["cnt"] > 0:
        conn.close()
        return 0  # Builds already exist
    
    # Get files for this request
    all_files = conn.execute(
        "SELECT id, original_filename, linked_file_id FROM files WHERE request_id = ? ORDER BY created_at ASC",
        (request_id,)
    ).fetchall()
    
    # Separate top-level files (no linked_file_id) from child files
    top_level_files = [f for f in all_files if not f["linked_file_id"]]
    child_files = [f for f in all_files if f["linked_file_id"]]
    
    # Build a mapping: parent_file_id -> list of child files
    children_by_parent = {}
    for cf in child_files:
        pid = cf["linked_file_id"]
        if pid not in children_by_parent:
            children_by_parent[pid] = []
        children_by_parent[pid].append(cf)
    
    # Get build count from top-level files if not specified
    if build_count is None:
        build_count = max(1, len(top_level_files)) if top_level_files else max(1, len(all_files))
    
    now = now_iso()
    build_ids = []
    
    # Create builds (one per top-level file)
    for i in range(build_count):
        build_id = str(uuid.uuid4())
        # Use file name as print_name if we have a matching top-level file
        print_name = None
        if i < len(top_level_files):
            original = top_level_files[i]["original_filename"]
            print_name = os.path.splitext(original)[0] if original else None
        
        conn.execute("""
            INSERT INTO builds (id, request_id, build_number, status, print_name, created_at, updated_at)
            VALUES (?, ?, ?, 'PENDING', ?, ?, ?)
        """, (build_id, request_id, i + 1, print_name, now, now))
        build_ids.append(build_id)
    
    # Assign top-level files to builds (1:1)
    for i, file in enumerate(top_level_files):
        if i < len(build_ids):
            conn.execute(
                "UPDATE files SET build_id = ? WHERE id = ?",
                (build_ids[i], file["id"])
            )
            # Also assign any child files (linked G-code, etc.) to the same build
            for cf in children_by_parent.get(file["id"], []):
                conn.execute(
                    "UPDATE files SET build_id = ? WHERE id = ?",
                    (build_ids[i], cf["id"])
                )
    
    # Handle orphan child files whose parent isn't in this request
    # (shouldn't normally happen, but be safe)
    assigned_child_ids = {cf["id"] for cfs in children_by_parent.values() for cf in cfs if cf["linked_file_id"] in {f["id"] for f in top_level_files}}
    for cf in child_files:
        if cf["id"] not in assigned_child_ids and build_ids:
            conn.execute(
                "UPDATE files SET build_id = ? WHERE id = ?",
                (build_ids[0], cf["id"])
            )
    
    # Update request with total_builds
    conn.execute(
        "UPDATE requests SET total_builds = ?, updated_at = ? WHERE id = ?",
        (build_count, now, request_id)
    )
    
    conn.commit()
    conn.close()
    
    return build_count


def mark_builds_ready(request_id: str) -> int:
    """
    Mark all PENDING builds as READY (approved for printing).
    Returns the number of builds marked ready.
    """
    conn = db()
    
    builds = conn.execute(
        "SELECT id FROM builds WHERE request_id = ? AND status = 'PENDING'",
        (request_id,)
    ).fetchall()
    
    now = now_iso()
    count = 0
    
    for b in builds:
        conn.execute(
            "UPDATE builds SET status = 'READY', updated_at = ? WHERE id = ?",
            (now, b["id"])
        )
        conn.execute(
            "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), b["id"], now, "PENDING", "READY", "Approved for printing")
        )
        count += 1
    
    conn.commit()
    conn.close()
    
    return count


# ─────────────────────────── 3D FILE PARSING ───────────────────────────
class NumpyEncoder(json.JSONEncoder):
    """JSON encoder that handles numpy types (float32, int64, etc.)"""
    def default(self, o):
        try:
            import numpy as np
            if isinstance(o, np.integer):
                return int(o)
            if isinstance(o, np.floating):
                return float(o)
            if isinstance(o, np.ndarray):
                return o.tolist()
        except ImportError:
            pass
        return super().default(o)


def safe_json_dumps(obj) -> str:
    """JSON dumps that handles numpy types"""
    return json.dumps(obj, cls=NumpyEncoder)


def parse_3d_file_metadata(file_path: str, original_filename: str) -> Optional[Dict[str, Any]]:
    """
    Parse a 3D file (STL, 3MF, OBJ) and extract metadata like dimensions and volume.
    Returns None if file cannot be parsed.
    """
    ext = os.path.splitext(original_filename.lower())[1]
    
    try:
        if ext == ".stl":
            return _parse_stl_file(file_path)
        elif ext == ".3mf":
            return _parse_3mf_file(file_path)
        elif ext == ".obj":
            return _parse_obj_file(file_path)
        else:
            return None
    except Exception as e:
        print(f"[FILE_PARSE] Error parsing {original_filename}: {e}")
        return None


def _parse_stl_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Parse STL file for dimensions and triangle count using numpy-stl"""
    try:
        from stl import mesh
        import numpy as np
        
        stl_mesh = mesh.Mesh.from_file(file_path)
        
        # Get bounding box dimensions
        min_coords = stl_mesh.min_
        max_coords = stl_mesh.max_
        
        # Convert numpy types to Python native types to avoid JSON serialization issues
        dimensions = {
            "x": float(round(max_coords[0] - min_coords[0], 2)),
            "y": float(round(max_coords[1] - min_coords[1], 2)),
            "z": float(round(max_coords[2] - min_coords[2], 2)),
        }
        
        # Calculate volume (approximate using signed volume method)
        # This works for closed meshes
        try:
            volume = abs(stl_mesh.get_mass_properties()[0])
            volume_cm3 = float(round(volume / 1000, 2))  # Convert mm³ to cm³
        except:
            volume_cm3 = None
        
        # Triangle count
        triangle_count = int(len(stl_mesh.vectors))
        
        return {
            "type": "stl",
            "dimensions_mm": dimensions,
            "volume_cm3": volume_cm3,
            "triangle_count": triangle_count,
            "is_valid": True,
        }
    except ImportError:
        print("[FILE_PARSE] numpy-stl not installed, skipping STL parsing")
        return None
    except Exception as e:
        print(f"[FILE_PARSE] STL parse error: {e}")
        return {"type": "stl", "is_valid": False, "error": str(e)}


def _parse_3mf_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Parse 3MF file (ZIP containing XML model data) for basic dimensions"""
    try:
        import zipfile
        import xml.etree.ElementTree as ET
        
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Find the model file (usually 3D/3dmodel.model)
            model_file = None
            for name in zf.namelist():
                if name.endswith('.model'):
                    model_file = name
                    break
            
            if not model_file:
                return {"type": "3mf", "is_valid": False, "error": "No model file found"}
            
            with zf.open(model_file) as f:
                tree = ET.parse(f)
                root = tree.getroot()
                
                # 3MF namespace
                ns = {'m': 'http://schemas.microsoft.com/3dmanufacturing/core/2015/02'}
                
                # Find all vertices to calculate bounding box
                vertices = []
                for mesh_elem in root.iter():
                    if mesh_elem.tag.endswith('vertex'):
                        x = float(mesh_elem.get('x', 0))
                        y = float(mesh_elem.get('y', 0))
                        z = float(mesh_elem.get('z', 0))
                        vertices.append((x, y, z))
                
                if vertices:
                    min_x = min(v[0] for v in vertices)
                    max_x = max(v[0] for v in vertices)
                    min_y = min(v[1] for v in vertices)
                    max_y = max(v[1] for v in vertices)
                    min_z = min(v[2] for v in vertices)
                    max_z = max(v[2] for v in vertices)
                    
                    return {
                        "type": "3mf",
                        "dimensions_mm": {
                            "x": float(round(max_x - min_x, 2)),
                            "y": float(round(max_y - min_y, 2)),
                            "z": float(round(max_z - min_z, 2)),
                        },
                        "vertex_count": int(len(vertices)),
                        "is_valid": True,
                    }
                
                return {"type": "3mf", "is_valid": True, "note": "Could not extract dimensions"}
                
    except Exception as e:
        print(f"[FILE_PARSE] 3MF parse error: {e}")
        return {"type": "3mf", "is_valid": False, "error": str(e)}


def _parse_obj_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Parse OBJ file for basic dimensions"""
    try:
        vertices = []
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith('v '):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            x, y, z = float(parts[1]), float(parts[2]), float(parts[3])
                            vertices.append((x, y, z))
                        except ValueError:
                            continue
        
        if vertices:
            min_x = min(v[0] for v in vertices)
            max_x = max(v[0] for v in vertices)
            min_y = min(v[1] for v in vertices)
            max_y = max(v[1] for v in vertices)
            min_z = min(v[2] for v in vertices)
            max_z = max(v[2] for v in vertices)
            
            return {
                "type": "obj",
                "dimensions_mm": {
                    "x": float(round(max_x - min_x, 2)),
                    "y": float(round(max_y - min_y, 2)),
                    "z": float(round(max_z - min_z, 2)),
                },
                "vertex_count": int(len(vertices)),
                "is_valid": True,
            }
        
        return {"type": "obj", "is_valid": True, "note": "No vertices found"}
        
    except Exception as e:
        print(f"[FILE_PARSE] OBJ parse error: {e}")
        return {"type": "obj", "is_valid": False, "error": str(e)}


@app.on_event("startup")
def _startup():
    init_db()
    ensure_migrations()
    seed_default_settings()
    
    # Initialize new auth system (multi-admin, user accounts, feature flags)
    init_auth_tables()
    init_feature_flags()
    
    # Create default admin from ADMIN_PASSWORD if no admins exist yet
    get_or_create_legacy_admin()
    
    # Seed demo data if DEMO_MODE is enabled
    if DEMO_MODE:
        print("[DEMO] Demo mode enabled - seeding fake data...")
        seed_demo_data(db)
    
    start_printer_polling()  # Start background printer status polling
    
    # Start trip reminder scheduler
    from app.trips import start_trip_reminder_scheduler
    start_trip_reminder_scheduler()

# Mount auth routes
from app.routes_auth import router as auth_router
app.include_router(auth_router)


async def require_admin(request: Request):
    """
    Require admin authentication. Supports (in order of preference):
    - Unified accounts (session cookie) - NEW
    - Multi-admin sessions (admin_session cookie) 
    - Legacy single password (admin_pw cookie or X-Admin-Password header)
    """
    # First, check for unified account session (newest system)
    from app.auth import get_current_account, AccountRole
    account = await get_current_account(request)
    if account and account.is_admin_level():
        return account  # Return account object for unified system
    
    # Second, check for multi-admin session (legacy multi-admin system)
    admin = await get_current_admin(request)
    if admin:
        return admin  # Return admin object for old multi-admin system
    
    # Fall back to legacy password check
    pw = request.headers.get("X-Admin-Password") or request.cookies.get("admin_pw") or ""
    if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
        return True  # Legacy auth successful
    
    # Not authenticated - redirect to login
    accept = request.headers.get("Accept", "")
    if "text/html" in accept:
        from urllib.parse import quote
        next_url = str(request.url.path)
        if request.url.query:
            next_url += f"?{request.url.query}"
        raise HTTPException(
            status_code=303,
            detail="Redirect to login",
            headers={"Location": f"/admin/login?next={quote(next_url)}"}
        )
    raise HTTPException(status_code=401, detail="Unauthorized")


# ------------------------
# Settings helpers (DB)
# ------------------------

DEFAULT_SETTINGS: Dict[str, str] = {
    # Recipients list for admin notifications
    "admin_notify_emails": "",
    # Booleans stored as "1"/"0"
    "admin_email_on_submit": "1",
    "admin_email_on_status": "1",

    # You said: requester should NOT email by default on submit
    "requester_email_on_submit": "0",
    # Status change emails to requester: yes
    "requester_email_on_status": "1",

    # Printer API integration (via flashforge-finder-api Flask server)
    "flashforge_api_url": "http://localhost:5000",
    "printer_adventurer_4_ip": "192.168.0.198",
    "printer_ad5x_ip": "192.168.0.157",
    "enable_printer_polling": "1",
    "enable_auto_print_match": "1",  # Auto-match printing file to queued requests
    "printer_offline_retries": "3",  # Retries before marking printer offline
    
    # Rush payment settings
    "rush_fee_amount": "5",
    "venmo_handle": "@YourVenmoHandle",
    "enable_rush_option": "1",
    
    # Admin per-status email settings (default all enabled)
    "notify_admin_needs_info": "1",
    "notify_admin_approved": "1",
    "notify_admin_printing": "1",
    "notify_admin_done": "1",
    "notify_admin_picked_up": "1",
    "notify_admin_rejected": "1",
    "notify_admin_cancelled": "1",
    
    # Progress notification settings
    # Comma-separated percentages to notify at (e.g., "50,75")
    "progress_notification_thresholds": "50,75",
    # Enable progress notifications (push primarily, email at 50% and 75%)
    "enable_progress_notifications": "1",
    "admin_progress_notifications": "0",

    # Shipping settings
    "shipping_enabled": "0",
    "shipping_default_country": "US",
    "shipping_notify_requester_updates": "1",
    "shipping_notify_admin_exceptions": "1",
    "shipping_default_weight_oz": "16",
    "shipping_default_length_in": "8",
    "shipping_default_width_in": "6",
    "shipping_default_height_in": "4",
    "shipping_from_name": "",
    "shipping_from_company": "",
    "shipping_from_phone": "",
    "shipping_from_address_line1": "",
    "shipping_from_address_line2": "",
    "shipping_from_city": "",
    "shipping_from_state": "",
    "shipping_from_postal_code": "",
    "shipping_from_country": "US",
    # Shippo provider credentials/config (admin UI editable; env vars still supported)
    "shippo_api_key": "",
    "shippo_webhook_user": "",
    "shippo_webhook_pass": "",
    "shippo_webhook_token": "",
}


def seed_default_settings():
    """
    Ensure all known settings exist in DB.
    """
    conn = db()
    cur = conn.cursor()
    for k, v in DEFAULT_SETTINGS.items():
        cur.execute("SELECT value FROM settings WHERE key = ?", (k,))
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                (k, v, now_iso())
            )
    conn.commit()
    conn.close()


def get_setting(key: str, default: Optional[str] = None) -> str:
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row:
        return row["value"]
    return default if default is not None else DEFAULT_SETTINGS.get(key, "")


def set_setting(key: str, value: str):
    conn = db()
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, now_iso())
    )
    conn.commit()
    conn.close()


def get_bool_setting(key: str, default: bool = False) -> bool:
    v = get_setting(key, "1" if default else "0")
    return v.strip() == "1"


def parse_email_list(raw: str) -> List[str]:
    return [e.strip() for e in (raw or "").split(",") if e.strip()]


def get_slicer_accuracy_factor(printer: str = None, material: str = None) -> Dict[str, Any]:
    """
    Calculate how accurate slicer estimates are based on historical data.
    Returns a dict with:
      - factor: multiplier to apply to slicer estimates (e.g., 1.15 = takes 15% longer)
      - sample_count: number of prints used to calculate
      - avg_accuracy: average accuracy percentage (100 = perfect)
      - message: human-readable explanation
    """
    try:
        conn = db()
        
        # Query for prints with both actual and estimated times
        if printer and material:
            rows = conn.execute("""
                SELECT duration_minutes, estimated_minutes 
                FROM print_history 
                WHERE printer = ? AND material = ? 
                AND estimated_minutes IS NOT NULL AND estimated_minutes > 0
                AND duration_minutes IS NOT NULL AND duration_minutes > 0
                ORDER BY created_at DESC
                LIMIT 20
            """, (printer, material)).fetchall()
        elif printer:
            rows = conn.execute("""
                SELECT duration_minutes, estimated_minutes 
                FROM print_history 
                WHERE printer = ?
                AND estimated_minutes IS NOT NULL AND estimated_minutes > 0
                AND duration_minutes IS NOT NULL AND duration_minutes > 0
                ORDER BY created_at DESC
                LIMIT 20
            """, (printer,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT duration_minutes, estimated_minutes 
                FROM print_history 
                WHERE estimated_minutes IS NOT NULL AND estimated_minutes > 0
                AND duration_minutes IS NOT NULL AND duration_minutes > 0
                ORDER BY created_at DESC
                LIMIT 30
            """).fetchall()
        
        conn.close()
        
        if not rows or len(rows) < 2:
            return {
                "factor": 1.0,
                "sample_count": len(rows) if rows else 0,
                "avg_accuracy": None,
                "message": "Not enough data yet"
            }
        
        # Calculate average ratio of actual/estimated
        ratios = []
        for row in rows:
            actual = row["duration_minutes"]
            estimated = row["estimated_minutes"]
            if estimated > 0:
                ratios.append(actual / estimated)
        
        if not ratios:
            return {
                "factor": 1.0,
                "sample_count": 0,
                "avg_accuracy": None,
                "message": "Not enough data yet"
            }
        
        avg_factor = sum(ratios) / len(ratios)
        avg_accuracy = (1 / avg_factor) * 100 if avg_factor > 0 else 100
        
        # Generate message
        if avg_factor > 1.1:
            diff_pct = int((avg_factor - 1) * 100)
            message = f"Typically takes {diff_pct}% longer than slicer"
        elif avg_factor < 0.9:
            diff_pct = int((1 - avg_factor) * 100)
            message = f"Typically finishes {diff_pct}% faster than slicer"
        else:
            message = "Slicer estimates are accurate"
        
        return {
            "factor": round(avg_factor, 2),
            "sample_count": len(ratios),
            "avg_accuracy": round(avg_accuracy, 1),
            "message": message
        }
        
    except Exception as e:
        print(f"[ETA] Error calculating slicer accuracy: {e}")
        return {
            "factor": 1.0,
            "sample_count": 0,
            "avg_accuracy": None,
            "message": "Error calculating"
        }


def get_adjusted_print_time(slicer_minutes: int, printer: str = None, material: str = None) -> Dict[str, Any]:
    """
    Get adjusted print time based on slicer estimate and historical accuracy.
    Returns dict with original, adjusted, and accuracy info.
    """
    accuracy = get_slicer_accuracy_factor(printer, material)
    adjusted = int(slicer_minutes * accuracy["factor"])
    
    return {
        "slicer_minutes": slicer_minutes,
        "adjusted_minutes": adjusted,
        "factor": accuracy["factor"],
        "sample_count": accuracy["sample_count"],
        "message": accuracy["message"],
        "slicer_display": f"{slicer_minutes // 60}h {slicer_minutes % 60}m" if slicer_minutes else None,
        "adjusted_display": f"{adjusted // 60}h {adjusted % 60}m" if adjusted else None,
    }


# ─────────────────────────── FILENAME MATCHING FOR AUTO-PRINT ───────────────────────────

def normalize_filename(filename: str) -> str:
    """
    Normalize a filename for fuzzy matching.
    Strips extension, converts to lowercase, replaces spaces/underscores with nothing.
    e.g., "Pencil Holder.stl" -> "pencilholder"
         "Pencil_Holder_0.2mm_PLA.gcode" -> "pencilholder02mmpla"
    """
    if not filename:
        return ""
    # Get base name (remove path)
    name = filename.split("/")[-1].split("\\")[-1]
    # Remove extension
    name = name.rsplit(".", 1)[0] if "." in name else name
    # Lowercase, remove spaces/underscores/dashes
    name = name.lower().replace(" ", "").replace("_", "").replace("-", "")
    return name


def get_filename_base(filename: str) -> str:
    """
    Get a cleaner base name for display (keeps some structure).
    e.g., "Pencil_Holder_0.2mm_PLA.gcode" -> "Pencil_Holder"
    """
    if not filename:
        return ""
    name = filename.split("/")[-1].split("\\")[-1]
    # Remove extension
    name = name.rsplit(".", 1)[0] if "." in name else name
    # Remove common slicer suffixes (0.2mm, PLA, PETG, etc.)
    import re
    # Remove things like _0.2mm, _PLA, _PETG, _ABS at the end
    name = re.sub(r'[_-]?\d+\.?\d*mm[_-]?(PLA|PETG|ABS|TPU)?$', '', name, flags=re.IGNORECASE)
    name = re.sub(r'[_-]?(PLA|PETG|ABS|TPU)$', '', name, flags=re.IGNORECASE)
    return name.strip("_- ")


def find_matching_requests_for_file(printer_file: str, printer_code: str) -> List[Dict]:
    """
    Find QUEUED, APPROVED, or IN_PROGRESS requests that match the filename being printed.
    For IN_PROGRESS requests, checks if there are READY builds that match.
    Returns list of matching requests, sorted by priority (best match first).
    
    Matching priority:
    1. Requests assigned to this specific printer
    2. Requests with no printer assigned
    3. By priority number (lower = higher priority)
    4. By created_at (older first - FIFO)
    """
    if not printer_file:
        return []
    
    normalized_printer_file = normalize_filename(printer_file)
    if not normalized_printer_file or len(normalized_printer_file) < 3:
        return []  # Too short to match reliably
    
    conn = db()
    
    # Get all QUEUED/APPROVED requests AND IN_PROGRESS requests that have READY builds
    # IN_PROGRESS means some builds are done but others are still pending
    requests = conn.execute("""
        SELECT DISTINCT r.id, r.print_name, r.printer, r.priority, r.created_at, r.requester_name,
               r.status, r.material
        FROM requests r
        LEFT JOIN builds b ON r.id = b.request_id
        WHERE r.status IN ('QUEUED', 'APPROVED')
           OR (r.status = 'IN_PROGRESS' AND b.status = 'READY')
        ORDER BY 
            CASE WHEN r.printer = ? THEN 0 ELSE 1 END,  -- This printer first
            COALESCE(r.priority, 999),                   -- Then by priority
            r.created_at                                  -- Then FIFO
    """, (printer_code,)).fetchall()
    
    matches = []
    
    for req in requests:
        # Check print_name for match
        if req["print_name"]:
            normalized_print_name = normalize_filename(req["print_name"])
            if normalized_print_name and (
                normalized_printer_file in normalized_print_name or 
                normalized_print_name in normalized_printer_file
            ):
                matches.append({
                    "id": req["id"],
                    "print_name": req["print_name"],
                    "printer": req["printer"],
                    "priority": req["priority"],
                    "created_at": req["created_at"],
                    "requester_name": req["requester_name"],
                    "status": req["status"],
                    "material": req["material"],
                    "match_source": "print_name"
                })
                continue
        
        # Check files for this request
        files = conn.execute(
            "SELECT original_filename FROM files WHERE request_id = ?",
            (req["id"],)
        ).fetchall()
        
        for f in files:
            normalized_file = normalize_filename(f["original_filename"])
            if normalized_file and (
                normalized_printer_file in normalized_file or 
                normalized_file in normalized_printer_file
            ):
                matches.append({
                    "id": req["id"],
                    "print_name": req["print_name"] or f["original_filename"],
                    "printer": req["printer"],
                    "priority": req["priority"],
                    "created_at": req["created_at"],
                    "requester_name": req["requester_name"],
                    "status": req["status"],
                    "material": req["material"],
                    "match_source": "file",
                    "matched_file": f["original_filename"]
                })
                break  # Only need one file match per request
    
    conn.close()
    return matches


# Global storage for print match suggestions (cleared on restart)
_print_match_suggestions: Dict[str, Dict] = {}  # printer_code -> {file, matches, timestamp}


def get_print_match_suggestions() -> Dict[str, Dict]:
    """Get current print match suggestions for all printers."""
    return _print_match_suggestions.copy()


def set_print_match_suggestion(printer_code: str, current_file: str, matches: List[Dict]):
    """Store print match suggestions for a printer."""
    global _print_match_suggestions
    if matches:
        _print_match_suggestions[printer_code] = {
            "file": current_file,
            "file_display": get_filename_base(current_file),
            "matches": matches,
            "timestamp": now_iso(),
            "auto_matched": False
        }
    elif printer_code in _print_match_suggestions:
        del _print_match_suggestions[printer_code]


def clear_print_match_suggestion(printer_code: str):
    """Clear suggestion for a printer (after match or print finished)."""
    global _print_match_suggestions
    if printer_code in _print_match_suggestions:
        del _print_match_suggestions[printer_code]




def _estimate_total_seconds_from_progress(elapsed_seconds: float, progress_percent: float,
                                          fallback_total_seconds: Optional[float] = None,
                                          smoothing_weight: float = 0.65,
                                          buffer_ratio: float = 0.05,
                                          min_elapsed_seconds: int = 120) -> Optional[float]:
    """
    Blend progress-based timing with a fallback estimate to smooth jitter.
    Returns an estimated total print time in seconds (not remaining).
    """
    if progress_percent is None or progress_percent <= 0:
        return None
    
    if progress_percent >= 100:
        return elapsed_seconds
    
    if elapsed_seconds < min_elapsed_seconds:
        return None
    
    try:
        progress_fraction = progress_percent / 100.0
        total_from_progress = elapsed_seconds / progress_fraction
        
        if fallback_total_seconds:
            total_seconds = (
                smoothing_weight * total_from_progress
                + (1 - smoothing_weight) * fallback_total_seconds
            )
        else:
            total_seconds = total_from_progress
        
        total_seconds *= (1 + buffer_ratio)

        if fallback_total_seconds:
            # Keep within a reasonable band around the provided estimate
            lower = fallback_total_seconds * 0.5
            upper = fallback_total_seconds * 2.5
            total_seconds = min(max(total_seconds, lower), upper)
        
        if 0 < total_seconds < 172800:  # cap at 48 hours
            return total_seconds
    except Exception as e:
        print(f"[ETA] Error smoothing progress estimate: {e}")
    
    return None


def _parse_start_time(start_iso: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp to naive datetime (UTC)."""
    if not start_iso:
        return None
    try:
        dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except Exception:
        return None


def _get_history_average_minutes(printer: str = None) -> Optional[float]:
    """Return average duration (minutes) from print_history, optionally scoped to printer."""
    try:
        conn = db()
        if printer:
            row = conn.execute(
                "SELECT AVG(duration_minutes) as avg_duration, COUNT(*) as count FROM print_history WHERE printer = ?",
                (printer,)
            ).fetchone()
            if row and row["count"] and row["count"] >= 2 and row["avg_duration"]:
                avg_minutes = float(row["avg_duration"])
                conn.close()
                return avg_minutes
        
        row = conn.execute(
            "SELECT AVG(duration_minutes) as avg_duration, COUNT(*) as count FROM print_history"
        ).fetchone()
        conn.close()
        
        if row and row["count"] and row["count"] >= 2 and row["avg_duration"]:
            return float(row["avg_duration"])
    except Exception as e:
        print(f"[ETA] Error calculating from history: {e}")
    return None


def get_smart_eta(printer: str = None, material: str = None,
                  current_percent: int = None, printing_started_at: str = None,
                  current_layer: int = None, total_layers: int = None,
                  estimated_minutes: Optional[float] = None,
                  now: Optional[datetime] = None,
                  moonraker_time_remaining: Optional[float] = None) -> Optional[datetime]:
    """
    Calculate a smart ETA based on:
    0. Moonraker live time_remaining (most accurate - from printer firmware/file analysis)
    1. Layer progress + elapsed time (most accurate calculated - layers are more linear than bytes)
    2. Percent progress + elapsed time (good fallback)
    3. Historical average for this printer/material combo
    
    Returns a datetime of estimated completion, or None if can't estimate.
    """
    now = now or datetime.utcnow()
    
    # Method 0: Moonraker live time remaining (most accurate - matches Fluidd/Mainsail display)
    # This uses the printer's own file-based ETA calculation which accounts for actual print speed
    if moonraker_time_remaining is not None and moonraker_time_remaining >= 0:
        if moonraker_time_remaining <= 0:
            return now
        return now + __import__('datetime').timedelta(seconds=moonraker_time_remaining)
    
    # Parse start time if available
    elapsed = 0
    started_dt = _parse_start_time(printing_started_at)
    if started_dt:
        elapsed = max((now - started_dt).total_seconds(), 0)
    
    # Prepare fallback totals for smoothing
    fallback_total_seconds = (estimated_minutes * 60) if estimated_minutes else None
    if not fallback_total_seconds:
        history_minutes = _get_history_average_minutes(printer)
        if history_minutes:
            fallback_total_seconds = history_minutes * 60
    
    # Method 1: Layer-based calculation (most accurate for FDM printing)
    # Layers are more linear than byte progress since each layer takes similar time
    if current_layer and total_layers and total_layers > 0:
        try:
            layer_percent = (current_layer / total_layers) * 100
            total_seconds = _estimate_total_seconds_from_progress(
                elapsed, layer_percent, fallback_total_seconds, smoothing_weight=0.75, buffer_ratio=0.03
            )
            if total_seconds is not None:
                remaining_seconds = total_seconds - elapsed
                if remaining_seconds <= 0:
                    return now
                return now + __import__('datetime').timedelta(seconds=remaining_seconds)
        except Exception as e:
            print(f"[ETA] Error calculating from layers: {e}")
    
    # Method 2: Percent-based calculation (fallback if no layer info)
    if current_percent and current_percent > 0:
        try:
            total_seconds = _estimate_total_seconds_from_progress(
                elapsed, current_percent, fallback_total_seconds, smoothing_weight=0.65, buffer_ratio=0.05
            )
            if total_seconds is not None:
                remaining_seconds = total_seconds - elapsed
                if remaining_seconds <= 0:
                    return now
                return now + __import__('datetime').timedelta(seconds=remaining_seconds)
        except Exception as e:
            print(f"[ETA] Error calculating from progress: {e}")
    
    # Method 3: Use fallback estimates (history or provided estimate)
    if fallback_total_seconds:
        return now + __import__('datetime').timedelta(seconds=fallback_total_seconds)
    
    return None


def format_eta_display(eta_dt: Optional[datetime]) -> str:
    """Format an ETA datetime for display in the UI.
    
    Note: eta_dt is expected in UTC (from get_smart_eta which uses utcnow).
    We convert to US Central time (CST/CDT) as the default display timezone.
    Client-side JS will further convert to the user's local time if available.
    """
    if not eta_dt:
        return "Unknown"
    
    # Convert UTC to US Central time (CST = UTC-6, CDT = UTC-5)
    # Use a fixed-offset approach that handles DST correctly
    from datetime import timezone as _tz
    try:
        from zoneinfo import ZoneInfo
        central_tz = ZoneInfo("America/Chicago")
        utc_eta = eta_dt.replace(tzinfo=_tz.utc)
        central_eta = utc_eta.astimezone(central_tz)
        # Determine label: CDT or CST
        tz_label = central_eta.strftime("%Z")  # "CST" or "CDT"
    except ImportError:
        # Fallback: assume CST (UTC-6) if zoneinfo not available
        central_eta = eta_dt - __import__('datetime').timedelta(hours=6)
        tz_label = "CST"
    
    # Compare in Central time
    utc_now = datetime.utcnow()
    try:
        central_now = utc_now.replace(tzinfo=_tz.utc).astimezone(central_tz)
        # Make naive for comparison
        central_eta_naive = central_eta.replace(tzinfo=None)
        central_now_naive = central_now.replace(tzinfo=None)
    except Exception:
        central_eta_naive = eta_dt - __import__('datetime').timedelta(hours=6)
        central_now_naive = utc_now - __import__('datetime').timedelta(hours=6)
    
    diff = central_eta_naive - central_now_naive
    
    if diff.total_seconds() < 0:
        return "Any moment now"
    
    # Format time as "3:45 PM" (works cross-platform)
    def format_time(dt: datetime) -> str:
        hour = dt.hour % 12
        if hour == 0:
            hour = 12
        minute = dt.minute
        ampm = "AM" if dt.hour < 12 else "PM"
        return f"{hour}:{minute:02d} {ampm}"
    
    # Format as "Dec 14, 3:45 PM CST" if more than a day away
    # or "Today at 3:45 PM CST" / "Tomorrow at 10:30 AM CST"
    if central_eta_naive.date() == central_now_naive.date():
        return f"Today at {format_time(central_eta_naive)} {tz_label}"
    elif central_eta_naive.date() == (central_now_naive + __import__('datetime').timedelta(days=1)).date():
        return f"Tomorrow at {format_time(central_eta_naive)} {tz_label}"
    else:
        return f"{central_eta_naive.strftime('%b %d')}, {format_time(central_eta_naive)} {tz_label}"




def get_request_eta_info(request_id: str, req: Dict = None,
                         printer_status: Dict = None,
                         now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Get comprehensive ETA info for a request with multi-build support.
    Returns:
      - current_build_eta: ETA for the currently printing build
      - request_eta: ETA for the entire request (all builds)
      - build_progress: Current build X of Y
      - builds_info: List of build status summaries
    """
    conn = db()
    
    # Get request if not provided
    if req is None:
        req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
        if not req_row:
            conn.close()
            return {"error": "Request not found"}
        req = dict(req_row)
    
    total_builds = req.get("total_builds") or 1
    now = now or datetime.utcnow()
    
    # For single-build requests, use existing logic
    if total_builds <= 1:
        conn.close()
        completed_builds = req.get("completed_builds") or 0
        return {
            "is_multi_build": False,
            "total_builds": 1,
            "completed_builds": completed_builds,
            "current_build_num": 1 if req.get("status") == "PRINTING" else None,
            "current_build_number": 1 if req.get("status") == "PRINTING" else None,
            "current_build_eta": None,
            "request_eta": None,
            "total_eta": None,
            "builds_info": [],
            "remaining_builds": 0,
            "blocked": req.get("status") == "BLOCKED",
        }
    
    # Get all builds for this request
    builds = conn.execute(
        """
        SELECT * FROM builds WHERE request_id = ? ORDER BY build_number
    """, (request_id,)).fetchall()
    conn.close()
    
    builds_list = [dict(b) for b in builds]
    completed_builds_count = sum(1 for b in builds_list if b["status"] == "COMPLETED")
    failed_builds_count = sum(1 for b in builds_list if b["status"] == "FAILED")
    blocked = req.get("status") == "BLOCKED" or failed_builds_count > 0
    
    # Calculate averages from completed builds to inform queued estimates
    completed_durations = []
    for b in builds_list:
        if b["status"] == "COMPLETED" and b.get("started_at") and b.get("completed_at"):
            try:
                started = datetime.fromisoformat(b["started_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                completed = datetime.fromisoformat(b["completed_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                completed_durations.append((completed - started).total_seconds() / 60)
            except Exception:
                pass
    avg_completed_minutes = sum(completed_durations) / len(completed_durations) if completed_durations else None
    history_avg_minutes = _get_history_average_minutes(req.get("printer"))
    default_build_minutes = (
        avg_completed_minutes
        or (req.get("print_time_minutes") / total_builds if req.get("print_time_minutes") else None)
        or (req.get("slicer_estimate_minutes") / total_builds if req.get("slicer_estimate_minutes") else None)
        or history_avg_minutes
        or 60
    )
    
    current_build_eta_dt = None
    current_build_eta_display = None
    current_build_number = None
    request_eta_dt = None
    request_eta_display = None
    request_remaining_seconds = 0
    builds_info = []
    
    for b in builds_list:
        status = b["status"]
        est_minutes = b.get("print_time_minutes") or b.get("slicer_estimate_minutes") or default_build_minutes
        if est_minutes is None:
            est_minutes = default_build_minutes
        build_eta_display = None
        build_eta_dt = None
        build_progress = b.get("progress")
        build_remaining_seconds = 0
        current_layer = None
        total_layers = None
        
        if status == "PRINTING":
            moonraker_remaining = None
            if printer_status:
                build_progress = printer_status.get("progress", build_progress)
                current_layer = printer_status.get("current_layer")
                total_layers = printer_status.get("total_layers")
                moonraker_remaining = printer_status.get("moonraker_time_remaining")
            start_time = b.get("started_at") or req.get("printing_started_at")
            build_eta_dt = get_smart_eta(
                printer=b.get("printer") or req.get("printer"),
                material=b.get("material") or req.get("material"),
                current_percent=build_progress,
                printing_started_at=start_time,
                current_layer=current_layer,
                total_layers=total_layers,
                estimated_minutes=est_minutes,
                now=now,
                moonraker_time_remaining=moonraker_remaining,
            )
            if build_eta_dt:
                build_eta_display = format_eta_display(build_eta_dt)
                build_remaining_seconds = max((build_eta_dt - now).total_seconds(), 0)
            else:
                build_remaining_seconds = (est_minutes or default_build_minutes) * 60
            request_remaining_seconds += build_remaining_seconds
            if current_build_eta_dt is None:
                current_build_eta_dt = build_eta_dt
                current_build_eta_display = build_eta_display
                current_build_number = b.get("build_number")
        elif status in ["READY", "PENDING"]:
            build_remaining_seconds = (est_minutes or default_build_minutes) * 60
            request_remaining_seconds += build_remaining_seconds
        elif status == "FAILED":
            blocked = True
        # COMPLETED/SKIPPED add no remaining time
        
        builds_info.append({
            "id": b["id"],
            "build_number": b["build_number"],
            "status": status,
            "print_name": b.get("print_name") or f"Build {b['build_number']}",
            "printer": b.get("printer"),
            "progress": build_progress,
            "is_current": status == "PRINTING",
            "eta_display": build_eta_display,
            "eta_utc": (build_eta_dt.isoformat() + "Z") if build_eta_dt else None,
        })
    
    remaining_builds = len([b for b in builds_list if b["status"] in ["PENDING", "READY", "PRINTING"]])
    if blocked:
        request_eta_display = "Blocked"
    elif request_remaining_seconds > 0:
        request_eta_dt = now + __import__('datetime').timedelta(seconds=request_remaining_seconds)
        request_eta_display = format_eta_display(request_eta_dt)
    
    return {
        "is_multi_build": True,
        "total_builds": total_builds,
        "completed_builds": completed_builds_count,
        "current_build_num": current_build_number,
        "current_build_number": current_build_number,
        "current_build_eta": current_build_eta_display,
        "current_build_eta_dt": (current_build_eta_dt.isoformat() + "Z") if current_build_eta_dt else None,
        "request_eta": request_eta_display,
        "request_eta_dt": (request_eta_dt.isoformat() + "Z") if request_eta_dt else None,
        "total_eta": request_eta_display,
        "total_eta_dt": (request_eta_dt.isoformat() + "Z") if request_eta_dt else None,
        "remaining_builds": remaining_builds,
        "builds_info": builds_info,
        "blocked": blocked,
    }


def send_build_start_notification(build: Dict, request: Dict):
    """
    Send notification when a build starts printing.
    Clearly indicates this is a build, not final completion.
    """
    build_num = build["build_number"]
    total_builds = request.get("total_builds") or 1
    request_id = request["id"]
    
    print(f"[BUILD-NOTIFY] Sending build start notification: Build {build_num}/{total_builds}")
    
    # Check notification settings
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)
    should_notify = get_bool_setting("notify_requester_printing", True)
    
    if not requester_email_on_status or not should_notify:
        return
    
    # Get user-level notification preferences (from user_notification_prefs table)
    user_prefs = get_user_notification_prefs(request.get("requester_email", ""))
    user_wants_email = user_prefs.get("status_email", True)
    user_wants_push = user_prefs.get("status_push", True)
    
    print_label = request.get("print_name") or f"Request {request_id[:8]}"
    build_label = build.get("print_name") or f"Build {build_num}"
    is_multi_build = total_builds > 1
    
    # Build position string
    position_str = f"Build {build_num} of {total_builds}" if is_multi_build else "Print"
    remaining = (total_builds - build_num) if is_multi_build else 0
    
    if user_wants_email and request.get("requester_email"):
        subject = f"[{APP_TITLE}] {position_str} Started - {print_label}"
        
        email_rows = [
            ("Print Name", print_label),
            ("Build", position_str if is_multi_build else "Single build"),
            ("Status", "PRINTING"),
            ("Printer", _human_printer(build.get("printer") or request.get("printer") or "") or "—"),
            ("Material", _human_material(build.get("material") or request.get("material") or "") or "—"),
        ]
        
        if remaining > 0 and is_multi_build:
            email_rows.append(("Remaining", f"{remaining} build(s) after this one"))
        
        text = (
            f"{position_str} has started printing!\n\n"
            f"Print: {print_label}\n"
            f"Build: {build_label}\n"
            f"Request ID: {request_id[:8]}\n"
            f"\n"
        )
        if remaining > 0 and is_multi_build:
            text += f"⚠️ This is NOT the final completion - {remaining} build(s) remain after this one.\n\n"
        text += (
            f"View progress: {BASE_URL}/my/{request_id}?token={request.get('access_token', '')}\n"
        )
        
        # Generate my-requests link
        my_requests_token = get_or_create_my_requests_token(request["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        # Check if user has an account (show account tip if not)
        show_account_tip = not bool(request.get("account_id"))
        tip_register_url = None
        if show_account_tip:
            from urllib.parse import quote
            tip_register_url = f"{BASE_URL}/auth/register?email={quote(request['requester_email'])}"
        
        html = build_email_html(
            title=f"🖨️ {position_str} Started",
            subtitle=f"'{print_label}' - {build_label} is now printing",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Progress",
            header_color="#f59e0b",  # Amber for in-progress
            footer_note=f"{'This is build ' + str(build_num) + ' of ' + str(total_builds) + '. ' if is_multi_build else ''}You will receive another notification when the print completes.",
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
            show_account_tip=show_account_tip,
            tip_register_url=tip_register_url,
        )
        send_email([request["requester_email"]], subject, text, html)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        send_push_notification(
            email=request["requester_email"],
            title=f"🖨️ {position_str} Started",
            body=f"'{print_label}' - {build_label} is now printing" + (f" ({remaining} more after this)" if remaining > 0 and is_multi_build else ""),
            url=f"/my/{request_id}?token={request.get('access_token', '')}"
        )


def send_build_complete_notification(build: Dict, request: Dict, snapshot_b64: Optional[str] = None):
    """
    Send notification when a build completes.
    Clearly indicates this is a build completion, not final request completion.
    """
    build_num = build["build_number"]
    total_builds = request.get("total_builds") or 1
    request_id = request["id"]
    completed_builds = request.get("completed_builds", 0) + 1  # +1 because this build just completed
    is_multi_build = total_builds > 1
    
    # Check if this is the FINAL build
    is_final = (completed_builds >= total_builds)
    
    # If this is a single-build request, treat this as the authoritative completion notification
    if not is_multi_build and is_final:
        send_request_complete_notification(request, snapshot_b64)
        return
    
    print(f"[BUILD-NOTIFY] Sending build complete notification: Build {build_num}/{total_builds}")
    
    # Check notification settings
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)
    should_notify = get_bool_setting("notify_requester_done", True)
    
    if not requester_email_on_status or not should_notify:
        return
    
    # Get user-level notification preferences (from user_notification_prefs table)
    user_prefs = get_user_notification_prefs(request.get("requester_email", ""))
    user_wants_email = user_prefs.get("status_email", True)
    user_wants_push = user_prefs.get("status_push", True)
    
    print_label = request.get("print_name") or f"Request {request_id[:8]}"
    build_label = build.get("print_name") or f"Build {build_num}"
    report_url = f"/open/{request_id}?token={request.get('access_token', '')}&build_id={build.get('id', '')}&report=1"
    
    # Build position string
    position_str = f"Build {build_num} of {total_builds}"
    remaining = total_builds - completed_builds
    
    if user_wants_email and request.get("requester_email"):
        subject = f"[{APP_TITLE}] {position_str} Complete - {print_label}"
        
        email_rows = [
            ("Print Name", print_label),
            ("Build Completed", position_str),
            ("Progress", f"{completed_builds}/{total_builds} builds done"),
            ("Status", "IN PROGRESS" if remaining > 0 else "DONE"),
        ]
        
        if build.get("final_temperature"):
            email_rows.append(("Final Temp", build["final_temperature"]))
        
        if remaining > 0:
            email_rows.append(("Remaining", f"{remaining} build(s) still to go"))
        
        text = (
            f"{position_str} has completed!\n\n"
            f"Print: {print_label}\n"
            f"Build: {build_label}\n"
            f"Progress: {completed_builds}/{total_builds} builds done\n"
            f"\n⚠️ This is NOT the final completion - {remaining} build(s) remaining.\n"
            f"You will be notified when all builds are complete and ready for pickup.\n"
            f"\nView progress: {BASE_URL}/my/{request_id}?token={request.get('access_token', '')}\n"
        )
        
        # Generate my-requests link
        my_requests_token = get_or_create_my_requests_token(request["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        # Include snapshot if available
        snapshot_to_send = snapshot_b64 if get_bool_setting("enable_camera_snapshot", False) else None
        
        # Check if user has an account (show account tip if not)
        show_account_tip = not bool(request.get("account_id"))
        tip_register_url = None
        if show_account_tip:
            from urllib.parse import quote
            tip_register_url = f"{BASE_URL}/auth/register?email={quote(request['requester_email'])}"
        
        html = build_email_html(
            title=f"✓ {position_str} Complete",
            subtitle=f"'{print_label}' - {build_label} finished successfully",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Progress",
            header_color="#10b981",  # Green for complete
            footer_note=f"This is build {build_num} of {total_builds}. {remaining} build(s) remaining. You will receive a final notification when everything is ready for pickup. If something looks off, click Report a Problem so we can intervene.",
            image_base64=snapshot_to_send,
            secondary_cta_url=f"{BASE_URL}{report_url}",
            secondary_cta_label="Report a Problem",
            show_account_tip=show_account_tip,
            tip_register_url=tip_register_url,
        )
        send_email([request["requester_email"]], subject, text, html, image_base64=snapshot_to_send)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        send_push_notification(
            email=request["requester_email"],
            title=f"✓ {position_str} Complete",
            body=f"'{print_label}' - {completed_builds}/{total_builds} builds done, {remaining} remaining",
            url=f"/my/{request_id}?token={request.get('access_token', '')}",
            data={"reportUrl": report_url},
            actions=[{"action": "report-problem", "title": "Report a problem"}]
        )


def send_build_fail_notification(build: Dict, request: Dict, reason: Optional[str] = None):
    """
    Send notification when a build fails.
    Lets requester know there's an issue but the admin is handling it.
    """
    build_num = build.get("build_number", 1)
    total_builds = request.get("total_builds") or 1
    request_id = request["id"]
    
    # Skip notification for single-build requests (handled by legacy system)
    if total_builds <= 1:
        return
    
    print(f"[BUILD-NOTIFY] Sending build FAIL notification: Build {build_num}/{total_builds}")
    
    # Check notification settings
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)
    
    if not requester_email_on_status:
        return
    
    # Get user-level notification preferences (from user_notification_prefs table)
    user_prefs = get_user_notification_prefs(request.get("requester_email", ""))
    user_wants_email = user_prefs.get("status_email", True)
    user_wants_push = user_prefs.get("status_push", True)
    
    print_label = request.get("print_name") or f"Request {request_id[:8]}"
    build_label = build.get("print_name") or f"Build {build_num}"
    
    if user_wants_email and request.get("requester_email"):
        subject = f"[{APP_TITLE}] ⚠️ Build Issue - {print_label}"
        
        email_rows = [
            ("Print Name", print_label),
            ("Build", f"{build_num} of {total_builds}"),
            ("Status", "Issue Detected"),
        ]
        
        if reason:
            email_rows.append(("Details", reason))
        
        text = (
            f"There was an issue with build {build_num} of your print.\n\n"
            f"Print: {print_label}\n"
            f"Build: {build_label}\n"
            f"\nDon't worry - our team is aware and will handle it.\n"
            f"This may involve a reprint of this build. We'll notify you when progress resumes.\n"
            f"\nView progress: {BASE_URL}/my/{request_id}?token={request.get('access_token', '')}\n"
        )
        
        # Generate my-requests link
        my_requests_token = get_or_create_my_requests_token(request["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        # Check if user has an account (show account tip if not)
        show_account_tip = not bool(request.get("account_id"))
        tip_register_url = None
        if show_account_tip:
            from urllib.parse import quote
            tip_register_url = f"{BASE_URL}/auth/register?email={quote(request['requester_email'])}"
        
        html = build_email_html(
            title=f"⚠️ Build Issue",
            subtitle=f"'{print_label}' - Build {build_num} needs attention",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Progress",
            header_color="#f59e0b",  # Amber for warning
            footer_note="Our team is handling this issue. No action needed from you.",
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
            show_account_tip=show_account_tip,
            tip_register_url=tip_register_url,
        )
        send_email([request["requester_email"]], subject, text, html)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        send_push_notification(
            email=request["requester_email"],
            title=f"⚠️ Build Issue",
            body=f"'{print_label}' - Build {build_num} needs attention. We're handling it.",
            url=f"/my/{request_id}?token={request.get('access_token', '')}"
        )


def send_request_complete_notification(request: Dict, snapshot_b64: Optional[str] = None):
    """
    Send notification when ALL builds are complete (request is fully done).
    This is the authoritative 'ready for pickup' notification.
    Style matches the standard single-print completion notification.
    """
    request_id = request["id"]
    total_builds = request.get("total_builds") or 1
    
    print(f"[BUILD-NOTIFY] Sending REQUEST COMPLETE notification for {request_id[:8]} ({total_builds} builds)")
    
    # Check notification settings
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)
    should_notify = get_bool_setting("notify_requester_done", True)
    
    if not requester_email_on_status or not should_notify:
        return
    
    # Get user-level notification preferences (from user_notification_prefs table)
    user_prefs = get_user_notification_prefs(request.get("requester_email", ""))
    user_wants_email = user_prefs.get("status_email", True)
    user_wants_push = user_prefs.get("status_push", True)
    
    print_label = request.get("print_name") or f"Request {request_id[:8]}"
    report_url = f"/open/{request_id}?token={request.get('access_token', '')}&report=1"
    
    if user_wants_email and request.get("requester_email"):
        # Simple subject like the legacy notification
        subject = f"[{APP_TITLE}] Print Complete! - {print_label}"
        
        email_rows = [
            ("Print Name", print_label),
            ("Request ID", request_id[:8]),
            ("Status", "READY FOR PICKUP"),
        ]
        
        # Only mention builds if there were multiple
        if total_builds > 1:
            email_rows.insert(2, ("Builds", f"All {total_builds} finished"))
        
        text = (
            f"Your print is complete and ready for pickup!\n\n"
            f"Print: {print_label}\n"
            f"Request ID: {request_id[:8]}\n"
        )
        if total_builds > 1:
            text += f"All {total_builds} builds finished.\n"
        text += f"\nView: {BASE_URL}/my/{request_id}?token={request.get('access_token', '')}\n"
        
        # Generate my-requests link
        my_requests_token = get_or_create_my_requests_token(request["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        # Include snapshot if available
        snapshot_to_send = snapshot_b64 if get_bool_setting("enable_camera_snapshot", False) else None
        
        # Check if user has an account (show account tip if not)
        show_account_tip = not bool(request.get("account_id"))
        tip_register_url = None
        if show_account_tip:
            from urllib.parse import quote
            tip_register_url = f"{BASE_URL}/auth/register?email={quote(request['requester_email'])}"
        
        html = build_email_html(
            title="Print Complete!",
            subtitle=f"'{print_label}' is ready for pickup",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Request",
            header_color="#06b6d4",  # Cyan for done
            image_base64=snapshot_to_send,
            secondary_cta_url=f"{BASE_URL}{report_url}",
            secondary_cta_label="Report a Problem",
            footer_note=f"<a href=\"{BASE_URL}{my_requests_url}\">All My Requests</a> • If the snapshot looks off, report a problem so we can pause the job.",
            show_account_tip=show_account_tip,
            tip_register_url=tip_register_url,
        )
        send_email([request["requester_email"]], subject, text, html, image_base64=snapshot_to_send)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        body = f"'{print_label}' is ready for pickup!"
        if total_builds > 1:
            body = f"'{print_label}' is ready for pickup! All {total_builds} builds finished."
        
        send_push_notification(
            email=request["requester_email"],
            title="Print Complete!",
            body=body,
            url=f"/my/{request_id}?token={request.get('access_token', '')}",
            data={"reportUrl": report_url},
            actions=[{"action": "report-problem", "title": "Report a problem"}]
        )


def get_progress_notification_thresholds() -> List[int]:
    """Get the configured progress notification thresholds as a sorted list of percentages."""
    raw = get_setting("progress_notification_thresholds", "50,75")
    thresholds = []
    for p in raw.split(","):
        p = p.strip()
        if p.isdigit():
            pct = int(p)
            if 0 < pct < 100:  # Only valid percentages between 1 and 99
                thresholds.append(pct)
    return sorted(set(thresholds))


def get_sent_progress_milestones(build_id: str) -> List[int]:
    """Get list of progress percentages that have already been notified for a build."""
    conn = db()
    rows = conn.execute(
        "SELECT milestone_percent FROM build_progress_milestones WHERE build_id = ?",
        (build_id,)
    ).fetchall()
    conn.close()
    return [row["milestone_percent"] for row in rows]


def record_progress_milestone(build_id: str, milestone_percent: int, notification_type: str = "push"):
    """Record that a progress milestone notification was sent."""
    conn = db()
    try:
        conn.execute(
            """INSERT INTO build_progress_milestones (id, build_id, milestone_percent, notified_at, notification_type)
               VALUES (?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), build_id, milestone_percent, now_iso(), notification_type)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Already recorded (unique constraint on build_id + milestone_percent)
        pass
    conn.close()


def clear_progress_milestones(build_id: str):
    """Clear all progress milestones for a build (used on retry/restart)."""
    conn = db()
    conn.execute("DELETE FROM build_progress_milestones WHERE build_id = ?", (build_id,))
    conn.commit()
    conn.close()


# ─────────────────────────── USER NOTIFICATION PREFERENCES ───────────────────────────
def get_user_notification_prefs(email: str) -> dict:
    """
    Get notification preferences for a user.
    Returns dict with progress_push, progress_email, progress_milestones, status_push, status_email, broadcast_push.
    Defaults to all push enabled, progress email disabled.
    """
    conn = db()
    row = conn.execute(
        "SELECT progress_push, progress_email, progress_milestones, status_push, status_email, broadcast_push FROM user_notification_prefs WHERE LOWER(email) = LOWER(?)",
        (email,)
    ).fetchone()
    conn.close()
    
    if row:
        return {
            "progress_push": bool(row["progress_push"]),
            "progress_email": bool(row["progress_email"]),
            "progress_milestones": row["progress_milestones"] if row["progress_milestones"] else "50,75",
            "status_push": bool(row["status_push"]),
            "status_email": bool(row["status_email"]),
            "broadcast_push": bool(row["broadcast_push"]),
        }
    
    # Default preferences - push on, progress email off (to avoid spam)
    return {
        "progress_push": True,
        "progress_email": True,
        "progress_milestones": "50,75",
        "status_push": True,
        "status_email": True,
        "broadcast_push": True,
    }


def update_user_notification_prefs(email: str, prefs: dict) -> bool:
    """Update notification preferences for a user. Creates record if doesn't exist."""
    conn = db()
    try:
        conn.execute("""
            INSERT INTO user_notification_prefs (email, progress_push, progress_email, progress_milestones, status_push, status_email, broadcast_push, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                progress_push = excluded.progress_push,
                progress_email = excluded.progress_email,
                progress_milestones = excluded.progress_milestones,
                status_push = excluded.status_push,
                status_email = excluded.status_email,
                broadcast_push = excluded.broadcast_push,
                updated_at = excluded.updated_at
        """, (
            email.lower(),
            1 if prefs.get("progress_push", True) else 0,
            1 if prefs.get("progress_email", False) else 0,
            prefs.get("progress_milestones", "50,75"),
            1 if prefs.get("status_push", True) else 0,
            1 if prefs.get("status_email", True) else 0,
            1 if prefs.get("broadcast_push", True) else 0,
            now_iso()
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[PREFS] Error updating notification prefs for {email}: {e}")
        conn.close()
        return False


def send_progress_notification(build: Dict, request: Dict, current_percent: int):
    """
    Send progress notification for a build at a specific percentage.
    
    Rules:
    - PUSH notifications are sent for user-configured thresholds (if user has push enabled)
    - EMAIL is sent at 50% and 75% (if user has email enabled) to surface mid-print issues
    - Message format: "Hey your print is XX% — check it out! (Build X of Y)"
    - Push notifications include a snapshot image URL when camera is available
    """
    build_id = build["id"]
    build_num = build.get("build_number", 1)
    total_builds = request.get("total_builds") or 1
    request_id = request["id"]
    printer_code = build.get("printer")
    
    # Check global setting
    if not get_bool_setting("enable_progress_notifications", True):
        return
    
    # Get user-level notification preferences FIRST (includes their custom milestones)
    requester_email = request.get("requester_email")
    if not requester_email:
        return
    
    user_prefs = get_user_notification_prefs(requester_email)
    user_wants_progress_push = user_prefs.get("progress_push", True)
    user_wants_progress_email = user_prefs.get("progress_email", False)
    
    # If user has disabled both progress notification types, skip early
    if not user_wants_progress_push and not user_wants_progress_email:
        return
    
    # Get user's configured thresholds (or defaults)
    user_milestones_str = user_prefs.get("progress_milestones", "50,75")
    thresholds_for_push = []
    for p in user_milestones_str.split(","):
        p = p.strip()
        if p.isdigit():
            pct = int(p)
            if 0 < pct < 100:
                thresholds_for_push.append(pct)
    thresholds_for_push = sorted(set(thresholds_for_push))
    
    # Always evaluate 50% and 75% for email to ensure health-check checkpoints
    required_email_milestones = {50, 75}
    admin_milestones = {25, 75}  # Always evaluate admin checkpoints
    all_milestones = sorted(set(thresholds_for_push) | required_email_milestones | admin_milestones)
    
    if not all_milestones:
        return
    
    # Get already-sent milestones
    sent_milestones = get_sent_progress_milestones(build_id)
    
    # Determine which milestones to fire (handles jumps like 49->80 firing both 50 and 75)
    milestones_to_send = []
    for threshold in all_milestones:
        if threshold <= current_percent and threshold not in sent_milestones:
            milestones_to_send.append(threshold)
    
    if not milestones_to_send:
        return
    
    # Record milestones if user disabled notifications (to prevent future checks)
    if not user_wants_progress_push and not user_wants_progress_email:
        print(f"[PROGRESS-NOTIFY] User {requester_email} has disabled all progress notifications")
        # Still record milestones to prevent future checks
        for milestone in milestones_to_send:
            record_progress_milestone(build_id, milestone, "disabled")
        return
    
    print_label = request.get("print_name") or f"Request {request_id[:8]}"
    access_token = request.get("access_token", "")
    
    # Build position context
    if total_builds > 1:
        build_context = f" (Build {build_num} of {total_builds})"
    else:
        build_context = ""
    
    # URL with anchor to specific build
    view_url = f"/my/{request_id}?token={access_token}&build_id={build_id}#build-{build_id}"
    report_url = f"/open/{request_id}?token={access_token}&build_id={build_id}&report=1"
    
    # Try to get a camera snapshot URL for the notification image (best effort)
    # Only include if camera is configured for this printer
    image_url = None
    if printer_code and printer_code in ["ADVENTURER_4", "AD5X"]:
        camera_url = get_camera_url(printer_code)
        if camera_url:
            # Use the public snapshot endpoint (with timestamp to avoid caching)
            image_url = f"{BASE_URL}/api/camera/{printer_code}/snapshot?ts={int(datetime.utcnow().timestamp())}"
            print(f"[PROGRESS-NOTIFY] Including camera snapshot URL: {image_url}")
    
    for milestone in milestones_to_send:
        print(f"[PROGRESS-NOTIFY] Sending {milestone}% notification for build {build_id[:8]}")
        
        # Cheerful milestone-specific messages
        milestone_messages = {
            25: ("🚀 Great start!", f"'{print_label}' is 25% done — off to a great start!{build_context}"),
            50: ("🎉 Halfway there!", f"'{print_label}' is 50% done — check it out!{build_context}"),
            75: ("🔥 Almost done!", f"'{print_label}' is 75% complete — looking great!{build_context}"),
            90: ("✨ Nearly there!", f"'{print_label}' is 90% done — almost ready!{build_context}"),
        }
        
        # Default fallback for custom thresholds
        default_title = f"📊 {milestone}% Complete"
        default_body = f"'{print_label}' is {milestone}% done — check it out!{build_context}"
        
        notification_title, notification_body = milestone_messages.get(milestone, (default_title, default_body))
        
        # Tag for this specific build's progress (allows replacing previous progress notification)
        notification_tag = f"progress-{build_id[:8]}"
        sent_any = False
        
        # Send PUSH notification (if user enabled)
        if user_wants_progress_push and (milestone in thresholds_for_push):
            send_push_notification(
                email=requester_email,
                title=notification_title,
                body=notification_body,
                url=view_url,
                image_url=image_url,  # Include snapshot image if available
                tag=notification_tag,   # Use tag to replace previous progress notifications for this build
                data={"reportUrl": report_url},
                actions=[{"action": "report-problem", "title": "Report a problem"}]
            )
            record_progress_milestone(build_id, milestone, "push")
            sent_any = True
        
        # Send EMAIL at 50% and 75% thresholds for proactive health checks
        if user_wants_progress_email and milestone in required_email_milestones:
            subject = f"[{APP_TITLE}] Print update - {print_label}"
            
            email_rows = [
                ("Print Name", print_label),
                ("Progress", f"{milestone}%"),
            ]
            if total_builds > 1:
                email_rows.append(("Build", f"{build_num} of {total_builds}"))
            
            text = (
                f"Hey your print is {milestone}% — check it out!{build_context}\n\n"
                f"Print: {print_label}\n"
                f"\nView progress: {BASE_URL}{view_url}\n"
            )
            
            # Generate my-requests link
            my_requests_token = get_or_create_my_requests_token(requester_email)
            my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"

            # Try to include a live snapshot inline if camera snapshots are enabled
            snapshot_to_send = None
            if get_bool_setting("enable_camera_snapshot", False) and printer_code:
                try:
                    # Use public snapshot endpoint so auth/certs match email links
                    snap_url = f"{BASE_URL}/api/camera/{printer_code}/snapshot"
                    r = httpx.get(snap_url, timeout=4)
                    if r.status_code == 200 and r.content:
                        snapshot_to_send = base64.b64encode(r.content).decode("utf-8")
                        print(f"[PROGRESS-NOTIFY] Included snapshot for {request_id[:8]} {milestone}%")
                except Exception as e:
                    print(f"[PROGRESS-NOTIFY] Snapshot failed for {printer_code}: {e}")
            
            html = build_email_html(
                title=notification_title,
                subtitle=notification_body,
                rows=email_rows,
                cta_url=f"{BASE_URL}{view_url}",
                cta_label="View Progress",
                header_color="#8b5cf6",  # Purple for progress updates
                secondary_cta_url=f"{BASE_URL}{report_url}",
                secondary_cta_label="Report a Problem",
                footer_note=f"<a href=\"{BASE_URL}{my_requests_url}\">All My Requests</a> • If something looks off, click Report a Problem so we can investigate.",
                image_base64=snapshot_to_send,
            )
            send_email([requester_email], subject, text, html, image_base64=snapshot_to_send)
            record_progress_milestone(build_id, milestone, "email")
            sent_any = True

        # Admin progress alerts at 25% and 75% with snapshot/link (toggleable)
        admin_progress_on = get_bool_setting("admin_progress_notifications", False)
        admin_emails = parse_email_list(get_setting("admin_notify_emails", "")) if admin_progress_on else []
        if admin_progress_on and admin_emails and milestone in admin_milestones:
            snapshot_to_send_admin = None
            snapshot_url = None
            if get_bool_setting("enable_camera_snapshot", False) and printer_code:
                snapshot_url = f"{BASE_URL}/api/camera/{printer_code}/snapshot"
                try:
                    r = httpx.get(snapshot_url, timeout=4)
                    if r.status_code == 200 and r.content:
                        snapshot_to_send_admin = base64.b64encode(r.content).decode("utf-8")
                        print(f"[PROGRESS-NOTIFY] Admin snapshot included for {request_id[:8]} {milestone}%")
                except Exception as e:
                    print(f"[PROGRESS-NOTIFY] Admin snapshot fetch failed: {e}")

            admin_subject = f"[{APP_TITLE}] Admin {milestone}% - {print_label} (Build {build_num})"
            admin_text = (
                f"{print_label} is {milestone}% complete{build_context}.\n"
                f"Request: {request_id[:8]}\n"
                f"Build: {build_num} of {total_builds}\n"
                f"Link: {BASE_URL}/admin/request/{request_id}\n"
            )
            admin_html = build_email_html(
                title=f"Admin {milestone}% checkpoint",
                subtitle=f"'{print_label}' (Build {build_num}) is at {milestone}%",
                rows=[
                    ("Request", request_id[:8]),
                    ("Build", f"{build_num} of {total_builds}"),
                    ("Progress", f"{milestone}%"),
                    ("Printer", _human_printer(printer_code) if printer_code else "—"),
                ],
                cta_url=f"{BASE_URL}/admin/request/{request_id}",
                cta_label="Open in Admin",
                header_color="#0ea5e9",
                secondary_cta_url=snapshot_url,
                secondary_cta_label="View Snapshot" if snapshot_url else None,
                image_base64=snapshot_to_send_admin,
            )
            send_email(admin_emails, admin_subject, admin_text, admin_html, image_base64=snapshot_to_send_admin)
            # Send admin push with snapshot (where supported)
            send_push_notification_to_admins(
                title=admin_subject,
                body=notification_body,
                url=f"/admin/request/{request_id}",
                tag=f"admin-progress-{build_id[:8]}",
                image_url=snapshot_url,
                data={"requestId": request_id, "buildId": build_id, "reportUrl": report_url},
                actions=[{"action": "report-problem", "title": "Report a problem"}]
            )
            # Record milestone so we don't keep re-sending admin alerts
            record_progress_milestone(build_id, milestone, "admin")
            sent_any = True  # prevent milestone from being re-sent/recorded
        
        # Record milestone even if no notifications sent (prevents re-check)
        if not sent_any:
            record_progress_milestone(build_id, milestone, "none")


def get_build_snapshots(build_id: str) -> List[Dict]:
    """Get all snapshots for a build."""
    conn = db()
    snapshots = conn.execute(
        "SELECT * FROM build_snapshots WHERE build_id = ? ORDER BY created_at DESC",
        (build_id,)
    ).fetchall()
    conn.close()
    return [dict(s) for s in snapshots]


def get_request_build_snapshots(request_id: str) -> List[Dict]:
    """Get all snapshots for all builds of a request, with build info."""
    conn = db()
    snapshots = conn.execute("""
        SELECT bs.*, b.build_number, b.print_name as build_name
        FROM build_snapshots bs
        JOIN builds b ON bs.build_id = b.id
        WHERE b.request_id = ?
        ORDER BY b.build_number, bs.created_at DESC
    """, (request_id,)).fetchall()
    conn.close()
    return [dict(s) for s in snapshots]


# ------------------------
# FlashForge Printer API (via flashforge-finder-api)
# ------------------------

class FlashForgeAPI:
    """Wrapper for flashforge-finder-api Flask server"""
    def __init__(self, flask_api_url: str, printer_ip: str):
        self.flask_api_url = flask_api_url.rstrip("/")
        self.printer_ip = printer_ip

    async def get_progress(self) -> Optional[Dict[str, Any]]:
        """Get print progress (%, bytes printed, etc)"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.flask_api_url}/{self.printer_ip}/progress"
                r = await client.get(url)
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            print(f"[PRINTER] Error fetching progress from {self.printer_ip}: {e}")
        return None

    async def get_status(self) -> Optional[Dict[str, Any]]:
        """Get printer status (READY, PRINTING, etc)"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.flask_api_url}/{self.printer_ip}/status"
                r = await client.get(url)
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            print(f"[PRINTER] Error fetching status from {self.printer_ip}: {e}")
        return None

    async def get_temperature(self) -> Optional[Dict[str, Any]]:
        """Get current and target temperature"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.flask_api_url}/{self.printer_ip}/temp"
                r = await client.get(url)
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            print(f"[PRINTER] Error fetching temperature from {self.printer_ip}: {e}")
        return None

    async def get_info(self) -> Optional[Dict[str, Any]]:
        """Get printer info (name, firmware, serial, type)"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.flask_api_url}/{self.printer_ip}/info"
                r = await client.get(url)
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            print(f"[PRINTER] Error fetching info from {self.printer_ip}: {e}")
        return None

    async def get_head_location(self) -> Optional[Dict[str, Any]]:
        """Get print head X, Y, Z location"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.flask_api_url}/{self.printer_ip}/head-location"
                r = await client.get(url)
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            print(f"[PRINTER] Error fetching head location from {self.printer_ip}: {e}")
        return None

    async def get_extended_status(self) -> Optional[Dict[str, Any]]:
        """Get extended status including current filename and layer info via direct M-codes.
        
        Uses a printer lock to prevent conflicts with print send operations.
        Has built-in retry logic with delays to handle transient connection issues.
        """
        import socket
        result = {}
        
        # Get the printer lock to prevent simultaneous connections
        printer_code = "ADVENTURER_4" if "198" in self.printer_ip else "AD5X"  # Derive from IP
        lock = get_printer_lock(printer_code)
        
        # Check if polling is paused for this printer
        if is_polling_paused(printer_code):
            print(f"[PRINTER] Polling paused for {printer_code}, skipping extended status")
            return None
        
        max_retries = 2
        retry_delay = 1.0  # seconds between retries
        
        # Try to acquire lock with timeout - do this ONCE before retry loop
        try:
            await asyncio.wait_for(lock.acquire(), timeout=5.0)
        except asyncio.TimeoutError:
            print(f"[PRINTER] Could not acquire lock for {self.printer_ip}, another operation in progress")
            return None
        
        try:
            for attempt in range(max_retries + 1):
                sock = None
                try:
                    # M119 gives us CurrentFile and detailed status
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.printer_ip, 8899))
                    
                    # Control request
                    sock.send(b"~M601 S1\r\n")
                    sock.recv(1024)
                    
                    # M119 for status + current file
                    sock.send(b"~M119\r\n")
                    response = b""
                    try:
                        while True:
                            chunk = sock.recv(2048)
                            if not chunk:
                                break
                            response += chunk
                            if b"ok\r\n" in response or b"ok\n" in response:
                                break
                    except socket.timeout:
                        pass
                    
                    m119_text = response.decode('utf-8', errors='ignore')
                    
                    # Parse M119 response
                    for line in m119_text.split('\n'):
                        line = line.strip()
                        if line.startswith('CurrentFile:'):
                            result['current_file'] = line.replace('CurrentFile:', '').strip()
                        elif line.startswith('MachineStatus:'):
                            result['machine_status'] = line.replace('MachineStatus:', '').strip()
                        elif line.startswith('LED:'):
                            result['led'] = line.replace('LED:', '').strip()
                        elif line.startswith('Status:'):
                            result['status_flags'] = line.replace('Status:', '').strip()
                    
                    # M27 for layer info
                    sock.send(b"~M27\r\n")
                    response = b""
                    try:
                        while True:
                            chunk = sock.recv(2048)
                            if not chunk:
                                break
                            response += chunk
                            if b"ok\r\n" in response or b"ok\n" in response:
                                break
                    except socket.timeout:
                        pass
                    
                    m27_text = response.decode('utf-8', errors='ignore')
                    
                    # Parse M27 response for layer info
                    for line in m27_text.split('\n'):
                        line = line.strip()
                        if line.startswith('Layer:'):
                            layer_part = line.replace('Layer:', '').strip()
                            if '/' in layer_part:
                                parts = layer_part.split('/')
                                result['current_layer'] = int(parts[0].strip())
                                result['total_layers'] = int(parts[1].strip())
                        elif line.startswith('SD printing byte'):
                            # "SD printing byte 32/100"
                            pass  # Already have progress from other endpoint
                    
                    return result if result else None
                    
                except (ConnectionRefusedError, OSError) as e:
                    if attempt < max_retries:
                        print(f"[PRINTER] Connection failed to {self.printer_ip} (attempt {attempt + 1}/{max_retries + 1}), retrying in {retry_delay}s: {e}")
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 1.5  # Exponential backoff
                    else:
                        print(f"[PRINTER] Error fetching extended status from {self.printer_ip} after {max_retries + 1} attempts: {e}")
                        return None
                except Exception as e:
                    print(f"[PRINTER] Error fetching extended status from {self.printer_ip}: {e}")
                    return None
                finally:
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
            
            return None
        finally:
            # Always release the lock when done (success or failure)
            lock.release()

    async def is_printing(self) -> bool:
        """Check if printer is currently printing"""
        status = await self.get_status()
        if not status:
            return False
        # FlashForge status format: check if MachineStatus is actively printing
        machine_status = status.get("MachineStatus", "READY").strip().upper()
        # Not printing if READY or any COMPLETED state
        if machine_status == "READY" or "COMPLETED" in machine_status:
            return False
        # Actively printing states: BUILDING, BUILDING_FROM_SD, etc.
        return "BUILDING" in machine_status or "PRINTING" in machine_status

    async def is_complete(self) -> bool:
        """Check if printer just finished a print (BUILDING_COMPLETED state or READY with 100%)"""
        status = await self.get_status()
        if not status:
            return False
        machine_status = status.get("MachineStatus", "").strip().upper()
        # Completed states (case insensitive)
        if "COMPLETED" in machine_status:
            return True
        # Also check if READY and at 100%
        if machine_status == "READY":
            percent = await self.get_percent_complete()
            return percent == 100
        return False

    async def get_percent_complete(self) -> Optional[int]:
        """Get print progress percentage"""
        progress = await self.get_progress()
        if not progress:
            return None
        return progress.get("PercentageCompleted")

    def calculate_eta(self, percent_complete: int, start_time_iso: str) -> Optional[int]:
        """
        Calculate estimated time remaining in seconds based on progress.
        Returns None if cannot calculate (e.g., just started, at 0%).
        """
        if percent_complete <= 0:
            return None
        
        try:
            start_time = datetime.fromisoformat(start_time_iso)
            elapsed = (datetime.now(start_time.tzinfo) - start_time).total_seconds()
            
            # Avoid division by zero
            if elapsed < 1:
                return None
            
            # Calculate rate: seconds per percent
            rate = elapsed / percent_complete
            remaining_percent = 100 - percent_complete
            eta_seconds = int(rate * remaining_percent)
            
            return max(0, eta_seconds)
        except Exception:
            return None


class MoonrakerAPI:
    """Wrapper for Moonraker API (Klipper-based printers).
    
    Implements the same interface as FlashForgeAPI so it can be used as a
    drop-in replacement via the get_printer_api() factory when the
    moonraker_ad5x feature flag is enabled.
    
    Moonraker REST API docs: https://moonraker.readthedocs.io/en/latest/web_api/
    """
    
    # Map Moonraker print_stats.state → FlashForge-compatible status strings
    _STATE_MAP = {
        "printing": "BUILDING",
        "paused": "PAUSED",
        "complete": "BUILD_COMPLETE",
        "standby": "READY",
        "error": "ERROR",
        "cancelled": "READY",
    }
    
    def __init__(self, moonraker_url: str, api_key: str = ""):
        self.base_url = moonraker_url.rstrip("/")
        self.api_key = api_key
        self._cached_objects: Optional[Dict[str, Any]] = None
        self._cached_at: float = 0
    
    def _headers(self) -> Dict[str, str]:
        """Build request headers, including API key if configured."""
        headers = {}
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
        return headers
    
    async def _query_objects(self, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Query all printer objects in a single request (minimizes round-trips).
        
        Caches for 2 seconds to avoid hammering the API when multiple methods
        are called in sequence (e.g., get_status + get_temp + get_progress).
        """
        import time
        now = time.time()
        if self._cached_objects and (now - self._cached_at) < 2.0:
            return self._cached_objects
        
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                url = (
                    f"{self.base_url}/printer/objects/query"
                    "?print_stats&virtual_sdcard&extruder&heater_bed&toolhead"
                    "&display_status&gcode_move"
                )
                r = await client.get(url, headers=self._headers())
                if r.status_code == 200:
                    data = r.json()
                    self._cached_objects = data.get("result", {}).get("status", {})
                    self._cached_at = now
                    return self._cached_objects
        except Exception as e:
            print(f"[MOONRAKER] Error querying objects: {e}")
        return None
    
    def _invalidate_cache(self):
        """Invalidate the object query cache (call after control actions)."""
        self._cached_objects = None
        self._cached_at = 0
    
    async def get_status(self) -> Optional[Dict[str, Any]]:
        """Get printer status in FlashForge-compatible format."""
        objects = await self._query_objects()
        if not objects:
            return None
        
        print_stats = objects.get("print_stats", {})
        state = print_stats.get("state", "standby")
        mapped_status = self._STATE_MAP.get(state, "UNKNOWN")
        
        return {"MachineStatus": mapped_status}
    
    async def get_progress(self) -> Optional[Dict[str, Any]]:
        """Get print progress in FlashForge-compatible format."""
        objects = await self._query_objects()
        if not objects:
            return None
        
        vsd = objects.get("virtual_sdcard", {})
        progress_float = vsd.get("progress", 0)  # 0.0 – 1.0
        percent = int(progress_float * 100)
        
        return {"PercentageCompleted": percent}
    
    async def get_temperature(self) -> Optional[Dict[str, Any]]:
        """Get nozzle temperature in FlashForge-compatible format."""
        objects = await self._query_objects()
        if not objects:
            return None
        
        extruder = objects.get("extruder", {})
        current = round(extruder.get("temperature", 0), 1)
        target = round(extruder.get("target", 0), 1)
        
        return {
            "Temperature": str(current),
            "TargetTemperature": str(target),
        }
    
    async def get_info(self) -> Optional[Dict[str, Any]]:
        """Get printer info from Moonraker."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.base_url}/printer/info",
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    data = r.json().get("result", {})
                    return {
                        "MachineName": data.get("hostname", "Klipper"),
                        "FirmwareVersion": data.get("software_version", "?"),
                        "SerialNumber": data.get("cpu_info", "?"),
                        "MachineType": "Klipper",
                        "state": data.get("state", "unknown"),
                        "state_message": data.get("state_message", ""),
                    }
        except Exception as e:
            print(f"[MOONRAKER] Error fetching info: {e}")
        return None
    
    async def get_head_location(self) -> Optional[Dict[str, Any]]:
        """Get toolhead position."""
        objects = await self._query_objects()
        if not objects:
            return None
        
        toolhead = objects.get("toolhead", {})
        position = toolhead.get("position", [0, 0, 0, 0])
        
        return {
            "X": round(position[0], 2) if len(position) > 0 else 0,
            "Y": round(position[1], 2) if len(position) > 1 else 0,
            "Z": round(position[2], 2) if len(position) > 2 else 0,
        }
    
    async def get_extended_status(self) -> Optional[Dict[str, Any]]:
        """Get extended status: current file, layers, etc.
        
        Combines print_stats data with display_status for a rich status response.
        Does NOT require raw socket connections — uses REST API only.
        """
        objects = await self._query_objects()
        if not objects:
            return None
        
        print_stats = objects.get("print_stats", {})
        display = objects.get("display_status", {})
        
        filename = print_stats.get("filename", "")
        info = print_stats.get("info", {})
        current_layer = info.get("current_layer")
        total_layer = info.get("total_layer")
        
        result = {}
        if filename:
            result["current_file"] = filename
        if current_layer is not None:
            result["current_layer"] = current_layer
        if total_layer is not None:
            result["total_layers"] = total_layer
        
        # Include Moonraker-specific extras
        result["print_duration"] = print_stats.get("print_duration", 0)
        result["filament_used"] = print_stats.get("filament_used", 0)
        result["state"] = print_stats.get("state", "standby")
        result["message"] = print_stats.get("message", "")
        
        # display_status.progress is Klipper's M73-reported progress (0.0–1.0)
        if display.get("progress") is not None:
            result["display_progress"] = int(display["progress"] * 100)
        
        return result if result else None
    
    async def is_printing(self) -> bool:
        """Check if printer is currently printing."""
        objects = await self._query_objects()
        if not objects:
            return False
        state = objects.get("print_stats", {}).get("state", "standby")
        return state == "printing"
    
    async def is_complete(self) -> bool:
        """Check if printer just finished a print."""
        objects = await self._query_objects()
        if not objects:
            return False
        state = objects.get("print_stats", {}).get("state", "standby")
        return state == "complete"
    
    async def get_percent_complete(self) -> Optional[int]:
        """Get print progress percentage (0-100)."""
        progress = await self.get_progress()
        if not progress:
            return None
        return progress.get("PercentageCompleted")
    
    def calculate_eta(self, percent_complete: int, start_time_iso: str) -> Optional[int]:
        """Calculate estimated time remaining in seconds (same as FlashForge)."""
        if percent_complete <= 0:
            return None
        try:
            start_time = datetime.fromisoformat(start_time_iso)
            elapsed = (datetime.now(start_time.tzinfo) - start_time).total_seconds()
            if elapsed < 1:
                return None
            rate = elapsed / percent_complete
            remaining_percent = 100 - percent_complete
            eta_seconds = int(rate * remaining_percent)
            return max(0, eta_seconds)
        except Exception:
            return None
    
    # ── Moonraker-only methods (not in FlashForgeAPI) ──────────────────
    
    async def get_bed_temp(self) -> Optional[Dict[str, Any]]:
        """Get heated bed temperature."""
        objects = await self._query_objects()
        if not objects:
            return None
        bed = objects.get("heater_bed", {})
        return {
            "temperature": round(bed.get("temperature", 0), 1),
            "target": round(bed.get("target", 0), 1),
        }
    
    async def get_file_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get G-code file metadata including slicer estimated time."""
        if not filename:
            return None
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.base_url}/server/files/metadata",
                    params={"filename": filename},
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json().get("result", {})
        except Exception as e:
            print(f"[MOONRAKER] Error fetching file metadata for {filename}: {e}")
        return None
    
    async def get_file_eta_seconds(self) -> Optional[int]:
        """Get the slicer's estimated total print time from G-code file metadata.
        
        This is the 'File' time shown in Fluidd (e.g., '43m 20s') — typically
        very accurate since it's calculated from the actual G-code.
        """
        objects = await self._query_objects()
        if not objects:
            return None
        
        filename = objects.get("print_stats", {}).get("filename")
        if not filename:
            return None
        
        metadata = await self.get_file_metadata(filename)
        if not metadata:
            return None
        
        estimated_time = metadata.get("estimated_time")
        return int(estimated_time) if estimated_time else None
    
    async def get_time_remaining(self) -> Optional[int]:
        """Calculate time remaining using Moonraker's own data.
        
        Uses file-based ETA (estimated_time) combined with progress for
        the most accurate estimate — matches what Fluidd shows.
        """
        objects = await self._query_objects()
        if not objects:
            return None
        
        print_stats = objects.get("print_stats", {})
        vsd = objects.get("virtual_sdcard", {})
        
        progress = vsd.get("progress", 0)
        print_duration = print_stats.get("print_duration", 0)
        
        if progress <= 0 or print_duration <= 0:
            return None
        
        # Method 1: File-based (most accurate)
        filename = print_stats.get("filename")
        if filename:
            metadata = await self.get_file_metadata(filename)
            if metadata and metadata.get("estimated_time"):
                total_est = metadata["estimated_time"]
                # Scale by actual progress rate
                actual_rate = print_duration / progress if progress > 0 else total_est
                remaining = actual_rate * (1 - progress)
                return max(0, int(remaining))
        
        # Method 2: Linear extrapolation from progress
        if progress > 0:
            total_est = print_duration / progress
            remaining = total_est - print_duration
            return max(0, int(remaining))
        
        return None
    
    async def get_thumbnail_url(self) -> Optional[str]:
        """Get URL for the current print's thumbnail (extracted from G-code)."""
        objects = await self._query_objects()
        if not objects:
            return None
        
        filename = objects.get("print_stats", {}).get("filename")
        if not filename:
            return None
        
        metadata = await self.get_file_metadata(filename)
        if not metadata:
            return None
        
        thumbnails = metadata.get("thumbnails", [])
        if not thumbnails:
            return None
        
        # Pick the largest thumbnail
        best = max(thumbnails, key=lambda t: t.get("width", 0) * t.get("height", 0))
        relative_path = best.get("relative_path")
        if relative_path:
            return f"{self.base_url}/server/files/gcodes/{relative_path}"
        return None
    
    async def get_server_files(self) -> Optional[List[Dict[str, Any]]]:
        """List G-code files on the printer."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{self.base_url}/server/files/list",
                    params={"root": "gcodes"},
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json().get("result", [])
        except Exception as e:
            print(f"[MOONRAKER] Error listing files: {e}")
        return None
    
    async def upload_file(self, filename: str, file_data: bytes, start_print: bool = False) -> Optional[Dict[str, Any]]:
        """Upload a G-code file to the printer.
        
        If start_print=True, Moonraker will begin printing the file immediately
        after upload, bypassing any Fluidd/Mainsail confirmation dialogs.
        """
        try:
            data = {}
            if start_print:
                data["print"] = "true"
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.base_url}/server/files/upload",
                    files={"file": (filename, file_data, "application/octet-stream")},
                    data=data,
                    headers=self._headers(),
                )
                if r.status_code == 201:
                    if start_print:
                        self._invalidate_cache()
                    return r.json()
        except Exception as e:
            print(f"[MOONRAKER] Error uploading file {filename}: {e}")
        return None
    
    async def get_file_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get G-code file metadata from Moonraker.
        
        After a file is uploaded, Moonraker parses it and extracts metadata
        including filament colors, referenced tools, filament types, etc.
        This is the same data Fluidd uses to detect multi-color prints.
        
        Returns dict with keys like:
          - referenced_tools: [0, 1, 2] — which tools the file uses
          - filament_colors: ['#FF0000', '#00FF00'] — colors per tool
          - filament_type: 'PLA' or 'PLA;PETG' — material types
          - filament_name: filament profile names
          - filament_total: total filament in mm
          - filament_change_count: number of filament changes
          - estimated_time: estimated print time in seconds
          - thumbnails: list of thumbnail images
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{self.base_url}/server/files/metadata",
                    params={"filename": filename},
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json().get("result", {})
        except Exception as e:
            print(f"[MOONRAKER] Error fetching metadata for {filename}: {e}")
        return None
    
    async def get_spoolman_spools(self) -> Optional[list]:
        """Get all spools from Spoolman via Moonraker proxy.
        
        Requires [spoolman] to be configured in moonraker.conf.
        Returns list of spool objects with filament info (color, material, vendor, weight).
        Returns None if Spoolman is not available.
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/server/spoolman/proxy",
                    json={
                        "request_method": "GET",
                        "path": "/v1/spool",
                        "use_v2_response": True,
                    },
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    data = r.json()
                    # v2 response wraps in {"response": ..., "error": ...}
                    if isinstance(data, dict) and "result" in data:
                        result = data["result"]
                        if isinstance(result, dict) and "response" in result:
                            return result["response"]
                        return result
                    return data
        except Exception as e:
            print(f"[MOONRAKER] Spoolman not available: {e}")
        return None
    
    async def get_active_spool(self) -> Optional[int]:
        """Get the currently active spool ID from Spoolman."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.base_url}/server/spoolman/spool_id",
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json().get("result", {}).get("spool_id")
        except Exception:
            pass
        return None
    
    async def set_active_spool(self, spool_id: Optional[int]) -> bool:
        """Set the active spool ID in Spoolman for filament tracking."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.post(
                    f"{self.base_url}/server/spoolman/spool_id",
                    json={"spool_id": spool_id},
                    headers=self._headers(),
                )
                return r.status_code == 200
        except Exception:
            pass
        return False
    
    async def start_print(self, filename: str) -> bool:
        """Start printing a file.
        
        Uses a longer timeout (60s) because ZMOD intercepts print starts
        and may run macros (homing, bed leveling) before responding.
        """
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.base_url}/printer/print/start",
                    json={"filename": filename},
                    headers=self._headers(),
                )
                self._invalidate_cache()
                if r.status_code == 200:
                    return True
                else:
                    body = r.text[:500] if r.text else "(empty)"
                    print(f"[MOONRAKER] start_print failed: HTTP {r.status_code} — {body}")
                    return False
        except httpx.TimeoutException:
            print(f"[MOONRAKER] start_print timed out after 60s for {filename}")
        except Exception as e:
            print(f"[MOONRAKER] Error starting print: {type(e).__name__}: {e}")
        return False
    
    async def run_gcode(self, script: str, timeout: float = 300) -> bool:
        """Run a G-code command on the printer.
        
        Args:
            script: G-code command(s) to run (multiple separated by newline).
            timeout: How long to wait for completion (default 300s for long ops like leveling).
        Returns:
            True if the command was accepted.
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    f"{self.base_url}/printer/gcode/script",
                    json={"script": script},
                    headers=self._headers(),
                )
                self._invalidate_cache()
                return r.status_code == 200
        except Exception as e:
            print(f"[MOONRAKER] Error running gcode '{script}': {e}")
        return False
    
    async def pause_print(self) -> bool:
        """Pause the current print."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/printer/print/pause",
                    headers=self._headers(),
                )
                self._invalidate_cache()
                return r.status_code == 200
        except Exception as e:
            print(f"[MOONRAKER] Error pausing print: {e}")
        return False
    
    async def resume_print(self) -> bool:
        """Resume a paused print."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/printer/print/resume",
                    headers=self._headers(),
                )
                self._invalidate_cache()
                return r.status_code == 200
        except Exception as e:
            print(f"[MOONRAKER] Error resuming print: {e}")
        return False
    
    async def cancel_print(self) -> bool:
        """Cancel the current print."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/printer/print/cancel",
                    headers=self._headers(),
                )
                self._invalidate_cache()
                return r.status_code == 200
        except Exception as e:
            print(f"[MOONRAKER] Error cancelling print: {e}")
        return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test the connection to Moonraker. Returns status info or error."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.base_url}/server/info",
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    result = r.json().get("result", {})
                    return {
                        "success": True,
                        "klippy_state": result.get("klippy_state", "unknown"),
                        "moonraker_version": result.get("moonraker_version", "?"),
                        "components": result.get("components", []),
                    }
                elif r.status_code == 401:
                    return {"success": False, "error": "Authentication required. Add an API key or configure trusted_clients in moonraker.conf."}
                else:
                    return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except httpx.ConnectError:
            return {"success": False, "error": f"Cannot connect to {self.base_url}. Check the URL and ensure Moonraker is running."}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_webcams(self) -> Optional[List[Dict[str, Any]]]:
        """List webcams configured in Moonraker.
        
        Queries GET /server/webcams/list which returns webcam entries with
        stream_url and snapshot_url fields. These are configured via
        moonraker.conf [webcam] sections or through front-end UIs like Fluidd.
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.base_url}/server/webcams/list",
                    headers=self._headers(),
                )
                if r.status_code == 200:
                    return r.json().get("result", {}).get("webcams", [])
        except Exception as e:
            print(f"[MOONRAKER] Error listing webcams: {e}")
        return None
    
    async def get_camera_urls(self, printer_code: str = "") -> Optional[Dict[str, str]]:
        """Get the best camera stream and snapshot URLs from Moonraker.
        
        Auto-discovers webcams via the Moonraker webcam API. Uses smart selection:
        1. Prefer webcam whose name matches the printer code (case-insensitive)
        2. Prefer webcam from 'database' source (user-configured in Fluidd/Mainsail)
        3. Fall back to first enabled webcam
        
        Returns dict with 'stream_url', 'snapshot_url', 'name', 'service' keys, or None.
        """
        webcams = await self.get_webcams()
        if not webcams:
            return None
        
        # Filter to enabled webcams
        enabled_cams = [wc for wc in webcams if wc.get("enabled", True)]
        if not enabled_cams:
            enabled_cams = webcams  # fallback: use all if none explicitly enabled
        
        # Smart selection: try to match by printer code name first
        cam = None
        if printer_code:
            code_lower = printer_code.lower()
            for wc in enabled_cams:
                wc_name = wc.get("name", "").lower()
                if wc_name == code_lower or code_lower in wc_name or wc_name in code_lower:
                    cam = wc
                    logger.info(f"[CAMERA] Selected webcam '{wc.get('name')}' by name match for {printer_code}")
                    break
        
        # If no name match, prefer database-sourced (user-configured in Fluidd/Mainsail)
        if cam is None:
            for wc in enabled_cams:
                if wc.get("source") == "database":
                    cam = wc
                    logger.info(f"[CAMERA] Selected webcam '{wc.get('name')}' (database source) for {printer_code}")
                    break
        
        # Last resort: first enabled webcam
        if cam is None:
            cam = enabled_cams[0]
            logger.info(f"[CAMERA] Selected first webcam '{cam.get('name')}' for {printer_code}")
        
        stream_url = cam.get("stream_url", "")
        snapshot_url = cam.get("snapshot_url", "")
        
        # Resolve relative URLs against the Moonraker host
        # Moonraker webcams can have relative paths like /webcam/?action=stream
        from urllib.parse import urlparse
        base_parsed = urlparse(self.base_url)
        base_host = f"{base_parsed.scheme}://{base_parsed.hostname}"
        if base_parsed.port and base_parsed.port not in (80, 443):
            base_host += f":{base_parsed.port}"
        
        def resolve_url(url: str) -> str:
            if not url:
                return ""
            if url.startswith("http://") or url.startswith("https://"):
                return url
            # Relative URL — resolve against Moonraker's host (port 80)
            host_no_port = f"{base_parsed.scheme}://{base_parsed.hostname}"
            return f"{host_no_port}/{url.lstrip('/')}"
        
        return {
            "stream_url": resolve_url(stream_url),
            "snapshot_url": resolve_url(snapshot_url),
            "name": cam.get("name", ""),
            "service": cam.get("service", ""),
        }


def get_printer_api(printer_code: str):
    """Get printer API instance for a printer (ADVENTURER_4 or AD5X).
    
    Returns MoonrakerAPI for AD5X when the moonraker_ad5x feature flag is enabled
    and a Moonraker URL is configured. Otherwise returns FlashForgeAPI.
    """
    # Moonraker path for AD5X (when feature flag is on)
    if printer_code == "AD5X" and is_feature_enabled("moonraker_ad5x"):
        moonraker_url = get_setting("moonraker_ad5x_url", "")
        if moonraker_url:
            api_key = get_setting("moonraker_ad5x_api_key", "")
            return MoonrakerAPI(moonraker_url, api_key)
        # Flag is on but no URL configured — fall through to FlashForge
        print("[PRINTER] moonraker_ad5x enabled but no URL configured, falling back to FlashForge")
    
    # FlashForge path (default for all printers)
    flask_url = get_setting("flashforge_api_url", "http://localhost:5000")
    
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    elif printer_code == "AD5X":
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    else:
        return None

    if not ip:
        return None

    return FlashForgeAPI(flask_url, ip)


def get_camera_url(printer_code: str) -> Optional[str]:
    """Get camera URL for a printer.
    
    For AD5X with Moonraker enabled, if no manual camera URL is set, derives
    the camera URL from the Moonraker IP using the standard ustreamer port (8080).
    This handles zmod/Klipper setups where ustreamer replaces the stock camera.
    
    Full Moonraker webcam auto-discovery (via /server/webcams/list) is available
    through the async get_camera_url_async() function.
    """
    if printer_code == "ADVENTURER_4":
        return get_setting("camera_adventurer_4_url", "")
    elif printer_code == "AD5X":
        manual_url = get_setting("camera_ad5x_url", "")
        if manual_url:
            return manual_url
        
        # Auto-derive from Moonraker URL when no manual camera URL is set
        if is_feature_enabled("moonraker_ad5x"):
            moonraker_url = get_setting("moonraker_ad5x_url", "")
            if moonraker_url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(moonraker_url)
                    hostname = parsed.hostname
                    if hostname:
                        # zmod uses ustreamer on port 8080
                        derived = f"http://{hostname}:8080/?action=stream"
                        logger.info(f"[CAMERA] Auto-detected AD5X camera URL from Moonraker: {derived}")
                        return derived
                except Exception:
                    pass
        return ""
    return None


async def get_camera_url_async(printer_code: str) -> Optional[str]:
    """Get camera stream URL with Moonraker webcam auto-discovery (async).
    
    Tries in order:
    1. Manual camera URL from settings (always wins)
    2. Moonraker webcam API auto-discovery (/server/webcams/list)
    3. Derived URL from Moonraker IP + ustreamer port 8080
    """
    # Manual URL always takes priority
    if printer_code == "ADVENTURER_4":
        return get_setting("camera_adventurer_4_url", "")
    elif printer_code == "AD5X":
        manual_url = get_setting("camera_ad5x_url", "")
        if manual_url:
            return manual_url
        
        # Try Moonraker webcam auto-discovery
        if is_feature_enabled("moonraker_ad5x"):
            moonraker_url = get_setting("moonraker_ad5x_url", "")
            if moonraker_url:
                api_key = get_setting("moonraker_ad5x_api_key", "")
                api = MoonrakerAPI(moonraker_url, api_key)
                try:
                    cam_urls = await api.get_camera_urls(printer_code="AD5X")
                    if cam_urls and cam_urls.get("stream_url"):
                        logger.info(f"[CAMERA] Auto-discovered AD5X camera via Moonraker API: {cam_urls['stream_url']} (name={cam_urls.get('name', '?')}, service={cam_urls.get('service', '?')})")
                        return cam_urls["stream_url"]
                except Exception as e:
                    logger.debug(f"[CAMERA] Moonraker webcam discovery failed: {e}")
                
                # Fallback: derive from Moonraker IP
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(moonraker_url)
                    hostname = parsed.hostname
                    if hostname:
                        return f"http://{hostname}:8080/?action=stream"
                except Exception:
                    pass
        return ""
    return None


async def get_camera_snapshot_url_async(printer_code: str) -> Optional[str]:
    """Get a dedicated snapshot URL from Moonraker webcam config (async).
    
    Moonraker's [webcam] section can have a separate snapshot_url that
    points directly to ustreamer's snapshot endpoint. This is more
    reliable than extracting a frame from the MJPEG stream, as ustreamer
    will wait for a real frame before responding (no placeholder).
    
    Returns the snapshot URL if available, or None.
    """
    if printer_code != "AD5X":
        return None
    if not is_feature_enabled("moonraker_ad5x"):
        return None
    moonraker_url = get_setting("moonraker_ad5x_url", "")
    if not moonraker_url:
        return None
    api_key = get_setting("moonraker_ad5x_api_key", "")
    api = MoonrakerAPI(moonraker_url, api_key)
    try:
        cam_urls = await api.get_camera_urls(printer_code=printer_code)
        if cam_urls and cam_urls.get("snapshot_url"):
            return cam_urls["snapshot_url"]
    except Exception:
        pass
    return None


async def capture_camera_snapshot(printer_code: str) -> Optional[bytes]:
    """Capture a snapshot from the printer's camera.
    
    Strategy (in order):
    1. Try Moonraker's dedicated snapshot_url (ustreamer waits for a real frame)
    2. Extract a frame from the MJPEG stream, skipping initial placeholder frames
       (ustreamer/crowsnest sends a 'Camera Off/Waiting' placeholder as the first
       frame when the stream starts, then switches to real frames)
    3. Fall back to derived snapshot URL (?action=snapshot)
    """
    camera_url = await get_camera_url_async(printer_code)
    if not camera_url:
        logger.debug(f"[CAMERA] No camera URL configured for {printer_code}")
        return None
    
    # Minimum size threshold for a "real" camera image vs placeholder.
    # ustreamer/crowsnest "Camera Off / Waiting..." placeholder JPEGs are
    # typically 5-12KB. Real camera frames are usually >20KB.
    MIN_REAL_FRAME_SIZE = 15000
    
    # ── Method 1: Moonraker's dedicated snapshot URL ──
    # This goes directly to ustreamer's /snapshot endpoint. If it returns
    # a large enough image, it's real. If it's small, it's likely the
    # "Camera Off" placeholder and we fall through to stream extraction.
    try:
        snapshot_api_url = await get_camera_snapshot_url_async(printer_code)
        if snapshot_api_url:
            logger.debug(f"[CAMERA] Trying Moonraker snapshot URL for {printer_code}: {snapshot_api_url}")
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(snapshot_api_url)
                if response.status_code == 200 and response.headers.get("content-type", "").startswith("image/"):
                    content_size = len(response.content)
                    if content_size > MIN_REAL_FRAME_SIZE:
                        logger.debug(f"[CAMERA] Got snapshot from {printer_code} via Moonraker snapshot URL ({content_size} bytes)")
                        return response.content
                    else:
                        logger.debug(f"[CAMERA] Snapshot URL returned small image ({content_size} bytes) - likely placeholder, trying stream extraction")
    except Exception as e:
        logger.debug(f"[CAMERA] Moonraker snapshot URL failed for {printer_code}: {e}")
    
    # ── Method 2: Extract frame from MJPEG stream, skip placeholders ──
    # ustreamer sends a small placeholder JPEG ("Camera Off / Waiting...")
    # as the first frame when the stream starts. Real camera frames follow
    # shortly after. We read up to 5 frames and return the first one that
    # exceeds MIN_REAL_FRAME_SIZE bytes.
    try:
        logger.debug(f"[CAMERA] Extracting frame from MJPEG stream for {printer_code}: {camera_url}")
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=8.0)) as client:
            async with client.stream("GET", camera_url) as response:
                buffer = b""
                frames_found = 0
                max_frames_to_check = 5
                last_good_frame = None
                
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    buffer += chunk
                    
                    # Look for complete JPEG frames (FFD8...FFD9)
                    while True:
                        start = buffer.find(b"\xff\xd8")
                        if start == -1:
                            break
                        end = buffer.find(b"\xff\xd9", start)
                        if end == -1:
                            break
                        
                        jpeg_data = buffer[start:end + 2]
                        buffer = buffer[end + 2:]  # consume the frame
                        frames_found += 1
                        frame_size = len(jpeg_data)
                        
                        logger.debug(f"[CAMERA] Frame {frames_found} from {printer_code}: {frame_size} bytes")
                        
                        # Placeholder frames from ustreamer are typically small.
                        # Real camera frames exceed MIN_REAL_FRAME_SIZE.
                        if frame_size > MIN_REAL_FRAME_SIZE:
                            logger.debug(f"[CAMERA] Using frame {frames_found} ({frame_size} bytes) - looks like real image")
                            return jpeg_data
                        
                        # Keep track of the last frame in case all are small
                        last_good_frame = jpeg_data
                        
                        if frames_found >= max_frames_to_check:
                            break
                    
                    if frames_found >= max_frames_to_check:
                        break
                    
                    # Prevent buffer from growing too large
                    if len(buffer) > 1000000:  # 1MB max
                        logger.warning(f"[CAMERA] Buffer too large, stopping frame search for {printer_code}")
                        break
                
                # If we found frames but none were large enough, the camera is
                # likely off/idle. Return None so the caller shows "camera unavailable"
                # rather than a confusing "Camera Off / Waiting..." placeholder image.
                if last_good_frame:
                    logger.debug(f"[CAMERA] All {frames_found} frames from {printer_code} were small (placeholder-sized), camera appears off/idle")
                    return None
    except Exception as e:
        logger.error(f"[CAMERA] MJPEG stream extraction error for {printer_code}: {e}")
    
    # ── Method 3: Derived snapshot URL (last resort) ──
    # Derive ?action=snapshot from the stream URL. Also checks size to
    # avoid returning a placeholder.
    try:
        import re
        snapshot_url = re.sub(r'\?action=stream(\d*)', r'?action=snapshot\1', camera_url)
        if snapshot_url != camera_url:  # only try if we actually derived a different URL
            logger.debug(f"[CAMERA] Trying derived snapshot URL for {printer_code}: {snapshot_url}")
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(snapshot_url)
                if response.status_code == 200 and response.headers.get("content-type", "").startswith("image/"):
                    content_size = len(response.content)
                    if content_size > MIN_REAL_FRAME_SIZE:
                        logger.debug(f"[CAMERA] Got snapshot from {printer_code} via derived URL ({content_size} bytes)")
                        return response.content
                    else:
                        logger.debug(f"[CAMERA] Derived snapshot returned small image ({content_size} bytes) - likely placeholder")
    except Exception as e:
        logger.debug(f"[CAMERA] Derived snapshot URL failed for {printer_code}: {e}")
    
    return None


async def poll_printer_status_worker():
    """
    Background worker that polls all configured printers every 30s.
    Auto-updates PRINTING -> DONE when printer reports 100% complete.
    
    In DEMO_MODE, this worker is disabled and fake printer data is used instead.
    """
    print("[POLL] Background printer polling started")
    
    # Skip real polling in demo mode
    if DEMO_MODE:
        print("[POLL] Demo mode active - printer polling disabled (using fake data)")
        while True:
            await asyncio.sleep(60)  # Just keep the task alive but do nothing
    
    while True:
        try:
            if not get_bool_setting("enable_printer_polling", True):
                await asyncio.sleep(30)
                continue
            
            print("[POLL] Checking for PRINTING requests...")
            add_poll_debug_log({"type": "poll_start", "message": "Checking for PRINTING requests"})

            conn = db()
            printing_reqs = conn.execute(
                "SELECT id, printer, printing_started_at, printing_email_sent, requester_email, requester_name, print_name, material, access_token, print_time_minutes, notification_prefs, active_build_id, status, total_builds FROM requests WHERE status IN ('PRINTING', 'IN_PROGRESS')",
                ()
            ).fetchall()
            conn.close()
            
            add_poll_debug_log({"type": "poll_found", "message": f"Found {len(printing_reqs)} PRINTING requests"})

            for req_row in printing_reqs:
                req = dict(req_row)  # Convert to dict for .get() support
                
                # Skip multi-build requests here; build-level polling handles notifications to avoid duplicates
                if req.get("total_builds") and req["total_builds"] > 1:
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": req.get("printer"),
                        "message": "Multi-build handled by build-level polling"
                    })
                    continue

                # If printer not on request (e.g., multi-build IN_PROGRESS), try active build
                effective_printer = req.get("printer")
                if (not effective_printer) and req.get("active_build_id"):
                    try:
                        conn_tmp = db()
                        build_row = conn_tmp.execute("SELECT printer, started_at FROM builds WHERE id = ?", (req["active_build_id"],)).fetchone()
                        conn_tmp.close()
                        if build_row:
                            effective_printer = build_row["printer"]
                            if not req.get("printing_started_at") and build_row["started_at"]:
                                req["printing_started_at"] = build_row["started_at"]
                    except Exception:
                        pass

                # Skip if still no printer
                if not effective_printer:
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": None,
                        "message": "No printer assigned for active build"
                    })
                    continue

                # Check if polling is paused for this printer (e.g., during print send)
                if is_polling_paused(effective_printer):
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": effective_printer,
                        "message": "Polling paused (print operation in progress)"
                    })
                    continue
                
                printer_api = get_printer_api(effective_printer)
                if not printer_api:
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": effective_printer,
                        "message": "No printer API configured"
                    })
                    continue

                # Check both status and progress
                is_printing = await printer_api.is_printing()
                is_complete = await printer_api.is_complete()
                percent_complete = await printer_api.get_percent_complete()
                
                # Debug logging
                status_info = await printer_api.get_status()
                machine_status = status_info.get("MachineStatus", "?") if status_info else "?"
                print(f"[POLL] {effective_printer}: status={machine_status}, printing={is_printing}, complete={is_complete}, progress={percent_complete}%")
                
                # Add to debug log
                add_poll_debug_log({
                    "type": "poll_check",
                    "request_id": req["id"][:8],
                    "print_name": req["print_name"],
                    "printer": req["printer"],
                    "machine_status": machine_status,
                    "is_printing": is_printing,
                    "is_complete": is_complete,
                    "percent_complete": percent_complete,
                    "should_complete": is_complete or ((not is_printing) and (percent_complete == 100)),
                    "message": f"Status: {machine_status}, Progress: {percent_complete}%"
                })

                rid = req["id"]

                # Calculate and update ETA
                if percent_complete and percent_complete > 0 and req["printing_started_at"]:
                    eta_seconds = printer_api.calculate_eta(percent_complete, req["printing_started_at"])
                    if eta_seconds is not None:
                        eta_iso = (datetime.now() + __import__('datetime').timedelta(seconds=eta_seconds)).isoformat()
                        conn = db()
                        conn.execute(
                            "UPDATE requests SET estimated_finish_time = ? WHERE id = ?",
                            (eta_iso, rid)
                        )
                        conn.commit()
                        conn.close()
                
                # Moonraker: write file-based slicer estimate to request for smart ETA
                if isinstance(printer_api, MoonrakerAPI) and is_printing:
                    try:
                        file_eta_total = await printer_api.get_file_eta_seconds()
                        if file_eta_total and file_eta_total > 0:
                            slicer_est_min = int(file_eta_total / 60)
                            conn = db()
                            # Only write if not already set (don't overwrite admin-entered values)
                            existing = conn.execute(
                                "SELECT slicer_estimate_minutes FROM requests WHERE id = ?", (rid,)
                            ).fetchone()
                            if existing and not existing["slicer_estimate_minutes"]:
                                conn.execute(
                                    "UPDATE requests SET slicer_estimate_minutes = ? WHERE id = ?",
                                    (slicer_est_min, rid)
                                )
                                conn.commit()
                                print(f"[MOONRAKER] Wrote slicer estimate {slicer_est_min}m to request {rid[:8]}")
                            conn.close()
                    except Exception as e:
                        print(f"[MOONRAKER] Error writing slicer estimate for {rid[:8]}: {e}")

                # Send PRINTING notification email with live printer data (if not already sent)
                # Note: sqlite3.Row doesn't have .get(), so we use bracket notation with fallback
                printing_email_sent = req["printing_email_sent"] if req["printing_email_sent"] else 0
                if not printing_email_sent and is_printing:
                    # Get extended info with layer count and file name
                    extended_info = await printer_api.get_extended_status()
                    current_layer = extended_info.get("current_layer") if extended_info else None
                    total_layers = extended_info.get("total_layers") if extended_info else None
                    current_file = extended_info.get("current_file") if extended_info else None
                    
                    # Only send email if we have layer info (indicates print is actually running)
                    if current_layer is not None and total_layers is not None and total_layers > 0:
                        print(f"[POLL] Sending PRINTING email for {rid[:8]} with layer {current_layer}/{total_layers}")
                        
                        # Calculate ETA based on layer progress
                        layer_progress = (current_layer / total_layers * 100) if total_layers > 0 else 0
                        eta_str = None
                        eta_completion = None
                        
                        if req["printing_started_at"] and layer_progress > 0:
                            eta_seconds = printer_api.calculate_eta(layer_progress, req["printing_started_at"])
                            if eta_seconds is not None and eta_seconds > 0:
                                hours = int(eta_seconds // 3600)
                                mins = int((eta_seconds % 3600) // 60)
                                if hours > 0:
                                    eta_str = f"~{hours}h {mins}m remaining"
                                else:
                                    eta_str = f"~{mins}m remaining"
                                from datetime import timedelta
                                eta_completion = (datetime.now() + timedelta(seconds=eta_seconds)).strftime("%I:%M %p")
                        
                        # Check notification settings
                        requester_email_on_status = get_bool_setting("requester_email_on_status", True)
                        should_notify_requester = get_bool_setting("notify_requester_printing", True)
                        
                        # Parse user notification preferences (user-level for consistency with manual status changes)
                        user_prefs = get_user_notification_prefs(req.get("requester_email", ""))
                        user_wants_email = user_prefs.get("status_email", True)
                        user_wants_push = user_prefs.get("status_push", True)
                        
                        # Define print_label before conditional blocks
                        print_label = req["print_name"] or f"Request {rid[:8]}"
                        
                        if requester_email_on_status and should_notify_requester and req["requester_email"] and user_wants_email:
                            subject = f"[{APP_TITLE}] Now Printing - {print_label}"
                            
                            # Build email rows with live printer data
                            email_rows = [
                                ("Print Name", print_label),
                                ("Request ID", rid[:8]),
                                ("Printer", _human_printer(req["printer"]) if req["printer"] else "—"),
                                ("Material", _human_material(req["material"]) if req["material"] else "—"),
                                ("Status", "PRINTING"),
                            ]
                            
                            # Add file info if available
                            if current_file:
                                # Clean up filename (remove path if present)
                                display_file = current_file.split("/")[-1].split("\\")[-1] if current_file else None
                                if display_file:
                                    email_rows.append(("File", display_file))
                            
                            # Add layer count
                            email_rows.append(("Progress", f"Layer {current_layer} of {total_layers}"))
                            
                            # Add ETA info
                            if eta_str:
                                email_rows.append(("Est. Time Remaining", eta_str))
                            if eta_completion:
                                email_rows.append(("Est. Completion", eta_completion))
                            
                            text = (
                                f"Your print has started!\n\n"
                                f"Print: {print_label}\n"
                                f"Request ID: {rid[:8]}\n"
                                f"Printer: {req['printer']}\n"
                                f"Progress: Layer {current_layer}/{total_layers}\n"
                                f"{f'ETA: {eta_str}' if eta_str else ''}\n"
                                f"\nView queue: {BASE_URL}/queue?mine={rid[:8]}\n"
                            )
                            
                            # Generate direct my-requests link
                            my_requests_token = get_or_create_my_requests_token(req["requester_email"])
                            my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
                            
                            # Check if user has an account (show account tip if not)
                            show_account_tip = not bool(req.get("account_id"))
                            tip_register_url = None
                            if show_account_tip:
                                from urllib.parse import quote
                                tip_register_url = f"{BASE_URL}/auth/register?email={quote(req['requester_email'])}"
                            
                            html = build_email_html(
                                title="Now Printing!",
                                subtitle=f"'{print_label}' is now printing!",
                                rows=email_rows,
                                cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                                cta_label="View in Queue",
                                header_color="#f59e0b",  # Orange for printing
                                secondary_cta_url=my_requests_url,
                                secondary_cta_label="All My Requests",
                                show_account_tip=show_account_tip,
                                tip_register_url=tip_register_url,
                            )
                            send_email([req["requester_email"]], subject, text, html)
                        
                        # Send push notification if user wants push
                        if user_wants_push:
                            send_push_notification(
                                email=req["requester_email"],
                                title="🖨️ Now Printing",
                                body=f"'{print_label}' has started printing",
                                url=f"/my/{rid}?token={req['access_token']}"
                            )
                        
                        # Also send admin notification if enabled
                        admin_email_on_status = get_bool_setting("admin_email_on_status", True)
                        should_notify_admin = get_bool_setting("notify_admin_printing", True)
                        admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
                        
                        if admin_email_on_status and should_notify_admin and admin_emails:
                            admin_subject = f"[{APP_TITLE}] {rid[:8]}: Now Printing"
                            admin_rows = [
                                ("Request ID", rid[:8]),
                                ("Requester", req["requester_name"] or "—"),
                                ("Email", req["requester_email"] or "—"),
                                ("Printer", _human_printer(req["printer"]) if req["printer"] else "—"),
                                ("Status", "PRINTING"),
                                ("Progress", f"Layer {current_layer} of {total_layers}"),
                            ]
                            if eta_str:
                                admin_rows.append(("Est. Time Remaining", eta_str))
                            
                            admin_text = (
                                f"Print has started.\n\n"
                                f"ID: {rid}\n"
                                f"Printer: {req['printer']}\n"
                                f"Progress: Layer {current_layer}/{total_layers}\n"
                                f"Admin: {BASE_URL}/admin/request/{rid}\n"
                            )
                            admin_html = build_email_html(
                                title="Print Started",
                                subtitle=f"Request {rid[:8]} is now printing",
                                rows=admin_rows,
                                cta_url=f"{BASE_URL}/admin/request/{rid}",
                                cta_label="Open in Admin",
                                header_color="#f59e0b",
                            )
                            send_email(admin_emails, admin_subject, admin_text, admin_html)
                        
                        # Mark email as sent
                        conn = db()
                        conn.execute(
                            "UPDATE requests SET printing_email_sent = 1 WHERE id = ?",
                            (rid,)
                        )
                        conn.commit()
                        conn.close()
                        print(f"[POLL] PRINTING email sent for {rid[:8]}")
                        add_poll_debug_log({
                            "type": "email_sent",
                            "request_id": rid[:8],
                            "message": "PRINTING notification email sent"
                        })

                # Auto-complete if printer reports complete OR (not printing AND at 100%)
                should_complete = is_complete or ((not is_printing) and (percent_complete == 100))

                if should_complete:
                    print(f"[PRINTER] {req['printer']} complete ({percent_complete}%), auto-updating {rid[:8]} to DONE")
                    add_poll_debug_log({
                        "type": "auto_complete",
                        "request_id": rid[:8],
                        "printer": req["printer"],
                        "percent_complete": percent_complete,
                        "is_complete": is_complete,
                        "is_printing": is_printing,
                        "message": f"Auto-completing: complete={is_complete}, printing={is_printing}, progress={percent_complete}%"
                    })

                    # Capture completion data before updating status
                    completion_snapshot = None
                    final_temp = None
                    extended_info = None
                    
                    # Try to capture a final snapshot
                    if get_bool_setting("enable_camera_snapshot", False):
                        try:
                            snapshot_data = await capture_camera_snapshot(effective_printer)
                            if snapshot_data:
                                completion_snapshot = base64.b64encode(snapshot_data).decode("utf-8")
                                print(f"[PRINTER] Captured completion snapshot for {rid[:8]} ({len(snapshot_data)} bytes)")
                        except Exception as e:
                            print(f"[PRINTER] Failed to capture completion snapshot: {e}")
                    
                    # Get final temperature
                    try:
                        temp_data = await printer_api.get_temperature()
                        if temp_data:
                            final_temp = f"{temp_data.get('Temperature', '?')}°C"
                            print(f"[PRINTER] Final temperature for {rid[:8]}: {final_temp}")
                    except Exception as e:
                        print(f"[PRINTER] Failed to get final temperature: {e}")
                    
                    # Get extended info for history
                    try:
                        extended_info = await printer_api.get_extended_status()
                    except Exception as e:
                        print(f"[PRINTER] Failed to get extended status: {e}")

                    # Auto-update status with completion data
                    conn = db()
                    req_row_raw = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
                    req_row = dict(req_row_raw) if req_row_raw else None  # Convert to dict for .get() support
                    
                    # Record to print history for learning ETAs
                    if req_row and req_row["printing_started_at"]:
                        try:
                            started_at = req_row["printing_started_at"]
                            completed_at = now_iso()
                            # Parse datetimes - strip timezone info for consistent comparison
                            started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00")).replace(tzinfo=None)
                            completed_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00")).replace(tzinfo=None)
                            duration_minutes = int((completed_dt - started_dt).total_seconds() / 60)
                            
                            conn.execute("""
                                INSERT INTO print_history 
                                (id, request_id, printer, material, print_name, started_at, completed_at, 
                                 duration_minutes, estimated_minutes, total_layers, file_name, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                str(uuid.uuid4()),
                                rid,
                                req_row["printer"] or "",
                                req_row["material"] or "",
                                req_row["print_name"] or "",
                                started_at,
                                completed_at,
                                duration_minutes,
                                req_row["slicer_estimate_minutes"] or req_row["print_time_minutes"],  # Use slicer estimate if available
                                extended_info.get("total_layers") if extended_info else None,
                                extended_info.get("current_file") if extended_info else None,
                                completed_at
                            ))
                            print(f"[PRINTER] Recorded print history: {duration_minutes} min actual, {req_row.get('slicer_estimate_minutes') or req_row.get('print_time_minutes') or '?'} min estimated for {req_row['printer']}")
                        except Exception as e:
                            print(f"[PRINTER] Failed to record print history: {e}")
                    
                    conn.execute(
                        "UPDATE requests SET status = ?, updated_at = ?, completion_snapshot = ?, final_temperature = ? WHERE id = ?",
                        ("DONE", now_iso(), completion_snapshot, final_temp, rid)
                    )
                    conn.execute(
                        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), rid, now_iso(), "PRINTING", "DONE", "Auto-completed by printer polling")
                    )
                    conn.commit()
                    conn.close()

                    # Send notification emails
                    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
                    admin_email_on_status = get_bool_setting("admin_email_on_status", True)
                    requester_email_on_status = get_bool_setting("requester_email_on_status", True)

                    # Parse user notification preferences (user-level for consistency with manual updates)
                    user_prefs = get_user_notification_prefs(req_row.get("requester_email", "") if req_row else "")
                    user_wants_email = user_prefs.get("status_email", True)
                    user_wants_push = user_prefs.get("status_push", True)

                    # Build email rows with completion data
                    email_rows = [("Request ID", rid[:8]), ("Status", "DONE")]
                    if final_temp:
                        email_rows.append(("Final Temp", final_temp))

                    print_label = req_row["print_name"] if req_row else f"Request {rid[:8]}"
                    report_url = f"{BASE_URL}/open/{rid}?token={req_row.get('access_token', '')}&report=1" if req_row else None

                    if requester_email_on_status and req_row and user_wants_email:
                        subject = f"[{APP_TITLE}] Print Complete! ({rid[:8]})"
                        text = f"Your print is done and ready for pickup!\n\nRequest ID: {rid[:8]}\n\nView queue: {BASE_URL}/queue?mine={rid[:8]}\n"
                        snapshot_to_send = completion_snapshot if get_bool_setting("enable_camera_snapshot", False) else None
                        
                        # Check if user has an account (show account tip if not)
                        show_account_tip = not bool(req_row.get("account_id"))
                        tip_register_url = None
                        if show_account_tip:
                            from urllib.parse import quote
                            tip_register_url = f"{BASE_URL}/auth/register?email={quote(req_row['requester_email'])}"
                        
                        html = build_email_html(
                            title="Print Complete!",
                            subtitle="Your request is ready for pickup.",
                            rows=email_rows,
                            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                            cta_label="View queue",
                            image_base64=snapshot_to_send,
                            secondary_cta_url=report_url,
                            secondary_cta_label="Report a Problem",
                            footer_note="If the photo looks off, click Report a Problem so we can pause the job.",
                            show_account_tip=show_account_tip,
                            tip_register_url=tip_register_url,
                        )
                        send_email([req_row["requester_email"]], subject, text, html, image_base64=snapshot_to_send)
                    
                    # Send push notification if user wants push
                    if user_wants_push and req_row and req_row.get("requester_email"):
                        print(f"[POLL] Sending push notification for completed print {rid[:8]}")
                        report_url = f"/open/{rid}?token={req_row.get('access_token', '')}&report=1"
                        send_push_notification(
                            email=req_row["requester_email"],
                            title="✅ Print Complete!",
                            body=f"'{print_label}' is ready for pickup!",
                            url=f"/my/{rid}?token={req_row.get('access_token', '')}",
                            data={"reportUrl": report_url},
                            actions=[{"action": "report-problem", "title": "Report a problem"}]
                        )

                    if admin_email_on_status and admin_emails and req_row:
                        admin_rows = [("Request ID", rid[:8]), ("Printer", req["printer"]), ("Status", "DONE")]
                        if final_temp:
                            admin_rows.append(("Final Temp", final_temp))
                        
                        admin_snapshot = completion_snapshot if get_bool_setting("enable_camera_snapshot", False) else None
                        subject = f"[{APP_TITLE}] Auto-completed: {rid[:8]}"
                        text = f"Print automatically marked DONE.\n\nID: {rid}\nPrinter: {req['printer']}\nAdmin: {BASE_URL}/admin/request/{rid}\n"
                        html = build_email_html(
                            title="Print Auto-Completed",
                            subtitle="Printer finished and is idle.",
                            rows=admin_rows,
                            cta_url=f"{BASE_URL}/admin/request/{rid}",
                            cta_label="Open in admin",
                            image_base64=admin_snapshot,
                        )
                        send_email(admin_emails, subject, text, html, image_base64=admin_snapshot)

            # ─────────────────────────── AUTO-MATCH PRINTING FILE TO REQUESTS ───────────────────────────
            # Check each printer for current file and try to match to QUEUED requests
            for printer_code in ["ADVENTURER_4", "AD5X"]:
                try:
                    # Skip if polling is paused for this printer
                    if is_polling_paused(printer_code):
                        continue
                    
                    printer_api = get_printer_api(printer_code)
                    if not printer_api:
                        continue
                    
                    is_printing = await printer_api.is_printing()
                    if not is_printing:
                        # Printer not printing, clear any suggestions
                        clear_print_match_suggestion(printer_code)
                        continue
                    
                    # Get current file being printed
                    extended = await printer_api.get_extended_status()
                    current_file = extended.get("current_file") if extended else None
                    
                    if not current_file:
                        continue
                    
                    # Check if there's already a PRINTING request for this printer
                    conn = db()
                    existing_printing = conn.execute(
                        "SELECT id FROM requests WHERE printer = ? AND status = 'PRINTING'",
                        (printer_code,)
                    ).fetchone()
                    conn.close()
                    
                    if existing_printing:
                        # Already have a request assigned to this printer, no need to match
                        clear_print_match_suggestion(printer_code)
                        continue
                    
                    # Find matching QUEUED/APPROVED requests
                    matches = find_matching_requests_for_file(current_file, printer_code)
                    
                    if not matches:
                        # No matches found
                        clear_print_match_suggestion(printer_code)
                        continue
                    
                    # Check if auto-match is enabled
                    auto_match_enabled = get_bool_setting("enable_auto_print_match", True)
                    
                    if len(matches) == 1 and auto_match_enabled:
                        # Exactly one match - auto-assign!
                        match = matches[0]
                        rid = match["id"]
                        old_status = match["status"]
                        
                        print(f"[AUTO-MATCH] Auto-matching request {rid[:8]} (status: {old_status}) to {printer_code} (file: {current_file})")
                        add_poll_debug_log({
                            "type": "auto_match",
                            "request_id": rid[:8],
                            "printer": printer_code,
                            "file": current_file,
                            "old_status": old_status,
                            "message": f"Auto-matched to {printer_code}"
                        })
                        
                        # For IN_PROGRESS requests, don't change status - just start the next build
                        # For QUEUED/APPROVED, update to PRINTING
                        if old_status != "IN_PROGRESS":
                            conn = db()
                            conn.execute(
                                "UPDATE requests SET status = 'PRINTING', printer = ?, printing_started_at = ?, updated_at = ? WHERE id = ?",
                                (printer_code, now_iso(), now_iso(), rid)
                            )
                            conn.execute(
                                "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
                                (str(uuid.uuid4()), rid, now_iso(), old_status, "PRINTING", f"Auto-matched to printer (file: {get_filename_base(current_file)})")
                            )
                            conn.commit()
                            conn.close()
                        
                        clear_print_match_suggestion(printer_code)
                        
                        # Immediately start the first READY/PENDING build so build-level notifications fire
                        try:
                            conn = db()
                            next_build = conn.execute("""
                                SELECT id, build_number FROM builds WHERE request_id = ? AND status IN ('READY', 'PENDING')
                                ORDER BY build_number LIMIT 1
                            """, (rid,)).fetchone()
                            conn.close()
                            
                            if next_build:
                                result = start_build(next_build["id"], printer_code, f"Auto-matched to printer (file: {get_filename_base(current_file)})")
                                if result.get("success"):
                                    print(f"[AUTO-MATCH] Started build {next_build['build_number']} for {rid[:8]} on {printer_code}")
                                else:
                                    print(f"[AUTO-MATCH] Failed to start build {next_build['id'][:8]} for {rid[:8]}: {result.get('error')}")
                            else:
                                print(f"[AUTO-MATCH] No READY build found for {rid[:8]} after auto-match")
                        except Exception as e:
                            print(f"[AUTO-MATCH] Failed to start build for {rid[:8]}: {e}")
                        
                    else:
                        # Multiple matches or auto-match disabled - store suggestion for admin UI
                        set_print_match_suggestion(printer_code, current_file, matches)
                        add_poll_debug_log({
                            "type": "match_suggestion",
                            "printer": printer_code,
                            "file": current_file,
                            "match_count": len(matches),
                            "message": f"Found {len(matches)} potential matches for {get_filename_base(current_file)}"
                        })
                        
                except Exception as e:
                    print(f"[AUTO-MATCH] Error checking {printer_code}: {e}")

            await asyncio.sleep(30)  # Poll every 30 seconds
        except Exception as e:
            import traceback
            error_traceback = traceback.format_exc()
            print(f"[PRINTER WORKER] Error: {e}")
            print(f"[PRINTER WORKER] Traceback: {error_traceback}")
            add_poll_debug_log({
                "type": "error",
                "error": str(e),
                "traceback": error_traceback,
                "message": f"Polling error: {e}"
            })
            await asyncio.sleep(30)


async def poll_builds_status_worker():
    """
    Background worker that polls builds in PRINTING status.
    Works at the build level for multi-build requests.
    Auto-updates build PRINTING -> COMPLETED when printer reports 100% complete.
    Then syncs the parent request status.
    
    In DEMO_MODE, this worker is disabled and fake printer data is used instead.
    """
    print("[BUILD-POLL] Background build polling started")
    
    # Skip real polling in demo mode
    if DEMO_MODE:
        print("[BUILD-POLL] Demo mode active - build polling disabled (using fake data)")
        while True:
            await asyncio.sleep(60)  # Just keep the task alive but do nothing
    
    while True:
        try:
            if not get_bool_setting("enable_printer_polling", True):
                await asyncio.sleep(30)
                continue
            
            conn = db()
            # Find all builds that are actively PRINTING
            printing_builds = conn.execute("""
                SELECT b.*, r.requester_email, r.requester_name, r.access_token, r.notification_prefs,
                       r.total_builds, r.completed_builds, r.print_name as request_print_name,
                       r.material as request_material, r.colors as request_colors, r.printer as request_printer
                FROM builds b
                JOIN requests r ON b.request_id = r.id
                WHERE b.status = 'PRINTING'
            """).fetchall()
            conn.close()
            
            if not printing_builds:
                await asyncio.sleep(30)
                continue
            
            print(f"[BUILD-POLL] Checking {len(printing_builds)} PRINTING builds...")
            
            for build in printing_builds:
                # Check if polling is paused for this printer (e.g., during print send)
                if is_polling_paused(build["printer"]):
                    print(f"[BUILD-POLL] Skipping {build['id'][:8]} - polling paused for {build['printer']}")
                    continue
                
                printer_api = get_printer_api(build["printer"])
                if not printer_api:
                    continue
                
                # Check printer status
                is_printing = await printer_api.is_printing()
                is_complete = await printer_api.is_complete()
                percent_complete = await printer_api.get_percent_complete()
                
                build_id = build["id"]
                request_id = build["request_id"]
                build_num = build["build_number"]
                total_builds = build["total_builds"] or 1
                
                # Auto-complete build if printer reports complete
                should_complete = is_complete or ((not is_printing) and (percent_complete == 100))
                
                # Moonraker: write file-based slicer estimate to build for smart ETA
                if isinstance(printer_api, MoonrakerAPI) and not should_complete and is_printing:
                    try:
                        file_eta_total = await printer_api.get_file_eta_seconds()
                        if file_eta_total and file_eta_total > 0:
                            slicer_est_min = int(file_eta_total / 60)
                            conn_mk = db()
                            existing_b = conn_mk.execute(
                                "SELECT slicer_estimate_minutes FROM builds WHERE id = ?", (build_id,)
                            ).fetchone()
                            if existing_b and not existing_b["slicer_estimate_minutes"]:
                                conn_mk.execute(
                                    "UPDATE builds SET slicer_estimate_minutes = ? WHERE id = ?",
                                    (slicer_est_min, build_id)
                                )
                                conn_mk.commit()
                                print(f"[MOONRAKER] Wrote slicer estimate {slicer_est_min}m to build {build_id[:8]}")
                            conn_mk.close()
                    except Exception as e:
                        print(f"[MOONRAKER] Error writing slicer estimate for build {build_id[:8]}: {e}")
                
                # Check for progress notifications BEFORE completion check
                # Only send progress notifications for builds that are still printing and not complete
                if not should_complete and percent_complete is not None and percent_complete > 0 and percent_complete < 100:
                    try:
                        # Build request dict for notification function
                        # Note: build is a sqlite3.Row, so use [] not .get()
                        request_dict = {
                            "id": request_id,
                            "requester_email": build["requester_email"],
                            "requester_name": build["requester_name"],
                            "access_token": build["access_token"],
                            "notification_prefs": build["notification_prefs"],
                            "total_builds": total_builds,
                            "print_name": build["request_print_name"],
                        }
                        build_dict = dict(build)
                        send_progress_notification(build_dict, request_dict, percent_complete)
                    except Exception as e:
                        print(f"[BUILD-POLL] Error sending progress notification: {e}")
                
                if should_complete:
                    print(f"[BUILD-POLL] Build {build_num}/{total_builds} complete for request {request_id[:8]}")
                    
                    # Capture completion data
                    extended_info = None
                    final_temp = None
                    
                    try:
                        extended_info = await printer_api.get_extended_status()
                        temp_data = await printer_api.get_temperature()
                        if temp_data:
                            final_temp = f"{temp_data.get('Temperature', '?')}°C"
                    except Exception as e:
                        print(f"[BUILD-POLL] Error getting completion data: {e}")
                    
                    # Update build with completion data
                    conn = db()
                    conn.execute("""
                        UPDATE builds SET 
                            status = 'COMPLETED',
                            completed_at = ?,
                            final_temperature = ?,
                            total_layers = ?,
                            file_name = ?,
                            updated_at = ?
                        WHERE id = ?
                    """, (
                        now_iso(),
                        final_temp,
                        extended_info.get("total_layers") if extended_info else None,
                        extended_info.get("current_file") if extended_info else None,
                        now_iso(),
                        build_id
                    ))
                    
                    # Record build status event
                    conn.execute(
                        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), build_id, now_iso(), "PRINTING", "COMPLETED", "Auto-completed by printer polling")
                    )
                    conn.commit()
                    conn.close()
                    
                    # Capture snapshot for this build
                    snapshot_b64 = None
                    if get_bool_setting("enable_camera_snapshot", False):
                        try:
                            snapshot_data = await capture_camera_snapshot(build["printer"])
                            if snapshot_data:
                                snapshot_b64 = base64.b64encode(snapshot_data).decode("utf-8")
                                conn = db()
                                conn.execute(
                                    "INSERT INTO build_snapshots (id, build_id, created_at, snapshot_data, snapshot_type) VALUES (?, ?, ?, ?, ?)",
                                    (str(uuid.uuid4()), build_id, now_iso(), snapshot_b64, "completion")
                                )
                                conn.commit()
                                conn.close()
                                print(f"[BUILD-POLL] Captured completion snapshot for build {build_id[:8]}")
                        except Exception as e:
                            print(f"[BUILD-POLL] Failed to capture snapshot: {e}")
                    
                    # Sync parent request status (skip DONE notification - we'll send it with snapshot below)
                    new_request_status = sync_request_status_from_builds(request_id, skip_done_notification=True)
                    
                    # Send build completion notification (or request completion if final build)
                    try:
                        conn = db()
                        request_for_notify = conn.execute(
                            "SELECT * FROM requests WHERE id = ?", (request_id,)
                        ).fetchone()
                        conn.close()
                        
                        if request_for_notify:
                            build_for_notify = dict(build)
                            build_for_notify["final_temperature"] = final_temp
                            send_build_complete_notification(
                                build_for_notify,
                                dict(request_for_notify),
                                snapshot_b64
                            )
                    except Exception as e:
                        print(f"[BUILD-POLL] Failed to send build notification: {e}")
                    
                    add_poll_debug_log({
                        "type": "build_complete",
                        "build_id": build_id[:8],
                        "request_id": request_id[:8],
                        "build_number": build_num,
                        "total_builds": total_builds,
                        "new_request_status": new_request_status,
                        "message": f"Build {build_num}/{total_builds} completed"
                    })
                    
                    # Auto-start next READY build if there is one
                    # This ensures continuous printing without admin intervention
                    if new_request_status == "IN_PROGRESS":
                        try:
                            conn_next = db()
                            next_build = conn_next.execute("""
                                SELECT id, build_number FROM builds 
                                WHERE request_id = ? AND status = 'READY' 
                                ORDER BY build_number LIMIT 1
                            """, (request_id,)).fetchone()
                            conn_next.close()
                            
                            if next_build:
                                # Use the same printer that just finished
                                completed_printer = build["printer"]
                                if completed_printer:
                                    result = start_build(
                                        next_build["id"], 
                                        completed_printer, 
                                        f"Auto-started after build {build_num} completed"
                                    )
                                    if result.get("success"):
                                        print(f"[BUILD-POLL] Auto-started build {next_build['build_number']} on {completed_printer} for request {request_id[:8]}")
                                        add_poll_debug_log({
                                            "type": "auto_start_next",
                                            "request_id": request_id[:8],
                                            "next_build_number": next_build["build_number"],
                                            "printer": completed_printer,
                                            "message": f"Auto-started build {next_build['build_number']} after {build_num} completed"
                                        })
                                    else:
                                        print(f"[BUILD-POLL] Failed to auto-start build {next_build['build_number']}: {result.get('error')}")
                        except Exception as e:
                            print(f"[BUILD-POLL] Error auto-starting next build: {e}")
                    
                    # Record to print history
                    if build["started_at"]:
                        try:
                            started_dt = datetime.fromisoformat(build["started_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                            completed_dt = datetime.utcnow()
                            duration_minutes = int((completed_dt - started_dt).total_seconds() / 60)
                            
                            # Use build values with fallback to request values
                            effective_printer = build["printer"] or build.get("request_printer") or ""
                            effective_material = build["material"] or build.get("request_material") or ""
                            effective_print_name = build["print_name"] or build.get("request_print_name") or f"Build {build_num}"
                            
                            conn = db()
                            conn.execute("""
                                INSERT INTO print_history 
                                (id, request_id, printer, material, print_name, started_at, completed_at, 
                                 duration_minutes, estimated_minutes, total_layers, file_name, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                str(uuid.uuid4()),
                                request_id,
                                effective_printer,
                                effective_material,
                                effective_print_name,
                                build["started_at"],
                                now_iso(),
                                duration_minutes,
                                build["slicer_estimate_minutes"] or build["print_time_minutes"],
                                extended_info.get("total_layers") if extended_info else None,
                                extended_info.get("current_file") if extended_info else None,
                                now_iso()
                            ))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            print(f"[BUILD-POLL] Failed to record print history: {e}")
            
            await asyncio.sleep(30)
        except Exception as e:
            import traceback
            print(f"[BUILD-POLL] Error: {e}")
            print(f"[BUILD-POLL] Traceback: {traceback.format_exc()}")
            await asyncio.sleep(30)


def start_printer_polling():
    """Start background printer polling in a thread (runs once at startup)"""
    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Run both legacy request-level polling and new build-level polling
        loop.run_until_complete(asyncio.gather(
            poll_printer_status_worker(),
            poll_builds_status_worker()
        ))

    thread = threading.Thread(target=run_async, daemon=True)
    thread.start()


# ------------------------
# Turnstile
# ------------------------

async def verify_turnstile(token: str, remoteip: Optional[str] = None) -> bool:
    if not TURNSTILE_SECRET_KEY:
        # LAN testing: allow submissions when Turnstile isn't configured.
        return True

    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remoteip:
        data["remoteip"] = remoteip

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, data=data)
            r.raise_for_status()
            payload = r.json()
            success = bool(payload.get("success"))
            if not success:
                # Log failed verification with error codes for debugging
                error_codes = payload.get("error-codes", [])
                logger.warning(f"Turnstile verification failed: {error_codes}, IP: {remoteip}")
            return success
    except httpx.TimeoutException:
        logger.error(f"Turnstile verification timed out for IP: {remoteip}")
        # On timeout, allow submission to avoid blocking users (fail open)
        return True
    except httpx.HTTPStatusError as e:
        logger.error(f"Turnstile HTTP error {e.response.status_code}: {e.response.text}")
        # On HTTP error, allow submission to avoid blocking users
        return True
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}", exc_info=True)
        # On unexpected error, allow submission to avoid blocking users
        return True


# ------------------------
# Email helpers
# ------------------------

def _human_printer(code: str) -> str:
    for c, label in PRINTERS:
        if c == code:
            return label
    return code


def _human_material(code: str) -> str:
    for c, label in MATERIALS:
        if c == code:
            return label
    return code


def build_email_html(title: str, subtitle: str, rows: List[Tuple[str, str]], cta_url: Optional[str] = None, cta_label: str = "Open", header_color: str = "#4f46e5", image_base64: Optional[str] = None, footer_note: Optional[str] = None, secondary_cta_url: Optional[str] = None, secondary_cta_label: str = "My Requests", show_account_tip: bool = False, tip_register_url: Optional[str] = None) -> str:
    """Build HTML email with optional header color customization and embedded image"""
    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    row_html = ""
    for k, v in rows:
        row_html += f"""
          <tr>
            <td style="padding:12px 0;color:#6b7280;font-size:13px;vertical-align:top;width:120px;font-weight:600;">{esc(k)}</td>
            <td style="padding:12px 0;color:#1f2937;font-size:14px;vertical-align:top;">{esc(v)}</td>
          </tr>
        """

    # Footer note (not escaped - allows HTML)
    note_html = ""
    if footer_note:
        note_html = f"""
          <div style="margin-top:16px;padding:12px;background:#f8fafc;border-radius:8px;border-left:4px solid #f59e0b;">
            <div style="color:#92400e;font-size:13px;">⚠️ {footer_note}</div>
          </div>
        """

    cta = ""
    if cta_url:
        secondary_btn = ""
        if secondary_cta_url:
            secondary_btn = f"""
              <a href="{esc(secondary_cta_url)}"
                 style="display:inline-block;background:#6b7280;color:#ffffff;text-decoration:none;
                        padding:12px 16px;border-radius:8px;font-weight:600;font-size:14px;border:0;margin-left:8px;">
                {esc(secondary_cta_label)}
              </a>
            """
        cta = f"""
          <div style="margin-top:20px;">
            <a href="{esc(cta_url)}"
               style="display:inline-block;background:{esc(header_color)};color:#ffffff;text-decoration:none;
                      padding:12px 16px;border-radius:8px;font-weight:600;font-size:14px;border:0;">
              {esc(cta_label)}
            </a>
            {secondary_btn}
          </div>
        """

    # Account creation tip for guest users
    account_tip_html = ""
    if show_account_tip and tip_register_url:
        account_tip_html = f"""
          <div style="margin-top:20px;padding:14px;background:#f0f9ff;border:1px solid #bfdbfe;border-radius:8px;">
            <div style="display:flex;align-items:start;gap:10px;">
              <div style="flex-shrink:0;color:#3b82f6;font-size:18px;">👤</div>
              <div style="flex:1;">
                <div style="color:#1e40af;font-size:13px;font-weight:600;margin-bottom:4px;">Track all your requests in one place</div>
                <div style="color:#1e3a8a;font-size:12px;margin-bottom:8px;">Create an account to manage all your print requests and save your preferences</div>
                <a href="{esc(tip_register_url)}" 
                   style="display:inline-block;background:#3b82f6;color:#ffffff;text-decoration:none;
                          padding:8px 14px;border-radius:6px;font-weight:600;font-size:12px;border:0;">
                  Create Account
                </a>
              </div>
            </div>
          </div>
        """

    # Embedded snapshot image - use CID reference for email attachment
    image_html = ""
    if image_base64:
        image_html = f"""
          <div style="margin-top:20px;border-radius:8px;overflow:hidden;">
            <div style="color:#6b7280;font-size:12px;margin-bottom:8px;font-weight:600;">📷 Completion Snapshot</div>
            <img src="cid:completion_snapshot" alt="Print completion snapshot" 
                 style="max-width:100%;height:auto;border-radius:8px;border:1px solid #e5e7eb;" />
          </div>
        """

    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f5f5f5;font-family:'Segoe UI', 'Helvetica Neue', Arial, sans-serif;">
    <div style="padding:24px;">
      <div style="max-width:600px;margin:0 auto;">
        <!-- Header -->
        <div style="background:{esc(header_color)};color:#ffffff;padding:24px 20px;border-radius:12px 12px 0 0;text-align:center;">
          <div style="font-size:24px;font-weight:800;margin-bottom:6px;">{esc(title)}</div>
          <div style="font-size:14px;opacity:0.9;">{esc(subtitle)}</div>
        </div>

        <!-- Main content -->
        <div style="background:#ffffff;border-radius:0 0 12px 12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
          <div style="padding:24px;">
            <table style="width:100%;border-collapse:collapse;">
              {row_html}
            </table>
            {note_html}
            {image_html}
            {cta}
            {account_tip_html}
          </div>
        </div>

        <!-- Footer -->
        <div style="color:#9ca3af;font-size:12px;margin-top:16px;text-align:center;">
          {esc(APP_TITLE)} • {esc(datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC"))}
          <br/><span style="color:#6b7280;font-size:11px;">💡 Install the app from your browser for instant push notifications</span>
        </div>
      </div>
    </div>
  </body>
</html>
"""


def log_notification_event(email: str, channel: str, subject: str, body: Optional[str] = None,
                           request_id: Optional[str] = None, build_id: Optional[str] = None,
                           endpoint: Optional[str] = None, status: str = "sent", error: Optional[str] = None):
    """Persist a notification event for debugging/delivery audits."""
    try:
        conn = db()
        conn.execute("""
            INSERT INTO notification_log (id, email, channel, subject, body, endpoint, request_id, build_id, status, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            email.lower() if email else "",
            channel,
            subject,
            body,
            endpoint,
            request_id,
            build_id,
            status,
            error,
            now_iso(),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[NOTIFY-LOG] Failed to log notification for {email}: {e}")


def get_notification_log(email: str, limit: int = 50) -> List[dict]:
    """Return recent notification events for an email."""
    conn = db()
    rows = conn.execute(
        """SELECT email, channel, subject, body, endpoint, request_id, build_id, status, error, created_at
               FROM notification_log
               WHERE LOWER(email) = LOWER(?)
               ORDER BY created_at DESC
               LIMIT ?""",
        (email, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _has_recent_push_alert(email: str, hours: int = 24) -> bool:
    """Check if we've already sent a push-failure alert email recently."""
    try:
        conn = db()
        rows = conn.execute(
            """SELECT created_at FROM notification_log
               WHERE LOWER(email) = LOWER(?) AND channel = 'email' AND subject LIKE '[Push Disabled]%'
               ORDER BY created_at DESC LIMIT 1""",
            (email,)
        ).fetchall()
        conn.close()
        if not rows:
            return False
        last = rows[0]["created_at"]
        from datetime import datetime, timedelta
        last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        return (datetime.utcnow() - last_dt) < timedelta(hours=hours)
    except Exception:
        return False


def get_or_create_my_requests_token(email: str) -> str:
    """
    Get existing valid token or create new one for 'My Requests' magic link.
    Returns the token string that can be used in /my-requests/view?token=XXX
    Token is valid for 30 days.
    """
    from datetime import timedelta
    email = email.strip().lower()
    conn = db()
    
    # Check for existing valid token
    existing = conn.execute(
        "SELECT token, expires_at FROM email_lookup_tokens WHERE email = ?",
        (email,)
    ).fetchone()
    
    if existing:
        try:
            expires = datetime.fromisoformat(existing["expires_at"].replace("Z", "+00:00"))
            if expires > datetime.now(expires.tzinfo):
                conn.close()
                return existing["token"]
        except:
            pass
    
    # Generate new token (30 days expiry for email links)
    token = secrets.token_urlsafe(32)
    created = now_iso()
    expiry = (datetime.utcnow() + timedelta(days=30)).isoformat(timespec="seconds") + "Z"
    
    # Clean up old tokens for this email
    conn.execute("DELETE FROM email_lookup_tokens WHERE email = ?", (email,))
    
    # Insert new token
    conn.execute(
        "INSERT INTO email_lookup_tokens (id, email, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), email, token, created, expiry)
    )
    conn.commit()
    conn.close()
    
    return token


def send_email(to_addrs: List[str], subject: str, text_body: str, html_body: Optional[str] = None, image_base64: Optional[str] = None):
    """
    Best-effort email. Never raises to the web request.
    image_base64: Optional base64-encoded JPEG to attach as inline image with CID "completion_snapshot"
    """
    to_addrs = [a.strip() for a in (to_addrs or []) if a and a.strip()]
    if not to_addrs:
        return
    if not (SMTP_HOST and SMTP_FROM):
        return  # email disabled / not configured

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg.set_content(text_body)

    if html_body:
        msg.add_alternative(html_body, subtype="html")
        
        # Attach inline image if provided
        if image_base64:
            try:
                import base64
                image_data = base64.b64decode(image_base64)
                # Get the HTML part and attach the image to it
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        # Add the image as a related part
                        msg.get_payload()[1].add_related(
                            image_data,
                            maintype="image",
                            subtype="jpeg",
                            cid="completion_snapshot"
                        )
                        break
            except Exception as e:
                print(f"[EMAIL] Failed to attach image: {e}")

    # Best-effort logging regardless of send outcome
    def _log_bulk(status: str, error: Optional[str] = None):
        for addr in to_addrs:
            log_notification_event(email=addr, channel="email", subject=subject, body=text_body[:500], status=status, error=error)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        _log_bulk("sent")
    except Exception as e:
        print(f"[EMAIL] Failed to send '{subject}' to {to_addrs}: {e}")
        _log_bulk("failed", str(e))
        return


# ─────────────────────────── PUSH NOTIFICATIONS ───────────────────────────
def send_push_notification(email: str, title: str, body: str, url: str = None, image_url: str = None, tag: str = None, data: dict = None, actions: Optional[List[Dict[str, str]]] = None) -> dict:
    """
    Send push notification to all subscriptions for a user (by email).
    Returns a dict with status and details for debugging.
    
    Args:
        email: User's email address
        title: Notification title
        body: Notification body text
        url: Click-through URL (default: /my-requests/view)
        image_url: Optional image URL to display in notification (for progress updates)
        tag: Optional tag for notification grouping (allows replacing existing notifications)
        data: Optional additional data to include in the notification payload
        actions: Optional list of notification actions (for quick responses)
    """
    result = {"email": email, "sent": 0, "failed": 0, "errors": []}
    
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        msg = "VAPID keys are not configured"
        print(f"[PUSH] ERROR: {msg}")
        result["errors"].append(msg)
        return result
        
    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        msg = "pywebpush not installed"
        print(f"[PUSH] ERROR: {msg}")
        result["errors"].append(msg)
        return result
        
    conn = db()
    subs = conn.execute(
        "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE LOWER(email) = LOWER(?)",
        (email,)
    ).fetchall()
    conn.close()
    
    result["subscriptions_found"] = len(subs)
    
    if not subs:
        msg = f"No push subscriptions found for email: {email}"
        print(f"[PUSH] {msg}")
        result["errors"].append(msg)
        log_notification_event(email=email, channel="push", subject=title, body=body[:500], status="failed", error=msg)
        return result
        
    print(f"[PUSH] Found {len(subs)} subscription(s) for {email}")
    
    # Normalize URL to absolute for better PWA handling (iOS/Android)
    resolved_url = url or "/my-requests/view"
    if resolved_url.startswith("/"):
        resolved_url = f"{BASE_URL}{resolved_url}"

    # Build notification payload with optional image support
    payload_data = {
        "title": title,
        "body": body,
        "url": resolved_url,
        "icon": "/static/icons/icon-192.png",
    }
    
    # Add optional image URL for rich notifications (progress updates, etc.)
    if image_url:
        payload_data["image"] = image_url
    
    # Add tag for notification grouping (allows replacing instead of stacking)
    if tag:
        payload_data["tag"] = tag
    
    # Add additional custom data
    if data:
        payload_data["data"] = data
    
    # Add actions (e.g., report a problem)
    if actions:
        payload_data["actions"] = actions
    
    payload = json.dumps(payload_data)
    
    for sub in subs:
        endpoint = sub["endpoint"]
        subscription_info = {
            "endpoint": endpoint,
            "keys": {
                "p256dh": sub["p256dh"],
                "auth": sub["auth"],
            }
        }
        
        # Build VAPID claims per-endpoint for maximum compatibility
        # Apple requires: sub (mailto:), aud (endpoint origin), exp (< 24h)
        from urllib.parse import urlparse
        import time
        
        parsed = urlparse(endpoint)
        aud = f"{parsed.scheme}://{parsed.netloc}"
        
        vapid_email = VAPID_CLAIMS_EMAIL
        if not vapid_email.startswith("mailto:"):
            vapid_email = f"mailto:{vapid_email}"
        
        # Use 12-hour exp to be safe with clock skew (Apple requires < 24h)
        exp_12h = int(time.time()) + (12 * 3600)
        
        vapid_claims = {
            "sub": vapid_email,
            "aud": aud,  # Explicitly set aud for the endpoint
            "exp": exp_12h,  # 12 hours to avoid clock skew issues
        }
        
        try:
            is_apple = 'apple.com' in endpoint
            print(f"[PUSH] Sending to {'Apple' if is_apple else 'other'} endpoint: {endpoint[:60]}...")
            print(f"[PUSH]   aud={aud}, exp_hours={12}, sub={vapid_email}")
            
            webpush(
                subscription_info=subscription_info,
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=vapid_claims,
                ttl=43200,  # 12 hours - matches our exp
            )
            print(f"[PUSH] OK: Sent notification for {email}")
            result["sent"] += 1
            log_notification_event(
                email=email,
                channel="push",
                subject=title,
                body=body[:500],
                status="sent",
                endpoint=endpoint
            )
        except WebPushException as e:
            error_msg = f"WebPush error: {e}"
            # Include response body if available for debugging
            if e.response:
                try:
                    error_msg += f" | Status: {e.response.status_code} | Body: {e.response.text[:200]}"
                except:
                    pass
            print(f"[PUSH] ✗ Failed: {error_msg}")
            result["failed"] += 1
            result["errors"].append(error_msg)
            log_notification_event(
                email=email,
                channel="push",
                subject=title,
                body=body[:500],
                status="failed",
                error=error_msg,
                endpoint=endpoint
            )
            
            # Remove invalid subscriptions (410 Gone or 404)
            if e.response and e.response.status_code in [404, 410]:
                conn = db()
                conn.execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (sub["endpoint"],))
                conn.commit()
                conn.close()
                print(f"[PUSH] Removed expired subscription (status {e.response.status_code})")
        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
            print(f"[PUSH] ✗ Error: {error_msg}")
            result["failed"] += 1
            result["errors"].append(error_msg)
    
    # Deduplicate repeated errors to reduce log spam (common when all subs expired)
    if result["errors"]:
        unique_errors = []
        seen = set()
        for err in result["errors"]:
            if err not in seen:
                unique_errors.append(err)
                seen.add(err)
        result["errors"] = unique_errors

    # If all pushes failed for this email, send a one-time alert email about disabled push
    status = "sent" if result["sent"] > 0 else "failed"
    if status == "failed" and email and not _has_recent_push_alert(email):
        alert_subject = "[Push Disabled] Action needed to restore notifications"
        alert_text = (
            "We tried to send push notifications to your devices, but all subscriptions appear to be expired or blocked.\n\n"
            "To restore push notifications:\n"
            "1) Open the Printellect app/site on your device.\n"
            "2) Go to My Account > Notification Settings.\n"
            "3) Toggle Push Notifications off, then back on to re-register.\n\n"
            "If you no longer want push, you can ignore this email."
        )
        alert_html = build_email_html(
            title="Push notifications need attention",
            subtitle="We couldn't reach any of your devices.",
            rows=[
                ("What happened", "All push subscriptions for your account failed."),
                ("How to fix", "Open the app and toggle Push Notifications off/on in My Account."),
            ],
            cta_url=f"{BASE_URL}/user/profile",
            cta_label="Open My Account",
            header_color="#f59e0b",
            footer_note="This alert is sent only once per day while push remains disabled.",
        )
        send_email([email], alert_subject, alert_text, alert_html)

    return result


def send_broadcast_notification(title: str, body: str, url: str = None, 
                                broadcast_type: str = "custom", sent_by: str = None,
                                metadata: dict = None, also_email: bool = False,
                                target_emails: list = None) -> dict:
    """
    Send a push notification to ALL or specific subscribed users.
    Used for system announcements, app updates, etc.
    
    Args:
        title: Notification title
        body: Notification body text
        url: Click-through URL (default: /changelog for updates, / for others)
        broadcast_type: Type of broadcast ('custom', 'app_update', 'announcement', 'maintenance')
        sent_by: Admin email or identifier who sent this
        metadata: Optional dict of additional metadata (e.g., version number)
        also_email: If True, also send email to subscribed users
        target_emails: List of specific emails to send to (None = all subscribers)
    
    Returns:
        dict with total_sent, total_failed, and details
    """
    result = {
        "broadcast_type": broadcast_type,
        "total_sent": 0,
        "total_failed": 0,
        "unique_emails": 0,
        "emails_sent": 0,
        "errors": []
    }
    
    # Get all unique emails with push subscriptions
    conn = db()
    all_emails = conn.execute(
        "SELECT DISTINCT email FROM push_subscriptions"
    ).fetchall()
    conn.close()
    
    # Filter to target emails if specified
    if target_emails:
        target_set = set(e.lower() for e in target_emails)
        emails = [row for row in all_emails if row["email"].lower() in target_set]
        print(f"[BROADCAST] Targeting {len(target_emails)} specific emails, {len(emails)} are subscribed")
    else:
        emails = all_emails
    
    result["unique_emails"] = len(emails)
    
    # Determine default URL based on broadcast type
    if not url:
        if broadcast_type == "app_update":
            url = "/changelog"
        else:
            url = "/"
    
    full_url = f"{BASE_URL}{url}" if url.startswith("/") else url
    
    # Send PUSH notifications (if VAPID is configured)
    if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
        if emails:
            print(f"[BROADCAST] Sending '{broadcast_type}' push to {len(emails)} subscribers")
            for row in emails:
                email = row["email"]
                push_result = send_push_notification(
                    email=email,
                    title=title,
                    body=body,
                    url=url,
                    tag=f"broadcast-{broadcast_type}"  # Group by type, replaces previous same-type broadcasts
                )
                result["total_sent"] += push_result.get("sent", 0)
                result["total_failed"] += push_result.get("failed", 0)
                if push_result.get("errors"):
                    result["errors"].extend(push_result["errors"])
        else:
            result["errors"].append("No push subscriptions found")
    else:
        result["errors"].append("VAPID keys not configured - push skipped")
    
    # Send EMAIL if requested
    if also_email and emails:
        print(f"[BROADCAST] Sending '{broadcast_type}' email to {len(emails)} subscribers")
        email_list = [row["email"] for row in emails]
        
        # Build broadcast email
        subject = f"[{APP_TITLE}] {title}"
        text_body = f"{body}\n\nView: {full_url}"
        html_body = build_email_html(
            title=title,
            subtitle=body,
            rows=[],
            cta_url=full_url,
            cta_label="View Details",
            header_color="#6366f1",  # Indigo for broadcasts
        )
        
        try:
            send_email(email_list, subject, text_body, html_body)
            result["emails_sent"] = len(email_list)
            print(f"[BROADCAST] Sent email to {len(email_list)} recipients")
        except Exception as e:
            result["errors"].append(f"Email error: {str(e)}")
            print(f"[BROADCAST] Email error: {e}")
    
    # Record the broadcast in history (include email count in metadata)
    broadcast_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    # Merge emails_sent into metadata
    full_metadata = metadata.copy() if metadata else {}
    if result["emails_sent"] > 0:
        full_metadata["emails_sent"] = result["emails_sent"]
    metadata_json = json.dumps(full_metadata) if full_metadata else None
    
    conn = db()
    conn.execute("""
        INSERT INTO broadcast_notifications 
        (id, title, body, url, broadcast_type, sent_at, sent_by, total_sent, total_failed, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (broadcast_id, title, body, url, broadcast_type, now, sent_by, 
          result["total_sent"], result["total_failed"], metadata_json))
    conn.commit()
    conn.close()
    
    result["broadcast_id"] = broadcast_id
    email_info = f", {result['emails_sent']} emails" if result['emails_sent'] > 0 else ""
    print(f"[BROADCAST] Completed: {result['total_sent']} push sent, {result['total_failed']} failed{email_info}")
    
    return result


def send_push_notification_to_admins(title: str, body: str, url: str = None, tag: str = None,
                                     image_url: Optional[str] = None, data: Optional[dict] = None,
                                     actions: Optional[List[Dict[str, str]]] = None) -> dict:
    """
    Send push notification to all admins who have push subscriptions.
    Uses the admin_notify_emails setting to determine which emails are admins.
    
    Args:
        title: Notification title
        body: Notification body text  
        url: Click-through URL (default: /admin)
        tag: Optional tag for notification grouping
    
    Returns:
        dict with sent/failed counts and any errors
    """
    result = {"total_sent": 0, "total_failed": 0, "admin_count": 0, "errors": []}
    
    # Get list of admin emails
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    
    if not admin_emails:
        print("[ADMIN-PUSH] No admin emails configured")
        result["errors"].append("No admin emails configured in settings")
        return result
    
    result["admin_count"] = len(admin_emails)
    print(f"[ADMIN-PUSH] Sending to {len(admin_emails)} admin(s): {title}")
    
    # Send push to each admin
    for admin_email in admin_emails:
        push_result = send_push_notification(
            email=admin_email,
            title=title,
            body=body,
            url=url or "/admin",
            tag=tag,
            image_url=image_url,
            data=data,
            actions=actions
        )
        result["total_sent"] += push_result.get("sent", 0)
        result["total_failed"] += push_result.get("failed", 0)
        if push_result.get("errors"):
            result["errors"].extend(push_result["errors"])
    
    print(f"[ADMIN-PUSH] Completed: {result['total_sent']} sent, {result['total_failed']} failed")
    return result


def get_broadcast_history(limit: int = 20) -> List[Dict]:
    """Get recent broadcast notification history."""
    conn = db()
    rows = conn.execute("""
        SELECT * FROM broadcast_notifications 
        ORDER BY sent_at DESC 
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def safe_ext(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


ALLOWED_EXTENSIONS = {'.stl', '.obj', '.3mf', '.gcode', '.step', '.stp', '.fpp', '.zip'}


def first_name_only(name: str) -> str:
    parts = (name or "").strip().split()
    return parts[0] if parts else ""


def get_printer_suggestions() -> Dict[str, Any]:
    """Get printer suggestion data based on current queue"""
    conn = db()
    
    # Count active jobs per printer
    printer_queue = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        count = conn.execute(
            "SELECT COUNT(*) as c FROM requests WHERE printer = ? AND status IN (?, ?, ?)",
            (printer_code, "APPROVED", "PRINTING", "NEW")
        ).fetchone()["c"]
        printer_queue[printer_code] = count
    
    # Count ANY printer requests (these could go to either)
    any_count = conn.execute(
        "SELECT COUNT(*) as c FROM requests WHERE printer = ? AND status IN (?, ?, ?)",
        ("ANY", "APPROVED", "PRINTING", "NEW")
    ).fetchone()["c"]
    
    conn.close()
    
    # Determine suggestion
    adv4_total = printer_queue["ADVENTURER_4"] + any_count
    ad5x_total = printer_queue["AD5X"] + any_count
    
    suggested = None
    suggestion_reason = None
    
    if adv4_total == 0 and ad5x_total == 0:
        suggestion_reason = "Both printers available!"
    elif adv4_total < ad5x_total:
        suggested = "ADVENTURER_4"
        suggestion_reason = f"Adventurer 4 has shorter queue ({adv4_total} vs {ad5x_total})"
    elif ad5x_total < adv4_total:
        suggested = "AD5X"
        suggestion_reason = f"AD5X has shorter queue ({ad5x_total} vs {adv4_total})"
    else:
        suggestion_reason = f"Both printers have similar queue ({adv4_total} jobs)"
    
    return {
        "suggested": suggested,
        "reason": suggestion_reason,
        "adventurer_4_queue": adv4_total,
        "ad5x_queue": ad5x_total,
        "total_queue": adv4_total + ad5x_total,
    }


def calculate_rush_price(queue_size: int, requester_name: str = "") -> Dict[str, Any]:
    """Calculate dynamic rush price based on queue and... special customers"""
    base_fee = int(get_setting("rush_fee_amount", "5"))
    
    # Dynamic pricing based on queue size
    # 0-2 jobs: base price
    # 3-5 jobs: base + $2
    # 6-10 jobs: base + $5
    # 10+ jobs: base + $10
    if queue_size <= 2:
        queue_multiplier = 0
        queue_reason = "Short queue"
    elif queue_size <= 5:
        queue_multiplier = 2
        queue_reason = "Moderate queue"
    elif queue_size <= 10:
        queue_multiplier = 5
        queue_reason = "Busy queue"
    else:
        queue_multiplier = 10
        queue_reason = "Very busy queue"
    
    calculated_price = base_fee + queue_multiplier
    
    # Special pricing for... certain individuals
    name_lower = (requester_name or "").lower().strip()
    brandon_multiplier = 1
    if "brandon" in name_lower:
        brandon_multiplier = 5
        calculated_price = calculated_price * brandon_multiplier
    
    return {
        "base_fee": base_fee,
        "queue_addon": queue_multiplier,
        "queue_reason": queue_reason,
        "multiplier": brandon_multiplier,
        "final_price": calculated_price,
        "is_special": brandon_multiplier > 1,
    }


def get_request_templates() -> List[Dict[str, Any]]:
    """Get all saved request templates"""
    conn = db()
    rows = conn.execute(
        "SELECT * FROM request_templates ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def render_form(request: Request, error: Optional[str], form: Dict[str, Any], user=None):
    # Get printer suggestions
    printer_suggestions = get_printer_suggestions()
    
    # Calculate dynamic rush pricing
    queue_size = printer_suggestions.get("total_queue", 0)
    requester_name = form.get("requester_name", "")
    rush_pricing = calculate_rush_price(queue_size, requester_name)
    
    # Rush payment settings
    rush_settings = {
        "enabled": get_bool_setting("enable_rush_option", True),
        "fee": rush_pricing["final_price"],  # Dynamic price!
        "base_fee": rush_pricing["base_fee"],
        "queue_addon": rush_pricing["queue_addon"],
        "queue_reason": rush_pricing["queue_reason"],
        "venmo_handle": get_setting("venmo_handle", "@YourVenmoHandle"),
    }
    
    # Get saved templates
    saved_templates = get_request_templates()
    
    # If user is logged in, pre-fill form with their preferences (unless form already has values)
    if user and not form.get("requester_name"):
        form = {
            "requester_name": user.display_name,
            "requester_email": user.email,
            "printer": user.preferred_printer or "",
            "material": user.preferred_material or "",
            "colors": user.preferred_colors or "",
            **form  # Allow explicit form values to override
        }
    
    # Check if user accounts feature is enabled
    user_accounts_enabled = is_feature_enabled("user_accounts")
    shipping_enabled = get_bool_setting("shipping_enabled", False)
    shipping_default_country = get_setting("shipping_default_country", "US")
    
    # Get queue stats for landing page
    queue_stats = None
    fun_stats = None
    recent_prints = []
    try:
        conn = get_conn()
        # Count printing
        printing = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE status IN ('PRINTING', 'IN_PROGRESS')"
        ).fetchone()[0]
        # Count queued (approved/pending)
        queued = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE status IN ('PENDING', 'APPROVED', 'NEEDS_INFO')"
        ).fetchone()[0]
        queue_stats = {
            "printing": printing,
            "queued": queued,
            "avg_wait": "1-2 days" if queued < 5 else "2-4 days" if queued < 10 else "4-7 days"
        }
        
        # Fun stats for landing page
        total_completed = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE status IN ('DONE', 'PICKED_UP')"
        ).fetchone()[0]
        # Estimate print hours (rough: 3 hours average per print)
        est_hours = total_completed * 3
        fun_stats = {
            "total_prints": total_completed,
            "est_hours": est_hours,
            "est_meters": round(total_completed * 15, 0),  # ~15m filament per print avg
        }
        
        # Recent completed prints (last 5)
        recent_rows = conn.execute("""
            SELECT print_name, colors, updated_at 
            FROM requests 
            WHERE status IN ('DONE', 'PICKED_UP') AND print_name IS NOT NULL
            ORDER BY updated_at DESC 
            LIMIT 5
        """).fetchall()
        recent_prints = [{"name": r[0], "colors": r[1], "date": r[2]} for r in recent_rows]
    except:
        pass
    
    # Get live printer status for landing page - use demo data or cached status
    printer_status = {}
    try:
        if DEMO_MODE:
            printer_status = get_demo_all_printers_status()
        else:
            # Use cached printer status (non-blocking)
            for printer_code in ["ADVENTURER_4", "AD5X"]:
                cached = get_cached_printer_status(printer_code)
                if cached:
                    printer_status[printer_code] = cached
                else:
                    printer_status[printer_code] = {
                        "status": None, "is_offline": True, "is_printing": False, "progress": None
                    }
    except:
        pass
    
    return templates.TemplateResponse("request_form_new.html", {
        "request": request,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "error": error,
        "form": form,
        "version": APP_VERSION,
        "printer_suggestions": printer_suggestions,
        "rush_settings": rush_settings,
        "saved_templates": saved_templates,
        "user": user,
        "user_accounts_enabled": user_accounts_enabled,
        "shipping_enabled": shipping_enabled,
        "shipping_default_country": shipping_default_country,
        "queue_stats": queue_stats,
        "printer_status": printer_status,
        "fun_stats": fun_stats,
        "recent_prints": recent_prints,
    }, status_code=400 if error else 200)


# Mount additional routers
from app.public import router as public_router
from app.my_requests import router as my_requests_router
from app.admin import router as admin_router
from app.admin_accounts import router as admin_accounts_router
from app.api_push import router as api_push_router
from app.api_builds import router as api_builds_router
from app.trips import router as trips_router
from app.printellect import router as printellect_router

app.include_router(public_router)
app.include_router(my_requests_router)
app.include_router(admin_router)
app.include_router(admin_accounts_router)
app.include_router(api_push_router)
app.include_router(api_builds_router)
app.include_router(trips_router)
app.include_router(printellect_router)
