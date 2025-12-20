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
APP_VERSION = "0.10.0"
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
# 0.10.0 - [FEATURE] User auth APIs, session stability fixes, notification settings improvements
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
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5  # 10MB per file, keep 5 backups
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
        if message and message.strip():
            self.logger.log(self.level, message.rstrip())
    
    def flush(self):
        pass

# Redirect stdout/stderr to capture print() statements
import sys
sys.stdout = PrintToLogger(logging.getLogger("printellect.stdout"), logging.INFO)
sys.stderr = PrintToLogger(logging.getLogger("printellect.stderr"), logging.ERROR)

logger.info(f"Logging initialized at level {LOG_LEVEL} - capturing all output")

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

# --- Serve /sw.js from site root for PWA ---
from fastapi.responses import FileResponse
@app.get('/sw.js')
async def service_worker():
    # Serve sw.js from app/static/sw.js at the root scope
    import os
    sw_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static', 'sw.js'))
    if not os.path.exists(sw_path):
        from fastapi import HTTPException
        print(f"[SW] ERROR: Service worker file not found at: {sw_path}")
        raise HTTPException(status_code=404, detail='Service worker not found')
    return FileResponse(
        sw_path, 
        media_type='application/javascript',
        headers={
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Service-Worker-Allowed': '/'
        }
    )

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
        
        conn = sqlite3.connect(DB_PATH)
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
                    "healthy": machine_status in ["READY", "PRINTING", "BUILDING", "BUILDING_FROM_SD", "BUILD_COMPLETE", "BUILD_COMPLETE_FROM_SD"],
                    "is_printing": machine_status in ["BUILDING", "BUILDING_FROM_SD"],
                    "current_file": extended.get("current_file") if extended else None,
                    "current_layer": extended.get("current_layer") if extended else None,
                    "total_layers": extended.get("total_layers") if extended else None,
                    "camera_url": camera_url,
                    "is_cached": False,
                    "last_seen": now_iso(),
                }
                
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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

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
      status TEXT NOT NULL
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

    # Multi-build support columns
    if "total_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN total_builds INTEGER DEFAULT 1")
    if "completed_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN completed_builds INTEGER DEFAULT 0")
    if "failed_builds" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN failed_builds INTEGER DEFAULT 0")
    if "active_build_id" not in cols:
        cur.execute("ALTER TABLE requests ADD COLUMN active_build_id TEXT")

    # Add build_id to files table to associate files with specific builds
    if files_cols and "build_id" not in files_cols:
        cur.execute("ALTER TABLE files ADD COLUMN build_id TEXT")

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
    Otherwise, creates one build per file.
    Auto-assigns files to builds 1:1 when file count matches build count.
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
    files = conn.execute(
        "SELECT id, original_filename FROM files WHERE request_id = ? ORDER BY created_at ASC",
        (request_id,)
    ).fetchall()
    
    # Get file count if build_count not specified
    if build_count is None:
        build_count = max(1, len(files))
    
    now = now_iso()
    build_ids = []
    
    # Create builds
    for i in range(build_count):
        build_id = str(uuid.uuid4())
        # Use file name as print_name if we have a matching file
        print_name = None
        if i < len(files):
            # Use filename without extension as print name
            original = files[i]["original_filename"]
            print_name = os.path.splitext(original)[0] if original else None
        
        conn.execute("""
            INSERT INTO builds (id, request_id, build_number, status, print_name, created_at, updated_at)
            VALUES (?, ?, ?, 'PENDING', ?, ?, ?)
        """, (build_id, request_id, i + 1, print_name, now, now))
        build_ids.append(build_id)
    
    # Auto-assign files to builds (1:1 mapping)
    for i, file in enumerate(files):
        if i < len(build_ids):
            conn.execute(
                "UPDATE files SET build_id = ? WHERE id = ?",
                (build_ids[i], file["id"])
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

# Mount auth routes
from app.routes_auth import router as auth_router
app.include_router(auth_router)


def require_admin(request: Request):
    pw = request.headers.get("X-Admin-Password") or request.cookies.get("admin_pw") or ""
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD is not set")
    if pw != ADMIN_PASSWORD:
        # For browser requests (HTML pages), redirect to login with next param
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
    return True


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
    # Enable progress notifications (push primarily, email at 50% only)
    "enable_progress_notifications": "1",
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
    Find QUEUED or APPROVED requests that match the filename being printed.
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
    
    # Get all QUEUED/APPROVED requests with their files
    requests = conn.execute("""
        SELECT r.id, r.print_name, r.printer, r.priority, r.created_at, r.requester_name,
               r.status, r.material
        FROM requests r
        WHERE r.status IN ('QUEUED', 'APPROVED')
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


def get_smart_eta(printer: str = None, material: str = None,
                  current_percent: int = None, printing_started_at: str = None,
                  current_layer: int = None, total_layers: int = None) -> Optional[datetime]:
    """
    Calculate a smart ETA based on:
    1. Layer progress + elapsed time (most accurate - layers are more linear than bytes)
    2. Percent progress + elapsed time (good fallback)
    3. Historical average for this printer/material combo
    
    Returns a datetime of estimated completion, or None if can't estimate.
    """
    now = datetime.utcnow()
    
    # Parse start time if available
    started_dt = None
    elapsed = 0
    if printing_started_at:
        try:
            started_dt = datetime.fromisoformat(printing_started_at.replace("Z", "+00:00"))
            if started_dt.tzinfo:
                started_dt = started_dt.replace(tzinfo=None)
            elapsed = (now - started_dt).total_seconds()
        except Exception:
            pass
    
    # Method 1: Layer-based calculation (most accurate for FDM printing)
    # Layers are more linear than byte progress since each layer takes similar time
    if current_layer and total_layers and total_layers > 0 and elapsed >= 120:
        try:
            layer_percent = (current_layer / total_layers) * 100
            if layer_percent > 0 and layer_percent < 100:
                # Calculate based on layer progress
                total_expected = elapsed / (layer_percent / 100)
                remaining_seconds = total_expected - elapsed
                
                # Add small buffer (3% - layers are more accurate so less buffer needed)
                remaining_seconds *= 1.03
                
                if 0 < remaining_seconds < 172800:  # < 48 hours
                    eta = now + __import__('datetime').timedelta(seconds=remaining_seconds)
                    return eta
        except Exception as e:
            print(f"[ETA] Error calculating from layers: {e}")
    
    # Method 2: Percent-based calculation (fallback if no layer info)
    if current_percent and current_percent > 0 and elapsed >= 120:
        try:
            if current_percent >= 100:
                return now
            
            # Calculate total expected time based on current progress
            total_expected = elapsed / (current_percent / 100)
            remaining_seconds = total_expected - elapsed
            
            # Add a buffer (5% - byte progress less reliable than layers)
            remaining_seconds *= 1.05
            
            if 0 < remaining_seconds < 172800:
                eta = now + __import__('datetime').timedelta(seconds=remaining_seconds)
                return eta
        except Exception as e:
            print(f"[ETA] Error calculating from progress: {e}")
    
    # Method 2: Use historical average from print_history
    try:
        conn = db()
        
        # Try to find average for this specific printer
        if printer:
            rows = conn.execute("""
                SELECT AVG(duration_minutes) as avg_duration, COUNT(*) as count
                FROM print_history 
                WHERE printer = ?
            """, (printer,)).fetchone()
            
            if rows and rows["count"] and rows["count"] >= 2 and rows["avg_duration"]:
                avg_minutes = int(rows["avg_duration"])
                conn.close()
                return datetime.now() + __import__('datetime').timedelta(minutes=avg_minutes)
        
        # Fall back to global average
        rows = conn.execute("""
            SELECT AVG(duration_minutes) as avg_duration, COUNT(*) as count
            FROM print_history
        """).fetchone()
        conn.close()
        
        if rows and rows["count"] and rows["count"] >= 2 and rows["avg_duration"]:
            avg_minutes = int(rows["avg_duration"])
            return datetime.now() + __import__('datetime').timedelta(minutes=avg_minutes)
            
    except Exception as e:
        print(f"[ETA] Error calculating from history: {e}")
    
    return None


def format_eta_display(eta_dt: Optional[datetime]) -> str:
    """Format an ETA datetime for display in the UI"""
    if not eta_dt:
        return "Unknown"
    
    now = datetime.now()
    diff = eta_dt - now
    
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
    
    # Format as "Dec 14, 3:45 PM" if more than a day away
    # or "Today at 3:45 PM" / "Tomorrow at 10:30 AM"
    if eta_dt.date() == now.date():
        return f"Today at {format_time(eta_dt)}"
    elif eta_dt.date() == (now + __import__('datetime').timedelta(days=1)).date():
        return f"Tomorrow at {format_time(eta_dt)}"
    else:
        return f"{eta_dt.strftime('%b %d')}, {format_time(eta_dt)}"


def get_request_eta_info(request_id: str, req: Dict = None) -> Dict[str, Any]:
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
    completed_builds = req.get("completed_builds") or 0
    
    # For single-build requests, use existing logic
    if total_builds <= 1:
        conn.close()
        return {
            "is_multi_build": False,
            "total_builds": 1,
            "completed_builds": completed_builds,
            "current_build_num": 1 if req.get("status") == "PRINTING" else None,
            "current_build_eta": None,
            "request_eta": None,
            "builds_info": [],
        }
    
    # Get all builds for this request
    builds = conn.execute("""
        SELECT * FROM builds WHERE request_id = ? ORDER BY build_number
    """, (request_id,)).fetchall()
    conn.close()
    
    builds_list = [dict(b) for b in builds]
    
    # Find the currently printing build
    current_build = None
    for b in builds_list:
        if b["status"] == "PRINTING":
            current_build = b
            break
    
    # Calculate ETA for current build if printing
    current_build_eta_dt = None
    current_build_eta_display = None
    
    if current_build and current_build.get("printer"):
        # Use get_smart_eta for the current build
        current_build_eta_dt = get_smart_eta(
            printer=current_build.get("printer"),
            material=current_build.get("material") or req.get("material"),
            current_percent=current_build.get("progress"),
            printing_started_at=current_build.get("started_at"),
            current_layer=None,
            total_layers=None
        )
        if current_build_eta_dt:
            current_build_eta_display = format_eta_display(current_build_eta_dt)
    
    # Calculate total request ETA (current build + remaining builds)
    request_eta_dt = None
    request_eta_display = None
    remaining_builds = total_builds - completed_builds - (1 if current_build else 0)
    
    if current_build_eta_dt and remaining_builds >= 0:
        # Estimate time for remaining builds using average of completed builds or estimates
        avg_build_time_minutes = 0
        
        # Check completed builds for actual duration
        completed_durations = []
        for b in builds_list:
            if b["status"] == "COMPLETED" and b.get("started_at") and b.get("completed_at"):
                try:
                    started = datetime.fromisoformat(b["started_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                    completed = datetime.fromisoformat(b["completed_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                    completed_durations.append((completed - started).total_seconds() / 60)
                except:
                    pass
        
        if completed_durations:
            avg_build_time_minutes = sum(completed_durations) / len(completed_durations)
        elif req.get("print_time_minutes"):
            # Fall back to slicer estimate divided by builds
            avg_build_time_minutes = req["print_time_minutes"] / total_builds
        
        # Total ETA = current build ETA + (remaining builds * avg time)
        remaining_minutes = remaining_builds * avg_build_time_minutes
        request_eta_dt = current_build_eta_dt + __import__('datetime').timedelta(minutes=remaining_minutes)
        request_eta_display = format_eta_display(request_eta_dt)
    
    # Build summary info
    builds_info = []
    for b in builds_list:
        builds_info.append({
            "id": b["id"],
            "build_number": b["build_number"],
            "status": b["status"],
            "print_name": b.get("print_name") or f"Build {b['build_number']}",
            "printer": b.get("printer"),
            "progress": b.get("progress"),
            "is_current": b["id"] == current_build["id"] if current_build else False,
        })
    
    return {
        "is_multi_build": True,
        "total_builds": total_builds,
        "completed_builds": completed_builds,
        "current_build_num": current_build["build_number"] if current_build else None,
        "current_build_eta": current_build_eta_display,
        "current_build_eta_dt": current_build_eta_dt.isoformat() if current_build_eta_dt else None,
        "request_eta": request_eta_display,
        "request_eta_dt": request_eta_dt.isoformat() if request_eta_dt else None,
        "remaining_builds": remaining_builds,
        "builds_info": builds_info,
    }


# ─────────────────────────── BUILD-LEVEL NOTIFICATIONS ───────────────────────────

def send_build_start_notification(build: Dict, request: Dict):
    """
    Send notification when a build starts printing.
    Clearly indicates this is a build, not final completion.
    """
    build_num = build["build_number"]
    total_builds = request.get("total_builds") or 1
    request_id = request["id"]
    
    # Skip notification for single-build requests (handled by legacy system)
    if total_builds <= 1:
        return
    
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
    
    # Build position string
    position_str = f"Build {build_num} of {total_builds}"
    remaining = total_builds - build_num
    
    if user_wants_email and request.get("requester_email"):
        subject = f"[{APP_TITLE}] {position_str} Started - {print_label}"
        
        email_rows = [
            ("Print Name", print_label),
            ("Build", position_str),
            ("Status", "PRINTING"),
            ("Printer", _human_printer(build.get("printer") or request.get("printer") or "") or "—"),
            ("Material", _human_material(build.get("material") or request.get("material") or "") or "—"),
        ]
        
        if remaining > 0:
            email_rows.append(("Remaining", f"{remaining} build(s) after this one"))
        
        text = (
            f"{position_str} has started printing!\n\n"
            f"Print: {print_label}\n"
            f"Build: {build_label}\n"
            f"Request ID: {request_id[:8]}\n"
            f"\n⚠️ This is NOT the final completion - {remaining} build(s) remain after this one.\n"
            f"\nView progress: {BASE_URL}/my/{request_id}?token={request.get('access_token', '')}\n"
        )
        
        # Generate my-requests link
        my_requests_token = get_or_create_my_requests_token(request["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        html = build_email_html(
            title=f"🖨️ {position_str} Started",
            subtitle=f"'{print_label}' - {build_label} is now printing",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Progress",
            header_color="#f59e0b",  # Amber for in-progress
            footer_note=f"This is build {build_num} of {total_builds}. You will receive another notification when all builds are complete.",
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
        )
        send_email([request["requester_email"]], subject, text, html)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        send_push_notification(
            email=request["requester_email"],
            title=f"🖨️ {position_str} Started",
            body=f"'{print_label}' - {build_label} is now printing ({remaining} more after this)",
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
    
    # Skip notification for single-build requests (handled by legacy system)
    if total_builds <= 1:
        return
    
    # Check if this is the FINAL build
    is_final = (completed_builds >= total_builds)
    
    if is_final:
        # Final build - send request completion notification instead
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
        
        html = build_email_html(
            title=f"✓ {position_str} Complete",
            subtitle=f"'{print_label}' - {build_label} finished successfully",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Progress",
            header_color="#10b981",  # Green for complete
            footer_note=f"This is build {build_num} of {total_builds}. {remaining} build(s) remaining. You will receive a final notification when everything is ready for pickup.",
            image_base64=snapshot_to_send,
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
        )
        send_email([request["requester_email"]], subject, text, html, image_base64=snapshot_to_send)
    
    # Send push notification
    if user_wants_push and request.get("requester_email"):
        send_push_notification(
            email=request["requester_email"],
            title=f"✓ {position_str} Complete",
            body=f"'{print_label}' - {completed_builds}/{total_builds} builds done, {remaining} remaining",
            url=f"/my/{request_id}?token={request.get('access_token', '')}"
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
        
        html = build_email_html(
            title="Print Complete!",
            subtitle=f"'{print_label}' is ready for pickup",
            rows=email_rows,
            cta_url=f"{BASE_URL}/my/{request_id}?token={request.get('access_token', '')}",
            cta_label="View Request",
            header_color="#06b6d4",  # Cyan for done
            image_base64=snapshot_to_send,
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
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
            url=f"/my/{request_id}?token={request.get('access_token', '')}"
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
        "progress_email": False,
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
    - EMAIL is sent ONLY at 50% threshold (if user has email enabled)
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
    thresholds = []
    for p in user_milestones_str.split(","):
        p = p.strip()
        if p.isdigit():
            pct = int(p)
            if 0 < pct < 100:
                thresholds.append(pct)
    thresholds = sorted(set(thresholds))
    
    if not thresholds:
        return
    
    # Get already-sent milestones
    sent_milestones = get_sent_progress_milestones(build_id)
    
    # Determine which milestones to fire (handles jumps like 49->80 firing both 50 and 75)
    milestones_to_send = []
    for threshold in thresholds:
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
    
    # Try to get a camera snapshot URL for the notification image (best effort)
    # Only include if camera is configured for this printer
    image_url = None
    if printer_code and printer_code in ["ADVENTURER_4", "AD5X"]:
        camera_url = get_camera_url(printer_code)
        if camera_url:
            # Use the public snapshot endpoint (with timestamp to avoid caching)
            image_url = f"{BASE_URL}/api/camera/{printer_code}/snapshot"
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
        
        # Send PUSH notification (if user enabled)
        if user_wants_progress_push:
            send_push_notification(
                email=requester_email,
                title=notification_title,
                body=notification_body,
                url=view_url,
                image_url=image_url,  # Include snapshot image if available
                tag=notification_tag   # Use tag to replace previous progress notifications for this build
            )
            record_progress_milestone(build_id, milestone, "push")
        
        # Send EMAIL only at 50% threshold (to avoid spam)
        if milestone == 50 and user_wants_progress_email:
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
            
            html = build_email_html(
                title=notification_title,
                subtitle=notification_body,
                rows=email_rows,
                cta_url=f"{BASE_URL}{view_url}",
                cta_label="View Progress",
                header_color="#8b5cf6",  # Purple for progress updates
                secondary_cta_url=my_requests_url,
                secondary_cta_label="All My Requests",
            )
            send_email([requester_email], subject, text, html)
            record_progress_milestone(build_id, milestone, "email")
        
        # Record milestone even if no notifications sent (prevents re-check)
        if not user_wants_progress_push and not (milestone == 50 and user_wants_progress_email):
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


def get_printer_api(printer_code: str) -> Optional[FlashForgeAPI]:
    """Get FlashForge API instance for a printer (ADVENTURER_4 or AD5X)"""
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
    """Get camera URL for a printer"""
    if printer_code == "ADVENTURER_4":
        return get_setting("camera_adventurer_4_url", "")
    elif printer_code == "AD5X":
        return get_setting("camera_ad5x_url", "")
    return None


async def capture_camera_snapshot(printer_code: str) -> Optional[bytes]:
    """Capture a snapshot from the printer's camera by extracting a frame from MJPEG stream"""
    camera_url = get_camera_url(printer_code)
    if not camera_url:
        logger.debug(f"[CAMERA] No camera URL configured for {printer_code}")
        return None
    
    try:
        # Try snapshot URL first (quick attempt with short timeout)
        snapshot_url = camera_url.replace("?action=stream", "?action=snapshot")
        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                response = await client.get(snapshot_url)
                if response.status_code == 200 and response.headers.get("content-type", "").startswith("image/"):
                    logger.debug(f"[CAMERA] Got snapshot from {printer_code} via snapshot endpoint ({len(response.content)} bytes)")
                    return response.content
            except httpx.TimeoutException:
                logger.debug(f"[CAMERA] Snapshot endpoint timed out for {printer_code}, trying stream method")
        
        # Fallback: Extract a single frame from the MJPEG stream
        logger.debug(f"[CAMERA] Trying to extract frame from MJPEG stream for {printer_code}")
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=5.0)) as client:
            async with client.stream("GET", camera_url) as response:
                buffer = b""
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    buffer += chunk
                    # Look for JPEG markers: starts with FFD8, ends with FFD9
                    start = buffer.find(b"\xff\xd8")
                    if start != -1:
                        end = buffer.find(b"\xff\xd9", start)
                        if end != -1:
                            jpeg_data = buffer[start:end + 2]
                            logger.debug(f"[CAMERA] Extracted JPEG frame ({len(jpeg_data)} bytes) from {printer_code}")
                            return jpeg_data
                    # Prevent buffer from growing too large
                    if len(buffer) > 500000:  # 500KB max
                        logger.warning(f"[CAMERA] Buffer too large, no JPEG found for {printer_code}")
                        break
    except Exception as e:
        logger.error(f"[CAMERA] Error capturing snapshot from {printer_code}: {e}")
    
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
                "SELECT id, printer, printing_started_at, printing_email_sent, requester_email, requester_name, print_name, material, access_token, print_time_minutes, notification_prefs FROM requests WHERE status = ?",
                ("PRINTING",)
            ).fetchall()
            conn.close()
            
            add_poll_debug_log({"type": "poll_found", "message": f"Found {len(printing_reqs)} PRINTING requests"})

            for req_row in printing_reqs:
                req = dict(req_row)  # Convert to dict for .get() support
                
                # Check if polling is paused for this printer (e.g., during print send)
                if is_polling_paused(req["printer"]):
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": req["printer"],
                        "message": "Polling paused (print operation in progress)"
                    })
                    continue
                
                printer_api = get_printer_api(req["printer"])
                if not printer_api:
                    add_poll_debug_log({
                        "type": "poll_skip",
                        "request_id": req["id"][:8],
                        "printer": req["printer"],
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
                print(f"[POLL] {req['printer']}: status={machine_status}, printing={is_printing}, complete={is_complete}, progress={percent_complete}%")
                
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
                        
                        # Parse user notification preferences
                        user_prefs = {"email": True, "push": False}
                        if req.get("notification_prefs"):
                            try:
                                user_prefs = json.loads(req["notification_prefs"])
                            except:
                                pass
                        user_wants_email = user_prefs.get("email", True)
                        user_wants_push = user_prefs.get("push", False)
                        
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
                            
                            html = build_email_html(
                                title="Now Printing!",
                                subtitle=f"'{print_label}' is now printing!",
                                rows=email_rows,
                                cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                                cta_label="View in Queue",
                                header_color="#f59e0b",  # Orange for printing
                                secondary_cta_url=my_requests_url,
                                secondary_cta_label="All My Requests",
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
                            snapshot_data = await capture_camera_snapshot(req["printer"])
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

                    # Parse user notification preferences
                    user_prefs = {"email": True, "push": False}
                    if req_row and req_row.get("notification_prefs"):
                        try:
                            user_prefs = json.loads(req_row["notification_prefs"])
                        except:
                            pass
                    user_wants_email = user_prefs.get("email", True)
                    user_wants_push = user_prefs.get("push", False)

                    # Build email rows with completion data
                    email_rows = [("Request ID", rid[:8]), ("Status", "DONE")]
                    if final_temp:
                        email_rows.append(("Final Temp", final_temp))

                    print_label = req_row["print_name"] if req_row else f"Request {rid[:8]}"

                    if requester_email_on_status and req_row and user_wants_email:
                        subject = f"[{APP_TITLE}] Print Complete! ({rid[:8]})"
                        text = f"Your print is done and ready for pickup!\n\nRequest ID: {rid[:8]}\n\nView queue: {BASE_URL}/queue?mine={rid[:8]}\n"
                        snapshot_to_send = completion_snapshot if get_bool_setting("enable_camera_snapshot", False) else None
                        html = build_email_html(
                            title="Print Complete!",
                            subtitle="Your request is ready for pickup.",
                            rows=email_rows,
                            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                            cta_label="View queue",
                            image_base64=snapshot_to_send,
                        )
                        send_email([req_row["requester_email"]], subject, text, html, image_base64=snapshot_to_send)
                    
                    # Send push notification if user wants push
                    if user_wants_push and req_row and req_row.get("requester_email"):
                        print(f"[POLL] Sending push notification for completed print {rid[:8]}")
                        send_push_notification(
                            email=req_row["requester_email"],
                            title="✅ Print Complete!",
                            body=f"'{print_label}' is ready for pickup!",
                            url=f"/my/{rid}?token={req_row.get('access_token', '')}"
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
                        
                        print(f"[AUTO-MATCH] Auto-matching request {rid[:8]} to {printer_code} (file: {current_file})")
                        add_poll_debug_log({
                            "type": "auto_match",
                            "request_id": rid[:8],
                            "printer": printer_code,
                            "file": current_file,
                            "message": f"Auto-matched to {printer_code}"
                        })
                        
                        conn = db()
                        old_status = match["status"]
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

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, data=data)
        r.raise_for_status()
        payload = r.json()
        return bool(payload.get("success"))


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


def build_email_html(title: str, subtitle: str, rows: List[Tuple[str, str]], cta_url: Optional[str] = None, cta_label: str = "Open", header_color: str = "#4f46e5", image_base64: Optional[str] = None, footer_note: Optional[str] = None, secondary_cta_url: Optional[str] = None, secondary_cta_label: str = "My Requests") -> str:
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

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"[EMAIL] Failed to send '{subject}' to {to_addrs}: {e}")
        return


# ─────────────────────────── PUSH NOTIFICATIONS ───────────────────────────
def send_push_notification(email: str, title: str, body: str, url: str = None, image_url: str = None, tag: str = None) -> dict:
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
        return result
        
    print(f"[PUSH] Found {len(subs)} subscription(s) for {email}")
    
    # Build notification payload with optional image support
    payload_data = {
        "title": title,
        "body": body,
        "url": url or "/my-requests/view",
        "icon": "/static/icons/icon-192.png",
    }
    
    # Add optional image URL for rich notifications (progress updates, etc.)
    if image_url:
        payload_data["image"] = image_url
    
    # Add tag for notification grouping (allows replacing instead of stacking)
    if tag:
        payload_data["tag"] = tag
    
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
    
    return result


def send_broadcast_notification(title: str, body: str, url: str = None, 
                                broadcast_type: str = "custom", sent_by: str = None,
                                metadata: dict = None, also_email: bool = False) -> dict:
    """
    Send a push notification to ALL subscribed users.
    Used for system announcements, app updates, etc.
    
    Args:
        title: Notification title
        body: Notification body text
        url: Click-through URL (default: /changelog for updates, / for others)
        broadcast_type: Type of broadcast ('custom', 'app_update', 'announcement', 'maintenance')
        sent_by: Admin email or identifier who sent this
        metadata: Optional dict of additional metadata (e.g., version number)
        also_email: If True, also send email to all subscribed users
    
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
    emails = conn.execute(
        "SELECT DISTINCT email FROM push_subscriptions"
    ).fetchall()
    conn.close()
    
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


def send_push_notification_to_admins(title: str, body: str, url: str = None, tag: str = None) -> dict:
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
            tag=tag
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
    }, status_code=400 if error else 200)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Check if user is logged in
    user = await optional_user(request)
    return render_form(request, None, form={}, user=user)


@app.post("/submit")
async def submit(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    print_name: str = Form(...),
    printer: str = Form(...),
    material: str = Form(...),
    colors: str = Form(...),
    link_url: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    rush_request: Optional[str] = Form(None),
    rush_payment_confirmed: Optional[str] = Form(None),
    turnstile_token: Optional[str] = Form(None, alias="cf-turnstile-response"),
    upload: Optional[UploadFile] = File(None),
):
    form_state = {
        "requester_name": requester_name,
        "requester_email": requester_email,
        "print_name": print_name,
        "printer": printer,
        "material": material,
        "colors": colors,
        "link_url": link_url or "",
        "notes": notes or "",
        "rush_request": rush_request,
        "rush_payment_confirmed": rush_payment_confirmed,
    }

    ok = await verify_turnstile(turnstile_token or "", request.client.host if request.client else None)
    if not ok:
        return render_form(request, "Human verification failed. Please try again.", form_state)

    if printer not in [p[0] for p in PRINTERS]:
        return render_form(request, "Invalid printer selection.", form_state)

    if material not in [m[0] for m in MATERIALS]:
        return render_form(request, "Invalid material selection.", form_state)

    if link_url:
        try:
            u = urllib.parse.urlparse(link_url.strip())
            if u.scheme not in ("http", "https"):
                raise ValueError("Invalid scheme")
        except Exception:
            return render_form(request, "Invalid link URL. Must start with http:// or https://", form_state)

    has_link = bool(link_url and link_url.strip())
    has_file = bool(upload and upload.filename)
    if not has_link and not has_file:
        return render_form(request, "Please provide either a link OR upload a file (one is required).", form_state)

    rid = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)  # Secure token for requester access
    created = now_iso()
    
    # Calculate dynamic rush pricing at submission time
    printer_suggestions = get_printer_suggestions()
    queue_size = printer_suggestions.get("total_queue", 0)
    rush_pricing = calculate_rush_price(queue_size, requester_name)
    final_rush_price = rush_pricing["final_price"]
    is_brandon = rush_pricing["is_special"]
    
    # Priority: P1 if rush requested AND payment confirmed, P3 default
    is_rush = rush_request and rush_payment_confirmed
    priority = 1 if is_rush else 3
    
    # Build rush note with actual calculated price
    if is_rush:
        if is_brandon:
            special_notes = f"🚀 RUSH REQUEST (${final_rush_price} paid - Brandon Tax™ x5) - Priority processing"
        else:
            special_notes = f"🚀 RUSH REQUEST (${final_rush_price} paid) - Priority processing"
    else:
        special_notes = None
    
    # If rush requested but no payment, add note for admin
    if rush_request and not rush_payment_confirmed:
        special_notes = f"⚠️ Rush requested (${final_rush_price}) but payment NOT confirmed - verify before prioritizing"
        priority = 2  # Medium priority, admin can bump to P1 after verifying payment

    conn = db()
    conn.execute(
        """INSERT INTO requests
           (id, created_at, updated_at, requester_name, requester_email, print_name, printer, material, colors, link_url, notes, status, special_notes, priority, admin_notes, access_token)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rid,
            created,
            created,
            requester_name.strip(),
            requester_email.strip(),
            print_name.strip() if print_name else None,
            printer,
            material,
            colors.strip(),
            link_url.strip() if link_url else None,
            notes,
            "NEW",
            special_notes,
            priority,
            None,
            access_token,
        )
    )
    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, created, None, "NEW", "Request submitted")
    )
    conn.commit()

    uploaded_name = None

    if has_file:
        ext = safe_ext(upload.filename)
        if ext not in ALLOWED_EXTS:
            conn.close()
            return render_form(request, f"Only these file types are allowed: {', '.join(sorted(ALLOWED_EXTS))}", form_state)

        max_bytes = MAX_UPLOAD_MB * 1024 * 1024
        data = await upload.read()
        if len(data) > max_bytes:
            conn.close()
            return render_form(request, f"File too large. Max size is {MAX_UPLOAD_MB}MB.", form_state)

        stored = f"{uuid.uuid4()}{ext}"
        out_path = os.path.join(UPLOAD_DIR, stored)

        sha = hashlib.sha256(data).hexdigest()
        with open(out_path, "wb") as f:
            f.write(data)

        # Parse 3D file metadata (dimensions, volume, etc.)
        file_metadata = parse_3d_file_metadata(out_path, upload.filename)
        file_metadata_json = safe_json_dumps(file_metadata) if file_metadata else None

        conn.execute(
            """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256, file_metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), rid, now_iso(), upload.filename, stored, len(data), sha, file_metadata_json)
        )
        conn.commit()

        uploaded_name = upload.filename

    conn.close()

    # --- EMAIL SETTINGS FROM DB ---
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    admin_email_on_submit = get_bool_setting("admin_email_on_submit", True)
    admin_email_on_status = get_bool_setting("admin_email_on_status", True)

    requester_email_on_submit = get_bool_setting("requester_email_on_submit", False)
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)

    # Requester email on submit (OFF by default)
    if requester_email_on_submit:
        subject = f"[{APP_TITLE}] Request received ({rid[:8]})"
        text = (
            f"Your request has been received.\n\n"
            f"Request ID: {rid}\nStatus: NEW\n\n"
            f"Queue: {BASE_URL}/queue?mine={rid[:8]}\n"
        )
        html = build_email_html(
            title="Request received",
            subtitle="We got it — you’re in the queue.",
            rows=[
                ("Request ID", rid[:8]),
                ("Printer", _human_printer(printer)),
                ("Material", _human_material(material)),
                ("Colors", colors.strip()),
                ("Link", (link_url.strip() if link_url else "—")),
                ("File", (uploaded_name or "—")),
            ],
            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
            cta_label="View queue",
            secondary_cta_url=f"{BASE_URL}/my-requests/view?token={get_or_create_my_requests_token(requester_email)}",
            secondary_cta_label="All My Requests",
        )
        send_email([requester_email.strip()], subject, text, html)

    # Admin email on submit
    if admin_email_on_submit and admin_emails:
        subject = f"[{APP_TITLE}] New request ({rid[:8]})"
        text = (
            f"New print request submitted.\n\n"
            f"ID: {rid}\n"
            f"Requester: {requester_name.strip()} ({requester_email.strip()})\n"
            f"Printer: {printer}\nMaterial: {material}\nColors: {colors.strip()}\n"
            f"Link: {link_url.strip() if link_url else '(none)'}\n"
            f"Admin: {BASE_URL}/admin/request/{rid}\n"
        )
        html = build_email_html(
            title="New request submitted",
            subtitle="Needs review in the admin dashboard.",
            rows=[
                ("Request ID", rid[:8]),
                ("Requester", requester_name.strip()),
                ("Email", requester_email.strip()),
                ("Printer", _human_printer(printer)),
                ("Material", _human_material(material)),
                ("Colors", colors.strip()),
                ("Link", (link_url.strip() if link_url else "—")),
                ("File", (uploaded_name or "—")),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="Open in admin",
        )
        send_email(admin_emails, subject, text, html)
        
        # Also send admin push notification
        send_push_notification_to_admins(
            title="📥 New Request",
            body=f"{requester_name.strip()} - {print_name or rid[:8]}",
            url=f"/admin/request/{rid}",
            tag="admin-new-request"
        )

    # Show thanks page with portal link
    return templates.TemplateResponse("thanks_new.html", {
        "request": request,
        "rid": rid,
        "print_name": print_name.strip() if print_name else None,
        "access_token": access_token,
        "version": APP_VERSION,
    })


@app.get("/queue", response_class=HTMLResponse)
async def public_queue(request: Request, mine: Optional[str] = None):
    conn = db()
    rows = conn.execute(
        """SELECT id, requester_name, print_name, printer, material, colors, status, special_notes, 
                  print_time_minutes, turnaround_minutes, printing_started_at, 
                  active_build_id, total_builds, completed_builds
           FROM requests 
           WHERE status NOT IN (?, ?, ?) 
           ORDER BY created_at ASC""",
        ("PICKED_UP", "REJECTED", "CANCELLED")
    ).fetchall()
    conn.close()

    items = []
    printing_idx = None
    
    # Fetch current printer status using cache with timeout
    # This prevents slow page loads when printers are offline
    printer_status = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        printer_status[printer_code] = await fetch_printer_status_with_cache(printer_code, timeout=3.0)
    
    # First pass: build items and find printing index, fetch real progress for PRINTING
    for idx, r in enumerate(rows):
        short_id = r["id"][:8]
        
        # Fetch real printer progress if currently printing
        printer_progress = None
        smart_eta = None
        smart_eta_display = None
        current_layer = None
        total_layers = None
        printing_started_at = r["printing_started_at"] if "printing_started_at" in r.keys() else None
        active_printer = r["printer"]  # Default to request printer
        
        # Handle IN_PROGRESS (multi-build) - get active build's printer
        active_build_id = r["active_build_id"] if "active_build_id" in r.keys() else None
        if r["status"] == "IN_PROGRESS" and active_build_id:
            conn_build = db()
            active_build = conn_build.execute(
                "SELECT printer, started_at FROM builds WHERE id = ?", 
                (active_build_id,)
            ).fetchone()
            conn_build.close()
            if active_build and active_build["printer"]:
                active_printer = active_build["printer"]
                if active_build["started_at"]:
                    printing_started_at = active_build["started_at"]
        
        if r["status"] in ["PRINTING", "IN_PROGRESS"]:
            # Fix missing printing_started_at for legacy requests
            if not printing_started_at:
                printing_started_at = now_iso()
                conn_fix = db()
                conn_fix.execute("UPDATE requests SET printing_started_at = ? WHERE id = ? AND printing_started_at IS NULL", 
                               (printing_started_at, r["id"]))
                conn_fix.commit()
                conn_fix.close()
            
            # Use cached printer status data (already fetched above)
            cached_status = printer_status.get(active_printer, {})
            if cached_status and not cached_status.get("is_offline"):
                printer_progress = cached_status.get("progress")
                current_layer = cached_status.get("current_layer")
                total_layers = cached_status.get("total_layers")
            
            # Calculate smart ETA based on layers (preferred) or progress
            eta_dt = get_smart_eta(
                printer=active_printer,
                material=r["material"],
                current_percent=printer_progress,
                printing_started_at=printing_started_at,
                current_layer=current_layer,
                total_layers=total_layers
            )
            if eta_dt:
                smart_eta = eta_dt.isoformat()
                smart_eta_display = format_eta_display(eta_dt)
        
        # Get printer health status
        printer_health = printer_status.get(active_printer, {}).get("healthy", None)
        
        items.append({
            "pos": idx + 1,
            "short_id": short_id,
            "requester_first": first_name_only(r["requester_name"]),
            "print_name": r["print_name"],
            "printer": active_printer,  # Use active build's printer for display
            "material": r["material"],
            "colors": r["colors"],
            "status": r["status"],
            "special_notes": (r["special_notes"] or "").strip(),
            "is_mine": bool(mine and mine == short_id),
            "print_time_minutes": r["print_time_minutes"],
            "turnaround_minutes": r["turnaround_minutes"],
            "estimated_wait_minutes": None,
            "printer_progress": printer_progress,  # Real progress % from API
            "printer_health": printer_health,  # True if ready/printing, False if error, None if unknown
            "smart_eta": smart_eta,  # ISO datetime of estimated completion
            "smart_eta_display": smart_eta_display,  # Human-readable "Today at 3:45 PM"
            "printing_started_at": printing_started_at,
            "current_layer": current_layer,  # Current layer number
            "total_layers": total_layers,  # Total layers in print
            "total_builds": r["total_builds"] if "total_builds" in r.keys() else 1,  # Multi-build support
            "completed_builds": r["completed_builds"] if "completed_builds" in r.keys() else 0,  # Multi-build support
        })
    
    # Separate items by status for display
    # Include IN_PROGRESS for multi-build requests that have active builds
    printing_items = [it for it in items if it["status"] in ["PRINTING", "IN_PROGRESS"]]
    approved_items = [it for it in items if it["status"] == "APPROVED"]
    done_items = [it for it in items if it["status"] == "DONE"]
    pending_items = [it for it in items if it["status"] in ["NEW", "NEEDS_INFO"]]
    
    # Group printing items by printer (for printer card display)
    # For multi-build requests, we need to query all PRINTING builds to find which printers are active
    printing_by_printer = {
        "ADVENTURER_4": None,
        "AD5X": None,
    }
    
    # First, query all builds that are currently PRINTING to handle multi-printer scenarios
    conn_builds = db()
    printing_builds = conn_builds.execute("""
        SELECT b.*, r.requester_name, r.print_name as request_print_name, r.material as request_material,
               r.total_builds, r.completed_builds, r.id as request_id
        FROM builds b
        JOIN requests r ON b.request_id = r.id
        WHERE b.status = 'PRINTING'
    """).fetchall()
    conn_builds.close()
    
    # Map request IDs to items for quick lookup
    items_by_request_id = {}
    for it in items:
        # Match full request ID by short_id prefix
        for r in rows:
            if r["id"][:8] == it["short_id"]:
                items_by_request_id[r["id"]] = it
                break
    
    # Create printer card entries from PRINTING builds
    for build in printing_builds:
        build_printer = build["printer"]
        if build_printer in printing_by_printer and printing_by_printer[build_printer] is None:
            # Get the parent request item
            request_id = build["request_id"]
            parent_item = items_by_request_id.get(request_id)
            
            if parent_item:
                # Create a printer-specific entry for this build
                # Get progress from cached printer status
                cached_status = printer_status.get(build_printer, {})
                build_progress = None
                build_layer = None
                build_total_layers = None
                build_eta_display = None
                
                if cached_status and not cached_status.get("is_offline"):
                    build_progress = cached_status.get("progress")
                    build_layer = cached_status.get("current_layer")
                    build_total_layers = cached_status.get("total_layers")
                    
                    # Calculate ETA for this specific build
                    started_at = build["started_at"]
                    if started_at:
                        eta_dt = get_smart_eta(
                            printer=build_printer,
                            material=build["material"] or parent_item["material"],
                            current_percent=build_progress,
                            printing_started_at=started_at,
                            current_layer=build_layer,
                            total_layers=build_total_layers
                        )
                        if eta_dt:
                            build_eta_display = format_eta_display(eta_dt)
                
                # Create entry for this printer
                printer_entry = dict(parent_item)
                printer_entry["printer"] = build_printer
                printer_entry["printer_progress"] = build_progress
                printer_entry["current_layer"] = build_layer
                printer_entry["total_layers"] = build_total_layers
                printer_entry["smart_eta_display"] = build_eta_display
                printer_entry["printing_started_at"] = build["started_at"]
                printer_entry["build_number"] = build["build_number"]
                printer_entry["build_print_name"] = build["print_name"]
                printing_by_printer[build_printer] = printer_entry
    
    # Fallback for single-build requests or legacy PRINTING status
    for pit in printing_items:
        if pit["printer"] in printing_by_printer and printing_by_printer[pit["printer"]] is None:
            printing_by_printer[pit["printer"]] = pit
    
    # If printer is BUILDING but no PRINTING item exists, show "likely printing" item
    # This handles the case where admin hasn't clicked "Started" yet but printer is running
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        if printing_by_printer[printer_code] is None:
            pstat = printer_status.get(printer_code, {})
            if pstat.get("is_printing"):
                # Find first approved item assigned to this printer (or ANY)
                for item in approved_items:
                    if item["printer"] in [printer_code, "ANY"]:
                        # Clone and mark as "likely" printing - will show in printer card
                        likely_item = dict(item)
                        likely_item["_likely_printing"] = True
                        printing_by_printer[printer_code] = likely_item
                        break
    
    # Helper to estimate remaining time for a printing item
    def estimate_remaining_minutes(item):
        """Estimate remaining time for a printing item based on layer progress or percent progress"""
        if not item.get("printing_started_at"):
            # Fall back to manual estimate
            if item.get("print_time_minutes"):
                progress = item.get("printer_progress") or 0
                remaining = item["print_time_minutes"] * (1 - progress / 100)
                return max(0, int(remaining))
            return None
        
        try:
            from datetime import datetime
            # Normalize to naive UTC
            started = datetime.fromisoformat(item["printing_started_at"].replace("Z", "+00:00"))
            if started.tzinfo:
                started = started.replace(tzinfo=None)
            now = datetime.utcnow()
            elapsed_minutes = (now - started).total_seconds() / 60
            
            # Need at least 2 minutes elapsed for reliable estimate
            if elapsed_minutes < 2:
                if item.get("print_time_minutes"):
                    return max(0, int(item["print_time_minutes"]))
                return None
            
            # Method 1: Layer-based (more accurate for FDM)
            if item.get("current_layer") and item.get("total_layers") and item["total_layers"] > 0:
                layer_progress = (item["current_layer"] / item["total_layers"]) * 100
                if layer_progress > 0:
                    total_estimated = elapsed_minutes / (layer_progress / 100)
                    remaining = total_estimated - elapsed_minutes
                    return max(0, int(remaining))
            
            # Method 2: Percent-based (fallback)
            if item.get("printer_progress") and item["printer_progress"] > 5:
                total_estimated = elapsed_minutes / (item["printer_progress"] / 100)
                remaining = total_estimated - elapsed_minutes
                return max(0, int(remaining))
        except Exception:
            pass
        
        # Fall back to manual estimate minus progress-based portion
        if item.get("print_time_minutes"):
            progress = item.get("printer_progress") or 0
            remaining = item["print_time_minutes"] * (1 - progress / 100)
            return max(0, int(remaining))
        
        return None
    
    # Track remaining time per printer for wait calculations
    printer_remaining = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        pit = printing_by_printer.get(printer_code)
        if pit:
            remaining = estimate_remaining_minutes(pit)
            # Store remaining time for the current print
            printer_remaining[printer_code] = remaining if remaining is not None else 30
            # Also store on the item for display
            pit["remaining_minutes"] = remaining
        else:
            printer_remaining[printer_code] = 0  # Printer idle
    
    # Build unified queue: PRINTING first, then APPROVED
    # This gives continuous queue numbering
    active_queue = printing_items + approved_items
    
    # Number the queue continuously
    for idx, item in enumerate(active_queue):
        item["queue_pos"] = idx + 1
    
    # Calculate wait times for APPROVED items only
    # (PRINTING items show remaining time, not wait time)
    for item in approved_items:
        target_printer = item["printer"]
        
        if target_printer == "ANY":
            # Goes to whichever printer finishes first
            wait = min(printer_remaining.values()) if printer_remaining else 0
        elif target_printer in printer_remaining:
            wait = printer_remaining[target_printer]
        else:
            wait = 0
        
        # Only show wait time if there's actually a wait
        item["estimated_wait_minutes"] = wait if wait > 0 else None
        
        # Update the printer's queue time for next item in line
        item_time = item.get("print_time_minutes") or 60  # Default 60 min for unknown prints
        if target_printer == "ANY":
            # Add to the printer with shortest queue
            shortest = min(printer_remaining, key=printer_remaining.get)
            printer_remaining[shortest] += item_time
        elif target_printer in printer_remaining:
            printer_remaining[target_printer] += item_time

    my_pos = None
    if mine:
        for it in active_queue:
            if it["short_id"] == mine:
                my_pos = it["queue_pos"]
                break

    counts = {"NEW": 0, "NEEDS_INFO": 0, "APPROVED": 0, "PRINTING": 0, "IN_PROGRESS": 0, "DONE": 0}
    for it in items:
        if it["status"] in counts:
            counts[it["status"]] += 1
    
    # Count actual printing builds (not just requests) for more accurate "Printing" stat
    # This handles multi-build scenarios where multiple builds print simultaneously
    printing_builds_count = sum(1 for p in printing_by_printer.values() if p is not None and not p.get("_likely_printing"))
    counts["PRINTING_BUILDS"] = printing_builds_count

    return templates.TemplateResponse("public_queue_new.html", {
        "request": request,
        "items": items,  # All items for backwards compat
        "active_queue": active_queue,  # PRINTING + APPROVED items with continuous numbering
        "pending_items": pending_items,  # NEW + NEEDS_INFO items awaiting review
        "done_items": done_items,  # DONE items for pickup section
        "printing_by_printer": printing_by_printer,  # PRINTING items grouped by printer
        "mine": mine,
        "my_pos": my_pos,
        "counts": counts,
        "printer_status": {
            "ADVENTURER_4": printer_status.get("ADVENTURER_4", {}),
            "AD5X": printer_status.get("AD5X", {}),
        },
        "version": APP_VERSION,
    })


@app.get("/repeat/{short_id}", response_class=HTMLResponse)
def repeat_request(request: Request, short_id: str):
    """Pre-fill form with data from a previous request"""
    conn = db()
    # Find request by short ID (first 8 chars)
    row = conn.execute(
        "SELECT requester_name, requester_email, print_name, printer, material, colors, link_url, notes "
        "FROM requests WHERE id LIKE ?",
        (f"{short_id}%",)
    ).fetchone()
    conn.close()
    
    if not row:
        return render_form(request, f"Request {short_id} not found.", {})
    
    form_data = {
        "requester_name": row["requester_name"],
        "requester_email": row["requester_email"],
        "print_name": row["print_name"],
        "printer": row["printer"],
        "material": row["material"],
        "colors": row["colors"],
        "link_url": row["link_url"] or "",
        "notes": row["notes"] or "",
    }
    
    return render_form(request, None, form_data)


# ─────────────────────────── REQUESTER PORTAL ───────────────────────────

@app.get("/open/{rid}", response_class=HTMLResponse)
async def open_in_app_page(request: Request, rid: str, token: str):
    """
    Smart redirect page that helps users open links in the PWA.
    If viewing in PWA: redirects directly to the request.
    If viewing in browser: shows instructions to open the app.
    """
    conn = db()
    req = conn.execute("SELECT access_token, print_name, requester_email FROM requests WHERE id = ?", (rid,)).fetchone()
    conn.close()
    
    if not req or req["access_token"] != token:
        raise HTTPException(status_code=403, detail="Invalid link")
    
    target_url = f"/my/{rid}?token={token}"
    return templates.TemplateResponse("open_in_app.html", {
        "request": request,
        "target_url": target_url,
        "rid": rid,
        "print_name": req["print_name"],
        "email": req["requester_email"],
    })


@app.get("/my/{rid}", response_class=HTMLResponse)
async def requester_portal(request: Request, rid: str, token: str):
    """Requester portal - view and interact with your request"""
    logger.debug(f"[REQUESTER_PORTAL] Loading request {rid[:8]}")
    conn = db()
    req = conn.execute(
        "SELECT * FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    
    if not req:
        conn.close()
        logger.warning(f"[REQUESTER_PORTAL] Request not found: {rid[:8]}")
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Verify access token
    if req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access token")
    
    # Get files
    files = conn.execute(
        "SELECT * FROM files WHERE request_id = ? ORDER BY created_at DESC", (rid,)
    ).fetchall()
    
    # Get status history
    history = conn.execute(
        "SELECT * FROM status_events WHERE request_id = ? ORDER BY created_at DESC", (rid,)
    ).fetchall()
    
    # Get messages
    messages = conn.execute(
        "SELECT * FROM request_messages WHERE request_id = ? ORDER BY created_at ASC", (rid,)
    ).fetchall()
    
    # Get builds with snapshots (for multi-build requests or DONE status)
    builds_with_snapshots = []
    builds = conn.execute(
        """SELECT b.*, bs.snapshot_data, bs.created_at as snapshot_created_at
           FROM builds b
           LEFT JOIN build_snapshots bs ON b.id = bs.build_id AND bs.snapshot_type = 'completion'
           WHERE b.request_id = ?
           ORDER BY b.build_number""",
        (rid,)
    ).fetchall()
    
    for b in builds:
        build_dict = dict(b)
        builds_with_snapshots.append(build_dict)
    
    # Fetch printer status if currently printing or in progress
    printer_status = None
    smart_eta_display = None
    active_printer = req["printer"]
    printing_started_at = req["printing_started_at"]
    
    if req["status"] in ["PRINTING", "IN_PROGRESS"]:
        # For IN_PROGRESS, get the printer from the active build
        if req["status"] == "IN_PROGRESS" and req["active_build_id"]:
            active_build = conn.execute(
                "SELECT printer, started_at FROM builds WHERE id = ?",
                (req["active_build_id"],)
            ).fetchone()
            if active_build and active_build["printer"]:
                active_printer = active_build["printer"]
                if active_build["started_at"]:
                    printing_started_at = active_build["started_at"]
        
        # Use cached printer status fetch for consistency and performance
        if active_printer:
            printer_status = await fetch_printer_status_with_cache(active_printer, timeout=3.0)
            logger.debug(f"[REQUESTER_PORTAL] Printer status for {active_printer}: {printer_status.get('status')}, {printer_status.get('progress')}%")
            
            # Calculate smart ETA if we have status
            if printer_status and not printer_status.get("is_offline"):
                eta_dt = get_smart_eta(
                    printer=active_printer,
                    material=req["material"],
                    current_percent=printer_status.get("progress") or 0,
                    printing_started_at=printing_started_at or now_iso(),
                    current_layer=printer_status.get("current_layer") or 0,
                    total_layers=printer_status.get("total_layers") or 0
                )
                if eta_dt:
                    smart_eta_display = format_eta_display(eta_dt)
    
    # Get requester email for push diagnostics
    requester_email = req["requester_email"]
    
    # Find the currently printing build and its associated file (for 3D preview in print status)
    current_printing_build = None
    current_printing_file = None
    for b in builds_with_snapshots:
        if b.get("status") == "PRINTING":
            current_printing_build = b
            
            # Method 1: Try to find file by build_id assignment
            for f in files:
                f_build_id = f["build_id"] if "build_id" in f.keys() else None
                if f_build_id and f_build_id == b["id"]:
                    ext = f["original_filename"].lower().split('.')[-1]
                    if ext in ['stl', 'obj', '3mf']:
                        current_printing_file = dict(f)
                        break
            
            # Method 2: Fallback to matching by file_name field on build
            if not current_printing_file and b.get("file_name"):
                for f in files:
                    if f["original_filename"] == b["file_name"]:
                        ext = f["original_filename"].lower().split('.')[-1]
                        if ext in ['stl', 'obj', '3mf']:
                            current_printing_file = dict(f)
                        break
            
            # Method 3: Last resort - use the first 3D file in the request
            if not current_printing_file:
                for f in files:
                    ext = f["original_filename"].lower().split('.')[-1]
                    if ext in ['stl', 'obj', '3mf']:
                        current_printing_file = dict(f)
                        break
            
            break
    
    conn.close()
    
    return templates.TemplateResponse("my_request.html", {
        "request": request,
        "req": req,
        "files": files,
        "history": history,
        "messages": messages,
        "token": token,
        "version": APP_VERSION,
        "printer_status": printer_status,
        "smart_eta_display": smart_eta_display,
        "build_eta_info": get_request_eta_info(rid, dict(req)),
        "active_printer": active_printer,
        "builds_with_snapshots": builds_with_snapshots,
        "requester_email": requester_email,
        "current_printing_build": current_printing_build,
        "current_printing_file": current_printing_file,
    })


@app.post("/my/{rid}/reply")
def requester_reply(request: Request, rid: str, token: str, message: str = Form(...)):
    """Requester sends a message"""
    conn = db()
    req = conn.execute("SELECT access_token, status, requester_name, requester_email, print_name FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    # Save message
    msg_id = str(uuid.uuid4())
    created = now_iso()
    conn.execute(
        "INSERT INTO request_messages (id, request_id, created_at, sender_type, message) VALUES (?, ?, ?, ?, ?)",
        (msg_id, rid, created, "requester", message)
    )
    
    # If status was NEEDS_INFO, switch back to NEW so admin sees it
    if req["status"] == "NEEDS_INFO":
        conn.execute("UPDATE requests SET status = ?, updated_at = ? WHERE id = ?", ("NEW", created, rid))
        conn.execute(
            "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), rid, created, "NEEDS_INFO", "NEW", "Requester responded")
        )
    
    conn.commit()
    conn.close()
    
    # Notify admin
    admin_emails = [e.strip() for e in get_setting("admin_notify_emails", "").split(",") if e.strip()]
    if admin_emails:
        subject = f"[{APP_TITLE}] Reply from {req['requester_name']} - {req['print_name'] or rid[:8]}"
        text = f"New message on request {rid[:8]}:\n\n{message}\n\nView: {BASE_URL}/admin/request/{rid}"
        html = build_email_html(
            title="💬 New Reply",
            subtitle=f"{req['requester_name']} responded to their request",
            rows=[
                ("Request", req['print_name'] or rid[:8]),
                ("Message", message),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="View Request",
            header_color="#6366f1",
        )
        send_email(admin_emails, subject, text, html)
        
        # Also send admin push notification for replies
        send_push_notification_to_admins(
            title="💬 Reply from Requester",
            body=f"{req['requester_name']}: {message[:50]}{'...' if len(message) > 50 else ''}",
            url=f"/admin/request/{rid}",
            tag="admin-requester-reply"
        )
    
    return RedirectResponse(url=f"/my/{rid}?token={token}", status_code=303)


@app.post("/my/{rid}/upload")
async def requester_upload(request: Request, rid: str, token: str, files: List[UploadFile] = File(...)):
    """Requester uploads additional files"""
    conn = db()
    req = conn.execute("SELECT access_token, status FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    if req["status"] not in ["NEW", "NEEDS_INFO"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot upload files in current status")
    
    created = now_iso()
    uploaded_names = []
    
    for upload in files:
        if not upload.filename:
            continue
            
        ext = os.path.splitext(upload.filename)[1].lower()
        if ext not in ALLOWED_EXTS:
            continue
        
        content = await upload.read()
        sha256 = hashlib.sha256(content).hexdigest()
        stored_name = f"{sha256}{ext}"
        
        # Save file
        uploads_dir = os.path.join(os.path.dirname(__file__), "static", "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        path = os.path.join(uploads_dir, stored_name)
        with open(path, "wb") as f:
            f.write(content)
        
        # Parse 3D file metadata (dimensions, volume, etc.)
        file_metadata = parse_3d_file_metadata(path, upload.filename)
        file_metadata_json = safe_json_dumps(file_metadata) if file_metadata else None
        
        # Record in database
        file_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256, file_metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, rid, created, upload.filename, stored_name, len(content), sha256, file_metadata_json)
        )
        uploaded_names.append(upload.filename)
    
    if uploaded_names:
        # Add a message about the upload
        msg_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO request_messages (id, request_id, created_at, sender_type, message) VALUES (?, ?, ?, ?, ?)",
            (msg_id, rid, created, "requester", f"Uploaded files: {', '.join(uploaded_names)}")
        )
        
        # If status was NEEDS_INFO, switch back to NEW
        if req["status"] == "NEEDS_INFO":
            conn.execute("UPDATE requests SET status = ?, updated_at = ? WHERE id = ?", ("NEW", created, rid))
            conn.execute(
                "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), rid, created, "NEEDS_INFO", "NEW", f"Requester uploaded: {', '.join(uploaded_names)}")
            )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/my/{rid}?token={token}", status_code=303)


@app.post("/my/{rid}/edit")
def requester_edit(
    request: Request, 
    rid: str, 
    token: str, 
    print_name: str = Form(""),
    link_url: str = Form(""),
    notes: str = Form("")
):
    """Requester edits their request details"""
    conn = db()
    req = conn.execute("SELECT access_token, status FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    if req["status"] not in ["NEW", "NEEDS_INFO"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot edit request in current status")
    
    created = now_iso()
    conn.execute(
        "UPDATE requests SET print_name = ?, link_url = ?, notes = ?, updated_at = ? WHERE id = ?",
        (print_name.strip() or None, link_url.strip() or None, notes.strip() or None, created, rid)
    )
    
    # Add a message about the edit
    msg_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO request_messages (id, request_id, created_at, sender_type, message) VALUES (?, ?, ?, ?, ?)",
        (msg_id, rid, created, "requester", "Updated request details")
    )
    
    # If status was NEEDS_INFO, switch back to NEW
    if req["status"] == "NEEDS_INFO":
        conn.execute("UPDATE requests SET status = ?, updated_at = ? WHERE id = ?", ("NEW", created, rid))
        conn.execute(
            "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), rid, created, "NEEDS_INFO", "NEW", "Requester updated request")
        )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/my/{rid}?token={token}", status_code=303)


@app.get("/my/{rid}/file/{file_id}")
async def requester_download_file(rid: str, file_id: str, token: str):
    """Requester downloads their own file."""
    conn = db()
    req = conn.execute("SELECT access_token FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    file_info = conn.execute(
        "SELECT stored_filename, original_filename FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    conn.close()
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = os.path.join(UPLOAD_DIR, file_info["stored_filename"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    return FileResponse(
        path=file_path,
        filename=file_info["original_filename"],
        media_type="application/octet-stream"
    )


@app.get("/my/{rid}/file/{file_id}/preview", response_class=HTMLResponse)
async def requester_preview_file(request: Request, rid: str, file_id: str, token: str):
    """Requester previews their 3D file in the viewer."""
    conn = db()
    req = conn.execute("SELECT access_token FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    file_info = conn.execute(
        "SELECT id, stored_filename, original_filename, file_metadata FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    conn.close()
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check if it's a supported 3D file
    ext = os.path.splitext(file_info["original_filename"].lower())[1]
    if ext not in [".stl", ".obj", ".3mf"]:
        raise HTTPException(status_code=400, detail="Preview only available for STL, OBJ, and 3MF files")
    
    file_path = os.path.join(UPLOAD_DIR, file_info["stored_filename"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Parse metadata
    metadata = None
    if file_info["file_metadata"]:
        try:
            metadata = json.loads(file_info["file_metadata"])
        except:
            pass
    
    return templates.TemplateResponse("file_preview_user.html", {
        "request": request,
        "req_id": rid,
        "token": token,
        "file": dict(file_info),
        "metadata": metadata,
        "file_url": f"/my/{rid}/file/{file_id}?token={token}",
    })


@app.post("/my/{rid}/cancel")
def requester_cancel(request: Request, rid: str, token: str):
    """Requester cancels their own request"""
    conn = db()
    req = conn.execute("SELECT access_token, status, print_name FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    # Can only cancel NEW, NEEDS_INFO, or APPROVED requests
    if req["status"] not in ["NEW", "NEEDS_INFO", "APPROVED"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot cancel request in current status")
    
    created = now_iso()
    from_status = req["status"]
    
    conn.execute(
        "UPDATE requests SET status = ?, updated_at = ? WHERE id = ?",
        ("CANCELLED", created, rid)
    )
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, created, from_status, "CANCELLED", "Cancelled by requester")
    )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/my/{rid}?token={token}", status_code=303)


@app.post("/my/{rid}/resubmit")
def requester_resubmit(request: Request, rid: str, token: str):
    """Requester resubmits a cancelled/rejected/picked-up request as a new request"""
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req or req["access_token"] != token:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid access")
    
    # Can only resubmit closed requests
    if req["status"] not in ["CANCELLED", "REJECTED", "PICKED_UP"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Can only resubmit closed requests")
    
    # Create a new request with same details
    new_id = str(uuid.uuid4())
    new_token = secrets.token_urlsafe(32)
    created = now_iso()
    
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, special_notes, print_time_minutes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        new_id, created, created,
        req["requester_name"], req["requester_email"],
        req["printer"], req["material"], req["colors"],
        req["link_url"], req["notes"], req["print_name"],
        "NEW", new_token, 3,  # Reset to default priority P3 for resubmitted requests
        None,  # Clear special_notes for fresh start
        req["print_time_minutes"]  # Keep estimated print time
    ))
    
    # Copy files
    files = conn.execute(
        "SELECT original_filename, stored_filename, size_bytes, sha256 FROM files WHERE request_id = ?",
        (rid,)
    ).fetchall()
    
    for f in files:
        conn.execute(
            "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), new_id, created, f["original_filename"], f["stored_filename"], f["size_bytes"], f["sha256"])
        )
    
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), new_id, created, None, "NEW", f"Resubmitted from request {rid[:8]}")
    )
    
    conn.commit()
    conn.close()
    
    # Redirect to the new request
    return RedirectResponse(url=f"/my/{new_id}?token={new_token}", status_code=303)


# ─────────────────────────── MY REQUESTS LOOKUP ───────────────────────────

@app.get("/my-requests", response_class=HTMLResponse)
def my_requests_lookup(request: Request, sent: Optional[str] = None, error: Optional[str] = None, token: Optional[str] = None):
    """Email lookup form for viewing all requests"""
    # If token provided in URL, redirect to view page (for PWA deep linking)
    if token:
        return RedirectResponse(url=f"/my-requests/view?token={token}", status_code=302)
    
    # Check if user accounts feature is enabled
    user_accounts_enabled = is_feature_enabled("user_accounts")
    
    return templates.TemplateResponse("my_requests_lookup_new.html", {
        "request": request,
        "sent": sent,
        "error": error,
        "version": APP_VERSION,
        "user_accounts_enabled": user_accounts_enabled,
    })


@app.post("/my-requests")
def my_requests_send_link(request: Request, email: str = Form(...)):
    """Send magic link to email for viewing all requests"""
    email = email.strip().lower()
    
    if not email or "@" not in email:
        return RedirectResponse(url="/my-requests?error=invalid", status_code=303)
    
    conn = db()
    
    # Check if this email has any requests
    requests_count = conn.execute(
        "SELECT COUNT(*) FROM requests WHERE LOWER(requester_email) = ?", (email,)
    ).fetchone()[0]
    
    if requests_count == 0:
        conn.close()
        # Don't reveal whether email exists - just say "sent"
        return RedirectResponse(url="/my-requests?sent=1", status_code=303)
    
    # Generate magic link token (expires in 30 days)
    token_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    # Generate a 6-digit short code for PWA sync (expires in 10 minutes)
    short_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    created = now_iso()
    
    # Calculate expiry (30 days from now for token)
    from datetime import timedelta
    expiry = (datetime.utcnow() + timedelta(days=30)).isoformat(timespec="seconds") + "Z"
    
    # Clean up old tokens for this email
    conn.execute("DELETE FROM email_lookup_tokens WHERE email = ?", (email,))
    
    # Insert new token with short code
    conn.execute(
        "INSERT INTO email_lookup_tokens (id, email, token, short_code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (token_id, email, token, short_code, created, expiry)
    )
    conn.commit()
    conn.close()
    
    # Send email with magic link
    magic_link = f"{BASE_URL}/my-requests/view?token={token}"
    subject = f"[{APP_TITLE}] Your Print Requests"
    text = f"Click here to view all your print requests:\n\n{magic_link}\n\nThis link expires in 30 days.\n\nIf you didn't request this, you can ignore this email."
    html = build_email_html(
        title="View Your Requests",
        subtitle="Click below to see all your print requests",
        rows=[
            ("Email", email),
            ("Requests", f"{requests_count} request(s) on file"),
        ],
        cta_url=magic_link,
        cta_label="View My Requests",
        header_color="#6366f1",
        footer_note="This link expires in 30 days. If you didn't request this, you can safely ignore this email.",
    )
    send_email([email], subject, text, html)
    
    return RedirectResponse(url="/my-requests?sent=1", status_code=303)


@app.get("/my-requests/view", response_class=HTMLResponse)
async def my_requests_view(request: Request, token: str):
    """View all requests for an email using magic link"""
    conn = db()
    
    # Find token
    token_row = conn.execute(
        "SELECT email, expires_at FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    
    if not token_row:
        conn.close()
        return templates.TemplateResponse("my_requests_lookup_new.html", {
            "request": request,
            "error": "expired",
            "version": APP_VERSION,
        })
    
    # Check expiry
    expiry = datetime.fromisoformat(token_row["expires_at"].replace("Z", "+00:00"))
    if datetime.utcnow().replace(tzinfo=expiry.tzinfo) > expiry:
        # Token expired - clean up
        conn.execute("DELETE FROM email_lookup_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return templates.TemplateResponse("my_requests_lookup_new.html", {
            "request": request,
            "error": "expired",
            "version": APP_VERSION,
        })
    
    email = token_row["email"]
    
    # Fetch all requests for this email, including multi-build info
    requests_list = conn.execute(
        """SELECT id, print_name, status, created_at, updated_at, printer, material, colors, 
                  access_token, completion_snapshot, printing_started_at, print_time_minutes,
                  active_build_id, total_builds, completed_builds
           FROM requests 
           WHERE LOWER(requester_email) = ?
           ORDER BY 
             CASE WHEN status = 'DONE' THEN 0
                  WHEN status IN ('PRINTING', 'IN_PROGRESS') THEN 1
                  WHEN status = 'NEEDS_INFO' THEN 2
                  ELSE 3 END,
             created_at DESC""",
        (email,)
    ).fetchall()
    
    # Enrich printing/in_progress requests with real-time printer status
    enriched_requests = []
    printer_status_cache = {}
    
    for req in requests_list:
        req_dict = dict(req)
        req_dict["printer_status"] = None
        req_dict["smart_eta_display"] = None
        
        # If printing or in_progress, fetch real-time printer status
        if req["status"] in ["PRINTING", "IN_PROGRESS"]:
            # For IN_PROGRESS, get the printer from the active build
            printer_code = req["printer"]
            printing_started_at = req["printing_started_at"]
            
            if req["status"] == "IN_PROGRESS" and req["active_build_id"]:
                active_build = conn.execute(
                    "SELECT printer, started_at FROM builds WHERE id = ?",
                    (req["active_build_id"],)
                ).fetchone()
                if active_build and active_build["printer"]:
                    printer_code = active_build["printer"]
                    if active_build["started_at"]:
                        printing_started_at = active_build["started_at"]
            
            req_dict["active_printer"] = printer_code  # Track which printer is active
            
            if printer_code:
                # Use cached printer status fetch for consistency and performance
                if printer_code not in printer_status_cache:
                    printer_status_cache[printer_code] = await fetch_printer_status_with_cache(printer_code, timeout=3.0)
                
                req_dict["printer_status"] = printer_status_cache.get(printer_code)
                
                # Calculate smart ETA if not offline
                if req_dict.get("printer_status") and not req_dict["printer_status"].get("is_offline"):
                    eta_dt = get_smart_eta(
                        printer=printer_code,
                        material=req["material"],
                        current_percent=req_dict["printer_status"].get("progress") or 0,
                        printing_started_at=printing_started_at or now_iso(),
                        current_layer=req_dict["printer_status"].get("current_layer") or 0,
                        total_layers=req_dict["printer_status"].get("total_layers") or 0
                    )
                    req_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        
        enriched_requests.append(req_dict)
    
    conn.close()
    
    return templates.TemplateResponse("my_requests_list_new.html", {
        "request": request,
        "email": email,
        "requests_list": enriched_requests,
        "token": token,  # Keep token for refresh
        "version": APP_VERSION,
    })


@app.get("/my-requests/demo", response_class=HTMLResponse)
async def my_requests_demo(request: Request):
    """Demo mode for testing the My Prints page without a real account"""
    from datetime import timedelta
    
    demo_email = "admin@jcubhub.com"
    demo_token = "demo-token-12345"
    
    # Generate fake requests with various statuses
    now = datetime.utcnow()
    fake_requests = [
        {
            "id": "demo-001-done-recent",
            "print_name": "Benchy Test Print",
            "status": "DONE",
            "created_at": (now - timedelta(days=2)).isoformat()[:10],
            "updated_at": (now - timedelta(hours=1)).isoformat(),
            "printer": "P1",
            "material": "PLA",
            "colors": "Blue",
            "access_token": "demo-access-1",
            "completion_snapshot": None,  # No snapshot for demo
            "printing_started_at": None,
            "print_time_minutes": 45,
            "printer_status": None,
            "smart_eta_display": None,
        },
        {
            "id": "demo-002-printing",
            "print_name": "Phone Stand v2",
            "status": "PRINTING",
            "created_at": (now - timedelta(days=1)).isoformat()[:10],
            "updated_at": now.isoformat(),
            "printer": "P2",
            "material": "PETG",
            "colors": "White",
            "access_token": "demo-access-2",
            "completion_snapshot": None,
            "printing_started_at": (now - timedelta(hours=2)).isoformat(),
            "print_time_minutes": 180,
            "printer_status": {
                "status": "BUILDING",
                "is_printing": True,
                "progress": 67,
                "current_layer": 134,
                "total_layers": 200,
                "temp": "215",
                "camera_url": None,
            },
            "smart_eta_display": "~1h 15m remaining",
        },
        {
            "id": "demo-003-approved",
            "print_name": "Cable Organizer Set",
            "status": "APPROVED",
            "created_at": (now - timedelta(hours=6)).isoformat()[:10],
            "updated_at": (now - timedelta(hours=4)).isoformat(),
            "printer": "ANY",
            "material": "PLA",
            "colors": "Black",
            "access_token": "demo-access-3",
            "completion_snapshot": None,
            "printing_started_at": None,
            "print_time_minutes": None,
            "printer_status": None,
            "smart_eta_display": None,
        },
        {
            "id": "demo-004-needs-info",
            "print_name": "Custom Part #47",
            "status": "NEEDS_INFO",
            "created_at": (now - timedelta(hours=12)).isoformat()[:10],
            "updated_at": (now - timedelta(hours=3)).isoformat(),
            "printer": "ANY",
            "material": "ABS",
            "colors": "Red",
            "access_token": "demo-access-4",
            "completion_snapshot": None,
            "printing_started_at": None,
            "print_time_minutes": None,
            "printer_status": None,
            "smart_eta_display": None,
        },
        {
            "id": "demo-005-new",
            "print_name": "Keycap Set",
            "status": "NEW",
            "created_at": (now - timedelta(hours=2)).isoformat()[:10],
            "updated_at": (now - timedelta(hours=2)).isoformat(),
            "printer": "ANY",
            "material": "PLA",
            "colors": "Rainbow",
            "access_token": "demo-access-5",
            "completion_snapshot": None,
            "printing_started_at": None,
            "print_time_minutes": None,
            "printer_status": None,
            "smart_eta_display": None,
        },
        {
            "id": "demo-006-picked-up",
            "print_name": "Desk Toy",
            "status": "PICKED_UP",
            "created_at": (now - timedelta(days=5)).isoformat()[:10],
            "updated_at": (now - timedelta(days=3)).isoformat(),
            "printer": "P1",
            "material": "PLA",
            "colors": "Yellow",
            "access_token": "demo-access-6",
            "completion_snapshot": None,
            "printing_started_at": None,
            "print_time_minutes": 30,
            "printer_status": None,
            "smart_eta_display": None,
        },
        {
            "id": "demo-007-done-old",
            "print_name": "Raspberry Pi Case",
            "status": "DONE",
            "created_at": (now - timedelta(days=7)).isoformat()[:10],
            "updated_at": (now - timedelta(days=6)).isoformat(),
            "printer": "P3",
            "material": "PETG",
            "colors": "Gray",
            "access_token": "demo-access-7",
            "completion_snapshot": None,
            "printing_started_at": None,
            "print_time_minutes": 120,
            "printer_status": None,
            "smart_eta_display": None,
        },
    ]
    
    # Sort like real requests: DONE first, then PRINTING, then NEEDS_INFO, then others
    status_order = {"DONE": 0, "PRINTING": 1, "NEEDS_INFO": 2}
    fake_requests.sort(key=lambda r: (status_order.get(r["status"], 3), r["created_at"]), reverse=False)
    
    return templates.TemplateResponse("my_requests_list_new.html", {
        "request": request,
        "email": demo_email,
        "requests_list": fake_requests,
        "token": demo_token,
        "version": APP_VERSION,
    })


# API endpoint to verify short code (for PWA session sync)
@app.post("/api/verify-code")
def verify_short_code(code: str = Form(...)):
    """Verify a 6-digit short code and return the token for PWA sync"""
    code = code.strip()
    
    if not code or len(code) != 6 or not code.isdigit():
        return {"success": False, "error": "Invalid code format"}
    
    conn = db()
    
    # Find token by short code (only valid for 10 minutes after creation)
    from datetime import timedelta
    ten_mins_ago = (datetime.utcnow() - timedelta(minutes=10)).isoformat(timespec="seconds") + "Z"
    
    token_row = conn.execute(
        """SELECT token, email, expires_at FROM email_lookup_tokens 
           WHERE short_code = ? AND created_at > ?""",
        (code, ten_mins_ago)
    ).fetchone()
    
    if not token_row:
        conn.close()
        return {"success": False, "error": "Invalid or expired code"}
    
    # Check token hasn't expired
    expiry = datetime.fromisoformat(token_row["expires_at"].replace("Z", "+00:00"))
    if datetime.utcnow().replace(tzinfo=expiry.tzinfo) > expiry:
        conn.close()
        return {"success": False, "error": "Session expired"}
    
    # Clear the short code after use (one-time use)
    conn.execute("UPDATE email_lookup_tokens SET short_code = NULL WHERE short_code = ?", (code,))
    conn.commit()
    conn.close()
    
    return {
        "success": True, 
        "token": token_row["token"],
        "email": token_row["email"]
    }


# API endpoint to generate a new short code for an existing session
@app.post("/api/generate-sync-code")
def generate_sync_code(token: str = Form(...)):
    """Generate a new 6-digit code for an authenticated session"""
    conn = db()
    
    token_row = conn.execute(
        "SELECT id, expires_at FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    
    if not token_row:
        conn.close()
        return {"success": False, "error": "Invalid session"}
    
    # Check not expired
    expiry = datetime.fromisoformat(token_row["expires_at"].replace("Z", "+00:00"))
    if datetime.utcnow().replace(tzinfo=expiry.tzinfo) > expiry:
        conn.close()
        return {"success": False, "error": "Session expired"}
    
    # Generate new short code
    short_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    # Update the token with new short code and refresh created_at for 10-min window
    conn.execute(
        "UPDATE email_lookup_tokens SET short_code = ?, created_at = ? WHERE id = ?",
        (short_code, now_iso(), token_row["id"])
    )
    conn.commit()
    conn.close()
    
    return {"success": True, "code": short_code, "expires_in": 600}  # 10 minutes in seconds


# ─────────────────────────── QUEUE API ───────────────────────────

@app.get("/api/queue")
async def queue_data_api(mine: Optional[str] = None):
    """JSON API for queue data (used for AJAX refresh)"""
    conn = db()
    rows = conn.execute(
        """SELECT id, requester_name, print_name, printer, material, colors, status, special_notes, 
                  print_time_minutes, turnaround_minutes, printing_started_at,
                  active_build_id, total_builds, completed_builds
           FROM requests 
           WHERE status NOT IN (?, ?, ?) 
           ORDER BY created_at ASC""",
        ("PICKED_UP", "REJECTED", "CANCELLED")
    ).fetchall()
    conn.close()

    items = []
    
    # Fetch current printer status using cache with timeout
    printer_status = {}
    for printer_code in ["ADVENTURER_4", "AD5X", "P1S"]:
        printer_status[printer_code] = await fetch_printer_status_with_cache(printer_code, timeout=3.0)
    
    # Build items list
    for idx, r in enumerate(rows):
        short_id = r["id"][:8]
        printer_progress = None
        smart_eta_display = None
        current_layer = None
        total_layers = None
        printing_started_at = r["printing_started_at"] if "printing_started_at" in r.keys() else None
        active_printer = r["printer"]  # Default to request printer
        
        # Handle IN_PROGRESS (multi-build) - get active build's printer
        active_build_id = r["active_build_id"] if "active_build_id" in r.keys() else None
        if r["status"] == "IN_PROGRESS" and active_build_id:
            conn_build = db()
            active_build = conn_build.execute(
                "SELECT printer, started_at FROM builds WHERE id = ?", 
                (active_build_id,)
            ).fetchone()
            conn_build.close()
            if active_build and active_build["printer"]:
                active_printer = active_build["printer"]
                if active_build["started_at"]:
                    printing_started_at = active_build["started_at"]
        
        if r["status"] in ["PRINTING", "IN_PROGRESS"]:
            # Use cached printer status
            cached_status = printer_status.get(active_printer, {})
            
            if cached_status and not cached_status.get("is_offline"):
                printer_progress = cached_status.get("progress")
                current_layer = cached_status.get("current_layer")
                total_layers = cached_status.get("total_layers")
            
            # Calculate smart ETA
            if printing_started_at:
                eta_dt = get_smart_eta(
                    printer=active_printer,
                    material=r["material"],
                    current_percent=printer_progress or 0,
                    printing_started_at=printing_started_at,
                    current_layer=current_layer or 0,
                    total_layers=total_layers or 0
                )
                if eta_dt:
                    smart_eta_display = format_eta_display(eta_dt)
        
        items.append({
            "short_id": short_id,
            "request_id": r["id"],  # Full ID for lookups
            "requester_first": first_name_only(r["requester_name"]),
            "print_name": r["print_name"],
            "printer": active_printer,
            "material": r["material"],
            "colors": r["colors"],
            "status": r["status"],
            "is_mine": bool(mine and mine == short_id),
            "printer_progress": printer_progress,
            "smart_eta_display": smart_eta_display,
            "current_layer": current_layer,
            "total_layers": total_layers,
            "total_builds": r["total_builds"] if "total_builds" in r.keys() else 1,
            "completed_builds": r["completed_builds"] if "completed_builds" in r.keys() else 0,
        })
    
    # Separate by status - include IN_PROGRESS for multi-build requests
    printing_items = [it for it in items if it["status"] in ["PRINTING", "IN_PROGRESS"]]
    approved_items = [it for it in items if it["status"] == "APPROVED"]
    done_items = [it for it in items if it["status"] == "DONE"]
    
    # Build active queue with continuous numbering
    active_queue = printing_items + approved_items
    for idx, item in enumerate(active_queue):
        item["queue_pos"] = idx + 1
    
    # Group printing items by printer (for printer card display)
    # For multi-build requests, query all PRINTING builds to find which printers are active
    printing_by_printer = {
        "ADVENTURER_4": None,
        "AD5X": None,
    }
    
    # Query all builds that are currently PRINTING to handle multi-printer scenarios
    conn_builds = db()
    printing_builds = conn_builds.execute("""
        SELECT b.*, r.requester_name, r.print_name as request_print_name, r.material as request_material,
               r.total_builds, r.completed_builds, r.id as request_id
        FROM builds b
        JOIN requests r ON b.request_id = r.id
        WHERE b.status = 'PRINTING'
    """).fetchall()
    conn_builds.close()
    
    # Map request IDs to items for quick lookup
    items_by_request_id = {it["request_id"]: it for it in items}
    
    # Create printer card entries from PRINTING builds
    for build in printing_builds:
        build_printer = build["printer"]
        if build_printer in printing_by_printer and printing_by_printer[build_printer] is None:
            request_id = build["request_id"]
            parent_item = items_by_request_id.get(request_id)
            
            if parent_item:
                # Get progress from cached printer status
                cached_status = printer_status.get(build_printer, {})
                build_progress = None
                build_layer = None
                build_total_layers = None
                build_eta_display = None
                
                if cached_status and not cached_status.get("is_offline"):
                    build_progress = cached_status.get("progress")
                    build_layer = cached_status.get("current_layer")
                    build_total_layers = cached_status.get("total_layers")
                    
                    # Calculate ETA for this specific build
                    started_at = build["started_at"]
                    if started_at:
                        eta_dt = get_smart_eta(
                            printer=build_printer,
                            material=build["material"] or parent_item["material"],
                            current_percent=build_progress or 0,
                            printing_started_at=started_at,
                            current_layer=build_layer or 0,
                            total_layers=build_total_layers or 0
                        )
                        if eta_dt:
                            build_eta_display = format_eta_display(eta_dt)
                
                # Create entry for this printer
                printer_entry = dict(parent_item)
                printer_entry["printer"] = build_printer
                printer_entry["printer_progress"] = build_progress
                printer_entry["current_layer"] = build_layer
                printer_entry["total_layers"] = build_total_layers
                printer_entry["smart_eta_display"] = build_eta_display
                printer_entry["build_number"] = build["build_number"]
                printer_entry["build_print_name"] = build["print_name"]
                # Find queue_pos from parent item
                printer_entry["queue_pos"] = parent_item.get("queue_pos", 1)
                printing_by_printer[build_printer] = printer_entry
    
    # Fallback for single-build requests or legacy PRINTING status
    for pit in printing_items:
        if pit["printer"] in printing_by_printer and printing_by_printer[pit["printer"]] is None:
            printing_by_printer[pit["printer"]] = pit
    
    # Find user's position
    my_pos = None
    if mine:
        for it in active_queue:
            if it["short_id"] == mine:
                my_pos = it["queue_pos"]
                break
    
    # Counts - include IN_PROGRESS in PRINTING count for display
    counts = {"NEW": 0, "NEEDS_INFO": 0, "APPROVED": 0, "PRINTING": 0, "IN_PROGRESS": 0, "DONE": 0}
    for it in items:
        if it["status"] in counts:
            counts[it["status"]] += 1
    
    # Count actual printing builds (not just requests) for more accurate "Printing" stat
    printing_builds_count = sum(1 for p in printing_by_printer.values() if p is not None and not p.get("_likely_printing"))
    counts["PRINTING_BUILDS"] = printing_builds_count
    
    return {
        "active_queue": active_queue,
        "done_items": done_items,
        "counts": counts,
        "my_pos": my_pos,
        "printer_status": printer_status,
        "printing_by_printer": printing_by_printer,  # Add this for printer card updates
        "timestamp": now_iso(),
    }


@app.get("/changelog", response_class=HTMLResponse)
def changelog(request: Request):
    """Version history and release notes"""
    return templates.TemplateResponse("changelog.html", {"request": request, "version": APP_VERSION})


# ─────────────────────────── FEEDBACK (Bug Reports & Suggestions) ───────────────────────────

@app.get("/feedback", response_class=HTMLResponse)
def feedback_form(request: Request, type: str = "bug", submitted: Optional[str] = None):
    """Form for submitting bug reports or suggestions"""
    feedback_type = type if type in ("bug", "suggestion") else "bug"
    return templates.TemplateResponse("feedback_form.html", {
        "request": request,
        "feedback_type": feedback_type,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "submitted": submitted == "1",
        "version": APP_VERSION,
    })


@app.post("/feedback")
async def feedback_submit(
    request: Request,
    feedback_type: str = Form(...),
    name: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    message: str = Form(...),
    page_url: Optional[str] = Form(None),
    turnstile_token: Optional[str] = Form(None, alias="cf-turnstile-response"),
):
    """Submit bug report or suggestion"""
    # Verify Turnstile
    ok = await verify_turnstile(turnstile_token or "", request.client.host if request.client else None)
    if not ok:
        return templates.TemplateResponse("feedback_form.html", {
            "request": request,
            "feedback_type": feedback_type,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "error": "Please complete the security check.",
            "form_data": {"name": name, "email": email, "message": message},
            "version": APP_VERSION,
        })
    
    # Validate
    if not message or len(message.strip()) < 10:
        return templates.TemplateResponse("feedback_form.html", {
            "request": request,
            "feedback_type": feedback_type,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "error": "Please provide a more detailed message (at least 10 characters).",
            "form_data": {"name": name, "email": email, "message": message},
            "version": APP_VERSION,
        })
    
    if feedback_type not in ("bug", "suggestion"):
        feedback_type = "bug"
    
    # Get user agent
    user_agent = request.headers.get("user-agent", "")[:500]
    
    # Save to database
    conn = db()
    feedback_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO feedback (id, type, name, email, message, page_url, user_agent, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)""",
        (feedback_id, feedback_type, name, email, message.strip(), page_url, user_agent, now_iso())
    )
    conn.commit()
    conn.close()
    
    # Send admin notification email
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails:
        type_label = "🐛 Bug Report" if feedback_type == "bug" else "💡 Suggestion"
        subject = f"[{APP_TITLE}] {type_label} Submitted"
        
        rows = [
            ("Type", type_label),
            ("From", name or "Anonymous"),
        ]
        if email:
            rows.append(("Email", email))
        rows.append(("Message", message[:200] + "..." if len(message) > 200 else message))
        if page_url:
            rows.append(("Page", page_url))
        
        text = f"{type_label}\n\nFrom: {name or 'Anonymous'}\nEmail: {email or 'N/A'}\n\nMessage:\n{message}\n"
        html = build_email_html(
            title=type_label,
            subtitle="New feedback submitted",
            rows=rows,
            cta_url=f"{BASE_URL}/admin/feedback",
            cta_label="View Feedback",
            header_color="#8b5cf6" if feedback_type == "suggestion" else "#ef4444",
        )
        send_email(admin_emails, subject, text, html)
    
    return RedirectResponse(url=f"/feedback?type={feedback_type}&submitted=1", status_code=303)


@app.get("/admin/feedback", response_class=HTMLResponse)
def admin_feedback_list(request: Request, status: Optional[str] = None, type: Optional[str] = None, _=Depends(require_admin)):
    """Admin view of all feedback"""
    conn = db()
    
    # Build query with optional filters
    where_clauses = []
    params = []
    
    if status and status in ("new", "reviewed", "resolved", "dismissed"):
        where_clauses.append("status = ?")
        params.append(status)
    
    if type and type in ("bug", "suggestion"):
        where_clauses.append("type = ?")
        params.append(type)
    
    where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    feedback = conn.execute(
        f"SELECT * FROM feedback{where_sql} ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'reviewed' THEN 1 ELSE 2 END, created_at DESC",
        params
    ).fetchall()
    
    # Count by status
    counts = conn.execute("""
        SELECT status, COUNT(*) as count FROM feedback GROUP BY status
    """).fetchall()
    conn.close()
    
    status_counts = {row["status"]: row["count"] for row in counts}
    
    return templates.TemplateResponse("admin_feedback.html", {
        "request": request,
        "feedback": feedback,
        "status_filter": status,
        "type_filter": type,
        "status_counts": status_counts,
        "version": APP_VERSION,
    })


@app.post("/admin/feedback/{fid}/status")
def admin_feedback_update(
    request: Request,
    fid: str,
    status: str = Form(...),
    admin_notes: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Update feedback status"""
    if status not in ("new", "reviewed", "resolved", "dismissed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    
    conn = db()
    feedback = conn.execute("SELECT * FROM feedback WHERE id = ?", (fid,)).fetchone()
    if not feedback:
        conn.close()
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    resolved_at = now_iso() if status == "resolved" else None
    
    conn.execute(
        "UPDATE feedback SET status = ?, admin_notes = ?, resolved_at = ? WHERE id = ?",
        (status, admin_notes, resolved_at, fid)
    )
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin/feedback", status_code=303)


@app.post("/admin/feedback/{fid}/delete")
def admin_feedback_delete(fid: str, _=Depends(require_admin)):
    """Permanently delete feedback"""
    conn = db()
    feedback = conn.execute("SELECT * FROM feedback WHERE id = ?", (fid,)).fetchone()
    if not feedback:
        conn.close()
        raise HTTPException(status_code=404, detail="Feedback not found")
    
    conn.execute("DELETE FROM feedback WHERE id = ?", (fid,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin/feedback", status_code=303)


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login(request: Request, next: Optional[str] = None):
    return templates.TemplateResponse("admin_login.html", {"request": request, "next": next})


@app.post("/admin/login")
def admin_login_post(password: str = Form(...), next: Optional[str] = Form(None)):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD is not set")
    if password != ADMIN_PASSWORD:
        # Preserve the next parameter on failed login
        redirect_url = "/admin/login?bad=1"
        if next:
            from urllib.parse import quote
            redirect_url += f"&next={quote(next)}"
        return RedirectResponse(url=redirect_url, status_code=303)

    # Redirect to next URL if provided, otherwise admin dashboard
    redirect_to = next if next and next.startswith("/admin") else "/admin"
    resp = RedirectResponse(url=redirect_to, status_code=303)
    # Set cookie with path=/ to ensure it's sent for all routes
    # secure=True only when running over HTTPS (production)
    is_https = BASE_URL.startswith("https://")
    resp.set_cookie(
        "admin_pw", 
        password, 
        httponly=True, 
        samesite="lax", 
        secure=is_https,  # Only require HTTPS in production
        path="/",  # Ensure cookie is sent for all routes
        max_age=604800  # 7 days
    )
    return resp


@app.get("/admin/logout")
def admin_logout():
    """Clear admin session cookie and redirect to home."""
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("admin_pw", path="/")  # Must match path used when setting
    return resp


def _fetch_requests_by_status(statuses, include_eta_fields: bool = False):
    """Fetch requests by status. statuses can be a string or list of statuses."""
    if isinstance(statuses, str):
        statuses = [statuses]
    
    placeholders = ",".join("?" * len(statuses))
    conn = db()
    if include_eta_fields:
        rows = conn.execute(
            f"""SELECT r.id, r.created_at, r.requester_name, r.printer, r.material, r.colors, 
                      r.link_url, r.status, r.priority, r.special_notes, r.printing_started_at,
                      r.print_name, r.total_builds, r.completed_builds, r.failed_builds,
                      (SELECT COUNT(*) FROM files f WHERE f.request_id = r.id) as file_count,
                      (SELECT GROUP_CONCAT(f.original_filename, ', ') FROM files f WHERE f.request_id = r.id) as file_names,
                      (SELECT COUNT(*) FROM request_messages m WHERE m.request_id = r.id AND m.sender_type = 'requester' AND m.is_read = 0) as unread_replies
               FROM requests r
               WHERE r.status IN ({placeholders}) 
               ORDER BY r.priority ASC, r.created_at ASC""",
            statuses
        ).fetchall()
    else:
        rows = conn.execute(
            f"""SELECT r.id, r.created_at, r.requester_name, r.printer, r.material, r.colors, 
                      r.link_url, r.status, r.priority, r.special_notes,
                      r.print_name, r.total_builds, r.completed_builds, r.failed_builds,
                      (SELECT COUNT(*) FROM files f WHERE f.request_id = r.id) as file_count,
                      (SELECT GROUP_CONCAT(f.original_filename, ', ') FROM files f WHERE f.request_id = r.id) as file_names,
                      (SELECT COUNT(*) FROM request_messages m WHERE m.request_id = r.id AND m.sender_type = 'requester' AND m.is_read = 0) as unread_replies
               FROM requests r
               WHERE r.status IN ({placeholders}) 
               ORDER BY r.priority ASC, r.created_at ASC""",
            statuses
        ).fetchall()
    conn.close()
    return rows


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, _=Depends(require_admin)):
    # Fetch NEW and NEEDS_INFO together for "needs attention" section
    new_reqs = _fetch_requests_by_status(["NEW", "NEEDS_INFO"])
    queued = _fetch_requests_by_status("APPROVED")
    # Include IN_PROGRESS for multi-build requests that have active builds
    printing_raw = _fetch_requests_by_status(["PRINTING", "IN_PROGRESS"], include_eta_fields=True)
    done = _fetch_requests_by_status("DONE")
    
    # Enrich printing requests with smart ETA
    printing = []
    for r in printing_raw:
        # Get current progress from printer for smart ETA calculation
        printer_progress = None
        current_layer = None
        total_layers = None
        active_printer = r["printer"]  # Default to request printer
        printing_started_at = r["printing_started_at"] if "printing_started_at" in r.keys() else None
        
        # Handle IN_PROGRESS (multi-build) - get active build's printer
        if r["status"] == "IN_PROGRESS":
            conn_build = db()
            active_build = conn_build.execute(
                """SELECT b.printer, b.started_at FROM builds b 
                   WHERE b.request_id = ? AND b.status = 'PRINTING' 
                   LIMIT 1""", 
                (r["id"],)
            ).fetchone()
            conn_build.close()
            if active_build and active_build["printer"]:
                active_printer = active_build["printer"]
                if active_build["started_at"]:
                    printing_started_at = active_build["started_at"]
        
        # Use cached printer status for consistency
        cached_status = await fetch_printer_status_with_cache(active_printer, timeout=3.0)
        if cached_status and not cached_status.get("is_offline"):
            printer_progress = cached_status.get("progress")
            current_layer = cached_status.get("current_layer")
            total_layers = cached_status.get("total_layers")
        
        # If printing_started_at is missing, set it now (for legacy requests)
        if not printing_started_at and r["status"] in ["PRINTING", "IN_PROGRESS"]:
            printing_started_at = now_iso()
            conn_fix = db()
            conn_fix.execute("UPDATE requests SET printing_started_at = ? WHERE id = ? AND printing_started_at IS NULL", 
                           (printing_started_at, r["id"]))
            conn_fix.commit()
            conn_fix.close()
        
        # Calculate smart ETA based on layers (preferred) or progress
        eta_dt = get_smart_eta(
            printer=active_printer,
            material=r["material"],
            current_percent=printer_progress,
            printing_started_at=printing_started_at,
            current_layer=current_layer,
            total_layers=total_layers
        )
        
        # Convert to dict and add ETA fields
        row_dict = dict(r)
        row_dict["smart_eta"] = eta_dt.isoformat() if eta_dt else None
        row_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        row_dict["printer_progress"] = printer_progress
        row_dict["active_printer"] = active_printer  # For display
        printing.append(row_dict)

    conn = db()
    closed = conn.execute(
        """SELECT r.id, r.created_at, r.requester_name, r.printer, r.material, r.colors, 
                  r.link_url, r.status, r.priority, r.special_notes, r.print_name
           FROM requests r
           WHERE r.status IN (?, ?, ?) 
           ORDER BY r.updated_at DESC 
           LIMIT 30""",
        ("PICKED_UP", "REJECTED", "CANCELLED")
    ).fetchall()
    conn.close()

    # Fetch printer status using cache with timeout
    printer_status = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        printer_status[printer_code] = await fetch_printer_status_with_cache(printer_code, timeout=3.0)

    # Get print match suggestions
    print_match_suggestions = get_print_match_suggestions()

    return templates.TemplateResponse("admin_queue.html", {
        "request": request,
        "new_reqs": new_reqs,
        "queued": queued,
        "printing": printing,
        "done": done,
        "closed": closed,
        "printer_status": {
            "ADVENTURER_4": printer_status.get("ADVENTURER_4", {}),
            "AD5X": printer_status.get("AD5X", {}),
        },
        "print_match_suggestions": print_match_suggestions,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "version": APP_VERSION,
    })


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request, _=Depends(require_admin), saved: Optional[str] = None):
    model = {
        "admin_notify_emails": get_setting("admin_notify_emails", ""),
        "admin_email_on_submit": get_bool_setting("admin_email_on_submit", True),
        "admin_email_on_status": get_bool_setting("admin_email_on_status", True),
        "requester_email_on_submit": get_bool_setting("requester_email_on_submit", False),
        "requester_email_on_status": get_bool_setting("requester_email_on_status", True),
        # Per-status notifications for requesters (default to enabled)
        "notify_requester_needs_info": get_setting("notify_requester_needs_info", "1"),
        "notify_requester_approved": get_setting("notify_requester_approved", "1"),
        "notify_requester_printing": get_setting("notify_requester_printing", "1"),
        "notify_requester_done": get_setting("notify_requester_done", "1"),
        "notify_requester_picked_up": get_setting("notify_requester_picked_up", "1"),
        "notify_requester_rejected": get_setting("notify_requester_rejected", "1"),
        "notify_requester_cancelled": get_setting("notify_requester_cancelled", "1"),
        # Per-status notifications for admins (default to enabled)
        "notify_admin_needs_info": get_setting("notify_admin_needs_info", "1"),
        "notify_admin_approved": get_setting("notify_admin_approved", "1"),
        "notify_admin_printing": get_setting("notify_admin_printing", "1"),
        "notify_admin_done": get_setting("notify_admin_done", "1"),
        "notify_admin_picked_up": get_setting("notify_admin_picked_up", "1"),
        "notify_admin_rejected": get_setting("notify_admin_rejected", "1"),
        "notify_admin_cancelled": get_setting("notify_admin_cancelled", "1"),
        # Rush settings
        "enable_rush_option": get_bool_setting("enable_rush_option", True),
        "rush_fee_amount": get_setting("rush_fee_amount", "5"),
        "venmo_handle": get_setting("venmo_handle", "@YourVenmoHandle"),
        "saved": bool(saved == "1"),
    }
    return templates.TemplateResponse("admin_settings.html", {"request": request, "s": model, "version": APP_VERSION})


@app.post("/admin/settings")
def admin_settings_post(
    request: Request,
    admin_notify_emails: str = Form(""),
    admin_email_on_submit: Optional[str] = Form(None),
    admin_email_on_status: Optional[str] = Form(None),
    requester_email_on_submit: Optional[str] = Form(None),
    requester_email_on_status: Optional[str] = Form(None),
    # Per-status notifications for requesters
    notify_requester_needs_info: Optional[str] = Form(None),
    notify_requester_approved: Optional[str] = Form(None),
    notify_requester_printing: Optional[str] = Form(None),
    notify_requester_done: Optional[str] = Form(None),
    notify_requester_picked_up: Optional[str] = Form(None),
    notify_requester_rejected: Optional[str] = Form(None),
    notify_requester_cancelled: Optional[str] = Form(None),
    # Per-status notifications for admins
    notify_admin_needs_info: Optional[str] = Form(None),
    notify_admin_approved: Optional[str] = Form(None),
    notify_admin_printing: Optional[str] = Form(None),
    notify_admin_done: Optional[str] = Form(None),
    notify_admin_picked_up: Optional[str] = Form(None),
    notify_admin_rejected: Optional[str] = Form(None),
    notify_admin_cancelled: Optional[str] = Form(None),
    # Rush settings
    enable_rush_option: Optional[str] = Form(None),
    rush_fee_amount: str = Form("5"),
    venmo_handle: str = Form("@YourVenmoHandle"),
    _=Depends(require_admin),
):
    # checkboxes: present => "on", missing => None
    set_setting("admin_notify_emails", (admin_notify_emails or "").strip())
    set_setting("admin_email_on_submit", "1" if admin_email_on_submit else "0")
    set_setting("admin_email_on_status", "1" if admin_email_on_status else "0")
    set_setting("requester_email_on_submit", "1" if requester_email_on_submit else "0")
    set_setting("requester_email_on_status", "1" if requester_email_on_status else "0")
    # Per-status notifications for requesters
    set_setting("notify_requester_needs_info", "1" if notify_requester_needs_info else "0")
    set_setting("notify_requester_approved", "1" if notify_requester_approved else "0")
    set_setting("notify_requester_printing", "1" if notify_requester_printing else "0")
    set_setting("notify_requester_done", "1" if notify_requester_done else "0")
    set_setting("notify_requester_picked_up", "1" if notify_requester_picked_up else "0")
    set_setting("notify_requester_rejected", "1" if notify_requester_rejected else "0")
    set_setting("notify_requester_cancelled", "1" if notify_requester_cancelled else "0")
    # Per-status notifications for admins
    set_setting("notify_admin_needs_info", "1" if notify_admin_needs_info else "0")
    set_setting("notify_admin_approved", "1" if notify_admin_approved else "0")
    set_setting("notify_admin_printing", "1" if notify_admin_printing else "0")
    set_setting("notify_admin_done", "1" if notify_admin_done else "0")
    set_setting("notify_admin_picked_up", "1" if notify_admin_picked_up else "0")
    set_setting("notify_admin_rejected", "1" if notify_admin_rejected else "0")
    set_setting("notify_admin_cancelled", "1" if notify_admin_cancelled else "0")
    # Rush settings
    set_setting("enable_rush_option", "1" if enable_rush_option else "0")
    set_setting("rush_fee_amount", (rush_fee_amount or "5").strip())
    set_setting("venmo_handle", (venmo_handle or "").strip())

    return RedirectResponse(url="/admin/settings?saved=1", status_code=303)


@app.get("/admin/analytics", response_class=HTMLResponse)
def admin_analytics(request: Request, _=Depends(require_admin)):
    """Print analytics and history dashboard"""
    conn = db()
    
    # Total stats
    all_reqs = conn.execute("SELECT * FROM requests").fetchall()
    
    # By status
    by_status = {}
    for status in ["NEW", "APPROVED", "PRINTING", "DONE", "PICKED_UP", "REJECTED", "CANCELLED"]:
        count = conn.execute("SELECT COUNT(*) as c FROM requests WHERE status = ?", (status,)).fetchone()["c"]
        by_status[status] = count
    
    # By printer
    by_printer = {}
    for printer in ["ANY", "ADVENTURER_4", "AD5X"]:
        count = conn.execute("SELECT COUNT(*) as c FROM requests WHERE printer = ?", (printer,)).fetchone()["c"]
        by_printer[printer] = count
    
    # By material
    by_material = {}
    for material in ["ANY", "PLA", "PETG", "ABS", "TPU", "RESIN", "OTHER"]:
        count = conn.execute("SELECT COUNT(*) as c FROM requests WHERE material = ?", (material,)).fetchone()["c"]
        by_material[material] = count
    
    # Monthly activity (last 30 days)
    month_ago = (datetime.now() - __import__('datetime').timedelta(days=30)).isoformat()
    month_reqs = conn.execute(
        "SELECT COUNT(*) as c FROM requests WHERE created_at > ?",
        (month_ago,)
    ).fetchone()["c"]
    
    # Average print time
    avg_time = conn.execute(
        "SELECT AVG(print_time_minutes) as avg FROM requests WHERE print_time_minutes IS NOT NULL AND print_time_minutes > 0"
    ).fetchone()["avg"]
    avg_mins = int(avg_time) if avg_time else 0
    avg_hours = avg_mins // 60
    avg_mins = avg_mins % 60
    
    # Completed (DONE + PICKED_UP)
    completed = conn.execute(
        "SELECT COUNT(*) as c FROM requests WHERE status IN (?, ?)",
        ("DONE", "PICKED_UP")
    ).fetchone()["c"]
    
    # Top requesters
    top_requesters = conn.execute("""
        SELECT requester_name as name, requester_email as email, 
               COUNT(*) as total,
               SUM(CASE WHEN status IN ('DONE', 'PICKED_UP') THEN 1 ELSE 0 END) as completed
        FROM requests
        GROUP BY requester_email
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """).fetchall()
    
    # Recent events
    recent_events = conn.execute("""
        SELECT se.created_at, se.from_status, se.to_status, r.id
        FROM status_events se
        JOIN requests r ON se.request_id = r.id
        ORDER BY se.created_at DESC
        LIMIT 20
    """).fetchall()
    
    conn.close()
    
    # Format data
    formatted_requesters = []
    for req in top_requesters:
        total = req["total"]
        completed_cnt = req["completed"]
        success = int(completed_cnt / total * 100) if total > 0 else 0
        formatted_requesters.append({
            "name": req["name"],
            "email": req["email"],
            "total": total,
            "completed": completed_cnt,
            "success_rate": success,
        })
    
    formatted_events = []
    for evt in recent_events:
        from_to = f"{evt['from_status'] or 'NEW'} → {evt['to_status']}"
        formatted_events.append({
            "time": evt["created_at"][:16],  # YYYY-MM-DD HH:MM
            "action": f"Request {evt['id'][:8]}: {from_to}",
        })
    
    stats = {
        "total_requests": len(all_reqs),
        "completed": completed,
        "avg_print_time_hours": avg_hours,
        "avg_print_time_mins": avg_mins,
        "month_requests": month_reqs,
        "by_status": by_status,
        "by_printer": {k: v for k, v in by_printer.items() if v > 0},
        "by_material": {k: v for k, v in by_material.items() if v > 0},
        "top_requesters": formatted_requesters,
        "recent_events": formatted_events,
    }
    
    # Print history learning data
    conn2 = db()
    ph_overall = conn2.execute("""
        SELECT AVG(duration_minutes) as avg_minutes,
               MIN(duration_minutes) as min_minutes,
               MAX(duration_minutes) as max_minutes,
               COUNT(*) as count,
               AVG(total_layers) as avg_layers,
               MAX(total_layers) as max_layers
        FROM print_history
    """).fetchone()
    
    ph_by_printer = conn2.execute("""
        SELECT printer, 
               AVG(duration_minutes) as avg_minutes,
               AVG(total_layers) as avg_layers,
               COUNT(*) as count
        FROM print_history
        GROUP BY printer
    """).fetchall()
    
    # Slicer accuracy data
    accuracy_stats = conn2.execute("""
        SELECT printer, material,
               AVG(CAST(duration_minutes AS FLOAT) / NULLIF(estimated_minutes, 0)) as avg_factor,
               COUNT(*) as sample_count
        FROM print_history
        WHERE estimated_minutes IS NOT NULL AND estimated_minutes > 0
              AND duration_minutes IS NOT NULL AND duration_minutes > 0
        GROUP BY printer, material
        ORDER BY sample_count DESC
    """).fetchall()
    
    conn2.close()
    
    stats["print_history"] = {
        "count": ph_overall["count"] if ph_overall else 0,
        "avg_minutes": int(ph_overall["avg_minutes"]) if ph_overall and ph_overall["avg_minutes"] else None,
        "min_minutes": int(ph_overall["min_minutes"]) if ph_overall and ph_overall["min_minutes"] else None,
        "max_minutes": int(ph_overall["max_minutes"]) if ph_overall and ph_overall["max_minutes"] else None,
        "avg_layers": int(ph_overall["avg_layers"]) if ph_overall and ph_overall["avg_layers"] else None,
        "max_layers": int(ph_overall["max_layers"]) if ph_overall and ph_overall["max_layers"] else None,
        "by_printer": [
            {
                "printer": p["printer"], 
                "avg_minutes": int(p["avg_minutes"]) if p["avg_minutes"] else None, 
                "avg_layers": int(p["avg_layers"]) if p["avg_layers"] else None,
                "count": p["count"]
            }
            for p in ph_by_printer
        ] if ph_by_printer else [],
    }
    
    # Format accuracy stats
    stats["slicer_accuracy"] = []
    for row in accuracy_stats:
        factor = row["avg_factor"]
        if factor:
            if factor > 1.1:
                diff_pct = int((factor - 1) * 100)
                msg = f"{diff_pct}% longer than slicer"
            elif factor < 0.9:
                diff_pct = int((1 - factor) * 100)
                msg = f"{diff_pct}% faster than slicer"
            else:
                msg = "Accurate"
            
            stats["slicer_accuracy"].append({
                "printer": row["printer"] or "Any",
                "material": row["material"] or "Any",
                "factor": round(factor, 2),
                "message": msg,
                "sample_count": row["sample_count"]
            })
    
    return templates.TemplateResponse("admin_analytics.html", {
        "request": request,
        "stats": stats,
        "version": APP_VERSION,
    })


@app.get("/admin/debug", response_class=HTMLResponse)
def admin_debug(request: Request, _=Depends(require_admin)):
    """Polling debug logs for troubleshooting"""
    logs = get_poll_debug_log()
    
    # Get polling pause status for each printer
    polling_status = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        polling_status[printer_code] = {
            "paused": is_polling_paused(printer_code),
            "paused_until": _polling_paused_until.get(printer_code)
        }
    
    return templates.TemplateResponse("admin_debug.html", {
        "request": request,
        "logs": logs,
        "printer_cache": _printer_status_cache,
        "failure_counts": _printer_failure_count,
        "polling_status": polling_status,
        "version": APP_VERSION,
    })


@app.post("/api/admin/pause-polling/{printer_code}")
def api_pause_polling(printer_code: str, duration: int = 60, _=Depends(require_admin)):
    """
    Pause polling for a specific printer.
    Useful when manually sending files to the printer.
    
    Args:
        printer_code: ADVENTURER_4 or AD5X
        duration: Pause duration in seconds (default 60, max 300)
    """
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    # Cap duration at 5 minutes
    duration = min(duration, 300)
    
    pause_printer_polling(printer_code, duration)
    return {"success": True, "printer": printer_code, "paused_for": duration}


@app.post("/api/admin/resume-polling/{printer_code}")
def api_resume_polling(printer_code: str, _=Depends(require_admin)):
    """Resume polling for a specific printer immediately."""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    resume_printer_polling(printer_code)
    return {"success": True, "printer": printer_code, "resumed": True}


# ─────────────────────────── BROADCAST NOTIFICATIONS ───────────────────────────

@app.get("/admin/broadcast", response_class=HTMLResponse)
def admin_broadcast_page(request: Request, _=Depends(require_admin)):
    """Admin page for sending broadcast notifications to all subscribers"""
    conn = db()
    
    # Get unique subscriber count
    subscriber_count = conn.execute(
        "SELECT COUNT(DISTINCT email) as c FROM push_subscriptions"
    ).fetchone()["c"]
    
    # Get total subscription count (includes multiple devices per user)
    total_subscriptions = conn.execute(
        "SELECT COUNT(*) as c FROM push_subscriptions"
    ).fetchone()["c"]
    
    # Get subscriber breakdown (email + device count)
    subscribers = conn.execute("""
        SELECT email, COUNT(*) as device_count 
        FROM push_subscriptions 
        GROUP BY email 
        ORDER BY device_count DESC, email
    """).fetchall()
    
    conn.close()
    
    # Get broadcast history
    history = get_broadcast_history(limit=10)
    
    return templates.TemplateResponse("admin_broadcast.html", {
        "request": request,
        "subscriber_count": subscriber_count,
        "total_subscriptions": total_subscriptions,
        "subscribers": [dict(s) for s in subscribers],
        "history": history,
        "version": APP_VERSION,
    })


@app.post("/admin/broadcast/send")
def admin_broadcast_send(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
    url: str = Form(""),
    broadcast_type: str = Form("custom"),
    send_email: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Send a broadcast notification to all subscribers"""
    # Don't access session directly - just log as 'admin'
    admin_user = "admin"
    
    result = send_broadcast_notification(
        title=title,
        body=body,
        url=url if url.strip() else None,
        broadcast_type=broadcast_type,
        sent_by=admin_user,
        also_email=bool(send_email)
    )
    
    return RedirectResponse(
        url=f"/admin/broadcast?sent=1&total={result['total_sent']}&failed={result['total_failed']}&emails={result.get('emails_sent', 0)}",
        status_code=303
    )


@app.post("/api/admin/broadcast/app-update")
def api_broadcast_app_update(
    request: Request,
    version: str = Form(None),
    send_email: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """
    Send an app update notification to all subscribers.
    Uses the current APP_VERSION if no version is specified.
    Links to the specific version section in the changelog.
    """
    version = version or APP_VERSION
    
    # Link to specific version anchor in changelog
    changelog_url = f"/changelog#v{version}"
    
    result = send_broadcast_notification(
        title="🎉 New Update Available!",
        body=f"Printellect v{version} is here with new features and improvements. Tap to see what's new!",
        url=changelog_url,
        broadcast_type="app_update",
        sent_by="admin",
        metadata={"version": version},
        also_email=bool(send_email)
    )
    
    # Check if request wants JSON (API call) or redirect (form submission)
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return {
            "success": result["total_sent"] > 0,
            "version": version,
            "total_sent": result["total_sent"],
            "total_failed": result["total_failed"],
            "unique_emails": result["unique_emails"],
            "emails_sent": result.get("emails_sent", 0)
        }
    
    # Form submission - redirect back to broadcast page
    return RedirectResponse(
        url=f"/admin/broadcast?sent=1&total={result['total_sent']}&failed={result['total_failed']}&emails={result.get('emails_sent', 0)}",
        status_code=303
    )


# ─────────────────────────── PUSH SUBSCRIPTION MANAGEMENT ───────────────────────────

@app.post("/api/admin/push/cleanup")
async def api_admin_push_cleanup(request: Request, _=Depends(require_admin)):
    """
    Test and cleanup push subscriptions for a specific email.
    Sends a silent test push and removes subscriptions that fail with 404/410.
    """
    try:
        data = await _parse_request_data(request)
        email = data.get("email")
        
        if not email:
            return JSONResponse(status_code=400, content={"success": False, "error": "Email required"})
        
        removed = await _cleanup_subscriptions_for_email(email)
        
        return {"success": True, "email": email, "removed": removed}
    except Exception as e:
        print(f"[PUSH-CLEANUP] Error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post("/api/admin/push/cleanup-all")
async def api_admin_push_cleanup_all(_=Depends(require_admin)):
    """
    Test and cleanup ALL push subscriptions.
    Sends silent test pushes and removes any that fail.
    """
    try:
        conn = db()
        subs = conn.execute("SELECT id, endpoint FROM push_subscriptions").fetchall()
        conn.close()
        
        removed = 0
        
        # Test each subscription
        for sub in subs:
            is_valid = await _test_subscription(sub["endpoint"])
            if not is_valid:
                conn = db()
                conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
                conn.commit()
                conn.close()
                removed += 1
                print(f"[PUSH-CLEANUP] Removed stale subscription: {sub['endpoint'][:50]}...")
        
        print(f"[PUSH-CLEANUP] Cleaned up {removed} stale subscriptions out of {len(subs)}")
        return {"success": True, "tested": len(subs), "removed": removed}
    except Exception as e:
        print(f"[PUSH-CLEANUP] Error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post("/api/admin/push/test-all")
async def api_admin_push_test_all(_=Depends(require_admin)):
    """
    Test all push subscriptions and report which are valid/invalid.
    Automatically removes invalid ones.
    """
    try:
        conn = db()
        subs = conn.execute("""
            SELECT id, email, endpoint 
            FROM push_subscriptions
        """).fetchall()
        conn.close()
        
        valid = 0
        invalid = 0
        removed = 0
        
        for sub in subs:
            is_valid = await _test_subscription(sub["endpoint"])
            if is_valid:
                valid += 1
            else:
                invalid += 1
                # Remove invalid subscription
                conn = db()
                conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
                conn.commit()
                conn.close()
                removed += 1
                print(f"[PUSH-TEST] Removed invalid subscription for {sub['email']}: {sub['endpoint'][:40]}...")
        
        print(f"[PUSH-TEST] Results: {valid} valid, {invalid} invalid, {removed} removed")
        return {"success": True, "valid": valid, "invalid": invalid, "removed": removed}
    except Exception as e:
        print(f"[PUSH-TEST] Error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


async def _test_subscription(endpoint: str) -> bool:
    """
    Test if a push subscription endpoint is still valid.
    Returns True if valid, False if expired/invalid.
    """
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        return True  # Can't test without VAPID, assume valid
    
    try:
        from pywebpush import webpush, WebPushException
        from urllib.parse import urlparse
        import time
        
        # We need the full subscription info, but we only have endpoint
        # We'll do a lightweight test by checking the endpoint status
        conn = db()
        sub = conn.execute(
            "SELECT p256dh, auth FROM push_subscriptions WHERE endpoint = ?",
            (endpoint,)
        ).fetchone()
        conn.close()
        
        if not sub:
            return False
        
        subscription_info = {
            "endpoint": endpoint,
            "keys": {
                "p256dh": sub["p256dh"],
                "auth": sub["auth"],
            }
        }
        
        # Build VAPID claims
        parsed = urlparse(endpoint)
        aud = f"{parsed.scheme}://{parsed.netloc}"
        
        vapid_email = VAPID_CLAIMS_EMAIL
        if not vapid_email.startswith("mailto:"):
            vapid_email = f"mailto:{vapid_email}"
        
        exp_12h = int(time.time()) + (12 * 3600)
        vapid_claims = {"sub": vapid_email, "aud": aud, "exp": exp_12h}
        
        # Send empty/silent push to test validity
        # Most push services will reject invalid subscriptions
        webpush(
            subscription_info=subscription_info,
            data="",  # Empty payload
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=vapid_claims,
            ttl=0,  # Immediate expiry - don't actually deliver
        )
        return True
    except WebPushException as e:
        # 404 or 410 means subscription is expired/invalid
        if e.response and e.response.status_code in [404, 410]:
            return False
        # Other errors might be temporary, consider valid
        return True
    except Exception:
        return True  # Assume valid on other errors


async def _cleanup_subscriptions_for_email(email: str) -> int:
    """
    Test and remove invalid subscriptions for a specific email.
    Returns number of subscriptions removed.
    """
    conn = db()
    subs = conn.execute(
        "SELECT id, endpoint FROM push_subscriptions WHERE email = ?",
        (email,)
    ).fetchall()
    conn.close()
    
    removed = 0
    for sub in subs:
        is_valid = await _test_subscription(sub["endpoint"])
        if not is_valid:
            conn = db()
            conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
            conn.commit()
            conn.close()
            removed += 1
            print(f"[PUSH-CLEANUP] Removed stale subscription for {email}")
    
    return removed


# ─────────────────────────── ERROR TESTING ENDPOINTS ───────────────────────────
# These endpoints are for testing the error handling system

@app.get("/test-error/500")
def test_error_500(_=Depends(require_admin)):
    """Test endpoint to trigger a 500 Internal Server Error (admin only)"""
    raise ValueError("This is a test error to verify error handling and reporting works correctly")


@app.get("/test-error/404")
def test_error_404():
    """Test endpoint to trigger a 404 Not Found error"""
    raise HTTPException(status_code=404, detail="This is a test 404 error")


@app.get("/test-error/403")
def test_error_403():
    """Test endpoint to trigger a 403 Forbidden error"""
    raise HTTPException(status_code=403, detail="This is a test 403 access denied error")


@app.get("/test-error/400")
def test_error_400():
    """Test endpoint to trigger a 400 Bad Request error"""
    raise HTTPException(status_code=400, detail="This is a test 400 bad request error")


# ─────────────────────────── SMOKE CHECK ENDPOINT ───────────────────────────
@app.get("/admin/smoke-check")
def admin_smoke_check(_=Depends(require_admin)):
    """
    Lightweight smoke check for regression safety.
    Tests core functionality without triggering side effects.
    Returns JSON health summary.
    """
    import time
    start = time.time()
    checks = {}
    
    # 1. Database connectivity
    try:
        conn = db()
        cur = conn.execute("SELECT COUNT(*) FROM requests")
        count = cur.fetchone()[0]
        conn.close()
        checks["database"] = {"ok": True, "requests_count": count}
    except Exception as e:
        checks["database"] = {"ok": False, "error": str(e)}
    
    # 2. Template loading (just verify they parse without rendering)
    key_templates = [
        "pwa_base.html",
        "public_queue_new.html", 
        "request_form_new.html",
        "my_requests_lookup_new.html",
        "admin_queue.html",
        "admin_request.html",
    ]
    template_checks = {}
    for tpl in key_templates:
        try:
            # Just get the template to verify it parses
            templates.get_template(tpl)
            template_checks[tpl] = True
        except Exception as e:
            template_checks[tpl] = str(e)
    checks["templates"] = {
        "ok": all(v is True for v in template_checks.values()),
        "details": template_checks
    }
    
    # 3. Settings database check
    try:
        admin_email = get_setting("admin_email", "")
        checks["settings"] = {"ok": True, "admin_email_set": bool(admin_email)}
    except Exception as e:
        checks["settings"] = {"ok": False, "error": str(e)}
    
    # 4. File storage paths
    try:
        data_dir = os.path.dirname(DB_PATH)
        uploads_exists = os.path.isdir(UPLOAD_DIR)
        data_exists = os.path.isdir(data_dir)
        checks["storage"] = {
            "ok": uploads_exists and data_exists,
            "uploads_dir": uploads_exists,
            "data_dir": data_exists
        }
    except Exception as e:
        checks["storage"] = {"ok": False, "error": str(e)}
    
    # 5. Environment config
    checks["environment"] = {
        "ok": True,
        "base_url": BASE_URL,
        "demo_mode": DEMO_MODE,
        "version": APP_VERSION
    }
    
    # Summary
    elapsed_ms = round((time.time() - start) * 1000, 2)
    all_ok = all(c.get("ok", False) for c in checks.values())
    
    return {
        "status": "healthy" if all_ok else "degraded",
        "checks": checks,
        "elapsed_ms": elapsed_ms,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/logs")
def get_logs(
    level: Optional[str] = None,
    limit: int = 100,
    search: Optional[str] = None,
    _=Depends(require_admin)
):
    """
    Get application logs (admin only)
    
    Query params:
    - level: Filter by log level (DEBUG, INFO, WARNING, ERROR)
    - limit: Number of logs to return (default 100, max 500)
    - search: Search text in log messages
    
    Returns JSON array of log entries, most recent first
    """
    limit = min(limit, LOG_BUFFER_SIZE)
    
    # Get logs from buffer (newest first)
    logs = list(log_buffer)
    logs.reverse()
    
    # Filter by level if specified
    if level:
        level = level.upper()
        logs = [l for l in logs if l["level"] == level]
    
    # Filter by search text
    if search:
        search = search.lower()
        logs = [l for l in logs if search in l["message"].lower() or search in l.get("module", "").lower()]
    
    # Limit results
    logs = logs[:limit]
    
    return {
        "count": len(logs),
        "total_in_buffer": len(log_buffer),
        "logs": logs
    }


@app.get("/api/logs/download")
def download_logs(_=Depends(require_admin)):
    """Download full log file (if available)"""
    if os.path.exists(LOG_FILE):
        return FileResponse(
            LOG_FILE,
            media_type="text/plain",
            filename=f"printellect-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        )
    else:
        # Return buffer logs as text
        log_text = "\n".join([l["formatted"] for l in log_buffer])
        return Response(
            content=log_text,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=printellect-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"}
        )


# ─────────────────────────── DEMO MODE ───────────────────────────

@app.get("/api/demo/status")
def api_demo_status():
    """Check if demo mode is active and get status info"""
    return get_demo_status()


@app.post("/api/demo/reset")
def api_demo_reset(request: Request, _=Depends(require_admin)):
    """Reset all data and reseed with fresh demo data (admin only, demo mode only)"""
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo reset only available in DEMO_MODE")
    
    success = reset_demo_data(db)
    if success:
        return {"success": True, "message": "Demo data reset successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to reset demo data")


# ─────────────────────────── STORE MANAGEMENT ───────────────────────────

@app.get("/admin/store", response_class=HTMLResponse)
def admin_store(request: Request, _=Depends(require_admin)):
    """Admin store item management"""
    conn = db()
    items = conn.execute("""
        SELECT si.*, 
               (SELECT COUNT(*) FROM store_item_files WHERE store_item_id = si.id) as file_count
        FROM store_items si 
        ORDER BY si.is_active DESC, si.name ASC
    """).fetchall()
    conn.close()
    
    return templates.TemplateResponse("admin_store.html", {
        "request": request,
        "items": items,
        "version": APP_VERSION,
    })


@app.post("/admin/store/add")
def admin_store_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    material: str = Form("PLA"),
    colors: str = Form(""),
    estimated_time_minutes: int = Form(0),
    link_url: str = Form(""),
    notes: str = Form(""),
    image: Optional[UploadFile] = File(None),
    _=Depends(require_admin)
):
    """Add a new store item"""
    item_id = str(uuid.uuid4())
    created = now_iso()
    
    # Handle image upload
    image_data = None
    if image and image.filename:
        import base64
        content = image.file.read()
        if len(content) < 5 * 1024 * 1024:  # Max 5MB
            image_data = base64.b64encode(content).decode('utf-8')
    
    conn = db()
    conn.execute("""
        INSERT INTO store_items (
            id, name, description, category, material, colors,
            estimated_time_minutes, image_data, link_url, notes,
            is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (
        item_id, name.strip(), description.strip() or None, category.strip() or None,
        material, colors.strip() or None, estimated_time_minutes or None,
        image_data, link_url.strip() or None, notes.strip() or None,
        created, created
    ))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}", status_code=303)


@app.get("/admin/store/item/{item_id}", response_class=HTMLResponse)
def admin_store_item(request: Request, item_id: str, _=Depends(require_admin)):
    """View/edit a store item"""
    conn = db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        raise HTTPException(status_code=404, detail="Store item not found")
    
    files = conn.execute(
        "SELECT * FROM store_item_files WHERE store_item_id = ? ORDER BY created_at DESC",
        (item_id,)
    ).fetchall()
    conn.close()
    
    return templates.TemplateResponse("admin_store_item.html", {
        "request": request,
        "item": item,
        "files": files,
        "version": APP_VERSION,
    })


@app.post("/admin/store/item/{item_id}/update")
def admin_store_item_update(
    request: Request,
    item_id: str,
    name: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    material: str = Form("PLA"),
    colors: str = Form(""),
    estimated_time_minutes: int = Form(0),
    link_url: str = Form(""),
    notes: str = Form(""),
    is_active: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    _=Depends(require_admin)
):
    """Update a store item"""
    conn = db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        raise HTTPException(status_code=404, detail="Store item not found")
    
    # Handle image upload
    image_data = item["image_data"]  # Keep existing if no new upload
    if image and image.filename:
        import base64
        content = image.file.read()
        if len(content) < 5 * 1024 * 1024:
            image_data = base64.b64encode(content).decode('utf-8')
    
    conn.execute("""
        UPDATE store_items SET
            name = ?, description = ?, category = ?, material = ?, colors = ?,
            estimated_time_minutes = ?, image_data = ?, link_url = ?, notes = ?,
            is_active = ?, updated_at = ?
        WHERE id = ?
    """, (
        name.strip(), description.strip() or None, category.strip() or None,
        material, colors.strip() or None, estimated_time_minutes or None,
        image_data, link_url.strip() or None, notes.strip() or None,
        1 if is_active else 0, now_iso(), item_id
    ))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}?saved=1", status_code=303)


@app.post("/admin/store/item/{item_id}/delete")
def admin_store_item_delete(request: Request, item_id: str, _=Depends(require_admin)):
    """Delete a store item"""
    conn = db()
    # Delete associated files
    conn.execute("DELETE FROM store_item_files WHERE store_item_id = ?", (item_id,))
    conn.execute("DELETE FROM store_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin/store?deleted=1", status_code=303)


@app.post("/admin/store/item/{item_id}/upload")
async def admin_store_item_upload(
    request: Request, 
    item_id: str, 
    files: List[UploadFile] = File(...),
    _=Depends(require_admin)
):
    """Upload files for a store item"""
    conn = db()
    item = conn.execute("SELECT id FROM store_items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        raise HTTPException(status_code=404, detail="Store item not found")
    
    uploads_dir = UPLOAD_DIR
    os.makedirs(uploads_dir, exist_ok=True)
    
    for upload in files:
        if not upload.filename:
            continue
            
        ext = safe_ext(upload.filename)
        if ext.lower() not in ALLOWED_EXTENSIONS:
            continue
        
        content = await upload.read()
        sha256 = hashlib.sha256(content).hexdigest()
        stored_name = f"store_{sha256}{ext}"
        path = os.path.join(uploads_dir, stored_name)
        
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(content)
        
        file_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO store_item_files (id, store_item_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (file_id, item_id, now_iso(), upload.filename, stored_name, len(content), sha256)
        )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}?uploaded=1", status_code=303)


@app.post("/admin/store/item/{item_id}/file/{file_id}/delete")
def admin_store_file_delete(request: Request, item_id: str, file_id: str, _=Depends(require_admin)):
    """Delete a file from a store item"""
    conn = db()
    conn.execute("DELETE FROM store_item_files WHERE id = ? AND store_item_id = ?", (file_id, item_id))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}", status_code=303)


# ─────────────────────────── PUBLIC STORE ───────────────────────────

@app.get("/store", response_class=HTMLResponse)
def public_store(request: Request, category: Optional[str] = None):
    """Public store browsing page"""
    conn = db()
    
    # Get unique categories
    categories = conn.execute("""
        SELECT DISTINCT category FROM store_items 
        WHERE is_active = 1 AND category IS NOT NULL AND category != ''
        ORDER BY category
    """).fetchall()
    
    # Get items
    if category:
        items = conn.execute("""
            SELECT * FROM store_items 
            WHERE is_active = 1 AND category = ?
            ORDER BY name ASC
        """, (category,)).fetchall()
    else:
        items = conn.execute("""
            SELECT * FROM store_items 
            WHERE is_active = 1
            ORDER BY name ASC
        """).fetchall()
    
    conn.close()
    
    return templates.TemplateResponse("store_new.html", {
        "request": request,
        "items": items,
        "categories": [c["category"] for c in categories],
        "selected_category": category,
        "version": APP_VERSION,
    })


@app.get("/store/item/{item_id}", response_class=HTMLResponse)
def store_item_view(request: Request, item_id: str):
    """View a store item and request it"""
    conn = db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ? AND is_active = 1", (item_id,)).fetchone()
    if not item:
        conn.close()
        raise HTTPException(status_code=404, detail="Item not found")
    
    files = conn.execute(
        "SELECT * FROM store_item_files WHERE store_item_id = ? ORDER BY created_at DESC",
        (item_id,)
    ).fetchall()
    conn.close()
    
    return templates.TemplateResponse("store_item.html", {
        "request": request,
        "item": item,
        "files": files,
        "version": APP_VERSION,
    })


@app.post("/submit-store-request/{item_id}")
def submit_store_request(
    request: Request,
    item_id: str,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    colors: str = Form(""),
    notes: str = Form(""),
):
    """Submit a print request from a store item"""
    conn = db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ? AND is_active = 1", (item_id,)).fetchone()
    if not item:
        conn.close()
        raise HTTPException(status_code=404, detail="Store item not found")
    
    # Create request
    rid = str(uuid.uuid4())
    created = now_iso()
    access_token = secrets.token_urlsafe(32)
    
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, print_time_minutes, store_item_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rid, created, created,
        requester_name.strip(), requester_email.strip().lower(),
        "ANY",  # Admin will assign printer
        item["material"],
        colors.strip() or item["colors"] or "",
        item["link_url"],
        notes.strip() or None,
        item["name"],  # Use store item name as print name
        "NEW",
        access_token,
        0,  # Default priority
        item["estimated_time_minutes"],
        item_id  # Link to store item
    ))
    
    # Copy store item files to request
    store_files = conn.execute(
        "SELECT original_filename, stored_filename, size_bytes, sha256 FROM store_item_files WHERE store_item_id = ?",
        (item_id,)
    ).fetchall()
    
    for f in store_files:
        conn.execute(
            "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), rid, created, f["original_filename"], f["stored_filename"], f["size_bytes"], f["sha256"])
        )
    
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, created, None, "NEW", f"Store item request: {item['name']}")
    )
    
    conn.commit()
    conn.close()
    
    # Send confirmation email
    if get_bool_setting("requester_email_on_submit", True):
        try:
            subject = f"[{APP_TITLE}] Request Received - {item['name']}"
            text = f"Your print request has been received!\n\nPrint: {item['name']}\nRequest ID: {rid[:8]}\n\nTrack: {BASE_URL}/open/{rid}?token={access_token}"
            
            email_rows = [
                ("Print Name", item["name"]),
                ("Request ID", rid[:8]),
                ("Material", item["material"]),
                ("Status", "NEW - Awaiting Review"),
            ]
            
            html = build_email_html(
                title="🖨 Request Received",
                subtitle=f"Your request for '{item['name']}' has been submitted",
                rows=email_rows,
                footer_note="You'll receive updates as your request is processed.",
                cta_label="Track Your Request",
                cta_url=f"{BASE_URL}/open/{rid}?token={access_token}",
            )
            
            send_email([requester_email.strip().lower()], subject, text, html)
        except Exception as e:
            print(f"[EMAIL] Failed to send confirmation: {e}")
    
    # Notify admin
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails and get_bool_setting("admin_email_on_submit", True):
        try:
            subject = f"[{APP_TITLE}] New Store Request - {item['name']}"
            text = f"New store item request:\n\nItem: {item['name']}\nRequester: {requester_name}\nEmail: {requester_email}\n\nReview: {BASE_URL}/admin/request/{rid}"
            send_email(admin_emails, subject, text)
        except Exception:
            pass
    
    return RedirectResponse(url=f"/thanks?id={rid[:8]}", status_code=303)


@app.get("/admin/printer-settings", response_class=HTMLResponse)
def admin_printer_settings(request: Request, _=Depends(require_admin), saved: Optional[str] = None):
    model = {
        "flashforge_api_url": get_setting("flashforge_api_url", "http://localhost:5000"),
        "printer_adventurer_4_ip": get_setting("printer_adventurer_4_ip", "192.168.0.198"),
        "printer_ad5x_ip": get_setting("printer_ad5x_ip", "192.168.0.157"),
        "camera_adventurer_4_url": get_setting("camera_adventurer_4_url", ""),
        "camera_ad5x_url": get_setting("camera_ad5x_url", ""),
        "enable_printer_polling": get_bool_setting("enable_printer_polling", True),
        "enable_camera_snapshot": get_bool_setting("enable_camera_snapshot", False),
        "enable_auto_print_match": get_bool_setting("enable_auto_print_match", True),
        "saved": bool(saved == "1"),
    }
    return templates.TemplateResponse("printer_settings.html", {"request": request, "s": model, "version": APP_VERSION})


@app.post("/admin/printer-settings")
def admin_printer_settings_post(
    request: Request,
    flashforge_api_url: str = Form(""),
    printer_adventurer_4_ip: str = Form(""),
    printer_ad5x_ip: str = Form(""),
    camera_adventurer_4_url: str = Form(""),
    camera_ad5x_url: str = Form(""),
    enable_printer_polling: Optional[str] = Form(None),
    enable_camera_snapshot: Optional[str] = Form(None),
    enable_auto_print_match: Optional[str] = Form(None),
    _=Depends(require_admin),
):
    set_setting("flashforge_api_url", flashforge_api_url.strip())
    set_setting("printer_adventurer_4_ip", printer_adventurer_4_ip.strip())
    set_setting("printer_ad5x_ip", printer_ad5x_ip.strip())
    set_setting("camera_adventurer_4_url", camera_adventurer_4_url.strip())
    set_setting("camera_ad5x_url", camera_ad5x_url.strip())
    set_setting("enable_printer_polling", "1" if enable_printer_polling else "0")
    set_setting("enable_camera_snapshot", "1" if enable_camera_snapshot else "0")
    set_setting("enable_auto_print_match", "1" if enable_auto_print_match else "0")

    return RedirectResponse(url="/admin/printer-settings?saved=1", status_code=303)


@app.get("/admin/request/{rid}", response_class=HTMLResponse)
def admin_request_detail(request: Request, rid: str, _=Depends(require_admin)):
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")
    files = conn.execute("SELECT * FROM files WHERE request_id = ? ORDER BY created_at DESC", (rid,)).fetchall()
    events = conn.execute("SELECT * FROM status_events WHERE request_id = ? ORDER BY created_at DESC", (rid,)).fetchall()
    messages = conn.execute("SELECT * FROM request_messages WHERE request_id = ? ORDER BY created_at ASC", (rid,)).fetchall()
    
    # Enrich files with parsed metadata
    enriched_files = []
    for f in files:
        f_dict = dict(f)
        if f_dict.get("file_metadata"):
            try:
                f_dict["metadata"] = json.loads(f_dict["file_metadata"])
            except:
                f_dict["metadata"] = None
        else:
            f_dict["metadata"] = None
        enriched_files.append(f_dict)
    
    # Build a map of build_id -> list of files
    files_by_build = {}
    for f in enriched_files:
        bid = f.get("build_id")
        if bid:
            if bid not in files_by_build:
                files_by_build[bid] = []
            files_by_build[bid].append(f)
    
    # Mark all requester messages as read when admin views the request
    conn.execute("UPDATE request_messages SET is_read = 1 WHERE request_id = ? AND sender_type = 'requester' AND is_read = 0", (rid,))
    conn.commit()
    
    # Get builds for this request
    builds = conn.execute("SELECT * FROM builds WHERE request_id = ? ORDER BY build_number", (rid,)).fetchall()
    builds_list = []
    for b in builds:
        b_dict = dict(b)
        # Attach files assigned to this build
        b_dict["assigned_files"] = files_by_build.get(b["id"], [])
        builds_list.append(b_dict)
    conn.close()
    
    # Get camera URL for the printer if configured
    camera_url = get_camera_url(req["printer"]) if req["printer"] in ["ADVENTURER_4", "AD5X"] else None
    
    # Get slicer accuracy info for this printer/material combo
    accuracy_info = get_slicer_accuracy_factor(req["printer"], req["material"])
    
    # Get multi-build ETA info
    build_eta_info = get_request_eta_info(rid, dict(req))
    
    return templates.TemplateResponse("admin_request.html", {
        "request": request,
        "req": req,
        "files": enriched_files,
        "events": events,
        "messages": messages,
        "builds": builds_list,
        "build_eta_info": build_eta_info,
        "status_flow": STATUS_FLOW,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "allowed_exts": ", ".join(sorted(ALLOWED_EXTS)),
        "max_upload_mb": MAX_UPLOAD_MB,
        "camera_url": camera_url,
        "now": datetime.now().timestamp(),  # For cache-busting
        "accuracy_info": accuracy_info,
        "version": APP_VERSION,
    })


@app.post("/admin/request/{rid}/duplicate")
def admin_duplicate_request(request: Request, rid: str, _=Depends(require_admin)):
    """Duplicate a request directly into the queue (for batch printing)"""
    conn = db()
    original = conn.execute(
        "SELECT requester_name, requester_email, print_name, printer, material, colors, link_url, notes, priority, special_notes FROM requests WHERE id = ?",
        (rid,)
    ).fetchone()
    
    if not original:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Create new request with same details
    new_id = str(uuid.uuid4())
    new_token = secrets.token_urlsafe(32)
    created = now_iso()
    
    conn.execute(
        """INSERT INTO requests
           (id, created_at, updated_at, requester_name, requester_email, print_name, printer, material, colors, link_url, notes, status, priority, special_notes, access_token)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id,
            created,
            created,
            original["requester_name"],
            original["requester_email"],
            original["print_name"],
            original["printer"],
            original["material"],
            original["colors"],
            original["link_url"],
            original["notes"],
            "NEW",  # Start as NEW
            original["priority"] or 3,  # Keep original priority or default P3
            original["special_notes"],  # Copy special notes too
            new_token,  # Generate access token
        )
    )
    
    # Copy files if any exist
    files = conn.execute("SELECT original_filename, stored_filename, size_bytes, sha256 FROM files WHERE request_id = ?", (rid,)).fetchall()
    for f in files:
        conn.execute(
            "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), new_id, created, f["original_filename"], f["stored_filename"], f["size_bytes"], f["sha256"])
        )
    
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), new_id, created, None, "NEW", f"Duplicated from request {rid[:8]}")
    )
    
    conn.commit()
    conn.close()
    
    # Redirect to the new request
    return RedirectResponse(url=f"/admin/request/{new_id}", status_code=303)


@app.post("/admin/request/{rid}/add-to-store")
def admin_add_request_to_store(
    request: Request,
    rid: str,
    name: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    material: str = Form("PLA"),
    colors: str = Form(""),
    estimated_time_minutes: int = Form(0),
    link_url: str = Form(""),
    copy_files: Optional[str] = Form(None),
    use_snapshot: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Create a store item from an existing request"""
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Create store item
    item_id = str(uuid.uuid4())
    created = now_iso()
    
    # Handle snapshot as thumbnail
    image_data = None
    if use_snapshot and req["completion_snapshot"]:
        image_data = req["completion_snapshot"]
    
    conn.execute("""
        INSERT INTO store_items (
            id, name, description, category, material, colors,
            estimated_time_minutes, image_data, link_url, notes,
            is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (
        item_id, name.strip(), description.strip() or None, category.strip() or None,
        material, colors.strip() or None, estimated_time_minutes or None,
        image_data, link_url.strip() or None, f"Created from request {rid[:8]}",
        created, created
    ))
    
    # Copy files if requested
    if copy_files:
        files = conn.execute(
            "SELECT original_filename, stored_filename, size_bytes, sha256 FROM files WHERE request_id = ?",
            (rid,)
        ).fetchall()
        
        for f in files:
            conn.execute(
                "INSERT INTO store_item_files (id, store_item_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), item_id, created, f["original_filename"], f["stored_filename"], f["size_bytes"], f["sha256"])
            )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}?created=1", status_code=303)


@app.post("/admin/match-print/{rid}")
def admin_match_print_to_request(
    request: Request,
    rid: str,
    printer: str = Form(...),
    _=Depends(require_admin)
):
    """
    Manually match a printing file to a request.
    Called from the suggestion banner in admin queue.
    """
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    if req["status"] not in ("QUEUED", "APPROVED"):
        conn.close()
        raise HTTPException(status_code=400, detail="Request must be in QUEUED or APPROVED status")
    
    old_status = req["status"]
    
    # Get the suggestion info for the comment
    suggestions = get_print_match_suggestions()
    current_file = suggestions.get(printer, {}).get("file", "unknown file")
    
    conn.execute(
        "UPDATE requests SET status = 'PRINTING', printer = ?, printing_started_at = ?, printing_email_sent = 0, updated_at = ? WHERE id = ?",
        (printer, now_iso(), now_iso(), rid)
    )
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), old_status, "PRINTING", f"Manually matched to printer (file: {get_filename_base(current_file)})")
    )
    conn.commit()
    conn.close()
    
    # Clear the suggestion for this printer
    clear_print_match_suggestion(printer)
    
    add_poll_debug_log({
        "type": "manual_match",
        "request_id": rid[:8],
        "printer": printer,
        "file": current_file,
        "message": f"Manually matched to {printer}"
    })
    
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/dismiss-match/{printer}")
def admin_dismiss_match_suggestion(
    request: Request,
    printer: str,
    _=Depends(require_admin)
):
    """Dismiss a print match suggestion."""
    clear_print_match_suggestion(printer)
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/request/{rid}/status")
def admin_set_status(
    request: Request,
    rid: str,
    to_status: str = Form(...),
    comment: Optional[str] = Form(None),
    printer: Optional[str] = Form(None),
    material: Optional[str] = Form(None),
    colors: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    if to_status not in STATUS_FLOW:
        raise HTTPException(status_code=400, detail="Invalid status")

    conn = db()
    req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")
    
    req = dict(req_row)  # Convert to dict for .get() support
    from_status = req["status"]
    
    # Validate printer selection when changing to PRINTING
    # Must have a specific printer selected (not "ANY" or empty)
    valid_printer_codes = [p[0] for p in PRINTERS if p[0] != "ANY"]
    effective_printer = printer.strip() if printer and printer.strip() else None
    
    if to_status == "PRINTING" and from_status != "PRINTING":
        if not effective_printer or effective_printer == "ANY":
            conn.close()
            raise HTTPException(
                status_code=400, 
                detail="A specific printer must be selected to start printing. 'Any' is not allowed."
            )
        if effective_printer not in valid_printer_codes:
            conn.close()
            raise HTTPException(status_code=400, detail=f"Invalid printer: {effective_printer}")
    
    # Track printing start time when transitioning to PRINTING
    update_cols = ["status", "updated_at"]
    update_vals: list = [to_status, now_iso()]
    
    if to_status == "PRINTING" and from_status != "PRINTING":
        update_cols.append("printing_started_at")
        update_vals.append(now_iso())
        # Reset email flag - the PRINTING email will be sent by background polling
        # once the printer reports layer count and file info
        update_cols.append("printing_email_sent")
        update_vals.append(0)
    
    # Update printer/material/colors if provided
    if printer and printer.strip():
        update_cols.append("printer")
        update_vals.append(printer.strip())
    if material and material.strip():
        update_cols.append("material")
        update_vals.append(material.strip())
    if colors is not None:
        update_cols.append("colors")
        update_vals.append(colors.strip() if colors else None)
    
    update_sql = "UPDATE requests SET " + ", ".join([f"{col} = ?" for col in update_cols]) + " WHERE id = ?"
    update_vals.append(rid)
    
    conn.execute(update_sql, update_vals)
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), from_status, to_status, comment)
    )
    conn.commit()
    conn.close()

    # When approving a request, set up builds (always at least 1)
    if to_status == "APPROVED" and from_status != "APPROVED":
        build_count = setup_builds_for_request(rid)
        # Mark all builds as READY since request is approved
        mark_builds_ready(rid)
    
    # When starting print, start the first READY build
    if to_status == "PRINTING" and from_status != "PRINTING":
        conn2 = db()
        # Find the first READY build for this request
        first_ready = conn2.execute("""
            SELECT id FROM builds WHERE request_id = ? AND status = 'READY' 
            ORDER BY build_number LIMIT 1
        """, (rid,)).fetchone()
        conn2.close()
        
        if first_ready:
            # Start the first build with the selected printer
            # Use the specific printer from the status change (never "ANY")
            start_printer = printer if printer and printer != "ANY" else None
            if start_printer:
                start_build(first_ready["id"], start_printer, comment)
            # If no specific printer, don't auto-start (admin must select one)

    # Settings-driven emails
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    admin_email_on_status = get_bool_setting("admin_email_on_status", True)
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)

    # Status-specific styling
    status_colors = {
        "NEEDS_INFO": "#f97316",  # Orange
        "APPROVED": "#10b981",  # Green
        "PRINTING": "#f59e0b",  # Amber
        "DONE": "#06b6d4",      # Cyan
        "PICKED_UP": "#8b5cf6", # Purple
        "REJECTED": "#ef4444",  # Red
        "CANCELLED": "#64748b", # Slate
    }
    status_titles = {
        "NEEDS_INFO": "⚠️ Info Needed",
        "APPROVED": "✓ Request Approved",
        "PRINTING": "🖨 Now Printing",
        "DONE": "✓ Ready for Pickup",
        "PICKED_UP": "✓ Completed",
        "REJECTED": "Request Rejected",
        "CANCELLED": "Request Cancelled",
    }
    
    header_color = status_colors.get(to_status, "#4f46e5")
    status_title = status_titles.get(to_status, "Status Update")
    
    # Calculate queue position and estimated wait for APPROVED status
    queue_position = None
    estimated_wait_str = None
    if to_status == "APPROVED":
        conn2 = db()
        # Count how many approved items are ahead (by priority, then created_at)
        queue_count = conn2.execute("""
            SELECT COUNT(*) FROM requests 
            WHERE status = 'APPROVED' 
            AND (priority > ? OR (priority = ? AND created_at < ?))
        """, (req["priority"], req["priority"], req["created_at"])).fetchone()[0]
        queue_position = queue_count + 1
        
        # Rough wait estimate: each print ~60 min avg + 30 min turnaround
        # This is very approximate
        estimated_wait_minutes = queue_count * 90  # 90 min per item ahead
        if estimated_wait_minutes > 0:
            hours = estimated_wait_minutes // 60
            mins = estimated_wait_minutes % 60
            if hours > 0:
                estimated_wait_str = f"{hours}h {mins}m"
            else:
                estimated_wait_str = f"{mins}m"
        else:
            estimated_wait_str = "You're next!"
        conn2.close()

    # Check fine-grain notification settings (admin settings)
    status_notify_settings = {
        "NEEDS_INFO": get_bool_setting("notify_requester_needs_info", True),
        "APPROVED": get_bool_setting("notify_requester_approved", True),
        "PRINTING": get_bool_setting("notify_requester_printing", True),
        "DONE": get_bool_setting("notify_requester_done", True),
        "PICKED_UP": get_bool_setting("notify_requester_picked_up", True),
        "REJECTED": get_bool_setting("notify_requester_rejected", True),
        "CANCELLED": get_bool_setting("notify_requester_cancelled", True),
    }
    should_notify_requester = status_notify_settings.get(to_status, True)
    
    # PRINTING emails are sent by background polling once printer reports live data
    # This allows us to include layer count, file name, and accurate ETA
    if to_status == "PRINTING":
        should_notify_requester = False  # Will be sent by poll_printer_status_worker

    # Parse user notification preferences - use the proper preferences table
    user_prefs = get_user_notification_prefs(req.get("requester_email", ""))
    user_wants_email = user_prefs.get("status_email", True)
    user_wants_push = user_prefs.get("status_push", True)  # Default to True for push notifications

    if requester_email_on_status and should_notify_requester and user_wants_email:
        print_label = req["print_name"] or f"Request {rid[:8]}"
        subject = f"[{APP_TITLE}] {status_title} - {print_label}"
        
        # Build text version
        text_lines = [
            f"Print: {print_label}\n",
            f"Status: {from_status} → {to_status}\n",
        ]
        if to_status == "APPROVED" and queue_position:
            text_lines.append(f"\nQueue Position: #{queue_position}")
            text_lines.append(f"Estimated Wait: {estimated_wait_str}")
            text_lines.append(f"\n⚠ Note: Wait times are estimates and may vary. Check the live queue for the most accurate status.\n")
        text_lines.append(f"\nComment: {comment or '(none)'}\n")
        if to_status == "NEEDS_INFO":
            text_lines.append(f"\nRespond here: {BASE_URL}/open/{rid}?token={req['access_token']}\n")
        else:
            text_lines.append(f"\nView queue: {BASE_URL}/queue?mine={rid[:8]}\n")
        text = "\n".join(text_lines)
        
        # Build HTML rows
        email_rows = [
            ("Print Name", req["print_name"] or "—"),
            ("Request ID", rid[:8]),
            ("Printer", _human_printer(printer or req["printer"]) if (printer or req["printer"]) else "ANY"),
            ("Material", _human_material(material or req["material"]) if (material or req["material"]) else "—"),
            ("Status", to_status),
        ]
        if to_status == "APPROVED" and queue_position:
            email_rows.append(("Queue Position", f"#{queue_position}"))
            email_rows.append(("Estimated Wait", estimated_wait_str))
        
        # Add ETA for PRINTING status
        if to_status == "PRINTING" and req["print_time_minutes"]:
            hours = req["print_time_minutes"] // 60
            mins = req["print_time_minutes"] % 60
            if hours > 0:
                eta_str = f"~{hours}h {mins}m"
            else:
                eta_str = f"~{mins}m"
            email_rows.append(("Est. Print Time", eta_str))
            
            # Calculate approximate completion time
            from datetime import timedelta
            completion_time = datetime.utcnow() + timedelta(minutes=req["print_time_minutes"])
            email_rows.append(("Est. Completion", completion_time.strftime("%I:%M %p UTC")))
        
        email_rows.append(("Comment", (comment or "—")))
        
        # Status-specific subtitles and notes
        print_label = req["print_name"] or f"Request {rid[:8]}"
        subtitle = f"'{print_label}' status: {to_status.replace('_', ' ').title()}"
        footer_note = None
        cta_label = "View in Queue"
        cta_url = f"{BASE_URL}/queue?mine={rid[:8]}"
        
        if to_status == "NEEDS_INFO":
            subtitle = f"We need more information about '{print_label}'"
            footer_note = "Click the button below to respond, upload files, or edit your request. Your request is on hold until we hear back from you."
            cta_label = "Respond to Request"
            cta_url = f"{BASE_URL}/open/{rid}?token={req['access_token']}"
        elif to_status == "APPROVED" and queue_position:
            footer_note = "Wait times are estimates and may vary. Check the live queue for the most accurate status."
        elif to_status == "PRINTING":
            subtitle = f"'{print_label}' is now printing!"
        elif to_status == "DONE":
            subtitle = f"'{print_label}' is complete and ready for pickup!"
        elif to_status == "PICKED_UP":
            subtitle = f"'{print_label}' has been picked up. Thanks!"
        elif to_status == "REJECTED":
            subtitle = f"'{print_label}' could not be completed"
        elif to_status == "CANCELLED":
            subtitle = f"'{print_label}' has been cancelled"
        
        # Generate direct my-requests link
        my_requests_token = get_or_create_my_requests_token(req["requester_email"])
        my_requests_url = f"{BASE_URL}/my-requests/view?token={my_requests_token}"
        
        html = build_email_html(
            title=status_title,
            subtitle=subtitle,
            rows=email_rows,
            cta_url=cta_url,
            cta_label=cta_label,
            header_color=header_color,
            footer_note=footer_note,
            secondary_cta_url=my_requests_url,
            secondary_cta_label="All My Requests",
        )
        send_email([req["requester_email"]], subject, text, html)

    # Send push notification for important status changes (if user wants push notifications)
    # NOTE: PRINTING is excluded because poll_printer_status_worker sends a better notification
    # with layer count and ETA once the printer reports those
    push_statuses = ["NEEDS_INFO", "APPROVED", "DONE", "CANCELLED", "REJECTED"]
    if to_status in push_statuses and user_wants_push:
        push_titles = {
            "NEEDS_INFO": "📝 Action Needed",
            "APPROVED": "✅ Request Approved",
            "DONE": "🎉 Print Complete!",
            "CANCELLED": "❌ Request Cancelled",
            "REJECTED": "❌ Request Rejected",
        }
        push_bodies = {
            "NEEDS_INFO": f"We need more info about '{req['print_name'] or 'your request'}'",
            "APPROVED": f"'{req['print_name'] or 'Your request'}' is approved and in queue",
            "DONE": f"'{req['print_name'] or 'Your request'}' is ready for pickup!",
            "CANCELLED": f"'{req['print_name'] or 'Your request'}' has been cancelled.",
            "REJECTED": f"'{req['print_name'] or 'Your request'}' was rejected.",
        }
        try:
            send_push_notification(
                email=req["requester_email"],
                title=push_titles.get(to_status, "Status Update"),
                body=push_bodies.get(to_status, f"Status changed to {to_status}"),
                url=f"/my/{rid}?token={req['access_token']}"
            )
        except Exception as e:
            print(f"[PUSH] Error sending push notification: {e}")

    if admin_email_on_status and admin_emails:
        # Check fine-grain admin notification settings
        admin_notify_settings = {
            "NEEDS_INFO": get_bool_setting("notify_admin_needs_info", True),
            "APPROVED": get_bool_setting("notify_admin_approved", True),
            "PRINTING": get_bool_setting("notify_admin_printing", True),
            "DONE": get_bool_setting("notify_admin_done", True),
            "PICKED_UP": get_bool_setting("notify_admin_picked_up", True),
            "REJECTED": get_bool_setting("notify_admin_rejected", True),
            "CANCELLED": get_bool_setting("notify_admin_cancelled", True),
        }
        should_notify_admin = admin_notify_settings.get(to_status, True)
        
        if should_notify_admin:
            subject = f"[{APP_TITLE}] {rid[:8]}: {from_status} → {to_status}"
            text = (
                f"Request status changed.\n\n"
                f"ID: {rid}\n"
                f"Status: {from_status} → {to_status}\n"
                f"Comment: {comment or '(none)'}\n"
                f"Requester: {req['requester_name']} ({req['requester_email']})\n"
                f"Admin: {BASE_URL}/admin/request/{rid}\n"
            )
            html = build_email_html(
                title=f"{from_status} → {to_status}",
                subtitle=f"Request {rid[:8]} status changed",
                rows=[
                    ("Request ID", rid[:8]),
                    ("Requester", req["requester_name"] or "—"),
                    ("Email", req["requester_email"] or "—"),
                    ("Printer", req["printer"] or "ANY"),
                    ("Status", to_status),
                    ("Comment", (comment or "—")),
                ],
                cta_url=f"{BASE_URL}/admin/request/{rid}",
                cta_label="Open in Admin",
                header_color=header_color,
            )
            send_email(admin_emails, subject, text, html)
            
            # Also send admin push notification for status changes
            admin_push_titles = {
                "DONE": "✅ Print Complete",
                "PICKED_UP": "📦 Picked Up",
                "REJECTED": "❌ Request Rejected",
                "CANCELLED": "🚫 Request Cancelled",
                "APPROVED": "✓ Request Approved",
                "PRINTING": "🖨️ Now Printing",
                "NEEDS_INFO": "❓ Info Requested",
            }
            admin_push_title = admin_push_titles.get(to_status, f"Status: {to_status}")
            send_push_notification_to_admins(
                title=admin_push_title,
                body=f"{req['requester_name']} - {req['print_name'] or rid[:8]}",
                url=f"/admin/request/{rid}",
                tag=f"admin-status-{rid[:8]}"
            )

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/send-reminder")
def admin_send_reminder(
    request: Request,
    rid: str,
    _=Depends(require_admin)
):
    """Send a reminder email to requester that info is needed"""
    conn = db()
    req = conn.execute(
        "SELECT requester_email, requester_name, print_name, status, access_token FROM requests WHERE id = ?",
        (rid,)
    ).fetchone()
    
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")
    
    if req["status"] != "NEEDS_INFO":
        conn.close()
        raise HTTPException(status_code=400, detail="Request is not in NEEDS_INFO status")
    
    conn.close()
    
    # Send reminder email
    print_label = req["print_name"] or f"Request {rid[:8]}"
    subject = f"[{APP_TITLE}] Reminder: We need more info for '{print_label}'"
    portal_url = f"{BASE_URL}/my/{rid}?token={req['access_token']}"
    text = (
        f"Hi {req['requester_name']},\n\n"
        f"This is a friendly reminder that we're still waiting for more information about your print request '{print_label}'.\n\n"
        f"Please respond so we can continue processing your request:\n{portal_url}\n\n"
        f"Thanks!"
    )
    html = build_email_html(
        title="⏰ Reminder: Info Needed",
        subtitle=f"We're waiting on your response for '{print_label}'",
        rows=[
            ("Request", print_label),
            ("Status", "Waiting for your response"),
        ],
        cta_url=portal_url,
        cta_label="Respond Now",
        header_color="#f97316",  # Orange
        footer_note="Please respond so we can continue processing your print request.",
    )
    send_email([req["requester_email"]], subject, text, html)
    
    return RedirectResponse(url=f"/admin/request/{rid}?reminder_sent=1", status_code=303)


@app.post("/admin/request/{rid}/message")
def admin_send_message(
    request: Request,
    rid: str,
    message: str = Form(...),
    _=Depends(require_admin)
):
    """Admin sends a message to the requester"""
    conn = db()
    req = conn.execute("SELECT requester_email, requester_name, print_name, access_token FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")
    
    # Save message
    msg_id = str(uuid.uuid4())
    created = now_iso()
    conn.execute(
        "INSERT INTO request_messages (id, request_id, created_at, sender_type, message) VALUES (?, ?, ?, ?, ?)",
        (msg_id, rid, created, "admin", message)
    )
    conn.commit()
    conn.close()
    
    # Notify requester via email
    requester_email_on_status = get_bool_setting("requester_email_on_status", True)
    if requester_email_on_status and req["requester_email"]:
        print_label = req["print_name"] or f"Request {rid[:8]}"
        subject = f"[{APP_TITLE}] New message about '{print_label}'"
        text = f"New message from admin:\n\n{message}\n\nRespond here: {BASE_URL}/open/{rid}?token={req['access_token']}"
        html = build_email_html(
            title="💬 New Message",
            subtitle=f"About your request '{print_label}'",
            rows=[
                ("Message", message),
            ],
            cta_url=f"{BASE_URL}/open/{rid}?token={req['access_token']}",
            cta_label="View & Reply",
            header_color="#6366f1",
        )
        send_email([req["requester_email"]], subject, text, html)
    
    # Send push notification to requester
    if req["requester_email"]:
        user_prefs = get_user_notification_prefs(req["requester_email"])
        if user_prefs.get("status_push", True):  # Use status_push for messages too
            print_label = req["print_name"] or f"Request {rid[:8]}"
            truncated_msg = message[:80] + "..." if len(message) > 80 else message
            try:
                send_push_notification(
                    email=req["requester_email"],
                    title="💬 New Message",
                    body=f"About '{print_label}': {truncated_msg}",
                    url=f"/my/{rid}?token={req['access_token']}",
                    tag=f"message-{rid[:8]}"
                )
            except Exception as e:
                print(f"[PUSH] Error sending message notification: {e}")
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


# ─────────────────────────── BUILD MANAGEMENT ENDPOINTS ───────────────────────────

@app.post("/admin/build/{build_id}/start")
def admin_start_build(
    request: Request,
    build_id: str,
    printer: str = Form(...),
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Start printing a specific build."""
    conn = db()
    build = conn.execute("SELECT request_id FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    result = start_build(build_id, printer, comment)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Cannot start build - invalid state"))
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/fail")
def admin_fail_build(
    request: Request,
    build_id: str,
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Mark a build as failed."""
    conn = db()
    build = conn.execute("SELECT request_id FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    success = fail_build(build_id, comment or "Marked failed by admin")
    if not success:
        raise HTTPException(status_code=400, detail="Cannot fail build - invalid state")
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/retry")
def admin_retry_build(
    request: Request,
    build_id: str,
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Retry a failed build."""
    conn = db()
    build = conn.execute("SELECT request_id FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    success = retry_build(build_id, comment or "Retried by admin")
    if not success:
        raise HTTPException(status_code=400, detail="Cannot retry build - invalid state")
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/skip")
def admin_skip_build(
    request: Request,
    build_id: str,
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Skip a build (mark as skipped)."""
    conn = db()
    build = conn.execute("SELECT request_id FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    success = skip_build(build_id, comment or "Skipped by admin")
    if not success:
        raise HTTPException(status_code=400, detail="Cannot skip build - invalid state")
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/complete")
async def admin_complete_build(
    request: Request,
    build_id: str,
    comment: Optional[str] = Form(None),
    capture_snapshot: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Manually mark a build as completed (with optional snapshot capture)."""
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    if build["status"] != "PRINTING":
        raise HTTPException(status_code=400, detail="Can only complete a PRINTING build")
    
    # Optionally capture snapshot
    snapshot_b64 = None
    if capture_snapshot == "1" and get_bool_setting("enable_camera_snapshot", False):
        try:
            snapshot_data = await capture_camera_snapshot(build["printer"])
            if snapshot_data:
                snapshot_b64 = base64.b64encode(snapshot_data).decode("utf-8")
        except Exception as e:
            print(f"[BUILD-COMPLETE] Failed to capture snapshot: {e}")
    
    success = complete_build(build_id, comment or "Manually completed by admin", snapshot_b64)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot complete build - invalid state")
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/request/{rid}/configure-builds")
def admin_configure_builds(
    request: Request,
    rid: str,
    build_count: str = Form("1"),  # Accept as string to handle empty/invalid
    _=Depends(require_admin)
):
    """Configure the number of builds for a request. Adjusts builds up or down."""
    # Parse build_count with safe defaults
    try:
        build_count_int = int(build_count) if build_count and build_count.strip() else 1
    except (ValueError, TypeError):
        build_count_int = 1
    
    # Clamp to valid range
    build_count_int = max(1, min(20, build_count_int))
    
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Get current builds
    existing_builds = conn.execute(
        "SELECT * FROM builds WHERE request_id = ? ORDER BY build_number", (rid,)
    ).fetchall()
    current_count = len(existing_builds)
    
    now = now_iso()
    
    if build_count_int > current_count:
        # Add more builds
        for i in range(current_count + 1, build_count_int + 1):
            build_id = str(uuid.uuid4())
            # New builds start as PENDING, or READY if request is approved
            initial_status = "READY" if req["status"] in ["APPROVED", "PRINTING", "IN_PROGRESS"] else "PENDING"
            conn.execute("""
                INSERT INTO builds (id, request_id, build_number, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (build_id, rid, i, initial_status, now, now))
    elif build_count_int < current_count:
        # Remove builds from the end (only if they haven't started)
        for b in reversed(existing_builds):
            if current_count <= build_count_int:
                break
            if b["status"] in ["PENDING", "READY"]:
                conn.execute("DELETE FROM builds WHERE id = ?", (b["id"],))
                current_count -= 1
    
    # Update total_builds on request
    conn.execute("UPDATE requests SET total_builds = ?, updated_at = ? WHERE id = ?", 
                 (build_count_int, now, rid))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/build/{build_id}/delete")
def admin_delete_build(
    request: Request,
    build_id: str,
    force: Optional[str] = Form(None),
    confirm: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """
    Delete a build and clean up associated data.
    
    - Blocks PRINTING builds unless force=1
    - Warns for COMPLETED builds, requires confirm=1
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    # Require confirmation for COMPLETED builds
    if build["status"] == "COMPLETED" and confirm != "1":
        raise HTTPException(
            status_code=400, 
            detail="Deleting a COMPLETED build requires confirmation. Set confirm=1 to proceed."
        )
    
    # Require force for PRINTING builds
    force_delete = force == "1"
    
    result = delete_build(build_id, force=force_delete)
    
    if not result["success"]:
        if result.get("requires_force"):
            raise HTTPException(
                status_code=400, 
                detail=f"{result['error']} Stop the print first, or use force=1 to override."
            )
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to delete build"))
    
    return RedirectResponse(url=f"/admin/request/{result['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/notes")
def admin_update_build_notes(
    request: Request,
    build_id: str,
    notes: str = Form(""),
    _=Depends(require_admin)
):
    """Update notes for a specific build."""
    conn = db()
    build = conn.execute("SELECT request_id FROM builds WHERE id = ?", (build_id,)).fetchone()
    if not build:
        conn.close()
        raise HTTPException(status_code=404, detail="Build not found")
    
    conn.execute("UPDATE builds SET notes = ?, updated_at = ? WHERE id = ?", 
                 (notes.strip() if notes else None, now_iso(), build_id))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/update")
def admin_update_build(
    request: Request,
    build_id: str,
    print_name: Optional[str] = Form(""),
    material: Optional[str] = Form(""),
    est_hours: Optional[str] = Form(""),  # Hours component
    est_minutes: Optional[str] = Form(""),  # Minutes component
    notes: Optional[str] = Form(""),
    colors: Optional[str] = Form(""),
    printer: Optional[str] = Form(""),  # Allow editing printer assignment
    _=Depends(require_admin)
):
    """Update details for a specific build. All fields are optional."""
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    if not build:
        conn.close()
        raise HTTPException(status_code=404, detail="Build not found")
    
    updates = ["updated_at = ?"]
    values: list = [now_iso()]
    
    # Handle print_name - empty string means clear, None means don't update
    if print_name is not None:
        updates.append("print_name = ?")
        values.append(print_name.strip() if print_name.strip() else None)
    
    # Handle material - empty or "same as request" clears it
    if material is not None:
        updates.append("material = ?")
        values.append(material.strip() if material.strip() else None)
    
    # Handle estimated time - combine hours and minutes
    if est_hours is not None or est_minutes is not None:
        updates.append("print_time_minutes = ?")
        try:
            hours = int(est_hours) if est_hours and est_hours.strip() else 0
            minutes = int(est_minutes) if est_minutes and est_minutes.strip() else 0
            total_minutes = (hours * 60) + minutes
            values.append(total_minutes if total_minutes > 0 else None)
        except (ValueError, TypeError):
            values.append(None)
    
    # Handle notes
    if notes is not None:
        updates.append("notes = ?")
        values.append(notes.strip() if notes.strip() else None)
    
    # Handle colors
    if colors is not None:
        updates.append("colors = ?")
        values.append(colors.strip() if colors.strip() else None)
    
    # Handle printer - only allow changing if build is not PRINTING
    # and validate against known printers (excluding "ANY")
    if printer is not None and printer.strip():
        printer_val = printer.strip()
        valid_printer_codes = [p[0] for p in PRINTERS if p[0] != "ANY"]
        
        if printer_val in valid_printer_codes:
            if build["status"] != "PRINTING":
                updates.append("printer = ?")
                values.append(printer_val)
            # If PRINTING, silently ignore printer change (can't change mid-print)
        # Empty or invalid printer is ignored (don't clear an existing assignment)
    
    values.append(build_id)
    conn.execute(f"UPDATE builds SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/build/{build_id}/set-status")
def admin_set_build_status(
    request: Request,
    build_id: str,
    status: str = Form(...),
    _=Depends(require_admin)
):
    """
    Manually change a build's status. Respects valid transitions:
    - PENDING -> READY, SKIPPED
    - READY -> PENDING (demote), SKIPPED  
    - FAILED -> PENDING (retry), SKIPPED
    - COMPLETED/SKIPPED are terminal (no changes allowed)
    - PRINTING cannot be changed manually (use complete/fail actions)
    """
    conn = db()
    build = conn.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    if not build:
        conn.close()
        raise HTTPException(status_code=404, detail="Build not found")
    
    current_status = build["status"]
    new_status = status.upper().strip()
    
    # Validate the new status is a known status
    if new_status not in BUILD_STATUS_FLOW:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")
    
    # Don't allow changes from terminal states
    if current_status in ["COMPLETED", "SKIPPED"]:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Cannot change status from {current_status} (terminal state)")
    
    # Don't allow manual changes to/from PRINTING (use complete/fail endpoints)
    if current_status == "PRINTING" or new_status == "PRINTING":
        conn.close()
        raise HTTPException(status_code=400, detail="Use Complete/Fail actions for PRINTING builds")
    
    # Allow transitions based on BUILD_TRANSITIONS, plus READY -> PENDING (demote)
    allowed = BUILD_TRANSITIONS.get(current_status, [])
    if new_status not in allowed and not (current_status == "READY" and new_status == "PENDING"):
        conn.close()
        raise HTTPException(status_code=400, detail=f"Cannot change from {current_status} to {new_status}")
    
    # No change needed
    if current_status == new_status:
        conn.close()
        return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)
    
    now = now_iso()
    
    # Update the build status
    conn.execute(
        "UPDATE builds SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now, build_id)
    )
    
    # Record status event
    conn.execute(
        "INSERT INTO build_status_events (id, build_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), build_id, now, current_status, new_status, f"Manual status change by admin")
    )
    
    conn.commit()
    conn.close()
    
    # Sync parent request status
    sync_request_status_from_builds(build["request_id"])
    
    print(f"[BUILD-STATUS] Changed build {build_id[:8]} from {current_status} to {new_status}")
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/request/{rid}/start-next-build")
def admin_start_next_build(
    request: Request,
    rid: str,
    printer: str = Form(...),
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Start the next READY build for a request."""
    conn = db()
    next_build = conn.execute("""
        SELECT id FROM builds WHERE request_id = ? AND status = 'READY' 
        ORDER BY build_number LIMIT 1
    """, (rid,)).fetchone()
    conn.close()
    
    if not next_build:
        raise HTTPException(status_code=400, detail="No READY builds available")
    
    result = start_build(next_build["id"], printer, comment)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to start build"))
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/build/{build_id}/start")
def admin_start_specific_build(
    request: Request,
    build_id: str,
    printer: str = Form(...),
    comment: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Start a specific build by ID (allows out-of-order printing)."""
    conn = db()
    build = conn.execute("SELECT id, request_id, status FROM builds WHERE id = ?", (build_id,)).fetchone()
    conn.close()
    
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    
    if build["status"] not in ["PENDING", "READY"]:
        raise HTTPException(status_code=400, detail=f"Cannot start build in {build['status']} status")
    
    result = start_build(build_id, printer, comment)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to start build"))
    
    return RedirectResponse(url=f"/admin/request/{build['request_id']}", status_code=303)


@app.post("/admin/request/{rid}/reorder-builds")
def admin_reorder_builds(
    request: Request,
    rid: str,
    build_order: str = Form(...),  # Comma-separated build IDs in new order
    _=Depends(require_admin)
):
    """Reorder builds by providing build IDs in desired order.
    
    Allows reordering even while builds are printing - printing builds will
    maintain their relative position in the new order. This enables reordering
    the queue of upcoming builds without affecting in-progress work.
    """
    conn = db()
    
    # Get current builds
    builds = conn.execute(
        "SELECT id, status, build_number FROM builds WHERE request_id = ? ORDER BY build_number", 
        (rid,)
    ).fetchall()
    
    if not builds:
        conn.close()
        raise HTTPException(status_code=404, detail="No builds found for this request")
    
    # Parse new order
    new_order = [bid.strip() for bid in build_order.split(",") if bid.strip()]
    
    # Validate that all build IDs are present
    existing_ids = {b["id"] for b in builds}
    if set(new_order) != existing_ids:
        conn.close()
        raise HTTPException(status_code=400, detail="Build order must include all build IDs exactly once")
    
    # Check if any PRINTING builds changed position - that's not allowed
    # But reordering non-printing builds is fine
    build_status = {b["id"]: b["status"] for b in builds}
    old_positions = {b["id"]: b["build_number"] for b in builds}
    
    for new_pos, build_id in enumerate(new_order, start=1):
        if build_status[build_id] == "PRINTING" and old_positions[build_id] != new_pos:
            conn.close()
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot move build #{old_positions[build_id]} while it's printing. You can reorder other builds around it."
            )
    
    # Update build numbers
    now = now_iso()
    for new_number, build_id in enumerate(new_order, start=1):
        conn.execute(
            "UPDATE builds SET build_number = ?, updated_at = ? WHERE id = ?",
            (new_number, now, build_id)
        )
    
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/priority")
def admin_set_priority(
    request: Request,
    rid: str,
    priority: int = Form(...),
    _=Depends(require_admin)
):
    if priority < 1 or priority > 5:
        raise HTTPException(status_code=400, detail="Priority must be 1..5")

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    conn.execute("UPDATE requests SET priority = ?, updated_at = ? WHERE id = ?", (priority, now_iso(), rid))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/request/{rid}/print-time")
def admin_set_print_time(
    request: Request,
    rid: str,
    hours: int = Form(0),
    minutes: int = Form(0),
    turnaround_minutes: int = Form(30),
    _=Depends(require_admin)
):
    """Set print time estimate (hours + minutes) for a request."""
    # Convert hours and minutes to total minutes
    slicer_minutes = hours * 60 + minutes
    
    if slicer_minutes < 0 or slicer_minutes > 999 * 60:  # up to 999 hours (0 allowed to clear)
        raise HTTPException(status_code=400, detail="Print time must be 0 to 999 hours")
    if turnaround_minutes < 0 or turnaround_minutes > 1440:  # 0 to 24 hours
        raise HTTPException(status_code=400, detail="Turnaround must be 0..1440 minutes")

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    # Get adjusted time based on historical accuracy
    if slicer_minutes > 0:
        adjusted = get_adjusted_print_time(slicer_minutes, req["printer"], req["material"])
        adjusted_minutes = adjusted["adjusted_minutes"]
    else:
        adjusted_minutes = 0

    # Store both the slicer estimate (for accuracy tracking) and the adjusted time (for queue predictions)
    conn.execute(
        "UPDATE requests SET slicer_estimate_minutes = ?, print_time_minutes = ?, turnaround_minutes = ?, updated_at = ? WHERE id = ?",
        (slicer_minutes if slicer_minutes > 0 else None, adjusted_minutes if adjusted_minutes > 0 else None, turnaround_minutes, now_iso(), rid)
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


def admin_set_special_notes(
    request: Request,
    rid: str,
    special_notes: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    cleaned = (special_notes or "").strip()
    if cleaned == "":
        cleaned = None

    conn.execute("UPDATE requests SET special_notes = ?, updated_at = ? WHERE id = ?", (cleaned, now_iso(), rid))
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), req["status"], req["status"], "Updated special notes")
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/admin-notes")
def admin_set_admin_notes(
    request: Request,
    rid: str,
    admin_notes: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    cleaned = (admin_notes or "").strip()
    if cleaned == "":
        cleaned = None

    conn.execute("UPDATE requests SET admin_notes = ?, updated_at = ? WHERE id = ?", (cleaned, now_iso(), rid))
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), req["status"], req["status"], "Updated admin work notes")
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/edit")
def admin_edit_request(
    request: Request,
    rid: str,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    print_name: str = Form(""),
    printer: str = Form(...),
    material: str = Form(...),
    colors: str = Form(...),
    link_url: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    if printer not in [p[0] for p in PRINTERS]:
        raise HTTPException(status_code=400, detail="Invalid printer selection")
    if material not in [m[0] for m in MATERIALS]:
        raise HTTPException(status_code=400, detail="Invalid material selection")

    cleaned_link = (link_url or "").strip()
    if cleaned_link:
        try:
            u = urllib.parse.urlparse(cleaned_link)
            if u.scheme not in ("http", "https"):
                raise ValueError("Invalid scheme")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid link URL")
    cleaned_link = cleaned_link or None

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    conn.execute(
        """UPDATE requests
           SET requester_name = ?, requester_email = ?, print_name = ?, printer = ?, material = ?, colors = ?, link_url = ?, notes = ?, updated_at = ?
           WHERE id = ?""",
        (
            requester_name.strip(),
            requester_email.strip(),
            print_name.strip() if print_name else None,
            printer,
            material,
            (colors or "").strip(),
            cleaned_link,
            notes,
            now_iso(),
            rid,
        )
    )
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), req["status"], req["status"], "Admin edited request details")
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/add-file")
async def admin_add_file(
    request: Request,
    rid: str,
    upload: List[UploadFile] = File(...),
    _=Depends(require_admin)
):
    if not upload or len(upload) == 0:
        raise HTTPException(status_code=400, detail="No files provided")

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    files_added = []
    errors = []

    for file in upload:
        if not file or not file.filename:
            continue

        ext = safe_ext(file.filename)
        if ext not in ALLOWED_EXTS:
            errors.append(f"{file.filename}: File type not allowed")
            continue

        data = await file.read()
        if len(data) > max_bytes:
            errors.append(f"{file.filename}: File too large (max {MAX_UPLOAD_MB}MB)")
            continue

        stored = f"{uuid.uuid4()}{ext}"
        out_path = os.path.join(UPLOAD_DIR, stored)

        sha = hashlib.sha256(data).hexdigest()
        with open(out_path, "wb") as f:
            f.write(data)

        # Parse 3D file metadata (dimensions, volume, etc.)
        file_metadata = parse_3d_file_metadata(out_path, file.filename)
        file_metadata_json = safe_json_dumps(file_metadata) if file_metadata else None

        conn.execute(
            """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256, file_metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), rid, now_iso(), file.filename, stored, len(data), sha, file_metadata_json)
        )
        files_added.append(file.filename)

    if files_added:
        comment = f"Admin added {len(files_added)} file(s): {', '.join(files_added)}"
        conn.execute(
            "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), rid, now_iso(), req["status"], req["status"], comment)
        )
        conn.execute("UPDATE requests SET updated_at = ? WHERE id = ?", (now_iso(), rid))
        conn.commit()

    conn.close()

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.get("/admin/request/{rid}/file/{file_id}")
def admin_download_file(request: Request, rid: str, file_id: str, _=Depends(require_admin)):
    """Protected file download endpoint for admins only."""
    conn = db()
    
    # Verify request exists
    req = conn.execute("SELECT id FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Verify file exists and belongs to this request
    file_info = conn.execute(
        "SELECT id, stored_filename, original_filename FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    conn.close()
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = os.path.join(UPLOAD_DIR, file_info["stored_filename"])
    
    # Verify file exists on disk
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Serve with Content-Disposition to force download
    return FileResponse(
        path=file_path,
        filename=file_info["original_filename"],
        media_type="application/octet-stream"
    )


@app.post("/admin/request/{rid}/file/{file_id}/delete")
def admin_delete_file(request: Request, rid: str, file_id: str, _=Depends(require_admin)):
    """Delete a file from a request."""
    conn = db()
    
    # Verify request exists
    req = conn.execute("SELECT id FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Get file info before deleting
    file_info = conn.execute(
        "SELECT id, stored_filename, original_filename FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    
    if not file_info:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    
    # Delete from database
    conn.execute("DELETE FROM files WHERE id = ? AND request_id = ?", (file_id, rid))
    conn.commit()
    conn.close()
    
    # Try to delete from disk (don't fail if file doesn't exist)
    file_path = os.path.join(UPLOAD_DIR, file_info["stored_filename"])
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass  # File couldn't be deleted, but DB record is gone
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.post("/admin/request/{rid}/file/{file_id}/assign-build")
def admin_assign_file_to_build(
    request: Request,
    rid: str,
    file_id: str,
    build_id: str = Form(""),
    _=Depends(require_admin)
):
    """Assign or unassign a file to a specific build."""
    conn = db()
    
    # Verify request exists
    req = conn.execute("SELECT id FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Verify file exists and belongs to this request
    file_info = conn.execute(
        "SELECT id, original_filename FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    
    if not file_info:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    
    # If build_id is empty, unassign the file
    if not build_id or build_id.strip() == "":
        conn.execute("UPDATE files SET build_id = NULL WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()
        return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)
    
    # Verify build exists and belongs to this request
    build = conn.execute(
        "SELECT id, build_number FROM builds WHERE id = ? AND request_id = ?",
        (build_id, rid)
    ).fetchone()
    
    if not build:
        conn.close()
        raise HTTPException(status_code=404, detail="Build not found")
    
    # Assign file to build
    conn.execute("UPDATE files SET build_id = ? WHERE id = ?", (build_id, file_id))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.get("/admin/request/{rid}/file/{file_id}/preview")
async def admin_preview_file(request: Request, rid: str, file_id: str, _=Depends(require_admin)):
    """Preview a 3D file (STL/OBJ/3MF) using an embedded viewer."""
    conn = db()
    
    # Verify request exists
    req = conn.execute("SELECT id FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Verify file exists and belongs to this request
    file_info = conn.execute(
        "SELECT id, stored_filename, original_filename, file_metadata FROM files WHERE id = ? AND request_id = ?",
        (file_id, rid)
    ).fetchone()
    conn.close()
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check if it's a supported 3D file
    ext = os.path.splitext(file_info["original_filename"].lower())[1]
    if ext not in [".stl", ".obj", ".3mf"]:
        raise HTTPException(status_code=400, detail="Preview only available for STL, OBJ, and 3MF files")
    
    file_path = os.path.join(UPLOAD_DIR, file_info["stored_filename"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Parse metadata
    metadata = None
    if file_info["file_metadata"]:
        try:
            metadata = json.loads(file_info["file_metadata"])
        except:
            pass
    
    return templates.TemplateResponse("file_preview.html", {
        "request": request,
        "req_id": rid,
        "file": dict(file_info),
        "metadata": metadata,
        "file_url": f"/admin/request/{rid}/file/{file_id}",
    })


@app.post("/admin/batch-update")
def admin_batch_update(
    request: Request,
    request_ids: str = Form(""),
    priority: str = Form(""),
    status: str = Form(""),
    _=Depends(require_admin)
):
    """Mass update multiple requests at once."""
    ids = [rid.strip() for rid in request_ids.split(",") if rid.strip()]
    if not ids:
        raise HTTPException(status_code=400, detail="No requests selected")
    
    # Convert empty strings to None
    priority_int: Optional[int] = None
    status_str: Optional[str] = None
    
    if priority and priority.strip():
        try:
            priority_int = int(priority)
        except ValueError:
            raise HTTPException(status_code=400, detail="Priority must be a valid integer")
    
    if status and status.strip():
        status_str = status.strip()
    
    # Validate inputs
    if priority_int is not None and (priority_int < 1 or priority_int > 5):
        raise HTTPException(status_code=400, detail="Priority must be 1..5")
    if status_str is not None and status_str not in STATUS_FLOW:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    # If nothing to update, return early
    if priority_int is None and status_str is None:
        return RedirectResponse(url="/admin", status_code=303)
    
    conn = db()
    updates = []
    if priority_int is not None:
        updates.append(f"priority = {priority_int}")
    if status_str is not None:
        updates.append(f"status = '{status_str}'")
    
    update_str = ", ".join(updates)
    update_str += f", updated_at = '{now_iso()}'"
    
    placeholders = ",".join(["?" for _ in ids])
    conn.execute(
        f"UPDATE requests SET {update_str} WHERE id IN ({placeholders})",
        ids
    )
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin", status_code=303)


# ─────────────────────────── CAMERA ENDPOINTS ───────────────────────────

@app.get("/api/camera/{printer_code}/snapshot")
async def camera_snapshot(printer_code: str):
    """Get a snapshot from printer camera (public for live view feature)"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        logger.warning(f"[CAMERA] Invalid printer code requested: {printer_code}")
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    try:
        image_data = await capture_camera_snapshot(printer_code)
        if not image_data:
            logger.warning(f"[CAMERA] No image data returned for {printer_code}")
            raise HTTPException(status_code=503, detail="Camera not available or not configured")
        
        logger.debug(f"[CAMERA] Snapshot captured for {printer_code}, size: {len(image_data)} bytes")
        return Response(content=image_data, media_type="image/jpeg")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[CAMERA] Error getting snapshot for {printer_code}: {e}")
        raise HTTPException(status_code=503, detail=f"Camera error: {str(e)}")


@app.get("/api/camera/{printer_code}/stream")
async def camera_stream_proxy(request: Request, printer_code: str, _=Depends(require_admin)):
    """Proxy the MJPEG stream from the printer's camera"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    camera_url = get_camera_url(printer_code)
    if not camera_url:
        raise HTTPException(status_code=503, detail="Camera not configured for this printer")
    
    print(f"[CAMERA] Starting stream proxy for {printer_code} from {camera_url}")
    
    # We need to get the content-type first, then stream
    # Create a client that stays open for the generator
    client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None))
    
    try:
        response = await client.send(
            client.build_request("GET", camera_url),
            stream=True
        )
        content_type = response.headers.get("content-type", "multipart/x-mixed-replace;boundary=boundarydonotcross")
        print(f"[CAMERA] Connected to {printer_code}, content-type: {content_type}")
        
        async def stream_generator():
            """Generator that proxies the MJPEG stream"""
            try:
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    yield chunk
            except Exception as e:
                print(f"[CAMERA] Stream error for {printer_code}: {e}")
            finally:
                await response.aclose()
                await client.aclose()
        
        return StreamingResponse(
            stream_generator(),
            media_type=content_type,
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    except Exception as e:
        await client.aclose()
        print(f"[CAMERA] Failed to connect to {printer_code}: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to connect to camera: {e}")


@app.get("/api/camera/status")
async def camera_status(_=Depends(require_admin)):
    """Check which printers have cameras configured"""
    return {
        "ADVENTURER_4": {
            "configured": bool(get_camera_url("ADVENTURER_4")),
            "url": get_camera_url("ADVENTURER_4"),
        },
        "AD5X": {
            "configured": bool(get_camera_url("AD5X")),
            "url": get_camera_url("AD5X"),
        },
    }


@app.get("/api/request/{rid}/completion-snapshot")
def get_completion_snapshot(rid: str, _=Depends(require_admin)):
    """Get the completion snapshot for a request"""
    conn = db()
    req = conn.execute("SELECT completion_snapshot FROM requests WHERE id = ?", (rid,)).fetchone()
    conn.close()
    
    if not req or not req["completion_snapshot"]:
        raise HTTPException(status_code=404, detail="No completion snapshot available")
    
    try:
        image_data = base64.b64decode(req["completion_snapshot"])
        return Response(content=image_data, media_type="image/jpeg")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decode snapshot")


@app.get("/api/poll-debug")
def get_poll_debug(_=Depends(require_admin)):
    """Get polling debug logs for troubleshooting auto-complete issues"""
    return {
        "logs": get_poll_debug_log(),
        "printer_cache": {k: v for k, v in _printer_status_cache.items()},
        "failure_counts": {k: v for k, v in _printer_failure_count.items()},
    }


@app.get("/api/slicer-accuracy")
def get_slicer_accuracy_api(printer: str = None, material: str = None, _=Depends(require_admin)):
    """Get slicer accuracy stats for a printer/material combo"""
    accuracy = get_slicer_accuracy_factor(printer, material)
    
    # Also get recent history
    conn = db()
    recent = conn.execute("""
        SELECT printer, material, print_name, duration_minutes, estimated_minutes, completed_at
        FROM print_history 
        WHERE estimated_minutes IS NOT NULL AND estimated_minutes > 0
        ORDER BY completed_at DESC
        LIMIT 20
    """).fetchall()
    conn.close()
    
    history = []
    for row in recent:
        actual = row["duration_minutes"]
        est = row["estimated_minutes"]
        diff_pct = round((actual / est - 1) * 100, 1) if est > 0 else 0
        history.append({
            "printer": row["printer"],
            "material": row["material"],
            "print_name": row["print_name"],
            "actual_minutes": actual,
            "estimated_minutes": est,
            "diff_percent": diff_pct,
            "completed_at": row["completed_at"],
        })
    
    return {
        "accuracy": accuracy,
        "recent_history": history,
    }


@app.get("/api/version")
def get_version():
    """Get application version"""
    return {"version": APP_VERSION, "title": APP_TITLE}


@app.get("/api/admin/check")
def check_admin_status(request: Request):
    """Check if the current user is authenticated as admin.
    Returns {is_admin: true/false} - used by PWA to show admin tab.
    """
    pw = request.cookies.get("admin_pw", "")
    is_admin = bool(pw and ADMIN_PASSWORD and pw == ADMIN_PASSWORD)
    return {"is_admin": is_admin}


# ─────────────────────────── PUSH NOTIFICATION API ───────────────────────────

def _get_email_from_token(token: str) -> Optional[str]:
    """Helper to resolve a my-requests token to email"""
    if not token:
        return None
    conn = db()
    row = conn.execute(
        "SELECT email FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    conn.close()
    return row["email"] if row else None


async def _parse_request_data(request: Request) -> dict:
    """Parse request body - handles both JSON and FormData, returns empty dict on error.
    Logs content-type and body length for debugging push issues."""
    content_type = request.headers.get("content-type", "")
    
    # Log request info for debugging (without sensitive data)
    try:
        body_bytes = await request.body()
        body_len = len(body_bytes) if body_bytes else 0
        print(f"[PUSH_PARSE] Content-Type: {content_type}, Body length: {body_len}")
    except:
        body_bytes = b""
        body_len = 0
        print(f"[PUSH_PARSE] Content-Type: {content_type}, Body: unreadable")
    
    # Try JSON first
    if "application/json" in content_type:
        try:
            if body_bytes:
                return json.loads(body_bytes)
            return {}
        except json.JSONDecodeError as e:
            print(f"[PUSH_PARSE] JSON decode error: {e}")
            return {}
        except Exception as e:
            print(f"[PUSH_PARSE] JSON parse error: {e}")
            return {}
    
    # Try FormData
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        try:
            # Need to re-create request body since we already consumed it
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive
            form = await request.form()
            data = dict(form)
            # Parse nested JSON in subscription field
            if "subscription" in data and isinstance(data["subscription"], str):
                try:
                    data["subscription"] = json.loads(data["subscription"])
                except:
                    pass
            return data
        except Exception as e:
            print(f"[PUSH_PARSE] FormData parse error: {e}")
            return {}
    
    # Fallback: try JSON anyway (some clients don't set Content-Type)
    try:
        if body_bytes:
            return json.loads(body_bytes)
    except:
        pass
    
    return {}


@app.get("/api/push/vapid-public-key")
def get_vapid_public_key():
    """Get the VAPID public key for push subscription"""
    if not VAPID_PUBLIC_KEY:
        return {"error": "Push notifications not configured", "publicKey": None}
    return {"publicKey": VAPID_PUBLIC_KEY}


# Test push notification endpoint
@app.post("/api/push/test")
async def test_push_notification(request: Request):
    """Test push notification for a user (by email or token) - returns detailed results"""
    try:
        data = await _parse_request_data(request)
        
        # Accept either email or token
        email = data.get("email")
        token = data.get("token")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token", "status": "error"}
            )
        
        print(f"[PUSH TEST] Testing push for email: {email}")
        result = send_push_notification(
            email, 
            "Test Notification", 
            "This is a test push notification from Printellect.",
            "/my-requests/view"
        )
        
        if result.get("sent", 0) > 0:
            return {"success": True, "status": "sent", "details": result}
        elif result.get("errors"):
            return {"success": False, "status": "error", "error": result.get("errors", [{}])[0].get("error", "Unknown error"), "details": result}
        else:
            return {"success": False, "status": "no_subscriptions", "error": "No push subscriptions found for this email", "details": result}
    except Exception as e:
        print(f"[PUSH TEST] Exception: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e), "status": "exception"}
        )


@app.post("/api/push/subscribe")
async def subscribe_push(request: Request):
    """Subscribe to push notifications for a user (with diagnostics logging)
    
    Accepts either:
    - JSON with {email, subscription}
    - FormData with {token, subscription} (token resolved to email)
    - Session-based auth via user_session cookie
    """
    try:
        data = await _parse_request_data(request)
        print(f"[PUSH] Subscribe attempt: {data}")
        
        # Accept either email or token
        email = data.get("email", "")
        token = data.get("token", "")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        subscription = data.get("subscription", {})
        
        if not email:
            print(f"[PUSH] ERROR: Missing email (token={token})")
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token"}
            )
        
        if not subscription:
            print(f"[PUSH] ERROR: Missing subscription data")
            return JSONResponse(
                status_code=400, 
                content={"success": False, "error": "Missing subscription"}
            )
        
        endpoint = subscription.get("endpoint")
        keys = subscription.get("keys", {})
        p256dh = keys.get("p256dh")
        auth = keys.get("auth")
        
        if not endpoint or not p256dh or not auth:
            print(f"[PUSH] ERROR: Invalid subscription data: {subscription}")
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid subscription data (missing endpoint/keys)"}
            )
        
        conn = db()
        # Check if subscription already exists for this endpoint
        existing = conn.execute(
            "SELECT id, email FROM push_subscriptions WHERE endpoint = ?",
            (endpoint,)
        ).fetchone()
        
        if existing:
            # Update email if endpoint exists but email changed
            if existing["email"].lower() != email.lower():
                conn.execute(
                    "UPDATE push_subscriptions SET email = ? WHERE endpoint = ?",
                    (email.lower(), endpoint)
                )
                conn.commit()
                print(f"[PUSH] Updated subscription email: {endpoint}")
            conn.close()
            return {"success": True, "status": "already_subscribed"}
        
        conn.execute(
            """INSERT INTO push_subscriptions (id, email, endpoint, p256dh, auth, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), email.lower(), endpoint, p256dh, auth, now_iso())
        )
        conn.commit()
        conn.close()
        print(f"[PUSH] Subscribed: {email} -> {endpoint[:50]}...")
        return {"success": True, "status": "subscribed"}
    except Exception as e:
        print(f"[PUSH] ERROR: Exception in subscribe_push: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


# Push diagnostics endpoint
@app.get("/api/push/diagnostics/{email}")
def push_diagnostics(email: str):
    """Return all push subscriptions for a user (by email, for diagnostics)"""
    conn = db()
    subs = conn.execute(
        "SELECT id, email, endpoint, p256dh, auth, created_at FROM push_subscriptions WHERE email = ?",
        (email,)
    ).fetchall()
    conn.close()
    return {"subscriptions": [dict(row) for row in subs]}


@app.get("/api/push/health")
def push_health_check(_=Depends(require_admin)):
    """Admin-only push notification health check endpoint.
    Confirms VAPID configuration, subscription counts, and tests push capability.
    """
    health = {
        "ok": True,
        "vapid_configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "vapid_public_key_length": len(VAPID_PUBLIC_KEY) if VAPID_PUBLIC_KEY else 0,
        "vapid_claims_email": VAPID_CLAIMS_EMAIL,
        "subscriptions": {"total": 0, "by_email": {}},
        "pywebpush_available": False,
        "test_result": None,
        "errors": []
    }
    
    # Check pywebpush
    try:
        from pywebpush import webpush, WebPushException
        health["pywebpush_available"] = True
    except ImportError:
        health["ok"] = False
        health["errors"].append("pywebpush not installed")
    
    # Check VAPID
    if not health["vapid_configured"]:
        health["ok"] = False
        health["errors"].append("VAPID keys not configured")
    
    # Count subscriptions
    conn = db()
    try:
        total = conn.execute("SELECT COUNT(*) as cnt FROM push_subscriptions").fetchone()
        health["subscriptions"]["total"] = total["cnt"] if total else 0
        
        by_email = conn.execute(
            "SELECT email, COUNT(*) as cnt FROM push_subscriptions GROUP BY email ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        health["subscriptions"]["by_email"] = {row["email"]: row["cnt"] for row in by_email}
    except Exception as e:
        health["errors"].append(f"DB error: {e}")
    finally:
        conn.close()
    
    # Test VAPID JWT generation
    if health["vapid_configured"]:
        try:
            from py_vapid import Vapid
            import base64
            key_bytes = base64.urlsafe_b64decode(VAPID_PRIVATE_KEY + '==')
            v = Vapid.from_raw(key_bytes)
            test_claims = {
                'sub': VAPID_CLAIMS_EMAIL if VAPID_CLAIMS_EMAIL.startswith('mailto:') else f'mailto:{VAPID_CLAIMS_EMAIL}',
                'aud': 'https://fcm.googleapis.com'
            }
            token = v.sign(test_claims)
            health["test_result"] = "JWT generation OK"
        except Exception as e:
            health["ok"] = False
            health["errors"].append(f"VAPID JWT test failed: {e}")
    
    return health


# Service Worker + Push debugging info endpoint
@app.get("/api/sw/debug")
def sw_debug_info():
    """Return server-side SW and push configuration info for debugging"""
    import os
    import time
    sw_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static', 'sw.js'))
    
    # Check VAPID key validity by trying to generate a test JWT
    jwt_test = {"status": "not_tested"}
    if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
        try:
            from py_vapid import Vapid
            import base64
            key_bytes = base64.urlsafe_b64decode(VAPID_PRIVATE_KEY + '==')
            v = Vapid.from_raw(key_bytes)
            test_claims = {
                'sub': VAPID_CLAIMS_EMAIL if VAPID_CLAIMS_EMAIL.startswith('mailto:') else f'mailto:{VAPID_CLAIMS_EMAIL}',
                'aud': 'https://web.push.apple.com'
            }
            token = v.sign(test_claims)
            # Decode the JWT payload to verify claims
            auth_header = token.get('Authorization', '')
            if auth_header.startswith('vapid t='):
                jwt_token = auth_header.split('t=')[1].split(',')[0]
                parts = jwt_token.split('.')
                if len(parts) == 3:
                    import json
                    payload_b64 = parts[1]
                    # Add padding
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += '=' * padding
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    now = int(time.time())
                    exp = payload.get('exp', 0)
                    jwt_test = {
                        "status": "ok",
                        "aud": payload.get('aud'),
                        "sub": payload.get('sub'),
                        "exp": exp,
                        "exp_human": time.ctime(exp),
                        "exp_in_seconds": exp - now,
                        "server_time": now,
                        "server_time_human": time.ctime(now),
                    }
        except Exception as e:
            jwt_test = {"status": "error", "error": str(e)}
    
    return {
        "sw_file_exists": os.path.exists(sw_path),
        "sw_file_path": sw_path,
        "vapid_configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "vapid_public_key_length": len(VAPID_PUBLIC_KEY) if VAPID_PUBLIC_KEY else 0,
        "vapid_private_key_length": len(VAPID_PRIVATE_KEY) if VAPID_PRIVATE_KEY else 0,
        "vapid_claims_email": VAPID_CLAIMS_EMAIL,
        "jwt_test": jwt_test,
        "base_url": BASE_URL,
        "app_version": APP_VERSION
    }


@app.post("/api/push/unsubscribe")
async def unsubscribe_push(request: Request):
    """Unsubscribe from push notifications (per user/email or token)
    
    Accepts either:
    - JSON with {email, endpoint?}
    - FormData with {token, endpoint?}
    - Session-based auth via user_session cookie
    """
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        endpoint = data.get("endpoint")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token"}
            )
        
        conn = db()
        if endpoint:
            result = conn.execute(
                "DELETE FROM push_subscriptions WHERE email = ? AND endpoint = ?",
                (email, endpoint)
            )
        else:
            # Remove all subscriptions for this user
            result = conn.execute(
                "DELETE FROM push_subscriptions WHERE email = ?",
                (email,)
            )
        deleted = result.rowcount
        conn.commit()
        conn.close()
        
        print(f"[PUSH] Unsubscribed {deleted} subscription(s) for {email}")
        return {"success": True, "status": "unsubscribed", "deleted": deleted}
    except Exception as e:
        print(f"[PUSH] ERROR in unsubscribe: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/push/clear-all")
async def clear_all_push_subscriptions(request: Request):
    """Clear ALL push subscriptions for a user - use when VAPID keys change"""
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token"}
            )
        
        conn = db()
        result = conn.execute(
            "DELETE FROM push_subscriptions WHERE email = ?",
            (email,)
        )
        deleted = result.rowcount
        conn.commit()
        conn.close()
        print(f"[PUSH] Cleared {deleted} subscriptions for {email}")
        return {"success": True, "status": "cleared", "deleted": deleted}
    except Exception as e:
        print(f"[PUSH] ERROR in clear-all: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


# ─────────────────────────── USER NOTIFICATION PREFERENCES API ───────────────────────────
@app.get("/api/user/notification-prefs")
async def api_get_user_notification_prefs(request: Request, email: str = None, token: str = None):
    """
    Get user-level notification preferences.
    Requires either email, my-requests token, or user session for auth.
    """
    # Try to get email from token if not provided directly
    if not email and token:
        email = _get_email_from_token(token)
    
    # Fallback to session-based auth
    if not email:
        user = await get_current_user(request)
        if user:
            email = user.email
    
    if not email:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Missing email or token"}
        )
    
    prefs = get_user_notification_prefs(email)
    return {
        "success": True,
        "email": email,
        "prefs": prefs
    }


@app.post("/api/user/notification-prefs")
async def api_update_user_notification_prefs(request: Request):
    """
    Update user-level notification preferences.
    Expected JSON body: {
        "email": "user@example.com", OR "token": "my-requests-token",
        "prefs": {
            "progress_push": true,
            "progress_email": false,
            "progress_milestones": "25,50,75,90",
            "status_push": true,
            "status_email": true,
            "broadcast_push": true
        }
    }
    Also supports session-based auth via user_session cookie.
    """
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        prefs = data.get("prefs", {})
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token"}
            )
        
        # Validate prefs structure - boolean keys
        bool_keys = {"progress_push", "progress_email", "status_push", "status_email", "broadcast_push"}
        sanitized_prefs = {}
        for key in bool_keys:
            if key in prefs:
                sanitized_prefs[key] = bool(prefs[key])
        
        # Handle progress_milestones (comma-separated string of percentages)
        if "progress_milestones" in prefs:
            milestones_raw = str(prefs["progress_milestones"])
            # Validate and sanitize milestones
            valid_milestones = []
            for p in milestones_raw.split(","):
                p = p.strip()
                if p.isdigit():
                    pct = int(p)
                    if 0 < pct < 100:
                        valid_milestones.append(pct)
            sanitized_prefs["progress_milestones"] = ",".join(str(m) for m in sorted(set(valid_milestones)))
        
        # Get existing prefs and merge
        existing = get_user_notification_prefs(email)
        existing.update(sanitized_prefs)
        
        success = update_user_notification_prefs(email, existing)
        
        if success:
            print(f"[PREFS] Updated notification prefs for {email}: {existing}")
            return {"success": True, "prefs": existing}
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": "Failed to update preferences"}
            )
    except Exception as e:
        print(f"[PREFS] ERROR: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.get("/api/notification-prefs/{rid}")
async def get_notification_prefs(rid: str, token: str = ""):
    """Get notification preferences for a request"""
    conn = db()
    req = conn.execute(
        "SELECT notification_prefs, access_token FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    conn.close()
    
    if not req:
        return {"email": True, "push": False}
    
    # Verify token
    if req["access_token"] != token:
        return {"email": True, "push": False}
    
    prefs = {"email": True, "push": False}
    if req["notification_prefs"]:
        try:
            prefs = json.loads(req["notification_prefs"])
        except:
            pass
    
    return prefs


@app.post("/api/notification-prefs/{rid}")
async def update_notification_prefs(rid: str, request: Request):
    """Update notification preferences for a request"""
    try:
        data = await _parse_request_data(request)
    except:
        data = {}
    
    token = data.get("token", "")
    email_enabled = data.get("email", True)
    push_enabled = data.get("push", False)
    
    conn = db()
    req = conn.execute(
        "SELECT access_token FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    
    if not req:
        conn.close()
        return JSONResponse(status_code=404, content={"ok": False, "error": "Request not found"})
    
    # Verify token
    if req["access_token"] != token:
        conn.close()
        return JSONResponse(status_code=403, content={"ok": False, "error": "Invalid token"})
    
    prefs = json.dumps({"email": email_enabled, "push": push_enabled})
    conn.execute(
        "UPDATE requests SET notification_prefs = ? WHERE id = ?",
        (prefs, rid)
    )
    conn.commit()
    conn.close()
    
    return {"ok": True, "status": "updated", "prefs": {"email": email_enabled, "push": push_enabled}}


@app.post("/api/update-global-email-notify")
async def update_global_email_notify(token: str = Form(...), email_enabled: str = Form("1")):
    """Update email notification preference for ALL requests belonging to a user"""
    conn = db()
    
    # Find user email from token
    token_row = conn.execute(
        "SELECT email FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    
    if not token_row:
        conn.close()
        return {"success": False, "error": "Invalid token"}
    
    user_email = token_row["email"]
    enabled = email_enabled == "1"
    
    # Update all requests for this user - preserve existing push setting
    conn.execute(
        """UPDATE requests 
           SET notification_prefs = json_set(
               COALESCE(notification_prefs, '{"email": true, "push": false}'), 
               '$.email', 
               json(?)
           )
           WHERE LOWER(requester_email) = LOWER(?)""",
        (enabled, user_email)
    )
    conn.commit()
    
    # Count updated rows
    updated = conn.total_changes
    conn.close()
    
    return {"success": True, "email": user_email, "enabled": enabled, "updated_requests": updated}


@app.get("/api/rush-pricing")
def get_rush_pricing(name: str = ""):
    """Get dynamic rush pricing based on queue and requester name"""
    printer_suggestions = get_printer_suggestions()
    queue_size = printer_suggestions.get("total_queue", 0)
    pricing = calculate_rush_price(queue_size, name)
    return {
        "price": pricing["final_price"],
        "base_fee": pricing["base_fee"],
        "queue_addon": pricing["queue_addon"],
        "queue_reason": pricing["queue_reason"],
        "is_special": pricing["is_special"],
        "queue_size": queue_size,
    }


# ─────────────────────────── REQUEST TEMPLATES ───────────────────────────

@app.get("/api/templates")
def list_templates():
    """Get all saved request templates"""
    return {"templates": get_request_templates()}


@app.post("/api/templates")
def create_template(
    name: str = Form(...),
    requester_name: str = Form(""),
    requester_email: str = Form(""),
    printer: str = Form("ANY"),
    material: str = Form("ANY"),
    colors: str = Form(""),
    notes: str = Form(""),
):
    """Save a new request template"""
    tid = str(uuid.uuid4())
    now = now_iso()
    
    conn = db()
    conn.execute(
        """INSERT INTO request_templates 
           (id, name, requester_name, requester_email, printer, material, colors, notes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (tid, name.strip(), requester_name.strip(), requester_email.strip(), 
         printer, material, colors.strip(), notes.strip(), now, now)
    )
    conn.commit()
    conn.close()
    
    return {"success": True, "id": tid, "message": f"Template '{name}' saved!"}


@app.delete("/api/templates/{template_id}")
def delete_template(template_id: str):
    """Delete a request template"""
    conn = db()
    conn.execute("DELETE FROM request_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Template deleted"}


@app.get("/api/templates/{template_id}")
def get_template(template_id: str):
    """Get a single template by ID"""
    conn = db()
    row = conn.execute(
        "SELECT * FROM request_templates WHERE id = ?", (template_id,)
    ).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Template not found")
    
    return dict(row)


@app.get("/api/printer/{printer_code}/debug")
async def printer_debug(printer_code: str, _=Depends(require_admin)):
    """Debug endpoint to test all available printer API endpoints.
    
    In DEMO_MODE, returns fake printer data.
    """
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    # Return demo data if in demo mode
    if DEMO_MODE:
        status = get_demo_printer_status(printer_code)
        job = get_demo_printer_job(printer_code)
        return {
            "_printer": printer_code,
            "_demo_mode": True,
            "info": {"Machine": f"Demo {printer_code}", "Type": "Demo Printer"},
            "status": {"MachineStatus": status.get("raw_status") if status else "READY"},
            "progress": {"PercentageCompleted": status.get("progress") if status else None},
            "temperature": {"Temperature": status.get("temp", "25") if status else "25"},
            "head_location": {"X": 0, "Y": 0, "Z": 0},
            "extended_status": {
                "current_file": job.get("file_name") if job else None,
                "current_layer": job.get("current_layer") if job else None,
                "total_layers": job.get("total_layers") if job else None,
            }
        }
    
    printer_api = get_printer_api(printer_code)
    if not printer_api:
        raise HTTPException(status_code=503, detail="Printer not configured")
    
    results = {"_printer": printer_code}
    
    # Test standard endpoints
    results["info"] = await printer_api.get_info()
    results["status"] = await printer_api.get_status()
    results["progress"] = await printer_api.get_progress()
    results["temperature"] = await printer_api.get_temperature()
    results["head_location"] = await printer_api.get_head_location()
    
    # NEW: Extended status with filename and layer info
    results["extended_status"] = await printer_api.get_extended_status()
    
    return results


@app.get("/api/printer/{printer_code}/job")
async def printer_job(printer_code: str, _=Depends(require_admin)):
    """Get current print job info - filename, layer progress, status.
    
    In DEMO_MODE, returns fake job data.
    """
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    # Return demo data if in demo mode
    if DEMO_MODE:
        job = get_demo_printer_job(printer_code)
        if job:
            return job
        return {"status": "idle", "message": "Demo printer is idle"}
    
    printer_api = get_printer_api(printer_code)
    if not printer_api:
        raise HTTPException(status_code=503, detail="Printer not configured")
    
    # Get all the data
    status = await printer_api.get_status()
    progress = await printer_api.get_progress()
    extended = await printer_api.get_extended_status()
    
    result = {
        "printer": printer_code,
        "machine_status": status.get("MachineStatus") if status else None,
        "percent_complete": progress.get("PercentageCompleted") if progress else None,
    }
    
    if extended:
        result["current_file"] = extended.get("current_file")
        result["current_layer"] = extended.get("current_layer")
        result["total_layers"] = extended.get("total_layers")
        result["layer_progress"] = f"{extended.get('current_layer', '?')}/{extended.get('total_layers', '?')}"
    
    return result


@app.get("/api/printers/status")
async def get_all_printers_status(_=Depends(require_admin)):
    """Get status of all printers - for AJAX refresh with retry logic.
    
    In DEMO_MODE, returns fake printer data instead of polling real printers.
    """
    # Return demo data if in demo mode
    if DEMO_MODE:
        return get_demo_all_printers_status()
    
    printer_status = {}
    max_retries = int(get_setting("printer_offline_retries", "3"))
    
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        try:
            printer_api = get_printer_api(printer_code)
            if printer_api:
                status = await printer_api.get_status()
                progress = await printer_api.get_progress()
                extended = await printer_api.get_extended_status()
                temp_data = await printer_api.get_temperature()
                
                if status:
                    machine_status = status.get("MachineStatus", "UNKNOWN")
                    is_printing = machine_status in ["BUILDING", "BUILDING_FROM_SD"]
                    
                    current_status = {
                        "status": machine_status.replace("_FROM_SD", ""),
                        "raw_status": machine_status,
                        "temp": temp_data.get("Temperature", "").split("/")[0] if temp_data else None,
                        "target_temp": temp_data.get("TargetTemperature") if temp_data else None,
                        "healthy": machine_status in ["READY", "PRINTING", "BUILDING", "BUILDING_FROM_SD"],
                        "is_printing": is_printing,
                        "progress": progress.get("PercentageCompleted") if progress else None,
                        "current_file": extended.get("current_file") if extended else None,
                        "current_layer": extended.get("current_layer") if extended else None,
                        "total_layers": extended.get("total_layers") if extended else None,
                        "camera_url": get_camera_url(printer_code),
                    }
                    # Successful poll - update cache and reset failure count
                    update_printer_status_cache(printer_code, current_status)
                    printer_status[printer_code] = current_status
                else:
                    # No status returned - count as failure
                    failure_count = record_printer_failure(printer_code)
                    cached = get_cached_printer_status(printer_code)
                    
                    if failure_count < max_retries and cached:
                        # Use cached status during retry period
                        printer_status[printer_code] = {
                            **cached,
                            "retrying": True,
                            "retry_count": failure_count,
                            "max_retries": max_retries,
                        }
                    else:
                        # Max retries exceeded - mark as offline
                        printer_status[printer_code] = {"status": "OFFLINE", "healthy": False}
            else:
                printer_status[printer_code] = {"status": "NOT_CONFIGURED", "healthy": False}
        except Exception as e:
            # Exception during poll - count as failure
            failure_count = record_printer_failure(printer_code)
            cached = get_cached_printer_status(printer_code)
            
            if failure_count < max_retries and cached:
                # Use cached status during retry period
                printer_status[printer_code] = {
                    **cached,
                    "retrying": True,
                    "retry_count": failure_count,
                    "max_retries": max_retries,
                    "last_error": str(e),
                }
            else:
                # Max retries exceeded - mark as error/offline
                printer_status[printer_code] = {"status": "ERROR", "error": str(e), "healthy": False}
    
    return printer_status


@app.get("/api/printer/{printer_code}/raw/{command}")
async def printer_raw_command(printer_code: str, command: str, _=Depends(require_admin)):
    """Send a raw M-code command to the printer and return the response"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    else:
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 8899))
        
        # Send control request first
        sock.send(b"~M601 S1\r\n")
        control_resp = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Send the command (add ~ prefix if not present)
        cmd = command if command.startswith("~") else f"~{command}"
        sock.send(f"{cmd}\r\n".encode())
        
        # Read response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"ok\r\n" in response or b"ok\n" in response:
                    break
            except socket.timeout:
                break
        
        sock.close()
        return {
            "command": cmd,
            "control_response": control_resp.strip(),
            "response": response.decode('utf-8', errors='ignore').strip(),
            "response_lines": response.decode('utf-8', errors='ignore').strip().split('\n')
        }
    except Exception as e:
        return {"command": command, "error": str(e)}


@app.get("/api/printer/{printer_code}/test-commands")
async def printer_test_commands(printer_code: str, _=Depends(require_admin)):
    """Test a bunch of M-codes to see what data we can get"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    else:
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    
    # Commands to test - focused on read-only status/info commands
    test_commands = [
        ("M20", "List SD card files"),
        ("M21", "Init SD card"),
        ("M27", "SD print status (extended)"),
        ("M31", "Print time"),
        ("M36", "Print file info"),
        ("M73", "Set/get print progress"),
        ("M78", "Print statistics"),
        ("M105", "Temperature report"),
        ("M114", "Current position"),
        ("M115", "Firmware info"),
        ("M119", "Endstop status"),
        ("M503", "Report settings"),
        ("M524", "Abort (just query, won't abort)"),
        ("M552", "Network status"),
        ("M650", "FlashForge specific?"),
        ("M651", "FlashForge specific?"),
        ("M652", "FlashForge specific?"),
        ("M660", "FlashForge specific?"),
        ("M661", "FlashForge SD file list"),
        ("M662", "FlashForge specific?"),
        # M25 REMOVED - it actually PAUSES the print!
        ("M994", "File list?"),
        ("M995", "Current file?"),
    ]
    
    results = {"_printer": printer_code, "_ip": ip, "commands": {}}
    
    import socket
    
    for cmd, desc in test_commands:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 8899))
            
            # Control request
            sock.send(b"~M601 S1\r\n")
            sock.recv(1024)
            
            # Send command
            sock.send(f"~{cmd}\r\n".encode())
            
            # Read response
            response = b""
            try:
                while True:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    response += chunk
                    if b"ok\r\n" in response or b"ok\n" in response or len(response) > 8000:
                        break
            except socket.timeout:
                pass
            
            sock.close()
            
            resp_text = response.decode('utf-8', errors='ignore').strip()
            # Mark as interesting if it has more than just "ok" or "Error"
            is_interesting = len(resp_text) > 20 and "Error" not in resp_text
            
            results["commands"][cmd] = {
                "desc": desc,
                "response": resp_text[:1000],
                "interesting": is_interesting
            }
        except Exception as e:
            results["commands"][cmd] = {"desc": desc, "error": str(e)}
    
    return results


@app.get("/api/print-history")
async def get_print_history(_=Depends(require_admin)):
    """Get print history stats for the learning ETA system"""
    conn = db()
    
    # All history entries
    history = conn.execute("""
        SELECT id, request_id, printer, material, print_name, started_at, completed_at, 
               duration_minutes, total_layers, file_name, created_at
        FROM print_history
        ORDER BY created_at DESC
        LIMIT 100
    """).fetchall()
    
    # Stats by printer
    by_printer = conn.execute("""
        SELECT printer, 
               AVG(duration_minutes) as avg_minutes,
               MIN(duration_minutes) as min_minutes,
               MAX(duration_minutes) as max_minutes,
               COUNT(*) as count
        FROM print_history
        GROUP BY printer
    """).fetchall()
    
    # Overall stats
    overall = conn.execute("""
        SELECT AVG(duration_minutes) as avg_minutes,
               MIN(duration_minutes) as min_minutes,
               MAX(duration_minutes) as max_minutes,
               COUNT(*) as count
        FROM print_history
    """).fetchone()
    
    conn.close()
    
    return {
        "history": [dict(h) for h in history],
        "by_printer": [dict(p) for p in by_printer],
        "overall": dict(overall) if overall else {},
    }


# ─────────────────────────── TIMELAPSE API ───────────────────────────

async def list_printer_files_via_mcode(printer_code: str, folder: str = "") -> List[Dict[str, Any]]:
    """List files on printer SD card via M-code commands"""
    import socket
    
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    elif printer_code == "AD5X":
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    else:
        return []
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 8899))
        
        # Control request
        sock.send(b"~M601 S1\r\n")
        sock.recv(1024)
        
        # M661 lists files (FlashForge specific)
        # M20 is standard G-code for SD card listing
        commands = ["M661", "M20"]
        all_files = []
        
        for cmd in commands:
            sock.send(f"~{cmd}\r\n".encode())
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"ok\r\n" in response or b"ok\n" in response or len(response) > 50000:
                        break
            except socket.timeout:
                pass
            
            resp_text = response.decode('utf-8', errors='ignore')
            
            # Parse file listings - look for common patterns
            for line in resp_text.split('\n'):
                line = line.strip()
                # Skip empty lines and command echoes
                if not line or line.startswith('CMD') or line == 'ok' or line.startswith('~'):
                    continue
                # Look for file extensions
                lower = line.lower()
                if any(ext in lower for ext in ['.mp4', '.avi', '.mov', '.gcode', '.3mf', '.gx']):
                    # Could be "filename.mp4" or "filename.mp4 SIZE" format
                    parts = line.split()
                    filename = parts[0] if parts else line
                    size = parts[1] if len(parts) > 1 else None
                    all_files.append({
                        "name": filename,
                        "size": size,
                        "is_timelapse": any(ext in lower for ext in ['.mp4', '.avi', '.mov']),
                    })
        
        sock.close()
        return all_files
        
    except Exception as e:
        print(f"[TIMELAPSE] Error listing files from {printer_code}: {e}")
        return []


async def get_timelapse_via_http(printer_code: str, filename: str) -> Optional[bytes]:
    """Try to fetch timelapse video via HTTP from printer's web interface"""
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    elif printer_code == "AD5X":
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    else:
        return None
    
    # Common FlashForge timelapse paths to try
    paths_to_try = [
        f"/timelapse/{filename}",
        f"/video/{filename}",
        f"/sdcard/timelapse/{filename}",
        f"/sd/timelapse/{filename}",
        f"/{filename}",
    ]
    
    # Common ports
    ports_to_try = [80, 8080, 8899, 8888]
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for port in ports_to_try:
            for path in paths_to_try:
                try:
                    url = f"http://{ip}:{port}{path}"
                    print(f"[TIMELAPSE] Trying {url}")
                    response = await client.get(url)
                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")
                        if "video" in content_type or filename.lower().endswith(('.mp4', '.avi', '.mov')):
                            print(f"[TIMELAPSE] Found video at {url}")
                            return response.content
                except Exception as e:
                    continue
    
    return None


@app.get("/api/printer/{printer_code}/files")
async def list_printer_files(printer_code: str, _=Depends(require_admin)):
    """List files on printer SD card"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    files = await list_printer_files_via_mcode(printer_code)
    return {
        "printer": printer_code,
        "files": files,
        "timelapse_count": sum(1 for f in files if f.get("is_timelapse")),
    }


@app.get("/api/printer/{printer_code}/timelapses")
async def list_printer_timelapses(printer_code: str, _=Depends(require_admin)):
    """List available timelapse videos from printer"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    all_files = await list_printer_files_via_mcode(printer_code)
    timelapses = [f for f in all_files if f.get("is_timelapse")]
    
    return {
        "printer": printer_code,
        "timelapses": timelapses,
        "count": len(timelapses),
    }


@app.get("/api/printer/{printer_code}/timelapse/{filename}")
async def get_printer_timelapse(printer_code: str, filename: str, _=Depends(require_admin)):
    """Download/stream a timelapse video from printer"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    # Validate filename to prevent path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    video_data = await get_timelapse_via_http(printer_code, filename)
    
    if not video_data:
        raise HTTPException(status_code=404, detail="Timelapse not found or not accessible")
    
    # Determine content type
    ext = filename.lower().split('.')[-1] if '.' in filename else 'mp4'
    content_types = {
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
    }
    content_type = content_types.get(ext, 'video/mp4')
    
    return Response(content=video_data, media_type=content_type)


@app.get("/api/printer/{printer_code}/timelapse-probe")
async def probe_printer_timelapse_access(printer_code: str, _=Depends(require_admin)):
    """Probe printer to discover timelapse access methods"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    if printer_code == "ADVENTURER_4":
        ip = get_setting("printer_adventurer_4_ip", "192.168.0.198")
    else:
        ip = get_setting("printer_ad5x_ip", "192.168.0.157")
    
    results = {
        "printer": printer_code,
        "ip": ip,
        "web_interfaces": [],
        "mcode_responses": {},
        "file_listing": None,
    }
    
    # Check for web interfaces - expanded port and path list
    ports_to_check = [80, 8080, 8888, 8899, 443, 8000, 5000, 3000, 9000, 10000]
    paths_to_check = [
        "/", "/index.html", "/timelapse", "/video", "/sd", "/sdcard",
        "/api", "/api/timelapse", "/api/files", "/files", "/media",
        "/recording", "/recordings", "/camera", "/stream",
    ]
    
    async with httpx.AsyncClient(timeout=2.0) as client:
        for port in ports_to_check:
            for path in paths_to_check:
                try:
                    url = f"http://{ip}:{port}{path}"
                    response = await client.get(url)
                    if response.status_code < 400:
                        results["web_interfaces"].append({
                            "url": url,
                            "status": response.status_code,
                            "content_type": response.headers.get("content-type", "unknown"),
                            "size": len(response.content),
                            "preview": response.text[:500] if "text" in response.headers.get("content-type", "") else None,
                        })
                except Exception:
                    continue
    
    # Try various M-codes to find file/timelapse info - capture raw responses
    import socket
    mcode_commands = [
        "M20",      # Standard SD card file list
        "M21",      # Init SD card
        "M661",     # FlashForge file list
        "M662",     # FlashForge specific
        "M115",     # Firmware info
        "M119",     # Status
        "M650",     # FlashForge specific
        "M651",     # FlashForge specific
        "M652",     # FlashForge specific
        "M660",     # FlashForge specific
        "M663",     # FlashForge specific
        "M664",     # FlashForge specific
        "M665",     # FlashForge specific
        "M700",     # Could be video related
        "M701",     # Could be video related
        "M800",     # Could be video related
        "M20 /timelapse",  # Try listing timelapse folder
        "M20 /video",      # Try listing video folder
        "M20 /recording",  # Try listing recording folder
    ]
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 8899))
        
        # Control request
        sock.send(b"~M601 S1\r\n")
        sock.recv(1024)
        
        for cmd in mcode_commands:
            try:
                sock.send(f"~{cmd}\r\n".encode())
                response = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if b"ok\r\n" in response or b"ok\n" in response or len(response) > 10000:
                            break
                except socket.timeout:
                    pass
                
                resp_text = response.decode('utf-8', errors='ignore').strip()
                # Only save if response has content beyond just "ok"
                if resp_text and len(resp_text) > 5:
                    results["mcode_responses"][cmd] = {
                        "response": resp_text,
                        "lines": resp_text.split('\n'),
                        "length": len(resp_text),
                    }
            except Exception as e:
                results["mcode_responses"][cmd] = {"error": str(e)}
        
        sock.close()
    except Exception as e:
        results["mcode_error"] = str(e)
    
    # Try file listing via M-code
    files = await list_printer_files_via_mcode(printer_code)
    results["file_listing"] = {
        "files": files,
        "count": len(files),
    }
    
    return results
