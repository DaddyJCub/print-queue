import os, uuid, sqlite3, hashlib, smtplib, ssl, urllib.parse, json, base64, secrets
from email.message import EmailMessage
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
import asyncio
import threading

import httpx
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# ─────────────────────────── VERSION ───────────────────────────
APP_VERSION = "1.8.5"
# Changelog:
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

APP_TITLE = "3D Print Queue"

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

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# FastAPI app with reverse proxy support (trust X-Forwarded-* headers for HTTPS detection)
app = FastAPI(title=APP_TITLE)
app.trust_proxy_headers = True

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

# Global printer status cache with retry logic
# Stores last successful status and failure count per printer
_printer_status_cache: Dict[str, Dict[str, Any]] = {}
_printer_failure_count: Dict[str, int] = {}

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

def update_printer_status_cache(printer_code: str, status: Dict[str, Any]):
    """Update cached printer status on successful poll"""
    _printer_status_cache[printer_code] = status
    _printer_failure_count[printer_code] = 0  # Reset failure count on success

def record_printer_failure(printer_code: str) -> int:
    """Record a printer poll failure and return the new failure count"""
    _printer_failure_count[printer_code] = _printer_failure_count.get(printer_code, 0) + 1
    return _printer_failure_count[printer_code]

def get_printer_failure_count(printer_code: str) -> int:
    """Get current failure count for a printer"""
    return _printer_failure_count.get(printer_code, 0)

# Status flow for admin actions
STATUS_FLOW = ["NEW", "NEEDS_INFO", "APPROVED", "PRINTING", "DONE", "PICKED_UP", "REJECTED", "CANCELLED"]

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
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    """)

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

    conn.commit()
    conn.close()


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


@app.on_event("startup")
def _startup():
    init_db()
    ensure_migrations()
    seed_default_settings()
    start_printer_polling()  # Start background printer status polling


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
        """Get extended status including current filename and layer info via direct M-codes"""
        import socket
        result = {}
        
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
            
            sock.close()
            return result if result else None
            
        except Exception as e:
            print(f"[PRINTER] Error fetching extended status from {self.printer_ip}: {e}")
            return None

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
        return None
    
    try:
        # Try snapshot URL first (quick attempt with short timeout)
        snapshot_url = camera_url.replace("?action=stream", "?action=snapshot")
        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                response = await client.get(snapshot_url)
                if response.status_code == 200 and response.headers.get("content-type", "").startswith("image/"):
                    print(f"[CAMERA] Got snapshot from {printer_code} via snapshot endpoint")
                    return response.content
            except httpx.TimeoutException:
                pass  # Snapshot endpoint not available, try stream method
        
        # Fallback: Extract a single frame from the MJPEG stream
        print(f"[CAMERA] Trying to extract frame from MJPEG stream for {printer_code}")
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
                            print(f"[CAMERA] Extracted JPEG frame ({len(jpeg_data)} bytes) from {printer_code}")
                            return jpeg_data
                    # Prevent buffer from growing too large
                    if len(buffer) > 500000:  # 500KB max
                        print(f"[CAMERA] Buffer too large, no JPEG found for {printer_code}")
                        break
    except Exception as e:
        print(f"[CAMERA] Error capturing snapshot from {printer_code}: {e}")
    
    return None


async def poll_printer_status_worker():
    """
    Background worker that polls all configured printers every 30s.
    Auto-updates PRINTING -> DONE when printer reports 100% complete.
    """
    print("[POLL] Background printer polling started")
    while True:
        try:
            if not get_bool_setting("enable_printer_polling", True):
                await asyncio.sleep(30)
                continue
            
            print("[POLL] Checking for PRINTING requests...")
            add_poll_debug_log({"type": "poll_start", "message": "Checking for PRINTING requests"})

            conn = db()
            printing_reqs = conn.execute(
                "SELECT id, printer, printing_started_at, printing_email_sent, requester_email, requester_name, print_name, material, access_token, print_time_minutes FROM requests WHERE status = ?",
                ("PRINTING",)
            ).fetchall()
            conn.close()
            
            add_poll_debug_log({"type": "poll_found", "message": f"Found {len(printing_reqs)} PRINTING requests"})

            for req in printing_reqs:
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
                        
                        if requester_email_on_status and should_notify_requester and req["requester_email"]:
                            print_label = req["print_name"] or f"Request {rid[:8]}"
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
                            
                            html = build_email_html(
                                title="Now Printing!",
                                subtitle=f"'{print_label}' is now printing!",
                                rows=email_rows,
                                cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                                cta_label="View in Queue",
                                header_color="#f59e0b",  # Orange for printing
                            )
                            send_email([req["requester_email"]], subject, text, html)
                        
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
                    req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
                    
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

                    # Build email rows with completion data
                    email_rows = [("Request ID", rid[:8]), ("Status", "DONE")]
                    if final_temp:
                        email_rows.append(("Final Temp", final_temp))

                    if requester_email_on_status and req_row:
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


def start_printer_polling():
    """Start background printer polling in a thread (runs once at startup)"""
    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(poll_printer_status_worker())

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


def build_email_html(title: str, subtitle: str, rows: List[Tuple[str, str]], cta_url: Optional[str] = None, cta_label: str = "Open", header_color: str = "#4f46e5", image_base64: Optional[str] = None, footer_note: Optional[str] = None) -> str:
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
        cta = f"""
          <div style="margin-top:20px;">
            <a href="{esc(cta_url)}"
               style="display:inline-block;background:{esc(header_color)};color:#ffffff;text-decoration:none;
                      padding:12px 16px;border-radius:8px;font-weight:600;font-size:14px;border:0;">
              {esc(cta_label)}
            </a>
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
        </div>
      </div>
    </div>
  </body>
</html>
"""


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


def render_form(request: Request, error: Optional[str], form: Dict[str, Any]):
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
    
    return templates.TemplateResponse("request_form.html", {
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
    }, status_code=400 if error else 200)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render_form(request, None, form={})


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

        conn.execute(
            """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), rid, now_iso(), upload.filename, stored, len(data), sha)
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

    # Show thanks page with portal link
    return templates.TemplateResponse("thanks.html", {
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
        "SELECT id, requester_name, print_name, printer, material, colors, status, special_notes, print_time_minutes, turnaround_minutes, printing_started_at "
        "FROM requests "
        "WHERE status NOT IN (?, ?, ?) "
        "ORDER BY created_at ASC",
        ("PICKED_UP", "REJECTED", "CANCELLED")
    ).fetchall()
    conn.close()

    items = []
    printing_idx = None
    
    # Fetch current printer status for health indicators
    printer_status = {}
    for printer_code in ["ADVENTURER_4", "AD5X"]:
        try:
            printer_api = get_printer_api(printer_code)
            if printer_api:
                status = await printer_api.get_status()
                progress = await printer_api.get_percent_complete()
                extended = await printer_api.get_extended_status()
                if status:
                    machine_status = status.get("MachineStatus", "UNKNOWN")
                    printer_status[printer_code] = {
                        "status": machine_status.replace("_FROM_SD", ""),
                        "temp": status.get("Temperature"),
                        "progress": progress,
                        "healthy": machine_status in ["READY", "PRINTING", "BUILDING", "BUILDING_FROM_SD"],
                        "is_printing": machine_status in ["BUILDING", "BUILDING_FROM_SD"],
                        "current_file": extended.get("current_file") if extended else None,
                        "current_layer": extended.get("current_layer") if extended else None,
                        "total_layers": extended.get("total_layers") if extended else None,
                    }
        except Exception:
            pass
    
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
        
        if r["status"] == "PRINTING":
            # Fix missing printing_started_at for legacy requests
            if not printing_started_at:
                printing_started_at = now_iso()
                conn_fix = db()
                conn_fix.execute("UPDATE requests SET printing_started_at = ? WHERE id = ? AND printing_started_at IS NULL", 
                               (printing_started_at, r["id"]))
                conn_fix.commit()
                conn_fix.close()
            
            printer_api = get_printer_api(r["printer"])
            current_layer = None
            total_layers = None
            if printer_api:
                try:
                    printer_progress = await printer_api.get_percent_complete()
                    # Get layer info for more accurate ETA
                    extended = await printer_api.get_extended_status()
                    if extended:
                        current_layer = extended.get("current_layer")
                        total_layers = extended.get("total_layers")
                except Exception:
                    pass  # Fall back to time-based estimate if API fails
            
            # Calculate smart ETA based on layers (preferred) or progress
            eta_dt = get_smart_eta(
                printer=r["printer"],
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
        printer_health = printer_status.get(r["printer"], {}).get("healthy", None)
        
        items.append({
            "pos": idx + 1,
            "short_id": short_id,
            "requester_first": first_name_only(r["requester_name"]),
            "print_name": r["print_name"],
            "printer": r["printer"],
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
        })
    
    # Separate items by status for display
    printing_items = [it for it in items if it["status"] == "PRINTING"]
    approved_items = [it for it in items if it["status"] == "APPROVED"]
    done_items = [it for it in items if it["status"] == "DONE"]
    pending_items = [it for it in items if it["status"] in ["NEW", "NEEDS_INFO"]]
    
    # Group printing items by printer (for printer card display)
    printing_by_printer = {
        "ADVENTURER_4": None,
        "AD5X": None,
    }
    for pit in printing_items:
        if pit["printer"] in printing_by_printer:
            printing_by_printer[pit["printer"]] = pit
    
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

    counts = {"NEW": 0, "NEEDS_INFO": 0, "APPROVED": 0, "PRINTING": 0, "DONE": 0}
    for it in items:
        if it["status"] in counts:
            counts[it["status"]] += 1

    return templates.TemplateResponse("public_queue.html", {
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

@app.get("/my/{rid}", response_class=HTMLResponse)
async def requester_portal(request: Request, rid: str, token: str):
    """Requester portal - view and interact with your request"""
    conn = db()
    req = conn.execute(
        "SELECT * FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    
    if not req:
        conn.close()
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
    
    conn.close()
    
    # Fetch printer status if currently printing
    printer_status = None
    smart_eta_display = None
    if req["status"] == "PRINTING" and req["printer"]:
        printer_api = get_printer_api(req["printer"])
        if printer_api:
            try:
                status = await printer_api.get_status()
                progress = await printer_api.get_percent_complete()
                extended = await printer_api.get_extended_status()
                if status:
                    machine_status = status.get("MachineStatus", "UNKNOWN")
                    current_layer = extended.get("current_layer") if extended else None
                    total_layers = extended.get("total_layers") if extended else None
                    printer_status = {
                        "status": machine_status.replace("_FROM_SD", ""),
                        "temp": status.get("Temperature"),
                        "progress": progress,
                        "is_printing": machine_status in ["BUILDING", "BUILDING_FROM_SD"],
                        "current_layer": current_layer,
                        "total_layers": total_layers,
                    }
                    
                    # Calculate smart ETA
                    eta_dt = get_smart_eta(
                        printer=req["printer"],
                        material=req["material"],
                        current_percent=progress,
                        printing_started_at=req["printing_started_at"],
                        current_layer=current_layer,
                        total_layers=total_layers
                    )
                    if eta_dt:
                        smart_eta_display = format_eta_display(eta_dt)
            except Exception:
                pass
    
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
        
        # Record in database
        file_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (file_id, rid, created, upload.filename, stored_name, len(content), sha256)
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
def my_requests_lookup(request: Request, sent: Optional[str] = None, error: Optional[str] = None):
    """Email lookup form for viewing all requests"""
    return templates.TemplateResponse("my_requests_lookup.html", {
        "request": request,
        "sent": sent,
        "error": error,
        "version": APP_VERSION,
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
    
    # Generate magic link token (expires in 24 hours)
    token_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    created = now_iso()
    
    # Calculate expiry (24 hours from now)
    from datetime import timedelta
    expiry = (datetime.utcnow() + timedelta(hours=24)).isoformat(timespec="seconds") + "Z"
    
    # Clean up old tokens for this email
    conn.execute("DELETE FROM email_lookup_tokens WHERE email = ?", (email,))
    
    # Insert new token
    conn.execute(
        "INSERT INTO email_lookup_tokens (id, email, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (token_id, email, token, created, expiry)
    )
    conn.commit()
    conn.close()
    
    # Send email with magic link
    magic_link = f"{BASE_URL}/my-requests/view?token={token}"
    subject = f"[{APP_TITLE}] Your Print Requests"
    text = f"Click here to view all your print requests:\n\n{magic_link}\n\nThis link expires in 24 hours.\n\nIf you didn't request this, you can ignore this email."
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
        footer_note="This link expires in 24 hours. If you didn't request this, you can safely ignore this email.",
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
        return templates.TemplateResponse("my_requests_lookup.html", {
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
        return templates.TemplateResponse("my_requests_lookup.html", {
            "request": request,
            "error": "expired",
            "version": APP_VERSION,
        })
    
    email = token_row["email"]
    
    # Fetch all requests for this email, including completion_snapshot
    requests_list = conn.execute(
        """SELECT id, print_name, status, created_at, updated_at, printer, material, colors, 
                  access_token, completion_snapshot, printing_started_at, print_time_minutes
           FROM requests 
           WHERE LOWER(requester_email) = ?
           ORDER BY 
             CASE WHEN status = 'DONE' THEN 0
                  WHEN status = 'PRINTING' THEN 1
                  WHEN status = 'NEEDS_INFO' THEN 2
                  ELSE 3 END,
             created_at DESC""",
        (email,)
    ).fetchall()
    
    conn.close()
    
    # Enrich printing requests with real-time printer status
    enriched_requests = []
    printer_status_cache = {}
    
    for req in requests_list:
        req_dict = dict(req)
        
        # If printing, fetch real-time printer status
        if req["status"] == "PRINTING" and req["printer"]:
            printer_code = req["printer"]
            
            # Cache printer status to avoid multiple calls
            if printer_code not in printer_status_cache:
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
                            
                            printer_status_cache[printer_code] = {
                                "status": machine_status.replace("_FROM_SD", ""),
                                "is_printing": is_printing,
                                "progress": progress.get("PercentageCompleted") if progress else None,
                                "current_file": extended.get("current_file") if extended else None,
                                "current_layer": extended.get("current_layer") if extended else None,
                                "total_layers": extended.get("total_layers") if extended else None,
                                "temp": temp_data.get("Temperature", "").split("/")[0] if temp_data else None,
                                "camera_url": get_camera_url(printer_code),
                            }
                except Exception as e:
                    print(f"[MY-REQUESTS] Error fetching printer status: {e}")
            
            req_dict["printer_status"] = printer_status_cache.get(printer_code)
            
            # Calculate smart ETA
            if req_dict.get("printer_status"):
                eta_dt = get_smart_eta(
                    printer=printer_code,
                    material=req["material"],
                    current_percent=req_dict["printer_status"].get("progress") or 0,
                    printing_started_at=req["printing_started_at"] or now_iso(),
                    current_layer=req_dict["printer_status"].get("current_layer") or 0,
                    total_layers=req_dict["printer_status"].get("total_layers") or 0
                )
                req_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        
        enriched_requests.append(req_dict)
    
    return templates.TemplateResponse("my_requests_list.html", {
        "request": request,
        "email": email,
        "requests_list": enriched_requests,
        "token": token,  # Keep token for refresh
        "version": APP_VERSION,
    })


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
def admin_feedback_list(request: Request, status: Optional[str] = None, _=Depends(require_admin)):
    """Admin view of all feedback"""
    conn = db()
    
    if status and status in ("new", "reviewed", "resolved", "dismissed"):
        feedback = conn.execute(
            "SELECT * FROM feedback WHERE status = ? ORDER BY created_at DESC",
            (status,)
        ).fetchall()
    else:
        feedback = conn.execute(
            "SELECT * FROM feedback ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'reviewed' THEN 1 ELSE 2 END, created_at DESC"
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
    resp.set_cookie("admin_pw", password, httponly=True, samesite="lax", secure=True, max_age=604800)  # 7 days, HTTPS only
    return resp


@app.get("/admin/logout")
def admin_logout():
    """Clear admin session cookie and redirect to home."""
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("admin_pw")
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
                      r.print_name,
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
                      r.print_name,
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
    printing_raw = _fetch_requests_by_status("PRINTING", include_eta_fields=True)
    done = _fetch_requests_by_status("DONE")
    
    # Enrich printing requests with smart ETA
    printing = []
    for r in printing_raw:
        # Get current progress from printer for smart ETA calculation
        printer_progress = None
        current_layer = None
        total_layers = None
        printer_api = get_printer_api(r["printer"])
        if printer_api:
            try:
                printer_progress = await printer_api.get_percent_complete()
                # Get layer info for more accurate ETA
                extended = await printer_api.get_extended_status()
                if extended:
                    current_layer = extended.get("current_layer")
                    total_layers = extended.get("total_layers")
            except Exception:
                pass
        
        # If printing_started_at is missing, set it now (for legacy requests)
        printing_started_at = r["printing_started_at"] if "printing_started_at" in r.keys() else None
        if not printing_started_at and r["status"] == "PRINTING":
            printing_started_at = now_iso()
            conn_fix = db()
            conn_fix.execute("UPDATE requests SET printing_started_at = ? WHERE id = ? AND printing_started_at IS NULL", 
                           (printing_started_at, r["id"]))
            conn_fix.commit()
            conn_fix.close()
        
        # Calculate smart ETA based on layers (preferred) or progress
        eta_dt = get_smart_eta(
            printer=r["printer"],
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

    # Fetch printer status with extended info
    printer_status = {}
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
                    
                    printer_status[printer_code] = {
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
        except Exception as e:
            print(f"[ADMIN] Error fetching printer {printer_code} status: {e}")

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
    return templates.TemplateResponse("admin_debug.html", {
        "request": request,
        "logs": logs,
        "printer_cache": _printer_status_cache,
        "failure_counts": _printer_failure_count,
        "version": APP_VERSION,
    })


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
    
    return templates.TemplateResponse("store.html", {
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
            text = f"Your print request has been received!\n\nPrint: {item['name']}\nRequest ID: {rid[:8]}\n\nTrack: {BASE_URL}/my/{rid}?token={access_token}"
            
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
                cta_url=f"{BASE_URL}/my/{rid}?token={access_token}",
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
    
    # Mark all requester messages as read when admin views the request
    conn.execute("UPDATE request_messages SET is_read = 1 WHERE request_id = ? AND sender_type = 'requester' AND is_read = 0", (rid,))
    conn.commit()
    conn.close()
    
    # Get camera URL for the printer if configured
    camera_url = get_camera_url(req["printer"]) if req["printer"] in ["ADVENTURER_4", "AD5X"] else None
    
    # Get slicer accuracy info for this printer/material combo
    accuracy_info = get_slicer_accuracy_factor(req["printer"], req["material"])
    
    return templates.TemplateResponse("admin_request.html", {
        "request": request,
        "req": req,
        "files": files,
        "events": events,
        "messages": messages,
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
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    from_status = req["status"]
    
    # Track printing start time when transitioning to PRINTING
    update_cols = ["status", "updated_at"]
    update_vals = [to_status, now_iso()]
    
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

    # Check fine-grain notification settings
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

    if requester_email_on_status and should_notify_requester:
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
            text_lines.append(f"\nRespond here: {BASE_URL}/my/{rid}?token={req['access_token']}\n")
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
            cta_url = f"{BASE_URL}/my/{rid}?token={req['access_token']}"
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
        
        html = build_email_html(
            title=status_title,
            subtitle=subtitle,
            rows=email_rows,
            cta_url=cta_url,
            cta_label=cta_label,
            header_color=header_color,
            footer_note=footer_note,
        )
        send_email([req["requester_email"]], subject, text, html)

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
        text = f"New message from admin:\n\n{message}\n\nRespond here: {BASE_URL}/my/{rid}?token={req['access_token']}"
        html = build_email_html(
            title="💬 New Message",
            subtitle=f"About your request '{print_label}'",
            rows=[
                ("Message", message),
            ],
            cta_url=f"{BASE_URL}/my/{rid}?token={req['access_token']}",
            cta_label="View & Reply",
            header_color="#6366f1",
        )
        send_email([req["requester_email"]], subject, text, html)
    
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
    upload: UploadFile = File(...),
    _=Depends(require_admin)
):
    if not upload or not upload.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = safe_ext(upload.filename)
    if ext not in ALLOWED_EXTS:
        raise HTTPException(status_code=400, detail=f"Only these file types are allowed: {', '.join(sorted(ALLOWED_EXTS))}")

    data = await upload.read()
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    if len(data) > max_bytes:
        raise HTTPException(status_code=400, detail=f"File too large. Max size is {MAX_UPLOAD_MB}MB.")

    stored = f"{uuid.uuid4()}{ext}"
    out_path = os.path.join(UPLOAD_DIR, stored)

    sha = hashlib.sha256(data).hexdigest()
    with open(out_path, "wb") as f:
        f.write(data)

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    conn.execute(
        """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, now_iso(), upload.filename, stored, len(data), sha)
    )
    conn.execute(
        "INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), rid, now_iso(), req["status"], req["status"], f"Admin added file: {upload.filename}")
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
async def camera_snapshot(printer_code: str, _=Depends(require_admin)):
    """Get a snapshot from printer camera"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    image_data = await capture_camera_snapshot(printer_code)
    if not image_data:
        raise HTTPException(status_code=503, detail="Camera not available or not configured")
    
    return Response(content=image_data, media_type="image/jpeg")


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
    """Debug endpoint to test all available printer API endpoints"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
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
    """Get current print job info - filename, layer progress, status"""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
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
    """Get status of all printers - for AJAX refresh with retry logic"""
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
