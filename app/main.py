import os, uuid, sqlite3, hashlib, smtplib, ssl, urllib.parse, json, base64
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
APP_VERSION = "1.7.3"
# Changelog:
# 1.7.3 - Timelapse API: list and download timelapse videos from printers
# 1.7.2 - Request templates: save and reuse common form configurations
# 1.7.1 - Dynamic rush pricing based on queue size + Brandon Tax™ x5 multiplier
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

ALLOWED_EXTS = set([e.strip().lower() for e in os.getenv("ALLOWED_EXTS", ".stl,.3mf").split(",") if e.strip()])
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

# NOTE: app/static must exist in your repo (can be empty with a .gitkeep)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Status flow for admin actions
STATUS_FLOW = ["NEW", "APPROVED", "PRINTING", "DONE", "PICKED_UP", "REJECTED", "CANCELLED"]

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
    
    # Rush payment settings
    "rush_fee_amount": "5",
    "venmo_handle": "@YourVenmoHandle",
    "enable_rush_option": "1",
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


def get_smart_eta(printer: str = None, material: str = None, 
                  current_percent: int = None, printing_started_at: str = None) -> Optional[datetime]:
    """
    Calculate a smart ETA based on:
    1. Current progress + elapsed time (most accurate when printing)
    2. Historical average for this printer/material combo
    
    Returns a datetime of estimated completion, or None if can't estimate.
    """
    # Method 1: If we have current progress, calculate from elapsed time
    if current_percent and current_percent > 0 and printing_started_at:
        try:
            started_dt = datetime.fromisoformat(printing_started_at)
            elapsed = (datetime.now() - started_dt).total_seconds()
            
            if current_percent >= 100:
                return datetime.now()
            
            # Skip if elapsed time is too short (< 2 minutes) - data not reliable yet
            # This happens when printing_started_at was just set retroactively
            if elapsed >= 120:  # At least 2 minutes of data
                # Calculate total expected time based on current progress
                # If 30% done in 60 minutes, total time = 60 / 0.30 = 200 minutes
                total_expected = elapsed / (current_percent / 100)
                remaining_seconds = total_expected - elapsed
                
                # Add a small buffer (5%) for accuracy
                remaining_seconds *= 1.05
                
                # Sanity check: remaining should be positive and reasonable (< 48 hours)
                if 0 < remaining_seconds < 172800:
                    eta = datetime.now() + __import__('datetime').timedelta(seconds=remaining_seconds)
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
        machine_status = status.get("MachineStatus", "READY").strip()
        # BUILDING_COMPLETED means done, not actively printing
        return machine_status not in ["READY", "BUILDING_COMPLETED", "BUILDING_FROM_SD_COMPLETED"]

    async def is_complete(self) -> bool:
        """Check if printer just finished a print (BUILDING_COMPLETED state or READY with 100%)"""
        status = await self.get_status()
        if not status:
            return False
        machine_status = status.get("MachineStatus", "").strip()
        # Completed states
        if machine_status in ["BUILDING_COMPLETED", "BUILDING_FROM_SD_COMPLETED"]:
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
    while True:
        try:
            if not get_bool_setting("enable_printer_polling", True):
                await asyncio.sleep(30)
                continue

            conn = db()
            printing_reqs = conn.execute(
                "SELECT id, printer FROM requests WHERE status = ?",
                ("PRINTING",)
            ).fetchall()
            conn.close()

            for req in printing_reqs:
                printer_api = get_printer_api(req["printer"])
                if not printer_api:
                    continue

                # Check both status and progress
                is_printing = await printer_api.is_printing()
                is_complete = await printer_api.is_complete()
                percent_complete = await printer_api.get_percent_complete()

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

                # Auto-complete if printer reports complete OR (not printing AND at 100%)
                should_complete = is_complete or ((not is_printing) and (percent_complete == 100))

                if should_complete:
                    print(f"[PRINTER] {req['printer']} complete ({percent_complete}%), auto-updating {rid[:8]} to DONE")

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
                    if req_row and req_row.get("printing_started_at"):
                        try:
                            started_at = req_row["printing_started_at"]
                            completed_at = now_iso()
                            started_dt = datetime.fromisoformat(started_at)
                            completed_dt = datetime.fromisoformat(completed_at)
                            duration_minutes = int((completed_dt - started_dt).total_seconds() / 60)
                            
                            conn.execute("""
                                INSERT INTO print_history 
                                (id, request_id, printer, material, print_name, started_at, completed_at, 
                                 duration_minutes, total_layers, file_name, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                str(uuid.uuid4()),
                                rid,
                                req_row.get("printer", ""),
                                req_row.get("material", ""),
                                req_row.get("print_name", ""),
                                started_at,
                                completed_at,
                                duration_minutes,
                                extended_info.get("total_layers") if extended_info else None,
                                extended_info.get("current_file") if extended_info else None,
                                completed_at
                            ))
                            print(f"[PRINTER] Recorded print history: {duration_minutes} minutes for {req_row.get('printer', '')}")
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
                        html = build_email_html(
                            title="Print Complete!",
                            subtitle="Your request is ready for pickup.",
                            rows=email_rows,
                            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                            cta_label="View queue",
                            image_base64=completion_snapshot if get_bool_setting("enable_camera_snapshot", False) else None,
                        )
                        send_email([req_row["requester_email"]], subject, text, html)

                    if admin_email_on_status and admin_emails and req_row:
                        admin_rows = [("Request ID", rid[:8]), ("Printer", req["printer"]), ("Status", "DONE")]
                        if final_temp:
                            admin_rows.append(("Final Temp", final_temp))
                        
                        subject = f"[{APP_TITLE}] Auto-completed: {rid[:8]}"
                        text = f"Print automatically marked DONE.\n\nID: {rid}\nPrinter: {req['printer']}\nAdmin: {BASE_URL}/admin/request/{rid}\n"
                        html = build_email_html(
                            title="Print Auto-Completed",
                            subtitle="Printer finished and is idle.",
                            rows=admin_rows,
                            cta_url=f"{BASE_URL}/admin/request/{rid}",
                            cta_label="Open in admin",
                            image_base64=completion_snapshot if get_bool_setting("enable_camera_snapshot", False) else None,
                        )
                        send_email(admin_emails, subject, text, html)

            await asyncio.sleep(30)  # Poll every 30 seconds
        except Exception as e:
            print(f"[PRINTER WORKER] Error: {e}")
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


def build_email_html(title: str, subtitle: str, rows: List[Tuple[str, str]], cta_url: Optional[str] = None, cta_label: str = "Open", header_color: str = "#4f46e5", image_base64: Optional[str] = None) -> str:
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

    # Embedded snapshot image
    image_html = ""
    if image_base64:
        image_html = f"""
          <div style="margin-top:20px;border-radius:8px;overflow:hidden;">
            <div style="color:#6b7280;font-size:12px;margin-bottom:8px;font-weight:600;">📷 Completion Snapshot</div>
            <img src="data:image/jpeg;base64,{image_base64}" alt="Print completion snapshot" 
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


def send_email(to_addrs: List[str], subject: str, text_body: str, html_body: Optional[str] = None):
    """
    Best-effort email. Never raises to the web request.
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
           (id, created_at, updated_at, requester_name, requester_email, print_name, printer, material, colors, link_url, notes, status, special_notes, priority, admin_notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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

    return RedirectResponse(url=f"/queue?mine={rid[:8]}", status_code=303)


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
            if printer_api:
                try:
                    printer_progress = await printer_api.get_percent_complete()
                except Exception:
                    pass  # Fall back to time-based estimate if API fails
            
            # Calculate smart ETA based on progress and history
            eta_dt = get_smart_eta(
                printer=r["printer"],
                material=r["material"],
                current_percent=printer_progress,
                printing_started_at=printing_started_at
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
        })
        if r["status"] == "PRINTING":
            printing_idx = idx
    
    # Second pass: calculate wait times from printing point onwards
    if printing_idx is not None:
        cumulative = 0
        for i in range(printing_idx, len(items)):
            if i == printing_idx:
                # Current printing: show its print time
                if items[i]["print_time_minutes"]:
                    cumulative = items[i]["print_time_minutes"]
                    items[i]["estimated_wait_minutes"] = cumulative
            else:
                # Queued item: add previous item's turnaround + this item's print time
                prev_item = items[i - 1]
                if prev_item["turnaround_minutes"] is not None:
                    cumulative += prev_item["turnaround_minutes"]
                else:
                    cumulative += 30  # default turnaround
                
                if items[i]["print_time_minutes"]:
                    cumulative += items[i]["print_time_minutes"]
                
                items[i]["estimated_wait_minutes"] = cumulative if cumulative > 0 else None

    my_pos = None
    if mine:
        for it in items:
            if it["short_id"] == mine:
                my_pos = it["pos"]
                break

    counts = {"NEW": 0, "APPROVED": 0, "PRINTING": 0, "DONE": 0}
    for it in items:
        if it["status"] in counts:
            counts[it["status"]] += 1

    return templates.TemplateResponse("public_queue.html", {
        "request": request,
        "items": items,
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


@app.get("/changelog", response_class=HTMLResponse)
def changelog(request: Request):
    """Version history and release notes"""
    return templates.TemplateResponse("changelog.html", {"request": request, "version": APP_VERSION})


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


def _fetch_requests_by_status(status: str, include_eta_fields: bool = False):
    conn = db()
    if include_eta_fields:
        rows = conn.execute(
            "SELECT id, created_at, requester_name, printer, material, colors, link_url, status, priority, special_notes, printing_started_at "
            "FROM requests "
            "WHERE status = ? "
            "ORDER BY priority ASC, created_at ASC",
            (status,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, created_at, requester_name, printer, material, colors, link_url, status, priority, special_notes "
            "FROM requests "
            "WHERE status = ? "
            "ORDER BY priority ASC, created_at ASC",
            (status,)
        ).fetchall()
    conn.close()
    return rows


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, _=Depends(require_admin)):
    new_reqs = _fetch_requests_by_status("NEW")
    queued = _fetch_requests_by_status("APPROVED")
    printing_raw = _fetch_requests_by_status("PRINTING", include_eta_fields=True)
    done = _fetch_requests_by_status("DONE")
    
    # Enrich printing requests with smart ETA
    printing = []
    for r in printing_raw:
        # Get current progress from printer for smart ETA calculation
        printer_progress = None
        printer_api = get_printer_api(r["printer"])
        if printer_api:
            try:
                printer_progress = await printer_api.get_percent_complete()
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
        
        # Calculate smart ETA
        eta_dt = get_smart_eta(
            printer=r["printer"],
            material=r["material"],
            current_percent=printer_progress,
            printing_started_at=printing_started_at
        )
        
        # Convert to dict and add ETA fields
        row_dict = dict(r)
        row_dict["smart_eta"] = eta_dt.isoformat() if eta_dt else None
        row_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        row_dict["printer_progress"] = printer_progress
        printing.append(row_dict)

    conn = db()
    closed = conn.execute(
        "SELECT id, created_at, requester_name, printer, material, colors, link_url, status, priority, special_notes "
        "FROM requests "
        "WHERE status IN (?, ?, ?) "
        "ORDER BY updated_at DESC "
        "LIMIT 30",
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
               COUNT(*) as count
        FROM print_history
    """).fetchone()
    
    ph_by_printer = conn2.execute("""
        SELECT printer, 
               AVG(duration_minutes) as avg_minutes,
               COUNT(*) as count
        FROM print_history
        GROUP BY printer
    """).fetchall()
    conn2.close()
    
    stats["print_history"] = {
        "count": ph_overall["count"] if ph_overall else 0,
        "avg_minutes": int(ph_overall["avg_minutes"]) if ph_overall and ph_overall["avg_minutes"] else None,
        "min_minutes": int(ph_overall["min_minutes"]) if ph_overall and ph_overall["min_minutes"] else None,
        "max_minutes": int(ph_overall["max_minutes"]) if ph_overall and ph_overall["max_minutes"] else None,
        "by_printer": [
            {"printer": p["printer"], "avg_minutes": int(p["avg_minutes"]) if p["avg_minutes"] else None, "count": p["count"]}
            for p in ph_by_printer
        ] if ph_by_printer else [],
    }
    
    return templates.TemplateResponse("admin_analytics.html", {
        "request": request,
        "stats": stats,
        "version": APP_VERSION,
    })



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
    _=Depends(require_admin),
):
    set_setting("flashforge_api_url", flashforge_api_url.strip())
    set_setting("printer_adventurer_4_ip", printer_adventurer_4_ip.strip())
    set_setting("printer_ad5x_ip", printer_ad5x_ip.strip())
    set_setting("camera_adventurer_4_url", camera_adventurer_4_url.strip())
    set_setting("camera_ad5x_url", camera_ad5x_url.strip())
    set_setting("enable_printer_polling", "1" if enable_printer_polling else "0")
    set_setting("enable_camera_snapshot", "1" if enable_camera_snapshot else "0")

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
    conn.close()
    
    # Get camera URL for the printer if configured
    camera_url = get_camera_url(req["printer"]) if req["printer"] in ["ADVENTURER_4", "AD5X"] else None
    
    return templates.TemplateResponse("admin_request.html", {
        "request": request,
        "req": req,
        "files": files,
        "events": events,
        "status_flow": STATUS_FLOW,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "allowed_exts": ", ".join(sorted(ALLOWED_EXTS)),
        "max_upload_mb": MAX_UPLOAD_MB,
        "camera_url": camera_url,
        "now": datetime.now().timestamp(),  # For cache-busting
        "version": APP_VERSION,
    })


@app.post("/admin/request/{rid}/status")
def admin_set_status(
    request: Request,
    rid: str,
    to_status: str = Form(...),
    comment: Optional[str] = Form(None),
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
        "APPROVED": "#10b981",  # Green
        "PRINTING": "#f59e0b",  # Amber
        "DONE": "#06b6d4",      # Cyan
        "PICKED_UP": "#8b5cf6", # Purple
        "REJECTED": "#ef4444",  # Red
        "CANCELLED": "#64748b", # Slate
    }
    status_titles = {
        "APPROVED": "✓ Request Approved",
        "PRINTING": "🖨 Now Printing",
        "DONE": "✓ Ready for Pickup",
        "PICKED_UP": "✓ Completed",
        "REJECTED": "Request Rejected",
        "CANCELLED": "Request Cancelled",
    }
    
    header_color = status_colors.get(to_status, "#4f46e5")
    status_title = status_titles.get(to_status, "Status Update")

    if requester_email_on_status:
        subject = f"[{APP_TITLE}] {status_title} ({rid[:8]})"
        text = (
            f"Your request status changed:\n\n"
            f"{from_status} → {to_status}\n\n"
            f"Comment: {comment or '(none)'}\n\n"
            f"View queue: {BASE_URL}/queue?mine={rid[:8]}\n"
        )
        html = build_email_html(
            title=status_title,
            subtitle=f"Request {rid[:8]} has been {to_status.lower().replace('_', ' ')}",
            rows=[
                ("Request ID", rid[:8]),
                ("Status", to_status),
                ("Comment", (comment or "—")),
            ],
            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
            cta_label="View in Queue",
            header_color=header_color,
        )
        send_email([req["requester_email"]], subject, text, html)

    if admin_email_on_status and admin_emails:
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
    total_minutes = hours * 60 + minutes
    
    if total_minutes < 1 or total_minutes > 999 * 60:  # up to 999 hours
        raise HTTPException(status_code=400, detail="Print time must be at least 1 minute (up to 999 hours)")
    if turnaround_minutes < 0 or turnaround_minutes > 1440:  # 0 to 24 hours
        raise HTTPException(status_code=400, detail="Turnaround must be 0..1440 minutes")

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        raise HTTPException(status_code=404, detail="Not found")

    conn.execute(
        "UPDATE requests SET print_time_minutes = ?, turnaround_minutes = ?, updated_at = ? WHERE id = ?",
        (total_minutes, turnaround_minutes, now_iso(), rid)
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
    """Get status of all printers - for AJAX refresh"""
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
                else:
                    printer_status[printer_code] = {"status": "OFFLINE", "healthy": False}
            else:
                printer_status[printer_code] = {"status": "NOT_CONFIGURED", "healthy": False}
        except Exception as e:
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
        "file_listing": None,
    }
    
    # Check for web interfaces
    ports_to_check = [80, 8080, 8888, 8899, 443]
    paths_to_check = ["/", "/index.html", "/timelapse", "/video", "/sd", "/sdcard"]
    
    async with httpx.AsyncClient(timeout=3.0) as client:
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
    
    # Try file listing via M-code
    files = await list_printer_files_via_mcode(printer_code)
    results["file_listing"] = {
        "files": files,
        "count": len(files),
    }
    
    return results
