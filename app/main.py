import os, uuid, sqlite3, hashlib, smtplib, ssl, urllib.parse, json, base64
from email.message import EmailMessage
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
import asyncio
import threading

import httpx
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

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
        cur.execute("UPDATE requests SET turnaround_minutes = 30 WHERE turnaround_minutes IS NULL")

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

    async def is_printing(self) -> bool:
        """Check if printer is currently printing"""
        status = await self.get_status()
        if not status:
            return False
        # FlashForge status format: check if MachineStatus != READY
        machine_status = status.get("MachineStatus", "READY").strip()
        return machine_status != "READY"

    async def get_percent_complete(self) -> Optional[int]:
        """Get print progress percentage"""
        progress = await self.get_progress()
        if not progress:
            return None
        return progress.get("PercentageCompleted")


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
                percent_complete = await printer_api.get_percent_complete()

                # Auto-complete if not printing anymore AND at 100%
                is_complete = (not is_printing) and (percent_complete == 100)

                if is_complete:
                    rid = req["id"]
                    print(f"[PRINTER] {req['printer']} complete ({percent_complete}%), auto-updating {rid[:8]} to DONE")

                    # Auto-update status
                    conn = db()
                    req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
                    conn.execute(
                        "UPDATE requests SET status = ?, updated_at = ? WHERE id = ?",
                        ("DONE", now_iso(), rid)
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

                    if requester_email_on_status and req_row:
                        subject = f"[{APP_TITLE}] Print Complete! ({rid[:8]})"
                        text = f"Your print is done and ready for pickup!\n\nRequest ID: {rid[:8]}\n\nView queue: {BASE_URL}/queue?mine={rid[:8]}\n"
                        html = build_email_html(
                            title="Print Complete!",
                            subtitle="Your request is ready for pickup.",
                            rows=[("Request ID", rid[:8]), ("Status", "DONE")],
                            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
                            cta_label="View queue",
                        )
                        send_email([req_row["requester_email"]], subject, text, html)

                    if admin_email_on_status and admin_emails and req_row:
                        subject = f"[{APP_TITLE}] Auto-completed: {rid[:8]}"
                        text = f"Print automatically marked DONE.\n\nID: {rid}\nPrinter: {req['printer']}\nAdmin: {BASE_URL}/admin/request/{rid}\n"
                        html = build_email_html(
                            title="Print Auto-Completed",
                            subtitle="Printer finished and is idle.",
                            rows=[("Request ID", rid[:8]), ("Printer", req["printer"]), ("Status", "DONE")],
                            cta_url=f"{BASE_URL}/admin/request/{rid}",
                            cta_label="Open in admin",
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


def build_email_html(title: str, subtitle: str, rows: List[Tuple[str, str]], cta_url: Optional[str] = None, cta_label: str = "Open") -> str:
    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    row_html = ""
    for k, v in rows:
        row_html += f"""
          <tr>
            <td style="padding:10px 0;color:#a1a1aa;font-size:12px;vertical-align:top;width:140px;">{esc(k)}</td>
            <td style="padding:10px 0;color:#111827;font-size:14px;vertical-align:top;">{esc(v)}</td>
          </tr>
        """

    cta = ""
    if cta_url:
        cta = f"""
          <div style="margin-top:18px;">
            <a href="{esc(cta_url)}"
               style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;
                      padding:10px 14px;border-radius:10px;font-weight:600;font-size:14px;">
              {esc(cta_label)}
            </a>
          </div>
        """

    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#0b0b0f;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;">
    <div style="padding:24px;">
      <div style="max-width:640px;margin:0 auto;">
        <div style="color:#e5e7eb;font-weight:800;font-size:18px;margin-bottom:10px;">{esc(APP_TITLE)}</div>

        <div style="background:#ffffff;border-radius:16px;overflow:hidden;">
          <div style="padding:18px 18px 0 18px;">
            <div style="font-size:18px;font-weight:800;color:#111827;">{esc(title)}</div>
            <div style="margin-top:6px;color:#6b7280;font-size:13px;">{esc(subtitle)}</div>
          </div>

          <div style="padding:0 18px 18px 18px;">
            <table style="width:100%;border-collapse:collapse;margin-top:10px;">
              {row_html}
            </table>
            {cta}
          </div>
        </div>

        <div style="color:#71717a;font-size:12px;margin-top:12px;">
          Sent by {esc(APP_TITLE)} • {esc(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))}
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


def render_form(request: Request, error: Optional[str], form: Dict[str, Any]):
    return templates.TemplateResponse("request_form.html", {
        "request": request,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "error": error,
        "form": form,
    }, status_code=400 if error else 200)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render_form(request, None, form={})


@app.post("/submit")
async def submit(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    printer: str = Form(...),
    material: str = Form(...),
    colors: str = Form(...),
    link_url: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    turnstile_token: Optional[str] = Form(None, alias="cf-turnstile-response"),
    upload: Optional[UploadFile] = File(None),
):
    form_state = {
        "requester_name": requester_name,
        "requester_email": requester_email,
        "printer": printer,
        "material": material,
        "colors": colors,
        "link_url": link_url or "",
        "notes": notes or "",
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

    conn = db()
    conn.execute(
        """INSERT INTO requests
           (id, created_at, updated_at, requester_name, requester_email, printer, material, colors, link_url, notes, status, special_notes, priority, admin_notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rid,
            created,
            created,
            requester_name.strip(),
            requester_email.strip(),
            printer,
            material,
            colors.strip(),
            link_url.strip() if link_url else None,
            notes,
            "NEW",
            None,
            3,
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
        "SELECT id, requester_name, printer, material, colors, status, special_notes, print_time_minutes, turnaround_minutes "
        "FROM requests "
        "WHERE status NOT IN (?, ?, ?) "
        "ORDER BY created_at ASC",
        ("PICKED_UP", "REJECTED", "CANCELLED")
    ).fetchall()
    conn.close()

    items = []
    printing_idx = None
    
    # First pass: build items and find printing index, fetch real progress for PRINTING
    for idx, r in enumerate(rows):
        short_id = r["id"][:8]
        
        # Fetch real printer progress if currently printing
        printer_progress = None
        if r["status"] == "PRINTING":
            printer_api = get_printer_api(r["printer"])
            if printer_api:
                try:
                    printer_progress = await printer_api.get_percent_complete()
                except Exception:
                    pass  # Fall back to time-based estimate if API fails
        
        items.append({
            "pos": idx + 1,
            "short_id": short_id,
            "requester_first": first_name_only(r["requester_name"]),
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
    })


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})


@app.post("/admin/login")
def admin_login_post(password: str = Form(...)):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD is not set")
    if password != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login?bad=1", status_code=303)

    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie("admin_pw", password, httponly=True, samesite="lax", secure=True, max_age=604800)  # 7 days, HTTPS only
    return resp


@app.get("/admin/logout")
def admin_logout():
    """Clear admin session cookie and redirect to home."""
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("admin_pw")
    return resp


def _fetch_requests_by_status(status: str):
    conn = db()
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
def admin_dashboard(request: Request, _=Depends(require_admin)):
    new_reqs = _fetch_requests_by_status("NEW")
    queued = _fetch_requests_by_status("APPROVED")
    printing = _fetch_requests_by_status("PRINTING")
    done = _fetch_requests_by_status("DONE")

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

    return templates.TemplateResponse("admin_queue.html", {
        "request": request,
        "new_reqs": new_reqs,
        "queued": queued,
        "printing": printing,
        "done": done,
        "closed": closed,
    })


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request, _=Depends(require_admin), saved: Optional[str] = None):
    model = {
        "admin_notify_emails": get_setting("admin_notify_emails", ""),
        "admin_email_on_submit": get_bool_setting("admin_email_on_submit", True),
        "admin_email_on_status": get_bool_setting("admin_email_on_status", True),
        "requester_email_on_submit": get_bool_setting("requester_email_on_submit", False),
        "requester_email_on_status": get_bool_setting("requester_email_on_status", True),
        "saved": bool(saved == "1"),
    }
    return templates.TemplateResponse("admin_settings.html", {"request": request, "s": model})


@app.post("/admin/settings")
def admin_settings_post(
    request: Request,
    admin_notify_emails: str = Form(""),
    admin_email_on_submit: Optional[str] = Form(None),
    admin_email_on_status: Optional[str] = Form(None),
    requester_email_on_submit: Optional[str] = Form(None),
    requester_email_on_status: Optional[str] = Form(None),
    _=Depends(require_admin),
):
    # checkboxes: present => "on", missing => None
    set_setting("admin_notify_emails", (admin_notify_emails or "").strip())
    set_setting("admin_email_on_submit", "1" if admin_email_on_submit else "0")
    set_setting("admin_email_on_status", "1" if admin_email_on_status else "0")
    set_setting("requester_email_on_submit", "1" if requester_email_on_submit else "0")
    set_setting("requester_email_on_status", "1" if requester_email_on_status else "0")

    return RedirectResponse(url="/admin/settings?saved=1", status_code=303)


@app.get("/admin/printer-settings", response_class=HTMLResponse)
def admin_printer_settings(request: Request, _=Depends(require_admin), saved: Optional[str] = None):
    model = {
        "flashforge_api_url": get_setting("flashforge_api_url", "http://localhost:5000"),
        "printer_adventurer_4_ip": get_setting("printer_adventurer_4_ip", "192.168.0.198"),
        "printer_ad5x_ip": get_setting("printer_ad5x_ip", "192.168.0.157"),
        "enable_printer_polling": get_bool_setting("enable_printer_polling", True),
        "saved": bool(saved == "1"),
    }
    return templates.TemplateResponse("printer_settings.html", {"request": request, "s": model})


@app.post("/admin/printer-settings")
def admin_printer_settings_post(
    request: Request,
    flashforge_api_url: str = Form(""),
    printer_adventurer_4_ip: str = Form(""),
    printer_ad5x_ip: str = Form(""),
    enable_printer_polling: Optional[str] = Form(None),
    _=Depends(require_admin),
):
    set_setting("flashforge_api_url", flashforge_api_url.strip())
    set_setting("printer_adventurer_4_ip", printer_adventurer_4_ip.strip())
    set_setting("printer_ad5x_ip", printer_ad5x_ip.strip())
    set_setting("enable_printer_polling", "1" if enable_printer_polling else "0")

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
    conn.execute("UPDATE requests SET status = ?, updated_at = ? WHERE id = ?", (to_status, now_iso(), rid))
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

    if requester_email_on_status:
        subject = f"[{APP_TITLE}] Status update ({rid[:8]})"
        text = (
            f"Your request status changed:\n\n"
            f"{from_status} → {to_status}\n\n"
            f"Comment: {comment or '(none)'}\n\n"
            f"View queue: {BASE_URL}/queue?mine={rid[:8]}\n"
        )
        html = build_email_html(
            title="Status update",
            subtitle=f"{from_status} → {to_status}",
            rows=[
                ("Request ID", rid[:8]),
                ("From", from_status),
                ("To", to_status),
                ("Comment", (comment or "—")),
            ],
            cta_url=f"{BASE_URL}/queue?mine={rid[:8]}",
            cta_label="View queue",
        )
        send_email([req["requester_email"]], subject, text, html)

    if admin_email_on_status and admin_emails:
        subject = f"[{APP_TITLE}] Admin: {rid[:8]} {from_status}→{to_status}"
        text = (
            f"Status changed.\n\n"
            f"ID: {rid}\n"
            f"{from_status} → {to_status}\n"
            f"Comment: {comment or '(none)'}\n"
            f"Admin: {BASE_URL}/admin/request/{rid}\n"
        )
        html = build_email_html(
            title="Admin status change",
            subtitle=f"{from_status} → {to_status}",
            rows=[
                ("Request ID", rid[:8]),
                ("From", from_status),
                ("To", to_status),
                ("Comment", (comment or "—")),
                ("Requester", (req["requester_name"] or "—")),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="Open in admin",
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
           SET requester_name = ?, requester_email = ?, printer = ?, material = ?, colors = ?, link_url = ?, notes = ?, updated_at = ?
           WHERE id = ?""",
        (
            requester_name.strip(),
            requester_email.strip(),
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
