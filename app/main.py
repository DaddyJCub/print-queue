import os, uuid, sqlite3, hashlib, smtplib, ssl, urllib.parse
from email.message import EmailMessage
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
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

app = FastAPI(title=APP_TITLE)
templates = Jinja2Templates(directory="app/templates")

# NOTE: app/static must exist in your repo (can be empty with a .gitkeep)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

STATUS_FLOW = ["NEW", "APPROVED", "PRINTING", "DONE", "PICKED_UP"]

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
    conn.commit()
    conn.close()


@app.on_event("startup")
def _startup():
    init_db()


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def require_admin(request: Request):
    pw = request.headers.get("X-Admin-Password") or request.cookies.get("admin_pw") or ""
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD is not set")
    if pw != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


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


def send_email(to_addr: str, subject: str, body: str):
    if not (SMTP_HOST and SMTP_FROM and to_addr):
        return  # email disabled

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def safe_ext(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def first_name_only(name: str) -> str:
    # "Jacob Zillmer" -> "Jacob"
    # "  Jacob   " -> "Jacob"
    parts = (name or "").strip().split()
    return parts[0] if parts else ""


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("request_form.html", {
        "request": request,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "error": None,
    })


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
    # Turnstile verification (if configured)
    ok = await verify_turnstile(turnstile_token or "", request.client.host if request.client else None)
    if not ok:
        return templates.TemplateResponse("request_form.html", {
            "request": request,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "printers": PRINTERS,
            "materials": MATERIALS,
            "error": "Human verification failed. Please try again.",
        }, status_code=400)

    # Validation: printer + material must be from dropdown lists
    if printer not in [p[0] for p in PRINTERS]:
        return templates.TemplateResponse("request_form.html", {
            "request": request,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "printers": PRINTERS,
            "materials": MATERIALS,
            "error": "Invalid printer selection.",
        }, status_code=400)

    if material not in [m[0] for m in MATERIALS]:
        return templates.TemplateResponse("request_form.html", {
            "request": request,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "printers": PRINTERS,
            "materials": MATERIALS,
            "error": "Invalid material selection.",
        }, status_code=400)

    # Link validation (if present)
    if link_url:
        try:
            u = urllib.parse.urlparse(link_url.strip())
            if u.scheme not in ("http", "https"):
                raise ValueError("Invalid scheme")
        except Exception:
            return templates.TemplateResponse("request_form.html", {
                "request": request,
                "turnstile_site_key": TURNSTILE_SITE_KEY,
                "printers": PRINTERS,
                "materials": MATERIALS,
                "error": "Invalid link URL. Must start with http:// or https://",
            }, status_code=400)

    # Require either link or file
    has_link = bool(link_url and link_url.strip())
    has_file = bool(upload and upload.filename)
    if not has_link and not has_file:
        return templates.TemplateResponse("request_form.html", {
            "request": request,
            "turnstile_site_key": TURNSTILE_SITE_KEY,
            "printers": PRINTERS,
            "materials": MATERIALS,
            "error": "Please provide either a link OR upload a file (one is required).",
        }, status_code=400)

    rid = str(uuid.uuid4())
    created = now_iso()

    conn = db()
    conn.execute(
        """INSERT INTO requests
           (id, created_at, updated_at, requester_name, requester_email, printer, material, colors, link_url, notes, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
        )
    )
    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, created, None, "NEW", "Request submitted")
    )
    conn.commit()

    # Optional upload
    if has_file:
        ext = safe_ext(upload.filename)
        if ext not in ALLOWED_EXTS:
            conn.close()
            return templates.TemplateResponse("request_form.html", {
                "request": request,
                "turnstile_site_key": TURNSTILE_SITE_KEY,
                "printers": PRINTERS,
                "materials": MATERIALS,
                "error": f"Only these file types are allowed: {', '.join(sorted(ALLOWED_EXTS))}",
            }, status_code=400)

        max_bytes = MAX_UPLOAD_MB * 1024 * 1024
        data = await upload.read()
        if len(data) > max_bytes:
            conn.close()
            return templates.TemplateResponse("request_form.html", {
                "request": request,
                "turnstile_site_key": TURNSTILE_SITE_KEY,
                "printers": PRINTERS,
                "materials": MATERIALS,
                "error": f"File too large. Max size is {MAX_UPLOAD_MB}MB.",
            }, status_code=413)

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

    conn.close()

    # Email requester (optional if SMTP configured)
    send_email(
        requester_email.strip(),
        f"[3D Print Queue] Request received ({rid[:8]})",
        f"Your request has been received.\n\nRequest ID: {rid}\nStatus: NEW\n\nYou'll be notified when status changes."
    )

    # After submit, take them directly to the public queue and highlight their row
    return RedirectResponse(url=f"/queue?mine={rid[:8]}", status_code=303)


@app.get("/thanks", response_class=HTMLResponse)
def thanks(request: Request, id: str):
    return templates.TemplateResponse("thanks.html", {"request": request, "rid": id})


@app.get("/queue", response_class=HTMLResponse)
def public_queue(request: Request, mine: Optional[str] = None):
    """
    Public queue: shows active requests (not picked up) in oldest-first order,
    plus a position number. Displays first-name only.
    """
    conn = db()
    rows = conn.execute(
        "SELECT id, created_at, requester_name, printer, material, colors, status "
        "FROM requests "
        "WHERE status != ? "
        "ORDER BY created_at ASC",
        ("PICKED_UP",)
    ).fetchall()
    conn.close()

    items = []
    for idx, r in enumerate(rows, start=1):
        short_id = r["id"][:8]
        items.append({
            "pos": idx,
            "short_id": short_id,
            "requester_first": first_name_only(r["requester_name"]),
            "printer": r["printer"],
            "material": r["material"],
            "colors": r["colors"],
            "status": r["status"],
            "is_mine": bool(mine and mine == short_id),
        })

    return templates.TemplateResponse("public_queue.html", {
        "request": request,
        "items": items,
        "mine": mine,
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
    resp.set_cookie("admin_pw", password, httponly=True, samesite="lax")
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin_queue(request: Request, _=Depends(require_admin), status: Optional[str] = None, printer: Optional[str] = None):
    conn = db()
    q = "SELECT * FROM requests"
    params = []
    filters = []
    if status:
        filters.append("status = ?")
        params.append(status)
    if printer:
        filters.append("printer = ?")
        params.append(printer)
    if filters:
        q += " WHERE " + " AND ".join(filters)
    q += " ORDER BY created_at DESC"

    rows = conn.execute(q, params).fetchall()
    conn.close()
    return templates.TemplateResponse("admin_queue.html", {
        "request": request,
        "rows": rows,
        "status_flow": STATUS_FLOW,
        "printers": PRINTERS,
        "filter_status": status,
        "filter_printer": printer
    })


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
        "printers": PRINTERS
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

    # Notify requester
    send_email(
        req["requester_email"],
        f"[3D Print Queue] Status update ({rid[:8]})",
        f"Your request status changed:\n\n{from_status} → {to_status}\n\nComment: {comment or '(none)'}\n\nRequest ID: {rid}"
    )

    return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)


@app.get("/download/{stored_filename}")
def download_file(stored_filename: str, _=Depends(require_admin)):
    path = os.path.join(UPLOAD_DIR, stored_filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Not found")
    return RedirectResponse(url=f"/uploads/{stored_filename}", status_code=302)


# Expose uploads as static (admin pages link directly)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
