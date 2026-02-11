import os, json, uuid, hashlib, secrets
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

from app.main import (
    templates,
    db,
    logger,
    APP_VERSION,
    APP_TITLE,
    BASE_URL,
    ALLOWED_EXTS,
    UPLOAD_DIR,
    parse_3d_file_metadata,
    safe_json_dumps,
    now_iso,
    get_request_eta_info,
    fetch_printer_status_with_cache,
    format_eta_display,
    get_smart_eta,
    get_setting,
    is_feature_enabled,
    get_or_create_my_requests_token,
    send_email,
    build_email_html,
    send_push_notification_to_admins,
)
from app.auth import optional_user, create_request_assignment
from app.models import AssignmentRole
from app.auth import get_current_user, get_current_admin

router = APIRouter()

# ─────────────────────────── REQUESTER PORTAL ───────────────────────────

@router.get("/open/{rid}", response_class=HTMLResponse)
async def open_in_app_page(request: Request, rid: str, token: str, report: Optional[str] = None, build_id: Optional[str] = None):
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
    if build_id:
        target_url += f"&build_id={build_id}"
    if report:
        target_url += "&report=1"
    return templates.TemplateResponse("open_in_app.html", {
        "request": request,
        "target_url": target_url,
        "rid": rid,
        "print_name": req["print_name"],
        "email": req["requester_email"],
        "report_mode": bool(report),
    })


@router.get("/my/{rid}", response_class=HTMLResponse)
async def requester_portal(request: Request, rid: str, token: str, report: Optional[str] = None, build_id: Optional[str] = None):
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

    # Normalize to dict for .get access
    req = dict(req)
    
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
                moonraker_remaining = printer_status.get("moonraker_time_remaining")
                eta_dt = get_smart_eta(
                    printer=active_printer,
                    material=req["material"],
                    current_percent=printer_status.get("progress") or 0,
                    printing_started_at=printing_started_at or now_iso(),
                    current_layer=printer_status.get("current_layer") or 0,
                    total_layers=printer_status.get("total_layers") or 0,
                    estimated_minutes=req["print_time_minutes"] or req["slicer_estimate_minutes"],
                    moonraker_time_remaining=moonraker_remaining
                )
                if eta_dt:
                    smart_eta_display = format_eta_display(eta_dt)
    
    # Get requester email for push diagnostics
    requester_email = req["requester_email"]
    
    # Find the currently printing build and its associated file (for 3D preview in print status)
    current_printing_build = None
    current_printing_file = None
    designer_name = None
    if req.get("designer_admin_id"):
        designer = conn.execute(
            "SELECT display_name, username FROM admins WHERE id = ?",
            (req["designer_admin_id"],)
        ).fetchone()
        if designer:
            designer_name = designer["display_name"] or designer["username"]
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
        "build_eta_info": get_request_eta_info(rid, dict(req), printer_status=printer_status),
        "active_printer": active_printer,
        "builds_with_snapshots": builds_with_snapshots,
        "requester_email": requester_email,
        "current_printing_build": current_printing_build,
        "current_printing_file": current_printing_file,
        "designer_name": designer_name,
        "report_mode": bool(report),
        "report_build_id": build_id,
    })


@router.post("/my/{rid}/reply")
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


@router.post("/my/{rid}/upload")
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


@router.post("/my/{rid}/edit")
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


@router.get("/my/{rid}/file/{file_id}")
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


@router.get("/my/{rid}/file/{file_id}/preview", response_class=HTMLResponse)
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


@router.post("/my/{rid}/cancel")
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


@router.post("/my/{rid}/resubmit")
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
    
    # Preserve account_id from original request if present
    account_id = req["account_id"] if "account_id" in req.keys() else None
    
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, special_notes, print_time_minutes, account_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        new_id, created, created,
        req["requester_name"], req["requester_email"],
        req["printer"], req["material"], req["colors"],
        req["link_url"], req["notes"], req["print_name"],
        "NEW", new_token, 3,  # Reset to default priority P3 for resubmitted requests
        None,  # Clear special_notes for fresh start
        req["print_time_minutes"],  # Keep estimated print time
        account_id,  # Preserve account link from original request
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
    
    # Copy requester assignment from original request if the original had an account
    if account_id:
        create_request_assignment(conn, new_id, account_id, AssignmentRole.REQUESTER)
    
    conn.commit()
    conn.close()
    
    # Redirect to the new request
    return RedirectResponse(url=f"/my/{new_id}?token={new_token}", status_code=303)


# ─────────────────────────── MY REQUESTS LOOKUP ───────────────────────────

@router.get("/my-requests", response_class=HTMLResponse)
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


@router.post("/my-requests")
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


@router.get("/my-requests/view", response_class=HTMLResponse)
async def my_requests_view(request: Request, token: str = None, user_session: str = None):
    """View all requests for an email using magic link or user session"""
    from app.auth import get_user_by_session, get_user_by_email, get_current_user
    
    conn = db()
    email = None
    token_to_use = token
    user = None
    needs_password_prompt = False
    is_admin_user = False
    
    # First, try user session auth
    if user_session:
        user = get_user_by_session(user_session)
        if user:
            email = user.email
            # Get or create a token for this email (for page functionality)
            token_to_use = get_or_create_my_requests_token(email)
            # Check if this user is also an admin
            admin = await get_current_admin(request)
            if admin and admin.id != "legacy":
                is_admin_user = True
            # Check if user needs password prompt (logged in via magic link but no password)
            if is_feature_enabled("user_accounts") and not user.password_hash:
                needs_password_prompt = True
    
    # Also try cookie-based session
    if not email:
        user = await get_current_user(request)
        if user:
            email = user.email
            token_to_use = get_or_create_my_requests_token(email)
            admin = await get_current_admin(request)
            if admin and admin.id != "legacy":
                is_admin_user = True
            if is_feature_enabled("user_accounts") and not user.password_hash:
                needs_password_prompt = True
    
    # If no session auth, try token auth
    if not email and token:
        token_row = conn.execute(
            "SELECT email, expires_at FROM email_lookup_tokens WHERE token = ?", (token,)
        ).fetchone()
        
        if token_row:
            # Check expiry
            expiry = datetime.fromisoformat(token_row["expires_at"].replace("Z", "+00:00"))
            if datetime.utcnow().replace(tzinfo=expiry.tzinfo) <= expiry:
                email = token_row["email"]
                # Check if user exists and needs password
                if is_feature_enabled("user_accounts"):
                    user = get_user_by_email(email)
                    if not user:
                        # Token user without account - prompt to create one
                        needs_password_prompt = True
                    elif not user.password_hash:
                        # User exists but no password - prompt to set one
                        needs_password_prompt = True
            else:
                # Token expired - clean up
                conn.execute("DELETE FROM email_lookup_tokens WHERE token = ?", (token,))
                conn.commit()
                conn.commit()
    
    # No valid auth
    if not email:
        conn.close()
        return templates.TemplateResponse("my_requests_lookup_new.html", {
            "request": request,
            "error": "expired",
            "version": APP_VERSION,
            "user_accounts_enabled": is_feature_enabled("user_accounts"),
        })
    
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
                    moonraker_remaining = req_dict["printer_status"].get("moonraker_time_remaining")
                    eta_dt = get_smart_eta(
                        printer=printer_code,
                        material=req["material"],
                        current_percent=req_dict["printer_status"].get("progress") or 0,
                        printing_started_at=printing_started_at or now_iso(),
                        current_layer=req_dict["printer_status"].get("current_layer") or 0,
                        total_layers=req_dict["printer_status"].get("total_layers") or 0,
                        estimated_minutes=req_dict.get("print_time_minutes") or req_dict.get("slicer_estimate_minutes"),
                        moonraker_time_remaining=moonraker_remaining
                    )
                    req_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        
        enriched_requests.append(req_dict)
    
    conn.close()
    
    return templates.TemplateResponse("my_requests_list_new.html", {
        "request": request,
        "email": email,
        "requests_list": enriched_requests,
        "token": token_to_use,  # Keep token for refresh
        "version": APP_VERSION,
        "user": user.to_dict() if user and hasattr(user, 'to_dict') else None,
        "needs_password_prompt": needs_password_prompt,
        "is_admin_user": is_admin_user,
        "user_accounts_enabled": is_feature_enabled("user_accounts"),
    })


@router.get("/my-requests/demo", response_class=HTMLResponse)
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
@router.post("/api/verify-code")
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
@router.post("/api/generate-sync-code")
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
