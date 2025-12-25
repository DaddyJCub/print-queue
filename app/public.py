import os, uuid, hashlib, secrets, urllib.parse
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

from app.auth import optional_user
from app.main import (
    templates,
    db,
    render_form,
    verify_turnstile,
    PRINTERS,
    MATERIALS,
    ALLOWED_EXTS,
    MAX_UPLOAD_MB,
    UPLOAD_DIR,
    parse_3d_file_metadata,
    safe_json_dumps,
    get_printer_suggestions,
    calculate_rush_price,
    now_iso,
    parse_email_list,
    get_setting,
    get_bool_setting,
    APP_TITLE,
    APP_VERSION,
    BASE_URL,
    TURNSTILE_SITE_KEY,
    safe_ext,
    _human_printer,
    _human_material,
    get_or_create_my_requests_token,
    send_email,
    build_email_html,
    send_push_notification_to_admins,
    fetch_printer_status_with_cache,
    format_eta_display,
    get_smart_eta,
    first_name_only,
)

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Check if user is logged in
    user = await optional_user(request)
    return render_form(request, None, form={}, user=user)


@router.post("/submit")
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
    upload: List[UploadFile] = File(default=[]),
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
    # Filter to only valid files with actual filenames
    valid_files = [f for f in upload if f and f.filename]
    has_file = len(valid_files) > 0
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
    
    # Build rush note for admin (stored in admin_notes, not special_notes)
    admin_notes = None
    if is_rush:
        if is_brandon:
            admin_notes = f"🚀 RUSH REQUEST (${final_rush_price} paid - Brandon Tax™ x5) - Priority processing"
        else:
            admin_notes = f"🚀 RUSH REQUEST (${final_rush_price} paid) - Priority processing"
    
    # If rush requested but no payment, add note for admin
    if rush_request and not rush_payment_confirmed:
        admin_notes = f"⚠️ Rush requested (${final_rush_price}) but payment NOT confirmed - verify before prioritizing"
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
            None,  # special_notes deprecated - use messages instead
            priority,
            admin_notes,  # Rush info goes here now
            access_token,
        )
    )
    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, created, None, "NEW", "Request submitted")
    )
    conn.commit()

    uploaded_names = []
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024

    if has_file:
        for file in valid_files:
            ext = safe_ext(file.filename)
            if ext not in ALLOWED_EXTS:
                conn.close()
                return render_form(request, f"File '{file.filename}' not allowed. Only these file types are allowed: {', '.join(sorted(ALLOWED_EXTS))}", form_state)

            data = await file.read()
            if len(data) > max_bytes:
                conn.close()
                return render_form(request, f"File '{file.filename}' too large. Max size is {MAX_UPLOAD_MB}MB.", form_state)

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
            uploaded_names.append(file.filename)
        
        conn.commit()

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
                ("Files", (", ".join(uploaded_names) if uploaded_names else "—")),
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
                ("Files", (", ".join(uploaded_names) if uploaded_names else "—")),
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


@router.get("/queue", response_class=HTMLResponse)
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
        r = dict(r)
        short_id = r["id"][:8]
        
        # Fetch real printer progress if currently printing
        printer_progress = None
        smart_eta = None
        smart_eta_display = None
        current_layer = None
        total_layers = None
        printing_started_at = r.get("printing_started_at")
        active_printer = r["printer"]  # Default to request printer
        
        # Handle IN_PROGRESS (multi-build) - get active build's printer
        active_build_id = r.get("active_build_id")
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
                total_layers=total_layers,
                estimated_minutes=r.get("print_time_minutes") or r.get("slicer_estimate_minutes")
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
        build = dict(build)
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
                            total_layers=build_total_layers,
                            estimated_minutes=build.get("print_time_minutes") or build.get("slicer_estimate_minutes") or parent_item.get("print_time_minutes") or parent_item.get("slicer_estimate_minutes")
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


@router.get("/repeat/{short_id}", response_class=HTMLResponse)
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



# ─────────────────────────── QUEUE API ───────────────────────────

@router.get("/api/queue")
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
        r = dict(r)
        short_id = r["id"][:8]
        printer_progress = None
        smart_eta_display = None
        current_layer = None
        total_layers = None
        printing_started_at = r.get("printing_started_at")
        active_printer = r["printer"]  # Default to request printer
        
        # Handle IN_PROGRESS (multi-build) - get active build's printer
        active_build_id = r.get("active_build_id")
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
                    total_layers=total_layers or 0,
                    estimated_minutes=r.get("print_time_minutes") or r.get("slicer_estimate_minutes")
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
        build = dict(build)
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
                            total_layers=build_total_layers or 0,
                            estimated_minutes=build.get("print_time_minutes") or build.get("slicer_estimate_minutes") or parent_item.get("print_time_minutes") or parent_item.get("slicer_estimate_minutes")
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


@router.get("/changelog", response_class=HTMLResponse)
def changelog(request: Request):
    """Version history and release notes"""
    return templates.TemplateResponse("changelog.html", {"request": request, "version": APP_VERSION})



# ─────────────────────────── FEEDBACK (Bug Reports & Suggestions) ───────────────────────────

@router.get("/feedback", response_class=HTMLResponse)
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


@router.post("/feedback")
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



@router.get('/sw.js')
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


# ─────────────────────────── PUBLIC STORE ───────────────────────────

@router.get("/store", response_class=HTMLResponse)
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


@router.get("/store/item/{item_id}", response_class=HTMLResponse)
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


@router.post("/submit-store-request/{item_id}")
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


