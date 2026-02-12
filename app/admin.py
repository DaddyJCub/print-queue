import os, uuid, hashlib, urllib.parse
from datetime import datetime
from typing import Optional, List

import httpx
from fastapi import APIRouter, Request, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response

from app.main import (
    templates,
    db,
    require_admin,
    fetch_printer_status_with_cache,
    get_poll_debug_log,
    _printer_status_cache,
    _printer_failure_count,
    _polling_paused_until,
    pause_printer_polling,
    resume_printer_polling,
    get_setting,
    get_bool_setting,
    set_setting,
    APP_VERSION,
    ADMIN_PASSWORD,
    BASE_URL,
    PRINTERS,
    MATERIALS,
    format_eta_display,
    get_smart_eta,
    get_print_match_suggestions,
    is_feature_enabled,
    is_polling_paused,
    now_iso,
    log_buffer,
    LOG_BUFFER_SIZE,
    LOG_FILE,
    ALLOWED_EXTENSIONS,
    safe_ext,
    UPLOAD_DIR,
    DB_PATH,
    get_printer_api,
    get_camera_url,
    MoonrakerAPI,
)
from app.auth import get_all_admins, log_audit, AuditAction
from app.demo_data import DEMO_MODE, get_demo_status, reset_demo_data

router = APIRouter()

@router.get("/admin/feedback", response_class=HTMLResponse)
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


@router.post("/admin/feedback/{fid}/status")
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


@router.post("/admin/feedback/{fid}/delete")
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


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login(request: Request, next: Optional[str] = None, bad: Optional[str] = None, legacy: Optional[str] = None):
    # If multi_admin is enabled and not explicitly requesting legacy, redirect to new login
    if is_feature_enabled("multi_admin") and legacy != "1":
        redirect_url = "/admin/login/new"
        if next:
            from urllib.parse import quote
            redirect_url += f"?next={quote(next)}"
        return RedirectResponse(url=redirect_url, status_code=303)
    
    return templates.TemplateResponse("admin_login.html", {"request": request, "next": next, "bad": bad})


@router.post("/admin/login")
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


@router.get("/admin/logout")
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
                      r.fulfillment_method,
                      (SELECT rs.shipping_status FROM request_shipping rs WHERE rs.request_id = r.id) as shipping_status,
                      (SELECT rs.tracking_number FROM request_shipping rs WHERE rs.request_id = r.id) as shipping_tracking_number,
                      r.requires_design, r.designer_admin_id, r.design_completed_at,
                      r.print_time_minutes, r.slicer_estimate_minutes,
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
                      r.fulfillment_method,
                      (SELECT rs.shipping_status FROM request_shipping rs WHERE rs.request_id = r.id) as shipping_status,
                      (SELECT rs.tracking_number FROM request_shipping rs WHERE rs.request_id = r.id) as shipping_tracking_number,
                      r.requires_design, r.designer_admin_id, r.design_completed_at,
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


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin=Depends(require_admin)):
    design_enabled = is_feature_enabled("designer_workflow")
    # Fetch NEW and NEEDS_INFO together for "needs attention" section
    new_reqs = _fetch_requests_by_status(["NEW", "NEEDS_INFO"])
    queued = _fetch_requests_by_status("APPROVED")
    # Include IN_PROGRESS for multi-build requests that have active builds
    printing_raw = _fetch_requests_by_status(["PRINTING", "IN_PROGRESS"], include_eta_fields=True)
    # BLOCKED requests need attention (failed builds)
    blocked = _fetch_requests_by_status("BLOCKED")
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
        active_est_minutes = None
        if r["status"] == "IN_PROGRESS":
            conn_build = db()
            active_build = conn_build.execute(
                """SELECT b.printer, b.started_at, b.print_time_minutes, b.slicer_estimate_minutes FROM builds b 
                   WHERE b.request_id = ? AND b.status = 'PRINTING' 
                   LIMIT 1""", 
                (r["id"],)
            ).fetchone()
            conn_build.close()
            if active_build and active_build["printer"]:
                active_printer = active_build["printer"]
                if active_build["started_at"]:
                    printing_started_at = active_build["started_at"]
                active_est_minutes = active_build["print_time_minutes"] or active_build["slicer_estimate_minutes"]
        else:
            try:
                active_est_minutes = r["print_time_minutes"]
            except Exception:
                active_est_minutes = None
        
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
        
        # Get Moonraker time remaining if available (most accurate ETA source)
        moonraker_remaining = None
        if cached_status:
            moonraker_remaining = cached_status.get("moonraker_time_remaining")
        
        # Calculate smart ETA based on layers (preferred) or progress
        eta_dt = get_smart_eta(
            printer=active_printer,
            material=r["material"],
            current_percent=printer_progress,
            printing_started_at=printing_started_at,
            current_layer=current_layer,
            total_layers=total_layers,
            estimated_minutes=active_est_minutes or r["print_time_minutes"] or r["slicer_estimate_minutes"],
            moonraker_time_remaining=moonraker_remaining
        )
        
        # Convert to dict and add ETA fields
        row_dict = dict(r)
        row_dict["smart_eta"] = (eta_dt.isoformat() + "Z") if eta_dt else None
        row_dict["smart_eta_display"] = format_eta_display(eta_dt) if eta_dt else None
        row_dict["printer_progress"] = printer_progress
        row_dict["active_printer"] = active_printer  # For display
        printing.append(row_dict)

    conn = db()
    closed = conn.execute(
        """SELECT r.id, r.created_at, r.requester_name, r.printer, r.material, r.colors, 
                  r.link_url, r.status, r.priority, r.special_notes, r.print_name,
                  r.fulfillment_method,
                  (SELECT rs.shipping_status FROM request_shipping rs WHERE rs.request_id = r.id) as shipping_status,
                  r.requires_design, r.designer_admin_id, r.design_completed_at
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

    # Active build per printer (for pause button on dashboard)
    active_builds_by_printer = {}
    conn_active = db()
    rows = conn_active.execute(
        """SELECT b.id, b.build_number, b.printer, b.request_id, r.print_name
           FROM builds b
           JOIN requests r ON r.id = b.request_id
           WHERE b.status = 'PRINTING' AND b.printer IN ('ADVENTURER_4', 'AD5X')"""
    ).fetchall()
    conn_active.close()
    for row in rows:
        active_builds_by_printer[row["printer"]] = dict(row)

    # Get print match suggestions
    print_match_suggestions = get_print_match_suggestions()
    
    # Admin context for design filters and permissions
    current_admin = admin if hasattr(admin, "to_dict") else None
    designer_lookup = {}
    if design_enabled:
        for a in get_all_admins():
            designer_lookup[a.id] = a.display_name or a.username
    can_manage_queue = current_admin.has_permission("manage_queue") if current_admin else True
    can_manage_designs = current_admin.has_permission("manage_designs") if current_admin else False

    return templates.TemplateResponse("admin_queue.html", {
        "request": request,
        "new_reqs": new_reqs,
        "queued": queued,
        "printing": printing,
        "blocked": blocked,
        "done": done,
        "closed": closed,
        "printer_status": {
            "ADVENTURER_4": printer_status.get("ADVENTURER_4", {}),
            "AD5X": printer_status.get("AD5X", {}),
        },
        "active_builds_by_printer": active_builds_by_printer,
        "print_match_suggestions": print_match_suggestions,
        "printers": PRINTERS,
        "materials": MATERIALS,
        "version": APP_VERSION,
        "current_admin": current_admin.to_dict() if current_admin else None,
        "designer_lookup": designer_lookup,
        "current_admin_can_manage_queue": can_manage_queue,
        "current_admin_can_manage_designs": can_manage_designs,
        "design_enabled": design_enabled,
    })


@router.get("/admin/shipping", response_class=HTMLResponse)
def admin_shipping_dashboard(
    request: Request,
    shipping_status: Optional[str] = None,
    task: Optional[str] = None,
    q: Optional[str] = None,
    _=Depends(require_admin),
):
    conn = db()
    rows = conn.execute(
        """SELECT
             r.id,
             r.created_at,
             r.updated_at,
             r.requester_name,
             r.requester_email,
             r.print_name,
             r.status,
             r.printer,
             r.material,
             r.colors,
             r.fulfillment_method,
             rs.shipping_status,
             rs.address_validation_status,
             rs.quote_amount_cents,
             rs.quote_currency,
             rs.quote_notes,
             rs.tracking_number,
             rs.tracking_url,
             rs.carrier,
             rs.service,
             rs.recipient_name,
             rs.city,
             rs.state,
             rs.postal_code,
             rs.country,
             rs.updated_at as shipping_updated_at
           FROM requests r
           LEFT JOIN request_shipping rs ON rs.request_id = r.id
           WHERE r.fulfillment_method = 'shipping'
           ORDER BY COALESCE(rs.updated_at, r.updated_at) DESC, r.created_at DESC"""
    ).fetchall()
    conn.close()

    items_all = []
    for row in rows:
        item = dict(row)
        ship_status = (item.get("shipping_status") or "REQUESTED").upper()
        item["shipping_status"] = ship_status
        item["address_validation_status"] = (item.get("address_validation_status") or "").lower()
        item["has_quote"] = item.get("quote_amount_cents") is not None
        item["has_tracking"] = bool(item.get("tracking_number"))
        item["is_exception"] = ship_status in {"EXCEPTION", "RETURNED"}
        item["in_transit"] = ship_status in {"PRE_TRANSIT", "IN_TRANSIT", "OUT_FOR_DELIVERY"}
        item["is_delivered"] = ship_status == "DELIVERED"
        item["print_complete"] = item.get("status") in {"DONE", "PICKED_UP"}
        item["needs_address_validation"] = item["address_validation_status"] != "valid"
        item["needs_quote"] = (not item["has_quote"]) and (not item["is_delivered"]) and ship_status not in {"CANCELLED"}
        item["needs_label"] = (not item["has_tracking"]) and (not item["is_delivered"]) and ship_status not in {"CANCELLED"}
        item["task_ready_for_fulfillment"] = item["print_complete"] and (item["needs_quote"] or item["needs_label"])
        items_all.append(item)

    status_counts = {}
    for item in items_all:
        status_counts[item["shipping_status"]] = status_counts.get(item["shipping_status"], 0) + 1

    task_counts = {
        "all": len(items_all),
        "exceptions": sum(1 for i in items_all if i["is_exception"]),
        "ready_for_fulfillment": sum(1 for i in items_all if i["task_ready_for_fulfillment"]),
        "in_transit": sum(1 for i in items_all if i["in_transit"]),
        "delivered": sum(1 for i in items_all if i["is_delivered"]),
        "pending_print": sum(1 for i in items_all if not i["print_complete"]),
    }

    items = list(items_all)
    normalized_status = (shipping_status or "").strip().upper()
    if normalized_status:
        items = [i for i in items if i["shipping_status"] == normalized_status]

    normalized_task = (task or "").strip().lower()
    if normalized_task == "exceptions":
        items = [i for i in items if i["is_exception"]]
    elif normalized_task == "ready_for_fulfillment":
        items = [i for i in items if i["task_ready_for_fulfillment"]]
    elif normalized_task == "in_transit":
        items = [i for i in items if i["in_transit"]]
    elif normalized_task == "delivered":
        items = [i for i in items if i["is_delivered"]]
    elif normalized_task == "pending_print":
        items = [i for i in items if not i["print_complete"]]

    search_term = (q or "").strip().lower()
    if search_term:
        items = [
            i for i in items
            if search_term in (i.get("id") or "").lower()
            or search_term in (i.get("print_name") or "").lower()
            or search_term in (i.get("requester_name") or "").lower()
            or search_term in (i.get("tracking_number") or "").lower()
        ]

    shipping_statuses = [
        "REQUESTED",
        "ADDRESS_VALIDATED",
        "QUOTED",
        "LABEL_PURCHASED",
        "PRE_TRANSIT",
        "IN_TRANSIT",
        "OUT_FOR_DELIVERY",
        "DELIVERED",
        "EXCEPTION",
        "RETURNED",
        "CANCELLED",
    ]
    shipping_defaults = {
        "weight_oz": get_setting("shipping_default_weight_oz", "16"),
        "length_in": get_setting("shipping_default_length_in", "8"),
        "width_in": get_setting("shipping_default_width_in", "6"),
        "height_in": get_setting("shipping_default_height_in", "4"),
    }

    return templates.TemplateResponse("admin_shipping.html", {
        "request": request,
        "items": items,
        "shipping_statuses": shipping_statuses,
        "shipping_status_filter": normalized_status,
        "task_filter": normalized_task,
        "q": q or "",
        "status_counts": status_counts,
        "task_counts": task_counts,
        "shipping_defaults": shipping_defaults,
        "version": APP_VERSION,
    })


@router.get("/admin/settings", response_class=HTMLResponse)
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
        "notify_requester_blocked": get_setting("notify_requester_blocked", "1"),
        # Per-status notifications for admins (default to enabled)
        "notify_admin_needs_info": get_setting("notify_admin_needs_info", "1"),
        "notify_admin_approved": get_setting("notify_admin_approved", "1"),
        "notify_admin_printing": get_setting("notify_admin_printing", "1"),
        "notify_admin_done": get_setting("notify_admin_done", "1"),
        "notify_admin_picked_up": get_setting("notify_admin_picked_up", "1"),
        "notify_admin_rejected": get_setting("notify_admin_rejected", "1"),
        "notify_admin_cancelled": get_setting("notify_admin_cancelled", "1"),
        "notify_admin_blocked": get_setting("notify_admin_blocked", "1"),
        # Rush settings
        "enable_rush_option": get_bool_setting("enable_rush_option", True),
        "rush_fee_amount": get_setting("rush_fee_amount", "5"),
        "venmo_handle": get_setting("venmo_handle", "@YourVenmoHandle"),
        # Shipping settings
        "shipping_enabled": get_bool_setting("shipping_enabled", False),
        "shipping_default_country": get_setting("shipping_default_country", "US"),
        "shipping_notify_requester_updates": get_bool_setting("shipping_notify_requester_updates", True),
        "shipping_notify_admin_exceptions": get_bool_setting("shipping_notify_admin_exceptions", True),
        "shipping_default_weight_oz": get_setting("shipping_default_weight_oz", "16"),
        "shipping_default_length_in": get_setting("shipping_default_length_in", "8"),
        "shipping_default_width_in": get_setting("shipping_default_width_in", "6"),
        "shipping_default_height_in": get_setting("shipping_default_height_in", "4"),
        "shipping_from_name": get_setting("shipping_from_name", ""),
        "shipping_from_company": get_setting("shipping_from_company", ""),
        "shipping_from_phone": get_setting("shipping_from_phone", ""),
        "shipping_from_address_line1": get_setting("shipping_from_address_line1", ""),
        "shipping_from_address_line2": get_setting("shipping_from_address_line2", ""),
        "shipping_from_city": get_setting("shipping_from_city", ""),
        "shipping_from_state": get_setting("shipping_from_state", ""),
        "shipping_from_postal_code": get_setting("shipping_from_postal_code", ""),
        "shipping_from_country": get_setting("shipping_from_country", "US"),
        "shippo_webhook_user": get_setting("shippo_webhook_user", "").strip() or os.getenv("SHIPPO_WEBHOOK_USER", "").strip(),
        "shippo_api_key_configured": bool(get_setting("shippo_api_key", "").strip() or os.getenv("SHIPPO_API_KEY", "").strip()),
        "shippo_webhook_pass_configured": bool(get_setting("shippo_webhook_pass", "").strip() or os.getenv("SHIPPO_WEBHOOK_PASS", "").strip()),
        "shippo_webhook_token_configured": bool(get_setting("shippo_webhook_token", "").strip() or os.getenv("SHIPPO_WEBHOOK_TOKEN", "").strip()),
        "saved": bool(saved == "1"),
    }
    return templates.TemplateResponse("admin_settings.html", {"request": request, "s": model, "version": APP_VERSION})


@router.post("/admin/settings")
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
    notify_requester_blocked: Optional[str] = Form(None),
    # Per-status notifications for admins
    notify_admin_needs_info: Optional[str] = Form(None),
    notify_admin_approved: Optional[str] = Form(None),
    notify_admin_printing: Optional[str] = Form(None),
    notify_admin_done: Optional[str] = Form(None),
    notify_admin_picked_up: Optional[str] = Form(None),
    notify_admin_rejected: Optional[str] = Form(None),
    notify_admin_cancelled: Optional[str] = Form(None),
    notify_admin_blocked: Optional[str] = Form(None),
    # Rush settings
    enable_rush_option: Optional[str] = Form(None),
    rush_fee_amount: str = Form("5"),
    venmo_handle: str = Form("@YourVenmoHandle"),
    # Shipping settings
    shipping_enabled: Optional[str] = Form(None),
    shipping_default_country: str = Form("US"),
    shipping_notify_requester_updates: Optional[str] = Form(None),
    shipping_notify_admin_exceptions: Optional[str] = Form(None),
    shipping_default_weight_oz: str = Form("16"),
    shipping_default_length_in: str = Form("8"),
    shipping_default_width_in: str = Form("6"),
    shipping_default_height_in: str = Form("4"),
    shipping_from_name: str = Form(""),
    shipping_from_company: str = Form(""),
    shipping_from_phone: str = Form(""),
    shipping_from_address_line1: str = Form(""),
    shipping_from_address_line2: str = Form(""),
    shipping_from_city: str = Form(""),
    shipping_from_state: str = Form(""),
    shipping_from_postal_code: str = Form(""),
    shipping_from_country: str = Form("US"),
    # Shippo provider config
    shippo_api_key: Optional[str] = Form(None),
    clear_shippo_api_key: Optional[str] = Form(None),
    shippo_webhook_user: str = Form(""),
    shippo_webhook_pass: Optional[str] = Form(None),
    clear_shippo_webhook_pass: Optional[str] = Form(None),
    shippo_webhook_token: Optional[str] = Form(None),
    clear_shippo_webhook_token: Optional[str] = Form(None),
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
    set_setting("notify_requester_blocked", "1" if notify_requester_blocked else "0")
    # Per-status notifications for admins
    set_setting("notify_admin_needs_info", "1" if notify_admin_needs_info else "0")
    set_setting("notify_admin_approved", "1" if notify_admin_approved else "0")
    set_setting("notify_admin_printing", "1" if notify_admin_printing else "0")
    set_setting("notify_admin_done", "1" if notify_admin_done else "0")
    set_setting("notify_admin_picked_up", "1" if notify_admin_picked_up else "0")
    set_setting("notify_admin_rejected", "1" if notify_admin_rejected else "0")
    set_setting("notify_admin_cancelled", "1" if notify_admin_cancelled else "0")
    set_setting("notify_admin_blocked", "1" if notify_admin_blocked else "0")
    # Rush settings
    set_setting("enable_rush_option", "1" if enable_rush_option else "0")
    set_setting("rush_fee_amount", (rush_fee_amount or "5").strip())
    set_setting("venmo_handle", (venmo_handle or "").strip())
    # Shipping settings
    set_setting("shipping_enabled", "1" if shipping_enabled else "0")
    set_setting("shipping_default_country", (shipping_default_country or "US").strip().upper())
    set_setting("shipping_notify_requester_updates", "1" if shipping_notify_requester_updates else "0")
    set_setting("shipping_notify_admin_exceptions", "1" if shipping_notify_admin_exceptions else "0")
    set_setting("shipping_default_weight_oz", (shipping_default_weight_oz or "16").strip())
    set_setting("shipping_default_length_in", (shipping_default_length_in or "8").strip())
    set_setting("shipping_default_width_in", (shipping_default_width_in or "6").strip())
    set_setting("shipping_default_height_in", (shipping_default_height_in or "4").strip())
    set_setting("shipping_from_name", (shipping_from_name or "").strip())
    set_setting("shipping_from_company", (shipping_from_company or "").strip())
    set_setting("shipping_from_phone", (shipping_from_phone or "").strip())
    set_setting("shipping_from_address_line1", (shipping_from_address_line1 or "").strip())
    set_setting("shipping_from_address_line2", (shipping_from_address_line2 or "").strip())
    set_setting("shipping_from_city", (shipping_from_city or "").strip())
    set_setting("shipping_from_state", (shipping_from_state or "").strip())
    set_setting("shipping_from_postal_code", (shipping_from_postal_code or "").strip())
    set_setting("shipping_from_country", (shipping_from_country or "US").strip().upper())
    # Shippo provider config
    if clear_shippo_api_key:
        set_setting("shippo_api_key", "")
    elif shippo_api_key and shippo_api_key.strip():
        set_setting("shippo_api_key", shippo_api_key.strip())
    set_setting("shippo_webhook_user", (shippo_webhook_user or "").strip())
    if clear_shippo_webhook_pass:
        set_setting("shippo_webhook_pass", "")
    elif shippo_webhook_pass and shippo_webhook_pass.strip():
        set_setting("shippo_webhook_pass", shippo_webhook_pass.strip())
    if clear_shippo_webhook_token:
        set_setting("shippo_webhook_token", "")
    elif shippo_webhook_token and shippo_webhook_token.strip():
        set_setting("shippo_webhook_token", shippo_webhook_token.strip())

    return RedirectResponse(url="/admin/settings?saved=1", status_code=303)


@router.get("/admin/analytics", response_class=HTMLResponse)
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


@router.get("/admin/debug", response_class=HTMLResponse)
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
        "moonraker_enabled": is_feature_enabled("moonraker_ad5x"),
        "version": APP_VERSION,
    })


@router.post("/api/admin/pause-polling/{printer_code}")
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


@router.post("/api/admin/resume-polling/{printer_code}")
def api_resume_polling(printer_code: str, _=Depends(require_admin)):
    """Resume polling for a specific printer immediately."""
    if printer_code not in ["ADVENTURER_4", "AD5X"]:
        raise HTTPException(status_code=400, detail="Invalid printer code")
    
    resume_printer_polling(printer_code)
    return {"success": True, "printer": printer_code, "resumed": True}



# ─────────────────────────── ERROR TESTING ENDPOINTS ───────────────────────────
# These endpoints are for testing the error handling system

@router.get("/test-error/500")
def test_error_500(_=Depends(require_admin)):
    """Test endpoint to trigger a 500 Internal Server Error (admin only)"""
    raise ValueError("This is a test error to verify error handling and reporting works correctly")


@router.get("/test-error/404")
def test_error_404():
    """Test endpoint to trigger a 404 Not Found error"""
    raise HTTPException(status_code=404, detail="This is a test 404 error")


@router.get("/test-error/403")
def test_error_403():
    """Test endpoint to trigger a 403 Forbidden error"""
    raise HTTPException(status_code=403, detail="This is a test 403 access denied error")


@router.get("/test-error/400")
def test_error_400():
    """Test endpoint to trigger a 400 Bad Request error"""
    raise HTTPException(status_code=400, detail="This is a test 400 bad request error")



# ─────────────────────────── SMOKE CHECK ENDPOINT ───────────────────────────
@router.get("/admin/smoke-check")
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


@router.get("/api/logs")
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


@router.get("/api/logs/download")
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

@router.get("/api/demo/status")
def api_demo_status():
    """Check if demo mode is active and get status info"""
    return get_demo_status()


@router.post("/api/demo/reset")
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

@router.get("/admin/store", response_class=HTMLResponse)
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


@router.post("/admin/store/add")
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


@router.get("/admin/store/item/{item_id}", response_class=HTMLResponse)
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


@router.post("/admin/store/item/{item_id}/update")
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


@router.post("/admin/store/item/{item_id}/delete")
def admin_store_item_delete(request: Request, item_id: str, _=Depends(require_admin)):
    """Delete a store item"""
    conn = db()
    # Delete associated files
    conn.execute("DELETE FROM store_item_files WHERE store_item_id = ?", (item_id,))
    conn.execute("DELETE FROM store_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin/store?deleted=1", status_code=303)


@router.post("/admin/store/item/{item_id}/upload")
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


@router.post("/admin/store/item/{item_id}/file/{file_id}/delete")
def admin_store_file_delete(request: Request, item_id: str, file_id: str, _=Depends(require_admin)):
    """Delete a file from a store item"""
    conn = db()
    conn.execute("DELETE FROM store_item_files WHERE id = ? AND store_item_id = ?", (file_id, item_id))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url=f"/admin/store/item/{item_id}", status_code=303)



@router.get("/admin/printer-settings", response_class=HTMLResponse)
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
        "moonraker_ad5x_enabled": is_feature_enabled("moonraker_ad5x"),
        "moonraker_ad5x_url": get_setting("moonraker_ad5x_url", ""),
        "moonraker_ad5x_api_key": get_setting("moonraker_ad5x_api_key", ""),
        "saved": bool(saved == "1"),
    }
    # Resolve the active camera URL so the admin can see what's being used
    model["camera_ad5x_resolved"] = get_camera_url("AD5X") or ""
    model["camera_adv4_resolved"] = get_camera_url("ADVENTURER_4") or ""
    return templates.TemplateResponse("printer_settings.html", {"request": request, "s": model, "version": APP_VERSION})


@router.post("/admin/printer-settings")
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
    moonraker_ad5x_url: str = Form(""),
    moonraker_ad5x_api_key: str = Form(""),
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
    set_setting("moonraker_ad5x_url", moonraker_ad5x_url.strip())
    set_setting("moonraker_ad5x_api_key", moonraker_ad5x_api_key.strip())

    return RedirectResponse(url="/admin/printer-settings?saved=1", status_code=303)


# ── Moonraker Printer Control Routes ─────────────────────────────────────
# All routes require admin auth and the moonraker_ad5x feature flag.
# Control actions are audit-logged and require confirmation parameters.

def _require_moonraker(printer_code: str):
    """Validate that Moonraker is enabled for this printer and return the API instance."""
    if printer_code != "AD5X":
        raise HTTPException(status_code=400, detail="Moonraker is only available for AD5X")
    if not is_feature_enabled("moonraker_ad5x"):
        raise HTTPException(status_code=403, detail="Moonraker integration is disabled. Enable the 'Moonraker AD5X' feature flag first.")
    api = get_printer_api(printer_code)
    if not isinstance(api, MoonrakerAPI):
        raise HTTPException(status_code=503, detail="Moonraker API not configured. Set the Moonraker URL in Printer Settings.")
    return api


@router.get("/api/admin/moonraker/{printer_code}/test")
async def moonraker_test_connection(printer_code: str, _=Depends(require_admin)):
    """Test Moonraker connection and return server info."""
    api = _require_moonraker(printer_code)
    result = await api.test_connection()
    return result


@router.get("/api/admin/moonraker/{printer_code}/webcams")
async def moonraker_list_webcams(printer_code: str, _=Depends(require_admin)):
    """List webcams configured in Moonraker and test camera connectivity."""
    api = _require_moonraker(printer_code)
    
    webcams = await api.get_webcams()
    cam_urls = await api.get_camera_urls()
    
    # Try to test snapshot reachability
    snapshot_reachable = False
    if cam_urls and cam_urls.get("snapshot_url"):
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(cam_urls["snapshot_url"])
                snapshot_reachable = r.status_code == 200
        except Exception:
            pass
    
    # Also test the derived ustreamer URL
    from urllib.parse import urlparse
    derived_url = None
    derived_reachable = False
    moonraker_url = get_setting("moonraker_ad5x_url", "")
    if moonraker_url:
        parsed = urlparse(moonraker_url)
        if parsed.hostname:
            derived_url = f"http://{parsed.hostname}:8080/?action=snapshot"
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    r = await client.get(derived_url)
                    derived_reachable = r.status_code == 200
            except Exception:
                pass
    
    return {
        "webcams": webcams or [],
        "auto_detected": cam_urls,
        "snapshot_reachable": snapshot_reachable,
        "derived_url": derived_url,
        "derived_reachable": derived_reachable,
    }


@router.get("/api/admin/moonraker/{printer_code}/files")
async def moonraker_list_files(printer_code: str, _=Depends(require_admin)):
    """List G-code files on the printer."""
    api = _require_moonraker(printer_code)
    files = await api.get_server_files()
    if files is None:
        raise HTTPException(status_code=502, detail="Failed to fetch file list from Moonraker")
    return {"files": files}


@router.post("/api/admin/printer/{printer_code}/upload")
async def moonraker_upload_file(
    printer_code: str,
    file: UploadFile = File(...),
    admin=Depends(require_admin),
):
    """Upload a G-code file to the printer via Moonraker."""
    api = _require_moonraker(printer_code)
    
    if not file.filename or not file.filename.lower().endswith(('.gcode', '.g')):
        raise HTTPException(status_code=400, detail="Only .gcode files can be uploaded to the printer")
    
    file_data = await file.read()
    if len(file_data) > 500 * 1024 * 1024:  # 500MB limit
        raise HTTPException(status_code=400, detail="File too large (max 500MB)")
    
    result = await api.upload_file(file.filename, file_data)
    if not result:
        raise HTTPException(status_code=502, detail="Failed to upload file to Moonraker")
    
    log_audit(
        action=AuditAction.PRINTER_FILE_UPLOADED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        actor_name=getattr(admin, 'display_name', None) or getattr(admin, 'username', 'admin'),
        target_type="printer",
        target_id=printer_code,
        details={"filename": file.filename, "size_bytes": len(file_data)},
    )
    
    return {"success": True, "filename": file.filename, "size": len(file_data)}


@router.post("/api/admin/printer/{printer_code}/start")
async def moonraker_start_print(
    printer_code: str,
    filename: str = Form(...),
    confirm: str = Form("0"),
    admin=Depends(require_admin),
):
    """Start printing a file on the printer. Requires confirm=1."""
    api = _require_moonraker(printer_code)
    
    if confirm != "1":
        raise HTTPException(status_code=400, detail="Confirmation required. Set confirm=1 to proceed.")
    
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    success = await api.start_print(filename)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to start print via Moonraker")
    
    log_audit(
        action=AuditAction.PRINTER_PRINT_STARTED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="printer",
        target_id=printer_code,
        details={"filename": filename},
    )
    
    return {"success": True, "action": "start", "filename": filename, "printer": printer_code}


@router.post("/api/admin/printer/{printer_code}/pause")
async def moonraker_pause_print(
    printer_code: str,
    confirm: str = Form("0"),
    admin=Depends(require_admin),
):
    """Pause the current print. Requires confirm=1."""
    api = _require_moonraker(printer_code)
    
    if confirm != "1":
        raise HTTPException(status_code=400, detail="Confirmation required. Set confirm=1 to proceed.")
    
    success = await api.pause_print()
    if not success:
        raise HTTPException(status_code=502, detail="Failed to pause print via Moonraker")
    
    log_audit(
        action=AuditAction.PRINTER_PRINT_PAUSED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="printer",
        target_id=printer_code,
    )
    
    return {"success": True, "action": "pause", "printer": printer_code}


@router.post("/api/admin/printer/{printer_code}/resume")
async def moonraker_resume_print(
    printer_code: str,
    confirm: str = Form("0"),
    admin=Depends(require_admin),
):
    """Resume a paused print. Requires confirm=1."""
    api = _require_moonraker(printer_code)
    
    if confirm != "1":
        raise HTTPException(status_code=400, detail="Confirmation required. Set confirm=1 to proceed.")
    
    success = await api.resume_print()
    if not success:
        raise HTTPException(status_code=502, detail="Failed to resume print via Moonraker")
    
    log_audit(
        action=AuditAction.PRINTER_PRINT_RESUMED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="printer",
        target_id=printer_code,
    )
    
    return {"success": True, "action": "resume", "printer": printer_code}


@router.post("/api/admin/printer/{printer_code}/cancel")
async def moonraker_cancel_print(
    printer_code: str,
    confirm: str = Form("0"),
    force: str = Form("0"),
    admin=Depends(require_admin),
):
    """Cancel the current print. Requires confirm=1. Use force=1 to bypass safety checks."""
    api = _require_moonraker(printer_code)
    
    if confirm != "1":
        raise HTTPException(status_code=400, detail="Confirmation required. Set confirm=1 to proceed.")
    
    # Extra safety: verify the printer is actually printing or paused
    is_printing = await api.is_printing()
    objects = await api._query_objects()
    state = objects.get("print_stats", {}).get("state", "standby") if objects else "unknown"
    
    if not is_printing and state != "paused" and force != "1":
        raise HTTPException(
            status_code=409,
            detail=f"Printer is not currently printing (state: {state}). Set force=1 to cancel anyway."
        )
    
    success = await api.cancel_print()
    if not success:
        raise HTTPException(status_code=502, detail="Failed to cancel print via Moonraker")
    
    log_audit(
        action=AuditAction.PRINTER_PRINT_CANCELLED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="printer",
        target_id=printer_code,
        details={"previous_state": state, "force": force == "1"},
    )
    
    return {"success": True, "action": "cancel", "printer": printer_code, "previous_state": state}
