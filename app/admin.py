import os, uuid, hashlib, urllib.parse
from datetime import datetime
from typing import Optional, List

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
)
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
async def admin_dashboard(request: Request, _=Depends(require_admin)):
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
        
        # Calculate smart ETA based on layers (preferred) or progress
        eta_dt = get_smart_eta(
            printer=active_printer,
            material=r["material"],
            current_percent=printer_progress,
            printing_started_at=printing_started_at,
            current_layer=current_layer,
            total_layers=total_layers,
            estimated_minutes=active_est_minutes or r["print_time_minutes"] or r["slicer_estimate_minutes"]
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
        "blocked": blocked,
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
        "saved": bool(saved == "1"),
    }
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


