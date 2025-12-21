import os, json, uuid, hashlib, base64, urllib.parse, secrets
from typing import Optional, List, Any, Dict
from datetime import datetime

import httpx

from fastapi import APIRouter, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import RedirectResponse, FileResponse, Response, StreamingResponse, HTMLResponse

from app.main import (
    templates,
    db,
    require_admin,
    ALLOWED_EXTS,
    MAX_UPLOAD_MB,
    UPLOAD_DIR,
    PRINTERS,
    MATERIALS,
    now_iso,
    parse_3d_file_metadata,
    safe_json_dumps,
    safe_ext,
    get_adjusted_print_time,
    start_build,
    fail_build,
    retry_build,
    skip_build,
    complete_build,
    delete_build,
    sync_request_status_from_builds,
    capture_camera_snapshot,
    BUILD_STATUS_FLOW,
    BUILD_TRANSITIONS,
    STATUS_FLOW,
    get_bool_setting,
    logger,
    get_printer_api,
    get_camera_url,
    _printer_status_cache,
    _printer_failure_count,
    record_printer_failure,
    update_printer_status_cache,
    get_cached_printer_status,
    get_poll_debug_log,
    get_slicer_accuracy_factor,
    get_request_templates,
    get_setting,
    APP_VERSION,
    APP_TITLE,
    ADMIN_PASSWORD,
    BASE_URL,
    add_poll_debug_log,
    clear_print_match_suggestion,
    mark_builds_ready,
    setup_builds_for_request,
    get_print_match_suggestions,
    get_request_eta_info,
    get_user_notification_prefs,
    parse_email_list,
    build_email_html,
    send_email,
    send_push_notification,
    send_push_notification_to_admins,
    get_filename_base,
    get_or_create_my_requests_token,
    first_name_only,
    _human_printer,
    _human_material,
)
from app.auth import get_current_admin
from app.demo_data import (
    DEMO_MODE,
    get_demo_printer_status,
    get_demo_printer_job,
    get_demo_all_printers_status,
)

router = APIRouter()

# ─────────────────────────── BUILD MANAGEMENT ENDPOINTS ───────────────────────────

@router.post("/admin/build/{build_id}/start")
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


@router.post("/admin/build/{build_id}/fail")
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


@router.post("/admin/build/{build_id}/retry")
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


@router.post("/admin/build/{build_id}/skip")
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


@router.post("/admin/build/{build_id}/complete")
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


@router.post("/admin/request/{rid}/configure-builds")
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


@router.post("/admin/build/{build_id}/delete")
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


@router.post("/admin/build/{build_id}/notes")
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


@router.post("/admin/build/{build_id}/update")
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


@router.post("/admin/build/{build_id}/set-status")
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


@router.post("/admin/request/{rid}/start-next-build")
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


@router.post("/admin/build/{build_id}/start")
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


@router.post("/admin/request/{rid}/reorder-builds")
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


@router.post("/admin/request/{rid}/priority")
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


@router.post("/admin/request/{rid}/print-time")
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


@router.post("/admin/request/{rid}/admin-notes")
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


@router.post("/admin/request/{rid}/edit")
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


@router.post("/admin/request/{rid}/add-file")
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


@router.get("/admin/request/{rid}/file/{file_id}")
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


@router.post("/admin/request/{rid}/file/{file_id}/delete")
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


@router.post("/admin/request/{rid}/file/{file_id}/assign-build")
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


@router.get("/admin/request/{rid}/file/{file_id}/preview")
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


@router.post("/admin/batch-update")
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

@router.get("/api/camera/{printer_code}/snapshot")
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


@router.get("/api/camera/{printer_code}/stream")
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


@router.get("/api/camera/status")
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


@router.get("/api/request/{rid}/completion-snapshot")
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


@router.get("/api/poll-debug")
def get_poll_debug(_=Depends(require_admin)):
    """Get polling debug logs for troubleshooting auto-complete issues"""
    return {
        "logs": get_poll_debug_log(),
        "printer_cache": {k: v for k, v in _printer_status_cache.items()},
        "failure_counts": {k: v for k, v in _printer_failure_count.items()},
    }


@router.get("/api/slicer-accuracy")
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


@router.get("/api/version")
def get_version():
    """Get application version"""
    return {"version": APP_VERSION, "title": APP_TITLE}


@router.get("/api/admin/check")
async def check_admin_status(request: Request):
    """Check if the current user is authenticated as admin.
    Returns {is_admin: true/false} - used by PWA to show admin tab.
    Supports both multi-admin sessions and legacy password auth.
    """
    # Check multi-admin session first
    admin = await get_current_admin(request)
    if admin:
        return {"is_admin": True, "admin_id": admin.id, "admin_name": admin.display_name}
    
    # Fall back to legacy password check
    pw = request.cookies.get("admin_pw", "")
    is_admin = bool(pw and ADMIN_PASSWORD and pw == ADMIN_PASSWORD)
    return {"is_admin": is_admin}



# ─────────────────────────── REQUEST TEMPLATES ───────────────────────────

@router.get("/api/templates")
def list_templates():
    """Get all saved request templates"""
    return {"templates": get_request_templates()}


@router.post("/api/templates")
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


@router.delete("/api/templates/{template_id}")
def delete_template(template_id: str):
    """Delete a request template"""
    conn = db()
    conn.execute("DELETE FROM request_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Template deleted"}


@router.get("/api/templates/{template_id}")
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


@router.get("/api/printer/{printer_code}/debug")
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


@router.get("/api/printer/{printer_code}/job")
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


@router.get("/api/printers/status")
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


@router.get("/api/printer/{printer_code}/raw/{command}")
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


@router.get("/api/printer/{printer_code}/test-commands")
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


@router.get("/api/print-history")
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


@router.get("/api/printer/{printer_code}/files")
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


@router.get("/api/printer/{printer_code}/timelapses")
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


@router.get("/api/printer/{printer_code}/timelapse/{filename}")
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


@router.get("/api/printer/{printer_code}/timelapse-probe")
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

@router.get("/admin/request/{rid}", response_class=HTMLResponse)
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


@router.post("/admin/request/{rid}/duplicate")
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


@router.post("/admin/request/{rid}/add-to-store")
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


@router.post("/admin/match-print/{rid}")
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


@router.post("/admin/dismiss-match/{printer}")
def admin_dismiss_match_suggestion(
    request: Request,
    printer: str,
    _=Depends(require_admin)
):
    """Dismiss a print match suggestion."""
    clear_print_match_suggestion(printer)
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/request/{rid}/status")
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


@router.post("/admin/request/{rid}/send-reminder")
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


@router.post("/admin/request/{rid}/message")
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


