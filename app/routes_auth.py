"""
Authentication and Admin Management Routes for Printellect.

These routes handle:
- User login/register/logout
- User profile management
- Admin login (new multi-admin system)
- Admin account management
- User account management (admin view)
- Feature flag management
- Audit log viewing
"""

import os
import sqlite3
from datetime import datetime
from typing import Optional, List
from urllib.parse import quote, unquote

from fastapi import APIRouter, Request, Form, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    # User auth
    create_user, get_user_by_email, authenticate_user, get_user_by_session,
    create_magic_link, verify_magic_link, create_user_session, delete_user_session,
    update_user_profile, get_current_user, require_user, optional_user,
    get_user_by_id, get_all_users, get_user_count, update_user, delete_user, set_user_status,
    hash_password, verify_password, _row_to_user, db, change_user_password,
    
    # Admin auth
    create_admin, get_admin_by_username, authenticate_admin, get_admin_by_session,
    logout_admin, get_all_admins, update_admin, change_admin_password, delete_admin,
    get_current_admin, require_admin, require_permission,
    check_legacy_admin_password, get_or_create_legacy_admin,
    
    # Feature flags
    get_feature_flag, get_all_feature_flags, update_feature_flag, is_feature_enabled,
    
    # Audit
    log_audit, get_audit_logs,
    
    # Init
    init_auth_tables, init_feature_flags,
)

from app.models import AdminRole, AuditAction, UserStatus

# ─────────────────────────── SETUP ───────────────────────────

router = APIRouter()
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

# Register the localtime filter
templates.env.filters["localtime"] = format_datetime_local

# Database helper
def get_db_path():
    return os.getenv("DB_PATH", "/data/app.db")

def db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def get_client_ip(request: Request) -> str:
    """Get client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ─────────────────────────── USER AUTH ROUTES ───────────────────────────

@router.get("/auth/login", response_class=HTMLResponse)
async def user_login_page(request: Request, next: str = None, error: str = None, success: str = None):
    """User login page."""
    # Check if user accounts feature is enabled
    if not is_feature_enabled("user_accounts"):
        # Fall back to the existing email lookup system
        return RedirectResponse(url="/my-prints", status_code=303)
    
    # Already logged in?
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url=next or "/auth/profile", status_code=303)
    
    return templates.TemplateResponse("auth_login.html", {
        "request": request,
        "next": next,
        "error": error,
        "success": success,
    })


@router.post("/auth/login")
async def user_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(None)
):
    """Handle user login."""
    user = authenticate_user(email, password)
    
    if not user:
        return RedirectResponse(
            url=f"/auth/login?error=Invalid email or password&next={quote(next or '')}",
            status_code=303
        )
    
    if user.status == UserStatus.SUSPENDED:
        return RedirectResponse(
            url=f"/auth/login?error=Your account has been suspended&next={quote(next or '')}",
            status_code=303
        )
    
    # Create session
    token = create_user_session(
        user.id,
        device_info=request.headers.get("User-Agent"),
        ip_address=get_client_ip(request)
    )
    
    # Redirect to profile or next URL
    redirect_url = next if next else "/auth/profile"
    resp = RedirectResponse(url=redirect_url, status_code=303)
    resp.set_cookie(
        "user_session",
        token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("BASE_URL", "").startswith("https"),
        path="/",
        max_age=30 * 24 * 60 * 60  # 30 days
    )
    
    return resp


@router.post("/auth/magic-link")
async def user_magic_link(
    request: Request,
    email: str = Form(...),
    next: str = Form(None)
):
    """Send magic link for passwordless login."""
    token = create_magic_link(email)
    
    # Always show success (don't reveal if email exists)
    # In production, you'd send an email here
    if token:
        # TODO: Send email with magic link
        # link = f"{BASE_URL}/auth/verify?token={token}"
        pass
    
    return RedirectResponse(
        url=f"/auth/login?success=Check your email for a login link&next={quote(next or '')}",
        status_code=303
    )


@router.get("/auth/verify")
async def user_verify_magic_link(request: Request, token: str):
    """Verify magic link and log user in."""
    user = verify_magic_link(token)
    
    if not user:
        return RedirectResponse(
            url="/auth/login?error=Invalid or expired link",
            status_code=303
        )
    
    # Create session
    session_token = create_user_session(
        user.id,
        device_info=request.headers.get("User-Agent"),
        ip_address=get_client_ip(request)
    )
    
    resp = RedirectResponse(url="/auth/profile", status_code=303)
    resp.set_cookie(
        "user_session",
        session_token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("BASE_URL", "").startswith("https"),
        path="/",
        max_age=30 * 24 * 60 * 60
    )
    
    return resp


@router.get("/auth/register", response_class=HTMLResponse)
async def user_register_page(request: Request, next: str = None, error: str = None):
    """User registration page."""
    if not is_feature_enabled("user_accounts"):
        return RedirectResponse(url="/", status_code=303)
    
    if not is_feature_enabled("user_registration"):
        return RedirectResponse(
            url="/auth/login?error=Registration is currently disabled",
            status_code=303
        )
    
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/auth/profile", status_code=303)
    
    return templates.TemplateResponse("auth_register.html", {
        "request": request,
        "next": next,
        "error": error,
    })


@router.post("/auth/register")
async def user_register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    phone: str = Form(None),
    next: str = Form(None)
):
    """Handle user registration."""
    # Validation
    if password != password2:
        return RedirectResponse(
            url=f"/auth/register?error=Passwords don't match&next={quote(next or '')}",
            status_code=303
        )
    
    if len(password) < 8:
        return RedirectResponse(
            url=f"/auth/register?error=Password must be at least 8 characters&next={quote(next or '')}",
            status_code=303
        )
    
    # Check if email exists
    existing = get_user_by_email(email)
    if existing:
        return RedirectResponse(
            url=f"/auth/register?error=Email already registered&next={quote(next or '')}",
            status_code=303
        )
    
    # Create user
    try:
        user = create_user(email, name, password)
        
        # Update phone if provided
        if phone:
            update_user_profile(user.id, phone=phone)
        
        # Create session
        token = create_user_session(
            user.id,
            device_info=request.headers.get("User-Agent"),
            ip_address=get_client_ip(request)
        )
        
        redirect_url = next if next else "/auth/profile"
        resp = RedirectResponse(url=redirect_url, status_code=303)
        resp.set_cookie(
            "user_session",
            token,
            httponly=True,
            samesite="lax",
            secure=os.getenv("BASE_URL", "").startswith("https"),
            path="/",
            max_age=30 * 24 * 60 * 60
        )
        
        return resp
        
    except Exception as e:
        return RedirectResponse(
            url=f"/auth/register?error=Registration failed: {str(e)}&next={quote(next or '')}",
            status_code=303
        )


@router.get("/auth/profile", response_class=HTMLResponse)
async def user_profile_page(request: Request, success: str = None):
    """User profile page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login?next=/auth/profile", status_code=303)
    
    # Get printers and materials for preferences dropdowns
    conn = db()
    printers = conn.execute("SELECT DISTINCT value as name FROM settings WHERE key LIKE 'printer_%_name'").fetchall()
    conn.close()
    
    materials = ["PLA", "PETG", "ABS", "TPU", "Resin", "Other"]
    
    return templates.TemplateResponse("auth_profile.html", {
        "request": request,
        "user": user,
        "printers": printers,
        "materials": materials,
        "success": success,
    })


@router.post("/auth/profile")
async def user_profile_update(
    request: Request,
    name: str = Form(...),
    phone: str = Form(None),
    preferred_printer: str = Form(None),
    preferred_material: str = Form(None),
    preferred_colors: str = Form(None),
    notes_template: str = Form(None),
    email_status_updates: str = Form(None),
    email_print_ready: str = Form(None),
    push_enabled: str = Form(None),
    push_progress: str = Form(None),
):
    """Update user profile."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    # Build notification prefs
    notification_prefs = {
        "email_status_updates": email_status_updates == "1",
        "email_print_ready": email_print_ready == "1",
        "push_enabled": push_enabled == "1",
        "push_progress": push_progress == "1",
    }
    
    update_user_profile(
        user.id,
        name=name,
        phone=phone or None,
        preferred_printer=preferred_printer or None,
        preferred_material=preferred_material or None,
        preferred_colors=preferred_colors or None,
        notes_template=notes_template or None,
        notification_prefs=notification_prefs,
    )
    
    return RedirectResponse(url="/auth/profile?success=Profile updated", status_code=303)


@router.get("/auth/logout")
async def user_logout(request: Request):
    """Log out user."""
    token = request.cookies.get("user_session")
    if token:
        delete_user_session(token)
    
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("user_session", path="/")
    return resp


# ─────────────────────────── ADMIN AUTH ROUTES ───────────────────────────

@router.get("/admin/login/new", response_class=HTMLResponse)
async def admin_login_new_page(request: Request, next: str = None, error: str = None):
    """New admin login page (multi-admin system)."""
    if not is_feature_enabled("multi_admin"):
        # Fall back to legacy login
        return RedirectResponse(url="/admin/login", status_code=303)
    
    admin = await get_current_admin(request)
    if admin and admin.id != "legacy":
        return RedirectResponse(url=next or "/admin", status_code=303)
    
    return templates.TemplateResponse("admin_login_new.html", {
        "request": request,
        "next": next,
        "error": error,
    })


@router.post("/admin/login/new")
async def admin_login_new_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(None)
):
    """Handle new admin login."""
    result = authenticate_admin(
        username,
        password,
        ip_address=get_client_ip(request)
    )
    
    if not result:
        return RedirectResponse(
            url=f"/admin/login/new?error=Invalid credentials&next={quote(next or '')}",
            status_code=303
        )
    
    admin, token = result
    
    redirect_url = next if next and next.startswith("/admin") else "/admin"
    resp = RedirectResponse(url=redirect_url, status_code=303)
    resp.set_cookie(
        "admin_session",
        token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("BASE_URL", "").startswith("https"),
        path="/",
        max_age=7 * 24 * 60 * 60  # 7 days
    )
    
    return resp


@router.get("/admin/logout/new")
async def admin_logout_new(request: Request):
    """Log out admin (new system)."""
    admin = await get_current_admin(request)
    if admin and admin.id != "legacy":
        logout_admin(admin.id)
    
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("admin_session", path="/")
    resp.delete_cookie("admin_pw", path="/")  # Also clear legacy cookie
    return resp


# ─────────────────────────── ADMIN MANAGEMENT ROUTES ───────────────────────────

@router.get("/admin/admins", response_class=HTMLResponse)
async def admin_management_page(
    request: Request,
    success: str = None,
    error: str = None,
    admin: dict = Depends(require_permission("manage_admins"))
):
    """Admin management page (Super Admin only)."""
    admins = get_all_admins()
    
    # Convert to dicts for template
    admins_data = [a.to_dict() for a in admins]
    
    return templates.TemplateResponse("admin_admins.html", {
        "request": request,
        "admins": admins_data,
        "current_admin": admin.to_dict() if hasattr(admin, 'to_dict') else admin,
        "success": success,
        "error": error,
    })


@router.post("/admin/admins/create")
async def admin_create(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(None),
    role: str = Form("operator"),
    admin: dict = Depends(require_permission("manage_admins"))
):
    """Create new admin account."""
    try:
        # Validate role
        try:
            admin_role = AdminRole(role)
        except ValueError:
            admin_role = AdminRole.OPERATOR
        
        # Check if username exists
        existing = get_admin_by_username(username)
        if existing:
            return RedirectResponse(
                url="/admin/admins?error=Username already exists",
                status_code=303
            )
        
        new_admin = create_admin(
            username=username,
            email=email,
            password=password,
            role=admin_role,
            display_name=display_name,
            created_by=admin.id if hasattr(admin, 'id') else None
        )
        
        return RedirectResponse(
            url=f"/admin/admins?success=Admin {username} created",
            status_code=303
        )
        
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/admins?error={str(e)}",
            status_code=303
        )


@router.post("/admin/admins/update")
async def admin_update(
    request: Request,
    admin_id: str = Form(...),
    display_name: str = Form(None),
    email: str = Form(...),
    role: str = Form(...),
    new_password: str = Form(None),
    is_active: str = Form(None),
    admin: dict = Depends(require_permission("manage_admins"))
):
    """Update admin account."""
    try:
        # Convert role
        try:
            admin_role = AdminRole(role)
        except ValueError:
            admin_role = AdminRole.OPERATOR
        
        update_admin(
            admin_id,
            display_name=display_name,
            email=email,
            role=admin_role,
            is_active=is_active == "1"
        )
        
        if new_password and len(new_password) >= 8:
            change_admin_password(admin_id, new_password)
        
        # Audit log
        log_audit(
            action=AuditAction.ADMIN_UPDATED,
            actor_type="admin",
            actor_id=admin.id if hasattr(admin, 'id') else None,
            target_type="admin",
            target_id=admin_id,
            details={"role": role, "is_active": is_active == "1"}
        )
        
        return RedirectResponse(
            url="/admin/admins?success=Admin updated",
            status_code=303
        )
        
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/admins?error={str(e)}",
            status_code=303
        )


@router.post("/admin/admins/{admin_id}/delete")
async def admin_delete(
    request: Request,
    admin_id: str,
    admin: dict = Depends(require_permission("manage_admins"))
):
    """Delete admin account."""
    current_admin_id = admin.id if hasattr(admin, 'id') else None
    
    if admin_id == current_admin_id:
        return RedirectResponse(
            url="/admin/admins?error=Cannot delete your own account",
            status_code=303
        )
    
    # Get username for audit
    from app.auth import get_admin_by_id
    target_admin = get_admin_by_id(admin_id)
    
    delete_admin(admin_id)
    
    log_audit(
        action=AuditAction.ADMIN_DELETED,
        actor_type="admin",
        actor_id=current_admin_id,
        target_type="admin",
        target_id=admin_id,
        details={"username": target_admin.username if target_admin else "unknown"}
    )
    
    return RedirectResponse(
        url="/admin/admins?success=Admin deleted",
        status_code=303
    )


# ─────────────────────────── FEATURE FLAG ROUTES ───────────────────────────

@router.get("/admin/features", response_class=HTMLResponse)
async def feature_flags_page(
    request: Request,
    success: str = None,
    admin: dict = Depends(require_permission("manage_settings"))
):
    """Feature flags management page."""
    import os
    flags = get_all_feature_flags()
    
    # Check if SMTP is configured
    smtp_configured = bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_FROM"))
    
    return templates.TemplateResponse("admin_features.html", {
        "request": request,
        "flags": flags,
        "success": success,
        "smtp_configured": smtp_configured,
    })


@router.post("/admin/features/{key}/toggle")
async def toggle_feature_flag(
    request: Request,
    key: str,
    admin: dict = Depends(require_permission("manage_settings"))
):
    """Toggle a feature flag."""
    try:
        data = await request.json()
        enabled = data.get("enabled", False)
        
        update_feature_flag(
            key,
            enabled=enabled,
            updated_by=admin.id if hasattr(admin, 'id') else None
        )
        
        return JSONResponse({"success": True, "enabled": enabled})
        
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=400)


# ─────────────────────────── AUDIT LOG ROUTES ───────────────────────────

@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_log_page(
    request: Request,
    page: int = 1,
    action: str = None,
    admin: dict = Depends(require_permission("view_audit_log"))
):
    """View audit logs."""
    per_page = 50
    offset = (page - 1) * per_page
    
    logs = get_audit_logs(
        limit=per_page,
        offset=offset,
        action=action
    )
    
    # Get unique actions for filter
    all_actions = [a.value for a in AuditAction]
    
    return templates.TemplateResponse("admin_audit.html", {
        "request": request,
        "logs": [log.to_dict() for log in logs],
        "actions": all_actions,
        "current_action": action,
        "page": page,
        "has_more": len(logs) == per_page,
    })


# ─────────────────────────── FILE SYNC ROUTES ───────────────────────────

@router.get("/admin/file-sync", response_class=HTMLResponse)
async def admin_file_sync_page(
    request: Request,
    admin: dict = Depends(require_permission("manage_queue"))
):
    """File sync admin page."""
    from app.file_sync import (
        get_all_sync_configs, get_pending_matches, get_sync_stats
    )
    
    folders = get_all_sync_configs()
    pending_matches = get_pending_matches()
    stats = get_sync_stats()
    feature_enabled = is_feature_enabled("file_sync")
    
    return templates.TemplateResponse("admin_file_sync.html", {
        "request": request,
        "folders": [f.to_dict() for f in folders],
        "pending_matches": pending_matches,
        "stats": stats,
        "feature_enabled": feature_enabled,
    })


@router.post("/admin/file-sync/folders")
async def add_sync_folder(
    request: Request,
    admin: dict = Depends(require_permission("manage_settings"))
):
    """Add a new sync folder configuration."""
    from app.file_sync import create_sync_config
    
    data = await request.json()
    
    config = create_sync_config(
        name=data.get("name", "Unnamed Folder"),
        folder_path=data["path"],
        extensions=data.get("extensions", ".stl,.obj,.3mf"),
        match_threshold=float(data.get("match_threshold", 0.7)),
        scan_interval=int(data.get("scan_interval", 300)),
        recursive=data.get("recursive", True),
        auto_attach=data.get("auto_attach", True)
    )
    
    # Audit log
    log_audit(
        action=AuditAction.SETTINGS_UPDATED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        details={"action": "add_sync_folder", "folder": data["path"]}
    )
    
    return JSONResponse({"success": True, "folder_id": config.id})


@router.patch("/admin/file-sync/folders/{folder_id}")
async def update_sync_folder(
    request: Request,
    folder_id: str,
    admin: dict = Depends(require_permission("manage_settings"))
):
    """Update a sync folder configuration."""
    from app.file_sync import update_sync_config
    
    data = await request.json()
    update_sync_config(folder_id, **data)
    
    return JSONResponse({"success": True})


@router.delete("/admin/file-sync/folders/{folder_id}")
async def delete_sync_folder(
    folder_id: str,
    admin: dict = Depends(require_permission("manage_settings"))
):
    """Delete a sync folder configuration."""
    from app.file_sync import delete_sync_config
    
    delete_sync_config(folder_id)
    
    log_audit(
        action=AuditAction.SETTINGS_UPDATED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        details={"action": "delete_sync_folder", "folder_id": folder_id}
    )
    
    return JSONResponse({"success": True})


@router.post("/admin/file-sync/folders/{folder_id}/sync")
async def sync_single_folder(
    folder_id: str,
    admin: dict = Depends(require_permission("manage_queue"))
):
    """Trigger sync for a single folder."""
    from app.file_sync import sync_folder
    
    result = sync_folder(folder_id)
    return JSONResponse({"success": True, "files_found": result.get("files_found", 0)})


@router.post("/admin/file-sync/sync-all")
async def sync_all_folders(
    admin: dict = Depends(require_permission("manage_queue"))
):
    """Trigger sync for all enabled folders."""
    from app.file_sync import run_full_sync
    
    result = run_full_sync()
    return JSONResponse({"success": True, **result})


@router.post("/admin/file-sync/process-matches")
async def process_all_matches(
    admin: dict = Depends(require_permission("manage_queue"))
):
    """Process all pending file matches."""
    from app.file_sync import get_active_sync_configs, process_pending_matches
    
    # Process all active configs
    total_processed = 0
    configs = get_active_sync_configs()
    for config in configs:
        result = process_pending_matches(config)
        total_processed += result.get("processed", 0)
    
    return JSONResponse({"success": True, "processed": total_processed})


@router.post("/admin/file-sync/matches/{match_id}/approve")
async def approve_match(
    match_id: str,
    admin: dict = Depends(require_permission("manage_queue"))
):
    """Approve a pending file match."""
    from app.file_sync import approve_file_match
    
    approve_file_match(match_id)
    
    log_audit(
        action=AuditAction.SETTINGS_UPDATED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        details={"action": "approve_file_match", "match_id": match_id}
    )
    
    return JSONResponse({"success": True})


@router.post("/admin/file-sync/matches/{match_id}/reject")
async def reject_match(
    match_id: str,
    admin: dict = Depends(require_permission("manage_queue"))
):
    """Reject a pending file match."""
    from app.file_sync import reject_file_match
    
    reject_file_match(match_id)
    return JSONResponse({"success": True})


# ─────────────────────────── API ENDPOINTS ───────────────────────────

@router.get("/api/user/me")
async def api_current_user(request: Request):
    """Get current logged-in user."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"user": None})
    
    return JSONResponse({"user": user.to_dict()})


@router.get("/api/features")
async def api_feature_flags(request: Request):
    """Get all feature flags (public endpoint)."""
    user = await get_current_user(request)
    flags = get_all_feature_flags()
    
    # Return only enabled status for public
    result = {}
    for key, flag in flags.items():
        user_id = user.id if user else None
        email = user.email if user else None
        result[key] = flag.is_enabled_for_user(user_id, email)
    
    return JSONResponse(result)


# ─────────────────────────── USER MANAGEMENT ROUTES ───────────────────────────

@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    page: int = Query(1, ge=1),
    status: str = Query(None),
    search: str = Query(None),
    success: str = Query(None),
    error: str = Query(None),
    admin: dict = Depends(require_permission("manage_users"))
):
    """User management admin page."""
    per_page = 25
    offset = (page - 1) * per_page
    
    users = get_all_users(limit=per_page, offset=offset, status=status, search=search)
    total_count = get_user_count(status=status, search=search)
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get all statuses for filter dropdown
    all_statuses = [s.value for s in UserStatus]
    
    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "users": [u.to_dict() for u in users],
        "total_count": total_count,
        "page": page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "status_filter": status,
        "search": search,
        "all_statuses": all_statuses,
        "success": success,
        "error": error,
    })


@router.post("/admin/users/create")
async def admin_create_user(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(None),
    status: str = Form("active"),
    admin: dict = Depends(require_permission("manage_users"))
):
    """Create a new user account (admin)."""
    try:
        # Check if user exists
        existing = get_user_by_email(email)
        if existing:
            return RedirectResponse(
                url=f"/admin/users?error=User with email {email} already exists",
                status_code=303
            )
        
        # Create user
        user = create_user(email=email, name=name, password=password)
        
        # Set status if not default
        if status != "unverified":
            set_user_status(user.id, UserStatus(status))
        
        # Audit log
        log_audit(
            action=AuditAction.USER_REGISTERED,
            actor_type="admin",
            actor_id=getattr(admin, 'id', None),
            target_type="user",
            target_id=user.id,
            details={"email": email, "created_by_admin": True}
        )
        
        return RedirectResponse(
            url="/admin/users?success=User created successfully",
            status_code=303
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/users?error={str(e)}",
            status_code=303
        )


@router.post("/admin/users/update")
async def admin_update_user(
    request: Request,
    user_id: str = Form(...),
    name: str = Form(None),
    email: str = Form(None),
    status: str = Form(None),
    credits: int = Form(None),
    admin: dict = Depends(require_permission("manage_users"))
):
    """Update a user account (admin)."""
    try:
        updates = {}
        if name:
            updates["name"] = name
        if email:
            updates["email"] = email
        if status:
            updates["status"] = UserStatus(status)
        if credits is not None:
            updates["credits"] = credits
        
        if updates:
            update_user(user_id, **updates)
        
        # Audit log
        log_audit(
            action=AuditAction.USER_UPDATED,
            actor_type="admin",
            actor_id=getattr(admin, 'id', None),
            target_type="user",
            target_id=user_id,
            details=updates
        )
        
        return RedirectResponse(
            url="/admin/users?success=User updated",
            status_code=303
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/users?error={str(e)}",
            status_code=303
        )


@router.post("/admin/users/{user_id}/suspend")
async def admin_suspend_user(
    user_id: str,
    admin: dict = Depends(require_permission("manage_users"))
):
    """Suspend a user account."""
    set_user_status(user_id, UserStatus.SUSPENDED)
    
    log_audit(
        action=AuditAction.USER_SUSPENDED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="user",
        target_id=user_id
    )
    
    return JSONResponse({"success": True})


@router.post("/admin/users/{user_id}/activate")
async def admin_activate_user(
    user_id: str,
    admin: dict = Depends(require_permission("manage_users"))
):
    """Reactivate a suspended user account."""
    set_user_status(user_id, UserStatus.ACTIVE)
    
    log_audit(
        action=AuditAction.USER_REACTIVATED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="user",
        target_id=user_id
    )
    
    return JSONResponse({"success": True})


@router.delete("/admin/users/{user_id}")
async def admin_delete_user(
    user_id: str,
    admin: dict = Depends(require_permission("manage_users"))
):
    """Delete a user account."""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    delete_user(user_id)
    
    log_audit(
        action=AuditAction.ADMIN_DELETED,  # Using admin deleted for now
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="user",
        target_id=user_id,
        details={"email": user.email}
    )
    
    return JSONResponse({"success": True})


@router.post("/admin/users/{user_id}/convert-to-admin")
async def admin_convert_user_to_admin(
    request: Request,
    user_id: str,
    role: str = Form("operator"),
    password: str = Form(None),
    admin: dict = Depends(require_permission("manage_admins"))
):
    """Convert a user to an admin account."""
    from app.auth import convert_user_to_admin
    
    try:
        admin_role = AdminRole(role)
    except ValueError:
        admin_role = AdminRole.OPERATOR
    
    new_admin = convert_user_to_admin(user_id, role=admin_role, password=password)
    
    if not new_admin:
        return RedirectResponse(
            url="/admin/users?error=Failed to convert user",
            status_code=303
        )
    
    log_audit(
        action=AuditAction.ADMIN_CREATED,
        actor_type="admin",
        actor_id=getattr(admin, 'id', None),
        target_type="admin",
        target_id=new_admin.id,
        details={"converted_from_user": user_id, "role": role}
    )
    
    return RedirectResponse(
        url=f"/admin/users?success=User converted to admin ({new_admin.username})",
        status_code=303
    )


# ─────────────────────────── ACCOUNT MIGRATION API ───────────────────────────

@router.get("/api/user/check-migration")
async def check_migration_status(request: Request, token: str = Query(None), email: str = Query(None)):
    """
    Check if a token-based user should be prompted to create an account.
    Used by My Prints page to show signup modal.
    """
    if not is_feature_enabled("user_accounts"):
        return JSONResponse({"should_prompt": False, "reason": "feature_disabled"})
    
    # If they have a user session cookie, they already have an account
    user = await get_current_user(request)
    if user:
        return JSONResponse({"should_prompt": False, "reason": "already_logged_in", "user": user.to_dict()})
    
    # If they have a token but no account, prompt them
    if token or email:
        # Check if there's an existing user with this email
        if email:
            existing = get_user_by_email(email)
            if existing:
                return JSONResponse({
                    "should_prompt": True, 
                    "reason": "has_account_not_logged_in",
                    "email": email
                })
        
        # They have a token but no account - prompt to create one
        return JSONResponse({
            "should_prompt": True,
            "reason": "token_user_no_account",
            "email": email
        })
    
    return JSONResponse({"should_prompt": False, "reason": "no_token"})


@router.post("/api/user/migrate-token")
async def migrate_token_to_account(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(None),
    token: str = Form(None)
):
    """
    Create an account from an existing email lookup token.
    Links their request history to the new account.
    """
    if not is_feature_enabled("user_accounts"):
        raise HTTPException(status_code=403, detail="User accounts are not enabled")
    
    # Check if user already exists
    existing = get_user_by_email(email)
    if existing:
        # Log them in instead
        session_token = create_user_session(
            existing.id,
            device_info=request.headers.get("User-Agent") or "unknown",
            ip_address=get_client_ip(request)
        )
        
        return JSONResponse({
            "success": True,
            "action": "logged_in",
            "session_token": session_token
        })
    
    # Create new user
    user = create_user(email=email, name=name, password=password)
    
    # Mark email as verified since they had a valid token
    set_user_status(user.id, UserStatus.ACTIVE)
    
    # Create session
    session_token = create_user_session(
        user.id,
        device_info=request.headers.get("User-Agent") or "unknown",
        ip_address=get_client_ip(request)
    )
    
    log_audit(
        action=AuditAction.USER_REGISTERED,
        actor_type="user",
        actor_id=user.id,
        details={"migrated_from_token": True, "email": email}
    )
    
    return JSONResponse({
        "success": True,
        "action": "created",
        "session_token": session_token,
        "user": user.to_dict()
    })


# ─────────────────────────── USER API ENDPOINTS (JSON) ───────────────────────────

@router.post("/api/user/login")
async def api_user_login(request: Request):
    """
    JSON API for user login.
    Accepts: { email, password }
    Returns: { success, session_token?, error? }
    """
    if not is_feature_enabled("user_accounts"):
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "User accounts are not enabled"}
        )
    
    try:
        data = await request.json()
    except:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Invalid JSON"}
        )
    
    email = data.get("email", "").strip()
    password = data.get("password", "")
    
    if not email:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Email is required"}
        )
    
    if not password:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Password is required"}
        )
    
    user = authenticate_user(email, password)
    
    if not user:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": "Invalid email or password"}
        )
    
    if user.status == UserStatus.SUSPENDED:
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "Your account has been suspended"}
        )
    
    # Create session
    session_token = create_user_session(
        user.id,
        device_info=request.headers.get("User-Agent") or "unknown",
        ip_address=get_client_ip(request)
    )
    
    response = JSONResponse({
        "success": True,
        "session_token": session_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name
        }
    })
    
    # Also set the cookie for web clients
    response.set_cookie(
        "user_session",
        session_token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("BASE_URL", "").startswith("https"),
        path="/",
        max_age=30 * 24 * 60 * 60
    )
    
    return response


@router.post("/api/user/register")
async def api_user_register(request: Request):
    """
    JSON API for user registration.
    Accepts: { email, name?, password? }
    Returns: { success, session_token?, error? }
    """
    if not is_feature_enabled("user_accounts"):
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "User accounts are not enabled"}
        )
    
    try:
        data = await request.json()
    except:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Invalid JSON"}
        )
    
    email = data.get("email", "").strip().lower()
    name = data.get("name", "").strip()
    password = data.get("password")
    
    if not email:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Email is required"}
        )
    
    # Check if user already exists
    existing = get_user_by_email(email)
    if existing:
        return JSONResponse(
            status_code=409,
            content={"success": False, "error": "An account with this email already exists"}
        )
    
    # Create user
    try:
        user = create_user(email=email, name=name or None, password=password or None)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Failed to create account: {str(e)}"}
        )
    
    # If password provided, auto-verify and create session
    if password:
        set_user_status(user.id, UserStatus.ACTIVE)
        
        session_token = create_user_session(
            user.id,
            device_info=request.headers.get("User-Agent") or "unknown",
            ip_address=get_client_ip(request)
        )
        
        log_audit(
            action=AuditAction.USER_REGISTERED,
            actor_type="user",
            actor_id=user.id,
            details={"email": email, "with_password": True}
        )
        
        response = JSONResponse({
            "success": True,
            "session_token": session_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name
            }
        })
        
        response.set_cookie(
            "user_session",
            session_token,
            httponly=True,
            samesite="lax",
            secure=os.getenv("BASE_URL", "").startswith("https"),
            path="/",
            max_age=30 * 24 * 60 * 60
        )
        
        return response
    else:
        # No password - would need magic link (not implemented in API yet)
        log_audit(
            action=AuditAction.USER_REGISTERED,
            actor_type="user",
            actor_id=user.id,
            details={"email": email, "with_password": False}
        )
        
        return JSONResponse({
            "success": True,
            "message": "Account created. Please check your email for verification.",
            "requires_verification": True
        })


# ─────────────────────────── USER PROFILE ROUTES ───────────────────────────

@router.get("/user/profile", response_class=HTMLResponse)
async def user_profile_page(
    request: Request,
    token: str = Query(None),
    success: str = Query(None),
    error: str = Query(None)
):
    """User profile and settings page."""
    if not is_feature_enabled("user_accounts"):
        return RedirectResponse(url="/my-requests", status_code=303)
    
    # Get user from token or session
    user = None
    if token:
        # Look up user by email lookup token
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/my-requests?error=not_logged_in", status_code=303)
    
    # Get printers and materials for preferences
    conn = db()
    printers = conn.execute("SELECT name FROM printers WHERE is_active = 1 ORDER BY name").fetchall()
    conn.close()
    
    materials = ["PLA", "PETG", "ABS", "TPU", "ASA", "Nylon", "Resin", "Other"]
    
    return templates.TemplateResponse("user_profile.html", {
        "request": request,
        "user": user,
        "token": token,
        "printers": printers,
        "materials": materials,
        "success": success,
        "error": error,
    })


@router.post("/user/profile")
async def update_user_profile_route(
    request: Request,
    token: str = Form(None),
    name: str = Form(None),
    phone: str = Form(None)
):
    """Update user profile information."""
    # Get user
    user = None
    if token:
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/my-requests?error=not_logged_in", status_code=303)
    
    # Update profile
    update_user_profile(user.id, name=name, phone=phone)
    
    # Redirect back with appropriate params
    redirect_params = "success=Profile updated"
    if token:
        redirect_params = f"token={token}&{redirect_params}"
    
    return RedirectResponse(
        url=f"/user/profile?{redirect_params}",
        status_code=303
    )


@router.post("/user/preferences")
async def update_user_preferences(
    request: Request,
    token: str = Form(None),
    preferred_printer: str = Form(None),
    preferred_material: str = Form(None),
    preferred_colors: str = Form(None),
    notes_template: str = Form(None)
):
    """Update user print preferences."""
    user = None
    if token:
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/my-requests?error=not_logged_in", status_code=303)
    
    update_user_profile(
        user.id,
        preferred_printer=preferred_printer,
        preferred_material=preferred_material,
        preferred_colors=preferred_colors,
        notes_template=notes_template
    )
    
    redirect_params = "success=Preferences saved"
    if token:
        redirect_params = f"token={token}&{redirect_params}"
    
    return RedirectResponse(
        url=f"/user/profile?{redirect_params}",
        status_code=303
    )


@router.post("/user/notifications")
async def update_user_notifications(
    request: Request,
    token: str = Form(None),
    email_status_updates: str = Form(None),
    email_print_ready: str = Form(None),
    push_enabled: str = Form(None),
    push_progress: str = Form(None)
):
    """Update user notification preferences."""
    user = None
    if token:
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/my-requests?error=not_logged_in", status_code=303)
    
    notification_prefs = {
        "email_status_updates": email_status_updates == "1",
        "email_print_ready": email_print_ready == "1",
        "push_enabled": push_enabled == "1",
        "push_progress": push_progress == "1",
    }
    
    update_user_profile(user.id, notification_prefs=notification_prefs)
    
    redirect_params = "success=Notification settings saved"
    if token:
        redirect_params = f"token={token}&{redirect_params}"
    
    return RedirectResponse(
        url=f"/user/profile?{redirect_params}",
        status_code=303
    )


@router.post("/user/password")
async def update_user_password(
    request: Request,
    token: str = Form(None),
    current_password: str = Form(None),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Set or change user password."""
    user = None
    if token:
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/my-requests?error=not_logged_in", status_code=303)
    
    # Validate passwords match
    if new_password != confirm_password:
        redirect_params = "error=Passwords don't match"
        if token:
            redirect_params = f"token={token}&{redirect_params}"
        return RedirectResponse(
            url=f"/user/profile?{redirect_params}",
            status_code=303
        )
    
    # If user has existing password, verify current password
    if user.password_hash and current_password:
        if not verify_password(current_password, user.password_hash):
            redirect_params = "error=Current password is incorrect"
            if token:
                redirect_params = f"token={token}&{redirect_params}"
            return RedirectResponse(
                url=f"/user/profile?{redirect_params}",
                status_code=303
            )
    
    # Hash and save new password
    password_hash = hash_password(new_password)
    conn = db()
    conn.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", 
                 (password_hash, datetime.utcnow().isoformat(timespec="seconds") + "Z", user.id))
    conn.commit()
    conn.close()
    
    redirect_params = "success=Password updated successfully"
    if token:
        redirect_params = f"token={token}&{redirect_params}"
    
    return RedirectResponse(
        url=f"/user/profile?{redirect_params}",
        status_code=303
    )


@router.post("/user/delete")
async def delete_user_account(
    request: Request,
    token: str = Form(None)
):
    """Delete user account (GDPR compliance)."""
    user = None
    if token:
        conn = db()
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN email_lookup_tokens t ON LOWER(u.email) = LOWER(t.email)
            WHERE t.token = ?
        """, (token,)).fetchone()
        conn.close()
        if row:
            user = _row_to_user(row)
    
    if not user:
        user = await get_current_user(request)
    
    if not user:
        return JSONResponse({"success": False, "error": "Not logged in"}, status_code=401)
    
    # Delete user sessions
    conn = db()
    conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user.id,))
    
    # Anonymize requests (keep history but remove PII)
    conn.execute("""
        UPDATE requests SET 
            requester_name = 'Deleted User',
            requester_email = 'deleted@deleted.com',
            requester_phone = NULL
        WHERE requester_email = ?
    """, (user.email,))
    
    # Delete user account
    conn.execute("DELETE FROM users WHERE id = ?", (user.id,))
    conn.commit()
    conn.close()
    
    log_audit(
        action=AuditAction.USER_UPDATED,
        actor_type="user",
        actor_id=user.id,
        details={"action": "account_deleted", "email": user.email}
    )
    
    return JSONResponse({"success": True})
