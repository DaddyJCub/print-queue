"""
Admin routes for unified account management.

Provides:
- Account listing with filters and pagination
- Account detail view with request history
- Account CRUD operations (create, edit, suspend, delete)
- Role management
- Session management (force logout)
- Account notes
"""

import os
import json
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Request, Form, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from app.main import (
    templates,
    db,
    require_admin,
    APP_VERSION,
)
from app.auth import (
    # Account CRUD
    create_account,
    get_account_by_id,
    get_account_by_email,
    get_all_accounts,
    search_accounts,
    update_account,
    # Session management
    delete_all_sessions,
    get_sessions_for_account,
    count_sessions_for_account,
    # Request assignments
    get_account_assignments,
    # Password hashing
    hash_password,
    # Models
)
from app.models import AccountRole, UserStatus, ACCOUNT_ROLE_PERMISSIONS, get_account_permissions

router = APIRouter()


def get_request_counts_for_account(account_id: str) -> dict:
    """Get request statistics for an account."""
    conn = db()
    
    # Count requests by email (legacy) or account_id
    account = get_account_by_id(account_id)
    if not account:
        conn.close()
        return {"total": 0, "pending": 0, "printing": 0, "completed": 0}
    
    email = account.email
    
    # Get counts by status
    rows = conn.execute("""
        SELECT status, COUNT(*) as count FROM requests
        WHERE email = ? OR account_id = ?
        GROUP BY status
    """, (email, account_id)).fetchall()
    conn.close()
    
    status_counts = {row["status"]: row["count"] for row in rows}
    
    return {
        "total": sum(status_counts.values()),
        "pending": status_counts.get("pending", 0),
        "printing": status_counts.get("printing", 0),
        "ready": status_counts.get("ready", 0),
        "completed": status_counts.get("completed", 0),
        "cancelled": status_counts.get("cancelled", 0),
    }


def get_requests_for_account(account_id: str, limit: int = 50) -> list:
    """Get recent requests for an account."""
    account = get_account_by_id(account_id)
    if not account:
        return []
    
    conn = db()
    rows = conn.execute("""
        SELECT id, email, name, file_name, status, created_at, 
               (SELECT COUNT(*) FROM request_files WHERE request_id = requests.id) as file_count
        FROM requests
        WHERE email = ? OR account_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (account.email, account_id, limit)).fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_account_notes(account_id: str) -> list:
    """Get notes for an account."""
    conn = db()
    rows = conn.execute("""
        SELECT n.*, a.name as created_by_name
        FROM account_notes n
        LEFT JOIN accounts a ON n.created_by = a.id
        WHERE n.account_id = ?
        ORDER BY n.created_at DESC
    """, (account_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_account_note(account_id: str, content: str, created_by: Optional[str] = None):
    """Add a note to an account."""
    import uuid
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    note_id = str(uuid.uuid4())
    
    conn.execute("""
        INSERT INTO account_notes (id, account_id, content, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (note_id, account_id, content, created_by, now))
    conn.commit()
    conn.close()
    return note_id


def delete_account_note(note_id: str):
    """Delete an account note."""
    conn = db()
    conn.execute("DELETE FROM account_notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()


def get_role_counts() -> dict:
    """Get count of accounts per role."""
    conn = db()
    rows = conn.execute("""
        SELECT role, COUNT(*) as count FROM accounts GROUP BY role
    """).fetchall()
    conn.close()
    return {row["role"]: row["count"] for row in rows}


def get_account_count(
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
) -> int:
    """Get total count of accounts with filters."""
    conn = db()
    
    query = "SELECT COUNT(*) as count FROM accounts WHERE 1=1"
    params = []
    
    if role:
        query += " AND role = ?"
        params.append(role)
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    if search:
        query += " AND (LOWER(email) LIKE ? OR LOWER(name) LIKE ?)"
        term = f"%{search.lower()}%"
        params.extend([term, term])
    
    result = conn.execute(query, params).fetchone()
    conn.close()
    return result["count"] if result else 0


def get_accounts_paginated(
    page: int = 1,
    per_page: int = 20,
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
) -> list:
    """Get accounts with pagination and filters."""
    conn = db()
    
    query = """
        SELECT a.*, 
               (SELECT COUNT(*) FROM requests WHERE email = a.email OR account_id = a.id) as total_requests
        FROM accounts a
        WHERE 1=1
    """
    params = []
    
    if role:
        query += " AND a.role = ?"
        params.append(role)
    
    if status:
        query += " AND a.status = ?"
        params.append(status)
    
    if search:
        query += " AND (LOWER(a.email) LIKE ? OR LOWER(a.name) LIKE ?)"
        term = f"%{search.lower()}%"
        params.extend([term, term])
    
    query += " ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


# ─────────────────────────── ACCOUNT LIST PAGE ───────────────────────────

@router.get("/admin/accounts", response_class=HTMLResponse)
def admin_accounts_list(
    request: Request,
    page: int = Query(1, ge=1),
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    success: Optional[str] = None,
    error: Optional[str] = None,
    _=Depends(require_admin)
):
    """Admin account listing page."""
    per_page = 20
    
    # Validate filters
    valid_roles = ["owner", "admin", "staff", "user"]
    valid_statuses = ["active", "suspended", "unverified"]
    
    if role and role not in valid_roles:
        role = None
    if status and status not in valid_statuses:
        status = None
    
    # Get paginated accounts
    accounts = get_accounts_paginated(page, per_page, role, status, search)
    total_count = get_account_count(role, status, search)
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    
    # Get role counts for stats
    role_counts = get_role_counts()
    
    return templates.TemplateResponse("admin_accounts.html", {
        "request": request,
        "accounts": accounts,
        "page": page,
        "total_pages": total_pages,
        "total_count": total_count,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "role_filter": role,
        "status_filter": status,
        "search": search,
        "all_roles": valid_roles,
        "all_statuses": valid_statuses,
        "role_counts": role_counts,
        "success": success,
        "error": error,
        "version": APP_VERSION,
    })


# ─────────────────────────── ACCOUNT DETAIL PAGE ───────────────────────────

@router.get("/admin/accounts/{account_id}", response_class=HTMLResponse)
def admin_account_detail(
    request: Request,
    account_id: str,
    tab: str = "requests",
    success: Optional[str] = None,
    error: Optional[str] = None,
    _=Depends(require_admin)
):
    """Admin account detail page."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Get request stats and list
    request_stats = get_request_counts_for_account(account_id)
    requests_list = get_requests_for_account(account_id)
    
    # Get assignments
    try:
        assignments = get_account_assignments(account_id)
    except:
        assignments = []
    
    # Get sessions
    try:
        session_count = count_sessions_for_account(account_id)
    except:
        session_count = 0
    
    # Get notes
    notes = get_account_notes(account_id)
    
    # Get permissions for this role
    role = AccountRole(account.role) if isinstance(account.role, str) else account.role
    permissions = get_account_permissions(role)
    
    return templates.TemplateResponse("admin_account_detail.html", {
        "request": request,
        "account": account,
        "request_stats": request_stats,
        "requests": requests_list,
        "assignments": assignments,
        "session_count": session_count,
        "notes": notes,
        "permissions": permissions,
        "active_tab": tab,
        "success": success,
        "error": error,
        "version": APP_VERSION,
    })


# ─────────────────────────── ACCOUNT ACTIONS ───────────────────────────

@router.post("/admin/accounts/create")
def admin_account_create(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    password: Optional[str] = Form(None),
    role: str = Form("user"),
    status: str = Form("active"),
    _=Depends(require_admin)
):
    """Create a new account."""
    # Validate role
    if role not in ["owner", "admin", "staff", "user"]:
        return RedirectResponse(
            url="/admin/accounts?error=Invalid+role",
            status_code=303
        )
    
    # Check if email already exists
    existing = get_account_by_email(email)
    if existing:
        return RedirectResponse(
            url="/admin/accounts?error=Email+already+exists",
            status_code=303
        )
    
    try:
        account_role = AccountRole(role)
        account_status = UserStatus(status) if status in ["active", "suspended", "unverified"] else UserStatus.ACTIVE
        
        account = create_account(
            email=email,
            name=name,
            password=password if password else None,
            role=account_role,
            status=account_status
        )
        
        return RedirectResponse(
            url=f"/admin/accounts/{account.id}?success=Account+created+successfully",
            status_code=303
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/accounts?error={str(e)}",
            status_code=303
        )


@router.post("/admin/accounts/{account_id}/edit")
def admin_account_edit(
    request: Request,
    account_id: str,
    name: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """Edit account details."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    updates = {}
    if name is not None:
        updates["name"] = name
    if email is not None and email != account.email:
        # Check if new email is already in use
        existing = get_account_by_email(email)
        if existing and existing.id != account_id:
            return RedirectResponse(
                url=f"/admin/accounts/{account_id}?error=Email+already+in+use",
                status_code=303
            )
        updates["email"] = email
    if phone is not None:
        updates["phone"] = phone
    if role is not None and role in ["owner", "admin", "staff", "user"]:
        updates["role"] = role
    
    if updates:
        update_account(account_id, **updates)
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?success=Account+updated",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/role")
def admin_account_change_role(
    request: Request,
    account_id: str,
    role: str = Form(...),
    _=Depends(require_admin)
):
    """Change account role."""
    if role not in ["owner", "admin", "staff", "user"]:
        return RedirectResponse(
            url=f"/admin/accounts?error=Invalid+role",
            status_code=303
        )
    
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    update_account(account_id, role=role)
    
    return RedirectResponse(
        url=f"/admin/accounts?success=Role+updated+for+{account.name or account.email}",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/suspend")
def admin_account_suspend(
    request: Request,
    account_id: str,
    _=Depends(require_admin)
):
    """Suspend an account."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    update_account(account_id, status="suspended")
    
    # Force logout all sessions
    try:
        delete_all_sessions(account_id)
    except:
        pass
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?success=Account+suspended",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/activate")
def admin_account_activate(
    request: Request,
    account_id: str,
    _=Depends(require_admin)
):
    """Activate a suspended account."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    update_account(account_id, status="active")
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?success=Account+activated",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/reset-password")
def admin_account_reset_password(
    request: Request,
    account_id: str,
    password: str = Form(...),
    _=Depends(require_admin)
):
    """Reset account password."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    if len(password) < 8:
        return RedirectResponse(
            url=f"/admin/accounts/{account_id}?error=Password+must+be+at+least+8+characters",
            status_code=303
        )
    
    new_hash = hash_password(password)
    update_account(account_id, password_hash=new_hash)
    
    # Force logout all sessions
    try:
        delete_all_sessions(account_id)
    except:
        pass
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?success=Password+reset+successfully",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/logout-all")
def admin_account_logout_all(
    request: Request,
    account_id: str,
    _=Depends(require_admin)
):
    """Force logout all sessions for an account."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    try:
        delete_all_sessions(account_id)
    except Exception as e:
        return RedirectResponse(
            url=f"/admin/accounts/{account_id}?error=Failed+to+terminate+sessions",
            status_code=303
        )
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?success=All+sessions+terminated",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/delete")
def admin_account_delete(
    request: Request,
    account_id: str,
    confirm_email: str = Form(...),
    _=Depends(require_admin)
):
    """Delete an account."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    if confirm_email != account.email:
        return RedirectResponse(
            url=f"/admin/accounts/{account_id}?tab=info&error=Email+confirmation+did+not+match",
            status_code=303
        )
    
    conn = db()
    
    # Delete related data
    conn.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM request_assignments WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM account_notes WHERE account_id = ?", (account_id,))
    
    # Unlink requests (preserve them)
    conn.execute("UPDATE requests SET account_id = NULL WHERE account_id = ?", (account_id,))
    
    # Delete account
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(
        url="/admin/accounts?success=Account+deleted+successfully",
        status_code=303
    )


# ─────────────────────────── ACCOUNT NOTES ───────────────────────────

@router.post("/admin/accounts/{account_id}/notes")
def admin_account_add_note(
    request: Request,
    account_id: str,
    content: str = Form(...),
    _=Depends(require_admin)
):
    """Add a note to an account."""
    account = get_account_by_id(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Get current admin ID from session (if using unified accounts)
    admin_id = None  # TODO: Get from current session
    
    add_account_note(account_id, content, admin_id)
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?tab=notes&success=Note+added",
        status_code=303
    )


@router.post("/admin/accounts/{account_id}/notes/{note_id}/delete")
def admin_account_delete_note(
    request: Request,
    account_id: str,
    note_id: str,
    _=Depends(require_admin)
):
    """Delete an account note."""
    delete_account_note(note_id)
    
    return RedirectResponse(
        url=f"/admin/accounts/{account_id}?tab=notes&success=Note+deleted",
        status_code=303
    )
