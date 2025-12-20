"""
Authentication and authorization services for Printellect.

Provides:
- User authentication (password + magic link)
- Admin authentication (password + session tokens)
- Role-based access control (RBAC)
- Audit logging
- Feature flag checking
"""

import os
import uuid
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from functools import wraps
import json
import logging

from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse

from app.models import (
    User, Admin, AdminRole, UserStatus, AuditAction, AuditLog, FeatureFlag,
    ROLE_PERMISSIONS, has_permission, DEFAULT_FEATURE_FLAGS,
    ALL_NEW_TABLES, INDEXES
)

logger = logging.getLogger("printellect.auth")

# ─────────────────────────── DATABASE HELPERS ───────────────────────────

def get_db_path():
    """Get database path from environment."""
    return os.getenv("DB_PATH", "/data/app.db")


def db():
    """Get database connection."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_tables():
    """Initialize authentication-related tables."""
    conn = db()
    cur = conn.cursor()
    
    for table_sql in ALL_NEW_TABLES:
        cur.execute(table_sql)
    
    for index_sql in INDEXES:
        try:
            cur.execute(index_sql)
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")
    
    conn.commit()
    conn.close()
    logger.info("Auth tables initialized")


def init_feature_flags():
    """Initialize default feature flags if they don't exist."""
    conn = db()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    for key, flag in DEFAULT_FEATURE_FLAGS.items():
        existing = cur.execute("SELECT key FROM feature_flags WHERE key = ?", (key,)).fetchone()
        if not existing:
            cur.execute("""
                INSERT INTO feature_flags (key, enabled, description, rollout_percentage, 
                                          allowed_users, allowed_emails, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key,
                1 if flag.enabled else 0,
                flag.description,
                flag.rollout_percentage,
                json.dumps(flag.allowed_users),
                json.dumps(flag.allowed_emails),
                now,
                now
            ))
    
    conn.commit()
    conn.close()
    logger.info("Feature flags initialized")


# ─────────────────────────── PASSWORD HASHING ───────────────────────────

def hash_password(password: str) -> str:
    """Hash a password using SHA256 with salt."""
    salt = secrets.token_hex(16)
    hash_val = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{hash_val}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    if not password_hash or ":" not in password_hash:
        return False
    salt, stored_hash = password_hash.split(":", 1)
    computed_hash = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return secrets.compare_digest(computed_hash, stored_hash)


def generate_session_token() -> str:
    """Generate a secure session token."""
    return secrets.token_urlsafe(32)


def generate_magic_link_token() -> str:
    """Generate a magic link token."""
    return secrets.token_urlsafe(48)


# ─────────────────────────── USER AUTHENTICATION ───────────────────────────

def create_user(email: str, name: str, password: Optional[str] = None) -> User:
    """Create a new user account."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    user_id = str(uuid.uuid4())
    
    password_hash = hash_password(password) if password else None
    
    conn.execute("""
        INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, email.lower(), name, password_hash, UserStatus.UNVERIFIED.value, now, now))
    conn.commit()
    conn.close()
    
    logger.info(f"User created: {email}")
    return get_user_by_id(user_id)


def get_user_by_id(user_id: str) -> Optional[User]:
    """Get user by ID."""
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_user(row)


def get_user_by_email(email: str) -> Optional[User]:
    """Get user by email (case-insensitive)."""
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_user(row)


def _row_to_user(row: sqlite3.Row) -> User:
    """Convert database row to User object."""
    notification_prefs = {}
    if row["notification_prefs"]:
        try:
            notification_prefs = json.loads(row["notification_prefs"])
        except:
            pass
    
    return User(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        phone=row["phone"],
        password_hash=row["password_hash"],
        status=UserStatus(row["status"]) if row["status"] else UserStatus.UNVERIFIED,
        email_verified=bool(row["email_verified"]),
        email_verified_at=row["email_verified_at"],
        preferred_printer=row["preferred_printer"],
        preferred_material=row["preferred_material"],
        preferred_colors=row["preferred_colors"],
        notes_template=row["notes_template"],
        notification_prefs=notification_prefs,
        total_requests=row["total_requests"] or 0,
        total_prints=row["total_prints"] or 0,
        credits=row["credits"] or 0,
        magic_link_token=row["magic_link_token"],
        magic_link_expires=row["magic_link_expires"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_login=row["last_login"],
    )


def authenticate_user(email: str, password: str) -> Optional[User]:
    """Authenticate user with email and password."""
    user = get_user_by_email(email)
    if not user:
        return None
    
    if not user.password_hash:
        return None  # User uses magic link only
    
    if not verify_password(password, user.password_hash):
        return None
    
    if user.status == UserStatus.SUSPENDED:
        return None
    
    # Update last login
    _update_user_last_login(user.id)
    
    return user


def create_magic_link(email: str) -> Optional[str]:
    """Create a magic link token for passwordless login."""
    user = get_user_by_email(email)
    if not user:
        return None
    
    token = generate_magic_link_token()
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat(timespec="seconds") + "Z"
    
    conn = db()
    conn.execute("""
        UPDATE users SET magic_link_token = ?, magic_link_expires = ?, updated_at = ?
        WHERE id = ?
    """, (token, expires, datetime.utcnow().isoformat(timespec="seconds") + "Z", user.id))
    conn.commit()
    conn.close()
    
    return token


def verify_magic_link(token: str) -> Optional[User]:
    """Verify magic link token and return user."""
    conn = db()
    row = conn.execute("""
        SELECT * FROM users WHERE magic_link_token = ? AND magic_link_expires > ?
    """, (token, datetime.utcnow().isoformat())).fetchone()
    conn.close()
    
    if not row:
        return None
    
    user = _row_to_user(row)
    
    # Clear the token and mark email as verified
    _clear_magic_link(user.id)
    if not user.email_verified:
        _verify_user_email(user.id)
    _update_user_last_login(user.id)
    
    return user


def _update_user_last_login(user_id: str):
    """Update user's last login timestamp."""
    conn = db()
    conn.execute("""
        UPDATE users SET last_login = ? WHERE id = ?
    """, (datetime.utcnow().isoformat(timespec="seconds") + "Z", user_id))
    conn.commit()
    conn.close()


def _clear_magic_link(user_id: str):
    """Clear magic link token after use."""
    conn = db()
    conn.execute("""
        UPDATE users SET magic_link_token = NULL, magic_link_expires = NULL WHERE id = ?
    """, (user_id,))
    conn.commit()
    conn.close()


def _verify_user_email(user_id: str):
    """Mark user's email as verified."""
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = db()
    conn.execute("""
        UPDATE users SET email_verified = 1, email_verified_at = ?, status = ? WHERE id = ?
    """, (now, UserStatus.ACTIVE.value, user_id))
    conn.commit()
    conn.close()


def update_user_profile(user_id: str, **kwargs) -> bool:
    """Update user profile fields."""
    allowed_fields = {
        "name", "phone", "preferred_printer", "preferred_material",
        "preferred_colors", "notes_template", "notification_prefs"
    }
    
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not updates:
        return False
    
    # Serialize notification_prefs if present
    if "notification_prefs" in updates and isinstance(updates["notification_prefs"], dict):
        updates["notification_prefs"] = json.dumps(updates["notification_prefs"])
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    values.append(datetime.utcnow().isoformat(timespec="seconds") + "Z")
    values.append(user_id)
    
    conn = db()
    conn.execute(f"UPDATE users SET {set_clause}, updated_at = ? WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def create_user_session(user_id: str, device_info: str = None, ip_address: str = None) -> str:
    """Create a new session for a user."""
    conn = db()
    session_id = str(uuid.uuid4())
    token = generate_session_token()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    expires = (datetime.utcnow() + timedelta(days=30)).isoformat(timespec="seconds") + "Z"
    
    conn.execute("""
        INSERT INTO user_sessions (id, user_id, token, device_info, ip_address, created_at, expires_at, last_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, user_id, token, device_info, ip_address, now, expires, now))
    conn.commit()
    conn.close()
    
    return token


def get_user_by_session(token: str) -> Optional[User]:
    """Get user by session token."""
    conn = db()
    # Use consistent ISO format with Z suffix for comparison
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    row = conn.execute("""
        SELECT u.* FROM users u
        JOIN user_sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, now)).fetchone()
    
    if row:
        # Update last active
        conn.execute("""
            UPDATE user_sessions SET last_active = ? WHERE token = ?
        """, (now, token))
        conn.commit()
    
    conn.close()
    
    if not row:
        return None
    
    return _row_to_user(row)


def delete_user_session(token: str):
    """Delete a user session (logout)."""
    conn = db()
    conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


# ─────────────────────────── USER MANAGEMENT (ADMIN) ───────────────────────────

def get_all_users(limit: int = 100, offset: int = 0, status: str = None, search: str = None) -> List[User]:
    """Get all users with optional filtering."""
    conn = db()
    
    query = "SELECT * FROM users WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    if search:
        query += " AND (LOWER(email) LIKE ? OR LOWER(name) LIKE ?)"
        search_term = f"%{search.lower()}%"
        params.extend([search_term, search_term])
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return [_row_to_user(row) for row in rows]


def get_user_count(status: str = None, search: str = None) -> int:
    """Get total count of users with optional filtering."""
    conn = db()
    
    query = "SELECT COUNT(*) as cnt FROM users WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    if search:
        query += " AND (LOWER(email) LIKE ? OR LOWER(name) LIKE ?)"
        search_term = f"%{search.lower()}%"
        params.extend([search_term, search_term])
    
    result = conn.execute(query, params).fetchone()
    conn.close()
    
    return result['cnt'] if result else 0


def update_user(user_id: str, **kwargs) -> bool:
    """Update any user field (admin-level access)."""
    allowed_fields = {
        "name", "email", "phone", "status", "email_verified",
        "preferred_printer", "preferred_material", "preferred_colors",
        "notes_template", "notification_prefs", "credits", "total_requests", "total_prints"
    }
    
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not updates:
        return False
    
    # Handle status enum
    if "status" in updates and isinstance(updates["status"], UserStatus):
        updates["status"] = updates["status"].value
    
    # Serialize notification_prefs if present
    if "notification_prefs" in updates and isinstance(updates["notification_prefs"], dict):
        updates["notification_prefs"] = json.dumps(updates["notification_prefs"])
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    values.append(datetime.utcnow().isoformat(timespec="seconds") + "Z")
    values.append(user_id)
    
    conn = db()
    conn.execute(f"UPDATE users SET {set_clause}, updated_at = ? WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def set_user_status(user_id: str, status: UserStatus) -> bool:
    """Set user account status (active, suspended, unverified)."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn.execute("""
        UPDATE users SET status = ?, updated_at = ? WHERE id = ?
    """, (status.value, now, user_id))
    conn.commit()
    conn.close()
    
    logger.info(f"User {user_id} status changed to {status.value}")
    return True


def change_user_password(user_id: str, new_password: str) -> bool:
    """Change a user's password."""
    conn = db()
    
    # Hash the new password
    password_hash = hash_password(new_password)
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    conn.execute("""
        UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
    """, (password_hash, now, user_id))
    conn.commit()
    conn.close()
    
    logger.info(f"User {user_id} password changed")
    return True


def update_user_profile(user_id: str, name: str = None, email: str = None) -> bool:
    """Update a user's profile information."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    updates = ["updated_at = ?"]
    params = [now]
    
    if name:
        updates.append("name = ?")
        params.append(name)
    
    if email:
        # Check if email is already in use by another user
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?", 
            (email.lower(), user_id)
        ).fetchone()
        if existing:
            conn.close()
            return False
        updates.append("email = ?")
        params.append(email.lower())
    
    params.append(user_id)
    
    conn.execute(f"""
        UPDATE users SET {', '.join(updates)} WHERE id = ?
    """, params)
    conn.commit()
    conn.close()
    
    logger.info(f"User {user_id} profile updated")
    return True


def delete_user(user_id: str) -> bool:
    """Delete a user account."""
    conn = db()
    
    # Delete sessions first
    conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    
    # Delete user
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    logger.info(f"User {user_id} deleted")
    return True


def convert_user_to_admin(user_id: str, role: AdminRole = AdminRole.OPERATOR, 
                          username: str = None, password: str = None) -> Optional[Admin]:
    """Convert a user account to an admin account."""
    user = get_user_by_id(user_id)
    if not user:
        return None
    
    # Generate username from email if not provided
    if not username:
        username = user.email.split('@')[0].lower()
        # Ensure uniqueness
        existing = get_admin_by_username(username)
        if existing:
            username = f"{username}_{str(uuid.uuid4())[:4]}"
    
    # Create admin account - use user's existing password hash if they have one and no new password provided
    if password:
        admin = create_admin(
            username=username,
            email=user.email,
            password=password,
            role=role,
            display_name=user.display_name
        )
    elif user.password_hash:
        # Reuse user's existing password hash
        admin = create_admin_with_hash(
            username=username,
            email=user.email,
            password_hash=user.password_hash,
            role=role,
            display_name=user.display_name
        )
    else:
        # No password available, generate random one
        admin = create_admin(
            username=username,
            email=user.email,
            password=secrets.token_urlsafe(16),
            role=role,
            display_name=user.display_name
        )
    
    logger.info(f"User {user.email} converted to admin {username} with role {role.value}")
    return admin


def link_user_to_email_token(email: str, token: str) -> Optional[User]:
    """
    Link an existing email lookup token to a user account.
    Used for migrating token-based users to full accounts.
    """
    user = get_user_by_email(email)
    if user:
        return user  # Already has account
    
    # Check if token matches any requests
    # This is for migration - creating account from existing token
    return None


# ─────────────────────────── ADMIN AUTHENTICATION ───────────────────────────

def create_admin(username: str, email: str, password: str, role: AdminRole = AdminRole.OPERATOR, 
                 display_name: str = None, created_by: str = None) -> Admin:
    """Create a new admin account."""
    password_hash = hash_password(password)
    return create_admin_with_hash(username, email, password_hash, role, display_name, created_by)


def create_admin_with_hash(username: str, email: str, password_hash: str, role: AdminRole = AdminRole.OPERATOR, 
                           display_name: str = None, created_by: str = None) -> Admin:
    """Create a new admin account with an existing password hash."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    admin_id = str(uuid.uuid4())
    
    conn.execute("""
        INSERT INTO admins (id, username, email, password_hash, display_name, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (admin_id, username.lower(), email.lower(), password_hash, display_name or username, role.value, now, now))
    conn.commit()
    conn.close()
    
    # Audit log
    log_audit(
        action=AuditAction.ADMIN_CREATED,
        actor_type="admin" if created_by else "system",
        actor_id=created_by,
        target_type="admin",
        target_id=admin_id,
        details={"username": username, "role": role.value}
    )
    
    logger.info(f"Admin created: {username} ({role.value})")
    return get_admin_by_id(admin_id)


def get_admin_by_id(admin_id: str) -> Optional[Admin]:
    """Get admin by ID."""
    conn = db()
    row = conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_admin(row)


def get_admin_by_username(username: str) -> Optional[Admin]:
    """Get admin by username (case-insensitive)."""
    conn = db()
    row = conn.execute("SELECT * FROM admins WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_admin(row)


def get_admin_by_email(email: str) -> Optional[Admin]:
    """Get admin by email (case-insensitive)."""
    conn = db()
    row = conn.execute("SELECT * FROM admins WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_admin(row)


def get_admin_by_session(token: str) -> Optional[Admin]:
    """Get admin by session token."""
    conn = db()
    row = conn.execute("""
        SELECT * FROM admins WHERE session_token = ? AND session_expires > ? AND is_active = 1
    """, (token, datetime.utcnow().isoformat())).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_admin(row)


def _row_to_admin(row: sqlite3.Row) -> Admin:
    """Convert database row to Admin object."""
    return Admin(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        password_hash=row["password_hash"],
        display_name=row["display_name"],
        role=AdminRole(row["role"]) if row["role"] else AdminRole.OPERATOR,
        is_active=bool(row["is_active"]),
        session_token=row["session_token"],
        session_expires=row["session_expires"],
        totp_secret=row["totp_secret"],
        totp_enabled=bool(row["totp_enabled"]),
        login_count=row["login_count"] or 0,
        last_login=row["last_login"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def authenticate_admin(username: str, password: str, ip_address: str = None) -> Optional[Tuple[Admin, str]]:
    """
    Authenticate admin with username/email and password.
    Returns (Admin, session_token) on success, None on failure.
    """
    # Try username first, then email
    admin = get_admin_by_username(username)
    if not admin:
        admin = get_admin_by_email(username)  # Allow login by email too
    
    if not admin:
        log_audit(
            action=AuditAction.ADMIN_LOGIN_FAILED,
            actor_type="unknown",
            actor_name=username,
            actor_ip=ip_address,
            details={"reason": "user_not_found"}
        )
        return None
    
    if not admin.is_active:
        log_audit(
            action=AuditAction.ADMIN_LOGIN_FAILED,
            actor_type="admin",
            actor_id=admin.id,
            actor_name=username,
            actor_ip=ip_address,
            details={"reason": "account_disabled"}
        )
        return None
    
    if not verify_password(password, admin.password_hash):
        log_audit(
            action=AuditAction.ADMIN_LOGIN_FAILED,
            actor_type="admin",
            actor_id=admin.id,
            actor_name=username,
            actor_ip=ip_address,
            details={"reason": "invalid_password"}
        )
        return None
    
    # Create session
    session_token = generate_session_token()
    session_expires = (datetime.utcnow() + timedelta(days=7)).isoformat(timespec="seconds") + "Z"
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    conn = db()
    conn.execute("""
        UPDATE admins SET session_token = ?, session_expires = ?, last_login = ?, 
                         login_count = login_count + 1, updated_at = ?
        WHERE id = ?
    """, (session_token, session_expires, now, now, admin.id))
    conn.commit()
    conn.close()
    
    # Audit log
    log_audit(
        action=AuditAction.ADMIN_LOGIN,
        actor_type="admin",
        actor_id=admin.id,
        actor_name=admin.username,
        actor_ip=ip_address
    )
    
    logger.info(f"Admin login: {username}")
    admin.session_token = session_token
    return (admin, session_token)


def logout_admin(admin_id: str):
    """Clear admin session (logout)."""
    conn = db()
    conn.execute("""
        UPDATE admins SET session_token = NULL, session_expires = NULL WHERE id = ?
    """, (admin_id,))
    conn.commit()
    conn.close()


def get_all_admins() -> List[Admin]:
    """Get all admin accounts."""
    conn = db()
    rows = conn.execute("SELECT * FROM admins ORDER BY created_at DESC").fetchall()
    conn.close()
    return [_row_to_admin(row) for row in rows]


def update_admin(admin_id: str, **kwargs) -> bool:
    """Update admin account."""
    allowed_fields = {"display_name", "email", "role", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not updates:
        return False
    
    # Convert role enum if present
    if "role" in updates and isinstance(updates["role"], AdminRole):
        updates["role"] = updates["role"].value
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    values.append(datetime.utcnow().isoformat(timespec="seconds") + "Z")
    values.append(admin_id)
    
    conn = db()
    conn.execute(f"UPDATE admins SET {set_clause}, updated_at = ? WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def change_admin_password(admin_id: str, new_password: str) -> bool:
    """Change admin password."""
    password_hash = hash_password(new_password)
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    conn = db()
    conn.execute("""
        UPDATE admins SET password_hash = ?, session_token = NULL, session_expires = NULL, updated_at = ?
        WHERE id = ?
    """, (password_hash, now, admin_id))
    conn.commit()
    conn.close()
    
    return True


def delete_admin(admin_id: str) -> bool:
    """Delete admin account."""
    conn = db()
    conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    conn.commit()
    conn.close()
    return True


# ─────────────────────────── LEGACY ADMIN SUPPORT ───────────────────────────

def check_legacy_admin_password(password: str) -> bool:
    """Check against legacy ADMIN_PASSWORD env var for backwards compatibility."""
    legacy_password = os.getenv("ADMIN_PASSWORD", "")
    if not legacy_password:
        return False
    return secrets.compare_digest(password, legacy_password)


def get_or_create_legacy_admin() -> Optional[Admin]:
    """
    For backwards compatibility: if ADMIN_PASSWORD is set but no admins exist,
    create a default super_admin account.
    """
    legacy_password = os.getenv("ADMIN_PASSWORD", "")
    if not legacy_password:
        return None
    
    # Check if any admins exist
    admins = get_all_admins()
    if admins:
        return None  # Admins exist, use the new system
    
    # Create default admin with the legacy password
    try:
        admin = create_admin(
            username="admin",
            email="admin@localhost",
            password=legacy_password,
            role=AdminRole.SUPER_ADMIN,
            display_name="Administrator"
        )
        logger.info("Created default admin from ADMIN_PASSWORD")
        return admin
    except Exception as e:
        logger.error(f"Failed to create legacy admin: {e}")
        return None


# ─────────────────────────── AUDIT LOGGING ───────────────────────────

def log_audit(
    action: AuditAction,
    actor_type: str,
    actor_id: str = None,
    actor_name: str = None,
    actor_ip: str = None,
    target_type: str = None,
    target_id: str = None,
    details: Dict[str, Any] = None
):
    """Log an auditable action."""
    conn = db()
    log_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    try:
        conn.execute("""
            INSERT INTO audit_log (id, created_at, action, actor_type, actor_id, actor_name, 
                                  actor_ip, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id, now, action.value, actor_type, actor_id, actor_name,
            actor_ip, target_type, target_id, json.dumps(details or {})
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
    finally:
        conn.close()


def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    action: str = None,
    actor_id: str = None,
    target_type: str = None,
    target_id: str = None,
    start_date: str = None,
    end_date: str = None
) -> List[AuditLog]:
    """Query audit logs with filters."""
    conn = db()
    
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    
    if action:
        query += " AND action = ?"
        params.append(action)
    if actor_id:
        query += " AND actor_id = ?"
        params.append(actor_id)
    if target_type:
        query += " AND target_type = ?"
        params.append(target_type)
    if target_id:
        query += " AND target_id = ?"
        params.append(target_id)
    if start_date:
        query += " AND created_at >= ?"
        params.append(start_date)
    if end_date:
        query += " AND created_at <= ?"
        params.append(end_date)
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        details = {}
        if row["details"]:
            try:
                details = json.loads(row["details"])
            except:
                pass
        
        logs.append(AuditLog(
            id=row["id"],
            created_at=row["created_at"],
            action=AuditAction(row["action"]) if row["action"] in [a.value for a in AuditAction] else row["action"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            actor_name=row["actor_name"],
            actor_ip=row["actor_ip"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            details=details
        ))
    
    return logs


# ─────────────────────────── FEATURE FLAGS ───────────────────────────

def get_feature_flag(key: str) -> Optional[FeatureFlag]:
    """Get a feature flag by key."""
    conn = db()
    row = conn.execute("SELECT * FROM feature_flags WHERE key = ?", (key,)).fetchone()
    conn.close()
    
    if not row:
        # Return default if exists
        return DEFAULT_FEATURE_FLAGS.get(key)
    
    return _row_to_feature_flag(row)


def _row_to_feature_flag(row: sqlite3.Row) -> FeatureFlag:
    """Convert database row to FeatureFlag object."""
    allowed_users = []
    allowed_emails = []
    try:
        allowed_users = json.loads(row["allowed_users"] or "[]")
        allowed_emails = json.loads(row["allowed_emails"] or "[]")
    except:
        pass
    
    return FeatureFlag(
        key=row["key"],
        enabled=bool(row["enabled"]),
        description=row["description"] or "",
        rollout_percentage=row["rollout_percentage"] or 100,
        allowed_users=allowed_users,
        allowed_emails=allowed_emails,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        created_by=row["created_by"],
    )


def is_feature_enabled(key: str, user_id: str = None, email: str = None) -> bool:
    """Check if a feature is enabled (optionally for a specific user)."""
    flag = get_feature_flag(key)
    if not flag:
        return False
    return flag.is_enabled_for_user(user_id, email)


def get_all_feature_flags() -> Dict[str, FeatureFlag]:
    """Get all feature flags."""
    conn = db()
    rows = conn.execute("SELECT * FROM feature_flags").fetchall()
    conn.close()
    
    flags = {}
    for row in rows:
        flag = _row_to_feature_flag(row)
        flags[flag.key] = flag
    
    # Add defaults for any missing flags
    for key, default_flag in DEFAULT_FEATURE_FLAGS.items():
        if key not in flags:
            flags[key] = default_flag
    
    return flags


def update_feature_flag(key: str, enabled: bool = None, rollout_percentage: int = None,
                        allowed_users: List[str] = None, allowed_emails: List[str] = None,
                        updated_by: str = None) -> bool:
    """Update a feature flag."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    existing = conn.execute("SELECT key FROM feature_flags WHERE key = ?", (key,)).fetchone()
    
    if existing:
        updates = []
        params = []
        
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        if rollout_percentage is not None:
            updates.append("rollout_percentage = ?")
            params.append(rollout_percentage)
        if allowed_users is not None:
            updates.append("allowed_users = ?")
            params.append(json.dumps(allowed_users))
        if allowed_emails is not None:
            updates.append("allowed_emails = ?")
            params.append(json.dumps(allowed_emails))
        
        updates.append("updated_at = ?")
        params.append(now)
        params.append(key)
        
        conn.execute(f"UPDATE feature_flags SET {', '.join(updates)} WHERE key = ?", params)
    else:
        # Create from default
        default = DEFAULT_FEATURE_FLAGS.get(key)
        if not default:
            conn.close()
            return False
        
        conn.execute("""
            INSERT INTO feature_flags (key, enabled, description, rollout_percentage, 
                                      allowed_users, allowed_emails, created_at, updated_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            key,
            1 if (enabled if enabled is not None else default.enabled) else 0,
            default.description,
            rollout_percentage if rollout_percentage is not None else default.rollout_percentage,
            json.dumps(allowed_users if allowed_users is not None else default.allowed_users),
            json.dumps(allowed_emails if allowed_emails is not None else default.allowed_emails),
            now,
            now,
            updated_by
        ))
    
    conn.commit()
    conn.close()
    
    # Audit log
    log_audit(
        action=AuditAction.FEATURE_FLAG_TOGGLED,
        actor_type="admin",
        actor_id=updated_by,
        target_type="feature_flag",
        target_id=key,
        details={"enabled": enabled, "rollout_percentage": rollout_percentage}
    )
    
    return True


# ─────────────────────────── FASTAPI DEPENDENCIES ───────────────────────────

async def get_current_user(request: Request) -> Optional[User]:
    """Get current logged-in user from session cookie."""
    token = request.cookies.get("user_session")
    if not token:
        return None
    return get_user_by_session(token)


async def get_current_admin(request: Request) -> Optional[Admin]:
    """Get current logged-in admin from session cookie."""
    # Try new session token first
    token = request.cookies.get("admin_session")
    if token:
        admin = get_admin_by_session(token)
        if admin:
            return admin
    
    # Fall back to legacy password cookie
    legacy_pw = request.cookies.get("admin_pw")
    if legacy_pw:
        # Check if it matches legacy env var
        if check_legacy_admin_password(legacy_pw):
            # Return a virtual admin for legacy mode
            return Admin(
                id="legacy",
                username="admin",
                email="admin@localhost",
                password_hash="",
                role=AdminRole.SUPER_ADMIN,
                display_name="Administrator (Legacy)",
                is_active=True,
                created_at="",
                updated_at=""
            )
        
        # Check if it matches any admin's password (for transition period)
        admins = get_all_admins()
        for admin in admins:
            if verify_password(legacy_pw, admin.password_hash):
                return admin
    
    return None


async def require_user(request: Request) -> User:
    """Require authenticated user."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    return user


async def require_admin(request: Request) -> Admin:
    """Require authenticated admin."""
    admin = await get_current_admin(request)
    if not admin:
        raise HTTPException(status_code=401, detail="Admin login required")
    return admin


def require_permission(permission: str):
    """Dependency factory for permission-based access control."""
    async def check_permission(request: Request, admin: Admin = Depends(require_admin)):
        if not admin.has_permission(permission):
            raise HTTPException(
                status_code=403, 
                detail=f"Permission denied. Required: {permission}"
            )
        return admin
    return check_permission


async def optional_user(request: Request) -> Optional[User]:
    """Get current user if logged in, None otherwise."""
    return await get_current_user(request)


# ─────────────────────────── FEATURE FLAG DEPENDENCY ───────────────────────────

def require_feature(feature_key: str):
    """Dependency factory for feature flag checks."""
    async def check_feature(request: Request, user: Optional[User] = Depends(optional_user)):
        user_id = user.id if user else None
        email = user.email if user else None
        
        if not is_feature_enabled(feature_key, user_id, email):
            raise HTTPException(
                status_code=403,
                detail=f"Feature '{feature_key}' is not enabled"
            )
        return True
    return check_feature
