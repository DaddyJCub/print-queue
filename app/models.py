"""
Database models and schema definitions for Printellect.

This module defines:
- User accounts (requesters)
- Admin accounts with RBAC (role-based access control)
- Feature flags for gradual rollout
- Audit logging
- STL folder sync configuration
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import json


# ─────────────────────────── ENUMS ───────────────────────────

class AdminRole(str, Enum):
    """Admin permission levels (hierarchical)"""
    SUPER_ADMIN = "super_admin"    # Full access: manage other admins, settings, everything
    ADMIN = "admin"                 # Manage queue, users, store, analytics
    OPERATOR = "operator"           # Manage queue only (approve, print, complete)
    VIEWER = "viewer"               # Read-only access to admin dashboard


class UserStatus(str, Enum):
    """User account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    UNVERIFIED = "unverified"


class AuditAction(str, Enum):
    """Types of auditable actions"""
    # Admin actions
    ADMIN_LOGIN = "admin_login"
    ADMIN_LOGOUT = "admin_logout"
    ADMIN_LOGIN_FAILED = "admin_login_failed"
    ADMIN_CREATED = "admin_created"
    ADMIN_UPDATED = "admin_updated"
    ADMIN_DELETED = "admin_deleted"
    ADMIN_ROLE_CHANGED = "admin_role_changed"
    
    # User actions
    USER_REGISTERED = "user_registered"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_UPDATED = "user_updated"
    USER_SUSPENDED = "user_suspended"
    USER_REACTIVATED = "user_reactivated"
    USER_EMAIL_VERIFIED = "user_email_verified"
    PASSWORD_RESET = "password_reset"
    
    # Request actions
    REQUEST_CREATED = "request_created"
    REQUEST_APPROVED = "request_approved"
    REQUEST_REJECTED = "request_rejected"
    REQUEST_CANCELLED = "request_cancelled"
    REQUEST_STATUS_CHANGED = "request_status_changed"
    REQUEST_PRIORITY_CHANGED = "request_priority_changed"
    
    # Store actions
    STORE_ITEM_CREATED = "store_item_created"
    STORE_ITEM_UPDATED = "store_item_updated"
    STORE_ITEM_DELETED = "store_item_deleted"
    STORE_PURCHASE = "store_purchase"
    
    # Settings actions
    SETTINGS_UPDATED = "settings_updated"
    FEATURE_FLAG_TOGGLED = "feature_flag_toggled"
    
    # File sync actions
    FILE_SYNC_STARTED = "file_sync_started"
    FILE_SYNC_COMPLETED = "file_sync_completed"
    FILE_AUTO_MATCHED = "file_auto_matched"
    
    # Trip actions
    TRIP_CREATED = "trip_created"
    TRIP_UPDATED = "trip_updated"
    TRIP_DELETED = "trip_deleted"
    TRIP_MEMBER_ADDED = "trip_member_added"
    TRIP_MEMBER_REMOVED = "trip_member_removed"
    TRIP_EVENT_CREATED = "trip_event_created"
    TRIP_EVENT_UPDATED = "trip_event_updated"
    TRIP_EVENT_DELETED = "trip_event_deleted"


class TripMemberRole(str, Enum):
    """Trip member permission levels"""
    OWNER = "owner"      # Full access, can delete trip, manage members
    EDITOR = "editor"    # Can add/edit events
    VIEWER = "viewer"    # Read-only access


class TripEventCategory(str, Enum):
    """Trip event category types"""
    FLIGHT = "flight"
    HOTEL = "hotel"
    ACTIVITY = "activity"
    MEAL = "meal"
    TRANSPORT = "transport"
    OTHER = "other"


# ─────────────────────────── PERMISSIONS ───────────────────────────

# Define what each role can do
ROLE_PERMISSIONS = {
    AdminRole.SUPER_ADMIN: {
        "manage_admins",      # Create, edit, delete other admins
        "manage_settings",    # System settings, feature flags
        "manage_queue",       # All queue operations
        "manage_users",       # User accounts
        "manage_store",       # Store items
        "view_analytics",     # Analytics dashboard
        "view_audit_log",     # Audit trail
        "send_broadcasts",    # System notifications
        "manage_printers",    # Printer configuration
        "manage_files",       # File sync settings
        "delete_requests",    # Delete requests permanently
        "export_data",        # Export data (GDPR, backups)
    },
    AdminRole.ADMIN: {
        "manage_queue",
        "manage_users",
        "manage_store",
        "view_analytics",
        "view_audit_log",
        "send_broadcasts",
        "manage_printers",
        "manage_files",
    },
    AdminRole.OPERATOR: {
        "manage_queue",       # Approve, print, complete requests
        "view_analytics",     # View-only analytics
    },
    AdminRole.VIEWER: {
        "view_analytics",     # View-only everything
    },
}

def has_permission(role: AdminRole, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())

def get_permissions(role: AdminRole) -> set:
    """Get all permissions for a role."""
    return ROLE_PERMISSIONS.get(role, set())


# ─────────────────────────── DATA CLASSES ───────────────────────────

@dataclass
class User:
    """User account (requesters)"""
    id: str
    email: str
    name: str
    created_at: str
    updated_at: str
    status: UserStatus = UserStatus.UNVERIFIED
    email_verified: bool = False
    email_verified_at: Optional[str] = None
    
    # Profile info (auto-filled in request form)
    phone: Optional[str] = None
    preferred_printer: Optional[str] = None
    preferred_material: Optional[str] = None
    preferred_colors: Optional[str] = None
    notes_template: Optional[str] = None
    
    # Notification preferences
    notification_prefs: Dict[str, Any] = field(default_factory=lambda: {
        "email_status_updates": True,
        "email_print_ready": True,
        "push_enabled": False,
        "push_progress": True,
        "push_milestones": [50, 75],
        # Trip notification preferences
        "trip_reminders_enabled": True,
        "trip_default_reminder_minutes": 30,  # Default reminder offset
    })
    
    # Stats
    total_requests: int = 0
    total_prints: int = 0
    
    # Store credits (future)
    credits: int = 0
    
    # Auth
    password_hash: Optional[str] = None  # None for magic link only users
    magic_link_token: Optional[str] = None
    magic_link_expires: Optional[str] = None
    last_login: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "preferred_printer": self.preferred_printer,
            "preferred_material": self.preferred_material,
            "preferred_colors": self.preferred_colors,
            "notes_template": self.notes_template,
            "notification_prefs": self.notification_prefs,
            "total_requests": self.total_requests,
            "total_prints": self.total_prints,
            "credits": self.credits,
            "status": self.status.value if isinstance(self.status, UserStatus) else self.status,
            "email_verified": self.email_verified,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }
    
    @property
    def display_name(self) -> str:
        """Return name or email prefix as display name."""
        return self.name or self.email.split('@')[0]


@dataclass
class Admin:
    """Admin account with RBAC"""
    id: str
    username: str
    email: str
    password_hash: str
    role: AdminRole
    created_at: str
    updated_at: str
    
    display_name: Optional[str] = None
    is_active: bool = True
    last_login: Optional[str] = None
    login_count: int = 0
    
    # 2FA (future)
    totp_secret: Optional[str] = None
    totp_enabled: bool = False
    
    # Session management
    session_token: Optional[str] = None
    session_expires: Optional[str] = None
    
    def has_permission(self, permission: str) -> bool:
        """Check if this admin has a specific permission."""
        if not self.is_active:
            return False
        return has_permission(self.role, permission)
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "display_name": self.display_name or self.username,
            "role": self.role.value if isinstance(self.role, AdminRole) else self.role,
            "is_active": self.is_active,
            "last_login": self.last_login,
            "login_count": self.login_count,
            "totp_enabled": self.totp_enabled,
            "created_at": self.created_at,
        }
        if include_sensitive:
            data["session_token"] = self.session_token
        return data


@dataclass
class AuditLog:
    """Audit trail entry"""
    id: str
    created_at: str
    action: AuditAction
    
    # Who performed the action
    actor_type: str  # "admin", "user", "system"
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_ip: Optional[str] = None
    
    # What was affected
    target_type: Optional[str] = None  # "request", "user", "admin", "store_item", "setting"
    target_id: Optional[str] = None
    
    # Details
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "action": self.action.value if isinstance(self.action, AuditAction) else self.action,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "actor_ip": self.actor_ip,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.details,
        }


@dataclass
class FeatureFlag:
    """Feature flag for gradual rollout"""
    key: str
    enabled: bool
    description: str
    
    # Rollout configuration
    rollout_percentage: int = 100  # 0-100
    allowed_users: List[str] = field(default_factory=list)  # User IDs with access
    allowed_emails: List[str] = field(default_factory=list)  # Email patterns (e.g., "*@company.com")
    
    # Metadata
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None
    
    def is_enabled_for_user(self, user_id: Optional[str] = None, email: Optional[str] = None) -> bool:
        """Check if flag is enabled for a specific user."""
        if not self.enabled:
            return False
        
        # Check allowed lists first
        if user_id and user_id in self.allowed_users:
            return True
        
        if email:
            for pattern in self.allowed_emails:
                if pattern.startswith("*"):
                    if email.endswith(pattern[1:]):
                        return True
                elif email == pattern:
                    return True
        
        # Rollout percentage (deterministic based on user_id)
        if self.rollout_percentage >= 100:
            return True
        if self.rollout_percentage <= 0:
            return False
        
        if user_id:
            # Use hash for deterministic rollout
            import hashlib
            hash_val = int(hashlib.md5(f"{self.key}:{user_id}".encode()).hexdigest(), 16)
            return (hash_val % 100) < self.rollout_percentage
        
        return False


@dataclass  
class FileSyncConfig:
    """Configuration for STL folder sync"""
    id: str
    name: str
    folder_path: str
    is_active: bool = True
    
    # Sync behavior
    watch_subfolders: bool = True
    auto_match_requests: bool = True
    move_matched_files: bool = True  # Move to /matched folder after matching
    archive_completed: bool = True   # Move to /archived after print completes
    
    # Matching settings
    match_confidence_threshold: float = 0.7  # 0-1, minimum fuzzy match score
    
    # File filters
    allowed_extensions: List[str] = field(default_factory=lambda: [".stl", ".3mf", ".obj", ".gcode"])
    
    # Timestamps
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    
    # Stats
    total_files_synced: int = 0
    total_files_matched: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON/template serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'path': self.folder_path,
            'enabled': self.is_active,
            'recursive': self.watch_subfolders,
            'auto_attach': self.auto_match_requests,
            'match_threshold': int(self.match_confidence_threshold * 100),
            'extensions': ','.join(self.allowed_extensions),
            'scan_interval': 300,  # Default, can extend model later
            'file_count': self.total_files_synced,
            'last_sync': self.last_sync_at,
            'created_at': self.created_at,
        }


# ─────────────────────────── TRIP DATA CLASSES ───────────────────────────

@dataclass
class Trip:
    """A trip/travel itinerary (private feature)"""
    id: str
    title: str
    destination: str
    start_date: str  # ISO date (YYYY-MM-DD)
    end_date: str    # ISO date (YYYY-MM-DD)
    created_by_user_id: str
    created_at: str
    updated_at: str
    
    # Optional fields
    timezone: str = "America/Los_Angeles"  # Default to Pacific for Vegas
    description: Optional[str] = None
    cover_image_url: Optional[str] = None
    pdf_itinerary_path: Optional[str] = None  # Path to uploaded PDF
    share_token: Optional[str] = None
    budget_cents: int = 0  # total budget for the trip
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'destination': self.destination,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'timezone': self.timezone,
            'description': self.description,
            'cover_image_url': self.cover_image_url,
            'pdf_itinerary_path': self.pdf_itinerary_path,
            'share_token': self.share_token,
            'budget_cents': self.budget_cents,
            'created_by_user_id': self.created_by_user_id,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }


@dataclass
class TripMember:
    """A member of a trip with role-based access"""
    id: str
    trip_id: str
    user_id: str
    role: TripMemberRole
    added_at: str
    added_by_user_id: Optional[str] = None
    
    # Cached user info for display
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'trip_id': self.trip_id,
            'user_id': self.user_id,
            'role': self.role.value if isinstance(self.role, TripMemberRole) else self.role,
            'added_at': self.added_at,
            'added_by_user_id': self.added_by_user_id,
            'user_email': self.user_email,
            'user_name': self.user_name,
        }
    
    def can_edit(self) -> bool:
        """Check if member can edit trip events"""
        role = self.role if isinstance(self.role, TripMemberRole) else TripMemberRole(self.role)
        return role in (TripMemberRole.OWNER, TripMemberRole.EDITOR)
    
    def can_manage_members(self) -> bool:
        """Check if member can add/remove other members"""
        role = self.role if isinstance(self.role, TripMemberRole) else TripMemberRole(self.role)
        return role == TripMemberRole.OWNER


@dataclass
class TripEvent:
    """An event within a trip (flight, hotel, activity, etc.)"""
    id: str
    trip_id: str
    title: str
    start_datetime: str  # ISO datetime or "all-day" marker
    timezone: str = "America/Los_Angeles"
    category: TripEventCategory
    created_at: str
    updated_at: str
    
    # Optional timing
    end_datetime: Optional[str] = None
    is_all_day: bool = False
    
    # Location info
    location_name: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    # Details
    notes: Optional[str] = None
    confirmation_number: Optional[str] = None
    
    # Links (stored as JSON)
    links: Dict[str, str] = field(default_factory=dict)  # e.g., {"maps": "url", "tickets": "url"}
    
    # Ordering
    sort_order: int = 0
    
    # For flight/transport
    departure_location: Optional[str] = None
    arrival_location: Optional[str] = None
    flight_number: Optional[str] = None
    
    # Reminder settings
    reminder_minutes: Optional[int] = 30  # Minutes before event (None = no reminder)
    reminder_sent: bool = False  # True once reminder has been sent
    cost_cents: int = 0  # Optional cost for budgeting
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'trip_id': self.trip_id,
            'title': self.title,
            'start_datetime': self.start_datetime,
            'timezone': self.timezone,
            'end_datetime': self.end_datetime,
            'is_all_day': self.is_all_day,
            'category': self.category.value if isinstance(self.category, TripEventCategory) else self.category,
            'location_name': self.location_name,
            'address': self.address,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'notes': self.notes,
            'confirmation_number': self.confirmation_number,
            'links': self.links,
            'sort_order': self.sort_order,
            'departure_location': self.departure_location,
            'arrival_location': self.arrival_location,
            'flight_number': self.flight_number,
            'reminder_minutes': self.reminder_minutes,
            'reminder_sent': self.reminder_sent,
            'cost_cents': self.cost_cents,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }


@dataclass
class TripEventComment:
    """Lightweight comment on a trip event"""
    id: str
    event_id: str
    user_id: str
    body: str
    created_at: str
    user_name: Optional[str] = None
    user_email: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "user_id": self.user_id,
            "body": self.body,
            "created_at": self.created_at,
            "user_name": self.user_name,
            "user_email": self.user_email,
        }

# ─────────────────────────── DEFAULT FEATURE FLAGS ───────────────────────────

DEFAULT_FEATURE_FLAGS = {
    # User accounts
    "user_accounts": FeatureFlag(
        key="user_accounts",
        enabled=True,  # Enable by default for development
        description="Allow users to create accounts and save preferences",
    ),
    "user_registration": FeatureFlag(
        key="user_registration",
        enabled=True,
        description="Allow new user registration (vs invite-only)",
    ),
    "user_password_auth": FeatureFlag(
        key="user_password_auth",
        enabled=True,
        description="Allow password login (vs magic link only)",
    ),
    
    # Store features
    "store_public": FeatureFlag(
        key="store_public",
        enabled=True,  # Store is already public
        description="Public store visibility",
    ),
    "store_payments": FeatureFlag(
        key="store_payments",
        enabled=False,
        description="Enable payment processing (Stripe)",
    ),
    "store_rewards": FeatureFlag(
        key="store_rewards",
        enabled=False,
        description="Enable rewards/credits system (watch ads, referrals)",
    ),
    "store_preorders": FeatureFlag(
        key="store_preorders",
        enabled=False,
        description="Allow preorders for out-of-stock items",
    ),
    
    # Advanced features
    "file_sync": FeatureFlag(
        key="file_sync",
        enabled=False,
        description="STL folder sync and auto-matching",
    ),
    "multi_admin": FeatureFlag(
        key="multi_admin",
        enabled=True,  # Enable for this implementation
        description="Multiple admin accounts with role-based access",
    ),
    "audit_logging": FeatureFlag(
        key="audit_logging",
        enabled=True,
        description="Detailed audit trail for admin actions",
    ),
    "octoprint_integration": FeatureFlag(
        key="octoprint_integration",
        enabled=False,
        description="OctoPrint/Klipper API integration",
    ),
    "auto_slicer": FeatureFlag(
        key="auto_slicer",
        enabled=False,
        description="Automatic slicing of STL files",
    ),
    
    # UI features
    "dark_mode_toggle": FeatureFlag(
        key="dark_mode_toggle",
        enabled=False,
        description="Allow users to toggle between dark/light mode",
    ),
    "3d_preview": FeatureFlag(
        key="3d_preview",
        enabled=True,  # Already implemented
        description="3D model preview with Three.js",
    ),
    
    # Private features (user-specific access)
    "trips": FeatureFlag(
        key="trips",
        enabled=True,  # Enabled but restricted to allowed_emails
        description="Private trips/itinerary feature (family use)",
        rollout_percentage=0,  # Don't auto-enable for anyone
        allowed_emails=[],  # Add specific emails in admin panel
    ),
}


# ─────────────────────────── SQL SCHEMAS ───────────────────────────

# These will be used by init_db() in main.py

USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    phone TEXT,
    password_hash TEXT,
    status TEXT NOT NULL DEFAULT 'unverified',
    email_verified INTEGER DEFAULT 0,
    email_verified_at TEXT,
    
    -- Preferences (auto-fill in request form)
    preferred_printer TEXT,
    preferred_material TEXT,
    preferred_colors TEXT,
    notes_template TEXT,
    notification_prefs TEXT DEFAULT '{}',
    
    -- Stats
    total_requests INTEGER DEFAULT 0,
    total_prints INTEGER DEFAULT 0,
    credits INTEGER DEFAULT 0,
    
    -- Auth tokens
    magic_link_token TEXT,
    magic_link_expires TEXT,
    reset_token TEXT,
    reset_token_expires TEXT,
    
    -- Timestamps
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login TEXT
);
"""

ADMINS_TABLE = """
CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'operator',
    is_active INTEGER DEFAULT 1,
    
    -- Session
    session_token TEXT,
    session_expires TEXT,
    
    -- 2FA
    totp_secret TEXT,
    totp_enabled INTEGER DEFAULT 0,
    
    -- Stats
    login_count INTEGER DEFAULT 0,
    last_login TEXT,
    
    -- Timestamps
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    action TEXT NOT NULL,
    
    -- Actor (who did it)
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    actor_ip TEXT,
    
    -- Target (what was affected)
    target_type TEXT,
    target_id TEXT,
    
    -- Additional details as JSON
    details TEXT DEFAULT '{}'
);
"""

FEATURE_FLAGS_TABLE = """
CREATE TABLE IF NOT EXISTS feature_flags (
    key TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 0,
    description TEXT,
    rollout_percentage INTEGER DEFAULT 100,
    allowed_users TEXT DEFAULT '[]',
    allowed_emails TEXT DEFAULT '[]',
    created_at TEXT,
    updated_at TEXT,
    created_by TEXT
);
"""

FILE_SYNC_CONFIGS_TABLE = """
CREATE TABLE IF NOT EXISTS file_sync_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    folder_path TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    watch_subfolders INTEGER DEFAULT 1,
    auto_match_requests INTEGER DEFAULT 1,
    move_matched_files INTEGER DEFAULT 1,
    archive_completed INTEGER DEFAULT 1,
    match_confidence_threshold REAL DEFAULT 0.7,
    allowed_extensions TEXT DEFAULT '[".stl", ".3mf", ".obj", ".gcode"]',
    created_at TEXT,
    updated_at TEXT,
    last_sync_at TEXT,
    total_files_synced INTEGER DEFAULT 0,
    total_files_matched INTEGER DEFAULT 0
);
"""

FILE_SYNC_QUEUE_TABLE = """
CREATE TABLE IF NOT EXISTS file_sync_queue (
    id TEXT PRIMARY KEY,
    sync_config_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_hash TEXT,
    status TEXT DEFAULT 'pending',
    matched_request_id TEXT,
    matched_build_id TEXT,
    match_confidence REAL,
    created_at TEXT NOT NULL,
    processed_at TEXT,
    FOREIGN KEY(sync_config_id) REFERENCES file_sync_configs(id)
);
"""

# User sessions for multi-device login tracking
USER_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    device_info TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_active TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""

# ─────────────────────────── TRIP TABLES ───────────────────────────

TRIPS_TABLE = """
CREATE TABLE IF NOT EXISTS trips (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    destination TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    timezone TEXT DEFAULT 'America/Los_Angeles',
    description TEXT,
    cover_image_url TEXT,
    pdf_itinerary_path TEXT,
    created_by_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(created_by_user_id) REFERENCES users(id)
);
"""

TRIP_MEMBERS_TABLE = """
CREATE TABLE IF NOT EXISTS trip_members (
    id TEXT PRIMARY KEY,
    trip_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    added_at TEXT NOT NULL,
    added_by_user_id TEXT,
    FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(trip_id, user_id)
);
"""

TRIP_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS trip_events (
    id TEXT PRIMARY KEY,
    trip_id TEXT NOT NULL,
    title TEXT NOT NULL,
    start_datetime TEXT NOT NULL,
    end_datetime TEXT,
    is_all_day INTEGER DEFAULT 0,
    category TEXT NOT NULL DEFAULT 'other',
    location_name TEXT,
    address TEXT,
    latitude REAL,
    longitude REAL,
    notes TEXT,
    confirmation_number TEXT,
    links TEXT DEFAULT '{}',
    sort_order INTEGER DEFAULT 0,
    departure_location TEXT,
    arrival_location TEXT,
    flight_number TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE
);
"""

# Index definitions for performance
INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
    "CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);",
    "CREATE INDEX IF NOT EXISTS idx_admins_session ON admins(session_token);",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_file_sync_queue_status ON file_sync_queue(status);",
    # Trip indexes
    "CREATE INDEX IF NOT EXISTS idx_trips_created_by ON trips(created_by_user_id);",
    "CREATE INDEX IF NOT EXISTS idx_trip_members_trip ON trip_members(trip_id);",
    "CREATE INDEX IF NOT EXISTS idx_trip_members_user ON trip_members(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_trip_events_trip ON trip_events(trip_id);",
    "CREATE INDEX IF NOT EXISTS idx_trip_events_start ON trip_events(start_datetime);",
]

ALL_NEW_TABLES = [
    USERS_TABLE,
    ADMINS_TABLE,
    AUDIT_LOG_TABLE,
    FEATURE_FLAGS_TABLE,
    FILE_SYNC_CONFIGS_TABLE,
    FILE_SYNC_QUEUE_TABLE,
    USER_SESSIONS_TABLE,
    TRIPS_TABLE,
    TRIP_MEMBERS_TABLE,
    TRIP_EVENTS_TABLE,
]
