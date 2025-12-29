"""
Private Trips Feature for Printellect.

This is a PRIVATE feature only accessible to permitted users (trip members).
It does NOT appear on any public pages or navigation.

Provides:
- Trip management (CRUD)
- Trip member management with role-based access
- Trip event management (flights, hotels, activities, etc.)
- PDF itinerary upload and viewing
- PWA-friendly trip timeline view
"""

import os
import uuid
import sqlite3
import json
import shutil
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from functools import wraps
import logging

from fastapi import APIRouter, Request, Form, HTTPException, Depends, Query, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, Response
from fastapi.templating import Jinja2Templates

from app.auth import (
    get_current_user, require_user, optional_user, get_user_by_id, get_user_by_email,
    log_audit, db, is_feature_enabled
)
from app.models import (
    Trip, TripMember, TripEvent, TripMemberRole, TripEventCategory, AuditAction, TripEventComment
)

logger = logging.getLogger("printellect.trips")

# ─────────────────────────── SETUP ───────────────────────────

router = APIRouter(prefix="/trips", tags=["trips"])
templates = Jinja2Templates(directory="app/templates")

# Timezone for display
DISPLAY_TIMEZONE = os.getenv("DISPLAY_TIMEZONE", "America/Los_Angeles")
BASE_URL = os.getenv("BASE_URL", "http://localhost:3000")

# Upload directory for trip files (PDFs, images)
TRIP_UPLOADS_DIR = os.getenv("TRIP_UPLOADS_DIR", "/data/trip_uploads")

def get_db_path():
    return os.getenv("DB_PATH", "/data/app.db")


def _get_tz(tz_name: str):
    """Return a ZoneInfo instance with safe fallback."""
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz_name or DISPLAY_TIMEZONE)
    except Exception:
        # Fallback to UTC to avoid crashing on bad tz strings
        return timezone.utc


def utc_now_iso() -> str:
    """UTC timestamp with Z suffix and no microseconds."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ensure_trips_feature(user):
    """Ensure trips feature is enabled for the user or raise 403."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not is_feature_enabled("trips", user_id=getattr(user, "id", None), email=getattr(user, "email", None)):
        raise HTTPException(status_code=403, detail="You don't have access to this feature")


def validate_share_token(trip: Trip, token: str) -> bool:
    return bool(trip and token and trip.share_token and secrets.compare_digest(trip.share_token, token))


def normalize_link(url_value: Optional[str]) -> Optional[str]:
    """Keep only http(s) links; drop everything else."""
    if not url_value:
        return None
    from urllib.parse import urlparse
    parsed = urlparse(url_value.strip())
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return url_value.strip()
    return None


def build_event_datetimes(
    start_date: str,
    start_time: Optional[str],
    end_date: Optional[str],
    end_time: Optional[str],
    is_all_day: bool,
    tz_name: str,
) -> Tuple[str, Optional[str], datetime, Optional[datetime]]:
    """
    Build UTC ISO datetimes (with Z) for storage and return both raw and parsed values.
    """
    tz = _get_tz(tz_name)
    # Start
    if is_all_day or not start_time:
        local_start = datetime.fromisoformat(f"{start_date}T00:00:00")
    else:
        local_start = datetime.fromisoformat(f"{start_date}T{start_time}:00")
    local_start = local_start.replace(tzinfo=tz)
    start_utc = local_start.astimezone(timezone.utc)
    start_iso = start_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    
    # End (optional)
    end_utc = None
    end_iso = None
    if end_date:
        if is_all_day or not end_time:
            local_end = datetime.fromisoformat(f"{end_date}T23:59:59")
        else:
            local_end = datetime.fromisoformat(f"{end_date}T{end_time}:00")
        local_end = local_end.replace(tzinfo=tz)
        end_utc = local_end.astimezone(timezone.utc)
        end_iso = end_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    
    return start_iso, end_iso, start_utc, end_utc


def parse_event_start(event: TripEvent) -> Optional[datetime]:
    """Parse an event's start_datetime into UTC."""
    try:
        raw = event.start_datetime
        if isinstance(raw, datetime):
            dt = raw
        elif isinstance(raw, str):
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            return None
        
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_get_tz(getattr(event, "timezone", DISPLAY_TIMEZONE)))
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _format_ics_datetime(dt: datetime, all_day: bool) -> str:
    if all_day:
        return dt.strftime("%Y%m%d")
    return dt.strftime("%Y%m%dT%H%M%SZ")


def build_trip_ics(trip: Trip, events: List[TripEvent]) -> str:
    """Generate a simple ICS feed for a trip."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        f"PRODID:-//Printellect Trips//EN",
        f"X-WR-CALNAME:{trip.title}",
    ]
    for e in events:
        start_dt = parse_event_start(e)
        if not start_dt:
            continue
        end_dt = None
        if e.end_datetime:
            try:
                end_dt = datetime.fromisoformat(e.end_datetime.replace("Z", "+00:00")).astimezone(timezone.utc)
            except Exception:
                end_dt = None
        if e.is_all_day:
            start_str = _format_ics_datetime(start_dt, True)
            end_str = _format_ics_datetime(end_dt or start_dt, True)
            dtstart_line = f"DTSTART;VALUE=DATE:{start_str}"
            dtend_line = f"DTEND;VALUE=DATE:{end_str}"
        else:
            start_str = _format_ics_datetime(start_dt, False)
            dtstart_line = f"DTSTART:{start_str}"
            if end_dt:
                end_str = _format_ics_datetime(end_dt, False)
                dtend_line = f"DTEND:{end_str}"
            else:
                dtend_line = None
        lines.extend([
            "BEGIN:VEVENT",
            f"UID:{e.id}",
            dtstart_line,
        ])
        if dtend_line:
            lines.append(dtend_line)
        lines.extend([
            f"SUMMARY:{e.title}",
            f"DESCRIPTION:{(e.notes or '').replace('\\n', '\\\\n')}",
            f"LOCATION:{e.location_name or ''}",
            "END:VEVENT",
        ])
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines)


def parse_ics_events(ics_text: str, default_tz: str) -> List[Dict[str, Any]]:
    """Very small ICS parser to pull VEVENT details without extra deps."""
    events = []
    current = {}
    for raw_line in ics_text.splitlines():
        line = raw_line.strip()
        if line.upper() == "BEGIN:VEVENT":
            current = {}
        elif line.upper() == "END:VEVENT":
            if current.get("SUMMARY") and current.get("DTSTART"):
                events.append(current)
            current = {}
        else:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current[key.upper()] = value
    
    parsed = []
    for item in events:
        summary = item.get("SUMMARY")
        dtstart = item.get("DTSTART")
        dtend = item.get("DTEND")
        location = item.get("LOCATION", "")
        notes = item.get("DESCRIPTION", "")
        is_all_day = False
        start_iso = None
        end_iso = None
        
        def parse_dt(val: str) -> Optional[datetime]:
            if not val:
                return None
            try:
                if val.endswith("Z"):
                    return datetime.strptime(val, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                if "T" in val:
                    tz = _get_tz(default_tz)
                    local = datetime.strptime(val, "%Y%m%dT%H%M%S").replace(tzinfo=tz)
                    return local.astimezone(timezone.utc)
                # Date-only
                return datetime.strptime(val, "%Y%m%d").replace(tzinfo=timezone.utc)
            except Exception:
                return None
        
        start_dt = parse_dt(dtstart)
        end_dt = parse_dt(dtend)
        if start_dt and "T" not in dtstart:
            is_all_day = True
        if start_dt:
            start_iso = start_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if end_dt:
            end_iso = end_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        
        parsed.append({
            "title": summary or "Untitled",
            "start_datetime": start_iso,
            "end_datetime": end_iso,
            "is_all_day": is_all_day,
            "location_name": location,
            "notes": notes.replace("\\n", "\n"),
        })
    return parsed


def validate_event_window(start_dt: datetime, end_dt: Optional[datetime], trip) -> None:
    """Ensure event dates fall within trip window and are ordered."""
    if end_dt and end_dt < start_dt:
        raise HTTPException(status_code=400, detail="Event end time cannot be before start time")
    
    # Compare in trip timezone so date boundaries align with user expectation
    tz = _get_tz(getattr(trip, "timezone", DISPLAY_TIMEZONE))
    trip_start = datetime.strptime(trip.start_date, "%Y-%m-%d").replace(tzinfo=tz)
    trip_end = datetime.strptime(trip.end_date, "%Y-%m-%d").replace(tzinfo=tz) + timedelta(days=1) - timedelta(seconds=1)
    
    start_local = start_dt.astimezone(tz)
    if start_local < trip_start or start_local > trip_end:
        raise HTTPException(status_code=400, detail="Event start is outside of the trip dates")
    if end_dt:
        end_local = end_dt.astimezone(tz)
        if end_local < trip_start or end_local > trip_end:
            raise HTTPException(status_code=400, detail="Event end is outside of the trip dates")

def format_datetime_local(value, fmt="%b %d, %Y at %I:%M %p"):
    """Convert ISO datetime string to local timezone for display"""
    if not value:
        return ""
    try:
        from datetime import timezone
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = value
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(DISPLAY_TIMEZONE)
            local_dt = dt.astimezone(tz)
        except Exception:
            from datetime import timedelta
            local_dt = dt - timedelta(hours=5)
        return local_dt.strftime(fmt)
    except Exception:
        return str(value)

templates.env.filters["localtime"] = format_datetime_local


# ─────────────────────────── DATABASE HELPERS ───────────────────────────

def _row_to_trip(row: sqlite3.Row) -> Trip:
    """Convert database row to Trip object."""
    return Trip(
        id=row["id"],
        title=row["title"],
        destination=row["destination"],
        start_date=row["start_date"],
        end_date=row["end_date"],
        timezone=row["timezone"] or "America/Los_Angeles",
        description=row["description"],
        cover_image_url=row["cover_image_url"],
        pdf_itinerary_path=row["pdf_itinerary_path"],
        share_token=row["share_token"] if "share_token" in row.keys() else None,
        budget_cents=row["budget_cents"] if "budget_cents" in row.keys() and row["budget_cents"] is not None else 0,
        created_by_user_id=row["created_by_user_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_trip_member(row: sqlite3.Row) -> TripMember:
    """Convert database row to TripMember object."""
    # For optional columns that may not exist (from JOINs), check keys first
    keys = row.keys()
    return TripMember(
        id=row["id"],
        trip_id=row["trip_id"],
        user_id=row["user_id"],
        role=TripMemberRole(row["role"]) if row["role"] else TripMemberRole.VIEWER,
        added_at=row["added_at"],
        added_by_user_id=row["added_by_user_id"] if "added_by_user_id" in keys else None,
        user_email=row["user_email"] if "user_email" in keys else None,
        user_name=row["user_name"] if "user_name" in keys else None,
    )


def _row_to_trip_event(row: sqlite3.Row) -> TripEvent:
    """Convert database row to TripEvent object."""
    links = {}
    if row["links"]:
        try:
            links = json.loads(row["links"])
        except:
            pass
    
    # Handle reminder columns that may not exist in older DBs
    keys = row.keys()
    reminder_minutes = row["reminder_minutes"] if "reminder_minutes" in keys else 30
    reminder_sent = bool(row["reminder_sent"]) if "reminder_sent" in keys else False
    timezone = row["timezone"] if "timezone" in keys and row["timezone"] else "America/Los_Angeles"
    cost_cents = row["cost_cents"] if "cost_cents" in keys and row["cost_cents"] is not None else 0
    
    return TripEvent(
        id=row["id"],
        trip_id=row["trip_id"],
        title=row["title"],
        start_datetime=row["start_datetime"],
        timezone=timezone,
        end_datetime=row["end_datetime"],
        is_all_day=bool(row["is_all_day"]),
        category=TripEventCategory(row["category"]) if row["category"] else TripEventCategory.OTHER,
        location_name=row["location_name"],
        address=row["address"],
        latitude=row["latitude"],
        longitude=row["longitude"],
        notes=row["notes"],
        confirmation_number=row["confirmation_number"],
        links=links,
        sort_order=row["sort_order"] or 0,
        departure_location=row["departure_location"],
        arrival_location=row["arrival_location"],
        flight_number=row["flight_number"],
        reminder_minutes=reminder_minutes,
        reminder_sent=reminder_sent,
        cost_cents=cost_cents,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ─────────────────────────── ACCESS CONTROL ───────────────────────────

def get_user_trip_membership(user_id: str, trip_id: str) -> Optional[TripMember]:
    """Get user's membership for a trip, or None if not a member."""
    conn = db()
    row = conn.execute("""
        SELECT tm.*, u.email as user_email, u.name as user_name
        FROM trip_members tm
        JOIN users u ON u.id = tm.user_id
        WHERE tm.trip_id = ? AND tm.user_id = ?
    """, (trip_id, user_id)).fetchone()
    conn.close()
    
    if not row:
        return None
    return _row_to_trip_member(row)


def require_trip_access(request: Request, trip_id: str, require_edit: bool = False) -> Tuple[Any, TripMember]:
    """
    Check if current user has access to a trip.
    Returns (user, membership) or raises HTTPException.
    """
    user = None
    # Try to get user from session
    session_token = request.cookies.get("user_session")
    if session_token:
        from app.auth import get_user_by_session
        user = get_user_by_session(session_token)
    
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="You don't have access to this trip")
    
    if require_edit and not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access to this trip")
    
    return user, membership


async def get_trip_access(request: Request, trip_id: str) -> Tuple[Optional[Any], Optional[TripMember]]:
    """
    Non-throwing version - returns (user, membership) or (None, None).
    """
    try:
        user = await get_current_user(request)
        if not user:
            return None, None
        membership = get_user_trip_membership(user.id, trip_id)
        return user, membership
    except:
        return None, None


# ─────────────────────────── TRIP CRUD ───────────────────────────

def create_trip(
    title: str,
    destination: str,
    start_date: str,
    end_date: str,
    created_by_user_id: str,
    timezone: str = "America/Los_Angeles",
    description: str = None,
    budget_cents: int = 0
) -> Trip:
    """Create a new trip and add creator as owner."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    trip_id = str(uuid.uuid4())
    share_token = secrets.token_urlsafe(16)
    
    conn.execute("""
        INSERT INTO trips (id, title, destination, start_date, end_date, timezone, 
                          description, share_token, budget_cents, created_by_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (trip_id, title, destination, start_date, end_date, timezone, 
          description, share_token, budget_cents, created_by_user_id, now, now))
    
    # Add creator as owner
    member_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO trip_members (id, trip_id, user_id, role, added_at, added_by_user_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (member_id, trip_id, created_by_user_id, TripMemberRole.OWNER.value, now, created_by_user_id))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Trip created: {title} ({trip_id}) by user {created_by_user_id}")
    return get_trip_by_id(trip_id)


def get_trip_by_id(trip_id: str) -> Optional[Trip]:
    """Get trip by ID."""
    conn = db()
    row = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
    return _row_to_trip(row)


def get_user_trips(user_id: str) -> List[Trip]:
    """Get all trips a user is a member of."""
    conn = db()
    rows = conn.execute("""
        SELECT t.* FROM trips t
        JOIN trip_members tm ON tm.trip_id = t.id
        WHERE tm.user_id = ?
        ORDER BY t.start_date DESC
    """, (user_id,)).fetchall()
    conn.close()
    
    return [_row_to_trip(row) for row in rows]


def update_trip(trip_id: str, **kwargs) -> bool:
    """Update trip fields."""
    allowed_fields = {"title", "destination", "start_date", "end_date", "timezone", 
                      "description", "cover_image_url", "pdf_itinerary_path",
                      "share_token", "budget_cents"}
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields and v is not None}
    
    if not updates:
        return False
    
    updates["updated_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values()) + [trip_id]
    
    conn = db()
    conn.execute(f"UPDATE trips SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def delete_trip(trip_id: str) -> bool:
    """Delete a trip and all associated data."""
    conn = db()
    # Grab PDF path before deletion
    trip_row = conn.execute("SELECT pdf_itinerary_path FROM trips WHERE id = ?", (trip_id,)).fetchone()
    pdf_path = trip_row["pdf_itinerary_path"] if trip_row else None
    
    # Delete events and members first (or rely on CASCADE)
    conn.execute("DELETE FROM trip_events WHERE trip_id = ?", (trip_id,))
    conn.execute("DELETE FROM trip_members WHERE trip_id = ?", (trip_id,))
    conn.execute("DELETE FROM trips WHERE id = ?", (trip_id,))
    conn.commit()
    conn.close()
    
    if pdf_path and os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
        except Exception as exc:
            logger.warning(f"Failed to remove PDF for trip {trip_id}: {exc}")
    
    logger.info(f"Trip deleted: {trip_id}")
    return True


# ─────────────────────────── TRIP MEMBERS ───────────────────────────

def get_trip_members(trip_id: str) -> List[TripMember]:
    """Get all members of a trip."""
    conn = db()
    rows = conn.execute("""
        SELECT tm.*, u.email as user_email, u.name as user_name
        FROM trip_members tm
        JOIN users u ON u.id = tm.user_id
        WHERE tm.trip_id = ?
        ORDER BY 
            CASE tm.role WHEN 'owner' THEN 1 WHEN 'editor' THEN 2 ELSE 3 END,
            tm.added_at
    """, (trip_id,)).fetchall()
    conn.close()
    
    return [_row_to_trip_member(row) for row in rows]


def add_trip_member(
    trip_id: str, 
    user_id: str, 
    role: TripMemberRole,
    added_by_user_id: str
) -> Optional[TripMember]:
    """Add a member to a trip."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    member_id = str(uuid.uuid4())
    
    try:
        conn.execute("""
            INSERT INTO trip_members (id, trip_id, user_id, role, added_at, added_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (member_id, trip_id, user_id, role.value, now, added_by_user_id))
        conn.commit()
    except sqlite3.IntegrityError:
        # User is already a member
        conn.close()
        return None
    
    conn.close()
    logger.info(f"Trip member added: user {user_id} to trip {trip_id} as {role.value}")
    return get_user_trip_membership(user_id, trip_id)


def update_trip_member_role(trip_id: str, user_id: str, new_role: TripMemberRole) -> bool:
    """Update a member's role."""
    conn = db()
    conn.execute("""
        UPDATE trip_members SET role = ? WHERE trip_id = ? AND user_id = ?
    """, (new_role.value, trip_id, user_id))
    conn.commit()
    affected = conn.total_changes
    conn.close()
    return affected > 0


def remove_trip_member(trip_id: str, user_id: str) -> bool:
    """Remove a member from a trip."""
    conn = db()
    conn.execute("""
        DELETE FROM trip_members WHERE trip_id = ? AND user_id = ?
    """, (trip_id, user_id))
    conn.commit()
    affected = conn.total_changes
    conn.close()
    
    if affected > 0:
        logger.info(f"Trip member removed: user {user_id} from trip {trip_id}")
    return affected > 0


# ─────────────────────────── TRIP EVENTS ───────────────────────────

def create_trip_event(
    trip_id: str,
    title: str,
    start_datetime: str,
    category: TripEventCategory,
    timezone: str = "America/Los_Angeles",
    **kwargs
) -> TripEvent:
    """Create a new trip event."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    event_id = str(uuid.uuid4())
    
    # Get max sort_order for this trip
    max_order = conn.execute(
        "SELECT MAX(sort_order) FROM trip_events WHERE trip_id = ?", (trip_id,)
    ).fetchone()[0] or 0
    
    links_json = json.dumps(kwargs.get("links", {}))
    
    # Default reminder for timed events (30 min), None for all-day
    is_all_day = kwargs.get("is_all_day")
    reminder_minutes = kwargs.get("reminder_minutes")
    if reminder_minutes is None:
        reminder_minutes = None if is_all_day else 30
    
    conn.execute("""
        INSERT INTO trip_events (
            id, trip_id, title, start_datetime, end_datetime, is_all_day, category,
            timezone,
            location_name, address, latitude, longitude, notes, confirmation_number,
            links, sort_order, departure_location, arrival_location, flight_number, cost_cents,
            reminder_minutes, reminder_sent, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id, trip_id, title, start_datetime,
        kwargs.get("end_datetime"),
        1 if is_all_day else 0,
        category.value,
        timezone,
        kwargs.get("location_name"),
        kwargs.get("address"),
        kwargs.get("latitude"),
        kwargs.get("longitude"),
        kwargs.get("notes"),
        kwargs.get("confirmation_number"),
        links_json,
        max_order + 1,
        kwargs.get("departure_location"),
        kwargs.get("arrival_location"),
        kwargs.get("flight_number"),
        kwargs.get("cost_cents", 0),
        reminder_minutes,
        0,  # reminder_sent defaults to false
        now, now
    ))
    conn.commit()
    conn.close()
    
    logger.info(f"Trip event created: {title} ({event_id}) for trip {trip_id}")
    return get_trip_event_by_id(event_id)


def get_trip_event_by_id(event_id: str) -> Optional[TripEvent]:
    """Get event by ID."""
    conn = db()
    row = conn.execute("SELECT * FROM trip_events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
    return _row_to_trip_event(row)


def get_trip_events(trip_id: str, limit: int = None) -> List[TripEvent]:
    """Get all events for a trip, ordered by datetime then sort_order."""
    conn = db()
    query = """
        SELECT * FROM trip_events WHERE trip_id = ?
        ORDER BY start_datetime, sort_order
    """
    if limit:
        query += f" LIMIT {limit}"
    
    rows = conn.execute(query, (trip_id,)).fetchall()
    conn.close()
    
    return [_row_to_trip_event(row) for row in rows]


def get_upcoming_events(trip_id: str, limit: int = 10) -> List[TripEvent]:
    """Get upcoming events for a trip (from now onwards)."""
    conn = db()
    rows = conn.execute("""
        SELECT * FROM trip_events 
        WHERE trip_id = ?
        ORDER BY start_datetime, sort_order
    """, (trip_id,)).fetchall()
    conn.close()
    
    events = [_row_to_trip_event(row) for row in rows]
    now_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
    upcoming = []
    for e in events:
        start = parse_event_start(e)
        if start and start >= now_utc:
            upcoming.append(e)
    return upcoming[:limit]


def get_events_by_date(trip_id: str, date: str) -> List[TripEvent]:
    """Get all events for a specific date (YYYY-MM-DD)."""
    conn = db()
    
    rows = conn.execute("""
        SELECT * FROM trip_events 
        WHERE trip_id = ? AND date(start_datetime) = date(?)
        ORDER BY start_datetime, sort_order
    """, (trip_id, date)).fetchall()
    conn.close()
    
    return [_row_to_trip_event(row) for row in rows]


def update_trip_event(event_id: str, **kwargs) -> bool:
    """Update event fields."""
    allowed_fields = {
        "title", "start_datetime", "end_datetime", "is_all_day", "category",
        "timezone", "location_name", "address", "latitude", "longitude", "notes",
        "confirmation_number", "links", "sort_order", "departure_location",
        "arrival_location", "flight_number", "reminder_minutes", "reminder_sent",
        "cost_cents"
    }
    updates = {}
    for k, v in kwargs.items():
        if k in allowed_fields:
            if k == "links" and isinstance(v, dict):
                updates[k] = json.dumps(v)
            elif k == "is_all_day":
                updates[k] = 1 if v else 0
            elif k == "reminder_sent":
                updates[k] = 1 if v else 0
            elif k == "category" and isinstance(v, TripEventCategory):
                updates[k] = v.value
            else:
                updates[k] = v
    
    if not updates:
        return False
    
    updates["updated_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values()) + [event_id]
    
    conn = db()
    conn.execute(f"UPDATE trip_events SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def delete_trip_event(event_id: str) -> bool:
    """Delete an event."""
    conn = db()
    conn.execute("DELETE FROM trip_events WHERE id = ?", (event_id,))
    conn.commit()
    affected = conn.total_changes
    conn.close()
    
    if affected > 0:
        logger.info(f"Trip event deleted: {event_id}")
    return affected > 0


def reorder_trip_events(trip_id: str, event_ids: List[str]) -> bool:
    """Reorder events by setting sort_order based on list position."""
    conn = db()
    for i, event_id in enumerate(event_ids):
        conn.execute("""
            UPDATE trip_events SET sort_order = ? WHERE id = ? AND trip_id = ?
        """, (i, event_id, trip_id))
    conn.commit()
    conn.close()
    return True


# ─────────────────────────── COMMENTS ───────────────────────────

def add_event_comment(event_id: str, user_id: str, body: str) -> TripEventComment:
    conn = db()
    now = utc_now_iso()
    comment_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO trip_event_comments (id, event_id, user_id, body, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (comment_id, event_id, user_id, body.strip(), now))
    conn.commit()
    conn.close()
    return get_event_comment(comment_id)


def get_event_comment(comment_id: str) -> Optional[TripEventComment]:
    conn = db()
    row = conn.execute("""
        SELECT c.*, u.name as user_name, u.email as user_email
        FROM trip_event_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ?
    """, (comment_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return TripEventComment(
        id=row["id"],
        event_id=row["event_id"],
        user_id=row["user_id"],
        body=row["body"],
        created_at=row["created_at"],
        user_name=row["user_name"],
        user_email=row["user_email"],
    )


def get_event_comments(event_id: str) -> List[TripEventComment]:
    conn = db()
    rows = conn.execute("""
        SELECT c.*, u.name as user_name, u.email as user_email
        FROM trip_event_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.event_id = ?
        ORDER BY c.created_at DESC
    """, (event_id,)).fetchall()
    conn.close()
    results = []
    for row in rows:
        results.append(TripEventComment(
            id=row["id"],
            event_id=row["event_id"],
            user_id=row["user_id"],
            body=row["body"],
            created_at=row["created_at"],
            user_name=row["user_name"],
            user_email=row["user_email"],
        ))
    return results


# ─────────────────────────── FILE HANDLING ───────────────────────────

MAX_PDF_BYTES = 10 * 1024 * 1024  # 10MB

def _validate_pdf_upload(pdf_file: UploadFile):
    """Lightweight validation to reduce bad uploads."""
    if not pdf_file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")
    if pdf_file.content_type and pdf_file.content_type not in ("application/pdf", "application/x-pdf"):
        raise HTTPException(status_code=400, detail="Only PDF uploads are allowed")
    head = pdf_file.file.read(5)
    pdf_file.file.seek(0)
    if head[:4] != b"%PDF":
        raise HTTPException(status_code=400, detail="File does not look like a PDF")


def save_trip_pdf(trip_id: str, file: UploadFile, existing_path: Optional[str] = None) -> str:
    """Save uploaded PDF itinerary and return the path."""
    os.makedirs(TRIP_UPLOADS_DIR, exist_ok=True)
    
    # Generate unique filename
    ext = os.path.splitext(file.filename)[1] or ".pdf"
    filename = f"{trip_id}_itinerary_{uuid.uuid4().hex[:8]}{ext}"
    filepath = os.path.join(TRIP_UPLOADS_DIR, filename)
    
    # Remove old file if provided
    if existing_path and os.path.exists(existing_path):
        try:
            os.remove(existing_path)
        except Exception as exc:
            logger.warning(f"Unable to remove old PDF for trip {trip_id}: {exc}")
    
    # Copy with size guard
    total = 0
    with open(filepath, "wb") as f:
        while True:
            chunk = file.file.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PDF_BYTES:
                f.close()
                os.remove(filepath)
                raise HTTPException(status_code=400, detail="PDF is too large (max 10MB)")
            f.write(chunk)
    
    # Update trip record
    update_trip(trip_id, pdf_itinerary_path=filepath)
    
    logger.info(f"PDF uploaded for trip {trip_id}: {filepath}")
    return filepath


# ─────────────────────────── ROUTES: TRIP LIST ───────────────────────────

@router.get("", response_class=HTMLResponse)
async def trips_list_page(request: Request):
    """List all trips for the current user (private page)."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login?next=/trips", status_code=303)
    
    # Check feature flag - trips is gated to specific users
    if not is_feature_enabled("trips", user_id=user.id, email=user.email):
        raise HTTPException(status_code=403, detail="You don't have access to this feature")
    
    trips = get_user_trips(user.id)
    
    # Enrich trips with upcoming event counts
    enriched_trips = []
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    for trip in trips:
        events = get_trip_events(trip.id)
        upcoming_count = 0
        for e in events:
            start_dt = parse_event_start(e)
            if start_dt and start_dt >= now:
                upcoming_count += 1
        
        enriched_trips.append({
            **trip.to_dict(),
            "upcoming_count": upcoming_count,
            "membership": get_user_trip_membership(user.id, trip.id),
        })
    
    return templates.TemplateResponse("trips_list.html", {
        "request": request,
        "user": user,
        "trips": enriched_trips,
    })


@router.get("/new", response_class=HTMLResponse)
async def new_trip_page(request: Request):
    """Create new trip form."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login?next=/trips/new", status_code=303)
    
    ensure_trips_feature(user)
    
    return templates.TemplateResponse("trip_new.html", {
        "request": request,
        "user": user,
    })


@router.post("/new")
async def create_trip_submit(
    request: Request,
    title: str = Form(...),
    destination: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    timezone: str = Form("America/Los_Angeles"),
    description: str = Form(None),
    budget: float = Form(0.0)
):
    """Handle new trip creation."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    try:
        budget_cents = int(float(budget) * 100)
    except Exception:
        budget_cents = 0
    
    trip = create_trip(
        title=title,
        destination=destination,
        start_date=start_date,
        end_date=end_date,
        timezone=timezone,
        description=description,
        budget_cents=budget_cents,
        created_by_user_id=user.id
    )
    
    log_audit(
        action=AuditAction.TRIP_CREATED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip",
        target_id=trip.id,
        details={"title": title, "destination": destination}
    )
    
    return RedirectResponse(url=f"/trips/{trip.id}", status_code=303)


# ─────────────────────────── ROUTES: TRIP VIEW ───────────────────────────

@router.get("/{trip_id}", response_class=HTMLResponse)
async def trip_view_page(request: Request, trip_id: str):
    """Trip overview page with timeline (PWA-first design)."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="You don't have access to this trip")
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    # Get all events
    all_events = get_trip_events(trip_id)
    
    # Get upcoming events (next event + coming up list)
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    upcoming_events = []
    for e in all_events:
        start_dt = parse_event_start(e)
        if start_dt and start_dt >= now:
            upcoming_events.append(e)
    next_event = upcoming_events[0] if upcoming_events else None
    coming_up = upcoming_events[1:11] if len(upcoming_events) > 1 else []
    
    # Budget + cost rollup
    total_cost_cents = sum(e.cost_cents or 0 for e in all_events)
    remaining_budget_cents = None
    if trip.budget_cents:
        remaining_budget_cents = max(trip.budget_cents - total_cost_cents, 0)
    
    # Group events by date for timeline
    events_by_date = {}
    for event in all_events:
        date_key = event.start_datetime[:10]  # YYYY-MM-DD
        if date_key not in events_by_date:
            events_by_date[date_key] = []
        events_by_date[date_key].append(event)
    
    # Generate date range for the trip
    from datetime import date as date_type
    start = datetime.strptime(trip.start_date, "%Y-%m-%d").date()
    end = datetime.strptime(trip.end_date, "%Y-%m-%d").date()
    trip_dates = []
    current = start
    while current <= end:
        date_str = current.strftime("%Y-%m-%d")
        trip_dates.append({
            "date": date_str,
            "day_name": current.strftime("%a"),
            "day_num": current.day,
            "month": current.strftime("%b"),
            "events": events_by_date.get(date_str, []),
            "is_today": current == datetime.utcnow().date(),
        })
        current += timedelta(days=1)
    
    members = get_trip_members(trip_id)
    
    return templates.TemplateResponse("trip_view.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "membership": membership,
        "next_event": next_event,
        "coming_up": coming_up,
        "all_events": all_events,
        "trip_dates": trip_dates,
        "events_by_date": events_by_date,
        "members": members,
        "can_edit": membership.can_edit(),
        "can_manage": membership.can_manage_members(),
        "categories": [c.value for c in TripEventCategory],
        "total_cost_cents": total_cost_cents,
        "remaining_budget_cents": remaining_budget_cents,
        "share_mode": False,
    })


@router.get("/shared/{trip_id}", response_class=HTMLResponse)
async def trip_view_shared(request: Request, trip_id: str, token: str = Query(...)):
    """View-only trip page via share token (no login required)."""
    trip = get_trip_by_id(trip_id)
    if not trip or not validate_share_token(trip, token):
        raise HTTPException(status_code=403, detail="Invalid or expired share link")
    
    all_events = get_trip_events(trip_id)
    
    # Group events by date for timeline (reuse logic)
    events_by_date = {}
    for event in all_events:
        date_key = event.start_datetime[:10]
        events_by_date.setdefault(date_key, []).append(event)
    
    from datetime import date as date_type
    start = datetime.strptime(trip.start_date, "%Y-%m-%d").date()
    end = datetime.strptime(trip.end_date, "%Y-%m-%d").date()
    trip_dates = []
    current = start
    while current <= end:
        date_str = current.strftime("%Y-%m-%d")
        trip_dates.append({
            "date": date_str,
            "day_name": current.strftime("%a"),
            "day_num": current.day,
            "month": current.strftime("%b"),
            "events": events_by_date.get(date_str, []),
            "is_today": current == datetime.utcnow().date(),
        })
        current += timedelta(days=1)
    
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    upcoming_events = []
    for e in all_events:
        start_dt = parse_event_start(e)
        if start_dt and start_dt >= now:
            upcoming_events.append(e)
    next_event = upcoming_events[0] if upcoming_events else None
    coming_up = upcoming_events[1:11] if len(upcoming_events) > 1 else []
    
    total_cost_cents = sum(e.cost_cents or 0 for e in all_events)
    remaining_budget_cents = None
    if trip.budget_cents:
        remaining_budget_cents = max(trip.budget_cents - total_cost_cents, 0)
    
    members = get_trip_members(trip_id)
    
    return templates.TemplateResponse("trip_view.html", {
        "request": request,
        "user": None,
        "trip": trip,
        "membership": None,
        "next_event": next_event,
        "coming_up": coming_up,
        "all_events": all_events,
        "trip_dates": trip_dates,
        "events_by_date": events_by_date,
        "members": members,
        "can_edit": False,
        "can_manage": False,
        "categories": [c.value for c in TripEventCategory],
        "total_cost_cents": total_cost_cents,
        "remaining_budget_cents": remaining_budget_cents,
        "share_mode": True,
    })


@router.get("/{trip_id}/edit", response_class=HTMLResponse)
async def trip_edit_page(request: Request, trip_id: str):
    """Edit trip details page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/edit", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    return templates.TemplateResponse("trip_edit.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "membership": membership,
    })


@router.post("/{trip_id}/edit")
async def trip_edit_submit(
    request: Request,
    trip_id: str,
    title: str = Form(...),
    destination: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    timezone: str = Form("America/Los_Angeles"),
    description: str = Form(None),
    budget: float = Form(0.0)
):
    """Handle trip edit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    try:
        budget_cents = int(float(budget) * 100)
    except Exception:
        budget_cents = None
    
    update_trip(
        trip_id,
        title=title,
        destination=destination,
        start_date=start_date,
        end_date=end_date,
        timezone=timezone,
        description=description,
        budget_cents=budget_cents
    )
    
    log_audit(
        action=AuditAction.TRIP_UPDATED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip",
        target_id=trip_id,
        details={"title": title}
    )
    
    return RedirectResponse(url=f"/trips/{trip_id}", status_code=303)


@router.post("/{trip_id}/delete")
async def trip_delete_submit(request: Request, trip_id: str):
    """Delete a trip (owner only)."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or membership.role != TripMemberRole.OWNER:
        raise HTTPException(status_code=403, detail="Only the owner can delete this trip")
    
    trip = get_trip_by_id(trip_id)
    delete_trip(trip_id)
    
    log_audit(
        action=AuditAction.TRIP_DELETED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip",
        target_id=trip_id,
        details={"title": trip.title if trip else "Unknown"}
    )
    
    return RedirectResponse(url="/trips", status_code=303)


# ─────────────────────────── ROUTES: MEMBERS ───────────────────────────

@router.get("/{trip_id}/members", response_class=HTMLResponse)
async def trip_members_page(request: Request, trip_id: str):
    """Manage trip members page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/members", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="You don't have access to this trip")
    
    trip = get_trip_by_id(trip_id)
    members = get_trip_members(trip_id)
    
    return templates.TemplateResponse("trip_members.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "members": members,
        "membership": membership,
        "can_manage": membership.can_manage_members(),
        "roles": [r.value for r in TripMemberRole],
    })


@router.get("/{trip_id}/share", response_class=HTMLResponse)
async def trip_share_page(request: Request, trip_id: str):
    """View/rotate share link for a trip (owner only)."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/share", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or membership.role != TripMemberRole.OWNER:
        raise HTTPException(status_code=403, detail="Only owners can manage sharing")
    
    trip = get_trip_by_id(trip_id)
    share_url = f"{BASE_URL}/trips/shared/{trip.id}?token={trip.share_token}"
    ics_url = f"{BASE_URL}/trips/{trip.id}/ics?token={trip.share_token}"
    
    return templates.TemplateResponse("trip_share.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "share_url": share_url,
        "ics_url": ics_url,
    })


@router.post("/{trip_id}/share/rotate")
async def rotate_trip_share_token(request: Request, trip_id: str):
    """Rotate the share token to invalidate old links."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or membership.role != TripMemberRole.OWNER:
        raise HTTPException(status_code=403, detail="Only owners can rotate share links")
    
    new_token = secrets.token_urlsafe(16)
    update_trip(trip_id, share_token=new_token)
    
    return RedirectResponse(url=f"/trips/{trip_id}/share", status_code=303)


@router.post("/{trip_id}/members/add")
async def add_member_submit(
    request: Request,
    trip_id: str,
    email: str = Form(...),
    role: str = Form("viewer")
):
    """Add a member by email."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_manage_members():
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    
    # Find user by email
    target_user = get_user_by_email(email)
    if not target_user:
        return JSONResponse({"error": f"No user found with email: {email}"}, status_code=404)
    
    # Enforce trips feature flag for invited user as well
    if not is_feature_enabled("trips", user_id=target_user.id, email=target_user.email):
        return JSONResponse({"error": "User is not eligible for trips feature"}, status_code=403)
    
    # Add member
    try:
        role_enum = TripMemberRole(role)
    except:
        role_enum = TripMemberRole.VIEWER
    
    new_member = add_trip_member(trip_id, target_user.id, role_enum, user.id)
    
    if not new_member:
        return JSONResponse({"error": "User is already a member"}, status_code=400)
    
    log_audit(
        action=AuditAction.TRIP_MEMBER_ADDED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip_member",
        target_id=new_member.id,
        details={"trip_id": trip_id, "user_email": email, "role": role}
    )
    
    return RedirectResponse(url=f"/trips/{trip_id}/members", status_code=303)


@router.post("/{trip_id}/members/{member_user_id}/role")
async def update_member_role_submit(
    request: Request,
    trip_id: str,
    member_user_id: str,
    role: str = Form(...)
):
    """Update a member's role."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_manage_members():
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    
    # Can't change own role
    if member_user_id == user.id:
        return JSONResponse({"error": "Cannot change your own role"}, status_code=400)
    
    try:
        role_enum = TripMemberRole(role)
    except:
        return JSONResponse({"error": "Invalid role"}, status_code=400)
    
    update_trip_member_role(trip_id, member_user_id, role_enum)
    
    return RedirectResponse(url=f"/trips/{trip_id}/members", status_code=303)


@router.post("/{trip_id}/members/{member_user_id}/remove")
async def remove_member_submit(
    request: Request,
    trip_id: str,
    member_user_id: str
):
    """Remove a member from the trip."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_manage_members():
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    
    # Can't remove yourself if you're the owner
    if member_user_id == user.id:
        return JSONResponse({"error": "Cannot remove yourself"}, status_code=400)
    
    target_membership = get_user_trip_membership(member_user_id, trip_id)
    if target_membership and target_membership.role == TripMemberRole.OWNER:
        return JSONResponse({"error": "Cannot remove the owner"}, status_code=400)
    
    remove_trip_member(trip_id, member_user_id)
    
    log_audit(
        action=AuditAction.TRIP_MEMBER_REMOVED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip_member",
        target_id=member_user_id,
        details={"trip_id": trip_id}
    )
    
    return RedirectResponse(url=f"/trips/{trip_id}/members", status_code=303)


# ─────────────────────────── ROUTES: EVENTS ───────────────────────────

@router.get("/{trip_id}/events/new", response_class=HTMLResponse)
async def new_event_page(request: Request, trip_id: str, date: str = None):
    """Create new event form."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/events/new", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    
    # Get user's default reminder preference
    default_reminder = 30
    if user.notification_prefs and isinstance(user.notification_prefs, dict):
        default_reminder = user.notification_prefs.get("trip_default_reminder_minutes", 30)
    
    return templates.TemplateResponse("trip_event_new.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "default_date": date or trip.start_date,
        "categories": [c.value for c in TripEventCategory],
        "reminder_options": REMINDER_OPTIONS,
        "default_reminder": default_reminder,
    })


@router.get("/{trip_id}/import/ics", response_class=HTMLResponse)
async def import_ics_page(request: Request, trip_id: str):
    """Upload ICS to import events."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/import/ics", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    
    return templates.TemplateResponse("trip_import.html", {
        "request": request,
        "user": user,
        "trip": trip,
    })


@router.post("/{trip_id}/import/ics")
async def import_ics_submit(
    request: Request,
    trip_id: str,
    ics_file: UploadFile = File(...)
):
    """Handle ICS upload and create events."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    content = ics_file.file.read().decode(errors="ignore")
    parsed = parse_ics_events(content, trip.timezone or DISPLAY_TIMEZONE)
    
    for item in parsed:
        start_raw = item["start_datetime"]
        end_raw = item["end_datetime"]
        if not start_raw:
            continue
        start_dt = datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_raw.replace("Z", "+00:00")) if end_raw else None
        try:
            validate_event_window(start_dt, end_dt, trip)
        except HTTPException:
            continue  # skip events outside trip window
        create_trip_event(
            trip_id=trip_id,
            title=item["title"],
            start_datetime=start_raw,
            category=TripEventCategory.OTHER,
            timezone=trip.timezone or DISPLAY_TIMEZONE,
            end_datetime=end_raw,
            is_all_day=item["is_all_day"],
            location_name=item.get("location_name"),
            notes=item.get("notes"),
        )
    
    return RedirectResponse(url=f"/trips/{trip_id}", status_code=303)


@router.post("/{trip_id}/events/new")
async def create_event_submit(
    request: Request,
    trip_id: str,
    title: str = Form(...),
    category: str = Form(...),
    start_date: str = Form(...),
    start_time: str = Form(None),
    end_date: str = Form(None),
    end_time: str = Form(None),
    is_all_day: bool = Form(False),
    location_name: str = Form(None),
    address: str = Form(None),
    notes: str = Form(None),
    confirmation_number: str = Form(None),
    flight_number: str = Form(None),
    departure_location: str = Form(None),
    arrival_location: str = Form(None),
    link_maps: str = Form(None),
    link_tickets: str = Form(None),
    reminder_minutes: int = Form(30),
    cost: float = Form(0.0),
):
    """Handle new event creation."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    # Build datetime strings
    try:
        start_datetime, end_datetime, start_dt, end_dt = build_event_datetimes(
            start_date, start_time, end_date, end_time, is_all_day, trip.timezone or DISPLAY_TIMEZONE
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid date or time provided")
    validate_event_window(start_dt, end_dt, trip)
    
    # Build links dict
    links = {}
    safe_maps = normalize_link(link_maps)
    safe_tickets = normalize_link(link_tickets)
    if safe_maps:
        links["maps"] = safe_maps
    if safe_tickets:
        links["tickets"] = safe_tickets
    
    try:
        cat = TripEventCategory(category)
    except:
        cat = TripEventCategory.OTHER
    
    # Validate category-specific data
    if cat in (TripEventCategory.FLIGHT, TripEventCategory.TRANSPORT):
        if not (departure_location and arrival_location):
            raise HTTPException(status_code=400, detail="Flights and transport events require departure and arrival locations")
    
    # Handle reminder - use None for all-day events, 0 means no reminder
    effective_reminder = None if is_all_day else (reminder_minutes if reminder_minutes >= 0 else 30)
    try:
        cost_cents = int(float(cost) * 100)
    except Exception:
        cost_cents = 0
    
    event = create_trip_event(
        trip_id=trip_id,
        title=title,
        start_datetime=start_datetime,
        category=cat,
        timezone=trip.timezone or DISPLAY_TIMEZONE,
        end_datetime=end_datetime,
        is_all_day=is_all_day,
        location_name=location_name,
        address=address,
        notes=notes,
        confirmation_number=confirmation_number,
        flight_number=flight_number,
        departure_location=departure_location,
        arrival_location=arrival_location,
        links=links,
        reminder_minutes=effective_reminder,
        cost_cents=cost_cents,
    )
    
    log_audit(
        action=AuditAction.TRIP_EVENT_CREATED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip_event",
        target_id=event.id,
        details={"trip_id": trip_id, "title": title}
    )
    
    return RedirectResponse(url=f"/trips/{trip_id}", status_code=303)


@router.get("/{trip_id}/events/{event_id}", response_class=HTMLResponse)
async def event_view_page(request: Request, trip_id: str, event_id: str):
    """View single event details."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/events/{event_id}", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="You don't have access to this trip")
    
    trip = get_trip_by_id(trip_id)
    event = get_trip_event_by_id(event_id)
    
    if not event or event.trip_id != trip_id:
        raise HTTPException(status_code=404, detail="Event not found")
    
    comments = get_event_comments(event_id)
    
    return templates.TemplateResponse("trip_event_view.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "event": event,
        "membership": membership,
        "can_edit": membership.can_edit(),
        "comments": comments,
    })


@router.get("/{trip_id}/events/{event_id}/edit", response_class=HTMLResponse)
async def event_edit_page(request: Request, trip_id: str, event_id: str):
    """Edit event form."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/events/{event_id}/edit", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    event = get_trip_event_by_id(event_id)
    
    if not event or event.trip_id != trip_id:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return templates.TemplateResponse("trip_event_edit.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "event": event,
        "categories": [c.value for c in TripEventCategory],
        "reminder_options": REMINDER_OPTIONS,
    })


@router.post("/{trip_id}/events/{event_id}/comments")
async def add_event_comment_submit(
    request: Request,
    trip_id: str,
    event_id: str,
    body: str = Form(...)
):
    """Add a comment to an event."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    if not body or not body.strip():
        return JSONResponse({"error": "Comment cannot be empty"}, status_code=400)
    
    event = get_trip_event_by_id(event_id)
    if not event or event.trip_id != trip_id:
        return JSONResponse({"error": "Event not found"}, status_code=404)
    
    add_event_comment(event_id, user.id, body)
    
    return RedirectResponse(url=f"/trips/{trip_id}/events/{event_id}", status_code=303)


@router.post("/{trip_id}/events/{event_id}/edit")
async def event_edit_submit(
    request: Request,
    trip_id: str,
    event_id: str,
    title: str = Form(...),
    category: str = Form(...),
    start_date: str = Form(...),
    start_time: str = Form(None),
    end_date: str = Form(None),
    end_time: str = Form(None),
    is_all_day: bool = Form(False),
    location_name: str = Form(None),
    address: str = Form(None),
    notes: str = Form(None),
    confirmation_number: str = Form(None),
    flight_number: str = Form(None),
    departure_location: str = Form(None),
    arrival_location: str = Form(None),
    link_maps: str = Form(None),
    link_tickets: str = Form(None),
    reminder_minutes: int = Form(30),
    cost: float = Form(0.0),
):
    """Handle event edit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    # Build datetime strings
    try:
        start_datetime, end_datetime, start_dt, end_dt = build_event_datetimes(
            start_date, start_time, end_date, end_time, is_all_day, trip.timezone or DISPLAY_TIMEZONE
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid date or time provided")
    validate_event_window(start_dt, end_dt, trip)
    
    # Build links dict
    links = {}
    safe_maps = normalize_link(link_maps)
    safe_tickets = normalize_link(link_tickets)
    if safe_maps:
        links["maps"] = safe_maps
    if safe_tickets:
        links["tickets"] = safe_tickets
    
    try:
        cat = TripEventCategory(category)
    except:
        cat = TripEventCategory.OTHER
    
    if cat in (TripEventCategory.FLIGHT, TripEventCategory.TRANSPORT):
        if not (departure_location and arrival_location):
            raise HTTPException(status_code=400, detail="Flights and transport events require departure and arrival locations")
    
    # Handle reminder - use None for all-day events, 0 means no reminder
    # Reset reminder_sent to 0 if time changed so notification can be resent
    effective_reminder = None if is_all_day else (reminder_minutes if reminder_minutes >= 0 else 30)
    try:
        cost_cents = int(float(cost) * 100)
    except Exception:
        cost_cents = 0
    
    update_trip_event(
        event_id,
        title=title,
        start_datetime=start_datetime,
        category=cat,
        timezone=trip.timezone or DISPLAY_TIMEZONE,
        end_datetime=end_datetime,
        is_all_day=is_all_day,
        location_name=location_name,
        address=address,
        notes=notes,
        confirmation_number=confirmation_number,
        flight_number=flight_number,
        departure_location=departure_location,
        arrival_location=arrival_location,
        links=links,
        reminder_minutes=effective_reminder,
        reminder_sent=False,  # Reset so reminder can be sent for new time
        cost_cents=cost_cents,
    )
    
    log_audit(
        action=AuditAction.TRIP_EVENT_UPDATED,
        actor_type="user",
        actor_id=user.id,
        actor_name=user.name,
        target_type="trip_event",
        target_id=event_id,
        details={"trip_id": trip_id, "title": title}
    )
    
    return RedirectResponse(url=f"/trips/{trip_id}", status_code=303)


@router.post("/{trip_id}/events/{event_id}/delete")
async def event_delete_submit(request: Request, trip_id: str, event_id: str):
    """Delete an event."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        raise HTTPException(status_code=403, detail="You don't have edit access")
    
    event = get_trip_event_by_id(event_id)
    if event and event.trip_id == trip_id:
        delete_trip_event(event_id)
        
        log_audit(
            action=AuditAction.TRIP_EVENT_DELETED,
            actor_type="user",
            actor_id=user.id,
            actor_name=user.name,
            target_type="trip_event",
            target_id=event_id,
            details={"trip_id": trip_id, "title": event.title}
        )
    
    return RedirectResponse(url=f"/trips/{trip_id}", status_code=303)


# ─────────────────────────── ROUTES: PDF UPLOAD ───────────────────────────

@router.get("/{trip_id}/pdf", response_class=HTMLResponse)
async def trip_pdf_page(request: Request, trip_id: str):
    """View/upload PDF itinerary page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next=/trips/{trip_id}/pdf", status_code=303)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="You don't have access to this trip")
    
    trip = get_trip_by_id(trip_id)
    
    return templates.TemplateResponse("trip_pdf.html", {
        "request": request,
        "user": user,
        "trip": trip,
        "membership": membership,
        "can_edit": membership.can_edit(),
    })


@router.post("/{trip_id}/pdf/upload")
async def upload_pdf_submit(
    request: Request,
    trip_id: str,
    pdf_file: UploadFile = File(...)
):
    """Upload PDF itinerary."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership or not membership.can_edit():
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    
    _validate_pdf_upload(pdf_file)
    
    trip = get_trip_by_id(trip_id)
    if not trip:
        return JSONResponse({"error": "Trip not found"}, status_code=404)
    
    filepath = save_trip_pdf(trip_id, pdf_file, existing_path=trip.pdf_itinerary_path)
    
    return RedirectResponse(url=f"/trips/{trip_id}/pdf", status_code=303)


@router.get("/{trip_id}/pdf/view")
async def view_pdf(request: Request, trip_id: str):
    """Serve the PDF file for viewing."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    ensure_trips_feature(user)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        raise HTTPException(status_code=403, detail="Access denied")
    
    trip = get_trip_by_id(trip_id)
    if not trip or not trip.pdf_itinerary_path:
        raise HTTPException(status_code=404, detail="No PDF uploaded")
    
    if not os.path.exists(trip.pdf_itinerary_path):
        raise HTTPException(status_code=404, detail="PDF file not found")
    
    return FileResponse(
        trip.pdf_itinerary_path,
        media_type="application/pdf",
        filename=f"{trip.title}_itinerary.pdf"
    )


# ─────────────────────────── API ENDPOINTS ───────────────────────────

@router.get("/api/{trip_id}/events")
async def api_get_events(request: Request, trip_id: str, date: str = None):
    """API: Get events for a trip (optionally filtered by date)."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    try:
        ensure_trips_feature(user)
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    if date:
        events = get_events_by_date(trip_id, date)
    else:
        events = get_trip_events(trip_id)
    
    return JSONResponse({
        "events": [e.to_dict() for e in events]
    })


@router.get("/api/{trip_id}/upcoming")
async def api_get_upcoming(request: Request, trip_id: str, limit: int = 10):
    """API: Get upcoming events."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    try:
        ensure_trips_feature(user)
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    
    membership = get_user_trip_membership(user.id, trip_id)
    if not membership:
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    events = get_upcoming_events(trip_id, limit)
    
    return JSONResponse({
        "events": [e.to_dict() for e in events]
    })


@router.get("/{trip_id}/ics")
async def trip_ics(request: Request, trip_id: str, token: str = Query(None)):
    """Download ICS feed for a trip (member or share token)."""
    trip = get_trip_by_id(trip_id)
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    if token:
        if not validate_share_token(trip, token):
            raise HTTPException(status_code=403, detail="Invalid share token")
    else:
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        ensure_trips_feature(user)
        membership = get_user_trip_membership(user.id, trip_id)
        if not membership:
            raise HTTPException(status_code=403, detail="Access denied")
    
    events = get_trip_events(trip_id)
    ics_body = build_trip_ics(trip, events)
    return Response(content=ics_body, media_type="text/calendar")


# ─────────────────────────── TRIP REMINDERS ───────────────────────────

REMINDER_OPTIONS = [
    (5, "5 minutes before"),
    (15, "15 minutes before"),
    (30, "30 minutes before"),
    (60, "1 hour before"),
    (180, "3 hours before"),
    (1440, "1 day before"),
]

def get_pending_trip_reminders() -> List[Dict[str, Any]]:
    """
    Get trip events that need reminders sent.
    
    Returns events where:
    - reminder_minutes is set (not NULL)
    - reminder_sent is false
    - is_all_day is false (only timed events get reminders)
    - start_datetime minus reminder_minutes is <= now
    
    Returns list of dicts with event, trip, and member info.
    """
    conn = db()
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    
    # Get candidate events (filtering by reminder_sent/all-day; timing handled in Python for timezone safety)
    events = conn.execute("""
        SELECT 
            e.*,
            t.title as trip_title,
            t.destination as trip_destination,
            t.timezone as trip_timezone
        FROM trip_events e
        JOIN trips t ON t.id = e.trip_id
        WHERE e.reminder_minutes IS NOT NULL
          AND e.reminder_sent = 0
          AND e.is_all_day = 0
    """).fetchall()
    
    results = []
    for event_row in events:
        event = _row_to_trip_event(event_row)
        start_dt = parse_event_start(event)
        if not start_dt:
            continue
        
        reminder_at = start_dt - timedelta(minutes=event.reminder_minutes or 0)
        if reminder_at > now:
            continue
        
        # Get all members of this trip who have push enabled and trip reminders enabled
        members = conn.execute("""
            SELECT tm.user_id, u.email, u.name, u.notification_prefs
            FROM trip_members tm
            JOIN users u ON u.id = tm.user_id
            WHERE tm.trip_id = ?
        """, (event.trip_id,)).fetchall()
        
        eligible_members = []
        for member in members:
            # Parse notification preferences
            prefs = {}
            if member["notification_prefs"]:
                try:
                    prefs = json.loads(member["notification_prefs"])
                except:
                    pass
            
            # Check if user has trip reminders enabled
            trip_reminders_enabled = prefs.get("trip_reminders_enabled", True)
            
            if trip_reminders_enabled:
                eligible_members.append({
                    "user_id": member["user_id"],
                    "email": member["email"],
                    "name": member["name"],
                })
        
        results.append({
            "event": event,
            "trip_title": event_row["trip_title"],
            "trip_destination": event_row["trip_destination"],
            "trip_timezone": event_row["trip_timezone"],
            "members": eligible_members,
        })
    
    conn.close()
    return results


def mark_reminder_sent(event_id: str) -> bool:
    """Mark a trip event reminder as sent."""
    conn = db()
    conn.execute(
        "UPDATE trip_events SET reminder_sent = 1 WHERE id = ?",
        (event_id,)
    )
    conn.commit()
    conn.close()
    return True


def reset_reminder(event_id: str) -> None:
    """Reset reminder_sent so it can be retried."""
    conn = db()
    conn.execute(
        "UPDATE trip_events SET reminder_sent = 0 WHERE id = ?",
        (event_id,)
    )
    conn.commit()
    conn.close()


def claim_reminder_send(event_id: str) -> bool:
    """
    Attempt to atomically claim a reminder for sending by flipping reminder_sent to 1.
    Returns True if this worker claimed it.
    """
    conn = db()
    now = utc_now_iso()
    cur = conn.execute(
        "UPDATE trip_events SET reminder_sent = 1, updated_at = ? WHERE id = ? AND reminder_sent = 0",
        (now, event_id)
    )
    conn.commit()
    claimed = cur.rowcount > 0
    conn.close()
    return claimed


def send_trip_event_reminder(event: TripEvent, trip_title: str, member_email: str) -> bool:
    """
    Send a push notification reminder for a trip event.
    
    Returns True if notification was sent successfully.
    """
    from app.main import send_push_notification, BASE_URL
    
    # Format the time for display
    try:
        event_time = datetime.fromisoformat(event.start_datetime.replace("Z", "+00:00"))
        time_str = event_time.strftime("%I:%M %p")
    except:
        time_str = event.start_datetime
    
    # Build notification body
    body_parts = [time_str]
    if event.location_name:
        body_parts.append(event.location_name)
    elif event.departure_location:
        body_parts.append(f"From {event.departure_location}")
    
    body = " • ".join(body_parts)
    
    # Deep link to the trip page with event focus
    url = f"{BASE_URL}/trips/{event.trip_id}?event={event.id}"
    
    result = send_push_notification(
        email=member_email,
        title=f"Up next: {event.title}",
        body=body,
        url=url,
        tag=f"trip-reminder-{event.id}",
        data={
            "type": "trip_reminder",
            "trip_id": event.trip_id,
            "trip_title": trip_title,
            "event_id": event.id,
            "event_title": event.title,
            "category": event.category.value if event.category else "other",
        }
    )
    
    return result.get("sent", 0) > 0


async def process_trip_reminders():
    """
    Process all pending trip reminders.
    
    This should be called periodically (e.g., every minute) by a background task.
    """
    pending = get_pending_trip_reminders()
    
    for item in pending:
        event = item["event"]
        trip_title = item["trip_title"]
        members = item["members"]
        
        # Try to claim this reminder to avoid duplicate sends across workers
        if not claim_reminder_send(event.id):
            continue
        
        sent_count = 0
        for member in members:
            try:
                if send_trip_event_reminder(event, trip_title, member["email"]):
                    sent_count += 1
                    logger.info(f"Trip reminder sent: {event.title} to {member['email']}")
            except Exception as e:
                logger.error(f"Failed to send trip reminder to {member['email']}: {e}")
        
        # If nothing was delivered, allow retry later
        if sent_count == 0 and members:
            reset_reminder(event.id)
        else:
            mark_reminder_sent(event.id)
        logger.info(f"Trip reminder processed: {event.title} ({sent_count}/{len(members)} sent)")


# Background task runner
_reminder_task_running = False

async def _reminder_loop():
    """Background loop that checks for reminders every minute."""
    global _reminder_task_running
    import asyncio
    
    while _reminder_task_running:
        try:
            await process_trip_reminders()
        except Exception as e:
            logger.error(f"Error processing trip reminders: {e}")
        
        await asyncio.sleep(60)  # Check every minute


def start_trip_reminder_scheduler():
    """Start the background trip reminder scheduler in a separate thread."""
    global _reminder_task_running
    import asyncio
    import threading
    
    if _reminder_task_running:
        return  # Already running
    
    _reminder_task_running = True
    
    def run_async():
        """Run the reminder loop in its own event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_reminder_loop())
    
    thread = threading.Thread(target=run_async, daemon=True)
    thread.start()
    logger.info("Trip reminder scheduler started")


def stop_trip_reminder_scheduler():
    """Stop the background trip reminder scheduler."""
    global _reminder_task_running
    _reminder_task_running = False
    logger.info("Trip reminder scheduler stopped")
