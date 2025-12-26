"""
Smoke tests for the Trips feature.

These tests verify that:
1. Trip routes are accessible (with auth)
2. Trip access control is enforced
3. Basic CRUD operations work
"""

import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import sys
import pytest
from fastapi.testclient import TestClient


TEST_ROOT = Path(__file__).resolve().parent
DATA_DIR = TEST_ROOT / "tmp_data"
UPLOAD_DIR = TEST_ROOT / "tmp_uploads"
TRIP_UPLOADS_DIR = TEST_ROOT / "tmp_trip_uploads"
sys.path.append(str(TEST_ROOT.parent))

# Keep tests self-contained
for path in (DATA_DIR, UPLOAD_DIR, TRIP_UPLOADS_DIR):
    path.mkdir(parents=True, exist_ok=True)

DB_FILE = DATA_DIR / "app.db"

# Delete existing DB to ensure clean state with new tables
if DB_FILE.exists():
    DB_FILE.unlink()

os.environ["DB_PATH"] = str(DB_FILE)
os.environ["UPLOAD_DIR"] = str(UPLOAD_DIR)
os.environ["TRIP_UPLOADS_DIR"] = str(TRIP_UPLOADS_DIR)
os.environ["DEMO_MODE"] = "1"
os.environ["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "admin-test-password")
os.environ.setdefault("BASE_URL", "http://testserver")
os.environ.setdefault("LOG_LEVEL", "ERROR")

from app.main import app, ensure_migrations, init_db
from app.auth import create_user, create_user_session, hash_password, db, init_auth_tables


def init_sandbox_db():
    """Ensure the SQLite schema exists."""
    init_db()
    init_auth_tables()
    ensure_migrations()


def create_test_user(email: str = "trip-test@example.com", name: str = "Trip Tester"):
    """Create a test user and return (user_id, session_token)."""
    init_sandbox_db()
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    user_id = str(uuid.uuid4())
    password_hash = hash_password("testpass123")
    
    try:
        conn.execute("""
            INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?)
        """, (user_id, email.lower(), name, password_hash, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        # User already exists, get their ID
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email.lower(),)).fetchone()
        user_id = row["id"] if row else user_id
    
    conn.close()
    
    session_token = create_user_session(user_id, device_info="Test", ip_address="127.0.0.1")
    return user_id, session_token


def create_test_trip(owner_user_id: str, title: str = "Vegas Test Trip"):
    """Create a test trip and return trip_id."""
    from app.trips import create_trip
    
    trip = create_trip(
        title=title,
        destination="Las Vegas, Nevada",
        start_date="2025-03-15",
        end_date="2025-03-20",
        timezone="America/Los_Angeles",
        created_by_user_id=owner_user_id
    )
    return trip.id


# ─────────────────────────── FIXTURES ───────────────────────────

@pytest.fixture
def client():
    """Test client fixture."""
    init_sandbox_db()
    return TestClient(app)


@pytest.fixture
def auth_user():
    """Create an authenticated user and return (user_id, session_token)."""
    return create_test_user()


@pytest.fixture
def auth_user2():
    """Create a second authenticated user."""
    return create_test_user("trip-test2@example.com", "Trip Tester 2")


@pytest.fixture
def trip_with_owner(auth_user):
    """Create a trip with an owner user."""
    user_id, session_token = auth_user
    trip_id = create_test_trip(user_id)
    return trip_id, user_id, session_token


# ─────────────────────────── TESTS ───────────────────────────

class TestTripsAccess:
    """Test trip access control."""
    
    def test_trips_list_requires_auth(self, client):
        """Trips list should redirect to login if not authenticated."""
        resp = client.get("/trips", follow_redirects=False)
        assert resp.status_code == 303
        assert "/auth/login" in resp.headers.get("location", "")
    
    def test_trips_list_authenticated(self, client, auth_user):
        """Authenticated user can access trips list."""
        user_id, session_token = auth_user
        resp = client.get("/trips", cookies={"user_session": session_token})
        assert resp.status_code == 200
        assert "My Trips" in resp.text
    
    def test_trip_view_requires_membership(self, client, trip_with_owner, auth_user2):
        """Non-members cannot view a trip."""
        trip_id, owner_id, owner_token = trip_with_owner
        _, other_token = auth_user2
        
        resp = client.get(f"/trips/{trip_id}", cookies={"user_session": other_token})
        assert resp.status_code == 403
    
    def test_trip_view_owner_access(self, client, trip_with_owner):
        """Owner can view their trip."""
        trip_id, owner_id, owner_token = trip_with_owner
        
        resp = client.get(f"/trips/{trip_id}", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        assert "Vegas Test Trip" in resp.text


class TestTripsCreate:
    """Test trip creation."""
    
    def test_create_trip_page(self, client, auth_user):
        """New trip page loads."""
        _, session_token = auth_user
        resp = client.get("/trips/new", cookies={"user_session": session_token})
        assert resp.status_code == 200
        assert "Create New Trip" in resp.text
    
    def test_create_trip_submit(self, client, auth_user):
        """Create trip form submission works."""
        _, session_token = auth_user
        
        resp = client.post(
            "/trips/new",
            data={
                "title": "New York Adventure",
                "destination": "New York City",
                "start_date": "2025-06-01",
                "end_date": "2025-06-05",
                "timezone": "America/New_York",
            },
            cookies={"user_session": session_token},
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "/trips/" in resp.headers.get("location", "")


class TestTripMembers:
    """Test trip member management."""
    
    def test_members_page_owner(self, client, trip_with_owner):
        """Owner can view members page."""
        trip_id, _, owner_token = trip_with_owner
        
        resp = client.get(f"/trips/{trip_id}/members", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        assert "Trip Members" in resp.text
    
    def test_add_member(self, client, trip_with_owner, auth_user2):
        """Owner can add a member."""
        trip_id, _, owner_token = trip_with_owner
        user2_id, user2_token = auth_user2
        
        # Get user2's email
        conn = db()
        user2 = conn.execute("SELECT email FROM users WHERE id = ?", (user2_id,)).fetchone()
        conn.close()
        
        resp = client.post(
            f"/trips/{trip_id}/members/add",
            data={"email": user2["email"], "role": "viewer"},
            cookies={"user_session": owner_token},
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        
        # Verify user2 can now view the trip
        resp = client.get(f"/trips/{trip_id}", cookies={"user_session": user2_token})
        assert resp.status_code == 200


class TestTripEvents:
    """Test trip event CRUD."""
    
    def test_create_event_page(self, client, trip_with_owner):
        """Event creation page loads."""
        trip_id, _, owner_token = trip_with_owner
        
        resp = client.get(f"/trips/{trip_id}/events/new", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        assert "Add Event" in resp.text
    
    def test_create_event_submit(self, client, trip_with_owner):
        """Event creation works."""
        trip_id, _, owner_token = trip_with_owner
        
        resp = client.post(
            f"/trips/{trip_id}/events/new",
            data={
                "title": "Check in at Bellagio",
                "category": "hotel",
                "start_date": "2025-03-15",
                "start_time": "15:00",
                "location_name": "Bellagio Hotel",
                "address": "3600 S Las Vegas Blvd",
            },
            cookies={"user_session": owner_token},
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        
        # Verify event appears on trip page
        resp = client.get(f"/trips/{trip_id}", cookies={"user_session": owner_token})
        assert "Check in at Bellagio" in resp.text


class TestTripPDF:
    """Test PDF upload functionality."""
    
    def test_pdf_page_loads(self, client, trip_with_owner):
        """PDF page loads."""
        trip_id, _, owner_token = trip_with_owner
        
        resp = client.get(f"/trips/{trip_id}/pdf", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        assert "PDF Itinerary" in resp.text


class TestTripAPI:
    """Test trip API endpoints."""
    
    def test_api_events(self, client, trip_with_owner):
        """API returns events JSON."""
        trip_id, _, owner_token = trip_with_owner
        
        # First create an event
        client.post(
            f"/trips/{trip_id}/events/new",
            data={
                "title": "API Test Event",
                "category": "activity",
                "start_date": "2025-03-16",
            },
            cookies={"user_session": owner_token},
            follow_redirects=False
        )
        
        resp = client.get(f"/trips/api/{trip_id}/events", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert len(data["events"]) > 0


class TestTripReminders:
    """Test trip reminder functionality."""
    
    def test_create_event_with_reminder(self, client, trip_with_owner):
        """Events can be created with reminder settings."""
        trip_id, _, owner_token = trip_with_owner
        
        # Create event with 60-minute reminder
        resp = client.post(
            f"/trips/{trip_id}/events/new",
            data={
                "title": "Reminder Test Event",
                "category": "activity",
                "start_date": "2025-03-16",
                "start_time": "14:00",
                "reminder_minutes": "60",
            },
            cookies={"user_session": owner_token},
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        
        # Verify event has reminder in API response
        resp = client.get(f"/trips/api/{trip_id}/events", cookies={"user_session": owner_token})
        data = resp.json()
        events = [e for e in data["events"] if e["title"] == "Reminder Test Event"]
        assert len(events) == 1
        assert events[0]["reminder_minutes"] == 60
        assert events[0]["reminder_sent"] == False
    
    def test_all_day_event_no_reminder(self, client, trip_with_owner):
        """All-day events don't get reminders."""
        trip_id, _, owner_token = trip_with_owner
        
        # Create all-day event
        resp = client.post(
            f"/trips/{trip_id}/events/new",
            data={
                "title": "All Day Event",
                "category": "hotel",
                "start_date": "2025-03-16",
                "is_all_day": "true",
                "reminder_minutes": "30",  # Should be ignored for all-day
            },
            cookies={"user_session": owner_token},
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        
        # Verify event has no reminder
        resp = client.get(f"/trips/api/{trip_id}/events", cookies={"user_session": owner_token})
        data = resp.json()
        events = [e for e in data["events"] if e["title"] == "All Day Event"]
        assert len(events) == 1
        assert events[0]["reminder_minutes"] is None
    
    def test_reminder_display_in_event_view(self, client, trip_with_owner):
        """Event view page shows reminder information."""
        trip_id, _, owner_token = trip_with_owner
        
        # Create event with reminder
        resp = client.post(
            f"/trips/{trip_id}/events/new",
            data={
                "title": "View Reminder Event",
                "category": "activity",
                "start_date": "2025-03-16",
                "start_time": "09:00",
                "reminder_minutes": "30",
            },
            cookies={"user_session": owner_token},
            follow_redirects=True
        )
        
        # Find the event ID from API
        resp = client.get(f"/trips/api/{trip_id}/events", cookies={"user_session": owner_token})
        data = resp.json()
        events = [e for e in data["events"] if e["title"] == "View Reminder Event"]
        event_id = events[0]["id"]
        
        # View event page
        resp = client.get(f"/trips/{trip_id}/events/{event_id}", cookies={"user_session": owner_token})
        assert resp.status_code == 200
        assert "Reminder" in resp.text
        assert "30 minutes before" in resp.text


# Run standalone
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
