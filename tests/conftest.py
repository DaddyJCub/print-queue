"""
Shared pytest fixtures and test utilities for Printellect tests.

This module provides:
- Database setup/teardown with isolation
- Common test data fixtures (requests, builds, users, store items)
- TestClient setup with proper environment configuration
- Helper functions for creating test entities
"""
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List

import pytest
from fastapi.testclient import TestClient

# ─────────────────────────── PATH SETUP ───────────────────────────

TEST_ROOT = Path(__file__).resolve().parent
DATA_DIR = TEST_ROOT / "tmp_data"
UPLOAD_DIR = TEST_ROOT / "tmp_uploads"

# Ensure test directories exist
for path in (DATA_DIR, UPLOAD_DIR):
    path.mkdir(parents=True, exist_ok=True)

DB_FILE = DATA_DIR / "app.db"

# ─────────────────────────── ENVIRONMENT ───────────────────────────

def configure_test_environment():
    """Configure environment variables for testing."""
    os.environ["DB_PATH"] = str(DB_FILE)
    os.environ["UPLOAD_DIR"] = str(UPLOAD_DIR)
    os.environ["DEMO_MODE"] = "1"  # Avoid external printer calls
    os.environ["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "admin-test-password")
    os.environ.setdefault("BASE_URL", "http://testserver")
    os.environ.setdefault("LOG_LEVEL", "WARNING")  # Reduce noise, but show warnings
    os.environ.setdefault("TURNSTILE_SECRET_KEY", "")  # Disable turnstile in tests
    os.environ["TEST_MODE"] = "1"  # Keep stdio passthrough for stable TestClient lifespan

configure_test_environment()

# Now we can import app modules
import sys
sys.path.insert(0, str(TEST_ROOT.parent))

from app.main import app, ensure_migrations, init_db  # noqa: E402

# ─────────────────────────── DATABASE HELPERS ───────────────────────────

def init_test_db():
    """Initialize the test database schema."""
    init_db()
    ensure_migrations()

def get_test_db():
    """Get a database connection for test operations."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def clear_all_test_data():
    """Clear all test data from database tables."""
    init_test_db()
    conn = get_test_db()
    tables = [
        "requests", "builds", "build_snapshots", "build_status_events",
        "status_events", "files", "store_items", "store_item_files",
        "push_subscriptions", "email_lookup_tokens", "request_messages",
        "users", "admins", "feedback", "request_templates",
        "request_assignments", "notification_prefs",
        "request_shipping", "request_shipping_rate_snapshots", "request_shipping_events",
        "device_update_status", "releases", "device_state", "commands",
        "pairing_sessions", "device_tokens", "devices",
    ]
    for table in tables:
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass  # Table may not exist
    conn.commit()
    conn.close()

def now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

# ─────────────────────────── TEST DATA FACTORIES ───────────────────────────

def create_test_request(
    status: str = "NEW",
    requester_name: str = "Test User",
    requester_email: str = "test@example.com",
    print_name: str = "Test Print",
    printer: str = "ANY",
    material: str = "PLA",
    colors: str = "Black",
    with_file: bool = False,
    with_builds: int = 0,
    fulfillment_method: str = "pickup",
    with_shipping: bool = False,
) -> Dict[str, Any]:
    """
    Create a test print request with optional files and builds.
    
    Returns dict with: request_id, access_token, and created entity details.
    """
    conn = get_test_db()
    rid = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)
    now = now_iso()
    
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            print_name, printer, material, colors, status, access_token,
            total_builds, completed_builds, failed_builds, fulfillment_method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    """, (
        rid, now, now, requester_name, requester_email,
        print_name, printer, material, colors, status, access_token,
        max(1, with_builds), fulfillment_method
    ))
    
    conn.execute("""
        INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
        VALUES (?, ?, ?, NULL, ?, 'Test request created')
    """, (str(uuid.uuid4()), rid, now, status))
    
    file_ids = []
    if with_file:
        file_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes)
            VALUES (?, ?, ?, 'test_model.stl', 'test_stored.stl', 1024)
        """, (file_id, rid, now))
        file_ids.append(file_id)
    
    build_ids = []
    if with_builds > 0:
        for i in range(with_builds):
            build_id = str(uuid.uuid4())
            build_status = "READY" if i > 0 else ("PRINTING" if status == "PRINTING" else "READY")
            conn.execute("""
                INSERT INTO builds (
                    id, request_id, build_number, status, printer, material, colors,
                    print_name, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                build_id, rid, i + 1, build_status, printer, material, colors,
                f"Build {i + 1}", now, now
            ))
            build_ids.append(build_id)
        
        # Update request with active build if printing
        if status == "PRINTING" and build_ids:
            conn.execute(
                "UPDATE requests SET active_build_id = ? WHERE id = ?",
                (build_ids[0], rid)
            )

    if fulfillment_method == "shipping" or with_shipping:
        conn.execute("""
            INSERT INTO request_shipping (
                id, request_id, created_at, updated_at, shipping_status,
                recipient_name, address_line1, city, state, postal_code, country
            ) VALUES (?, ?, ?, ?, 'REQUESTED', ?, ?, ?, ?, ?, 'US')
        """, (
            str(uuid.uuid4()), rid, now, now,
            requester_name, "123 Test St", "Austin", "TX", "78701"
        ))
    
    conn.commit()
    conn.close()
    
    # Create email lookup token for my-requests access
    requester_token = create_email_lookup_token(requester_email)
    
    return {
        "request_id": rid,
        "access_token": access_token,
        "requester_token": requester_token,
        "requester_email": requester_email,
        "file_ids": file_ids,
        "build_ids": build_ids,
        "status": status,
    }

def create_email_lookup_token(email: str) -> str:
    """Create an email lookup token for my-requests access."""
    conn = get_test_db()
    token = secrets.token_urlsafe(24)
    now = datetime.utcnow()
    expires = now + timedelta(days=30)
    
    conn.execute("""
        INSERT INTO email_lookup_tokens (id, email, token, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        str(uuid.uuid4()), email, token,
        now.isoformat(timespec="seconds") + "Z",
        expires.isoformat(timespec="seconds") + "Z"
    ))
    conn.commit()
    conn.close()
    return token

def create_store_item(
    name: str = "Test Item",
    category: str = "Test",
    is_active: bool = True,
) -> str:
    """Create a test store item. Returns item_id."""
    conn = get_test_db()
    item_id = str(uuid.uuid4())
    now = now_iso()
    
    conn.execute("""
        INSERT INTO store_items (
            id, name, description, category, material, colors,
            estimated_time_minutes, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        item_id, name, f"Test {name}", category, "PLA", "Blue",
        30, 1 if is_active else 0, now, now
    ))
    conn.commit()
    conn.close()
    return item_id

def create_test_user(
    email: str = "user@example.com",
    display_name: str = "Test User",
    password_hash: str = None,
) -> str:
    """Create a test user account. Returns user_id."""
    conn = get_test_db()
    user_id = str(uuid.uuid4())
    now = now_iso()
    
    # Simple password hash for testing (not secure, but fine for tests)
    if password_hash is None:
        import hashlib
        password_hash = hashlib.sha256("testpassword".encode()).hexdigest()
    
    conn.execute("""
        INSERT INTO users (
            id, email, display_name, password_hash, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, email, display_name, password_hash, now, now))
    conn.commit()
    conn.close()
    return user_id

# ─────────────────────────── PYTEST FIXTURES ───────────────────────────

@pytest.fixture(scope="session")
def test_client():
    """
    Session-scoped test client. Use for tests that don't need data isolation.
    """
    with TestClient(app) as client:
        init_test_db()
        yield client

@pytest.fixture
def client():
    """
    Function-scoped test client with clean database state.
    Each test gets a fresh database.
    """
    clear_all_test_data()
    with TestClient(app) as client:
        yield client

@pytest.fixture
def admin_client():
    """
    Test client pre-authenticated as admin.
    """
    clear_all_test_data()
    with TestClient(app) as client:
        client.cookies.set("admin_pw", os.environ["ADMIN_PASSWORD"])
        yield client

@pytest.fixture
def sample_request(client):
    """Create a basic test request and return its data."""
    return create_test_request()

@pytest.fixture
def printing_request(client):
    """Create a request in PRINTING status with builds."""
    return create_test_request(
        status="PRINTING",
        with_builds=3,
        print_name="Multi-Build Print"
    )

@pytest.fixture
def store_item(client):
    """Create a test store item and return its ID."""
    return create_store_item()

# ─────────────────────────── ASSERTION HELPERS ───────────────────────────

def assert_html_contains(response, *texts: str):
    """Assert that HTML response contains all specified text strings."""
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    for text in texts:
        assert text in response.text, f"Expected '{text}' in response"

def assert_html_not_contains(response, *texts: str):
    """Assert that HTML response does not contain any of the specified strings."""
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    for text in texts:
        assert text not in response.text, f"Did not expect '{text}' in response"

def assert_json_success(response):
    """Assert JSON response indicates success."""
    assert response.status_code == 200
    data = response.json()
    assert data.get("ok") is True or data.get("success") is True

def assert_json_error(response, expected_status: int = 400):
    """Assert JSON response indicates error."""
    assert response.status_code == expected_status
    data = response.json()
    assert data.get("ok") is False or "error" in data or "detail" in data

def assert_redirect_to(response, path: str):
    """Assert response redirects to the specified path."""
    assert response.status_code in (302, 303, 307), f"Expected redirect, got {response.status_code}"
    location = response.headers.get("location", "")
    assert path in location, f"Expected redirect to '{path}', got '{location}'"
