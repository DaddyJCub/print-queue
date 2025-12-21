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
sys.path.append(str(TEST_ROOT.parent))

# Keep tests self-contained and inside the repo sandbox
for path in (DATA_DIR, UPLOAD_DIR):
    path.mkdir(parents=True, exist_ok=True)

DB_FILE = DATA_DIR / "app.db"
if DB_FILE.exists():
    DB_FILE.unlink()

os.environ["DB_PATH"] = str(DB_FILE)
os.environ["UPLOAD_DIR"] = str(UPLOAD_DIR)
os.environ["DEMO_MODE"] = "1"  # Avoid external printer calls during tests
os.environ["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "admin-test-password")
os.environ.setdefault("BASE_URL", "http://testserver")
os.environ.setdefault("LOG_LEVEL", "ERROR")  # Silence noisy demo logs during smoke tests

from app.main import app, ensure_migrations, init_db  # noqa: E402


def init_sandbox_db():
    """Ensure the SQLite schema exists for the sandbox DB."""
    init_db()
    ensure_migrations()


def clear_test_data():
    """Remove test data to keep smoke checks isolated."""
    init_sandbox_db()
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    tables = [
        "requests",
        "builds",
        "build_snapshots",
        "status_events",
        "files",
        "store_items",
        "store_item_files",
        "push_subscriptions",
        "email_lookup_tokens",
        "request_messages",
    ]
    for table in tables:
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            # Table may not exist yet in some environments
            pass
    conn.commit()
    conn.close()


def seed_store_item():
    """Insert a minimal active store item for route smoke tests."""
    init_sandbox_db()
    conn = sqlite3.connect(DB_FILE)
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    item_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO store_items (
            id, name, description, category, material, colors,
            estimated_time_minutes, image_data, link_url, notes,
            is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            item_id,
            "Test Gadget",
            "Demo item for smoke tests",
            "Gadgets",
            "PLA",
            "Blue",
            45,
            None,
            None,
            "Smoke test fixture",
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return item_id


def seed_multi_build_request(include_snapshot: bool = True):
    """
    Create a request with multiple builds across states and optional snapshots.
    Returns dict with keys: request_id, requester_token, access_token, build_ids.
    """
    init_sandbox_db()
    clear_test_data()

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    now = datetime.utcnow()
    rid = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(16)
    requester_email = "multi-build@example.com"
    requester_name = "Multi Build User"

    created_at = now.isoformat(timespec="seconds") + "Z"

    conn.execute(
        """
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            created_at,
            created_at,
            requester_name,
            requester_email,
            "ANY",
            "PLA",
            "Black",
            None,
            "Multi-build smoke test",
            "IN_PROGRESS",
        ),
    )

    build_statuses = [
        ("READY", None, None),
        ("PRINTING", now - timedelta(minutes=10), None),
        ("COMPLETED", now - timedelta(hours=2), now - timedelta(hours=1, minutes=30)),
        ("COMPLETED", now - timedelta(hours=1), now - timedelta(minutes=45)),
        ("FAILED", now - timedelta(hours=3), None),
    ]

    build_ids = []
    printing_build_id = None
    completed_with_photo = None
    for idx, (status, started_at, completed_at) in enumerate(build_statuses, start=1):
        build_id = str(uuid.uuid4())
        build_ids.append(build_id)
        if status == "PRINTING":
            printing_build_id = build_id
        if status == "COMPLETED" and include_snapshot and completed_with_photo is None:
            completed_with_photo = build_id

        conn.execute(
            """
            INSERT INTO builds (
                id, request_id, build_number, status, printer, material, colors,
                print_name, print_time_minutes, slicer_estimate_minutes,
                started_at, completed_at, progress, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                build_id,
                rid,
                idx,
                status,
                "ADVENTURER_4" if status in ("PRINTING", "COMPLETED") else "ANY",
                "PLA",
                "Black",
                f"Build {idx}",
                90,
                100,
                started_at.isoformat(timespec="seconds") + "Z" if started_at else None,
                completed_at.isoformat(timespec="seconds") + "Z" if completed_at else None,
                42 if status == "PRINTING" else None,
                created_at,
                created_at,
            ),
        )

    if completed_with_photo:
        conn.execute(
            """
            INSERT INTO build_snapshots (id, build_id, created_at, snapshot_data, snapshot_type)
            VALUES (?, ?, ?, ?, 'completion')
            """,
            (
                str(uuid.uuid4()),
                completed_with_photo,
                created_at,
                "dGVzdC1zbmFwc2hvdA==",  # base64("test-snapshot")
            ),
        )

    conn.execute(
        """
        UPDATE requests
        SET access_token = ?, total_builds = ?, completed_builds = ?, failed_builds = ?, active_build_id = ?
        WHERE id = ?
        """,
        (
            access_token,
            len(build_ids),
            sum(1 for s, _, _ in build_statuses if s == "COMPLETED"),
            sum(1 for s, _, _ in build_statuses if s == "FAILED"),
            printing_build_id,
            rid,
        ),
    )

    requester_token = secrets.token_urlsafe(24)
    conn.execute(
        """
        INSERT INTO email_lookup_tokens (id, email, token, short_code, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            requester_email,
            requester_token,
            None,
            created_at,
            (now + timedelta(days=1)).isoformat(timespec="seconds") + "Z",
        ),
    )

    conn.commit()
    conn.close()

    return {
        "request_id": rid,
        "requester_token": requester_token,
        "access_token": access_token,
        "build_ids": build_ids,
    }


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as client:
        # Ensure a clean, initialized sandbox DB for all smoke checks
        clear_test_data()
        yield client


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "New Print Request" in response.text


def test_queue_page_loads(client):
    response = client.get("/queue")
    assert response.status_code == 200
    assert "Print Queue" in response.text


def test_my_requests_invalid_token_shows_friendly_message(client):
    response = client.get("/my-requests/view", params={"token": "invalid"})
    assert response.status_code == 200
    assert "Session expired" in response.text


def test_admin_login_accessible(client):
    response = client.get("/admin/login", allow_redirects=False)
    assert response.status_code in (200, 303)
    if response.status_code == 303:
        assert response.headers["location"].startswith("/admin/login/new")
    else:
        assert "admin" in response.text.lower()


def test_push_vapid_public_key_endpoint(client):
    response = client.get("/api/push/vapid-public-key")
    assert response.status_code == 200
    payload = response.json()
    assert {"ok", "publicKey"}.issubset(payload.keys())


def test_push_health_endpoint_returns_json(client):
    response = client.get("/api/push/health", cookies={"admin_pw": os.environ["ADMIN_PASSWORD"]})
    assert response.status_code == 200
    payload = response.json()
    assert "ok" in payload and "errors" in payload


def test_store_routes_render(client):
    clear_test_data()
    item_id = seed_store_item()

    store_resp = client.get("/store")
    assert store_resp.status_code == 200
    assert "Store" in store_resp.text

    item_resp = client.get(f"/store/item/{item_id}")
    assert item_resp.status_code == 200
    assert "Test Gadget" in item_resp.text


def test_feedback_and_changelog_pages(client):
    feedback = client.get("/feedback")
    changelog = client.get("/changelog")
    assert feedback.status_code == 200
    assert changelog.status_code == 200
    assert "feedback" in feedback.text.lower()
    assert "version" in changelog.text.lower()


def test_offline_and_sw_assets_are_served(client):
    offline = client.get("/offline.html")
    if offline.status_code == 404:
        offline = client.get("/static/offline.html")
    assert offline.status_code == 200
    assert "offline" in offline.text.lower()

    sw = client.get("/sw.js")
    assert sw.status_code == 200
    assert "SW_VERSION" in sw.text and "CACHE_NAME" in sw.text


def test_public_queue_contains_mobile_and_desktop_containers(client):
    resp = client.get("/queue")
    assert resp.status_code == 200
    assert 'id="queue-mobile"' in resp.text
    assert 'id="queue-desktop"' in resp.text


def test_my_requests_view_shows_multi_build_progress_and_details(client):
    seeded = seed_multi_build_request()
    view = client.get("/my-requests/view", params={"token": seeded["requester_token"]})
    assert view.status_code == 200
    assert "Build" in view.text
    assert f"{len(seeded['build_ids'])}" in view.text  # total builds appears in copy

    detail = client.get(f"/my/{seeded['request_id']}", params={"token": seeded["access_token"]})
    assert detail.status_code == 200
    assert "builds done" in detail.text or "build(s) remaining" in detail.text or "builds" in detail.text
    assert f"build-{seeded['build_ids'][0]}" in detail.text
    assert "dGVzdC1zbmFwc2hvdA==" in detail.text  # snapshot reference present
    assert "photos will appear" in detail.text.lower()  # placeholder for builds without photos


def test_push_endpoints_return_json_on_bad_payloads(client):
    unsub = client.post("/api/push/unsubscribe")
    assert unsub.status_code == 400
    assert "application/json" in unsub.headers.get("content-type", "")
    assert unsub.json().get("ok") is False

    sub = client.post(
        "/api/push/subscribe",
        data="not-json",
        headers={"content-type": "application/json"},
    )
    assert sub.status_code == 400
    assert "application/json" in sub.headers.get("content-type", "")
    assert sub.json().get("ok") is False

    test_push = client.post("/api/push/test")
    assert "application/json" in test_push.headers.get("content-type", "")
    assert test_push.json().get("ok") is False


def test_build_start_requires_specific_printer(client):
    seeded = seed_multi_build_request(include_snapshot=False)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("UPDATE requests SET status = 'APPROVED' WHERE id = ?", (seeded["request_id"],))
    conn.commit()
    conn.close()

    response = client.post(
        f"/admin/request/{seeded['request_id']}/status",
        data={"to_status": "PRINTING", "printer": "ANY"},
        cookies={"admin_pw": os.environ["ADMIN_PASSWORD"]},
        allow_redirects=False,
    )
    assert response.status_code == 400
    assert "printer must be selected" in response.text.lower()
