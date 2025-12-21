import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_ROOT = Path(__file__).resolve().parent
DATA_DIR = TEST_ROOT / "tmp_data"
UPLOAD_DIR = TEST_ROOT / "tmp_uploads"

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

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as client:
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
