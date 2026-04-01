import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
import json
import zipfile

import pytest
from tests.conftest import get_test_db
from app.auth import invalidate_feature_flag_cache


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _create_account_session(email: str = "owner@example.com", enable_printellect: bool = True) -> tuple[str, str]:
    conn = get_test_db()
    account_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    session_token = f"sess-{uuid.uuid4()}"
    now = _now_iso()
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat(timespec="seconds") + "Z"

    conn.execute(
        """
        INSERT INTO accounts (id, email, name, role, status, created_at, updated_at)
        VALUES (?, ?, ?, 'user', 'active', ?, ?)
        """,
        (account_id, email, "Owner", now, now),
    )
    conn.execute(
        """
        INSERT INTO sessions (id, account_id, token, created_at, expires_at, last_active)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (session_id, account_id, session_token, now, expires, now),
    )

    # Always normalize the Printellect flag to an allow-list model in test setup.
    flag_row = conn.execute(
        "SELECT allowed_emails FROM feature_flags WHERE key = 'printellect_device_control'"
    ).fetchone()
    if flag_row:
        try:
            allowed_emails = json.loads(flag_row["allowed_emails"] or "[]")
        except Exception:
            allowed_emails = []
        allowed_emails = [e for e in allowed_emails if e != email]
        if enable_printellect:
            allowed_emails.append(email)
        conn.execute(
            "UPDATE feature_flags SET enabled = 1, rollout_percentage = 0, allowed_users = '[]', allowed_emails = ?, updated_at = ? WHERE key = 'printellect_device_control'",
            (json.dumps(allowed_emails), now),
        )
    conn.commit()
    conn.close()

    # Invalidate the app's in-memory feature flag cache so direct DB writes
    # are visible immediately to subsequent API calls within the same test.
    invalidate_feature_flag_cache("printellect_device_control")

    return account_id, session_token


def _admin_cookie() -> dict:
    return {"admin_pw": os.environ["ADMIN_PASSWORD"]}


def _create_claimed_online_device(client, device_id: str, owner_email: str):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": device_id, "name": f"Device {device_id}"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, session_token = _create_account_session(email=owner_email)
    client.cookies.set("session", session_token)
    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200

    provision = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": device["device_id"],
            "claim_code": device["claim_code"],
            "fw_version": "1.0.0-test",
            "app_version": "1.0.0-test",
        },
    )
    assert provision.status_code == 200
    token = provision.json()["device_token"]
    auth = {"Authorization": f"Bearer {token}"}

    hb = client.post(
        "/api/printellect/device/v1/heartbeat",
        json={"fw_version": "1.0.0-test", "app_version": "1.0.0-test", "rssi": -55},
        headers=auth,
    )
    assert hb.status_code == 200
    return device, token


def test_printellect_feature_flag_blocks_unassigned_user(client):
    # Force known flag state regardless of prior tests.
    conn = get_test_db()
    conn.execute(
        "UPDATE feature_flags SET enabled = 1, rollout_percentage = 0, allowed_users = '[]', allowed_emails = '[]' WHERE key = 'printellect_device_control'"
    )
    conn.commit()
    conn.close()

    _, session_token = _create_account_session(email="blocked-user@example.com", enable_printellect=False)
    client.cookies.set("session", session_token)

    resp = client.get("/api/printellect/devices")
    assert resp.status_code == 403


def test_provision_unclaimed_device_returns_unclaimed(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1001", "name": "Test Device"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    payload = create.json()["device"]

    prov = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": payload["device_id"],
            "claim_code": payload["claim_code"],
            "fw_version": "0.0.1",
            "app_version": "0.0.1",
        },
    )
    assert prov.status_code == 200
    assert prov.json()["status"] == "unclaimed"
    assert prov.json()["legacy_status"] == "waiting"
    assert prov.json()["poll_interval_ms"] >= 500


def test_provision_invalid_claim_code_returns_403(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1010", "name": "Test Device"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200

    prov = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": "perkbase-1010",
            "claim_code": "wrong-code",
            "fw_version": "0.0.1",
            "app_version": "0.0.1",
        },
    )
    assert prov.status_code == 403


def test_claim_conflict_and_same_owner_idempotent(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1011", "name": "Claim Device"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, owner_session = _create_account_session(email="owner1@example.com")
    client.cookies.set("session", owner_session)
    claim_owner = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim_owner.status_code == 200

    # Same owner can claim again (idempotent behavior).
    claim_again = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim_again.status_code == 200
    assert claim_again.json()["status"] == "claimed"

    # Different owner gets ownership conflict.
    _, other_session = _create_account_session(email="owner2@example.com")
    client.cookies.set("session", other_session)
    claim_other = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim_other.status_code == 409


def test_claim_provision_and_command_lifecycle(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1002", "name": "Device A"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, session_token = _create_account_session()
    client.cookies.set("session", session_token)

    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200
    assert claim.json()["status"] == "claimed"

    # Device is offline until heartbeat, so user action should be rejected.
    offline_action = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/stop",
        json={},
    )
    assert offline_action.status_code == 409

    provision = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": device["device_id"],
            "claim_code": device["claim_code"],
            "fw_version": "1.0.0",
            "app_version": "1.0.0",
        },
    )
    assert provision.status_code == 200
    assert provision.json()["status"] == "provisioned"
    assert provision.json()["legacy_status"] == "claimed"
    token = provision.json()["device_token"]

    heartbeat = client.post(
        "/api/printellect/device/v1/heartbeat",
        json={"fw_version": "1.0.0", "app_version": "1.0.0", "rssi": -52},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert heartbeat.status_code == 200

    enqueue = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/play",
        json={"perk": "juggernog"},
    )
    assert enqueue.status_code == 200
    cmd_id = enqueue.json()["cmd_id"]

    next_cmd = client.get(
        "/api/printellect/device/v1/commands/next",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert next_cmd.status_code == 200
    cmd = next_cmd.json()
    assert cmd["cmd_id"] == cmd_id
    assert cmd["action"] == "play_perk"

    executing = client.post(
        f"/api/printellect/device/v1/commands/{cmd_id}/status",
        json={"status": "executing"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert executing.status_code == 200

    state = client.post(
        "/api/printellect/device/v1/state",
        json={"playing": True, "perk_id": "juggernog", "volume": 15, "brightness": 30},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert state.status_code == 200

    completed = client.post(
        f"/api/printellect/device/v1/commands/{cmd_id}/status",
        json={"status": "completed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert completed.status_code == 200

    detail = client.get(f"/api/printellect/devices/{device['device_id']}")
    assert detail.status_code == 200
    data = detail.json()["device"]
    assert data["online"] is True
    assert data["state"].get("perk_id") == "juggernog"
    assert data["recent_commands"][0]["status"] in {"completed", "executing", "delivered"}


def test_reprovision_revokes_old_token(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1012", "name": "Rotate Token"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, session_token = _create_account_session(email="token-owner@example.com")
    client.cookies.set("session", session_token)
    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200

    first = client.post(
        "/api/printellect/device/v1/provision",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"], "fw_version": "1", "app_version": "1"},
    )
    assert first.status_code == 200
    token1 = first.json()["device_token"]

    second = client.post(
        "/api/printellect/device/v1/provision",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"], "fw_version": "1", "app_version": "2"},
    )
    assert second.status_code == 200
    token2 = second.json()["device_token"]
    assert token1 != token2

    old_hb = client.post(
        "/api/printellect/device/v1/heartbeat",
        json={"fw_version": "1.0.0", "app_version": "1.0.0"},
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert old_hb.status_code == 401

    new_hb = client.post(
        "/api/printellect/device/v1/heartbeat",
        json={"fw_version": "1.0.0", "app_version": "2.0.0"},
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert new_hb.status_code == 200


def test_bad_claim_code_rate_limited_and_no_owner_leak(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1013", "name": "Rate Limit Device"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, owner_session = _create_account_session(email="owner-rate@example.com")
    client.cookies.set("session", owner_session)
    claim_ok = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim_ok.status_code == 200

    # New user repeatedly attempts invalid claim code; should never get ownership info.
    _, attacker_session = _create_account_session(email="attacker@example.com")
    client.cookies.set("session", attacker_session)
    statuses = []
    last_body = {}
    for _ in range(10):
        resp = client.post(
            "/api/printellect/pairing/claim",
            json={"device_id": device["device_id"], "claim_code": "bad-claim"},
        )
        statuses.append(resp.status_code)
        try:
            last_body = resp.json()
        except Exception:
            last_body = {}

    assert any(s == 429 for s in statuses)
    assert all(s in {403, 429} for s in statuses)
    assert "owner" not in str(last_body).lower()


def test_bad_provision_claim_code_rate_limited_and_no_owner_leak(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1014", "name": "Provision Guard"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, owner_session = _create_account_session(email="prov-owner@example.com")
    client.cookies.set("session", owner_session)
    claim_ok = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim_ok.status_code == 200

    statuses = []
    last_body = {}
    for _ in range(10):
        resp = client.post(
            "/api/printellect/device/v1/provision",
            json={
                "device_id": device["device_id"],
                "claim_code": "wrong-provision-claim",
                "fw_version": "1.0.0",
                "app_version": "1.0.0",
            },
        )
        statuses.append(resp.status_code)
        try:
            last_body = resp.json()
        except Exception:
            last_body = {}

    assert any(s == 429 for s in statuses)
    assert all(s in {403, 429} for s in statuses)
    assert "owner" not in str(last_body).lower()


def test_release_upload_promote_and_fetch_files(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1020", "name": "OTA Device"},
        cookies=_admin_cookie(),
    )
    device = create.json()["device"]

    _, session_token = _create_account_session(email="ota-owner@example.com")
    client.cookies.set("session", session_token)
    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200

    provision = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": device["device_id"],
            "claim_code": device["claim_code"],
            "fw_version": "1.0.0",
            "app_version": "1.0.0",
        },
    )
    token = provision.json()["device_token"]
    auth = {"Authorization": f"Bearer {token}"}

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        manifest_path = root / "manifest.json"
        bundle_path = root / "app_bundle.zip"

        manifest = {
            "version": "0.3.0-test",
            "channel": "stable",
            "entrypoint": "main.py",
            "files": [{"path": "main.py"}],
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.py", "print('hello from ota')\n")
            zf.writestr("lib/helper.py", "VALUE = 1\n")

        with manifest_path.open("rb") as manifest_fh, bundle_path.open("rb") as bundle_fh:
            upload = client.post(
                "/api/printellect/admin/releases/upload",
                data={"channel": "stable", "notes": "qa smoke"},
                files={
                    "manifest": ("manifest.json", manifest_fh, "application/json"),
                    "bundle": ("app_bundle.zip", bundle_fh, "application/zip"),
                },
                cookies=_admin_cookie(),
            )

    assert upload.status_code == 200
    version = upload.json()["version"]
    assert version == "0.3.0-test"

    promote = client.post(
        f"/api/printellect/admin/releases/{version}/promote",
        json={},
        cookies=_admin_cookie(),
    )
    assert promote.status_code == 200

    latest = client.get("/api/printellect/device/v1/releases/latest?channel=stable", headers=auth)
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["version"] == version
    assert latest_body["manifest"]["entrypoint"] == "main.py"
    assert len(latest_body["manifest"]["files"]) >= 1

    file_resp = client.get(f"/api/printellect/device/v1/releases/{version}/files/main.py", headers=auth)
    assert file_resp.status_code == 200
    assert "hello from ota" in file_resp.text


def test_release_upload_package_zip_mode(client):
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-1021", "name": "OTA Package Device"},
        cookies=_admin_cookie(),
    )
    device = create.json()["device"]

    _, session_token = _create_account_session(email="ota-package-owner@example.com")
    client.cookies.set("session", session_token)
    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200

    provision = client.post(
        "/api/printellect/device/v1/provision",
        json={
            "device_id": device["device_id"],
            "claim_code": device["claim_code"],
            "fw_version": "1.0.0",
            "app_version": "1.0.0",
        },
    )
    token = provision.json()["device_token"]
    auth = {"Authorization": f"Bearer {token}"}

    with tempfile.TemporaryDirectory() as td:
        package_path = Path(td) / "firmware_folder.zip"
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.py", "print('package mode')\n")
            zf.writestr("lib/audio.py", "VOLUME=20\n")

        with package_path.open("rb") as package_fh:
            upload = client.post(
                "/api/printellect/admin/releases/upload",
                data={"channel": "stable", "notes": "package mode", "version": "0.4.0-pkg", "entrypoint": "main.py"},
                files={"package": ("firmware_folder.zip", package_fh, "application/zip")},
                cookies=_admin_cookie(),
            )

    assert upload.status_code == 200
    assert upload.json()["mode"] == "package"
    assert upload.json()["version"] == "0.4.0-pkg"
    assert upload.json()["file_count"] >= 2

    promote = client.post(
        "/api/printellect/admin/releases/0.4.0-pkg/promote",
        json={},
        cookies=_admin_cookie(),
    )
    assert promote.status_code == 200

    latest = client.get("/api/printellect/device/v1/releases/latest?channel=stable", headers=auth)
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["version"] == "0.4.0-pkg"
    assert latest_body["manifest"]["entrypoint"] == "main.py"

    file_resp = client.get("/api/printellect/device/v1/releases/0.4.0-pkg/files/main.py", headers=auth)
    assert file_resp.status_code == 200
    assert "package mode" in file_resp.text


def test_printellect_pages_render(client):
    _, session_token = _create_account_session(email="pages-owner@example.com")
    client.cookies.set("session", session_token)

    owner_pages = [
        "/printellect/devices",
        "/printellect/add-device",
        "/printellect/help",
        "/pair?device_id=perkbase-9999&claim=TEST&name=Demo",
    ]
    for path in owner_pages:
        resp = client.get(path)
        assert resp.status_code == 200

    admin_pages = [
        "/admin/printellect/devices",
        "/admin/printellect/releases",
    ]
    for path in admin_pages:
        resp = client.get(path, cookies=_admin_cookie())
        assert resp.status_code == 200

    help_page = client.get("/printellect/help")
    assert help_page.status_code == 200
    assert "Help & Guides" in help_page.text

    releases_page = client.get("/admin/printellect/releases", cookies=_admin_cookie())
    assert releases_page.status_code == 200
    assert "OTA Rollout Guide" in releases_page.text


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("qrcode"),
    reason="qrcode package not installed",
)
def test_admin_qr_svg_endpoint(client):
    resp = client.get(
        "/api/printellect/admin/qr.svg",
        params={"payload": "printellect://pair?device_id=perkbase-001&claim=TEST"},
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 200
    assert "svg" in (resp.headers.get("content-type") or "").lower()


def test_admin_create_device_returns_device_json_bundle(client):
    resp = client.post(
        "/api/printellect/admin/devices",
        json={"name": "Bench Device"},
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 200
    body = resp.json()
    device = body["device"]
    assert device["device_id"]
    assert device["claim_code"]
    assert device["qr_payload"].startswith("printellect://pair?")
    assert "/pair?" in device["fallback_url"]
    assert isinstance(device.get("device_json"), dict)
    assert device["device_json"]["device_id"] == device["device_id"]
    assert device["device_json"]["claim_code"] == device["claim_code"]
    assert device["device_json"]["hw_model"] == "pico2w"


def test_admin_device_management_update_unclaim_delete(client):
    created = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-mgmt-1", "name": "Mgmt Device"},
        cookies=_admin_cookie(),
    )
    assert created.status_code == 200
    device = created.json()["device"]

    owner_account_id, _ = _create_account_session(email="managed-owner@example.com")

    updated = client.patch(
        f"/api/printellect/admin/devices/{device['device_id']}",
        json={"name": "Renamed Base", "notes": "bench test", "owner_user_id": owner_account_id},
        cookies=_admin_cookie(),
    )
    assert updated.status_code == 200
    updated_body = updated.json()["device"]
    assert updated_body["name"] == "Renamed Base"
    assert updated_body["owner_user_id"] == owner_account_id
    assert updated_body["notes"] == "bench test"

    blocked_delete = client.delete(
        f"/api/printellect/admin/devices/{device['device_id']}",
        cookies=_admin_cookie(),
    )
    assert blocked_delete.status_code == 409

    unclaim = client.post(
        f"/api/printellect/admin/devices/{device['device_id']}/unclaim",
        cookies=_admin_cookie(),
    )
    assert unclaim.status_code == 200
    assert unclaim.json()["device"]["owner_user_id"] is None

    deleted = client.delete(
        f"/api/printellect/admin/devices/{device['device_id']}",
        cookies=_admin_cookie(),
    )
    assert deleted.status_code == 200

    listed = client.get("/api/printellect/admin/devices", cookies=_admin_cookie())
    assert listed.status_code == 200
    assert all(d["device_id"] != device["device_id"] for d in listed.json().get("devices", []))


# ────────────────────── Build from Source ──────────────────────


def test_build_from_source_creates_release(client):
    """Build a release from device/pico2w/ source and verify it appears in the list."""
    resp = client.post(
        "/api/printellect/admin/releases/build",
        json={"channel": "stable", "notes": "auto build test"},
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["mode"] == "build"
    assert body["file_count"] >= 1
    version = body["version"]

    # Verify it shows in the list
    listed = client.get("/api/printellect/admin/releases", cookies=_admin_cookie())
    versions = [r["version"] for r in listed.json()["releases"]]
    assert version in versions


def test_build_from_source_auto_increments_version(client):
    """Two consecutive builds should produce incrementing versions."""
    resp1 = client.post(
        "/api/printellect/admin/releases/build",
        json={"channel": "stable"},
        cookies=_admin_cookie(),
    )
    assert resp1.status_code == 200
    v1 = resp1.json()["version"]

    resp2 = client.post(
        "/api/printellect/admin/releases/build",
        json={"channel": "stable"},
        cookies=_admin_cookie(),
    )
    assert resp2.status_code == 200
    v2 = resp2.json()["version"]
    assert v2 != v1


# ────────────────────── Delete Release ──────────────────────


def test_delete_release(client):
    """Upload a release, then delete it."""
    with tempfile.TemporaryDirectory() as td:
        package_path = Path(td) / "firmware.zip"
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.py", "print('delete me')\n")

        with package_path.open("rb") as fh:
            upload = client.post(
                "/api/printellect/admin/releases/upload",
                data={"version": "99.0.0-del", "channel": "beta"},
                files={"package": ("firmware.zip", fh, "application/zip")},
                cookies=_admin_cookie(),
            )
    assert upload.status_code == 200

    # Delete it
    resp = client.delete(
        "/api/printellect/admin/releases/99.0.0-del",
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    # Verify it's gone
    listed = client.get("/api/printellect/admin/releases", cookies=_admin_cookie())
    versions = [r["version"] for r in listed.json()["releases"]]
    assert "99.0.0-del" not in versions


def test_delete_current_release_blocked(client):
    """Cannot delete a release that is currently promoted."""
    with tempfile.TemporaryDirectory() as td:
        package_path = Path(td) / "firmware.zip"
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.py", "print('keep me')\n")

        with package_path.open("rb") as fh:
            upload = client.post(
                "/api/printellect/admin/releases/upload",
                data={"version": "99.1.0-keep", "channel": "beta"},
                files={"package": ("firmware.zip", fh, "application/zip")},
                cookies=_admin_cookie(),
            )
    assert upload.status_code == 200

    # Promote it
    client.post(
        "/api/printellect/admin/releases/99.1.0-keep/promote",
        json={},
        cookies=_admin_cookie(),
    )

    # Delete should fail with 409
    resp = client.delete(
        "/api/printellect/admin/releases/99.1.0-keep",
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 409


# ────────────────────── Bulk OTA Push ──────────────────────


def test_push_release_to_devices(client):
    """Push a release OTA command to a claimed device."""
    # Create + claim a device
    create = client.post(
        "/api/printellect/admin/devices",
        json={"device_id": "perkbase-push-1", "name": "Push Test"},
        cookies=_admin_cookie(),
    )
    assert create.status_code == 200
    device = create.json()["device"]

    _, session_token = _create_account_session(email="push-owner@example.com")
    client.cookies.set("session", session_token)
    claim = client.post(
        "/api/printellect/pairing/claim",
        json={"device_id": device["device_id"], "claim_code": device["claim_code"]},
    )
    assert claim.status_code == 200

    # Create a release to push
    with tempfile.TemporaryDirectory() as td:
        package_path = Path(td) / "firmware.zip"
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.py", "print('push test')\n")

        with package_path.open("rb") as fh:
            upload = client.post(
                "/api/printellect/admin/releases/upload",
                data={"version": "99.2.0-push", "channel": "stable"},
                files={"package": ("firmware.zip", fh, "application/zip")},
                cookies=_admin_cookie(),
            )
    assert upload.status_code == 200

    # Push to all devices
    resp = client.post(
        "/api/printellect/admin/releases/99.2.0-push/push",
        json={},
        cookies=_admin_cookie(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["devices_pushed"] >= 1
    assert body["version"] == "99.2.0-push"

    # Verify update status
    status = client.get("/api/printellect/admin/update-status", cookies=_admin_cookie())
    assert status.status_code == 200
    device_statuses = {d["device_id"]: d for d in status.json()["devices"]}
    assert "perkbase-push-1" in device_statuses
    assert device_statuses["perkbase-push-1"]["target_version"] == "99.2.0-push"
    assert device_statuses["perkbase-push-1"]["status"] == "available"


# ────────────────────── OTA Status Page ──────────────────────


def test_ota_status_page_renders(client):
    resp = client.get("/admin/printellect/ota-status", cookies=_admin_cookie())
    assert resp.status_code == 200
    assert "OTA Update Status" in resp.text


def test_boot_ok_rejects_version_mismatch_against_target(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-ota-mismatch-1",
        owner_email="ota-mismatch@example.com",
    )
    del device
    auth = {"Authorization": f"Bearer {token}"}

    status = client.post(
        "/api/printellect/device/v1/update/status",
        json={"status": "applying", "version": "9.9.9", "progress": 90},
        headers=auth,
    )
    assert status.status_code == 200

    bad_boot = client.post(
        "/api/printellect/device/v1/boot-ok",
        json={"version": "9.9.8"},
        headers=auth,
    )
    assert bad_boot.status_code == 409

    conn = get_test_db()
    row = conn.execute(
        "SELECT target_version, status, last_error FROM device_update_status WHERE device_id = ?",
        ("perkbase-ota-mismatch-1",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["target_version"] == "9.9.9"
    assert row["status"] == "failed"
    assert "version mismatch" in (row["last_error"] or "")


def test_boot_ok_matching_version_marks_success_and_updates_device_app_version(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-ota-match-1",
        owner_email="ota-match@example.com",
    )
    del device
    auth = {"Authorization": f"Bearer {token}"}

    status = client.post(
        "/api/printellect/device/v1/update/status",
        json={"status": "applying", "version": "10.0.0", "progress": 95},
        headers=auth,
    )
    assert status.status_code == 200

    boot_ok = client.post(
        "/api/printellect/device/v1/boot-ok",
        json={"version": "10.0.0"},
        headers=auth,
    )
    assert boot_ok.status_code == 200

    conn = get_test_db()
    update_row = conn.execute(
        "SELECT target_version, status, progress, last_error FROM device_update_status WHERE device_id = ?",
        ("perkbase-ota-match-1",),
    ).fetchone()
    device_row = conn.execute(
        "SELECT app_version FROM devices WHERE device_id = ?",
        ("perkbase-ota-match-1",),
    ).fetchone()
    conn.close()
    assert update_row is not None
    assert update_row["target_version"] == "10.0.0"
    assert update_row["status"] == "success"
    assert update_row["progress"] == 100
    assert update_row["last_error"] is None
    assert device_row is not None
    assert device_row["app_version"] == "10.0.0"


def test_update_status_success_rejects_mismatched_version(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-ota-status-mismatch-1",
        owner_email="ota-status-mismatch@example.com",
    )
    del device
    auth = {"Authorization": f"Bearer {token}"}

    applying = client.post(
        "/api/printellect/device/v1/update/status",
        json={"status": "applying", "version": "11.0.0", "progress": 90},
        headers=auth,
    )
    assert applying.status_code == 200

    mismatch = client.post(
        "/api/printellect/device/v1/update/status",
        json={"status": "success", "version": "11.0.1", "progress": 100},
        headers=auth,
    )
    assert mismatch.status_code == 409

    conn = get_test_db()
    row = conn.execute(
        "SELECT target_version, status, last_error FROM device_update_status WHERE device_id = ?",
        ("perkbase-ota-status-mismatch-1",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["target_version"] == "11.0.0"
    assert row["status"] == "failed"
    assert "version mismatch" in (row["last_error"] or "")


def test_light_color_and_effect_actions_queue_structured_payloads(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-color-1",
        owner_email="color-owner@example.com",
    )

    color_cmd = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/light-color",
        json={"color": "#0A84FF"},
    )
    assert color_cmd.status_code == 200
    assert color_cmd.json()["action"] == "set_light_color"
    assert color_cmd.json()["payload"]["color"] == {"r": 10, "g": 132, "b": 255}

    auth = {"Authorization": f"Bearer {token}"}
    next_cmd = client.get("/api/printellect/device/v1/commands/next", headers=auth)
    assert next_cmd.status_code == 200
    assert next_cmd.json()["action"] == "set_light_color"

    bad_effect = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/light-effect",
        json={"effect": "bad_effect"},
    )
    assert bad_effect.status_code == 422

    effect_cmd = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/light-effect",
        json={"effect": "pulse", "speed_ms": 250, "color": "#34C759"},
    )
    assert effect_cmd.status_code == 200
    assert effect_cmd.json()["payload"]["effect"] == "pulse"
    assert effect_cmd.json()["payload"]["color"] == {"r": 52, "g": 199, "b": 89}


def test_test_lights_and_command_result_visible_in_detail_and_list(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-diag-1",
        owner_email="diag-owner@example.com",
    )
    auth = {"Authorization": f"Bearer {token}"}

    enqueue = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/test-lights",
        json={"effect": "pulse", "duration_ms": 1500, "speed_ms": 300, "color": "#FF3B30"},
    )
    assert enqueue.status_code == 200
    cmd_id = enqueue.json()["cmd_id"]
    assert enqueue.json()["payload"]["color"] == {"r": 255, "g": 59, "b": 48}

    next_cmd = client.get("/api/printellect/device/v1/commands/next", headers=auth)
    assert next_cmd.status_code == 200
    assert next_cmd.json()["cmd_id"] == cmd_id

    done = client.post(
        f"/api/printellect/device/v1/commands/{cmd_id}/status",
        json={"status": "completed", "result": {"effect": "pulse", "duration_ms": 1500, "ok": True}},
        headers=auth,
    )
    assert done.status_code == 200

    detail = client.get(f"/api/printellect/devices/{device['device_id']}")
    assert detail.status_code == 200
    recent = detail.json()["device"]["recent_commands"][0]
    assert recent["cmd_id"] == cmd_id
    assert recent["result"]["effect"] == "pulse"
    assert recent["result"]["ok"] is True

    listed = client.get("/api/printellect/devices")
    assert listed.status_code == 200
    listed_device = next(d for d in listed.json()["devices"] if d["device_id"] == device["device_id"])
    assert listed_device["last_command"]["action"] == "test_lights"
    assert listed_device["last_command"]["result"]["effect"] == "pulse"


def test_command_stream_returns_queued_command(client):
    device, token = _create_claimed_online_device(
        client,
        device_id="perkbase-stream-1",
        owner_email="stream-owner@example.com",
    )
    enqueue = client.post(
        f"/api/printellect/devices/{device['device_id']}/actions/stop",
        json={},
    )
    assert enqueue.status_code == 200

    auth = {"Authorization": f"Bearer {token}"}
    streamed = client.get("/api/printellect/device/v1/commands/stream?timeout_s=2", headers=auth)
    assert streamed.status_code == 200
    assert streamed.json()["action"] == "stop_audio"

    empty = client.get("/api/printellect/device/v1/commands/stream?timeout_s=1", headers=auth)
    assert empty.status_code == 204


def test_rename_device_updates_devices_table(client):
    device, _ = _create_claimed_online_device(
        client,
        device_id="perkbase-rename-1",
        owner_email="rename-owner@example.com",
    )

    renamed = client.put(
        f"/api/printellect/devices/{device['device_id']}/name",
        json={"name": "Renamed In Table"},
    )
    assert renamed.status_code == 200

    conn = get_test_db()
    row = conn.execute("SELECT name FROM devices WHERE device_id = ?", (device["device_id"],)).fetchone()
    conn.close()
    assert row is not None
    assert row["name"] == "Renamed In Table"


def test_openapi_contains_new_printellect_light_and_stream_contracts(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    paths = schema.get("paths", {})

    assert "/api/printellect/devices/{device_id}/actions/light-color" in paths
    assert "/api/printellect/devices/{device_id}/actions/light-effect" in paths
    assert "/api/printellect/device/v1/commands/stream" in paths
    assert "/api/printellect/device/v1/update/status" in paths
    assert "/api/printellect/device/v1/boot-ok" in paths

    command_status_post = paths["/api/printellect/device/v1/commands/{cmd_id}/status"]["post"]
    request_body = command_status_post.get("requestBody", {})
    assert request_body

    update_status_post = paths["/api/printellect/device/v1/update/status"]["post"]
    assert update_status_post.get("requestBody")
    boot_ok_post = paths["/api/printellect/device/v1/boot-ok"]["post"]
    assert boot_ok_post.get("requestBody")


def test_device_detail_page_shows_enhanced_diagnostics_controls(client):
    device, _ = _create_claimed_online_device(
        client,
        device_id="perkbase-ui-1",
        owner_email="ui-owner@example.com",
    )
    resp = client.get(f"/printellect/devices/{device['device_id']}")
    assert resp.status_code == 200
    assert "lightColorPicker" in resp.text
    assert "setLightEffectBtn" in resp.text
    assert "diagResults" in resp.text
