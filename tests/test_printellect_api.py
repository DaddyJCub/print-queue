import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
import json
import zipfile

from tests.conftest import get_test_db


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

    return account_id, session_token


def _admin_cookie() -> dict:
    return {"admin_pw": os.environ["ADMIN_PASSWORD"]}


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
