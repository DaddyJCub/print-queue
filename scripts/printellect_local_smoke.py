#!/usr/bin/env python3
"""
Local smoke test for Printellect device-control flow.

Prereqs:
- API server running (default http://127.0.0.1:3000)
- DB_PATH points to same sqlite file used by server
- ADMIN_PASSWORD set (or defaults to "admin")
"""

import os
import sqlite3
import sys
import uuid
import json
from datetime import datetime, timedelta

import httpx


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def fail(message):
    print("FAIL:", message)
    sys.exit(1)


def create_account_session(db_path, email):
    conn = sqlite3.connect(db_path)
    account_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    session_token = "sess-" + str(uuid.uuid4())
    now = now_iso()
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat(timespec="seconds") + "Z"

    conn.execute(
        """
        INSERT INTO accounts (id, email, name, role, status, created_at, updated_at)
        VALUES (?, ?, ?, 'user', 'active', ?, ?)
        """,
        (account_id, email, "Smoke User", now, now),
    )
    conn.execute(
        """
        INSERT INTO sessions (id, account_id, token, created_at, expires_at, last_active)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (session_id, account_id, session_token, now, expires, now),
    )

    flag_row = conn.execute(
        "SELECT allowed_emails FROM feature_flags WHERE key = 'printellect_device_control'"
    ).fetchone()
    if flag_row:
        try:
            allowed_emails = json.loads(flag_row[0] or "[]")
        except Exception:
            allowed_emails = []
        if email not in allowed_emails:
            allowed_emails.append(email)
        conn.execute(
            "UPDATE feature_flags SET enabled = 1, rollout_percentage = 0, allowed_emails = ?, updated_at = ? WHERE key = 'printellect_device_control'",
            (json.dumps(allowed_emails), now),
        )

    conn.commit()
    conn.close()
    return session_token


def main():
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:3000").rstrip("/")
    db_path = os.getenv("DB_PATH")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin")
    if not db_path:
        fail("DB_PATH is required")

    device_id = "perkbase-smoke-" + str(uuid.uuid4())[:8]

    with httpx.Client(base_url=base_url, timeout=10.0, follow_redirects=True) as client:
        # 1) admin creates device
        client.cookies.set("admin_pw", admin_password)
        create = client.post(
            "/api/printellect/admin/devices",
            json={"device_id": device_id, "name": "Smoke Device"},
        )
        if create.status_code != 200:
            fail("admin create device failed: %s %s" % (create.status_code, create.text))
        device = create.json()["device"]
        claim_code = device["claim_code"]
        print("OK: created device", device_id)

        # 2) pre-claim provision should be unclaimed
        prov_wait = client.post(
            "/api/printellect/device/v1/provision",
            json={
                "device_id": device_id,
                "claim_code": claim_code,
                "fw_version": "1.0.0-smoke",
                "app_version": "1.0.0-smoke",
            },
        )
        if prov_wait.status_code != 200 or prov_wait.json().get("status") != "unclaimed":
            fail("expected unclaimed provision response, got: %s %s" % (prov_wait.status_code, prov_wait.text))
        print("OK: unclaimed provision response")

        # 3) create account session directly in sqlite, then claim
        user_session = create_account_session(db_path, "smoke-%s@example.com" % str(uuid.uuid4())[:8])
        client.cookies.set("session", user_session)
        claim = client.post(
            "/api/printellect/pairing/claim",
            json={"device_id": device_id, "claim_code": claim_code},
        )
        if claim.status_code != 200:
            fail("pairing claim failed: %s %s" % (claim.status_code, claim.text))
        print("OK: claimed device")

        # 4) provision again should return token
        prov = client.post(
            "/api/printellect/device/v1/provision",
            json={
                "device_id": device_id,
                "claim_code": claim_code,
                "fw_version": "1.0.0-smoke",
                "app_version": "1.0.0-smoke",
            },
        )
        body = prov.json() if prov.headers.get("content-type", "").startswith("application/json") else {}
        if prov.status_code != 200 or body.get("status") != "provisioned":
            fail("provision failed: %s %s" % (prov.status_code, prov.text))
        token = body.get("device_token")
        if not token:
            fail("provisioned response missing device_token")
        print("OK: provisioned token")

        auth_headers = {"Authorization": "Bearer " + token}

        # 5) heartbeat makes device online
        hb = client.post(
            "/api/printellect/device/v1/heartbeat",
            json={"fw_version": "1.0.0-smoke", "app_version": "1.0.0-smoke", "rssi": -50},
            headers=auth_headers,
        )
        if hb.status_code != 200:
            fail("heartbeat failed: %s %s" % (hb.status_code, hb.text))
        print("OK: heartbeat")

        # 6) enqueue command from user + run command lifecycle from device
        action = client.post("/api/printellect/devices/%s/actions/play" % device_id, json={"perk": "juggernog"})
        if action.status_code != 200:
            fail("enqueue play failed: %s %s" % (action.status_code, action.text))
        cmd_id = action.json()["cmd_id"]

        nxt = client.get("/api/printellect/device/v1/commands/next", headers=auth_headers)
        if nxt.status_code != 200:
            fail("next command failed: %s %s" % (nxt.status_code, nxt.text))
        if nxt.json().get("cmd_id") != cmd_id:
            fail("unexpected cmd_id from next command")

        ex = client.post(
            "/api/printellect/device/v1/commands/%s/status" % cmd_id,
            json={"status": "executing"},
            headers=auth_headers,
        )
        if ex.status_code != 200:
            fail("executing status failed: %s %s" % (ex.status_code, ex.text))

        st = client.post(
            "/api/printellect/device/v1/state",
            json={"playing": True, "perk_id": "juggernog", "track_id": "juggernog", "volume": 15, "brightness": 35},
            headers=auth_headers,
        )
        if st.status_code != 200:
            fail("state update failed: %s %s" % (st.status_code, st.text))

        done = client.post(
            "/api/printellect/device/v1/commands/%s/status" % cmd_id,
            json={"status": "completed"},
            headers=auth_headers,
        )
        if done.status_code != 200:
            fail("completed status failed: %s %s" % (done.status_code, done.text))
        print("OK: command lifecycle")

        detail = client.get("/api/printellect/devices/%s" % device_id)
        if detail.status_code != 200:
            fail("device detail failed: %s %s" % (detail.status_code, detail.text))

    print("PASS: Printellect local smoke test completed")


if __name__ == "__main__":
    main()
