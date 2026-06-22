"""
Tests for the cross-network printer agent API (app.printer_agent).

Covers the full agent lifecycle: admin creates an agent, the agent provisions
with the claim code, an admin enqueues a gcode job ("Send to LK5"), the agent
claims it, downloads the file, streams status, and uploads a camera snapshot.
"""
import os
import uuid

import pytest

from tests.conftest import get_test_db


PREFIX = "/api/printer-agent/v1"
ADMIN = "/api/printer-agent/admin"


def _make_gcode_file(name: str = "widget.gcode", body: str = "; gcode\nG28\nG1 X10 Y10\n") -> str:
    """Insert a loose .gcode file row + write it to the upload dir; return file_id."""
    file_id = str(uuid.uuid4())
    stored = f"{uuid.uuid4().hex}.gcode"
    upload_dir = os.environ["UPLOAD_DIR"]
    os.makedirs(upload_dir, exist_ok=True)
    with open(os.path.join(upload_dir, stored), "w") as fh:
        fh.write(body)
    conn = get_test_db()
    conn.execute(
        "INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256) "
        "VALUES (?, '', ?, ?, ?, ?, ?)",
        (file_id, "2026-01-01T00:00:00Z", name, stored, len(body), "deadbeef"),
    )
    conn.commit()
    conn.close()
    return file_id


def _create_agent(admin_client, name="LK5 Pro Bench", printer_code="LK5_PRO"):
    r = admin_client.post(f"{ADMIN}/agents", json={"name": name, "printer_code": printer_code})
    assert r.status_code == 200, r.text
    return r.json()


def _provision(client, agent_id, claim_code):
    return client.post(
        f"{PREFIX}/provision",
        json={"agent_id": agent_id, "claim_code": claim_code, "agent_version": "1.0.0"},
    )


# ─────────────────────────── provisioning ───────────────────────────

def test_create_and_provision_agent(client, admin_client):
    created = _create_agent(admin_client)
    assert created["agent_id"].startswith("agent-")
    assert created["claim_code"]

    r = _provision(client, created["agent_id"], created["claim_code"])
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "provisioned"
    assert data["agent_token"]
    assert data["printer_code"] == "LK5_PRO"


def test_provision_rejects_bad_claim_code(client, admin_client):
    created = _create_agent(admin_client)
    r = _provision(client, created["agent_id"], "wrong-code")
    assert r.status_code == 403


def test_provision_rejects_unknown_agent(client):
    r = _provision(client, "agent-doesnotexist", "whatever")
    assert r.status_code == 403


def test_create_agent_requires_admin(client):
    r = client.post(f"{ADMIN}/agents", json={"name": "x"})
    assert r.status_code == 401


# ─────────────────────────── heartbeat ───────────────────────────

def test_heartbeat_requires_bearer(client):
    r = client.post(f"{PREFIX}/heartbeat", json={})
    assert r.status_code == 401


def test_heartbeat_updates_status(client, admin_client):
    created = _create_agent(admin_client)
    token = _provision(client, created["agent_id"], created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(
        f"{PREFIX}/heartbeat",
        headers=headers,
        json={"agent_version": "1.0.0", "printer": {"state": "printing", "progress": 42, "nozzle_temp": 205, "nozzle_target": 210}},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Admin listing reflects the heartbeat + online status.
    agents = admin_client.get(f"{ADMIN}/agents").json()["agents"]
    me = next(a for a in agents if a["agent_id"] == created["agent_id"])
    assert me["online"] is True
    assert me["status"]["progress"] == 42


# ─────────────────────────── job lifecycle ───────────────────────────

def test_full_job_lifecycle(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # No jobs yet.
    assert client.get(f"{PREFIX}/jobs/next", headers=headers).status_code == 204

    # Admin enqueues a gcode file ("Send to LK5").
    file_id = _make_gcode_file()
    enq = admin_client.post(f"{ADMIN}/agents/{agent_id}/jobs", json={"file_id": file_id})
    assert enq.status_code == 200, enq.text
    job_id = enq.json()["job_id"]

    # Agent claims it.
    nxt = client.get(f"{PREFIX}/jobs/next", headers=headers)
    assert nxt.status_code == 200
    payload = nxt.json()
    assert payload["job_id"] == job_id
    assert payload["file_name"] == "widget.gcode"

    # Second poll returns nothing (already claimed).
    assert client.get(f"{PREFIX}/jobs/next", headers=headers).status_code == 204

    # Agent downloads the file.
    dl = client.get(f"{PREFIX}/jobs/{job_id}/file", headers=headers)
    assert dl.status_code == 200
    assert "G28" in dl.text

    # Agent reports progress then completion.
    assert client.post(f"{PREFIX}/jobs/{job_id}/status", headers=headers,
                       json={"status": "printing", "progress": 10}).status_code == 200
    assert client.post(f"{PREFIX}/jobs/{job_id}/status", headers=headers,
                       json={"status": "completed"}).status_code == 200

    jobs = admin_client.get(f"{ADMIN}/agents/{agent_id}/jobs").json()["jobs"]
    done = next(j for j in jobs if j["job_id"] == job_id)
    assert done["status"] == "completed"
    assert done["progress"] == 100


def test_enqueue_rejects_non_gcode(client, admin_client):
    created = _create_agent(admin_client)
    # A non-gcode file.
    file_id = _make_gcode_file(name="model.stl", body="solid\n")
    r = admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/jobs", json={"file_id": file_id})
    assert r.status_code == 422


def test_job_file_isolated_between_agents(client, admin_client):
    a = _create_agent(admin_client, name="A")
    b = _create_agent(admin_client, name="B")
    token_b = _provision(client, b["agent_id"], b["claim_code"]).json()["agent_token"]

    file_id = _make_gcode_file()
    job_id = admin_client.post(f"{ADMIN}/agents/{a['agent_id']}/jobs", json={"file_id": file_id}).json()["job_id"]

    # Agent B must not be able to download agent A's job file.
    r = client.get(f"{PREFIX}/jobs/{job_id}/file", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 404


def test_cancel_job(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    file_id = _make_gcode_file()
    job_id = admin_client.post(f"{ADMIN}/agents/{agent_id}/jobs", json={"file_id": file_id}).json()["job_id"]

    assert admin_client.post(f"{ADMIN}/jobs/{job_id}/cancel").status_code == 200
    jobs = admin_client.get(f"{ADMIN}/agents/{agent_id}/jobs").json()["jobs"]
    assert next(j for j in jobs if j["job_id"] == job_id)["status"] == "canceled"


def test_revoked_agent_cannot_use_token(client, admin_client):
    created = _create_agent(admin_client)
    token = _provision(client, created["agent_id"], created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post(f"{PREFIX}/heartbeat", headers=headers, json={}).status_code == 200

    assert admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/revoke").status_code == 200
    assert client.post(f"{PREFIX}/heartbeat", headers=headers, json={}).status_code == 401


# ─────────────────────────── snapshot + ingest ───────────────────────────

def test_snapshot_upload_and_admin_fetch(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]

    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    r = client.post(
        f"{PREFIX}/snapshot",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "image/jpeg"},
        content=png,
    )
    assert r.status_code == 200

    got = admin_client.get(f"{ADMIN}/agents/{agent_id}/snapshot.jpg")
    assert got.status_code == 200
    assert got.content == png


def test_ingest_gcode_with_token(client, admin_client):
    # The ingest token is surfaced to admins.
    ingest_token = admin_client.get(f"{ADMIN}/agents").json()["ingest_token"]
    assert ingest_token

    files = {"file": ("auto.gcode", b"; sliced by cura\nG28\n", "text/plain")}
    r = client.post(f"{PREFIX}/ingest/gcode", files=files, headers={"X-Ingest-Token": ingest_token})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["file_name"] == "auto.gcode"

    # The ingested file can then be dispatched to an agent.
    created = _create_agent(admin_client)
    enq = admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/jobs", json={"file_id": data["file_id"]})
    assert enq.status_code == 200


def test_ingest_gcode_rejects_bad_token(client):
    files = {"file": ("auto.gcode", b"G28\n", "text/plain")}
    r = client.post(f"{PREFIX}/ingest/gcode", files=files, headers={"X-Ingest-Token": "nope"})
    assert r.status_code == 401


# ─────────────────────────── remote management commands ───────────────────────────

def test_command_lifecycle(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # No commands yet.
    assert client.get(f"{PREFIX}/commands/next", headers=headers).status_code == 204

    # Admin queues a get_logs command.
    enq = admin_client.post(f"{ADMIN}/agents/{agent_id}/commands", json={"action": "get_logs"})
    assert enq.status_code == 200, enq.text
    cmd_id = enq.json()["cmd_id"]

    # Agent claims it (and a second poll returns nothing).
    nxt = client.get(f"{PREFIX}/commands/next", headers=headers)
    assert nxt.status_code == 200
    assert nxt.json()["action"] == "get_logs"
    assert client.get(f"{PREFIX}/commands/next", headers=headers).status_code == 204

    # Agent reports a result.
    r = client.post(f"{PREFIX}/commands/{cmd_id}/status", headers=headers,
                    json={"status": "completed", "result": {"logs": "hello world"}})
    assert r.status_code == 200

    cmds = admin_client.get(f"{ADMIN}/agents/{agent_id}/commands").json()["commands"]
    done = next(c for c in cmds if c["cmd_id"] == cmd_id)
    assert done["status"] == "completed"
    assert done["result"]["logs"] == "hello world"


def test_command_rejects_unknown_action(admin_client):
    created = _create_agent(admin_client)
    r = admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/commands", json={"action": "rm_rf_slash"})
    assert r.status_code == 422


def test_command_requires_admin_to_enqueue(client, admin_client):
    created = _create_agent(admin_client)
    r = client.post(f"{ADMIN}/agents/{created['agent_id']}/commands", json={"action": "get_logs"})
    assert r.status_code == 401


def test_command_next_requires_bearer(client):
    assert client.get(f"{PREFIX}/commands/next").status_code == 401


# ─────────────────────────── unified long-poll (events) ───────────────────────────

def test_events_returns_command(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    admin_client.post(f"{ADMIN}/agents/{agent_id}/commands", json={"action": "identify"})
    r = client.get(f"{PREFIX}/events/next", params={"timeout_s": 1, "want_jobs": 1}, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "command"
    assert body["command"]["action"] == "identify"


def test_events_returns_job_and_prioritizes_commands(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    file_id = _make_gcode_file()
    admin_client.post(f"{ADMIN}/agents/{agent_id}/jobs", json={"file_id": file_id})
    admin_client.post(f"{ADMIN}/agents/{agent_id}/commands", json={"action": "identify"})

    # Command first (priority), then the job on the next call.
    first = client.get(f"{PREFIX}/events/next", params={"timeout_s": 1}, headers=headers).json()
    assert first["type"] == "command"
    second = client.get(f"{PREFIX}/events/next", params={"timeout_s": 1}, headers=headers).json()
    assert second["type"] == "job"


def test_events_want_jobs_zero_skips_jobs(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    file_id = _make_gcode_file()
    admin_client.post(f"{ADMIN}/agents/{agent_id}/jobs", json={"file_id": file_id})
    # want_jobs=0 → no command, no job claimed → 204 after the (short) hold.
    r = client.get(f"{PREFIX}/events/next", params={"timeout_s": 1, "want_jobs": 0}, headers=headers)
    assert r.status_code == 204


def test_events_timeout_204(client, admin_client):
    created = _create_agent(admin_client)
    token = _provision(client, created["agent_id"], created["claim_code"]).json()["agent_token"]
    r = client.get(f"{PREFIX}/events/next", params={"timeout_s": 1},
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 204


def test_events_requires_bearer(client):
    assert client.get(f"{PREFIX}/events/next").status_code == 401


# ─────────────────────────── agent OTA ───────────────────────────

def _make_agent_bundle() -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("printqueue_agent/__init__.py", "__version__ = '9.9.9'\n")
        zf.writestr("printqueue_agent/agent.py", "# updated\n")
    return buf.getvalue()


def test_upload_and_push_agent_update(client, admin_client):
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    bundle = _make_agent_bundle()
    up = admin_client.post(
        f"{ADMIN}/agent-releases",
        data={"version": "1.1.0"},
        files={"file": ("agent.zip", bundle, "application/zip")},
    )
    assert up.status_code == 200, up.text

    rels = admin_client.get(f"{ADMIN}/agent-releases").json()["releases"]
    assert any(r["version"] == "1.1.0" and r["is_current"] for r in rels)

    push = admin_client.post(f"{ADMIN}/agents/{agent_id}/update")
    assert push.status_code == 200, push.text
    assert push.json()["version"] == "1.1.0"

    cmd = client.get(f"{PREFIX}/commands/next", headers=headers).json()
    assert cmd["action"] == "update_agent"
    assert cmd["payload"]["version"] == "1.1.0"

    dl = client.get(cmd["payload"]["bundle_url"], headers=headers)
    assert dl.status_code == 200
    assert dl.content == bundle


def test_push_update_without_release_404(admin_client):
    # Releases are global; clear them so the "no release" path is deterministic.
    conn = get_test_db()
    conn.execute("DELETE FROM printer_agent_releases")
    conn.commit()
    conn.close()

    created = _create_agent(admin_client)
    r = admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/update")
    assert r.status_code == 404


def test_upload_rejects_non_package_zip(admin_client):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("random.txt", "nope")
    r = admin_client.post(
        f"{ADMIN}/agent-releases",
        data={"version": "0.0.1"},
        files={"file": ("x.zip", buf.getvalue(), "application/zip")},
    )
    assert r.status_code == 422


def test_bundle_download_requires_bearer(client, admin_client):
    admin_client.post(
        f"{ADMIN}/agent-releases",
        data={"version": "2.0.0"},
        files={"file": ("a.zip", _make_agent_bundle(), "application/zip")},
    )
    assert client.get(f"{PREFIX}/releases/agent/2.0.0/bundle").status_code == 401


# ─────────────────────────── printer firmware ───────────────────────────

def test_upload_and_flash_firmware(client, admin_client):
    created = _create_agent(admin_client, printer_code="LK5_PRO")
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    headers = {"Authorization": f"Bearer {token}"}

    hexdata = b":100000000C9434000C9446000C9446000C944600AA\n:00000001FF\n"
    up = admin_client.post(
        f"{ADMIN}/firmware",
        data={"version": "2.1.2", "printer_code": "LK5_PRO"},
        files={"file": ("marlin.hex", hexdata, "text/plain")},
    )
    assert up.status_code == 200, up.text

    fws = admin_client.get(f"{ADMIN}/firmware").json()["firmware"]
    assert any(f["version"] == "2.1.2" and f["is_current"] for f in fws)

    flash = admin_client.post(f"{ADMIN}/agents/{agent_id}/flash")
    assert flash.status_code == 200, flash.text

    cmd = client.get(f"{PREFIX}/commands/next", headers=headers).json()
    assert cmd["action"] == "flash_firmware"
    assert cmd["payload"]["version"] == "2.1.2"

    dl = client.get(cmd["payload"]["firmware_url"], headers=headers)
    assert dl.status_code == 200
    assert dl.content == hexdata


def test_upload_firmware_rejects_non_hex(admin_client):
    r = admin_client.post(
        f"{ADMIN}/firmware",
        data={"version": "1.0", "printer_code": "LK5_PRO"},
        files={"file": ("notfirmware.txt", b"nope", "text/plain")},
    )
    assert r.status_code == 422


def test_flash_without_firmware_404(admin_client):
    conn = get_test_db()
    conn.execute("DELETE FROM printer_firmware")
    conn.commit()
    conn.close()
    created = _create_agent(admin_client, printer_code="LK5_PRO")
    r = admin_client.post(f"{ADMIN}/agents/{created['agent_id']}/flash")
    assert r.status_code == 404


# ─────────────────────────── guided-setup agent package ───────────────────────────

def test_agent_package_download(client, admin_client):
    token = admin_client.get(f"{ADMIN}/agents").json()["ingest_token"]
    r = client.get(f"{PREFIX}/agent-package.tar.gz", params={"token": token})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"

    import io
    import tarfile
    tf = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz")
    names = tf.getnames()
    # The tarball ships the agent package and keeps the "agent/" prefix.
    assert any(n.endswith("agent/printqueue_agent/__init__.py") for n in names)
    assert any(n.endswith("agent/requirements.txt") for n in names)
    # Never leaks a local config.json.
    assert not any(n.endswith("config.json") for n in names)


def test_agent_package_requires_token(client):
    assert client.get(f"{PREFIX}/agent-package.tar.gz").status_code == 401
    assert client.get(f"{PREFIX}/agent-package.tar.gz", params={"token": "wrong"}).status_code == 401


# ─────────────────────────── admin web UI ───────────────────────────

def test_admin_agents_page_renders(admin_client):
    r = admin_client.get("/admin/printer-agents")
    assert r.status_code == 200
    assert "Print Agents" in r.text


def test_setup_guide_doc_accessible(admin_client):
    r = admin_client.get("/admin/printellect/docs/lk5-pro-agent-setup.md")
    assert r.status_code == 200
    assert "setup guide" in r.text.lower()


def test_security_doc_accessible(admin_client):
    r = admin_client.get("/admin/printellect/docs/agent-security.md")
    assert r.status_code == 200
    assert "security" in r.text.lower()


def test_admin_agents_page_requires_admin(client):
    r = client.get("/admin/printer-agents", follow_redirects=False)
    assert r.status_code in (401, 302, 303, 307)


def test_admin_gcode_files_list(client, admin_client):
    _make_gcode_file(name="dispatchable.gcode")
    r = admin_client.get(f"{ADMIN}/gcode-files")
    assert r.status_code == 200
    names = [f["original_filename"] for f in r.json()["files"]]
    assert "dispatchable.gcode" in names


def test_admin_dispatch_to_lk5(client, admin_client):
    """The request-page 'Send to LK5' button: resolves the agent by printer_code."""
    code = f"LK5_{uuid.uuid4().hex[:8].upper()}"
    created = _create_agent(admin_client, name="Bench LK5", printer_code=code)
    file_id = _make_gcode_file(name="part.gcode")

    r = admin_client.post(f"{ADMIN}/dispatch", json={"file_id": file_id, "request_id": "req-123", "printer_code": code})
    assert r.status_code == 200, r.text
    assert r.json()["agent_id"] == created["agent_id"]

    jobs = admin_client.get(f"{ADMIN}/agents/{created['agent_id']}/jobs").json()["jobs"]
    assert any(j["file_name"] == "part.gcode" and j["request_id"] == "req-123" for j in jobs)


def test_admin_dispatch_no_agent_404(admin_client):
    file_id = _make_gcode_file(name="orphan.gcode")
    r = admin_client.post(f"{ADMIN}/dispatch", json={"file_id": file_id, "printer_code": "NO_SUCH_PRINTER"})
    assert r.status_code == 404


def test_admin_dispatch_requires_admin(client):
    r = client.post(f"{ADMIN}/dispatch", json={"file_id": "x"})
    assert r.status_code == 401


def test_request_page_shows_lk5_button_only_for_lk5(admin_client):
    """The 'Send to LK5 Pro' button appears on LK5 requests, not on others."""
    from tests.conftest import create_test_request

    lk5 = create_test_request(printer="LK5_PRO", status="QUEUED", with_file=True)
    other = create_test_request(printer="AD5X", status="QUEUED", with_file=True)

    # Make the attached files .gcode so they render in the G-code section.
    conn = get_test_db()
    for data in (lk5, other):
        conn.execute("UPDATE files SET original_filename = 'p.gcode', stored_filename = 'p.gcode' WHERE id = ?",
                     (data["file_ids"][0],))
    conn.commit()
    conn.close()

    r_lk5 = admin_client.get(f"/admin/request/{lk5['request_id']}")
    r_other = admin_client.get(f"/admin/request/{other['request_id']}")
    assert r_lk5.status_code == 200 and r_other.status_code == 200
    assert "Send to LK5 Pro" in r_lk5.text
    assert "Send to LK5 Pro" not in r_other.text


# ─────────────────────────── one-click print (Cura plugin) ───────────────────────────

def test_print_now_uploads_and_dispatches(client, admin_client):
    """The Cura 'Send to LK5' button: upload gcode + enqueue in one call."""
    created = _create_agent(admin_client)
    agent_id = created["agent_id"]
    token = _provision(client, agent_id, created["claim_code"]).json()["agent_token"]
    ingest_token = admin_client.get(f"{ADMIN}/agents").json()["ingest_token"]

    files = {"file": ("cura_print.gcode", b"; sliced\nG28\nG1 X5\n", "text/plain")}
    r = client.post(
        f"{PREFIX}/print",
        files=files,
        data={"agent_id": agent_id},
        headers={"X-Ingest-Token": ingest_token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "queued"
    assert r.json()["agent_id"] == agent_id

    # The agent immediately sees the job without any admin dispatch step.
    nxt = client.get(f"{PREFIX}/jobs/next", headers={"Authorization": f"Bearer {token}"})
    assert nxt.status_code == 200
    assert nxt.json()["file_name"] == "cura_print.gcode"


def test_print_now_resolves_agent_by_printer_code(client, admin_client):
    """With no agent_id, it targets the agent registered for the printer_code."""
    # Unique printer_code so resolution is unambiguous regardless of other agents.
    code = f"LK5_{uuid.uuid4().hex[:8].upper()}"
    created = _create_agent(admin_client, name="Default LK5", printer_code=code)
    ingest_token = admin_client.get(f"{ADMIN}/agents").json()["ingest_token"]

    files = {"file": ("auto.gcode", b"G28\n", "text/plain")}
    r = client.post(
        f"{PREFIX}/print",
        files=files,
        data={"printer_code": code},
        headers={"X-Ingest-Token": ingest_token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["agent_id"] == created["agent_id"]


def test_print_now_requires_token(client, admin_client):
    _create_agent(admin_client)
    files = {"file": ("auto.gcode", b"G28\n", "text/plain")}
    r = client.post(f"{PREFIX}/print", files=files, data={"printer_code": "LK5_PRO"},
                    headers={"X-Ingest-Token": "wrong"})
    assert r.status_code == 401


def test_print_now_no_agent_returns_404(client, admin_client):
    ingest_token = admin_client.get(f"{ADMIN}/agents").json()["ingest_token"]
    files = {"file": ("auto.gcode", b"G28\n", "text/plain")}
    r = client.post(f"{PREFIX}/print", files=files, data={"printer_code": "NOPE_PRINTER"},
                    headers={"X-Ingest-Token": ingest_token})
    assert r.status_code == 404
