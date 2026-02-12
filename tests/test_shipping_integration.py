import base64

from tests.conftest import create_test_request, get_test_db


def _set_shipping_enabled(enabled: bool = True):
    conn = get_test_db()
    conn.execute(
        """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
        ("shipping_enabled", "1" if enabled else "0", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()


def test_shippo_status_mapping():
    from app.shipping_shippo import map_shippo_tracking_status

    assert map_shippo_tracking_status("PRE_TRANSIT") == "PRE_TRANSIT"
    assert map_shippo_tracking_status("TRANSIT") == "IN_TRANSIT"
    assert map_shippo_tracking_status("OUT_FOR_DELIVERY") == "OUT_FOR_DELIVERY"
    assert map_shippo_tracking_status("DELIVERED") == "DELIVERED"
    assert map_shippo_tracking_status("FAILURE") == "EXCEPTION"


def test_shippo_webhook_idempotency(client, monkeypatch):
    _set_shipping_enabled(True)
    req = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="shipwebhook@example.com")

    conn = get_test_db()
    conn.execute(
        "UPDATE request_shipping SET tracking_number = ?, carrier = ? WHERE request_id = ?",
        ("9400111899223847182933", "USPS", req["request_id"]),
    )
    conn.commit()
    conn.close()

    from app import api_builds
    monkeypatch.setattr(api_builds, "_notify_requester_shipping_status", lambda *args, **kwargs: None)
    monkeypatch.setenv("SHIPPO_WEBHOOK_USER", "shippo")
    monkeypatch.setenv("SHIPPO_WEBHOOK_PASS", "secret")

    auth = "Basic " + base64.b64encode(b"shippo:secret").decode("ascii")
    payload = {
        "event": "track_updated",
        "object_id": "evt_123",
        "data": {
            "object_id": "trk_123",
            "tracking_number": "9400111899223847182933",
            "carrier": "USPS",
            "tracking_status": {"status": "TRANSIT"},
        },
    }

    first = client.post("/webhooks/shippo", json=payload, headers={"Authorization": auth})
    assert first.status_code == 200
    second = client.post("/webhooks/shippo", json=payload, headers={"Authorization": auth})
    assert second.status_code == 200
    assert second.json().get("duplicate") is True

    conn = get_test_db()
    row = conn.execute("SELECT shipping_status FROM request_shipping WHERE request_id = ?", (req["request_id"],)).fetchone()
    events = conn.execute(
        "SELECT COUNT(*) as c FROM request_shipping_events WHERE request_id = ? AND provider_event_id = ?",
        (req["request_id"], "track_updated:evt_123"),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row["shipping_status"] == "IN_TRANSIT"
    assert events["c"] == 1


def test_shippo_webhook_auth_with_url_token(client, monkeypatch):
    _set_shipping_enabled(True)
    req = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="shiptoken@example.com")

    conn = get_test_db()
    conn.execute(
        "UPDATE request_shipping SET tracking_number = ?, carrier = ? WHERE request_id = ?",
        ("9400111899223847000000", "USPS", req["request_id"]),
    )
    conn.execute(
        """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
        ("shippo_webhook_token", "tok_test_123", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    from app import api_builds
    monkeypatch.setattr(api_builds, "_notify_requester_shipping_status", lambda *args, **kwargs: None)

    payload = {
        "event": "track_updated",
        "object_id": "evt_tok_1",
        "data": {
            "object_id": "trk_tok_1",
            "tracking_number": "9400111899223847000000",
            "carrier": "USPS",
            "tracking_status": {"status": "OUT_FOR_DELIVERY"},
        },
    }

    ok = client.post("/webhooks/shippo?token=tok_test_123", json=payload)
    ok_path = client.post("/webhooks/shippo/tok_test_123", json=payload)
    bad = client.post("/webhooks/shippo?token=wrong", json=payload)
    assert ok.status_code == 200
    assert ok_path.status_code == 200
    assert bad.status_code == 401


def test_shippo_webhook_handles_string_data_payload(client, monkeypatch):
    _set_shipping_enabled(True)
    req = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="shipstrdata@example.com")

    conn = get_test_db()
    conn.execute(
        "UPDATE request_shipping SET provider_transaction_id = ? WHERE request_id = ?",
        ("txn_str_123", req["request_id"]),
    )
    conn.execute(
        """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
        ("shippo_webhook_token", "tok_test_456", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    from app import api_builds
    monkeypatch.setattr(api_builds, "_notify_requester_shipping_status", lambda *args, **kwargs: None)

    payload = {
        "event": "transaction_updated",
        "object_id": "evt_string_data_1",
        "data": "txn_str_123",
    }
    resp = client.post("/webhooks/shippo?token=tok_test_456", json=payload)
    assert resp.status_code == 200
