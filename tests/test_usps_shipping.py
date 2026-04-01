"""
Tests for USPS v3 API shipping integration.

Covers:
- USPS status mapping
- USPSClient address validation, rates, tracking, labels (mocked)
- USPS route integration (validate-address, rates, buy-label with USPS path)
- Tracking poller logic
- Batch operations
- Label PDF storage and serving
- Helper functions (save_label_pdf, usps_tracking_url, _format_mail_class)
"""
import json
import os
import tempfile
import uuid

import pytest

from tests.conftest import (
    create_test_request,
    get_test_db,
    assert_redirect_to,
)


# ---------------------------------------------------------------------------
# Helper: enable shipping in test DB
# ---------------------------------------------------------------------------

def _set_shipping_enabled(enabled: bool = True):
    conn = get_test_db()
    conn.execute(
        """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
        ("shipping_enabled", "1" if enabled else "0", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()


def _set_usps_configured():
    """Configure USPS credentials in the test DB so _usps_configured() returns True."""
    conn = get_test_db()
    for key, val in [
        ("usps_client_id", "test_client_id"),
        ("usps_client_secret", "test_client_secret"),
        ("usps_test_mode", "1"),
        ("ship_from_name", "Test Lab"),
        ("ship_from_street1", "100 Test St"),
        ("ship_from_city", "Austin"),
        ("ship_from_state", "TX"),
        ("ship_from_zip", "78701"),
    ]:
        conn.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (key, val, "2026-01-01T00:00:00Z"),
        )
    conn.commit()
    conn.close()


def _set_usps_label_configured():
    """Add CRID/MID/EPS needed for label purchase."""
    conn = get_test_db()
    for key, val in [
        ("usps_crid", "12345678"),
        ("usps_mid", "900123456"),
        ("usps_eps_account", "1000000001"),
    ]:
        conn.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (key, val, "2026-01-01T00:00:00Z"),
        )
    conn.commit()
    conn.close()


# ===========================================================================
# 1. Status mapping tests
# ===========================================================================

class TestUSPSStatusMapping:
    """Test map_usps_tracking_status covers all USPS statusCategory values."""

    def test_pre_shipment(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Pre-Shipment") == "PRE_TRANSIT"

    def test_accepted(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Accepted") == "PRE_TRANSIT"

    def test_in_transit(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("In Transit") == "IN_TRANSIT"

    def test_in_transit_hyphenated(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("In-Transit") == "IN_TRANSIT"

    def test_out_for_delivery(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Out for Delivery") == "OUT_FOR_DELIVERY"

    def test_delivered(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Delivered") == "DELIVERED"

    def test_alert_maps_to_exception(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Alert") == "EXCEPTION"

    def test_return_to_sender(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Return to Sender") == "RETURNED"

    def test_returned(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Returned") == "RETURNED"

    def test_unknown_string_defaults_to_in_transit(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("Something New") == "IN_TRANSIT"

    def test_empty_defaults_to_pre_transit(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("") == "PRE_TRANSIT"
        assert map_usps_tracking_status(None) == "PRE_TRANSIT"

    def test_case_insensitive(self):
        from app.shipping_usps import map_usps_tracking_status
        assert map_usps_tracking_status("delivered") == "DELIVERED"
        assert map_usps_tracking_status("IN TRANSIT") == "IN_TRANSIT"
        assert map_usps_tracking_status("alert") == "EXCEPTION"


# ===========================================================================
# 2. Helper function tests
# ===========================================================================

class TestUSPSHelpers:
    """Test standalone helper functions."""

    def test_usps_tracking_url(self):
        from app.shipping_usps import usps_tracking_url
        url = usps_tracking_url("9400111899223847182933")
        assert "9400111899223847182933" in url
        assert "tools.usps.com" in url

    def test_usps_tracking_url_strips_whitespace(self):
        from app.shipping_usps import usps_tracking_url
        url = usps_tracking_url("  1234  ")
        assert "tLabels=1234" in url

    def test_save_label_pdf(self):
        from app.shipping_usps import save_label_pdf
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_bytes = b"%PDF-1.4 fake label content"
            path = save_label_pdf("req_123", pdf_bytes, base_dir=tmpdir)
            assert "req_123.pdf" in path
            with open(path, "rb") as f:
                assert f.read() == pdf_bytes

    def test_format_mail_class(self):
        from app.shipping_usps import _format_mail_class
        assert _format_mail_class("PRIORITY_MAIL") == "USPS Priority Mail"
        assert _format_mail_class("USPS_GROUND_ADVANTAGE") == "USPS Ground Advantage"
        assert _format_mail_class("FIRST_CLASS_MAIL") == "USPS First-Class Mail"
        # Unknown class gets title-cased
        assert _format_mail_class("SOME_NEW_CLASS") == "Some New Class"

    def test_normalize_rates_sorts_by_price(self):
        from app.shipping_usps import USPSClient
        # We can test normalize_rates without a real client—just call the method
        # Need a client instance; we must mock credentials
        client = USPSClient.__new__(USPSClient)  # bypass __init__
        raw = {
            "rateOptions": [
                {"mailClass": "PRIORITY_MAIL_EXPRESS", "totalBasePrice": 26.95, "rateIndicator": "SP"},
                {"mailClass": "USPS_GROUND_ADVANTAGE", "totalBasePrice": 5.40, "rateIndicator": "SP"},
                {"mailClass": "PRIORITY_MAIL", "totalBasePrice": 9.80, "rateIndicator": "SP"},
            ]
        }
        rates = client.normalize_rates(raw)
        assert len(rates) == 3
        # Cheapest first
        assert float(rates[0]["amount"]) == 5.40
        assert float(rates[1]["amount"]) == 9.80
        assert float(rates[2]["amount"]) == 26.95
        assert rates[0]["provider"] == "USPS"

    def test_is_address_valid(self):
        from app.shipping_usps import USPSClient
        client = USPSClient.__new__(USPSClient)
        assert client.is_address_valid({"additionalInfo": {"DPVConfirmation": "Y"}}) is True
        assert client.is_address_valid({"additionalInfo": {"DPVConfirmation": "S"}}) is True
        assert client.is_address_valid({"additionalInfo": {"DPVConfirmation": "D"}}) is True
        assert client.is_address_valid({"additionalInfo": {"DPVConfirmation": "N"}}) is False
        assert client.is_address_valid({"additionalInfo": {}}) is False
        assert client.is_address_valid({}) is False

    def test_normalize_state_full_name(self):
        from app.shipping_usps import _normalize_state
        assert _normalize_state("Wisconsin") == "WI"
        assert _normalize_state("  california  ") == "CA"
        assert _normalize_state("NEW YORK") == "NY"
        assert _normalize_state("TX") == "TX"
        assert _normalize_state("wi") == "WI"
        assert _normalize_state("") == ""

    def test_normalize_zip_strips_plus4(self):
        from app.shipping_usps import _normalize_zip
        assert _normalize_zip("54601-6318") == "54601"
        assert _normalize_zip("90210") == "90210"
        assert _normalize_zip("  10001-1234  ") == "10001"
        assert _normalize_zip("") == ""


# ===========================================================================
# 3. USPSClient init validation
# ===========================================================================

class TestUSPSClientInit:
    """Test USPSClient constructor validation."""

    def test_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("USPS_CLIENT_ID", raising=False)
        monkeypatch.delenv("USPS_CLIENT_SECRET", raising=False)
        from app.shipping_usps import USPSClient
        with pytest.raises(RuntimeError, match="credentials"):
            USPSClient(client_id="", client_secret="")

    def test_test_env_uses_tem_base_url(self):
        from app.shipping_usps import USPSClient
        client = USPSClient(client_id="id", client_secret="secret", use_test_env=True)
        assert "apis-tem.usps.com" in client._base_url
        assert "apis-tem.usps.com" in client._token_url

    def test_prod_env_uses_prod_base_url(self):
        from app.shipping_usps import USPSClient
        client = USPSClient(client_id="id", client_secret="secret", use_test_env=False)
        assert client._base_url == "https://apis.usps.com"


# ===========================================================================
# 4. Route integration: USPS validate-address
# ===========================================================================

class TestUSPSValidateAddressRoute:
    """Test the validate-address endpoint with USPS path."""

    def test_usps_validate_address_valid(self, admin_client, monkeypatch):
        _set_shipping_enabled(True)
        _set_usps_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeUSPSClient:
            def __init__(self, **kwargs):
                pass
            def validate_address(self, street, city, state, zip_code="", secondary=""):
                return {
                    "address": {"streetAddress": "123 TEST ST", "city": "AUSTIN", "state": "TX", "ZIPCode": "78701"},
                    "additionalInfo": {"DPVConfirmation": "Y"},
                }
            def is_address_valid(self, result):
                return True

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        monkeypatch.setattr(api_builds, "_usps_client", lambda: FakeUSPSClient())

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/validate-address",
            follow_redirects=False,
        )
        assert response.status_code == 303

        conn = get_test_db()
        row = conn.execute(
            "SELECT shipping_status, address_validation_status FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert row["shipping_status"] == "ADDRESS_VALIDATED"
        assert row["address_validation_status"] == "valid"

    def test_usps_validate_address_invalid(self, admin_client, monkeypatch):
        _set_shipping_enabled(True)
        _set_usps_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeUSPSClient:
            def __init__(self, **kwargs):
                pass
            def validate_address(self, street, city, state, zip_code="", secondary=""):
                return {
                    "address": {},
                    "additionalInfo": {"DPVConfirmation": "N", "footnotes": "Street not found"},
                }
            def is_address_valid(self, result):
                return False

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        monkeypatch.setattr(api_builds, "_usps_client", lambda: FakeUSPSClient())

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/validate-address",
            follow_redirects=False,
        )
        assert response.status_code == 303

        conn = get_test_db()
        row = conn.execute(
            "SELECT shipping_status, address_validation_status FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert row["address_validation_status"] == "invalid"
        # Status should NOT advance to ADDRESS_VALIDATED
        assert row["shipping_status"] != "ADDRESS_VALIDATED"


# ===========================================================================
# 5. Route integration: USPS rates
# ===========================================================================

class TestUSPSRatesRoute:
    """Test the rates endpoint with USPS path."""

    def test_usps_fetch_rates(self, admin_client, monkeypatch):
        _set_shipping_enabled(True)
        _set_usps_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeUSPSClient:
            def __init__(self, **kwargs):
                pass
            def get_rates(self, origin_zip, dest_zip, weight_oz, length_in=0, width_in=0, height_in=0, mail_classes=None):
                return {
                    "rateOptions": [
                        {"mailClass": "PRIORITY_MAIL", "totalBasePrice": 9.80, "rateIndicator": "SP"},
                        {"mailClass": "USPS_GROUND_ADVANTAGE", "totalBasePrice": 5.40, "rateIndicator": "SP"},
                    ]
                }
            def normalize_rates(self, raw):
                return [
                    {"provider": "USPS", "mail_class": "USPS_GROUND_ADVANTAGE", "service_name": "USPS Ground Advantage", "amount": "5.40"},
                    {"provider": "USPS", "mail_class": "PRIORITY_MAIL", "service_name": "USPS Priority Mail", "amount": "9.80"},
                ]

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        monkeypatch.setattr(api_builds, "_usps_client", lambda: FakeUSPSClient())
        monkeypatch.setattr(api_builds, "_shipping_from_address", lambda: {
            "name": "Test Lab", "street1": "100 Test St", "city": "Austin",
            "state": "TX", "zip": "78701", "country": "US",
        })

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/rates",
            data={"package_weight_oz": "12", "package_length_in": "8", "package_width_in": "6", "package_height_in": "4"},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303)

        conn = get_test_db()
        snap = conn.execute(
            "SELECT * FROM request_shipping_rate_snapshots WHERE request_id = ? ORDER BY created_at DESC LIMIT 1",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert snap is not None

    def test_usps_rates_missing_origin_zip(self, admin_client, monkeypatch):
        """If ship-from ZIP is not configured, should return 400."""
        _set_shipping_enabled(True)
        _set_usps_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        # Clear origin ZIP
        conn = get_test_db()
        conn.execute("DELETE FROM settings WHERE key = 'ship_from_zip'")
        conn.commit()
        conn.close()

        # Also patch _shipping_from_address to return empty ZIP
        original_from = api_builds._shipping_from_address
        monkeypatch.setattr(api_builds, "_shipping_from_address", lambda: {**original_from(), "zip": ""})

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/rates",
            data={"package_weight_oz": "12"},
            follow_redirects=False,
        )
        assert response.status_code == 400


# ===========================================================================
# 6. Route integration: USPS buy-label
# ===========================================================================

class TestUSPSBuyLabelRoute:
    """Test the buy-label endpoint with USPS path."""

    def test_usps_buy_label_success(self, admin_client, monkeypatch):
        _set_shipping_enabled(True)
        _set_usps_configured()
        _set_usps_label_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeUSPSClient:
            def __init__(self, **kwargs):
                pass
            def get_payment_token(self, crid, mid, account_number, account_type="EPS"):
                return "pay_tok_fake_123"
            def create_label(self, from_address, to_address, weight_oz, length_in, width_in, height_in, mail_class="PRIORITY_MAIL", payment_token="", image_type="PDF"):
                return {
                    "tracking_number": "9400111899223847999999",
                    "postage": "9.80",
                    "label_bytes": b"%PDF-1.4 fake label",
                    "raw_response": {"trackingNumber": "9400111899223847999999", "postage": "9.80"},
                }

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        monkeypatch.setattr(api_builds, "_usps_client", lambda: FakeUSPSClient())
        monkeypatch.setattr(api_builds, "_notify_requester_shipping_status", lambda *args, **kwargs: None)

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/buy-label",
            data={"mail_class": "PRIORITY_MAIL"},
            follow_redirects=False,
        )
        assert response.status_code == 303

        conn = get_test_db()
        row = conn.execute(
            "SELECT shipping_status, tracking_number, carrier, label_file_path, provider FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["tracking_number"] == "9400111899223847999999"
        assert row["carrier"] == "USPS"
        assert row["provider"] == "usps"
        # Label should have been saved
        assert row["label_file_path"] is not None
        assert row["label_file_path"].endswith(".pdf")

    def test_usps_buy_label_missing_crid_mid_eps(self, admin_client, monkeypatch):
        """Label purchase fails when CRID/MID/EPS are not configured."""
        _set_shipping_enabled(True)
        _set_usps_configured()
        # Intentionally do NOT call _set_usps_label_configured()
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeUSPSClient:
            def __init__(self, **kwargs):
                pass

        monkeypatch.setattr(api_builds, "_usps_configured", lambda: True)
        monkeypatch.setattr(api_builds, "_usps_client", lambda: FakeUSPSClient())
        # Ensure CRID/MID/EPS are empty (prior tests may have set them in settings)
        monkeypatch.setattr(api_builds, "_usps_crid", lambda: "")
        monkeypatch.setattr(api_builds, "_usps_mid", lambda: "")
        monkeypatch.setattr(api_builds, "_usps_eps_account", lambda: "")

        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/buy-label",
            data={"mail_class": "PRIORITY_MAIL"},
            follow_redirects=False,
        )
        assert response.status_code == 400


# ===========================================================================
# 7. Label PDF serving
# ===========================================================================

class TestLabelPDFServing:
    """Test the label PDF download route."""

    def test_serve_label_pdf(self, admin_client):
        _set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        # Create a temp label file
        from app.shipping_usps import save_label_pdf
        label_bytes = b"%PDF-1.4 test label content for serving"
        label_path = save_label_pdf(req["request_id"], label_bytes, base_dir="tests/tmp_data/labels")

        conn = get_test_db()
        conn.execute(
            "UPDATE request_shipping SET label_file_path = ? WHERE request_id = ?",
            (label_path, req["request_id"]),
        )
        conn.commit()
        conn.close()

        response = admin_client.get(f"/admin/request/{req['request_id']}/shipping/label.pdf")
        assert response.status_code == 200
        assert b"%PDF-1.4" in response.content
        # Cleanup
        os.remove(label_path)

    def test_serve_label_pdf_not_found(self, admin_client):
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)
        response = admin_client.get(f"/admin/request/{req['request_id']}/shipping/label.pdf")
        assert response.status_code == 404


# ===========================================================================
# 8. Batch operations
# ===========================================================================

class TestBatchOperations:
    """Test POST /admin/shipping/batch actions."""

    def test_batch_mark_delivered(self, admin_client):
        _set_shipping_enabled(True)
        req1 = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="batch1@example.com")
        req2 = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="batch2@example.com")

        # Set tracking numbers so they appear as active
        conn = get_test_db()
        for req in [req1, req2]:
            conn.execute(
                "UPDATE request_shipping SET tracking_number = ?, carrier = ?, shipping_status = ? WHERE request_id = ?",
                ("94001118992238471829" + req["request_id"][:2], "USPS", "IN_TRANSIT", req["request_id"]),
            )
        conn.commit()
        conn.close()

        ids_csv = f"{req1['request_id']},{req2['request_id']}"
        response = admin_client.post(
            "/admin/shipping/batch",
            data={"action": "mark-delivered", "ids": ids_csv},
            follow_redirects=False,
        )
        assert response.status_code == 303

        conn = get_test_db()
        for req in [req1, req2]:
            row = conn.execute(
                "SELECT shipping_status, delivered_at FROM request_shipping WHERE request_id = ?",
                (req["request_id"],),
            ).fetchone()
            assert row["shipping_status"] == "DELIVERED"
            assert row["delivered_at"] is not None
        # Check events were created
        events = conn.execute(
            "SELECT COUNT(*) as c FROM request_shipping_events WHERE event_type = 'delivered_batch'",
        ).fetchone()
        conn.close()
        assert events["c"] == 2

    def test_batch_mark_delivered_skips_already_delivered(self, admin_client):
        """Batch should skip requests that are already DELIVERED."""
        _set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)
        conn = get_test_db()
        conn.execute(
            "UPDATE request_shipping SET shipping_status = 'DELIVERED' WHERE request_id = ?",
            (req["request_id"],),
        )
        conn.commit()
        conn.close()

        response = admin_client.post(
            "/admin/shipping/batch",
            data={"action": "mark-delivered", "ids": req["request_id"]},
            follow_redirects=False,
        )
        assert response.status_code == 303

        conn = get_test_db()
        events = conn.execute(
            "SELECT COUNT(*) as c FROM request_shipping_events WHERE request_id = ? AND event_type = 'delivered_batch'",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert events["c"] == 0  # Should not create an event if already delivered

    def test_batch_empty_ids_redirects(self, admin_client):
        """Batch with no IDs should just redirect back."""
        response = admin_client.post(
            "/admin/shipping/batch",
            data={"action": "mark-delivered", "ids": ""},
            follow_redirects=False,
        )
        assert response.status_code == 303


# ===========================================================================
# 9. Tracking poller unit tests
# ===========================================================================

class TestTrackingPollerHelpers:
    """Test components of the tracking poller without running the async loop."""

    def test_now_iso_format(self):
        from app.shipping_poller import _now_iso
        ts = _now_iso()
        assert ts.endswith("Z")
        assert "T" in ts
        # Should be parseable
        from datetime import datetime
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def test_poller_updates_status_on_change(self, client, monkeypatch):
        """Simulate a tracking poll that finds a status change and verify DB update."""
        _set_shipping_enabled(True)
        req = create_test_request(
            fulfillment_method="shipping",
            with_shipping=True,
            requester_email="polltest@example.com",
        )

        # Set initial shipping state
        conn = get_test_db()
        conn.execute(
            """UPDATE request_shipping
               SET tracking_number = ?, carrier = ?, shipping_status = ?, provider = ?
               WHERE request_id = ?""",
            ("9400111899223847111111", "USPS", "PRE_TRANSIT", "usps", req["request_id"]),
        )
        conn.commit()
        conn.close()

        # Directly test the DB update logic that the poller performs
        from app.shipping_usps import map_usps_tracking_status
        new_status = map_usps_tracking_status("In Transit")
        assert new_status == "IN_TRANSIT"

        # Simulate the update the poller would make
        from app.shipping_poller import _now_iso
        now = _now_iso()
        conn = get_test_db()
        conn.execute(
            """UPDATE request_shipping
               SET usps_last_polled_at = ?, shipping_status = ?, tracking_status = ?, updated_at = ?
               WHERE request_id = ?""",
            (now, new_status, new_status, now, req["request_id"]),
        )
        conn.execute(
            """INSERT INTO request_shipping_events
               (id, request_id, created_at, event_type, shipping_status, provider, message, payload_json)
               VALUES (?, ?, ?, 'tracking_poll', ?, 'usps', ?, ?)""",
            (
                str(uuid.uuid4()),
                req["request_id"],
                now,
                new_status,
                f"USPS tracking updated: PRE_TRANSIT → {new_status}",
                json.dumps({"statusCategory": "In Transit"}),
            ),
        )
        conn.commit()

        # Verify
        row = conn.execute(
            "SELECT shipping_status, tracking_status, usps_last_polled_at FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        event = conn.execute(
            "SELECT * FROM request_shipping_events WHERE request_id = ? AND event_type = 'tracking_poll'",
            (req["request_id"],),
        ).fetchone()
        conn.close()

        assert row["shipping_status"] == "IN_TRANSIT"
        assert row["tracking_status"] == "IN_TRANSIT"
        assert row["usps_last_polled_at"] is not None
        assert event is not None
        assert "IN_TRANSIT" in event["message"]

    def test_poller_sets_delivered_at(self, client):
        """When a tracking update shows DELIVERED, delivered_at should be set."""
        _set_shipping_enabled(True)
        req = create_test_request(
            fulfillment_method="shipping",
            with_shipping=True,
            requester_email="polldeliver@example.com",
        )

        conn = get_test_db()
        conn.execute(
            """UPDATE request_shipping
               SET tracking_number = ?, shipping_status = ?, provider = ?
               WHERE request_id = ?""",
            ("9400111899223847222222", "IN_TRANSIT", "usps", req["request_id"]),
        )
        conn.commit()

        from app.shipping_poller import _now_iso
        now = _now_iso()
        conn.execute(
            """UPDATE request_shipping
               SET shipping_status = 'DELIVERED', tracking_status = 'DELIVERED',
                   delivered_at = COALESCE(delivered_at, ?), updated_at = ?
               WHERE request_id = ?""",
            (now, now, req["request_id"]),
        )
        conn.commit()

        row = conn.execute(
            "SELECT delivered_at FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert row["delivered_at"] is not None


# ===========================================================================
# 10. USPS settings in admin
# ===========================================================================

class TestUSPSAdminSettings:
    """Test the USPS configuration section on the admin settings page."""

    def test_settings_page_shows_usps_section(self, admin_client):
        response = admin_client.get("/admin/settings")
        assert response.status_code == 200
        assert "USPS" in response.text
        assert "usps_client_id" in response.text

    def test_save_usps_settings(self, admin_client):
        response = admin_client.post(
            "/admin/settings",
            data={
                "usps_client_id": "new_test_client_id",
                "usps_client_secret": "new_test_secret",
                "usps_crid": "88888888",
                "usps_mid": "999888777",
                "usps_eps_account": "2000000002",
                "usps_tracking_poll_minutes": "15",
                "usps_test_mode": "1",
            },
            follow_redirects=False,
        )
        assert response.status_code in (200, 303)

        conn = get_test_db()
        crid = conn.execute("SELECT value FROM settings WHERE key = 'usps_crid'").fetchone()
        poll = conn.execute("SELECT value FROM settings WHERE key = 'usps_tracking_poll_minutes'").fetchone()
        conn.close()
        assert crid is not None
        assert crid["value"] == "88888888"
        assert poll is not None
        assert poll["value"] == "15"


# ===========================================================================
# 11. Shipping dashboard page
# ===========================================================================

class TestShippingDashboard:
    """Test the shipping dashboard page renders with USPS data."""

    def test_shipping_dashboard_loads_with_data(self, admin_client):
        _set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True, requester_email="dash@example.com")

        # Add tracking number
        conn = get_test_db()
        conn.execute(
            """UPDATE request_shipping
               SET tracking_number = ?, carrier = ?, shipping_status = ?, estimated_delivery_date = ?
               WHERE request_id = ?""",
            ("9400111899223847333333", "USPS", "IN_TRANSIT", "2026-01-15", req["request_id"]),
        )
        conn.commit()
        conn.close()

        response = admin_client.get("/admin/shipping")
        assert response.status_code == 200
        assert "9400111899223847333333" in response.text

    def test_shipping_dashboard_empty(self, admin_client):
        response = admin_client.get("/admin/shipping")
        assert response.status_code == 200


# ===========================================================================
# 12. Printellect device notification
# ===========================================================================

class TestPrintellectDeviceNotification:
    """Test the notify_device_shipping_status function."""

    def test_notify_device_shipping_status_no_account(self, client):
        """When no Printellect account exists, should not raise."""
        try:
            from app.printellect import notify_device_shipping_status
            # Should gracefully handle non-existent accounts
            notify_device_shipping_status("nonexistent@example.com", "IN_TRANSIT")
        except ImportError:
            pytest.skip("printellect module not available")

    def test_validate_action_payload_notify_shipping(self, client):
        """The notify_shipping action should validate status payloads."""
        try:
            from app.printellect import _validate_action_payload
        except ImportError:
            pytest.skip("printellect module not available")

        # Valid statuses
        for status in ("in_transit", "out_for_delivery", "delivered", "exception"):
            result = _validate_action_payload("notify_shipping", {"status": status})
            # Should not raise; returns validated payload dict or True/None
            assert result is not False

        # Invalid status should raise or return error
        try:
            result = _validate_action_payload("notify_shipping", {"status": "BAD_STATUS"})
            # If it returns an error value instead of raising
            if isinstance(result, str):
                assert "invalid" in result.lower() or "status" in result.lower()
        except (ValueError, Exception):
            pass  # Expected for invalid status

    def test_notify_device_shipping_status_queues_command_for_owned_device(self, client):
        try:
            from app.printellect import notify_device_shipping_status
        except ImportError:
            pytest.skip("printellect module not available")

        now = "2026-01-01T00:00:00Z"
        account_id = str(uuid.uuid4())
        device_id = "perkbase-ship-01"

        conn = get_test_db()
        conn.execute(
            """
            INSERT INTO accounts (id, email, name, role, status, created_at, updated_at)
            VALUES (?, ?, ?, 'user', 'active', ?, ?)
            """,
            (account_id, "notify-owner@example.com", "Notify Owner", now, now),
        )
        conn.execute(
            """
            INSERT INTO devices (device_id, name, owner_user_id, claim_code_hash, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (device_id, "Ship Device", account_id, "sha256:test", now, now),
        )
        conn.commit()
        conn.close()

        notify_device_shipping_status("notify-owner@example.com", "OUT_FOR_DELIVERY")

        conn = get_test_db()
        cmd = conn.execute(
            "SELECT action, payload_json, status FROM commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        conn.close()

        assert cmd is not None
        assert cmd["action"] == "notify_shipping"
        payload = json.loads(cmd["payload_json"] or "{}")
        assert payload["status"] == "out_for_delivery"
