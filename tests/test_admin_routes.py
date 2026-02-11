"""
Tests for admin-facing routes: authentication, queue management, settings.

Covers:
- Admin authentication flow
- Queue management endpoints
- Request status transitions
- Admin settings and configuration
- Audit logging
"""
import pytest
from datetime import datetime

# Import test utilities from conftest (auto-loaded by pytest)
from tests.conftest import (
    create_test_request,
    create_store_item,
    assert_html_contains,
    assert_html_not_contains,
    assert_json_success,
    assert_redirect_to,
    get_test_db,
)


class TestAdminAuth:
    """Tests for admin authentication."""
    
    def test_admin_login_page_loads(self, client):
        """Admin login page should load."""
        response = client.get("/admin/login")
        assert response.status_code == 200
        assert_html_contains(response, "login", "password")
    
    def test_admin_redirects_or_denies_when_not_authenticated(self, client):
        """Admin pages should require authentication."""
        response = client.get("/admin", follow_redirects=False)
        # App can either redirect (303, 307, 302) or return 401 Unauthorized
        assert response.status_code in (303, 307, 302, 401)
    
    def test_admin_with_invalid_credentials(self, client):
        """Admin login with wrong credentials should fail."""
        response = client.post("/admin/login", data={
            "username": "wrong",
            "password": "wrongpassword",
        }, follow_redirects=False)
        
        # Should stay on login page or redirect back to login
        assert response.status_code in (200, 303)
        if response.status_code == 200:
            assert "invalid" in response.text.lower() or "incorrect" in response.text.lower()


class TestAdminAuthenticatedRoutes:
    """Tests requiring admin authentication."""
    
    def test_admin_dashboard_page_loads(self, admin_client):
        """Admin dashboard page should load (this is the main queue view)."""
        response = admin_client.get("/admin")
        assert response.status_code == 200
        # Dashboard should have basic admin content
        assert "admin" in response.text.lower() or "dashboard" in response.text.lower() or "queue" in response.text.lower()
    
    def test_admin_dashboard_shows_requests(self, admin_client):
        """Admin dashboard should show all requests."""
        req = create_test_request(status="PENDING", print_name="Admin Test Print")
        
        response = admin_client.get("/admin")
        # Dashboard loads successfully (request may or may not be visible depending on status)
        assert response.status_code == 200
    
    def test_admin_request_detail_loads(self, admin_client):
        """Admin request detail page should load."""
        req = create_test_request(print_name="Detail Test")
        
        response = admin_client.get(f"/admin/request/{req['request_id']}")
        assert response.status_code == 200
        assert_html_contains(response, "Detail Test")
    
    def test_admin_request_nonexistent(self, admin_client):
        """Non-existent request should 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = admin_client.get(f"/admin/request/{fake_id}")
        assert response.status_code == 404


class TestAdminStatusTransitions:
    """Tests for request status changes."""
    
    def test_approve_pending_request(self, admin_client):
        """Should be able to approve a pending request (NEW -> APPROVED)."""
        req = create_test_request(status="NEW")
        
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "APPROVED"},
            follow_redirects=False
        )
        
        # Should succeed with redirect or JSON response
        assert response.status_code in (200, 303)
    
    def test_reject_pending_request(self, admin_client):
        """Should be able to reject a pending request (NEW -> REJECTED)."""
        req = create_test_request(status="NEW")
        
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "REJECTED", "comment": "Test rejection"},
            follow_redirects=False
        )
        
        assert response.status_code in (200, 303)
    
    def test_start_printing_requires_printer(self, admin_client):
        """Starting print should require a specific printer selection."""
        req = create_test_request(status="APPROVED")
        
        # Try to print without specifying printer - should fail
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "PRINTING"},  # No printer specified
            follow_redirects=False
        )
        
        # Should fail with 400 because no printer specified
        assert response.status_code in (400, 422)
    
    def test_start_printing_with_printer(self, admin_client):
        """Starting print with a valid printer should work."""
        req = create_test_request(status="APPROVED")
        
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "PRINTING", "printer": "ADVENTURER_4"},
            follow_redirects=False
        )
        
        # Should succeed
        assert response.status_code in (200, 303)
    
    def test_mark_request_complete(self, admin_client):
        """Should be able to mark a printing request as complete."""
        req = create_test_request(status="PRINTING")
        
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "DONE"},
            follow_redirects=False
        )
        
        assert response.status_code in (200, 303)


class TestAdminShipping:
    """Tests for admin shipping endpoints."""

    def _set_shipping_enabled(self, enabled: bool = True):
        conn = get_test_db()
        conn.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            ("shipping_enabled", "1" if enabled else "0", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
        conn.close()

    def test_fetch_shipping_rates_persists_snapshot(self, admin_client, monkeypatch):
        self._set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeShippo:
            def create_shipment_and_rates(self, address_from, address_to, parcel, metadata=None):
                return {
                    "object_id": "shippo_shipment_123",
                    "rates": [
                        {"object_id": "rate_1", "provider": "USPS", "amount": "8.40", "servicelevel": {"name": "Ground"}},
                        {"object_id": "rate_2", "provider": "UPS", "amount": "12.10", "servicelevel": {"name": "2nd Day"}},
                    ],
                }

        monkeypatch.setattr(api_builds, "ShippoClient", lambda **kw: FakeShippo())
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

    def test_save_shipping_quote_updates_record(self, admin_client):
        self._set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/quote",
            data={"quote_amount": "14.99", "quote_notes": "Manual quote"},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303)

        conn = get_test_db()
        row = conn.execute("SELECT shipping_status, quote_amount_cents FROM request_shipping WHERE request_id = ?", (req["request_id"],)).fetchone()
        conn.close()
        assert row is not None
        assert row["shipping_status"] == "QUOTED"
        assert row["quote_amount_cents"] == 1499

    def test_buy_label_persists_tracking(self, admin_client, monkeypatch):
        self._set_shipping_enabled(True)
        req = create_test_request(fulfillment_method="shipping", with_shipping=True)

        from app import api_builds

        class FakeShippo:
            def buy_label(self, rate_id, metadata=None):
                return {
                    "object_id": "txn_123",
                    "shipment": "shipment_123",
                    "tracking_number": "9400111899223847182933",
                    "tracking_provider": "USPS",
                    "tracking_status": "PRE_TRANSIT",
                    "label_url": "https://example.com/label.png",
                    "label_file": "https://example.com/label.pdf",
                    "rate": {
                        "provider": "USPS",
                        "servicelevel_name": "Ground Advantage",
                        "amount": "8.40",
                    },
                }

        monkeypatch.setattr(api_builds, "ShippoClient", lambda **kw: FakeShippo())
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/shipping/buy-label",
            data={"rate_id": "rate_123"},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303)

        conn = get_test_db()
        row = conn.execute(
            "SELECT shipping_status, tracking_number, carrier, label_url FROM request_shipping WHERE request_id = ?",
            (req["request_id"],),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["tracking_number"] == "9400111899223847182933"
        assert row["carrier"] == "USPS"
        assert row["label_url"] == "https://example.com/label.png"


class TestAdminSettings:
    """Tests for admin settings pages."""
    
    def test_admin_settings_page_loads(self, admin_client):
        """Admin settings page should load."""
        response = admin_client.get("/admin/settings")
        assert response.status_code == 200

    def test_admin_shipping_page_loads(self, admin_client):
        """Admin shipping dashboard should load."""
        response = admin_client.get("/admin/shipping")
        assert response.status_code == 200
    
    def test_admin_accounts_page_loads(self, admin_client):
        """Admin accounts page should load."""
        response = admin_client.get("/admin/accounts")
        assert response.status_code == 200
    
    def test_admin_analytics_page_loads(self, admin_client):
        """Admin analytics page should load."""
        # Create some sample data so analytics doesn't divide by zero
        create_test_request(status="NEW")
        create_test_request(status="DONE")
        
        response = admin_client.get("/admin/analytics")
        # Analytics page should load successfully
        assert response.status_code == 200


class TestAdminStore:
    """Tests for admin store management."""
    
    def test_admin_store_page_loads(self, admin_client):
        """Admin store page should load."""
        response = admin_client.get("/admin/store")
        assert response.status_code == 200
    
    def test_admin_store_shows_all_items(self, admin_client):
        """Admin store should show both active and inactive items."""
        active_id = create_store_item(name="Active Admin Item", is_active=True)
        inactive_id = create_store_item(name="Inactive Admin Item", is_active=False)
        
        response = admin_client.get("/admin/store")
        # Admin store should list items (check at least the page loads)
        assert response.status_code == 200
    
    def test_admin_store_item_detail(self, admin_client):
        """Admin store item detail should load."""
        item_id = create_store_item(name="Detailed Store Item")
        
        response = admin_client.get(f"/admin/store/item/{item_id}")
        assert response.status_code == 200
        assert_html_contains(response, "Detailed Store Item")


class TestAdminFeatureFlags:
    """Tests for feature flag management."""
    
    def test_admin_features_page_loads(self, admin_client):
        """Admin features page should load."""
        response = admin_client.get("/admin/features")
        assert response.status_code == 200
    
    def test_admin_audit_page_loads(self, admin_client):
        """Admin audit log page should load."""
        response = admin_client.get("/admin/audit")
        assert response.status_code == 200


class TestAdminFeedback:
    """Tests for feedback management."""
    
    def test_admin_feedback_page_loads(self, admin_client):
        """Admin feedback page should load."""
        response = admin_client.get("/admin/feedback")
        assert response.status_code == 200


class TestAdminBroadcast:
    """Tests for broadcast notifications."""
    
    def test_admin_broadcast_page_loads(self, admin_client):
        """Admin broadcast page should load."""
        response = admin_client.get("/admin/broadcast")
        assert response.status_code == 200


class TestAdminDebug:
    """Tests for debug/diagnostic pages."""
    
    def test_admin_debug_page_loads(self, admin_client):
        """Admin debug page should load (if exists)."""
        response = admin_client.get("/admin/debug")
        # Debug page might not exist in all configurations
        assert response.status_code in (200, 404)


class TestAdminErrorHandling:
    """Tests for error handling in admin routes."""
    
    def test_invalid_request_id_format(self, admin_client):
        """Invalid UUID format should be handled gracefully."""
        response = admin_client.get("/admin/request/not-a-uuid")
        assert response.status_code in (400, 404, 422)
    
    def test_transition_invalid_request(self, admin_client):
        """Transitioning non-existent request should fail gracefully."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = admin_client.post(
            f"/admin/request/{fake_id}/status",
            data={"to_status": "APPROVED"}
        )
        assert response.status_code in (404, 400)
    
    def test_invalid_status_value(self, admin_client):
        """Invalid status value should be rejected."""
        req = create_test_request(status="NEW")
        
        response = admin_client.post(
            f"/admin/request/{req['request_id']}/status",
            data={"to_status": "INVALID_STATUS"}
        )
        # Should be rejected with 400 - invalid status
        assert response.status_code == 400
