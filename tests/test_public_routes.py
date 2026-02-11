"""
Tests for public-facing routes: request submission, queue, store, feedback.

Covers:
- Happy paths for all public pages
- Form validation and error handling
- Edge cases and error scenarios
- Response content verification
"""
import pytest
from io import BytesIO

# Import test utilities from conftest (auto-loaded by pytest)
from tests.conftest import (
    create_test_request,
    create_store_item,
    create_email_lookup_token,
    assert_html_contains,
    assert_html_not_contains,
    assert_redirect_to,
    clear_all_test_data,
    get_test_db,
)


class TestHomePage:
    """Tests for the home/request form page."""
    
    def test_home_page_loads(self, client):
        """Home page should load with request form."""
        response = client.get("/")
        assert response.status_code == 200
        assert_html_contains(response, "New Print Request", "form")
    
    def test_home_page_shows_printer_options(self, client):
        """Home page should display printer selection options."""
        response = client.get("/")
        assert_html_contains(response, "printer", "material")
    
    def test_home_page_accessible_without_auth(self, client):
        """Home page should be accessible without any authentication."""
        response = client.get("/")
        assert response.status_code == 200


class TestRequestSubmission:
    """Tests for the /submit endpoint."""

    def _set_shipping_enabled(self, enabled: bool = True):
        conn = get_test_db()
        now = "2026-01-01T00:00:00Z"
        conn.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            ("shipping_enabled", "1" if enabled else "0", now),
        )
        conn.commit()
        conn.close()
    
    def test_submit_with_valid_data_and_link(self, client):
        """Valid submission with link URL should succeed."""
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
            "link_url": "https://example.com/model.stl",
        }, follow_redirects=False)
        
        # Should redirect to thanks page or show success
        assert response.status_code in (200, 303)
        if response.status_code == 200:
            # Check for various success indicators
            text_lower = response.text.lower()
            assert any(word in text_lower for word in ["thank", "received", "submitted", "success"])
    
    def test_submit_rejects_invalid_printer(self, client):
        """Submission with invalid printer code should fail."""
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "INVALID_PRINTER",
            "material": "PLA",
            "colors": "Blue",
            "link_url": "https://example.com/model.stl",
        })
        
        assert response.status_code in (200, 400)
        assert "invalid" in response.text.lower() or "printer" in response.text.lower()
    
    def test_submit_rejects_invalid_material(self, client):
        """Submission with invalid material code should fail."""
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "UNOBTAINIUM",
            "colors": "Blue",
            "link_url": "https://example.com/model.stl",
        })
        
        assert response.status_code in (200, 400)
        assert "invalid" in response.text.lower() or "material" in response.text.lower()
    
    def test_submit_requires_link_or_file(self, client):
        """Submission without link or file should fail."""
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
            # No link_url or file
        })
        
        assert response.status_code in (200, 400)
        assert "link" in response.text.lower() or "file" in response.text.lower() or "required" in response.text.lower()
    
    def test_submit_rejects_invalid_link_url(self, client):
        """Submission with malformed URL should fail gracefully."""
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
            "link_url": "not-a-valid-url",
        })
        
        assert response.status_code in (200, 400)
        assert "invalid" in response.text.lower() or "url" in response.text.lower()
    
    def test_submit_rejects_disallowed_file_extension(self, client):
        """Submission with disallowed file type should fail."""
        fake_file = BytesIO(b"malicious content")
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
        }, files={"upload": ("malware.exe", fake_file, "application/octet-stream")})
        
        assert response.status_code in (200, 400)
        assert "not allowed" in response.text.lower() or "file type" in response.text.lower()
    
    def test_submit_with_valid_stl_file(self, client):
        """Submission with valid STL file should succeed."""
        # Minimal valid-looking STL content
        stl_content = b"solid test\nendsolid test"
        stl_file = BytesIO(stl_content)
        
        response = client.post("/submit", data={
            "requester_name": "Test User",
            "requester_email": "test@example.com",
            "print_name": "My Test Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
        }, files={"upload": ("model.stl", stl_file, "application/octet-stream")})
        
        # Should succeed
        assert response.status_code in (200, 303)
        if response.status_code == 200:
            # Check for success indicators
            text_lower = response.text.lower()
            assert any(word in text_lower for word in ["thank", "received", "submitted", "success"])
    
    def test_submit_preserves_form_data_on_error(self, client):
        """When submission fails, form should preserve entered data."""
        response = client.post("/submit", data={
            "requester_name": "My Unique Name",
            "requester_email": "unique@example.com",
            "print_name": "My Unique Print",
            "printer": "INVALID",  # This will cause failure
            "material": "PLA",
            "colors": "Custom Color",
        })
        
        # Form should re-render with preserved values
        assert "My Unique Name" in response.text or "unique@example.com" in response.text

    def test_submit_shipping_requires_account(self, client):
        """Guests selecting shipping are redirected into registration flow."""
        self._set_shipping_enabled(True)
        response = client.post("/submit", data={
            "requester_name": "Guest User",
            "requester_email": "guest@example.com",
            "print_name": "Ship Me",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Black",
            "link_url": "https://example.com/model.stl",
            "fulfillment_method": "shipping",
            "ship_recipient_name": "Guest User",
            "ship_address_line1": "123 Main St",
            "ship_city": "Austin",
            "ship_state": "TX",
            "ship_postal_code": "78701",
            "ship_country": "US",
        }, follow_redirects=False)
        assert response.status_code in (303, 302)
        location = response.headers.get("location", "")
        assert location.startswith("/auth/register")
        assert "email=guest%40example.com" in location

    def test_submit_shipping_missing_address_fields(self, client):
        """Shipping submission validates required address fields."""
        self._set_shipping_enabled(True)
        from app.auth import create_user, create_user_session
        user = create_user("shipmissing@example.com", "Ship Missing", "Password123")
        token = create_user_session(user.id, "pytest", "127.0.0.1")
        client.cookies.set("user_session", token)

        response = client.post("/submit", data={
            "requester_name": "Ship Missing",
            "requester_email": "shipmissing@example.com",
            "print_name": "Address Check",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Black",
            "link_url": "https://example.com/model.stl",
            "fulfillment_method": "shipping",
            "ship_recipient_name": "Ship Missing",
            # Missing street/city/state/postal
            "ship_country": "US",
        })
        assert response.status_code in (200, 400)
        assert "missing shipping info" in response.text.lower()

    def test_submit_shipping_authenticated_creates_shipping_record(self, client):
        """Authenticated shipping submit creates both request and request_shipping rows."""
        self._set_shipping_enabled(True)
        from app.auth import create_user, create_user_session
        user = create_user("shipok@example.com", "Ship OK", "Password123")
        token = create_user_session(user.id, "pytest", "127.0.0.1")
        client.cookies.set("user_session", token)

        response = client.post("/submit", data={
            "requester_name": "Ship OK",
            "requester_email": "shipok@example.com",
            "print_name": "Shipping Print",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
            "link_url": "https://example.com/model.stl",
            "fulfillment_method": "shipping",
            "ship_recipient_name": "Ship OK",
            "ship_address_line1": "123 Main St",
            "ship_city": "Austin",
            "ship_state": "TX",
            "ship_postal_code": "78701",
            "ship_country": "US",
            "ship_service_preference": "standard",
        }, follow_redirects=False)
        assert response.status_code in (200, 303)

        conn = get_test_db()
        req = conn.execute(
            "SELECT id, fulfillment_method FROM requests WHERE requester_email = ? ORDER BY created_at DESC LIMIT 1",
            ("shipok@example.com",),
        ).fetchone()
        assert req is not None
        assert req["fulfillment_method"] == "shipping"
        shipping = conn.execute("SELECT * FROM request_shipping WHERE request_id = ?", (req["id"],)).fetchone()
        conn.close()
        assert shipping is not None


class TestQueuePage:
    """Tests for the public queue page."""
    
    def test_queue_page_loads(self, client):
        """Queue page should load successfully."""
        response = client.get("/queue")
        assert response.status_code == 200
        assert_html_contains(response, "Print Queue")
    
    def test_queue_shows_mobile_and_desktop_views(self, client):
        """Queue should have both mobile and desktop containers."""
        response = client.get("/queue")
        assert_html_contains(response, 'id="queue-mobile"', 'id="queue-desktop"')
    
    def test_queue_shows_request_when_exists(self, client):
        """Queue should display existing requests."""
        req = create_test_request(status="APPROVED", print_name="Visible Print")
        
        response = client.get("/queue")
        assert_html_contains(response, "Visible Print")
    
    def test_queue_hides_picked_up_requests(self, client):
        """Queue should not show PICKED_UP requests."""
        req = create_test_request(status="PICKED_UP", print_name="Hidden Print")
        
        response = client.get("/queue")
        assert_html_not_contains(response, "Hidden Print")
    
    def test_queue_mine_parameter_highlights_request(self, client):
        """Queue with mine parameter should highlight the user's request."""
        req = create_test_request(status="APPROVED", print_name="My Special Print")
        short_id = req["request_id"][:8]
        
        response = client.get(f"/queue?mine={short_id}")
        assert response.status_code == 200
        # Should contain the request and possibly highlighting class
        assert "My Special Print" in response.text


class TestStorePage:
    """Tests for the store pages."""
    
    def test_store_page_loads(self, client):
        """Store page should load successfully."""
        response = client.get("/store")
        assert response.status_code == 200
        assert "store" in response.text.lower()
    
    def test_store_shows_active_items(self, client):
        """Store should display active items."""
        item_id = create_store_item(name="Available Widget", is_active=True)
        
        response = client.get("/store")
        assert_html_contains(response, "Available Widget")
    
    def test_store_hides_inactive_items(self, client):
        """Store should not display inactive items."""
        item_id = create_store_item(name="Hidden Widget", is_active=False)
        
        response = client.get("/store")
        assert_html_not_contains(response, "Hidden Widget")
    
    def test_store_item_detail_page(self, client):
        """Store item detail page should load for valid item."""
        item_id = create_store_item(name="Detail Widget")
        
        response = client.get(f"/store/item/{item_id}")
        assert response.status_code == 200
        assert_html_contains(response, "Detail Widget")
    
    def test_store_item_404_for_invalid_id(self, client):
        """Store item page should 404 for non-existent item."""
        response = client.get("/store/item/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404


class TestFeedbackAndChangelog:
    """Tests for feedback form and changelog pages."""
    
    def test_feedback_page_loads(self, client):
        """Feedback page should load successfully."""
        response = client.get("/feedback")
        assert response.status_code == 200
        assert "feedback" in response.text.lower()
    
    def test_changelog_page_loads(self, client):
        """Changelog page should load successfully."""
        response = client.get("/changelog")
        assert response.status_code == 200
        assert "version" in response.text.lower() or "changelog" in response.text.lower()
    
    def test_feedback_submission(self, client):
        """Feedback form should accept submissions."""
        response = client.post("/feedback", data={
            "feedback_type": "suggestion",  # Note: field is feedback_type, not type
            "name": "Test Feedback User",
            "email": "feedback@example.com",
            "message": "This is a detailed test feedback message for testing purposes.",  # Must be >= 10 chars
        }, follow_redirects=True)  # Follow redirects to see the final page
        
        # Should show success after redirect
        assert response.status_code == 200
        # Feedback page should show success message or re-render cleanly
        text_lower = response.text.lower()
        assert "feedback" in text_lower or "submitted" in text_lower or "success" in text_lower or "thank" in text_lower


class TestStaticAssets:
    """Tests for static assets and PWA files."""
    
    def test_offline_page_loads(self, client):
        """Offline page should be accessible."""
        # Try both possible locations
        response = client.get("/static/offline.html")
        if response.status_code == 404:
            response = client.get("/offline.html")
        
        assert response.status_code == 200
        assert "offline" in response.text.lower()
    
    def test_service_worker_loads(self, client):
        """Service worker JS should be accessible."""
        response = client.get("/sw.js")
        assert response.status_code == 200
        assert "SW_VERSION" in response.text or "CACHE_NAME" in response.text
    
    def test_manifest_loads(self, client):
        """PWA manifest should be accessible."""
        response = client.get("/manifest.json")
        if response.status_code == 404:
            response = client.get("/static/manifest.json")
        
        assert response.status_code == 200


class TestErrorHandling:
    """Tests for error handling and edge cases."""
    
    def test_404_returns_friendly_page(self, client):
        """Non-existent routes should return friendly 404 page."""
        response = client.get("/this-route-does-not-exist")
        assert response.status_code == 404
        # Should be a rendered error page, not raw JSON
        assert "not found" in response.text.lower() or "404" in response.text
    
    def test_invalid_request_id_format(self, client):
        """Invalid UUID format should be handled gracefully."""
        response = client.get("/my/not-a-valid-uuid?token=sometoken")
        # Should not crash - either 404 or 400
        assert response.status_code in (400, 404, 403, 422)
    
    def test_missing_required_form_fields(self, client):
        """Missing required form fields should return helpful error."""
        response = client.post("/submit", data={
            "requester_name": "Test",
            # Missing other required fields
        })
        
        # Should return 422 (validation error) or 400, or re-render form with error
        assert response.status_code in (200, 400, 422)


class TestMyRequestsAccess:
    """Tests for requester portal access and token validation."""
    
    def test_my_requests_invalid_token(self, client):
        """Invalid token should show friendly error."""
        response = client.get("/my-requests/view?token=invalid-token")
        assert response.status_code == 200
        assert "expired" in response.text.lower() or "invalid" in response.text.lower()
    
    def test_my_requests_valid_token(self, client):
        """Valid token should show requests list."""
        req = create_test_request()
        
        response = client.get(f"/my-requests/view?token={req['requester_token']}")
        assert response.status_code == 200
        # Should show the request or empty state
        assert "request" in response.text.lower() or "print" in response.text.lower()
    
    def test_my_request_detail_invalid_token(self, client):
        """Request detail with wrong token should be rejected."""
        req = create_test_request()
        
        response = client.get(f"/my/{req['request_id']}?token=wrong-token")
        assert response.status_code == 403
    
    def test_my_request_detail_valid_access(self, client):
        """Request detail with valid token should load."""
        req = create_test_request(print_name="My Detailed Print")
        
        response = client.get(f"/my/{req['request_id']}?token={req['access_token']}")
        assert response.status_code == 200
        assert_html_contains(response, "My Detailed Print")
    
    def test_my_request_nonexistent(self, client):
        """Non-existent request ID should 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = client.get(f"/my/{fake_id}?token=anytoken")
        assert response.status_code == 404
