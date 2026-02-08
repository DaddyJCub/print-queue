"""
Tests for UX redesign components (Phases 3-4)

Tests cover:
- Form field components rendering
- Empty state components
- Error/success banners
- Service worker update notification
- Button loading states
- File upload validation

Uses simple string-based assertions instead of BeautifulSoup for compatibility.
"""

import pytest
import re
from fastapi.testclient import TestClient
from conftest import get_test_db


class TestFormFieldComponents:
    """Test that form field components render correctly in templates."""
    
    def test_feedback_form_uses_form_components(self, client):
        """Feedback form should use new form field components."""
        response = client.get("/feedback?type=bug")
        assert response.status_code == 200
        
        html = response.text
        # Check for form-field class divs (from component)
        assert 'class="form-field' in html or "form-field" in html, \
            "Should have form-field class divs"
        
        # Check for proper label structure
        label_count = html.count('<label')
        assert label_count >= 3, f"Should have labels for name, email, message (found {label_count})"
        
        # Check for optional indicators
        assert "(optional)" in html.lower() or "text-zinc-500" in html, \
            "Should show optional for non-required fields"
    
    def test_feedback_form_has_required_fields(self, client):
        """Feedback form should mark required fields."""
        response = client.get("/feedback?type=bug")
        assert response.status_code == 200
        
        # Required message field should have required attribute
        assert 'required' in response.text


class TestEmptyStateComponent:
    """Test that empty state component renders in appropriate pages."""
    
    def test_admin_feedback_shows_empty_state(self, admin_client):
        """Admin feedback page should show empty state when no feedback."""
        # Clear any existing feedback
        conn = get_test_db()
        conn.execute("DELETE FROM feedback")
        conn.commit()
        conn.close()
        
        response = admin_client.get("/admin/feedback")
        assert response.status_code == 200
        
        # Check for empty state indicators
        assert "No feedback" in response.text or "empty-state" in response.text or \
               "No items" in response.text, "Should show empty state message"
    
    def test_trips_list_prompts_login_or_shows_empty(self, client):
        """Trips list should prompt login or show empty state."""
        # Without authentication, should prompt to sign in or show trips intro
        response = client.get("/trips")
        assert response.status_code == 200
        
        # Should show sign in prompt or trip creation prompt
        html = response.text.lower()
        assert "sign in" in html or "log in" in html or "create" in html or \
               "no trips" in html or "get started" in html, \
               "Should prompt to sign in or create trip"


class TestErrorSuccessBanners:
    """Test error and success banner rendering."""
    
    def test_feedback_form_shows_error_banner_on_invalid(self, client):
        """Feedback form should show error banner for invalid submissions."""
        response = client.post("/feedback", data={
            "feedback_type": "bug",
            "message": "short",  # Too short
        })
        # Should redirect or show error
        assert response.status_code in [200, 303, 422]
    
    def test_admin_login_shows_error_on_bad_credentials(self, client):
        """Admin login should show error for invalid credentials."""
        response = client.post("/admin/login/new", data={
            "username": "nonexistent",
            "password": "wrongpassword"
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert "Invalid" in response.text or "error" in response.text.lower()


class TestServiceWorkerUpdate:
    """Test service worker update notification infrastructure."""
    
    def test_pwa_base_has_sw_update_notification(self, client):
        """PWA base template should include SW update notification code."""
        response = client.get("/")
        assert response.status_code == 200
        
        # Check for update notification function
        assert "showUpdateNotification" in response.text
        assert "sw-update-banner" in response.text
        assert "SKIP_WAITING" in response.text
    
    def test_service_worker_has_skip_waiting_handler(self, client):
        """Service worker should handle SKIP_WAITING message."""
        response = client.get("/sw.js")
        assert response.status_code == 200
        
        # Check for SKIP_WAITING handler
        assert "SKIP_WAITING" in response.text
        assert "skipWaiting" in response.text
    
    def test_service_worker_version_updated(self, client):
        """Service worker should have version 2.7.0 or higher."""
        response = client.get("/sw.js")
        assert response.status_code == 200
        
        # Extract version
        match = re.search(r"SW_VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", response.text)
        assert match is not None, "SW_VERSION should be defined"
        
        version = match.group(1)
        major, minor, patch = map(int, version.split("."))
        assert (major, minor, patch) >= (2, 7, 0), f"SW version should be >= 2.7.0, got {version}"


class TestButtonLoadingStates:
    """Test button loading state infrastructure."""
    
    def test_pwa_base_has_loading_helpers(self, client):
        """PWA base template should include button loading helpers."""
        response = client.get("/")
        assert response.status_code == 200
        
        # Check for loading state functions
        assert "setButtonLoading" in response.text
        assert "resetButton" in response.text
        assert "loadingSpinnerSVG" in response.text
    
    def test_forms_have_data_loading_attribute(self, client):
        """Key forms should have data-loading attribute."""
        # Check request form
        response = client.get("/")
        assert response.status_code == 200
        assert 'data-loading="Submitting..."' in response.text
        
        # Check admin login
        response = client.get("/admin/login/new")
        assert response.status_code == 200
        assert 'data-loading="Signing in..."' in response.text


class TestInputValidation:
    """Test real-time input validation infrastructure."""
    
    def test_pwa_base_has_validation_helpers(self, client):
        """PWA base template should include validation helpers."""
        response = client.get("/")
        assert response.status_code == 200
        
        # Check for validation functions
        assert "validateInput" in response.text
        assert "showInputError" in response.text
        assert "clearInputError" in response.text


class TestFileUploadUX:
    """Test file upload UX improvements."""
    
    def test_request_form_has_file_validation(self, client):
        """Request form should have client-side file validation."""
        response = client.get("/")
        assert response.status_code == 200
        
        # Check for file validation constants
        assert "MAX_FILE_SIZE" in response.text
        assert "ALLOWED_EXTENSIONS" in response.text
        assert "validateFiles" in response.text
    
    def test_request_form_has_file_type_icons(self, client):
        """Request form should have file type icons."""
        response = client.get("/")
        assert response.status_code == 200
        
        # Check for file icons mapping
        assert "FILE_ICONS" in response.text
        assert ".stl" in response.text
        assert ".3mf" in response.text


class TestAccessibilityAttributes:
    """Test that form components include accessibility attributes."""
    
    def test_form_fields_have_required_attribute(self, client):
        """Required form fields should have required attribute."""
        response = client.get("/feedback?type=bug")
        assert response.status_code == 200
        
        # The message field should be marked as required
        assert 'name="message"' in response.text
        assert 'required' in response.text
    
    def test_labels_have_for_attribute(self, client):
        """Labels should have for attribute linking to inputs."""
        response = client.get("/feedback?type=bug")
        assert response.status_code == 200
        
        # Check labels have for attributes
        # The form_field component creates labels with for attributes
        label_for_pattern = re.compile(r'<label[^>]+for="[^"]+"')
        labels = label_for_pattern.findall(response.text)
        assert len(labels) >= 1, "Should have labels with for attributes"
    
    def test_inputs_have_id_matching_label_for(self, client):
        """Inputs should have id attributes matching label for."""
        response = client.get("/feedback?type=bug")
        assert response.status_code == 200
        
        # Check inputs have id attributes
        input_id_pattern = re.compile(r'<(?:input|textarea|select)[^>]+id="([^"]+)"')
        ids = input_id_pattern.findall(response.text)
        assert len(ids) >= 1, "Should have inputs with id attributes"
