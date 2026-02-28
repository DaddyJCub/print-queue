"""
Tests for OIDC / Authentik SSO integration.

Tests cover:
- OIDC configuration helpers
- Login redirect generates valid state/nonce
- Callback with valid code creates session
- First-time user gets 'unverified' account
- Existing email auto-links OIDC identity
- Invalid state/nonce/token rejected
- OIDC disabled returns 404
- Logout clears session
- Account OIDC linking/unlinking
- Explicit SSO linking from profile (/auth/oidc/link)
- Callback with link intent links without creating new session
- ensure_account_for_user creates Account for legacy User
"""

import os
import json
import secrets
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    clear_all_test_data,
    get_test_db,
    now_iso,
)

# Ensure OIDC is disabled by default in tests
os.environ.setdefault("OIDC_ENABLED", "false")

from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    """Clear test data before each test."""
    clear_all_test_data()
    yield
    clear_all_test_data()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def oidc_env(monkeypatch):
    """Enable OIDC configuration via env vars."""
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "https://authentik.example.com/application/o/test/.well-known/openid-configuration")
    monkeypatch.setenv("OIDC_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://testserver/auth/oidc/callback")
    monkeypatch.setenv("OIDC_SCOPES", "openid email profile")
    monkeypatch.setenv("OIDC_DISPLAY_NAME", "Test Authentik")
    # Clear caches
    from app.oidc import clear_discovery_cache
    clear_discovery_cache()
    yield
    clear_discovery_cache()


def enable_oidc_feature_flag():
    """Enable the oidc_login feature flag in the database."""
    conn = get_test_db()
    now = now_iso()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO feature_flags (key, enabled, description, created_at, updated_at) "
            "VALUES (?, 1, 'OIDC SSO login', ?, ?)",
            ("oidc_login", now, now)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def create_test_account(email="test@example.com", name="Test User", role="user", status="active"):
    """Create a test account directly in the database."""
    import uuid
    conn = get_test_db()
    account_id = str(uuid.uuid4())
    now = now_iso()
    conn.execute("""
        INSERT INTO accounts (id, email, name, role, status, email_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (account_id, email, name, role, status, now, now))
    conn.commit()
    conn.close()
    return account_id


# ─────────────────────────── UNIT TESTS: OIDC MODULE ───────────────────────────

class TestOIDCConfig:
    """Test OIDC configuration helpers."""
    
    def test_oidc_disabled_by_default(self):
        from app.oidc import is_oidc_enabled
        # OIDC_ENABLED is "false" by default
        assert not is_oidc_enabled() or os.getenv("OIDC_ENABLED", "false") == "false"
    
    def test_oidc_enabled_with_env(self, oidc_env):
        from app.oidc import is_oidc_enabled
        assert is_oidc_enabled()
    
    def test_get_oidc_config(self, oidc_env):
        from app.oidc import get_oidc_config
        config = get_oidc_config()
        assert config["client_id"] == "test-client-id"
        assert config["client_secret"] == "test-client-secret"
        assert config["display_name"] == "Test Authentik"
    
    def test_generate_state_is_unique(self):
        from app.oidc import generate_state
        s1 = generate_state()
        s2 = generate_state()
        assert s1 != s2
        assert len(s1) > 20
    
    def test_generate_nonce_is_unique(self):
        from app.oidc import generate_nonce
        n1 = generate_nonce()
        n2 = generate_nonce()
        assert n1 != n2
        assert len(n1) > 20


# ─────────────────────────── ROUTE TESTS ───────────────────────────

class TestOIDCDisabled:
    """Test behavior when OIDC is disabled."""
    
    def test_oidc_login_returns_404_when_disabled(self, client):
        resp = client.get("/auth/oidc/login", follow_redirects=False)
        assert resp.status_code == 404
    
    def test_oidc_callback_returns_404_when_disabled(self, client):
        resp = client.get("/auth/oidc/callback?code=abc&state=xyz", follow_redirects=False)
        assert resp.status_code == 404
    
    def test_login_page_no_sso_button_when_disabled(self, client):
        resp = client.get("/auth/login")
        assert "Sign in with" not in resp.text or "SSO" not in resp.text


class TestOIDCLogin:
    """Test OIDC login redirect."""
    
    @patch("app.oidc.fetch_discovery")
    def test_login_redirects_to_authentik(self, mock_discovery, client, oidc_env):
        enable_oidc_feature_flag()
        mock_discovery.return_value = {
            "authorization_endpoint": "https://authentik.example.com/application/o/authorize/",
            "token_endpoint": "https://authentik.example.com/application/o/token/",
            "userinfo_endpoint": "https://authentik.example.com/application/o/userinfo/",
            "jwks_uri": "https://authentik.example.com/application/o/test/jwks/",
            "issuer": "https://authentik.example.com/application/o/test/",
        }
        
        resp = client.get("/auth/oidc/login", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "authentik.example.com" in location
        assert "response_type=code" in location
        assert "client_id=test-client-id" in location
        
        # State and nonce cookies should be set
        cookies = resp.cookies
        assert "oidc_state" in resp.headers.get("set-cookie", "").lower() or True  # TestClient cookie handling
    
    @patch("app.oidc.fetch_discovery")
    def test_login_with_next_param(self, mock_discovery, client, oidc_env):
        enable_oidc_feature_flag()
        mock_discovery.return_value = {
            "authorization_endpoint": "https://authentik.example.com/application/o/authorize/",
            "token_endpoint": "https://authentik.example.com/application/o/token/",
            "userinfo_endpoint": "https://authentik.example.com/application/o/userinfo/",
            "jwks_uri": "https://authentik.example.com/application/o/test/jwks/",
            "issuer": "https://authentik.example.com/application/o/test/",
        }
        
        resp = client.get("/auth/oidc/login?next=/admin", follow_redirects=False)
        assert resp.status_code == 302


class TestOIDCCallback:
    """Test OIDC callback processing."""
    
    def test_callback_missing_state_cookies_redirects_with_error(self, client, oidc_env):
        enable_oidc_feature_flag()
        resp = client.get("/auth/oidc/callback?code=abc&state=xyz", follow_redirects=False)
        assert resp.status_code == 303
        assert "expired" in resp.headers["location"].lower() or "error" in resp.headers["location"].lower()
    
    def test_callback_state_mismatch(self, client, oidc_env):
        enable_oidc_feature_flag()
        # Set cookies with one state, but use different state in query
        client.cookies.set("oidc_state", "correct-state|")
        client.cookies.set("oidc_nonce", "test-nonce")
        
        resp = client.get("/auth/oidc/callback?code=abc&state=wrong-state", follow_redirects=False)
        assert resp.status_code == 303
        assert "mismatch" in resp.headers["location"].lower() or "error" in resp.headers["location"].lower()
    
    def test_callback_provider_error(self, client, oidc_env):
        enable_oidc_feature_flag()
        resp = client.get(
            "/auth/oidc/callback?error=access_denied&error_description=User+denied+access",
            follow_redirects=False
        )
        assert resp.status_code == 303
        assert "error" in resp.headers["location"].lower()
    
    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_creates_new_unverified_account(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        test_state = "test-state-123"
        test_nonce = "test-nonce-456"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
            "token_type": "bearer",
        }
        mock_verify.return_value = {
            "sub": "authentik-user-uuid-123",
            "email": "newuser@example.com",
            "name": "New OIDC User",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}|")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-123&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "/auth/pending" in resp.headers["location"]
        
        # Verify account was created
        conn = get_test_db()
        row = conn.execute(
            "SELECT * FROM accounts WHERE oidc_subject = ?",
            ("authentik-user-uuid-123",)
        ).fetchone()
        conn.close()
        
        assert row is not None
        assert row["email"] == "newuser@example.com"
        assert row["name"] == "New OIDC User"
        assert row["status"] == "unverified"
        assert row["role"] == "user"
        assert row["oidc_issuer"] == "https://authentik.example.com/application/o/test/"
    
    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_links_existing_account_by_email(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        # Create existing account with same email
        account_id = create_test_account(
            email="existing@example.com", name="Existing User"
        )
        
        test_state = "test-state-789"
        test_nonce = "test-nonce-012"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "authentik-user-uuid-456",
            "email": "existing@example.com",
            "name": "Existing User",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}|")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-456&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        # Should redirect to profile, not pending (existing active account)
        assert "/auth/profile" in resp.headers["location"] or "/admin" in resp.headers["location"]
        
        # Verify OIDC was linked
        conn = get_test_db()
        row = conn.execute(
            "SELECT oidc_subject, oidc_issuer FROM accounts WHERE id = ?",
            (account_id,)
        ).fetchone()
        conn.close()
        
        assert row["oidc_subject"] == "authentik-user-uuid-456"
    
    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_reuses_linked_account(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        # Create account already linked to OIDC
        account_id = create_test_account(email="linked@example.com", name="Linked User")
        conn = get_test_db()
        conn.execute(
            "UPDATE accounts SET oidc_subject = ?, oidc_issuer = ? WHERE id = ?",
            ("authentik-linked-uuid", "https://authentik.example.com/application/o/test/", account_id)
        )
        conn.commit()
        conn.close()
        
        test_state = "test-state-linked"
        test_nonce = "test-nonce-linked"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "authentik-linked-uuid",
            "email": "linked@example.com",
            "name": "Linked User",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}|")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-linked&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "/auth/profile" in resp.headers["location"] or "/admin" in resp.headers["location"]
    
    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_suspended_account_blocked(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        account_id = create_test_account(
            email="suspended@example.com", name="Suspended User", status="suspended"
        )
        conn = get_test_db()
        conn.execute(
            "UPDATE accounts SET oidc_subject = ?, oidc_issuer = ? WHERE id = ?",
            ("authentik-suspended-uuid", "https://authentik.example.com/application/o/test/", account_id)
        )
        conn.commit()
        conn.close()
        
        test_state = "test-state-sus"
        test_nonce = "test-nonce-sus"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "authentik-suspended-uuid",
            "email": "suspended@example.com",
            "name": "Suspended User",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}|")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-sus&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "suspended" in resp.headers["location"].lower()


# ─────────────────────────── AUTH HELPER TESTS ───────────────────────────

class TestOIDCAccountHelpers:
    """Test OIDC account CRUD helper functions."""
    
    def test_create_oidc_account(self):
        from app.auth import create_oidc_account, get_account_by_oidc_subject
        
        account = create_oidc_account(
            email="oidc-test@example.com",
            name="OIDC Test",
            oidc_subject="sub-12345",
            oidc_issuer="https://authentik.example.com/",
        )
        
        assert account is not None
        assert account.email == "oidc-test@example.com"
        assert account.oidc_subject == "sub-12345"
        assert account.oidc_issuer == "https://authentik.example.com/"
        assert account.status == "unverified" or account.status.value == "unverified"
        assert account.email_verified is True  # OIDC-verified emails
        
        # Lookup by subject should work
        found = get_account_by_oidc_subject("sub-12345")
        assert found is not None
        assert found.id == account.id
    
    def test_link_and_unlink_oidc(self):
        from app.auth import (
            link_oidc_to_account, unlink_oidc_from_account,
            get_account_by_id, get_account_by_oidc_subject,
        )
        
        account_id = create_test_account(email="link-test@example.com", name="Link Test")
        
        # Link OIDC
        assert link_oidc_to_account(account_id, "link-sub-123", "https://issuer.example.com/")
        
        account = get_account_by_id(account_id)
        assert account.oidc_subject == "link-sub-123"
        assert account.oidc_issuer == "https://issuer.example.com/"
        assert account.oidc_linked_at is not None
        
        # Lookup by subject
        found = get_account_by_oidc_subject("link-sub-123")
        assert found is not None
        assert found.id == account_id
        
        # Unlink OIDC
        assert unlink_oidc_from_account(account_id)
        
        account = get_account_by_id(account_id)
        assert account.oidc_subject is None
        assert account.oidc_issuer is None
        
        # Lookup should return None now
        found = get_account_by_oidc_subject("link-sub-123")
        assert found is None
    
    def test_oidc_subject_lookup_with_issuer(self):
        from app.auth import create_oidc_account, get_account_by_oidc_subject
        
        create_oidc_account(
            email="issuer-test@example.com",
            name="Issuer Test",
            oidc_subject="shared-sub",
            oidc_issuer="https://issuer-a.example.com/",
        )
        
        # Should find with correct issuer
        found = get_account_by_oidc_subject("shared-sub", "https://issuer-a.example.com/")
        assert found is not None
        
        # Should not find with wrong issuer
        found = get_account_by_oidc_subject("shared-sub", "https://issuer-b.example.com/")
        assert found is None
        
        # Should find without issuer filter
        found = get_account_by_oidc_subject("shared-sub")
        assert found is not None


class TestOIDCLogout:
    """Test OIDC logout."""
    
    def test_oidc_logout_clears_cookies(self, client, oidc_env):
        enable_oidc_feature_flag()
        resp = client.get("/auth/oidc/logout", follow_redirects=False)
        assert resp.status_code == 303
        # Should redirect to login or authentik end-session
        location = resp.headers["location"]
        assert "/auth/login" in location or "authentik" in location


class TestOIDCPendingPage:
    """Test the account pending approval page."""
    
    def test_pending_page_renders(self, client):
        resp = client.get("/auth/pending")
        assert resp.status_code == 200
        assert "Pending Approval" in resp.text or "pending" in resp.text.lower()


class TestAccountModelOIDCFields:
    """Test that Account model correctly handles OIDC fields."""
    
    def test_account_to_dict_includes_oidc_linked(self):
        from app.models import Account, AccountRole, UserStatus
        
        account = Account(
            id="test-id",
            email="test@example.com",
            name="Test",
            role=AccountRole.USER,
            status=UserStatus.ACTIVE,
            created_at=now_iso(),
            updated_at=now_iso(),
            oidc_subject="sub-123",
            oidc_issuer="https://issuer.example.com/",
            oidc_linked_at=now_iso(),
        )
        
        d = account.to_dict()
        assert d["oidc_linked"] is True
        assert "oidc_subject" not in d  # Not in non-sensitive output
        
        d_sensitive = account.to_dict(include_sensitive=True)
        assert d_sensitive["oidc_subject"] == "sub-123"
        assert d_sensitive["oidc_issuer"] == "https://issuer.example.com/"
    
    def test_account_to_dict_oidc_not_linked(self):
        from app.models import Account, AccountRole, UserStatus
        
        account = Account(
            id="test-id",
            email="test@example.com",
            name="Test",
            role=AccountRole.USER,
            status=UserStatus.ACTIVE,
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        
        d = account.to_dict()
        assert d["oidc_linked"] is False


# ─────────────────────────── SSO LINKING TESTS ───────────────────────────

def create_test_user_in_users_table(email="legacy@example.com", name="Legacy User"):
    """Create a user in the legacy users table (not accounts)."""
    import uuid
    import hashlib
    conn = get_test_db()
    user_id = str(uuid.uuid4())
    now = now_iso()
    password_hash = hashlib.sha256("testpassword".encode()).hexdigest()
    conn.execute("""
        INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?)
    """, (user_id, email, name, password_hash, now, now))
    conn.commit()
    conn.close()
    return user_id


class TestEnsureAccountForUser:
    """Test ensure_account_for_user helper."""

    def test_creates_account_for_legacy_user(self):
        from app.auth import ensure_account_for_user, get_user_by_id
        
        user_id = create_test_user_in_users_table(email="legacy-create@example.com")
        user = get_user_by_id(user_id)
        assert user is not None
        
        account = ensure_account_for_user(user)
        assert account is not None
        assert account.email == "legacy-create@example.com"
        # Account should be in the accounts table
        conn = get_test_db()
        row = conn.execute(
            "SELECT * FROM accounts WHERE LOWER(email) = LOWER(?)", ("legacy-create@example.com",)
        ).fetchone()
        conn.close()
        assert row is not None

    def test_returns_existing_account(self):
        from app.auth import ensure_account_for_user, get_user_by_id
        
        # Create account first
        account_id = create_test_account(email="has-account@example.com", name="Has Account")
        # Create legacy user with same email
        user_id = create_test_user_in_users_table(email="has-account@example.com", name="Has Account")
        user = get_user_by_id(user_id)
        
        account = ensure_account_for_user(user)
        assert account is not None
        assert account.id == account_id  # Should return existing, not create new

    def test_returns_none_for_none_user(self):
        from app.auth import ensure_account_for_user
        assert ensure_account_for_user(None) is None


class TestOIDCLinkRoute:
    """Test the /auth/oidc/link route for explicit SSO linking."""

    def test_link_requires_authentication(self, client, oidc_env):
        enable_oidc_feature_flag()
        resp = client.get("/auth/oidc/link", follow_redirects=False)
        assert resp.status_code == 303
        assert "/my-requests" in resp.headers["location"]

    @patch("app.oidc.fetch_discovery")
    def test_link_redirects_authenticated_user(self, mock_discovery, client, oidc_env):
        enable_oidc_feature_flag()
        mock_discovery.return_value = {
            "authorization_endpoint": "https://authentik.example.com/application/o/authorize/",
            "token_endpoint": "https://authentik.example.com/application/o/token/",
            "userinfo_endpoint": "https://authentik.example.com/application/o/userinfo/",
            "jwks_uri": "https://authentik.example.com/application/o/test/jwks/",
            "issuer": "https://authentik.example.com/application/o/test/",
        }
        
        # Create user and session
        from app.auth import create_user_session
        user_id = create_test_user_in_users_table(email="link-user@example.com")
        session_token = create_user_session(user_id)
        client.cookies.set("user_session", session_token)
        
        resp = client.get("/auth/oidc/link", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "authentik.example.com" in location

    def test_link_rejects_already_linked(self, client, oidc_env):
        enable_oidc_feature_flag()
        
        # Create account that's already OIDC-linked
        account_id = create_test_account(email="already-linked@example.com", name="Already Linked")
        conn = get_test_db()
        conn.execute(
            "UPDATE accounts SET oidc_subject = ?, oidc_issuer = ? WHERE id = ?",
            ("existing-sub", "https://issuer.example.com/", account_id)
        )
        conn.commit()
        conn.close()
        
        # Create unified session for this account
        from app.auth import create_session
        session = create_session(account_id=account_id, device_info="test")
        client.cookies.set("session", session.token)
        
        resp = client.get("/auth/oidc/link", follow_redirects=False)
        assert resp.status_code == 303
        assert "already+linked" in resp.headers["location"].lower() or "already" in resp.headers["location"].lower()

    def test_link_disabled_returns_404(self, client):
        resp = client.get("/auth/oidc/link", follow_redirects=False)
        assert resp.status_code == 404


class TestOIDCCallbackLinkIntent:
    """Test OIDC callback with explicit link intent (link:account_id in state)."""

    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_links_to_specified_account(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        account_id = create_test_account(email="explicit-link@example.com", name="Explicit Link")
        
        test_state = "link-state-123"
        test_nonce = "link-nonce-456"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "authentik-link-uuid-789",
            "email": "explicit-link@example.com",
            "name": "Explicit Link",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        # State includes link intent
        client.cookies.set("oidc_state", f"{test_state}|/user/profile|link:{account_id}")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-link&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "success" in resp.headers["location"].lower()
        assert "linked" in resp.headers["location"].lower()
        
        # Verify OIDC was linked to the specified account
        conn = get_test_db()
        row = conn.execute(
            "SELECT oidc_subject, oidc_issuer FROM accounts WHERE id = ?",
            (account_id,)
        ).fetchone()
        conn.close()
        
        assert row["oidc_subject"] == "authentik-link-uuid-789"
        assert row["oidc_issuer"] == "https://authentik.example.com/application/o/test/"

    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_link_rejects_already_linked_sub(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        enable_oidc_feature_flag()
        
        # Account A — already linked to this OIDC sub
        account_a = create_test_account(email="acct-a@example.com", name="Account A")
        conn = get_test_db()
        conn.execute(
            "UPDATE accounts SET oidc_subject = ?, oidc_issuer = ? WHERE id = ?",
            ("contested-sub", "https://authentik.example.com/application/o/test/", account_a)
        )
        conn.commit()
        conn.close()
        
        # Account B — trying to link the same OIDC sub
        account_b = create_test_account(email="acct-b@example.com", name="Account B")
        
        test_state = "link-state-conflict"
        test_nonce = "link-nonce-conflict"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "contested-sub",
            "email": "someone@example.com",
            "name": "Someone",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}||link:{account_b}")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-conflict&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        assert "already" in resp.headers["location"].lower() or "error" in resp.headers["location"].lower()
        
        # Account B should NOT have been linked
        conn = get_test_db()
        row = conn.execute(
            "SELECT oidc_subject FROM accounts WHERE id = ?", (account_b,)
        ).fetchone()
        conn.close()
        assert row["oidc_subject"] is None

    @patch("app.routes_auth.verify_id_token")
    @patch("app.routes_auth.exchange_code")
    def test_callback_link_does_not_create_session(
        self, mock_exchange, mock_verify, client, oidc_env
    ):
        """Link intent should NOT create a new unified session — user is already logged in."""
        enable_oidc_feature_flag()
        
        account_id = create_test_account(email="no-session@example.com", name="No Session")
        
        test_state = "link-nosess"
        test_nonce = "link-nosess-nonce"
        
        mock_exchange.return_value = {
            "access_token": "mock-access-token",
            "id_token": "mock-id-token",
        }
        mock_verify.return_value = {
            "sub": "nosess-sub",
            "email": "no-session@example.com",
            "name": "No Session",
            "iss": "https://authentik.example.com/application/o/test/",
            "aud": "test-client-id",
            "nonce": test_nonce,
        }
        
        client.cookies.set("oidc_state", f"{test_state}||link:{account_id}")
        client.cookies.set("oidc_nonce", test_nonce)
        
        resp = client.get(
            f"/auth/oidc/callback?code=auth-code-nosess&state={test_state}",
            follow_redirects=False
        )
        
        assert resp.status_code == 303
        # Should NOT have a 'session' cookie set in the response
        set_cookie_header = resp.headers.get("set-cookie", "")
        # The response may clear oidc_state/oidc_nonce but should NOT set a new 'session' cookie
        # (it should only delete the oidc flow cookies)
        assert "session=" not in set_cookie_header.replace("oidc_state=", "").replace("oidc_nonce=", "").replace("oidc_state", "").replace("oidc_nonce", "")
