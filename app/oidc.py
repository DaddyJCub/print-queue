"""
OpenID Connect (OIDC) client for Authentik SSO integration.

Handles:
- OIDC discovery (well-known configuration)
- Authorization URL generation with state/nonce
- Authorization code exchange for tokens
- ID token validation (signature, issuer, audience, expiry, nonce)
- Userinfo retrieval
"""

import os
import time
import secrets
import logging
from typing import Optional, Dict, Any, Tuple

import httpx
from authlib.jose import jwt, JsonWebKey
from authlib.common.security import generate_token

logger = logging.getLogger("printellect.oidc")

# ─────────────────────────── CONFIGURATION ───────────────────────────

def _bool_env(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).strip().lower() in ("1", "true", "yes")


def is_oidc_enabled() -> bool:
    """Check if OIDC authentication is enabled."""
    return _bool_env("OIDC_ENABLED", False)


def get_oidc_config() -> Dict[str, str]:
    """Get OIDC configuration from environment variables."""
    return {
        "discovery_url": os.getenv("OIDC_DISCOVERY_URL", ""),
        "client_id": os.getenv("OIDC_CLIENT_ID", ""),
        "client_secret": os.getenv("OIDC_CLIENT_SECRET", ""),
        "redirect_uri": os.getenv("OIDC_REDIRECT_URI", ""),
        "scopes": os.getenv("OIDC_SCOPES", "openid email profile"),
        "display_name": os.getenv("OIDC_DISPLAY_NAME", "Authentik"),
        "end_session_redirect_uri": os.getenv("OIDC_END_SESSION_REDIRECT_URI", ""),
    }


# ─────────────────────────── DISCOVERY CACHE ───────────────────────────

_discovery_cache: Optional[Dict[str, Any]] = None
_discovery_cache_time: float = 0
_jwks_cache: Optional[Any] = None
_jwks_cache_time: float = 0

CACHE_TTL = 3600  # 1 hour


async def fetch_discovery() -> Dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    global _discovery_cache, _discovery_cache_time
    
    now = time.time()
    if _discovery_cache and (now - _discovery_cache_time) < CACHE_TTL:
        return _discovery_cache
    
    config = get_oidc_config()
    discovery_url = config["discovery_url"]
    
    if not discovery_url:
        raise ValueError("OIDC_DISCOVERY_URL not configured")
    
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        _discovery_cache = resp.json()
        _discovery_cache_time = now
    
    logger.info(f"OIDC discovery document fetched from {discovery_url}")
    return _discovery_cache


async def fetch_jwks(jwks_uri: str) -> Any:
    """Fetch and cache the JWKS (JSON Web Key Set)."""
    global _jwks_cache, _jwks_cache_time
    
    now = time.time()
    if _jwks_cache and (now - _jwks_cache_time) < CACHE_TTL:
        return _jwks_cache
    
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        _jwks_cache = JsonWebKey.import_key_set(resp.json())
        _jwks_cache_time = now
    
    logger.info("OIDC JWKS keys fetched and cached")
    return _jwks_cache


def clear_discovery_cache():
    """Clear the discovery and JWKS caches (for testing)."""
    global _discovery_cache, _discovery_cache_time, _jwks_cache, _jwks_cache_time
    _discovery_cache = None
    _discovery_cache_time = 0
    _jwks_cache = None
    _jwks_cache_time = 0


# ─────────────────────────── AUTH FLOW ───────────────────────────

def generate_state() -> str:
    """Generate a cryptographically secure state parameter."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate a cryptographically secure nonce parameter."""
    return secrets.token_urlsafe(32)


async def get_authorization_url(state: str, nonce: str, next_url: Optional[str] = None) -> str:
    """
    Build the authorization URL to redirect the user to Authentik.
    
    Args:
        state: CSRF-protection state parameter
        nonce: Replay-protection nonce parameter
        next_url: Optional post-login redirect URL (encoded in state)
    
    Returns:
        Full authorization URL string
    """
    discovery = await fetch_discovery()
    config = get_oidc_config()
    
    auth_endpoint = discovery["authorization_endpoint"]
    
    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": config["scopes"],
        "state": state,
        "nonce": nonce,
    }
    
    # Build query string
    query = "&".join(f"{k}={httpx.QueryParams({k: v})}" for k, v in params.items())
    # Use httpx for proper encoding
    url = httpx.URL(auth_endpoint, params=params)
    return str(url)


async def exchange_code(code: str) -> Dict[str, Any]:
    """
    Exchange an authorization code for tokens.
    
    Args:
        code: Authorization code from callback
    
    Returns:
        Token response dict containing access_token, id_token, etc.
    """
    discovery = await fetch_discovery()
    config = get_oidc_config()
    
    token_endpoint = discovery["token_endpoint"]
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config["redirect_uri"],
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
    }
    
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(token_endpoint, data=data)
        if resp.status_code != 200:
            logger.error(f"Token exchange failed: {resp.status_code} {resp.text}")
            raise ValueError(f"Token exchange failed: {resp.status_code}")
        return resp.json()


async def verify_id_token(id_token: str, nonce: str) -> Dict[str, Any]:
    """
    Verify and decode an ID token JWT.
    
    Validates:
    - Signature against JWKS
    - Issuer matches discovery document
    - Audience matches client_id
    - Token is not expired
    - Nonce matches expected value
    
    Args:
        id_token: Raw JWT string
        nonce: Expected nonce value
    
    Returns:
        Decoded token claims
    
    Raises:
        ValueError: If token validation fails
    """
    discovery = await fetch_discovery()
    config = get_oidc_config()
    
    # Fetch JWKS for signature verification
    jwks = await fetch_jwks(discovery["jwks_uri"])
    
    try:
        claims = jwt.decode(id_token, jwks)
        
        # Validate standard claims
        claims.validate()
        
        # Verify issuer
        if claims.get("iss") != discovery["issuer"]:
            raise ValueError(
                f"Invalid issuer: expected {discovery['issuer']}, got {claims.get('iss')}"
            )
        
        # Verify audience
        aud = claims.get("aud")
        if isinstance(aud, list):
            if config["client_id"] not in aud:
                raise ValueError(f"Client ID not in audience: {aud}")
        elif aud != config["client_id"]:
            raise ValueError(f"Invalid audience: expected {config['client_id']}, got {aud}")
        
        # Verify nonce
        if claims.get("nonce") != nonce:
            raise ValueError("Nonce mismatch — possible replay attack")
        
        return dict(claims)
        
    except Exception as e:
        logger.error(f"ID token verification failed: {e}")
        raise ValueError(f"ID token verification failed: {e}")


async def get_userinfo(access_token: str) -> Dict[str, Any]:
    """
    Fetch user profile from the OIDC userinfo endpoint.
    
    Args:
        access_token: Bearer access token
    
    Returns:
        User profile dict (sub, email, name, etc.)
    """
    discovery = await fetch_discovery()
    userinfo_endpoint = discovery["userinfo_endpoint"]
    
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if resp.status_code != 200:
            logger.error(f"Userinfo request failed: {resp.status_code}")
            raise ValueError(f"Userinfo request failed: {resp.status_code}")
        return resp.json()


async def get_end_session_url(id_token_hint: Optional[str] = None, post_logout_redirect: Optional[str] = None) -> Optional[str]:
    """
    Build the end-session (logout) URL for Authentik.
    
    Returns None if the provider doesn't support end_session_endpoint.
    """
    try:
        discovery = await fetch_discovery()
    except Exception:
        return None
    
    end_session_endpoint = discovery.get("end_session_endpoint")
    if not end_session_endpoint:
        return None
    
    config = get_oidc_config()
    params = {}
    if id_token_hint:
        params["id_token_hint"] = id_token_hint
    
    redirect = post_logout_redirect or config.get("end_session_redirect_uri")
    if redirect:
        params["post_logout_redirect_uri"] = redirect
    
    if params:
        url = httpx.URL(end_session_endpoint, params=params)
        return str(url)
    
    return end_session_endpoint
