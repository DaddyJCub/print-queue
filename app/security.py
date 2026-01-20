"""
Security middleware for Printellect.

Provides:
- CSRF protection for forms
- Rate limiting for sensitive endpoints
- Security headers
"""

import os
import secrets
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Callable, List, Tuple
from functools import wraps
from collections import defaultdict
import threading

from fastapi import Request, Response, HTTPException, Form
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("printellect.security")

# ─────────────────────────── CSRF PROTECTION ───────────────────────────

# CSRF token configuration
CSRF_TOKEN_NAME = "csrf_token"
CSRF_COOKIE_NAME = "csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_LENGTH = 32
CSRF_TOKEN_EXPIRY_HOURS = 24

# Methods that require CSRF protection
CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths exempt from CSRF (e.g., API endpoints with token auth)
CSRF_EXEMPT_PATHS = [
    "/api/push/",       # Push notification API uses its own auth
    "/api/builds/",     # Build status API
    "/api/printer/",    # Printer API
    "/health",          # Health check
    "/api/webhooks/",   # Webhooks use signatures
]


def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def get_csrf_token(request: Request) -> str:
    """
    Get or create a CSRF token for the current request.
    
    Stores the token in request.state for template access.
    """
    # Check if already generated for this request
    if hasattr(request.state, "csrf_token"):
        return request.state.csrf_token
    
    # Try to get from cookie first
    token = request.cookies.get(CSRF_COOKIE_NAME)
    
    # Generate new token if not present or expired
    if not token:
        token = generate_csrf_token()
    
    # Store in request state for templates
    request.state.csrf_token = token
    return token


def validate_csrf_token(request: Request, token: str) -> bool:
    """Validate a CSRF token against the cookie."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token or not token:
        return False
    
    # Constant-time comparison
    return secrets.compare_digest(cookie_token, token)


def is_csrf_exempt(path: str) -> bool:
    """Check if a path is exempt from CSRF protection."""
    for exempt_path in CSRF_EXEMPT_PATHS:
        if path.startswith(exempt_path):
            return True
    return False


def set_csrf_cookie(response: Response, token: str) -> None:
    """Set the CSRF cookie on a response."""
    is_secure = os.getenv("BASE_URL", "").startswith("https")
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,  # JavaScript needs to read it for AJAX requests
        secure=is_secure,
        samesite="lax",
        max_age=CSRF_TOKEN_EXPIRY_HOURS * 3600,
        path="/"
    )


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce CSRF protection on state-changing requests.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate/get token for all requests
        token = get_csrf_token(request)
        
        # Only validate on protected methods
        if request.method in CSRF_PROTECTED_METHODS:
            # Skip exempt paths
            if not is_csrf_exempt(request.url.path):
                # Get token from form or header
                submitted_token = None
                
                # Try header first (AJAX)
                submitted_token = request.headers.get(CSRF_HEADER_NAME)
                
                # If not in header, check form data
                if not submitted_token:
                    # We need to peek at form data
                    # This is tricky because form data can only be read once
                    content_type = request.headers.get("content-type", "")
                    
                    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                        # For form submissions, the token should be in the form
                        # We'll validate in the route handler instead
                        pass
                    elif "application/json" in content_type:
                        # JSON requests must use header
                        if not submitted_token:
                            # Check if this is an API route (might have other auth)
                            if not is_csrf_exempt(request.url.path):
                                logger.warning(f"CSRF token missing for JSON POST to {request.url.path}")
                                # Don't block yet - let routes handle their own auth
        
        # Process request
        response = await call_next(request)
        
        # Set CSRF cookie on all responses
        set_csrf_cookie(response, token)
        
        return response


def csrf_protect():
    """
    Dependency for explicit CSRF validation in form handlers.
    
    Usage:
        @router.post("/submit")
        async def submit(request: Request, csrf: bool = Depends(csrf_protect())):
            ...
    """
    async def validate(request: Request, csrf_token: str = Form(None)):
        if not validate_csrf_token(request, csrf_token):
            logger.warning(f"CSRF validation failed for {request.url.path}")
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        return True
    return validate


# ─────────────────────────── RATE LIMITING ───────────────────────────

# In-memory rate limit storage (for single-instance deployments)
# For production with multiple instances, use Redis
_rate_limit_storage: Dict[str, List[float]] = defaultdict(list)
_rate_limit_lock = threading.Lock()

# Rate limit configuration
RATE_LIMIT_CONFIG = {
    # Path pattern -> (requests, window_seconds)
    "/admin/login": (5, 60),          # 5 attempts per minute
    "/auth/login": (10, 60),          # 10 attempts per minute
    "/auth/register": (3, 60),        # 3 registrations per minute
    "/auth/magic-link": (3, 300),     # 3 magic link requests per 5 minutes
    "/auth/reset-password": (3, 300), # 3 reset requests per 5 minutes
    "/api/push/subscribe": (10, 60),  # 10 subscriptions per minute
}


def get_client_ip(request: Request) -> str:
    """Get the client's IP address, considering proxies."""
    # Check X-Forwarded-For header (for proxies)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct connection
    if request.client:
        return request.client.host
    
    return "unknown"


def get_rate_limit_key(request: Request, endpoint: str) -> str:
    """Generate a rate limit key for the request."""
    ip = get_client_ip(request)
    return f"{endpoint}:{ip}"


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
    """
    Check if a request should be rate limited.
    
    Returns (is_allowed, remaining_requests).
    """
    now = time.time()
    window_start = now - window_seconds
    
    with _rate_limit_lock:
        # Clean old entries
        _rate_limit_storage[key] = [
            t for t in _rate_limit_storage[key] if t > window_start
        ]
        
        # Check limit
        current_count = len(_rate_limit_storage[key])
        if current_count >= max_requests:
            return False, 0
        
        # Record this request
        _rate_limit_storage[key].append(now)
        return True, max_requests - current_count - 1


def get_rate_limit_config(path: str) -> Optional[Tuple[int, int]]:
    """Get rate limit config for a path."""
    for pattern, config in RATE_LIMIT_CONFIG.items():
        if path.startswith(pattern):
            return config
    return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce rate limits on sensitive endpoints.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        config = get_rate_limit_config(request.url.path)
        
        if config:
            max_requests, window_seconds = config
            key = get_rate_limit_key(request, request.url.path)
            
            is_allowed, remaining = check_rate_limit(key, max_requests, window_seconds)
            
            if not is_allowed:
                logger.warning(f"Rate limit exceeded for {key}")
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again later."},
                    headers={
                        "Retry-After": str(window_seconds),
                        "X-RateLimit-Limit": str(max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time() + window_seconds))
                    }
                )
            
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            
            return response
        
        return await call_next(request)


def rate_limit(max_requests: int, window_seconds: int):
    """
    Dependency for explicit rate limiting in route handlers.
    
    Usage:
        @router.post("/sensitive")
        async def sensitive(request: Request, _: bool = Depends(rate_limit(5, 60))):
            ...
    """
    async def check(request: Request):
        key = get_rate_limit_key(request, request.url.path)
        is_allowed, remaining = check_rate_limit(key, max_requests, window_seconds)
        
        if not is_allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(window_seconds)}
            )
        return True
    return check


# ─────────────────────────── SECURITY HEADERS ───────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Content Security Policy (adjust as needed)
        # Note: 'unsafe-inline' needed for Jinja2 templates with inline scripts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://challenges.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' https: wss:; "
            "frame-src https://challenges.cloudflare.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # XSS protection (legacy, but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(self), payment=()"
        )
        
        return response


# ─────────────────────────── HELPER FUNCTIONS ───────────────────────────

def csrf_input(request: Request) -> str:
    """
    Generate a hidden CSRF input field for forms.
    
    Usage in templates:
        {{ csrf_input(request) | safe }}
    """
    token = get_csrf_token(request)
    return f'<input type="hidden" name="{CSRF_TOKEN_NAME}" value="{token}">'


def cleanup_rate_limits(max_age_seconds: int = 3600) -> int:
    """
    Clean up old rate limit entries to prevent memory leaks.
    
    Returns number of entries cleaned.
    """
    cutoff = time.time() - max_age_seconds
    cleaned = 0
    
    with _rate_limit_lock:
        keys_to_delete = []
        for key, timestamps in _rate_limit_storage.items():
            # Remove old timestamps
            original_count = len(timestamps)
            _rate_limit_storage[key] = [t for t in timestamps if t > cutoff]
            cleaned += original_count - len(_rate_limit_storage[key])
            
            # Mark empty keys for deletion
            if not _rate_limit_storage[key]:
                keys_to_delete.append(key)
        
        # Delete empty keys
        for key in keys_to_delete:
            del _rate_limit_storage[key]
    
    logger.debug(f"Cleaned up {cleaned} rate limit entries")
    return cleaned
