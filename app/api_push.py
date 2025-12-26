import json
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from app.main import (
    templates,
    db,
    require_admin,
    send_broadcast_notification,
    get_broadcast_history,
    APP_VERSION,
    send_email,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY,
    VAPID_CLAIMS_EMAIL,
    BASE_URL,
    calculate_rush_price,
    get_printer_suggestions,
    now_iso,
    send_push_notification,
    get_user_notification_prefs,
    update_user_notification_prefs,
)
from app.auth import get_current_user

router = APIRouter()

# ─────────────────────────── BROADCAST NOTIFICATIONS ───────────────────────────

@router.get("/admin/broadcast", response_class=HTMLResponse)
def admin_broadcast_page(request: Request, _=Depends(require_admin)):
    """Admin page for sending broadcast notifications to all subscribers"""
    conn = db()
    
    # Get unique subscriber count
    subscriber_count = conn.execute(
        "SELECT COUNT(DISTINCT email) as c FROM push_subscriptions"
    ).fetchone()["c"]
    
    # Get total subscription count (includes multiple devices per user)
    total_subscriptions = conn.execute(
        "SELECT COUNT(*) as c FROM push_subscriptions"
    ).fetchone()["c"]
    
    # Get subscriber breakdown (email + device count)
    subscribers = conn.execute("""
        SELECT email, COUNT(*) as device_count 
        FROM push_subscriptions 
        GROUP BY email 
        ORDER BY device_count DESC, email
    """).fetchall()
    
    conn.close()
    
    # Get broadcast history
    history = get_broadcast_history(limit=10)
    
    return templates.TemplateResponse("admin_broadcast.html", {
        "request": request,
        "subscriber_count": subscriber_count,
        "total_subscriptions": total_subscriptions,
        "subscribers": [dict(s) for s in subscribers],
        "history": history,
        "version": APP_VERSION,
    })


@router.post("/admin/broadcast/send")
def admin_broadcast_send(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
    url: str = Form(""),
    broadcast_type: str = Form("custom"),
    send_email: Optional[str] = Form(None),
    target: str = Form("all"),
    target_emails: str = Form(""),
    _=Depends(require_admin)
):
    """Send a broadcast notification to all or specific subscribers"""
    # Don't access session directly - just log as 'admin'
    admin_user = "admin"
    
    # Parse target emails if targeting specific users
    specific_emails = None
    if target == "specific" and target_emails.strip():
        # Parse comma or newline separated emails
        specific_emails = [
            e.strip().lower() 
            for e in target_emails.replace('\n', ',').split(',') 
            if e.strip()
        ]
    
    result = send_broadcast_notification(
        title=title,
        body=body,
        url=url if url.strip() else None,
        broadcast_type=broadcast_type,
        sent_by=admin_user,
        also_email=bool(send_email),
        target_emails=specific_emails
    )
    
    return RedirectResponse(
        url=f"/admin/broadcast?sent=1&total={result['total_sent']}&failed={result['total_failed']}&emails={result.get('emails_sent', 0)}",
        status_code=303
    )


@router.post("/api/admin/broadcast/app-update")
def api_broadcast_app_update(
    request: Request,
    version: str = Form(None),
    send_email: Optional[str] = Form(None),
    _=Depends(require_admin)
):
    """
    Send an app update notification to all subscribers.
    Uses the current APP_VERSION if no version is specified.
    Links to the specific version section in the changelog.
    """
    version = version or APP_VERSION
    
    # Link to specific version anchor in changelog
    changelog_url = f"/changelog#v{version}"
    
    result = send_broadcast_notification(
        title="🎉 New Update Available!",
        body=f"Printellect v{version} is here with new features and improvements. Tap to see what's new!",
        url=changelog_url,
        broadcast_type="app_update",
        sent_by="admin",
        metadata={"version": version},
        also_email=bool(send_email)
    )
    
    # Check if request wants JSON (API call) or redirect (form submission)
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return {
            "success": result["total_sent"] > 0,
            "version": version,
            "total_sent": result["total_sent"],
            "total_failed": result["total_failed"],
            "unique_emails": result["unique_emails"],
            "emails_sent": result.get("emails_sent", 0)
        }
    
    # Form submission - redirect back to broadcast page
    return RedirectResponse(
        url=f"/admin/broadcast?sent=1&total={result['total_sent']}&failed={result['total_failed']}&emails={result.get('emails_sent', 0)}",
        status_code=303
    )


# ─────────────────────────── PUSH SUBSCRIPTION MANAGEMENT ───────────────────────────

@router.post("/api/admin/push/cleanup")
async def api_admin_push_cleanup(request: Request, _=Depends(require_admin)):
    """
    Test and cleanup push subscriptions for a specific email.
    Sends a silent test push and removes subscriptions that fail with 404/410.
    """
    try:
        data = await _parse_request_data(request)
        email = data.get("email")
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Email required", "success": False}
            )
        
        removed = await _cleanup_subscriptions_for_email(email)
        
        return {"ok": True, "error": None, "success": True, "email": email, "removed": removed}
    except Exception as e:
        print(f"[PUSH-CLEANUP] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )


@router.post("/api/admin/push/cleanup-all")
async def api_admin_push_cleanup_all(_=Depends(require_admin)):
    """
    Test and cleanup ALL push subscriptions.
    Sends silent test pushes and removes any that fail.
    """
    try:
        conn = db()
        subs = conn.execute("SELECT id, endpoint FROM push_subscriptions").fetchall()
        conn.close()
        
        removed = 0
        
        # Test each subscription
        for sub in subs:
            is_valid = await _test_subscription(sub["endpoint"])
            if not is_valid:
                conn = db()
                conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
                conn.commit()
                conn.close()
                removed += 1
                print(f"[PUSH-CLEANUP] Removed stale subscription: {sub['endpoint'][:50]}...")
        
        print(f"[PUSH-CLEANUP] Cleaned up {removed} stale subscriptions out of {len(subs)}")
        return {"ok": True, "error": None, "success": True, "tested": len(subs), "removed": removed}
    except Exception as e:
        print(f"[PUSH-CLEANUP] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )


@router.post("/api/admin/push/test-all")
async def api_admin_push_test_all(_=Depends(require_admin)):
    """
    Test all push subscriptions and report which are valid/invalid.
    Automatically removes invalid ones.
    """
    try:
        conn = db()
        subs = conn.execute("""
            SELECT id, email, endpoint 
            FROM push_subscriptions
        """).fetchall()
        conn.close()
        
        valid = 0
        invalid = 0
        removed = 0
        
        for sub in subs:
            is_valid = await _test_subscription(sub["endpoint"])
            if is_valid:
                valid += 1
            else:
                invalid += 1
                # Remove invalid subscription
                conn = db()
                conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
                conn.commit()
                conn.close()
                removed += 1
                print(f"[PUSH-TEST] Removed invalid subscription for {sub['email']}: {sub['endpoint'][:40]}...")
        
        print(f"[PUSH-TEST] Results: {valid} valid, {invalid} invalid, {removed} removed")
        return {"ok": True, "error": None, "success": True, "valid": valid, "invalid": invalid, "removed": removed}
    except Exception as e:
        print(f"[PUSH-TEST] Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )


async def _test_subscription(endpoint: str) -> bool:
    """
    Test if a push subscription endpoint is still valid.
    Returns True if valid, False if expired/invalid.
    """
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        return True  # Can't test without VAPID, assume valid
    
    try:
        from pywebpush import webpush, WebPushException
        from urllib.parse import urlparse
        import time
        
        # We need the full subscription info, but we only have endpoint
        # We'll do a lightweight test by checking the endpoint status
        conn = db()
        sub = conn.execute(
            "SELECT p256dh, auth FROM push_subscriptions WHERE endpoint = ?",
            (endpoint,)
        ).fetchone()
        conn.close()
        
        if not sub:
            return False
        
        subscription_info = {
            "endpoint": endpoint,
            "keys": {
                "p256dh": sub["p256dh"],
                "auth": sub["auth"],
            }
        }
        
        # Build VAPID claims
        parsed = urlparse(endpoint)
        aud = f"{parsed.scheme}://{parsed.netloc}"
        
        vapid_email = VAPID_CLAIMS_EMAIL
        if not vapid_email.startswith("mailto:"):
            vapid_email = f"mailto:{vapid_email}"
        
        exp_12h = int(time.time()) + (12 * 3600)
        vapid_claims = {"sub": vapid_email, "aud": aud, "exp": exp_12h}
        
        # Send empty/silent push to test validity
        # Most push services will reject invalid subscriptions
        webpush(
            subscription_info=subscription_info,
            data="",  # Empty payload
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=vapid_claims,
            ttl=0,  # Immediate expiry - don't actually deliver
        )
        return True
    except WebPushException as e:
        # 404 or 410 means subscription is expired/invalid
        if e.response and e.response.status_code in [404, 410]:
            return False
        # Other errors might be temporary, consider valid
        return True
    except Exception:
        return True  # Assume valid on other errors


async def _cleanup_subscriptions_for_email(email: str) -> int:
    """
    Test and remove invalid subscriptions for a specific email.
    Returns number of subscriptions removed.
    """
    conn = db()
    subs = conn.execute(
        "SELECT id, endpoint FROM push_subscriptions WHERE email = ?",
        (email,)
    ).fetchall()
    conn.close()
    
    removed = 0
    for sub in subs:
        is_valid = await _test_subscription(sub["endpoint"])
        if not is_valid:
            conn = db()
            conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sub["id"],))
            conn.commit()
            conn.close()
            removed += 1
            print(f"[PUSH-CLEANUP] Removed stale subscription for {email}")
    
    return removed



# ─────────────────────────── PUSH NOTIFICATION API ───────────────────────────

def _get_email_from_token(token: str) -> Optional[str]:
    """Helper to resolve a my-requests token to email"""
    if not token:
        return None
    conn = db()
    row = conn.execute(
        "SELECT email FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    conn.close()
    return row["email"] if row else None


async def _parse_request_data(request: Request) -> dict:
    """Parse request body - handles both JSON and FormData, returns empty dict on error.
    Logs content-type and body length for debugging push issues."""
    content_type = request.headers.get("content-type", "")
    
    # Log request info for debugging (without sensitive data)
    try:
        body_bytes = await request.body()
        body_len = len(body_bytes) if body_bytes else 0
        print(f"[PUSH_PARSE] Content-Type: {content_type}, Body length: {body_len}")
    except:
        body_bytes = b""
        body_len = 0
        print(f"[PUSH_PARSE] Content-Type: {content_type}, Body: unreadable")

    if body_len == 0:
        return {}
    
    # Try JSON first
    if "application/json" in content_type:
        try:
            if body_bytes:
                return json.loads(body_bytes)
            return {}
        except json.JSONDecodeError as e:
            print(f"[PUSH_PARSE] JSON decode error: {e}")
            return {}
        except Exception as e:
            print(f"[PUSH_PARSE] JSON parse error: {e}")
            return {}
    
    # Try FormData
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        try:
            # Need to re-create request body since we already consumed it
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive
            form = await request.form()
            data = dict(form)
            # Parse nested JSON in subscription field
            if "subscription" in data and isinstance(data["subscription"], str):
                try:
                    data["subscription"] = json.loads(data["subscription"])
                except:
                    pass
            return data
        except Exception as e:
            print(f"[PUSH_PARSE] FormData parse error: {e}")
            return {}
    
    # Fallback: try JSON anyway (some clients don't set Content-Type)
    try:
        if body_bytes:
            return json.loads(body_bytes)
    except:
        pass
    
    return {}


@router.get("/api/push/vapid-public-key")
def get_vapid_public_key():
    """Get the VAPID public key for push subscription"""
    if not VAPID_PUBLIC_KEY:
        return {"ok": False, "error": "Push notifications not configured", "publicKey": None}
    return {"ok": True, "error": None, "publicKey": VAPID_PUBLIC_KEY}


# Test push notification endpoint
@router.post("/api/push/test")
async def test_push_notification(request: Request):
    """Test push notification for a user (by email or token) - returns detailed results"""
    try:
        data = await _parse_request_data(request)
        
        # Accept either email or token
        email = data.get("email")
        token = data.get("token")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Missing email or invalid token", "success": False, "status": "error"}
            )
        
        print(f"[PUSH TEST] Testing push for email: {email}")
        result = send_push_notification(
            email, 
            "Test Notification", 
            "This is a test push notification from Printellect.",
            "/my-requests/view"
        )
        
        if result.get("sent", 0) > 0:
            return {"ok": True, "error": None, "success": True, "status": "sent", "details": result}
        elif result.get("errors"):
            return {
                "ok": False,
                "error": result.get("errors", [{}])[0].get("error", "Unknown error"),
                "success": False,
                "status": "error",
                "details": result
            }
        else:
            return {
                "ok": False,
                "error": "No push subscriptions found for this email",
                "success": False,
                "status": "no_subscriptions",
                "details": result
            }
    except Exception as e:
        print(f"[PUSH TEST] Exception: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False, "status": "exception"}
        )


@router.post("/api/push/subscribe")
async def subscribe_push(request: Request):
    """Subscribe to push notifications for a user (with diagnostics logging)
    
    Accepts either:
    - JSON with {email, subscription}
    - FormData with {token, subscription} (token resolved to email)
    - Session-based auth via user_session cookie
    """
    try:
        data = await _parse_request_data(request)
        print(f"[PUSH] Subscribe attempt: {data}")
        
        # Accept either email or token
        email = data.get("email", "")
        token = data.get("token", "")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        subscription = data.get("subscription", {})
        
        if not email:
            print(f"[PUSH] ERROR: Missing email (token={token})")
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Missing email or invalid token", "success": False}
            )
        
        if not subscription:
            print(f"[PUSH] ERROR: Missing subscription data")
            return JSONResponse(
                status_code=400, 
                content={"ok": False, "error": "Missing subscription", "success": False}
            )
        
        endpoint = subscription.get("endpoint")
        keys = subscription.get("keys", {})
        p256dh = keys.get("p256dh")
        auth = keys.get("auth")
        
        if not endpoint or not p256dh or not auth:
            print(f"[PUSH] ERROR: Invalid subscription data: {subscription}")
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Invalid subscription data (missing endpoint/keys)", "success": False}
            )
        
        conn = db()
        # Check if subscription already exists for this endpoint
        existing = conn.execute(
            "SELECT id, email FROM push_subscriptions WHERE endpoint = ?",
            (endpoint,)
        ).fetchone()
        
        if existing:
            # Update email if endpoint exists but email changed
            if existing["email"].lower() != email.lower():
                conn.execute(
                    "UPDATE push_subscriptions SET email = ? WHERE endpoint = ?",
                    (email.lower(), endpoint)
                )
                conn.commit()
                print(f"[PUSH] Updated subscription email: {endpoint}")
            conn.close()
            return {"ok": True, "error": None, "success": True, "status": "already_subscribed"}
        
        conn.execute(
            """INSERT INTO push_subscriptions (id, email, endpoint, p256dh, auth, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), email.lower(), endpoint, p256dh, auth, now_iso())
        )
        conn.commit()
        conn.close()
        print(f"[PUSH] Subscribed: {email} -> {endpoint[:50]}...")
        return {"ok": True, "error": None, "success": True, "status": "subscribed"}
    except Exception as e:
        print(f"[PUSH] ERROR: Exception in subscribe_push: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )


# Push diagnostics endpoint
@router.get("/api/push/diagnostics/{email}")
def push_diagnostics(email: str):
    """Return all push subscriptions for a user (by email, for diagnostics)"""
    conn = db()
    subs = conn.execute(
        "SELECT id, email, endpoint, p256dh, auth, created_at FROM push_subscriptions WHERE email = ?",
        (email,)
    ).fetchall()
    conn.close()
    return {"ok": True, "error": None, "subscriptions": [dict(row) for row in subs]}


@router.get("/api/push/health")
def push_health_check(_=Depends(require_admin)):
    """Admin-only push notification health check endpoint.
    Confirms VAPID configuration, subscription counts, and tests push capability.
    """
    health = {
        "ok": True,
        "vapid_configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "vapid_public_key_length": len(VAPID_PUBLIC_KEY) if VAPID_PUBLIC_KEY else 0,
        "vapid_claims_email": VAPID_CLAIMS_EMAIL,
        "subscriptions": {"total": 0, "by_email": {}},
        "pywebpush_available": False,
        "test_result": None,
        "errors": []
    }
    
    # Check pywebpush
    try:
        from pywebpush import webpush, WebPushException
        health["pywebpush_available"] = True
    except ImportError:
        health["ok"] = False
        health["errors"].append("pywebpush not installed")
    
    # Check VAPID
    if not health["vapid_configured"]:
        health["ok"] = False
        health["errors"].append("VAPID keys not configured")
    
    # Count subscriptions
    conn = db()
    try:
        total = conn.execute("SELECT COUNT(*) as cnt FROM push_subscriptions").fetchone()
        health["subscriptions"]["total"] = total["cnt"] if total else 0
        
        by_email = conn.execute(
            "SELECT email, COUNT(*) as cnt FROM push_subscriptions GROUP BY email ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        health["subscriptions"]["by_email"] = {row["email"]: row["cnt"] for row in by_email}
    except Exception as e:
        health["errors"].append(f"DB error: {e}")
    finally:
        conn.close()
    
    # Test VAPID JWT generation
    if health["vapid_configured"]:
        try:
            from py_vapid import Vapid
            import base64
            key_bytes = base64.urlsafe_b64decode(VAPID_PRIVATE_KEY + '==')
            v = Vapid.from_raw(key_bytes)
            test_claims = {
                'sub': VAPID_CLAIMS_EMAIL if VAPID_CLAIMS_EMAIL.startswith('mailto:') else f'mailto:{VAPID_CLAIMS_EMAIL}',
                'aud': 'https://fcm.googleapis.com'
            }
            token = v.sign(test_claims)
            health["test_result"] = "JWT generation OK"
        except Exception as e:
            health["ok"] = False
            health["errors"].append(f"VAPID JWT test failed: {e}")
    
    health["error"] = "; ".join(health["errors"]) if health["errors"] else None
    return health


# Service Worker + Push debugging info endpoint
@router.get("/api/sw/debug")
def sw_debug_info():
    """Return server-side SW and push configuration info for debugging"""
    import os
    import time
    sw_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static', 'sw.js'))
    
    # Check VAPID key validity by trying to generate a test JWT
    jwt_test = {"status": "not_tested"}
    if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
        try:
            from py_vapid import Vapid
            import base64
            key_bytes = base64.urlsafe_b64decode(VAPID_PRIVATE_KEY + '==')
            v = Vapid.from_raw(key_bytes)
            test_claims = {
                'sub': VAPID_CLAIMS_EMAIL if VAPID_CLAIMS_EMAIL.startswith('mailto:') else f'mailto:{VAPID_CLAIMS_EMAIL}',
                'aud': 'https://web.push.apple.com'
            }
            token = v.sign(test_claims)
            # Decode the JWT payload to verify claims
            auth_header = token.get('Authorization', '')
            if auth_header.startswith('vapid t='):
                jwt_token = auth_header.split('t=')[1].split(',')[0]
                parts = jwt_token.split('.')
                if len(parts) == 3:
                    import json
                    payload_b64 = parts[1]
                    # Add padding
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += '=' * padding
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    now = int(time.time())
                    exp = payload.get('exp', 0)
                    jwt_test = {
                        "status": "ok",
                        "aud": payload.get('aud'),
                        "sub": payload.get('sub'),
                        "exp": exp,
                        "exp_human": time.ctime(exp),
                        "exp_in_seconds": exp - now,
                        "server_time": now,
                        "server_time_human": time.ctime(now),
                    }
        except Exception as e:
            jwt_test = {"status": "error", "error": str(e)}
    
    return {
        "sw_file_exists": os.path.exists(sw_path),
        "sw_file_path": sw_path,
        "vapid_configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "vapid_public_key_length": len(VAPID_PUBLIC_KEY) if VAPID_PUBLIC_KEY else 0,
        "vapid_private_key_length": len(VAPID_PRIVATE_KEY) if VAPID_PRIVATE_KEY else 0,
        "vapid_claims_email": VAPID_CLAIMS_EMAIL,
        "jwt_test": jwt_test,
        "base_url": BASE_URL,
        "app_version": APP_VERSION
    }


@router.post("/api/push/unsubscribe")
async def unsubscribe_push(request: Request):
    """Unsubscribe from push notifications (per user/email or token)
    
    Accepts either:
    - JSON with {email, endpoint?}
    - FormData with {token, endpoint?}
    - Session-based auth via user_session cookie
    """
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        endpoint = data.get("endpoint")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Missing email or invalid token", "success": False}
            )
        
        conn = db()
        if endpoint:
            result = conn.execute(
                "DELETE FROM push_subscriptions WHERE email = ? AND endpoint = ?",
                (email, endpoint)
            )
        else:
            # Remove all subscriptions for this user
            result = conn.execute(
                "DELETE FROM push_subscriptions WHERE email = ?",
                (email,)
            )
        deleted = result.rowcount
        conn.commit()
        conn.close()
        
        print(f"[PUSH] Unsubscribed {deleted} subscription(s) for {email}")
        return {"ok": True, "error": None, "success": True, "status": "unsubscribed", "deleted": deleted}
    except Exception as e:
        print(f"[PUSH] ERROR in unsubscribe: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )


@router.post("/api/push/clear-all")
async def clear_all_push_subscriptions(request: Request):
    """Clear ALL push subscriptions for a user - use when VAPID keys change"""
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        
        if not email and token:
            email = _get_email_from_token(token)
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Missing email or invalid token", "success": False}
            )
        
        conn = db()
        result = conn.execute(
            "DELETE FROM push_subscriptions WHERE email = ?",
            (email,)
        )
        deleted = result.rowcount
        conn.commit()
        conn.close()
        print(f"[PUSH] Cleared {deleted} subscriptions for {email}")
        return {"ok": True, "error": None, "success": True, "status": "cleared", "deleted": deleted}
    except Exception as e:
        print(f"[PUSH] ERROR in clear-all: {e}")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e), "success": False}
        )



# ─────────────────────────── USER NOTIFICATION PREFERENCES API ───────────────────────────
@router.get("/api/user/notification-prefs")
async def api_get_user_notification_prefs(request: Request, email: str = None, token: str = None):
    """
    Get user-level notification preferences.
    Requires either email, my-requests token, or user session for auth.
    """
    # Try to get email from token if not provided directly
    if not email and token:
        email = _get_email_from_token(token)
    
    # Fallback to session-based auth
    if not email:
        user = await get_current_user(request)
        if user:
            email = user.email
    
    if not email:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Missing email or token"}
        )
    
    prefs = get_user_notification_prefs(email)
    return {
        "success": True,
        "email": email,
        "prefs": prefs
    }


@router.post("/api/user/notification-prefs")
async def api_update_user_notification_prefs(request: Request):
    """
    Update user-level notification preferences.
    Expected JSON body: {
        "email": "user@example.com", OR "token": "my-requests-token",
        "prefs": {
            "progress_push": true,
            "progress_email": false,
            "progress_milestones": "25,50,75,90",
            "status_push": true,
            "status_email": true,
            "broadcast_push": true
        }
    }
    Also supports session-based auth via user_session cookie.
    """
    try:
        data = await _parse_request_data(request)
        
        email = data.get("email")
        token = data.get("token")
        prefs = data.get("prefs", {})
        
        if not email and token:
            email = _get_email_from_token(token)
        
        # Fallback to session-based auth
        if not email:
            user = await get_current_user(request)
            if user:
                email = user.email
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Missing email or invalid token"}
            )
        
        # Validate prefs structure - boolean keys
        bool_keys = {"progress_push", "progress_email", "status_push", "status_email", "broadcast_push"}
        sanitized_prefs = {}
        for key in bool_keys:
            if key in prefs:
                sanitized_prefs[key] = bool(prefs[key])
        
        # Handle progress_milestones (comma-separated string of percentages)
        if "progress_milestones" in prefs:
            milestones_raw = str(prefs["progress_milestones"])
            # Validate and sanitize milestones
            valid_milestones = []
            for p in milestones_raw.split(","):
                p = p.strip()
                if p.isdigit():
                    pct = int(p)
                    if 0 < pct < 100:
                        valid_milestones.append(pct)
            sanitized_prefs["progress_milestones"] = ",".join(str(m) for m in sorted(set(valid_milestones)))
        
        # Get existing prefs and merge
        existing = get_user_notification_prefs(email)
        existing.update(sanitized_prefs)
        
        success = update_user_notification_prefs(email, existing)
        
        if success:
            print(f"[PREFS] Updated notification prefs for {email}: {existing}")
            return {"success": True, "prefs": existing}
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": "Failed to update preferences"}
            )
    except Exception as e:
        print(f"[PREFS] ERROR: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@router.get("/api/notification-prefs/{rid}")
async def get_notification_prefs(rid: str, token: str = ""):
    """Get notification preferences for a request"""
    conn = db()
    req = conn.execute(
        "SELECT notification_prefs, access_token FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    conn.close()
    
    if not req:
        return {"email": True, "push": False}
    
    # Verify token
    if req["access_token"] != token:
        return {"email": True, "push": False}
    
    prefs = {"email": True, "push": False}
    if req["notification_prefs"]:
        try:
            prefs = json.loads(req["notification_prefs"])
        except:
            pass
    
    return prefs


@router.post("/api/notification-prefs/{rid}")
async def update_notification_prefs(rid: str, request: Request):
    """Update notification preferences for a request"""
    try:
        data = await _parse_request_data(request)
    except:
        data = {}
    
    token = data.get("token", "")
    email_enabled = data.get("email", True)
    push_enabled = data.get("push", False)
    
    conn = db()
    req = conn.execute(
        "SELECT access_token FROM requests WHERE id = ?", (rid,)
    ).fetchone()
    
    if not req:
        conn.close()
        return JSONResponse(status_code=404, content={"ok": False, "error": "Request not found"})
    
    # Verify token
    if req["access_token"] != token:
        conn.close()
        return JSONResponse(status_code=403, content={"ok": False, "error": "Invalid token"})
    
    prefs = json.dumps({"email": email_enabled, "push": push_enabled})
    conn.execute(
        "UPDATE requests SET notification_prefs = ? WHERE id = ?",
        (prefs, rid)
    )
    conn.commit()
    conn.close()
    
    return {"ok": True, "status": "updated", "prefs": {"email": email_enabled, "push": push_enabled}}


@router.post("/api/update-global-email-notify")
async def update_global_email_notify(token: str = Form(...), email_enabled: str = Form("1")):
    """Update email notification preference for ALL requests belonging to a user"""
    conn = db()
    
    # Find user email from token
    token_row = conn.execute(
        "SELECT email FROM email_lookup_tokens WHERE token = ?", (token,)
    ).fetchone()
    
    if not token_row:
        conn.close()
        return {"success": False, "error": "Invalid token"}
    
    user_email = token_row["email"]
    enabled = email_enabled == "1"
    
    # Update all requests for this user - preserve existing push setting
    conn.execute(
        """UPDATE requests 
           SET notification_prefs = json_set(
               COALESCE(notification_prefs, '{"email": true, "push": false}'), 
               '$.email', 
               json(?)
           )
           WHERE LOWER(requester_email) = LOWER(?)""",
        (enabled, user_email)
    )
    conn.commit()
    
    # Count updated rows
    updated = conn.total_changes
    conn.close()
    
    return {"success": True, "email": user_email, "enabled": enabled, "updated_requests": updated}


@router.get("/api/rush-pricing")
def get_rush_pricing(name: str = ""):
    """Get dynamic rush pricing based on queue and requester name"""
    printer_suggestions = get_printer_suggestions()
    queue_size = printer_suggestions.get("total_queue", 0)
    pricing = calculate_rush_price(queue_size, name)
    return {
        "price": pricing["final_price"],
        "base_fee": pricing["base_fee"],
        "queue_addon": pricing["queue_addon"],
        "queue_reason": pricing["queue_reason"],
        "is_special": pricing["is_special"],
        "queue_size": queue_size,
    }


